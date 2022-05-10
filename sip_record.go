package main

import (
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"

	"github.com/panjjo/gosip/sip"
	"github.com/panjjo/gosip/utils"
	"github.com/sirupsen/logrus"
)

/*
SIP服务: 处理录像(视音频回放)/录像文件

-----------------
1. 查询录像文件列表
******************************************************************/

/******************************************************************
本SIP服务发送SIP消息给对方 | 本SIP -> 对方SIP
******************************************************************/

// sipRecordList 查询录像文件列表.发起请求 | Message.RecordInfo
func sipRecordList(to NVRDevices, start, end int64) error {
	hb := sip.NewHeaderBuilder().SetTo(to.addr).SetFrom(_serverDevices.addr).AddVia(&sip.ViaHop{
		Params: sip.NewParams().Add("branch", sip.String{Str: sip.GenerateBranch()}),
	}).SetContentType(&sip.ContentTypeXML).SetMethod(sip.MESSAGE)
	req := sip.NewRequest("", sip.MESSAGE, to.addr.URI, sip.DefaultSipVersion, hb.Build(), sip.GetRecordInfoXML(to.DeviceID, start, end))
	req.SetDestination(to.source)
	tx, err := srv.Request(req)
	if err != nil {
		return err
	}
	response := tx.GetResponse()
	if response.StatusCode() != http.StatusOK {
		return errors.New(response.Reason())
	}
	return nil
}

// MessageRecordInfoResponse 录像文件列表 {Message.RecordInfo} SIP消息体
type MessageRecordInfoResponse struct {
	CmdType  string       `xml:"CmdType"`
	SN       int          `xml:"SN"`
	DeviceID string       `xml:"DeviceID"`
	SumNum   int          `xml:"SumNum"`
	Item     []RecordItem `xml:"RecordList>Item"`
}

// RecordItem 录像文件详情
type RecordItem struct {
	// DeviceID 设备编号
	DeviceID string `xml:"DeviceID" bson:"DeviceID" json:"DeviceID"`
	// Name 设备名称
	Name      string `xml:"Name" bson:"Name" json:"Name"`
	FilePath  string `xml:"FilePath" bson:"FilePath" json:"FilePath"`
	Address   string `xml:"Address" bson:"Address" json:"Address"`
	StartTime string `xml:"StartTime" bson:"StartTime" json:"StartTime"`
	EndTime   string `xml:"EndTime" bson:"EndTime" json:"EndTime"`
	Secrecy   int    `xml:"Secrecy" bson:"Secrecy" json:"Secrecy"`
	Type      string `xml:"Type" bson:"Type" json:"Type"`
}

// recordList 本SIP服务向对方SIP服务发起请求：请求录像文件列表,当等待对方回复时,recordList用于记录对方回复的消息
type recordList struct {
	deviceid string // 请求的设备ID
	resp     chan interface{}
	num      int
	data     [][]int64 // 回复消息中,记录{录像文件的时间范围}的集合, 需要这样做的原因: 申请一个 s,e 的时间范围回放流,很可能是包含很多个录像文件的 !!
	l        *sync.Mutex
	last     RecordItem
	s, e     int64 // 请求回放的开始时间, 请求回放的结束时间
}

// 当前获取目录文件设备集合 | 保存的是本SIP服务有多少"请求录像文件列表的请求", 目的:当对方回复消息后,判断是我方请求的,并将回复的数据存储在这个集合中
//
// {设备ID: list} 注意: list: recordList 实体
var _recordList *sync.Map

/******************************************************************
对方发送SIP消息给本SIP服务 | 对方SIP -> 本SIP
******************************************************************/

// sipMessageRecordInfo 查询录像文件列表.对方回复 | Message.RecordInfo
//
// 接收对方来的录像文件列表 | 对方通过 Message.RecordInfo SIP消息发送给本SIP服务，body就是录像文件列表
func sipMessageRecordInfo(u NVRDevices, body string) error {
	message := &MessageRecordInfoResponse{}
	if err := utils.XMLDecode([]byte(body), message); err != nil {
		logrus.Errorln("Message Unmarshal xml err:", err, "body:", body)
		return err
	}
	if list, ok := _recordList.Load(message.DeviceID); ok { //发现有此设备ID的录像文件列表的SIP请求, 进行处理此SIP回复消息
		info := list.(recordList)
		info.l.Lock()
		defer info.l.Unlock()
		info.num += len(message.Item)
		var sint, eint int64
		for _, item := range message.Item {
			s, _ := time.ParseInLocation("2006-01-02T15:04:05", item.StartTime, time.Local)
			e, _ := time.ParseInLocation("2006-01-02T15:04:05", item.EndTime, time.Local)
			sint = s.Unix()
			eint = e.Unix()
			if sint < info.s { // 判断是否符合请求的开始时间
				sint = info.s
			}
			if eint > info.e { // 判断是否符合请求的结束时间
				eint = info.e
			}
			info.data = append(info.data, []int64{sint, eint}) // 所以: [sint,eint] <= [info.s, info.e]
		}
		if info.num == message.SumNum {
			// 获取到完整数据
			info.resp <- transRecordList(info.data)
		}
		_recordList.Store(message.DeviceID, info) // 更新
		return nil
	}
	return errors.New("recordlist devices not found")
}

/* 助手方法
******************************************************************/

// RecordResponse 查询录像文件列表的响应体
type RecordResponse struct {
	DayTotal int           `json:"daynum"`  // 总共几天
	TimeNum  int           `json:"timenum"` // 统计了几次时间序列
	Data     []interface{} `json:"list"`    // 返回数据: []{date: "", items: []RecordInfo}, 如: []{date: "2006-01-02", items: []{Start: 时间戳, End: 时间戳}}
}

// RecordInfo 时间序列(录像文件的时间范围)
type RecordInfo struct {
	Start int64 `json:"start" bson:"start"`
	End   int64 `json:"end" bson:"end"`
}

// transRecordList 将返回的多组数据合并，时间连续的进行合并，最后按照天返回数据，返回为某天内时间段列表
//
// 方法作用: 转换多种组合的录像文件列表时间序列([][]int64), 组织转换成高效率, 可人为识别, 易于实际生产使用的数据, 作为响应体返回
func transRecordList(data [][]int64) RecordResponse {
	if len(data) == 0 {
		return RecordResponse{}
	}
	res := RecordResponse{}

	sort.Slice(data, func(i, j int) bool {
		return data[i][0] < data[j][0] // 以每个的开始时间(sint)进行升序
	})

	// 整理时间序列: 将 {时间范围序列} 将连续的连起来, 将不连续的收集起来
	newData := [][]int64{}
	var newDataIE = []int64{}
	for x, d := range data {
		if x == 0 {
			newDataIE = d
			continue
		}
		if d[0] == newDataIE[1] { // 时间连续
			newDataIE[1] = d[1]
		} else {
			newData = append(newData, newDataIE)
			newDataIE = d
		}
	}
	newData = append(newData, newDataIE) // 注意: 把最后一轮的newDataIE也要加入进来

	list := map[string][]RecordInfo{} // 收集每天对应的时间序列
	var cs, ce time.Time
	dates := []string{} // 按照天进行区分记录
	for _, d := range newData {
		s := time.Unix(d[0], 0)
		e := time.Unix(d[1], 0)
		cs, _ = time.ParseInLocation("20060102", s.Format("20060102"), time.Local) // 注意: 以凌晨进行获取时间戳,单位:天 的时间戳
		for {
			ce = cs.Add(24 * time.Hour)
			if e.Unix() >= ce.Unix() {
				// 当前时段跨天{cs的第二天}
				if v, ok := list[cs.Format("2006-01-02")]; ok { // 之前记录这一天了, 追加{同一天，但不连续}
					list[cs.Format("2006-01-02")] = append(v, RecordInfo{
						Start: utils.Max(s.Unix(), cs.Unix()),
						End:   ce.Unix() - 1,
					})
				} else { // 之前还未记录这一天, 新建记录一天
					list[cs.Format("2006-01-02")] = []RecordInfo{
						{
							Start: utils.Max(s.Unix(), cs.Unix()),
							End:   ce.Unix() - 1,
						},
					}
					dates = append(dates, cs.Format("2006-01-02"))
					res.DayTotal++
				}
				res.TimeNum++
				cs = ce // e > ce 的天, 所以需要继续查看下一天
			} else {
				if v, ok := list[cs.Format("2006-01-02")]; ok { // 之前记录这一天了, 追加{同一天，但不连续}
					list[cs.Format("2006-01-02")] = append(v, RecordInfo{
						Start: utils.Max(s.Unix(), cs.Unix()),
						End:   e.Unix(),
					})
				} else { // 之前还未记录这一天, 新建记录一天
					list[cs.Format("2006-01-02")] = []RecordInfo{
						{
							Start: utils.Max(s.Unix(), cs.Unix()),
							End:   e.Unix(),
						},
					}
					dates = append(dates, cs.Format("2006-01-02"))
					res.DayTotal++
				}
				res.TimeNum++
				break
			}
		}
	}

	resData := []interface{}{}
	for _, date := range dates {
		resData = append(resData, map[string]interface{}{
			"date":  date,
			"items": list[date], // []RecordInfo, 这一天date, 有哪些时间序列(时间范围)
		})

	}
	res.Data = resData
	return res
}

/* 定时任务
******************************************************************/

// clearRecordFile 定时清理过期的录制文件
func clearRecordFile() {
	var files []RecordFiles
	var ids []string
	for {
		files = []RecordFiles{}
		ids = []string{}
		// 1天:86400秒
		dbClient.Find(fileTB, M{"end": M{"$lt": time.Now().Unix() - int64(config.Record.Expire)*86400}, "clear": false}, 0, 100, "start", false, &files)
		for _, file := range files {
			filename := filepath.Join(config.Record.FilePath, file.File)
			if _, err := os.Stat(filename); err == nil {
				os.Remove(filename)
			}
			ids = append(ids, file.ID)
		}
		if len(ids) > 0 {
			dbClient.UpdateMany(fileTB, M{"id": M{"$in": ids}}, M{"$set": M{"clear": true}})
		}
		if len(files) != 100 { // 翻页结束
			break
		}
	}
}
