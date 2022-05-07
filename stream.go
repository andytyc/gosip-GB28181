package main

import (
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/panjjo/gosip/sip"
	"github.com/panjjo/gosip/utils"
	"github.com/sirupsen/logrus"
	"go.mongodb.org/mongo-driver/mongo"
)

var streamTB = "streams"

// DeviceStream 表{streamTB: streams}的表结构
type DeviceStream struct {
	// T 流类型 0  直播 1 历史
	T int

	SSRC       string
	DeviceID   string
	UserID     string
	StreamType string // pull 媒体服务器主动拉流，push 监控设备主动推流

	// Status 0正常 1关闭 -1 尚未开始
	Status int

	Ftag   map[string]string // header from params
	Ttag   map[string]string // header to params
	CallID string            // header callid

	Time string
	// Stop 是否停止推/拉流
	Stop bool
}

type playList struct {
	// ssrcResponse 回复ssrc对应那条消息的相关参数
	//
	// key=ssrc value=PlayParams 播放对应的PlayParams 用来发送bye获取tag，callid等数据
	ssrcResponse *sync.Map

	// devicesSucc 对设备ID唯一映射,防止重复直播
	//
	// key=deviceid value={ssrc,path} 当前设备直播信息，防止重复直播
	devicesSucc *sync.Map

	// ssrc ssrc编号
	ssrc int
}

// _playList 推流内存同步映射表 (锁定: SSRC编号)
var _playList playList

// getSSRC 获取一个新的可用的ssrc编号(没有流在使用或在占用)
func getSSRC(t int) string {
	r := false
	for {
		_playList.ssrc++
		key := fmt.Sprintf("%d%s%04d", t, _sysinfo.Region[3:8], _playList.ssrc) // 1 + 5 + 4 = 10位
		stream := DeviceStream{}
		if err := dbClient.Get(streamTB, M{"ssrc": ssrc2stream(key), "stop": false}, &stream); err == mongo.ErrNoDocuments || stream.SSRC == "" {
			return key
		}
		if _playList.ssrc > 9000 && !r {
			// 第一轮达到9000后,再重复一次看看是否有停止的流(因为调用此函数获取ssrc时,此时的_playList.ssrc几乎都不会在0最开始地方(而是上次获取的地方))
			// 否则,已经重复过一次了(确保9000以内都没有可用的情况下),那么继续在9000基础上往上增加++,知道获取到可用的ssrc
			_playList.ssrc = 0
			r = true
		}
	}
}

// 定时检查未关闭的流/定时关闭推送流
//
// 检查规则：
//
// 1. 数据库查询当前status=0在推流状态的所有流信息
//
// 2. 比对当前_playList中存在的流，如果不在_playlist或者ssrc与deviceid不匹配则关闭
func checkStream() {
	logrus.Debugln("checkStreamWithCron")
	var skip int64
	for {
		streams := []DeviceStream{}
		dbClient.Find(streamTB, M{"status": 0}, skip, 100, "", false, &streams)
		for _, stream := range streams {
			logrus.Debugln("checkStreamStreamID", stream.SSRC, stream.DeviceID)
			if p, ok := _playList.ssrcResponse.Load(stream.SSRC); ok {
				playParams := p.(playParams)
				if stream.DeviceID == playParams.DeviceID {
					// 此流在用
					// 查询media流是否仍然存在。不存在的需要关闭。
					rtpInfo := zlmGetMediaInfo(playParams.SSRC)
					if rtpInfo.Exist {
						// 流仍然存在
						continue
					}
					if !playParams.stream && time.Now().Unix() < playParams.ext {
						// 推流尚未成功 未超时
						continue
					}
				}
			}
			logrus.Debugln("checkStreamActiveUser", stream.SSRC, stream.UserID)
			user, ok := _activeDevices.Get(stream.UserID)
			if !ok {
				continue
			}
			if user.source == nil {
				logrus.Warningln("checkStreamUserSource is nil", stream.SSRC, stream.UserID)
				continue
			}
			logrus.Debugln("checkStreamClosed", stream.SSRC, stream.UserID)
			// 关闭此流
			device := Devices{}
			if err := dbClient.Get(deviceTB, M{"deviceid": stream.DeviceID}, &device); err != nil {
				logrus.Errorln("checkStreamGetDeviceError", stream.SSRC, stream.DeviceID, err)
				dbClient.Update(streamTB, M{"ssrc": stream.SSRC, "stop": false}, M{"$set": M{"err": err.Error()}})
				device = Devices{
					DeviceID: stream.DeviceID,
					URIStr:   fmt.Sprintf("sip:%s@%s", stream.DeviceID, _serverDevices.Region),
				}
			}
			deviceURI, _ := sip.ParseURI(device.URIStr)
			device.addr = &sip.Address{URI: deviceURI}
			for k, v := range stream.Ttag {
				user.addr.Params.Add(k, sip.String{Str: v})
			}
			for k, v := range stream.Ftag {
				_serverDevices.addr.Params.Add(k, sip.String{Str: v})
			}
			var callid sip.CallID
			callid = sip.CallID(stream.CallID)

			_serverDevices.addr.Params.Add("tag", sip.String{Str: utils.RandString(20)})
			hb := sip.NewHeaderBuilder().SetTo(device.addr).SetFrom(_serverDevices.addr).AddVia(&sip.ViaHop{
				Params: sip.NewParams().Add("branch", sip.String{Str: sip.GenerateBranch()}),
			}).SetContentType(&sip.ContentTypeSDP).SetMethod(sip.BYE).SetContact(_serverDevices.addr).SetCallID(&callid)
			req := sip.NewRequest("", sip.BYE, user.addr.URI, sip.DefaultSipVersion, hb.Build(), "")
			req.SetDestination(user.source)
			req.SetRecipient(device.addr.URI)

			// 不管成功不成功 程序都删除掉，后面开新流，关闭不成功的后面重试
			_playList.ssrcResponse.Delete(stream.SSRC)
			_playList.devicesSucc.Delete(stream.DeviceID)

			tx, err := srv.Request(req)
			if err != nil {
				logrus.Warningln("checkStreamClosedFail", stream.SSRC, err)
				dbClient.Update(streamTB, M{"ssrc": stream.SSRC, "stop": false}, M{"$set": M{"err": err.Error()}})
				continue
			}
			response := tx.GetResponse()
			if response == nil {
				logrus.Warningln("checkStreamClosedFail response is nil", device.DeviceID)
				continue
			}
			if response.StatusCode() != http.StatusOK {
				if response.StatusCode() == 481 {
					logrus.Infoln("checkStreamClosedFail1", stream.SSRC, response.StatusCode())
					dbClient.Update(streamTB, M{"ssrc": stream.SSRC, "stop": false}, M{"$set": M{"err": response.Reason(), "status": 1}})
				} else {
					logrus.Warningln("checkStreamClosedFail1", stream.SSRC, response.StatusCode())
					dbClient.Update(streamTB, M{"ssrc": stream.SSRC, "stop": false}, M{"$set": M{"err": response.Reason()}})
				}
				continue
			}
			dbClient.Update(streamTB, M{"ssrc": stream.SSRC, "stop": false}, M{"$set": M{"status": 1, "stop": true}})

		}
		if len(streams) != 100 { // 翻页结束
			break
		}
		skip += 100
	}
}
