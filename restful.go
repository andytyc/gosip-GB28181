package main

import (
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"strconv"
	"sync"
	"time"

	"github.com/julienschmidt/httprouter"
	"github.com/panjjo/gosip/sip"
	"github.com/panjjo/gosip/utils"
	"github.com/sirupsen/logrus"
	"go.mongodb.org/mongo-driver/mongo"
)

/*
实现API服务, 处理restful-api的相关接口

-----------------

1. auth身份认证
2. 各接口处理
******************************************************************/

// apiAuthCheck 用于API接口的统一认证入口
func apiAuthCheck(h httprouter.Handle, requiredPassword string) httprouter.Handle {
	return func(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
		// Get the Basic Authentication credentials
		// 获取基本身份验证凭据, 进行身份验证:checkSign
		if ok, msg := checkSign(r.RequestURI, requiredPassword, r.Form); ok {
			// Delegate request to the given handle
			// 将请求委托给给定的句柄 - h: 具体处理的逻辑接口
			h(w, r, ps)
		} else {
			// Request Basic Authentication otherwise
			// 否则请求基本身份验证, 返回验证失败
			_apiResponse(w, statusAuthERR, msg)
		}
	}
}

type apiResponse struct {
	C  string      `json:"code"`
	D  interface{} `json:"data"`
	T  int64       `json:"time"`
	ID string      `json:"id"`
}

func _apiResponse(w http.ResponseWriter, code string, data interface{}) {
	w.WriteHeader(code2code[code])
	w.Header().Add("Content-Type", "application/json")
	_, err := w.Write(utils.JSONEncode(apiResponse{
		code, data, time.Now().Unix(), utils.RandString(16),
	}))
	if err != nil {
		logrus.Errorln("send response api fail.", err)
	}
}

/*
******************************************************************/

// 注册新用户设备/注册NVR用户设备
func apiNewUsers(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
	pwd := r.URL.Query().Get("pwd")
	if pwd == "" {
		_apiResponse(w, statusParamsERR, "密码不能为空")
		return
	}
	user := NVRDevices{
		DeviceID: fmt.Sprintf("%s%06d", _sysinfo.UID, _sysinfo.UNUM+1),
		Region:   _sysinfo.Region,
		PWD:      pwd,
		Name:     r.URL.Query().Get("name"),
	}
	if user.Name == "" {
		user.Name = user.DeviceID
	}
	if err := dbClient.Insert(userTB, user); err != nil {
		_apiResponse(w, statusDBERR, err)
		return
	}
	if err := dbClient.Update(sysTB, M{}, M{"$inc": M{"unum": 1}}); err != nil {
		_apiResponse(w, statusDBERR, err)
		return
	}
	_sysinfo.UNUM++
	user.Sys = _sysinfo
	_apiResponse(w, statusSucc, user)
}

// 更新用户设备/更新NVR用户设备
func apiUpdateUsers(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	id := ps.ByName("id")
	if id == "" {
		_apiResponse(w, statusParamsERR, "缺少用户设备ID")
		return
	}
	user := NVRDevices{}
	err := dbClient.Get(userTB, M{"deviceid": id}, &user)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			_apiResponse(w, statusParamsERR, "用户设备不存在")
			return
		}
		_apiResponse(w, statusDBERR, err)
		return
	}
	pwd := r.URL.Query().Get("pwd")
	if pwd == "" {
		_apiResponse(w, statusParamsERR, "密码不能为空")
		return
	}
	update := M{}
	if pwd != user.PWD {
		update["pwd"] = pwd
		user.PWD = pwd
	}
	name := r.URL.Query().Get("name")
	if name != user.Name {
		update["name"] = name
		user.Name = name
	}
	err = dbClient.Update(userTB, M{"deviceid": user.DeviceID}, M{"$set": update})
	if err != nil {
		_apiResponse(w, statusDBERR, err)
		return
	}
	_apiResponse(w, statusSucc, user)
}

// 删除用户设备/删除NVR用户设备，同时会删除所有归属的通道设备
func apiDelUsers(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	id := ps.ByName("id")
	if id == "" {
		_apiResponse(w, statusParamsERR, "缺少用户设备ID")
		return
	}
	user := NVRDevices{}
	err := dbClient.Get(userTB, M{"deviceid": id}, &user)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			_apiResponse(w, statusParamsERR, "用户设备不存在")
			return
		}
		_apiResponse(w, statusDBERR, err)
		return
	}
	dbClient.DelMany(deviceTB, M{"pdid": user.DeviceID})
	dbClient.Del(userTB, M{"deviceid": user.DeviceID})
	_apiResponse(w, statusSucc, "")
}

// 注册通道设备 | 注意: 绑定所属哪个用户设备
func apiNewDevices(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	id := ps.ByName("id")
	if id == "" {
		_apiResponse(w, statusParamsERR, "缺少用户设备ID")
		return
	}
	user := NVRDevices{}
	err := dbClient.Get(userTB, M{"deviceid": id}, &user)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			_apiResponse(w, statusParamsERR, "用户设备不存在")
			return
		}
		_apiResponse(w, statusDBERR, err)
		return
	}
	device := Devices{
		DeviceID: fmt.Sprintf("%s%06d", _sysinfo.DID, _sysinfo.DNUM+1),
		PDID:     id,
	}
	if err := dbClient.Insert(deviceTB, device); err != nil {
		_apiResponse(w, statusDBERR, err)
		return
	}
	if err := dbClient.Update(sysTB, M{}, M{"$inc": M{"dnum": 1}}); err != nil {
		_apiResponse(w, statusDBERR, err)
		return
	}
	_sysinfo.DNUM++
	_apiResponse(w, statusSucc, device)
}

// 删除通道设备
func apiDelDevices(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	id := ps.ByName("id")
	if id == "" {
		_apiResponse(w, statusParamsERR, "缺少监控设备ID")
		return
	}
	user := Devices{}
	err := dbClient.Get(deviceTB, M{"deviceid": id}, &user)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			_apiResponse(w, statusParamsERR, "监控设备不存在")
			return
		}
		_apiResponse(w, statusDBERR, err)
		return
	}
	dbClient.Del(deviceTB, M{"deviceid": user.DeviceID})
	_apiResponse(w, statusSucc, "")
}

// 直播 同一通道设备公用一个直播流 | 也就是:视音频直播
func apiPlay(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	deviceid := ps.ByName("id")
	d := playParams{S: time.Time{}, E: time.Time{}, DeviceID: deviceid}
	params := r.URL.Query()
	if params.Get("t") == "1" {
		// 视音频回放
		d.T = 1
		s, _ := strconv.ParseInt(params.Get("start"), 10, 64)
		if s == 0 {
			_apiResponse(w, statusParamsERR, "开始时间错误")
			return
		}
		d.S = time.Unix(s, 0)
		e, _ := strconv.ParseInt(params.Get("end"), 10, 64)
		d.E = time.Unix(e, 0)
	} else {
		// 视音频直播
		//
		// 直播的判断当前是否存在播放 (同一通道设备公用一个直播流)
		if succ, ok := _playList.devicesSucc.Load(deviceid); ok {
			_apiResponse(w, statusSucc, succ)
			return
		}
	}
	res := sipPlay(d) // SIP服务发起流请求会话
	switch res.(type) {
	case error, string:
		_apiResponse(w, statusParamsERR, res)
		return
	default:
		_apiResponse(w, statusSucc, res)
		return
	}
}

// 重播，每个重播请求都会生成一个新直播流 | 也就是:视音频回放
func apiReplay(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	r.URL.RawQuery = r.URL.RawQuery + "&t=1"
	apiPlay(w, r, ps)
}

// 停止播放（停止直播/重播）
func apiStopPlay(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	id := ps.ByName("id")
	if _, ok := _playList.ssrcResponse.Load(id); !ok {
		_apiResponse(w, statusSucc, "视频流不存在或已关闭")
		return
	}
	sipStopPlay(id)
	logrus.Infoln("closeStream apiStopPlay", id)
	_apiResponse(w, statusSucc, "")
	return
}

// 获取录像文件列表 | 使用场景: 正规流程中,当请求视频回放时,需要先查询设备存储的录像文件的时间范围，是否支持请求的时间范围
func apiFileList(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	id := ps.ByName("id")
	device := Devices{}
	if err := dbClient.Get(deviceTB, M{"deviceid": id}, &device); err != nil {
		if err == mongo.ErrNoDocuments {
			_apiResponse(w, statusParamsERR, "监控设备不存在")
			return
		}
		_apiResponse(w, statusDBERR, err)
		return
	}
	if time.Now().Unix()-device.Active > 30*60 {
		_apiResponse(w, statusParamsERR, "监控设备已掉线")
		return
	}
	params := r.URL.Query()
	start, _ := strconv.ParseInt(params.Get("start"), 10, 64) // 请求回放的开始时间
	if start == 0 {
		_apiResponse(w, statusParamsERR, "开始时间错误")
		return
	}
	end, _ := strconv.ParseInt(params.Get("end"), 10, 64) // 请求回放的结束时间
	if end == 0 {
		_apiResponse(w, statusParamsERR, "结束时间错误")
		return
	}
	if start >= end {
		_apiResponse(w, statusParamsERR, "开始时间不能小于结束时间")
		return
	}
	user := NVRDevices{}
	user, ok := _activeDevices.Get(device.PDID)
	if !ok {
		_apiResponse(w, statusParamsERR, "用户设备已掉线")
		return
	}
	for {
		if _, ok := _recordList.Load(device.DeviceID); ok {
			// 当前有对该设备的录像文件列表查询请求, 稍后再试: 排队
			//
			//TODO: 这里和下边的Store有同步问题? 原因:加入请求了4次此接口,1个在处理,3个等待排队,而第一个释放时,这3个有可能同时允许请求
			time.Sleep(1 * time.Second)
		} else {
			break
		}
	}

	user.DeviceID = device.DeviceID
	deviceURI, _ := sip.ParseURI(device.URIStr)
	user.addr = &sip.Address{URI: deviceURI}
	resp := make(chan interface{}, 1)
	defer close(resp)

	// 创建一个请求(等待回复), 记录在: _recordList //TODO: 看上边的for{}等待排队,这里逻辑有同步问题,有可能出现:多个同时进行Store操作,而Message回复也在Store更新内容
	_recordList.Store(user.DeviceID, recordList{deviceid: user.DeviceID, resp: resp, data: [][]int64{}, l: &sync.Mutex{}, s: start, e: end})
	defer _recordList.Delete(user.DeviceID)

	err := sipRecordList(user, start, end)
	if err != nil {
		_apiResponse(w, statusParamsERR, "监控设备返回错误"+err.Error())
		return
	}
	select {
	case res := <-resp:
		_apiResponse(w, statusSucc, res)
	case <-time.Tick(10 * time.Second):
		// 10秒未完成返回当前获取到的数据
		if list, ok := _recordList.Load(user.DeviceID); ok {
			info := list.(recordList)
			_apiResponse(w, statusSucc, transRecordList(info.data))
			return
		}
		_apiResponse(w, statusSysERR, "获取超时")
	}
}

// _apiRecordList 记录流录制 key:ssrc  value=channel
var _apiRecordList apiRecordList

// RecordFiles 录制文件表 | 表: fileTB{files}
type RecordFiles struct {
	Start  int64      `json:"start" bson:"start"` // 调用zlm开始录制命令成功,记录:开始生活
	End    int64      `json:"end" bson:"end"`
	Stream string     `json:"stream" bson:"stream"` // 设备ID
	ID     string     `json:"id" bson:"id"`         // 录制文件任务id
	Status int        `json:"status" bson:"status"`
	File   string     `json:"file" bson:"file"`
	Clear  bool       `json:"clear" bson:"clear"`
	params url.Values // 调用zlm的参数
}

type apiRecordItem struct {
	resp   chan string // zlm录制完毕后，发送通知
	clos   chan bool
	params url.Values // 调用zlm的参数, 用于: 开启录制
	req    url.Values
	id     string // 录制文件任务id, 注意: 不是设备ID, 是随机生成的一个录制文件任务id
}

// start 开始录制
func (ri *apiRecordItem) start() (string, interface{}) {
	err := zlmStartRecord(ri.params)
	if err != nil {
		return statusParamsERR, err
	}
	if config.Record.Recordmax != -1 {
		go func() {
			select {
			case <-time.Tick(time.Duration(config.Record.Recordmax) * time.Second):
				// 自动停止录制
				ri.stop()
				url := <-ri.resp
				notify(notifyRecordStop(url, ri.req))
			case <-ri.clos:
				// 调用stop接口(ps: 外部有人主动停止了录制)
			}
		}()
	}

	err = dbClient.Insert(fileTB, RecordFiles{
		ID:     ri.id,
		Stream: ri.params.Get("stream"),
		params: ri.params,
		Start:  time.Now().Unix(),
	})
	if err != nil {
		return statusDBERR, err
	}
	return statusSucc, ri.id // 返回录制任务ID
}

func (ri *apiRecordItem) stop() (string, interface{}) {
	err := zlmStopRecord(ri.params)
	if err != nil {
		return statusSysERR, ""
	}
	return statusSucc, ""
}

func (ri *apiRecordItem) down(url string) {
	dbClient.Update(fileTB, M{"id": ri.id}, M{"$set": M{"end": time.Now().Unix(), "status": 1, "file": url}})
}

type apiRecordList struct {
	items map[string]*apiRecordItem
	l     sync.RWMutex
}

func (rl *apiRecordList) Get(id string) (*apiRecordItem, bool) {
	rl.l.RLock()
	defer rl.l.RUnlock()
	res, ok := rl.items[id]
	return res, ok
}

func (rl *apiRecordList) Start(id string, values url.Values) *apiRecordItem {
	item := &apiRecordItem{resp: make(chan string, 1), clos: make(chan bool, 1), params: values, id: utils.RandString(32)}
	rl.l.Lock()
	rl.items[id] = item
	rl.l.Unlock()
	return item
}

func (rl *apiRecordList) Stop(id string) {
	rl.l.Lock()
	delete(rl.items, id)
	rl.l.Unlock()
}

// apiRecordStart 视频流录制 | 默认保存为mp4文件，录制最多录制10分钟，10分钟后自动停止，一个流只能存在一个录制
func apiRecordStart(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	id := ps.ByName("id")
	if _, ok := _playList.ssrcResponse.Load(id); !ok { // 前提条件: 需要有直播视频流存在
		_apiResponse(w, statusParamsERR, "视频流不存在")
		return
	}
	if _, ok := _apiRecordList.Get(id); ok { // 该视频流正在录制中
		_apiResponse(w, statusParamsERR, "视频流存在未完成录制")
		return
	}
	values := url.Values{}
	values.Set("secret", config.Media.Secret)
	values.Set("type", "1")
	values.Set("vhost", "__defaultVhost__")
	values.Set("app", "rtp")
	values.Set("stream", id)
	req := r.URL.Query()
	item := _apiRecordList.Start(id, values)
	item.req = req
	code, data := item.start()
	if code != statusSucc {
		_apiRecordList.Stop(id)
		data = fmt.Sprintf("录制失败:%v", data)
	}
	_apiResponse(w, code, data)
	return
}

// apiRecordStop 停止录制 | 传入录制时返回的data字段
func apiRecordStop(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	id := ps.ByName("id")

	if item, ok := _apiRecordList.Get(id); !ok {
		_apiResponse(w, statusParamsERR, "录制不存在或已结束")
	} else {
		code, data := item.stop()
		if code == statusSucc {
			item.clos <- true
		} else {
			data = fmt.Sprintf("停止录制失败:%v", data)
		}
		url := <-item.resp
		_apiResponse(w, code, url)
	}
}

/******************************************************************
接收zlm对本restful服务的请求, 处理zlm请求(MediaServer: 流媒体服务)
******************************************************************/

// mediaRequest 请求体
type mediaRequest struct {
	APP    string `json:"app"`
	Params string `json:"params"`
	Stream string `json:"stream"` // 设备ID
	Schema string `json:"schema"`
	URL    string `json:"url"`
	Regist bool   `json:"regist"`
}

func _mediaResponse(w http.ResponseWriter, data interface{}) {
	w.Header().Add("Content-Type", "application/json")
	_, err := w.Write(utils.JSONEncode(data))
	if err != nil {
		logrus.Errorln("send response api fail.", err)
	}
}

func apiWebHooks(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	method := ps.ByName("method")
	body := r.Body
	defer body.Close()
	data, err := ioutil.ReadAll(body)
	if err != nil {
		_mediaResponse(w, map[string]interface{}{
			"code": -1,
			"msg":  "body error",
		})
		return
	}
	logrus.Debugln(method, string(data))
	req := &mediaRequest{}
	if err := utils.JSONDecode(data, &req); err != nil {
		_mediaResponse(w, map[string]interface{}{
			"code": -1,
			"msg":  "body error",
		})
		return
	}
	switch method {
	case "on_server_started":
		_sysinfo.MediaServer = true
		_mediaResponse(w, map[string]interface{}{
			"code": 0,
			"msg":  "success"})
	case "on_http_access":
		_mediaResponse(w, map[string]interface{}{
			"code":   0,
			"second": 86400, // 1天:86400秒
		})
	case "on_play":
		//视频播放触发鉴权
		params, err := url.ParseQuery(req.Params)
		if err != nil {
			_mediaResponse(w, map[string]interface{}{
				"code": -1,
				"msg":  "body error",
			})
			return
		}
		if ok, msg := checkSign(fmt.Sprintf("/rtp/%s/hls.m3u8", req.Stream), config.Secret, params); ok {
			_mediaResponse(w, map[string]interface{}{
				"code": 0,
				"msg":  "",
			})
		} else {
			_mediaResponse(w, map[string]interface{}{
				"code": -1,
				"msg":  msg,
			})
		}
	case "on_publish":
		// 推流鉴权
		_mediaResponse(w, map[string]interface{}{
			"code":       0,
			"enableHls":  config.Stream.HLS,
			"enableMP4":  false,
			"enableRtxp": config.Stream.RTMP,
			"msg":        "success",
		})
	case "on_stream_none_reader":
		// 无人阅读通知 {流无法访问}
		sipStopPlay(req.Stream)
		_mediaResponse(w, map[string]interface{}{
			"code":  0,
			"close": true,
		})
		logrus.Infoln("closeStream on_stream_none_reader", req.Stream)
	case "on_stream_not_found":
		// 流没找到 {没有流推给zlm}
		ssrc := req.Stream
		if d, ok := _playList.ssrcResponse.Load(ssrc); ok {
			params := d.(playParams)
			if params.stream {
				if params.streamType == streamTypePush {
					// 存在推流记录关闭当前，重新发起推流
					sipStopPlay(ssrc)
					logrus.Infoln("closeStream stream pushed!", req.Stream)
				} else {
					// 拉流的，重新拉流
					sipPlay(params)
					logrus.Infoln("closeStream stream pulled!", req.Stream)
				}
			} else {
				if time.Now().Unix() > params.ext {
					// 发送请求，但超时未接收到推流数据，关闭流
					sipStopPlay(ssrc)
					logrus.Infoln("closeStream stream wait timeout", req.Stream)
				}
			}
		}
		_mediaResponse(w, map[string]interface{}{
			"code": 0,
			"msg":  "success",
		})
	case "on_record_mp4":
		// mp4 录制完成 {录制任务完毕}
		if item, ok := _apiRecordList.Get(req.Stream); ok {
			_apiRecordList.Stop(req.Stream)
			item.down(req.URL)
			item.resp <- fmt.Sprintf("%s/%s", config.Media.HTTP, req.URL)
		}
		_mediaResponse(w, map[string]interface{}{
			"code": 0,
			"msg":  "success"})
	case "on_stream_changed":
		ssrc := req.Stream
		if req.Regist {
			if req.Schema == "rtmp" {
				d, ok := _playList.ssrcResponse.Load(ssrc)
				if ok {
					// 接收到流注册事件，更新ssrc数据
					params := d.(playParams)
					params.stream = true
					_playList.ssrcResponse.Store(params.SSRC, params)
				} else {
					// ssrc不存在，关闭流
					sipStopPlay(ssrc)
					logrus.Infoln("closeStream on_stream_changed notfound!", req.Stream)
				}
			}
		} else {
			if req.Schema == "hls" {
				//接收到流注销事件
				_, ok := _playList.ssrcResponse.Load(ssrc)
				if ok {
					// 流还存在，注销
					sipStopPlay(ssrc)
					logrus.Infoln("closeStream on_stream_changed cancel!", req.Stream)
				}
			}
		}
		_mediaResponse(w, map[string]interface{}{
			"code": 0,
			"msg":  "success"})
		//
	default:
		// logrus.Warnln(method)
	}
}

func restfulAPI() {
	router := httprouter.New()

	// 用户设备 (1:n -> 包含通道设备)
	router.GET("/users", apiAuthCheck(apiNewUsers, config.Secret))               // 注册新用户设备
	router.GET("/users/:id/update", apiAuthCheck(apiUpdateUsers, config.Secret)) // 更新用户设备
	router.GET("/users/:id/delete", apiAuthCheck(apiDelUsers, config.Secret))    // 删除用户设备,同时会删除所有归属的通道设备

	// 通道设备
	router.GET("/users/:id/devices", apiAuthCheck(apiNewDevices, config.Secret))  // 注册新通道设备
	router.GET("/devices/:id/delete", apiAuthCheck(apiDelDevices, config.Secret)) // 删除通道设备

	// 流
	router.GET("/devices/:id/play", apiAuthCheck(apiPlay, config.Secret))      // 播放
	router.GET("/devices/:id/replay", apiAuthCheck(apiReplay, config.Secret))  // 回播
	router.GET("/play/:id/stop", apiAuthCheck(apiStopPlay, config.Secret))     // 停止播放
	router.GET("/devices/:id/files", apiAuthCheck(apiFileList, config.Secret)) // 获取历史文件/录像文件列表

	router.GET("/play/:id/record", apiAuthCheck(apiRecordStart, config.Secret)) // 录制
	router.GET("/record/:id/stop", apiAuthCheck(apiRecordStop, config.Secret))  // 停止录制

	// 处理来自zlm的任务命令交互请求(如: 任务处理进度): MediaServer
	router.POST("/index/hook/:method", apiWebHooks)

	logrus.Fatal(http.ListenAndServe(config.API, router))
}
