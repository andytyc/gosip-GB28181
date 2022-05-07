package main

import (
	"fmt"
	"net/http"

	"github.com/panjjo/gosip/sip"
	"github.com/panjjo/gosip/utils"
	"github.com/sirupsen/logrus"
)

// MessageReceive 接收到的 "sip.Method: MESSAGE" 方法的请求数据最外层，主要用来判断数据类型(CmdType)
//
// xml的具体结构,可以参考sip.models的指令 xml 字符串
type MessageReceive struct {
	CmdType string `xml:"CmdType"`
	SN      int    `xml:"SN"`
}

// handlerRegister 处理接口句柄: Message
func handlerMessage(req *sip.Request, tx *sip.Transaction) {
	u, ok := parserDevicesFromReqeust(req)
	if !ok {
		// 未解析出来源用户返回错误
		tx.Respond(sip.NewResponseFromRequest("", req, http.StatusBadRequest, http.StatusText(http.StatusBadRequest), ""))
		return
	}
	// 判断是否存在body数据
	if len, have := req.ContentLength(); !have || len.Equals(0) {
		// 不存在就直接返回的成功
		tx.Respond(sip.NewResponseFromRequest("", req, http.StatusOK, "", ""))
		return
	}
	body := req.Body()
	message := &MessageReceive{}

	if err := utils.XMLDecode([]byte(body), message); err != nil {
		logrus.Errorln("Message Unmarshal xml err:", err, "body:", body)
		tx.Respond(sip.NewResponseFromRequest("", req, http.StatusBadRequest, http.StatusText(http.StatusBadRequest), ""))
		return
	}
	switch message.CmdType {
	case "Catalog":
		// 目录设备列表
		sipMessageCatalog(u, body)
		tx.Respond(sip.NewResponseFromRequest("", req, http.StatusOK, "", ""))
		return
	case "Keepalive":
		// heardbeat 心跳
		if err := sipMessageKeepalive(u, body); err == nil {
			tx.Respond(sip.NewResponseFromRequest("", req, http.StatusOK, "", ""))
			// 心跳后同步注册设备列表信息
			sipCatalog(u)
			return
		}
	case "RecordInfo":
		// 设备音视频文件列表 //TODO: ?缺少return
		sipMessageRecordInfo(u, body)
		tx.Respond(sip.NewResponseFromRequest("", req, http.StatusOK, "", ""))
	case "DeviceInfo":
		// 主设备信息
		sipMessageDeviceInfo(u, body)
		tx.Respond(sip.NewResponseFromRequest("", req, http.StatusOK, "", ""))
		return
	}
	tx.Respond(sip.NewResponseFromRequest("", req, http.StatusBadRequest, http.StatusText(http.StatusBadRequest), ""))
}

// handlerRegister 处理接口句柄: Register : 注册/注销
func handlerRegister(req *sip.Request, tx *sip.Transaction) {
	// 判断是否存在授权字段
	if hdrs := req.GetHeaders("Authorization"); len(hdrs) > 0 {
		fromUser, ok := parserDevicesFromReqeust(req)
		if !ok {
			return
		}
		user := NVRDevices{}
		if err := dbClient.Get(userTB, M{"deviceid": fromUser.DeviceID}, &user); err == nil {
			if !user.Regist {
				// 如果数据库里用户未激活，替换user数据
				fromUser.PWD = user.PWD
				user = fromUser
			}
			user.addr = fromUser.addr
			authenticateHeader := hdrs[0].(*sip.GenericHeader)
			auth := sip.AuthFromValue(authenticateHeader.Contents)
			auth.SetPassword(user.PWD)
			auth.SetUsername(user.DeviceID)
			auth.SetMethod(string(req.Method()))
			auth.SetURI(auth.Get("uri"))
			if auth.CalcResponse() == auth.Get("response") {
				// 验证成功
				// 记录活跃设备
				user.source = fromUser.source
				user.addr = fromUser.addr
				_activeDevices.Store(user.DeviceID, user)
				if !user.Regist {
					// 第一次激活，保存数据库
					user.Regist = true
					dbClient.Update(userTB, M{"deviceid": user.DeviceID}, M{"$set": user})
					logrus.Infoln("new user regist,id:", user.DeviceID)
				}
				tx.Respond(sip.NewResponseFromRequest("", req, http.StatusOK, "", ""))
				// 注册成功后查询设备信息，获取制作厂商等信息
				go notify(notifyUserRegister(user)) // 对配置中有订阅消息的进行通知推送
				go sipDeviceInfo(fromUser)          // 请求当前DeviceID的设备/服务信息(如:制作厂商等信息)
				return
			}
		}
	}
	resp := sip.NewResponseFromRequest("", req, http.StatusUnauthorized, http.StatusText(http.StatusUnauthorized), "")
	resp.AppendHeader(&sip.GenericHeader{HeaderName: "WWW-Authenticate", Contents: fmt.Sprintf("Digest Nonce=\"%s\" Realm=\"%s\"", req.MessageID(), req.MessageID())})
	tx.Respond(resp)
}
