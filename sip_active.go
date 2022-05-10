package main

import (
	"time"

	"github.com/panjjo/gosip/utils"
	"github.com/sirupsen/logrus"
)

/******************************************************************
对方发送SIP消息给本SIP服务 | 对方SIP -> 本SIP
******************************************************************/

// MessageNotify 心跳 | 心跳包xml结构
type MessageNotify struct {
	CmdType  string `xml:"CmdType"`
	SN       int    `xml:"SN"`
	DeviceID string `xml:"DeviceID"`
	Status   string `xml:"Status"`
	Info     string `xml:"Info"`
}

// sipMessageKeepalive 数据包: Message.Keepalive | 心跳来的body是用户设备信息(如：该用户设备的状态)
func sipMessageKeepalive(u NVRDevices, body string) error {
	message := &MessageNotify{}
	if err := utils.XMLDecode([]byte(body), message); err != nil {
		logrus.Errorln("Message Unmarshal xml err:", err, "body:", body)
		return err
	}
	update := M{}
	if message.Status == "OK" {
		update["active"] = time.Now().Unix()
		_activeDevices.Store(u.DeviceID, u)
	} else {
		update["active"] = -1
		_activeDevices.Delete(u.DeviceID)
	}
	go notify(notifyUserAcitve(u.DeviceID, message.Status)) // 通知事件
	return dbClient.Update(userTB, M{"deviceid": u.DeviceID}, M{"$set": update})
}
