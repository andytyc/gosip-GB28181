package main

import (
	"fmt"
	"net/url"
	"time"

	"github.com/panjjo/gosip/utils"
	"github.com/sirupsen/logrus"
)

/*
实现了对 "配置文件中订阅需要通知消息的地址" 进行推送通知消息

-----------------

Notify
消息通知结构 | 就是有人订阅了我们的消息(需要我们主动推送) | 就是在配置里设置了的通知对象集, 我们需要向对方主动推送消息给他们
******************************************************************/

// 配置文件中的 notifyMap 的key支持的的枚举值
const (
	// NotifyMethodUserActive 用户活跃状态通知
	NotifyMethodUserActive = "users.active"
	// NotifyMethodUserRegister 用户注册通知
	NotifyMethodUserRegister = "users.regiester"
	// NotifyMethodDeviceActive 设备活跃通知
	NotifyMethodDeviceActive = "devices.active"
	// NotifyMethodRecordStop 视频录制结束
	NotifyMethodRecordStop = "records.stop"
)

// Notify 消息通知结构 | 就是有人订阅了我们的消息(需要我们主动推送) | 就是在配置里设置了的通知对象集, 我们需要向对方主动推送消息给他们
type Notify struct {
	Method string      `json:"method"`
	Data   interface{} `json:"data"`
}

func notify(data *Notify) {
	if url, ok := config.notifyMap[data.Method]; ok {
		res, err := utils.PostJSONRequest(url, data)
		if err != nil {
			logrus.Warningln(data.Method, "send notify fail.", err)
		}
		if string(res) != "ok" {
			logrus.Warningln(data.Method, "send notify resp fail.", string(res), "len:", len(res), config.Notify, data)
		}
		logrus.Debug("notify send succ:", data.Method, data.Data)
	}
}

func notifyUserAcitve(id, status string) *Notify {
	return &Notify{
		Method: NotifyMethodUserActive,
		Data: map[string]interface{}{
			"deviceid": id,
			"status":   status,
			"time":     time.Now().Unix(),
		},
	}
}

func notifyUserRegister(u NVRDevices) *Notify {
	u.Sys = _sysinfo
	return &Notify{
		Method: NotifyMethodUserRegister,
		Data:   u,
	}
}

func notifyDeviceActive(d Devices) *Notify {
	return &Notify{
		Method: NotifyMethodDeviceActive,
		Data: map[string]interface{}{
			"deviceid": d.DeviceID,
			"status":   d.Status,
			"time":     time.Now().Unix(),
		},
	}
}

func notifyRecordStop(url string, req url.Values) *Notify {
	d := map[string]interface{}{
		"url": fmt.Sprintf("%s/%s", config.Media.HTTP, url),
	}
	for k, v := range req {
		d[k] = v[0]
	}
	return &Notify{
		Method: NotifyMethodRecordStop,
		Data:   d,
	}
}
