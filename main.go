package main

import (
	"net/http"
	_ "net/http/pprof"

	"github.com/panjjo/gosip/sip"
	"github.com/robfig/cron"
)

var (
	// sip服务用户信息 也就是当前自己的服务用户信息(即:gosip服务), 比如:自己的SIP编号(LID),SIP域(Region),地址(IP:Port)
	_serverDevices NVRDevices
	srv            *sip.Server
)

func main() {
	go func() {
		http.ListenAndServe("0.0.0.0:6060", nil)
	}()
	srv = sip.NewServer()
	srv.RegistHandler(sip.REGISTER, handlerRegister)
	srv.RegistHandler(sip.MESSAGE, handlerMessage)
	go srv.ListenUDPServer(config.UDP)
	restfulAPI()
}

func init() {
	loadConfig()
	dbClient = NewClient().SetDB(config.DB.DBName)
	loadSYSInfo()
	_cron()
}

// _cron 设置定时任务
func _cron() {
	c := cron.New()                             // 新建一个定时任务对象
	c.AddFunc("0 */5 * * * *", checkStream)     // 定时关闭推送流
	c.AddFunc("0 */5 * * * *", clearRecordFile) // 定时清理录制文件
	c.Start()
}
