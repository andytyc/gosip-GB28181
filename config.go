package main

import (
	"strings"

	"github.com/sirupsen/logrus"
	"github.com/spf13/viper"
)

// Config Config
type Config struct {
	// MOD 运行模式
	MOD string `json:"mod" yaml:"mod" mapstructure:"mod"`
	// DB 数据库
	DB DBConfig `json:"database" yaml:"database" mapstructure:"database"`
	// LogLevel 日志级别
	LogLevel string `json:"logger" yaml:"logger" mapstructure:"logger"`
	// UDP sip服务器udp端口(IP:Port)
	UDP string `json:"udp" yaml:"udp" mapstructure:"udp"`
	// API sip服务 restfulapi 端口
	API string `json:"api" yaml:"api" mapstructure:"api"`
	// Secret restful接口验证key 验证请求使用
	Secret string `json:"secret" yaml:"secret" mapstructure:"secret"`
	// Media 对接c++开发的zlm(即:ZLMediaKit),编译后的media服务:MediaServer
	Media MediaServer `json:"media" yaml:"media" mapstructure:"media"`
	// Stream 实时流
	Stream Stream `json:"stream" yaml:"stream" mapstructure:"stream"`
	// Record 视频录制,文件
	Record RecordCfg `json:"record" yaml:"record" mapstructure:"record"`
	// GB28181 对接GB28181协议,系统运行信息
	GB28181 sysInfo `json:"gb28181" yaml:"gb28181" mapstructure:"gb28181"`
	// Notify 通知
	Notify    map[string]string `json:"notify" yaml:"notify" mapstructure:"notify"`
	notifyMap map[string]string
}

// RecordCfg 视频录制,文件
type RecordCfg struct {
	// FilePath 录像文件路径, 备注: zlm 不会自动清理录制文件，需要配置录像文件路径和定时清理时间。
	FilePath string `json:"filepath" yaml:"filepath" mapstructure:"filepath"`
	// 录制文件录制完成后多久删除,单位天
	Expire int `json:"expire" yaml:"expire"  mapstructure:"expire"`
	// Recordmax 视频录制最长时间,单位秒
	Recordmax int `json:"recordmax" yaml:"recordmax"  mapstructure:"recordmax"`
}

// Stream 实时流
type Stream struct {
	// HLS 是否开启视频流转hls
	HLS bool `json:"hls" yaml:"hls" mapstructure:"hls"`
	// RTMP 是否开启视频流转rtmp
	RTMP bool `json:"rtmp" yaml:"rtmp" mapstructure:"rtmp"`
}

// MediaServer 对接c++开发的zlm(即:ZLMediaKit),编译后的media服务:MediaServer
type MediaServer struct {
	// RESTFUL media 服务器restfulapi地址
	RESTFUL string `json:"restful" yaml:"restful" mapstructure:"restful"`
	// HTTP media 服务器 http请求地址
	HTTP string `json:"http" yaml:"http" mapstructure:"http"`
	// WS media 服务器 ws请求地址
	WS string `json:"ws" yaml:"ws" mapstructure:"ws"`
	// RTMP media 服务器 rtmp请求地址
	RTMP string `json:"rtmp" yaml:"rtmp" mapstructure:"rtmp"`
	// RTP media rtp请求地址 zlm对外开放的接受rtp推流的地址
	RTP string `json:"rtp" yaml:"rtp" mapstructure:"rtp"`
	// Secret zlm secret key 用来请求zlm接口验证
	Secret string `json:"secret" yaml:"secret" mapstructure:"secret"`
}

var config *Config

// loadConfig 加载配置,日志初始化,数据库初始化
func loadConfig() {
	viper.SetConfigType("yml")
	viper.SetConfigName("config")
	viper.AddConfigPath("./")
	viper.SetDefault("logger", "debug")
	viper.SetDefault("udp", "0.0.0.0:5060")
	viper.SetDefault("api", "0.0.0.0:8090")
	viper.SetDefault("mod", "release")

	viper.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
	viper.AutomaticEnv()
	err := viper.ReadInConfig()
	if err != nil {
		logrus.Fatalln("init config error:", err)
	}
	logrus.Infoln("init config ok")
	config = &Config{}
	err = viper.Unmarshal(&config)
	if err != nil {
		logrus.Fatalln("init config unmarshal error:", err)
	}
	logrus.Infof("config :%+v", config)
	level, _ := logrus.ParseLevel(config.LogLevel)
	logrus.SetLevel(level)
	InitDB(config.DB)
	config.MOD = strings.ToUpper(config.MOD)
	notifyMap := map[string]string{}
	if config.Notify != nil {
		for k, v := range config.Notify {
			if v != "" {
				notifyMap[strings.ReplaceAll(k, "_", ".")] = v
			}
		}
	}
	config.notifyMap = notifyMap
	if config.Record.Expire == 0 {
		config.Record.Expire = 7
	}
	if config.Record.Recordmax == 0 {
		config.Record.Expire = 600
	}
}
