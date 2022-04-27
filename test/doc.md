# 架构

```bash
.
├── Dockerfile
├── Makefile
├── README.md

# 配置文件
├── config.go
├── config.yml

# 数据库: mongo
├── db.go

├── demo

# 处理句柄: SIP服务处理的接口
├── handler.go

├── m.go
├── main.go
├── notify.go
├── restful.go

├── sip_active.go
├── sip_devices.go
├── sip_play.go
├── sip_record.go
├── stream.go
├── sys.go

# 对接zlm: 和zlm服务交互接口
└── zlm.go

######################################################################

# SIP协议以及数据交互的封装: SIP协议传输格式,SIP服务封装及交互(请求,回复,接收回复)
├── sip

.
├── auth.go

# SIP的数据报文(packet),以及连接
├── connection.go

# SIP相关头: SSRC,Via,....

├── header.go
├── message.go
├── models.go

# 解析器: 根据SIP协议传输格式,将接收对方的数据报文packet解析成本服务可识别的消息体Message
├── parser.go

├── request.go
├── response.go
├── server.go

# SIP服务直接交互的合约: 请求,回复,接收回复
└── tx.go

######################################################################

├── utils
```
