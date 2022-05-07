package sip

import (
	"fmt"
	"net"
	"net/http"
	"sync"

	"github.com/panjjo/gosip/utils"
	"github.com/sirupsen/logrus"
)

/*
实现了处理SIP消息的SIP服务

-----------------

Server
SIP服务, 本质上实现的是一个UDP通信服务, 但拆包和组包对数据报文的处理根据SIP协议进行

涉及到的相关模块:
1. Connection, 保存连接conn对象,管理连接(关闭conn),接收(Write)/发送(Read)数据报文
2. Parse, 解码器将 SIP消息 的原始字节转换为 Message 对象 (根据SIP协议传输格式)
3. transacionts, 合同表(txs), 同一个CallId的多个数据报文都是同一个合同tx
4. RequestHandler, 接口句柄, 处理具体业务逻辑的接口
******************************************************************/

var (
	// IPv4 max size(2^16 - 1) = 65535 字节 (除以1024约等于64KB)
	bufferSize uint16 = 65535 - 20 - 8 // IPv4 max size(2^16 - 1) - IPv4 Header size - UDP Header size
)

// RequestHandler 请求处理程序/请求处理句柄(处理具体接口的逻辑)
type RequestHandler func(req *Request, tx *Transaction)

// Server SIP服务
type Server struct {
	udpaddr net.Addr
	conn    Connection

	// txs 此服务已激活合同映射表
	txs *transacionts

	// hmu 用于requestHandlers句柄映射表, 路由方法:处理句柄
	hmu             *sync.RWMutex
	requestHandlers map[RequestMethod]RequestHandler

	// port 服务端口
	port *Port
	// host 自身机器网络IP
	host net.IP
}

// NewServer 新建SIP服务
func NewServer() *Server {
	activeTX = &transacionts{txs: map[string]*Transaction{}, rwm: &sync.RWMutex{}}
	srv := &Server{hmu: &sync.RWMutex{},
		txs:             activeTX,
		requestHandlers: map[RequestMethod]RequestHandler{}}
	return srv
}

// newTX 新建合约
func (s *Server) newTX(key string) *Transaction {
	return s.txs.newTX(key, s.conn)
}

// getTX 获取合约
func (s *Server) getTX(key string) *Transaction {
	return s.txs.getTX(key)
}

// mustTX 相比较getTX,不存在则会新建合约
func (s *Server) mustTX(key string) *Transaction {
	tx := s.txs.getTX(key)
	if tx == nil {
		tx = s.txs.newTX(key, s.conn)
	}
	return tx
}

// ListenUDPServer 监听UDP服务,阻塞同步
func (s *Server) ListenUDPServer(addr string) {
	udpaddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		logrus.Fatal("net.ResolveUDPAddr err", err, addr)
	}
	s.port = NewPort(udpaddr.Port)
	s.host, err = utils.ResolveSelfIP()
	if err != nil {
		logrus.Fatal("net.ListenUDP resolveip err", err, addr)
	}
	udp, err := net.ListenUDP("udp", udpaddr)
	if err != nil {
		logrus.Fatal("net.ListenUDP err", err, addr)
	}
	s.conn = newUDPConnection(udp)
	var (
		raddr net.Addr
		num   int
	)
	buf := make([]byte, bufferSize)
	parser := newParser()
	defer parser.stop()
	go s.handlerListen(parser.out)
	for {
		num, raddr, err = s.conn.ReadFrom(buf)
		if err != nil {
			logrus.Errorln("udp.ReadFromUDP err", err)
			continue
		}
		parser.in <- newPacket(buf[:num], raddr)
	}
}

// RegistHandler 注册处理句柄
func (s *Server) RegistHandler(method RequestMethod, handler RequestHandler) {
	s.hmu.Lock()
	s.requestHandlers[method] = handler
	s.hmu.Unlock()
}

// handlerListen 处理监听到的消息(已经成功解析为Message的消息)
func (s *Server) handlerListen(msgs chan Message) {
	var msg Message
	for {
		msg = <-msgs
		switch msg.(type) {
		case *Request:
			// 处理请求消息
			req := msg.(*Request)
			req.SetDestination(s.udpaddr)
			s.handlerRequest(req)
		case *Response:
			// 处理回复消息
			resp := msg.(*Response)
			resp.SetDestination(s.udpaddr)
			s.handlerResponse(resp)
		}
	}
}

// handlerRequest 处理请求消息
func (s *Server) handlerRequest(msg *Request) {
	tx := s.mustTX(getTXKey(msg))
	logrus.Traceln("receive request from:", msg.Source(), ",method:", msg.Method(), "txKey:", tx.key, "message: \n", msg.String())
	s.hmu.RLock()
	handler, ok := s.requestHandlers[msg.Method()]
	s.hmu.RUnlock()
	if !ok {
		logrus.Errorln("not found handler func,requestMethod:", msg.Method(), msg.String())
		go handlerMethodNotAllowed(msg, tx)
		return
	}

	go handler(msg, tx)
}

// handlerRequest 处理回复消息
func (s *Server) handlerResponse(msg *Response) {
	tx := s.getTX(getTXKey(msg))
	logrus.Traceln("receive response from:", msg.Source(), "txKey:", tx.key, "message: \n", msg.String())
	if tx == nil {
		logrus.Infoln("not found tx. receive response from:", msg.Source(), "message: \n", msg.String())
	} else {
		tx.receiveResponse(msg)
	}
}

// Request 发起请求 | 将req消息作为请求发送出去
func (s *Server) Request(req *Request) (*Transaction, error) {
	viaHop, ok := req.ViaHop()
	if !ok {
		return nil, fmt.Errorf("missing required 'Via' header")
	}
	viaHop.Host = s.host.String()
	viaHop.Port = s.port
	if viaHop.Params == nil {
		viaHop.Params = NewParams().Add("branch", String{Str: GenerateBranch()})
	}
	if !viaHop.Params.Has("rport") {
		viaHop.Params.Add("rport", nil)
	}

	tx := s.mustTX(getTXKey(req))
	return tx, tx.Request(req)
}

func handlerMethodNotAllowed(req *Request, tx *Transaction) {
	resp := NewResponseFromRequest("", req, http.StatusMethodNotAllowed, http.StatusText(http.StatusMethodNotAllowed), "")
	tx.Respond(resp)
}
