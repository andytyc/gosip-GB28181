package sip

import (
	"fmt"
	"net"
	"net/http"
	"sync"

	"github.com/panjjo/gosip/utils"
	"github.com/sirupsen/logrus"
)

var (
	bufferSize uint16 = 65535 - 20 - 8 // IPv4 max size - IPv4 Header size - UDP Header size
)

// RequestHandler 请求处理程序/请求处理句柄
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

func (s *Server) newTX(key string) *Transaction {
	return s.txs.newTX(key, s.conn)
}

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

func (s *Server) handlerListen(msgs chan Message) {
	var msg Message
	for {
		msg = <-msgs
		switch msg.(type) {
		case *Request:
			req := msg.(*Request)
			req.SetDestination(s.udpaddr)
			s.handlerRequest(req)
		case *Response:
			resp := msg.(*Response)
			resp.SetDestination(s.udpaddr)
			s.handlerResponse(resp)
		}
	}
}

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

func (s *Server) handlerResponse(msg *Response) {
	tx := s.getTX(getTXKey(msg))
	logrus.Traceln("receive response from:", msg.Source(), "txKey:", tx.key, "message: \n", msg.String())
	if tx == nil {
		logrus.Infoln("not found tx. receive response from:", msg.Source(), "message: \n", msg.String())
	} else {
		tx.receiveResponse(msg)
	}
}

// Request Request
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
