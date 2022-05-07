package sip

import (
	"bufio"
	"bytes"
	"io"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/panjjo/gosip/utils"
	"github.com/sirupsen/logrus"
)

/*
连接对象的双方进行消息交互传输 []byte <=> []byte

-----------------

Packet
对数据报文(字节)进行读对象封装为一个读取器(包裹了数据报文形成一个读取器，方便按需读取)

Connection
实现了Connection接口 | 实现了Connection接口 -> 保存连接对象,管理连接(关闭),接收(Write)/发送(Read)数据报文
******************************************************************/

// Packet 数据包/数据报文, 简称: 数据报文 | 对数据报文(字节)进行读对象封装为一个读取器(包裹了数据报文形成一个读取器，方便按需读取)
type Packet struct {
	// reader 读对象
	reader *bufio.Reader
	// raddr 远端地址
	raddr net.Addr
	// bodylength 消息正文长度
	bodylength int
}

// newPacket 新建数据包/数据报文
//
// 对数据报文(字节)进行读对象封装为一个读取器(包裹了数据报文形成一个读取器，方便按需读取)
//
// data: 接收的数据, raddr: 远端地址
func newPacket(data []byte, raddr net.Addr) Packet {
	logrus.Traceln("receive new packet,from:", raddr.String(), string(data))
	return Packet{
		reader:     bufio.NewReader(bytes.NewReader(data)),
		raddr:      raddr,
		bodylength: getBodyLength(data),
	}
}

// nextLine 按照行读取: 读取数据报文的下一行数据
func (p *Packet) nextLine() (string, error) {
	str, err := p.reader.ReadString('\n')
	if err != nil {
		return "", err
	}
	if len(str) >= 2 {
		str = str[:len(str)-2]
	}
	return str, err
}

// bodyLength 获取body数据长度
func (p *Packet) bodyLength() int {
	return p.bodylength
}

// getBody 读取body数据
func (p *Packet) getBody() (string, error) {
	if p.bodyLength() < 1 {
		return "", nil
	}
	body := make([]byte, p.bodylength)
	if p.bodylength > 0 {
		n, err := io.ReadFull(p.reader, body)
		if err != nil {
			return "", err
		}
		if n != p.bodylength {
			logrus.Warningf("body length err,%d!=%d,body:%s", n, p.bodylength, string(body))
			return string(body[:n]), nil
		}
	}
	return string(body), nil
}

// Connection Wrapper around net.Conn.
//
// 实现了Connection接口 实现了Connection接口 -> 保存连接对象,管理连接(关闭),接收(Write)/发送(Read)数据报文
type Connection interface {
	net.Conn
	Network() string
	// String() string
	ReadFrom(buf []byte) (num int, raddr net.Addr, err error)
	WriteTo(buf []byte, raddr net.Addr) (num int, err error)
}

// connection 实现了Connection接口
type connection struct {
	// baseConn 开启监听后的连接对象,作为本connection结构体的基础连接对象
	baseConn net.Conn
	// 本地地址
	laddr net.Addr
	// 远端地址
	raddr  net.Addr
	mu     sync.RWMutex
	logKey string
}

// newUDPConnection 实现了Connection接口 | 实现了Connection接口 -> 保存连接对象,管理连接(关闭),接收(Write)/发送(Read)数据报文
func newUDPConnection(baseConn net.Conn) Connection {
	conn := &connection{
		baseConn: baseConn,
		laddr:    baseConn.LocalAddr(),
		raddr:    baseConn.RemoteAddr(),
		logKey:   "udpConnection",
	}
	return conn
}

func (conn *connection) Read(buf []byte) (int, error) {
	var (
		num int
		err error
	)

	num, err = conn.baseConn.Read(buf)

	if err != nil {
		return num, utils.NewError(err, conn.logKey, "read", conn.baseConn.LocalAddr().String())
	}
	return num, err
}

func (conn *connection) ReadFrom(buf []byte) (num int, raddr net.Addr, err error) {
	num, raddr, err = conn.baseConn.(net.PacketConn).ReadFrom(buf)
	if err != nil {
		return num, raddr, utils.NewError(err, conn.logKey, "readfrom", conn.baseConn.LocalAddr().String(), raddr.String())
	}
	logrus.Tracef("readFrom %d , %s -> %s \n %s", num, raddr, conn.LocalAddr(), string(buf[:num]))
	return num, raddr, err
}

func (conn *connection) Write(buf []byte) (int, error) {
	var (
		num int
		err error
	)

	num, err = conn.baseConn.Write(buf)
	if err != nil {
		return num, utils.NewError(err, conn.logKey, "write", conn.baseConn.LocalAddr().String())
	}
	return num, err
}

func (conn *connection) WriteTo(buf []byte, raddr net.Addr) (num int, err error) {
	num, err = conn.baseConn.(net.PacketConn).WriteTo(buf, raddr)
	if err != nil {
		return num, utils.NewError(err, conn.logKey, "writeTo", conn.baseConn.LocalAddr().String(), raddr.String())
	}
	logrus.Tracef("writeTo %d , %s -> %s \n %s", num, conn.baseConn.LocalAddr(), raddr.String(), string(buf[:num]))
	return num, err
}

func (conn *connection) LocalAddr() net.Addr {
	return conn.baseConn.LocalAddr()
}

func (conn *connection) RemoteAddr() net.Addr {
	return conn.baseConn.RemoteAddr()
}

func (conn *connection) Close() error {
	err := conn.baseConn.Close()
	if err != nil {
		return utils.NewError(err, conn.logKey, "close", conn.baseConn.LocalAddr().String(), conn.baseConn.RemoteAddr().String())
	}
	return nil
}

func (conn *connection) Network() string {
	return strings.ToUpper(conn.baseConn.LocalAddr().Network())
}

func (conn *connection) SetDeadline(t time.Time) error {
	return conn.baseConn.SetDeadline(t)
}

func (conn *connection) SetReadDeadline(t time.Time) error {
	return conn.baseConn.SetReadDeadline(t)
}

func (conn *connection) SetWriteDeadline(t time.Time) error {
	return conn.baseConn.SetWriteDeadline(t)
}
