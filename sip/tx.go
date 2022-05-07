package sip

import (
	"net/http"
	"sync"
	"time"

	"github.com/panjjo/gosip/utils"
	"github.com/sirupsen/logrus"
)

/*
处理 "同一个CallID" 下的多个数据报文交互，这种叫做: Transaction(合同: 处理某一个具体的事件, 比如: 请求视频流建立会话INVITE)

-----------------
transacionts
管理不同key(也就是callid)的合同, {callid : 合同tx}

Transaction
缩写: tx/TX
注解: key其实就是callid, 合同: 也就是"callid相同"的多个数据报文，都是一个合同交互，属于同一个合同
******************************************************************/

// activeTX 内存已激活合同映射表 key=key value=Transaction 其中的key其实就是callid
var activeTX *transacionts

/*
******************************************************/

// transacionts 管理不同key(也就是callid)的合同, {callid : 合同tx}
//
// newTX key其实就是callid, 合同: 也就是"callid相同"的多个数据报文，都是一个合同交互，属于同一个合同
type transacionts struct {
	txs map[string]*Transaction
	rwm *sync.RWMutex
}

// newTX key其实就是callid, 合同: 也就是"callid相同"的多个数据报文，都是一个合同交互，属于同一个合同
func (txs *transacionts) newTX(key string, conn Connection) *Transaction {
	tx := NewTransaction(key, conn)
	txs.rwm.Lock()
	txs.txs[key] = tx
	txs.rwm.Unlock()
	return tx
}

// getTX key其实就是callid, 合同: 也就是"callid相同"的多个数据报文，都是一个合同交互，属于同一个合同
func (txs *transacionts) getTX(key string) *Transaction {
	txs.rwm.RLock()
	tx, ok := txs.txs[key]
	if !ok {
		tx = nil
	}
	txs.rwm.RUnlock()
	return tx
}

// rmTX key其实就是callid, 合同: 也就是"callid相同"的多个数据报文，都是一个合同交互，属于同一个合同
func (txs *transacionts) rmTX(tx *Transaction) {
	txs.rwm.Lock()
	delete(txs.txs, tx.key)
	txs.rwm.Unlock()
}

/*
******************************************************/

// Transaction 交易/合约/交互, 简称:合同 | 用于数据报文的交互
//
// key其实就是callid, 合同: 也就是"callid相同"的多个数据报文，都是一个合同交互，属于同一个合同
type Transaction struct {
	// conn 连接实例对象
	conn Connection
	// key 其实就是callid
	key string
	// resp 收到消息队列
	resp chan *Response
	// active 连接激活队列, 触发激活的动作有以下几种,假如在20s内没有触发,则关闭conn连接对象
	//
	// 1: 接收到对方的回复消息到队列
	// 2: 从队列读取了对方的回复消息
	active chan int
}

// NewTransaction 新建合约
func NewTransaction(key string, conn Connection) *Transaction {
	logrus.Traceln("new tx", key, time.Now().Format("2006-01-02 15:04:05"))
	tx := &Transaction{conn: conn, key: key, resp: make(chan *Response, 10), active: make(chan int, 1)} // active队列会在watch立刻触发,所以长度1个够用
	go tx.watch()
	return tx
}

// Key 查询
func (tx *Transaction) Key() string {
	return tx.key
}

// watch 监听激活
func (tx *Transaction) watch() {
	for {
		select {
		case <-tx.active:
			logrus.Traceln("active tx", tx.Key(), time.Now().Format("2006-01-02 15:04:05"))
		case <-time.After(20 * time.Second):
			tx.Close()
			logrus.Traceln("watch closed tx", tx.key, time.Now().Format("2006-01-02 15:04:05"))
			return
		}
	}
}

// Close 关闭合同
func (tx *Transaction) Close() {
	logrus.Traceln("closed tx", tx.key, time.Now().Format("2006-01-02 15:04:05"))
	activeTX.rmTX(tx)
	close(tx.resp)
	close(tx.active)
}

// GetResponse 读取了对方的回复消息,从队列中读取,触发一次激活
//
// 注意: 假如对方没有回复消息(或者很久一直没回复,回复很慢超时),那么阻塞等待超时时间为20s
func (tx *Transaction) GetResponse() *Response {
	for {
		res := <-tx.resp
		if res == nil {
			return res
		}
		tx.active <- 2
		logrus.Traceln("response tx", tx.key, time.Now().Format("2006-01-02 15:04:05"))
		if res.StatusCode() == http.StatusContinue || res.statusCode == http.StatusSwitchingProtocols {
			// Trying(100) and Dialog Establishement(101: 对话建立) 等待下一个返回
			continue
		}
		return res
	}
}

// Response 接收对方的回复消息,写入到队列等待读取,触发一次激活
func (tx *Transaction) receiveResponse(msg *Response) {
	defer func() {
		if r := recover(); r != nil {
			logrus.Errorln("send to closed channel, txkey:", tx.key, "message: \n", msg.String())
		}
	}()
	logrus.Traceln("receiveResponse tx", tx.Key(), time.Now().Format("2006-01-02 15:04:05"))
	tx.resp <- msg
	tx.active <- 1
}

// Respond 回复消息 将res消息发送出去 -> res.dest, callid就是tx.key
func (tx *Transaction) Respond(res *Response) error {
	logrus.Traceln("send response,to:", res.dest.String(), "txkey:", tx.key, "message: \n", res.String())
	_, err := tx.conn.WriteTo([]byte(res.String()), res.dest)
	return err
}

// Request 请求消息 将req消息发送出去 -> req.dest, callid就是tx.key
func (tx *Transaction) Request(req *Request) error {
	logrus.Traceln("send request,to:", req.dest.String(), "txkey:", tx.key, "message: \n", req.String())
	_, err := tx.conn.WriteTo([]byte(req.String()), req.dest)
	return err
}

/*
******************************************************************/

// getTXKey 获取消息(Message)中的callid, 也就是合同tx的key
func getTXKey(msg Message) (key string) {
	callid, ok := msg.CallID()
	if ok {
		key = callid.String()
	} else {
		key = utils.RandString(10)
	}
	return
}
