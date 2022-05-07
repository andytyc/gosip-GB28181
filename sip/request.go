package sip

import (
	"bytes"
	"fmt"
	"net"
	"strings"

	"github.com/gofrs/uuid"
)

/*
实现了SIP消息Message接口 的请求

-----------------

Request
处理请求概念的消息
******************************************************************/

// Request 请求消息 | 实现了SIP消息Message接口
type Request struct {
	message   // 包含message结构,注意: 有重复方法的则是Request的(重写了),否则是message的方法
	method    RequestMethod
	recipient *URI
}

// NewRequest 创建一个请求对象 | 实现了SIP消息Message接口 | 对方请求 或 我方请求
func NewRequest(
	messID MessageID,
	method RequestMethod,
	recipient *URI,
	sipVersion string,
	hdrs []Header,
	body string,
) *Request {
	req := new(Request)
	if messID == "" {
		req.messID = MessageID(uuid.Must(uuid.NewV4()).String())
	} else {
		req.messID = messID
	}
	req.SetSipVersion(sipVersion)
	req.startLine = req.StartLine
	req.headers = newHeaders(hdrs)
	req.SetMethod(method)
	req.SetRecipient(recipient)

	if strings.TrimSpace(body) != "" {
		req.SetBody(body, true)
	}
	return req
}

// NewRequestFromResponse 创建一个请求对象 | 实现了SIP消息Message接口 | 根据对方响应进行请求
func NewRequestFromResponse(method RequestMethod, inviteResponse *Response) *Request {
	contact, _ := inviteResponse.Contact()
	ackRequest := NewRequest(
		inviteResponse.MessageID(),
		method,
		contact.Address,
		inviteResponse.SipVersion(),
		[]Header{},
		"",
	)

	CopyHeaders("Via", inviteResponse, ackRequest)
	viaHop, _ := ackRequest.ViaHop()
	// update branch, 2xx ACK is separate Tx
	viaHop.Params.Add("branch", String{Str: GenerateBranch()})

	if len(inviteResponse.GetHeaders("Route")) > 0 {
		CopyHeaders("Route", inviteResponse, ackRequest)
	} else {
		for _, h := range inviteResponse.GetHeaders("Record-Route") {
			uris := make([]*URI, 0)
			for _, u := range h.(*RecordRouteHeader).Addresses {
				uris = append(uris, u.Clone())
			}
			ackRequest.AppendHeader(&RouteHeader{
				Addresses: uris,
			})
		}
	}

	CopyHeaders("From", inviteResponse, ackRequest)
	CopyHeaders("To", inviteResponse, ackRequest)
	CopyHeaders("Call-ID", inviteResponse, ackRequest)
	cseq, _ := inviteResponse.CSeq()
	cseq.MethodName = method
	cseq.SeqNo++
	ackRequest.AppendHeader(cseq)
	ackRequest.SetSource(inviteResponse.Destination())
	ackRequest.SetDestination(inviteResponse.Source())
	return ackRequest
}

// StartLine returns Request Line - RFC 2361 7.1.
func (req *Request) StartLine() string {
	var buffer bytes.Buffer

	// Every SIP request starts with a Request Line - RFC 2361 7.1.
	buffer.WriteString(
		fmt.Sprintf(
			"%s %s %s",
			string(req.method),
			req.Recipient(),
			req.SipVersion(),
		),
	)

	return buffer.String()
}

// Method Method
func (req *Request) Method() RequestMethod {
	return req.method
}

// SetMethod SetMethod
func (req *Request) SetMethod(method RequestMethod) {
	req.method = method
}

// Recipient Recipient
func (req *Request) Recipient() *URI {
	return req.recipient
}

// SetRecipient SetRecipient
func (req *Request) SetRecipient(recipient *URI) {
	req.recipient = recipient
}

// IsInvite IsInvite
func (req *Request) IsInvite() bool {
	return req.Method() == INVITE
}

// IsAck IsAck
func (req *Request) IsAck() bool {
	return req.Method() == ACK
}

// IsCancel IsCancel
func (req *Request) IsCancel() bool {
	return req.Method() == CANCEL
}

// Source Source
func (req *Request) Source() net.Addr {
	return req.source
}

// SetSource SetSource
func (req *Request) SetSource(src net.Addr) {
	req.source = src
}

// Destination Destination
func (req *Request) Destination() net.Addr {
	return req.dest
}

// SetDestination SetDestination
func (req *Request) SetDestination(dest net.Addr) {
	req.dest = dest
}

// Clone Clone
func (req *Request) Clone() Message {
	return NewRequest(
		"",
		req.Method(),
		req.Recipient().Clone(),
		req.SipVersion(),
		req.headers.CloneHeaders(),
		req.Body(),
	)
}
