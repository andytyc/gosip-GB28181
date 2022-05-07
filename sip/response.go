package sip

import (
	"bytes"
	"fmt"
	"strings"

	"github.com/gofrs/uuid"
)

/*
实现了SIP消息Message接口 的回复

-----------------

Response
处理回复概念的消息
******************************************************************/

// Response 发送/回复消息 | 实现了SIP消息Message接口 | 我方主动发送消息 或 对方请求我们进行回复消息给对方
type Response struct {
	message
	statusCode int
	reason     string
}

// NewResponseFromRequest | 实现了SIP消息Message接口 | 根据对方请求回复给对方消息
func NewResponseFromRequest(
	resID MessageID,
	req *Request,
	statusCode int,
	reason string,
	body string,
) *Response {
	res := NewResponse(
		resID,
		req.SipVersion(),
		statusCode,
		reason,
		[]Header{},
		"",
	)

	CopyHeaders("Record-Route", req, res)
	CopyHeaders("Via", req, res)
	CopyHeaders("From", req, res)
	CopyHeaders("To", req, res)
	CopyHeaders("Call-ID", req, res)
	CopyHeaders("CSeq", req, res)

	if statusCode == 100 {
		CopyHeaders("Timestamp", req, res)
	}

	res.SetSource(req.Destination())
	res.SetDestination(req.Source())

	if len(body) > 0 {
		res.SetBody(body, true)
	}

	return res
}

// NewResponse | 实现了SIP消息Message接口 | 我方主动发送消息
func NewResponse(
	messID MessageID,
	sipVersion string,
	statusCode int,
	reason string,
	hdrs []Header,
	body string,
) *Response {
	res := new(Response)
	if messID == "" {
		res.messID = MessageID(uuid.Must(uuid.NewV4()).String())
	} else {
		res.messID = messID
	}
	res.startLine = res.StartLine
	res.SetSipVersion(sipVersion)
	res.headers = newHeaders(hdrs)
	res.SetStatusCode(statusCode)
	res.SetReason(reason)

	if strings.TrimSpace(body) != "" {
		res.SetBody(body, true)
	}

	return res
}

// Reason Reason
func (res *Response) Reason() string {
	return res.reason
}

// SetReason SetReason
func (res *Response) SetReason(reason string) {
	res.reason = reason
}

// SetStatusCode SetStatusCode
func (res *Response) SetStatusCode(code int) {
	res.statusCode = code
}

// StatusCode StatusCode
func (res *Response) StatusCode() int {
	return res.statusCode
}

// StartLine returns Response Status Line - RFC 2361 7.2.
func (res *Response) StartLine() string {
	var buffer bytes.Buffer

	// Every SIP response starts with a Status Line - RFC 2361 7.2.
	buffer.WriteString(
		fmt.Sprintf(
			"%s %d %s",
			res.SipVersion(),
			res.StatusCode(),
			res.Reason(),
		),
	)

	return buffer.String()
}

// Clone Clone
func (res *Response) Clone() Message {
	return NewResponse(
		"",
		res.SipVersion(),
		res.StatusCode(),
		res.Reason(),
		res.headers.CloneHeaders(),
		res.Body(),
	)
}

// IsAck IsAck
func (res *Response) IsAck() bool {
	if cseq, ok := res.CSeq(); ok {
		return cseq.MethodName == ACK
	}
	return false
}

// IsCancel IsCancel
func (res *Response) IsCancel() bool {
	if cseq, ok := res.CSeq(); ok {
		return cseq.MethodName == CANCEL
	}
	return false
}
