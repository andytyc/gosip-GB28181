package sip

import (
	"bytes"
	"fmt"
	"net"
)

/*
对 SIP消息Message 进行了基本声明和接口实现

-----------------

Message
SIP消息接口 介绍了常见的 SIP 消息 RFC 3261 - 7。
此接口, Request, Response 都是些了Message的接口
******************************************************************/

// MessageID MessageID
type MessageID string

// RequestMethod This is syntactic sugar around the string type, so make sure to use
// the Equals method rather than built-in equality, or you'll fall foul of case differences.
// If you're defining your own Method, uppercase is preferred but not compulsory.
type RequestMethod string

// It's nicer to avoid using raw strings to represent methods, so the following standard
// method names are defined here as constants for convenience.
const (
	INVITE   RequestMethod = "INVITE"
	ACK      RequestMethod = "ACK"
	CANCEL   RequestMethod = "CANCEL"
	BYE      RequestMethod = "BYE"
	REGISTER RequestMethod = "REGISTER"
	OPTIONS  RequestMethod = "OPTIONS"
	// SUBSCRIBE RequestMethod = "SUBSCRIBE"
	// NOTIFY  RequestMethod = "NOTIFY"
	// REFER   RequestMethod = "REFER"
	INFO    RequestMethod = "INFO"
	MESSAGE RequestMethod = "MESSAGE"
)

// Message introduces common SIP message RFC 3261 - 7.
//
// 消息介绍了常见的 SIP 消息 RFC 3261 - 7。
type Message interface {
	MessageID() MessageID

	Clone() Message
	// Start line returns message start line.
	StartLine() string
	// String returns string representation of SIP message in RFC 3261 form.
	String() string
	// SipVersion returns SIP protocol version.
	SipVersion() string
	// SetSipVersion sets SIP protocol version.
	SetSipVersion(version string)

	// Headers returns all message headers.
	Headers() []Header
	// GetHeaders returns slice of headers of the given type.
	GetHeaders(name string) []Header
	// AppendHeader appends header to message.
	AppendHeader(header Header)
	// PrependHeader prepends header to message.
	RemoveHeader(name string)

	// Body returns message body.
	Body() string
	// SetBody sets message body.
	SetBody(body string, setContentLength bool)

	/* Helper getters for common headers */
	// CallID returns 'Call-ID' header.
	CallID() (*CallID, bool)
	// Via returns the top 'Via' header field.
	Via() (ViaHeader, bool)
	// ViaHop returns the first segment of the top 'Via' header.
	ViaHop() (*ViaHop, bool)
	// From returns 'From' header field.
	From() (*FromHeader, bool)
	// To returns 'To' header field.
	To() (*ToHeader, bool)
	// CSeq returns 'CSeq' header field.
	CSeq() (*CSeq, bool)
	ContentLength() (*ContentLength, bool)
	ContentType() (*ContentType, bool)
	Contact() (*ContactHeader, bool)

	Transport() string
	Source() net.Addr
	SetSource(src net.Addr)
	Destination() net.Addr
	SetDestination(dest net.Addr)

	IsCancel() bool
	IsAck() bool
}

type message struct {
	// message headers
	*headers
	messID       MessageID
	sipVersion   string
	body         string
	source, dest net.Addr
	startLine    func() string
}

// MessageID MessageID
func (msg *message) MessageID() MessageID {
	return msg.messID
}

// StartLine StartLine
func (msg *message) StartLine() string {
	return msg.startLine()
}

func (msg *message) String() string {
	var buffer bytes.Buffer

	// write message start line
	buffer.WriteString(msg.StartLine() + "\r\n")
	// Write the headers.
	buffer.WriteString(msg.headers.String())
	// message body
	buffer.WriteString("\r\n" + msg.Body())

	return buffer.String()
}

// SipVersion SipVersion
func (msg *message) SipVersion() string {
	return msg.sipVersion
}

// SetSipVersion SetSipVersion
func (msg *message) SetSipVersion(version string) {
	msg.sipVersion = version
}

// Body Body
func (msg *message) Body() string {
	return msg.body
}

// SetBody sets message body, calculates it length and add 'Content-Length' header.
func (msg *message) SetBody(body string, setContentLength bool) {
	msg.body = body
	if setContentLength {
		hdrs := msg.GetHeaders("Content-Length")
		if len(hdrs) == 0 {
			length := ContentLength(len(body))
			msg.AppendHeader(&length)
		} else {
			length := ContentLength(len(body))
			hdrs[0] = &length
		}
	}
}

//Transport  Transport
func (msg *message) Transport() string {
	if viaHop, ok := msg.ViaHop(); ok {
		return viaHop.Transport
	}
	return DefaultProtocol
}

// Source Source
func (msg *message) Source() net.Addr {
	return msg.source
}

// SetSource SetSource
func (msg *message) SetSource(src net.Addr) {
	msg.source = src
}

// Destination Destination
func (msg *message) Destination() net.Addr {
	return msg.dest
}

// SetDestination SetDestination
func (msg *message) SetDestination(dest net.Addr) {
	msg.dest = dest
}

// URI  A SIP or SIPS URI, including all params and URI header params.
//
// URI SIP 或 SIPS URI，包括所有参数和 URI 标头参数。
//noinspection GoNameStartsWithPackageName
//
// 格式:
// sip/sips : user[:password] @ IP[:Port]/Demain [;key=val;key=val] [?key=val&key=val]
//
// sip:34020000002000000001@192.168.0.66:5060
// sip:34020000002000000001@3402000000
// sips:34020000002000000001@3402000000
// sip:34020000002000000001:123346@3402000000
// sip:34020000002000000001:123346@192.168.0.66:5060
// sips:34020000002000000001:123346@192.168.0.66:5060;type=12;
// sips:34020000002000000001:123346@192.168.0.66:5060?type=12;
//
// URI 解析方法见 sip.parser.go 的
// func ParseURI(uriStr string) (uri *URI, err error) {
// func ParseSipURI(uriStr string) (uri URI, err error) {
// func ParseParams(){}
type URI struct {
	// URI 是否传输加密
	//
	// True if and only if the URI is a SIPS URI.
	// 当且仅当 URI 是 SIPS URI 时为真。
	FIsEncrypted bool

	// URI 的用户部分, 通常会是用户ID(编号)
	//
	// The user part of the URI: the 'joe' in sip:joe@bloggs.com
	// This is a pointer, so that URIs without a user part can have 'nil'.
	//
	// URI 的用户部分：sip:joe@bloggs.com 中的 'joe'
	// 这是一个指针，因此没有用户部分的 URI 可以有 'nil'。
	FUser MaybeString

	// URI 的密码字段, 可选
	//
	// The password field of the URI. This is represented in the URI as joe:hunter2@bloggs.com.
	// Note that if a URI has a password field, it *must* have a user field as well.
	// This is a pointer, so that URIs without a password field can have 'nil'.
	// Note that RFC 3261 strongly recommends against the use of password fields in SIP URIs,
	// as they are fundamentally insecure.
	//
	// URI 的密码字段。 这在 URI 中表示为 joe:hunter2@bloggs.com。
	// 请注意，如果 URI 有密码字段，它*必须*也有用户字段。
	// 这是一个指针，因此没有密码字段的 URI 可以有 'nil'。
	// 请注意，RFC 3261 强烈建议不要在 SIP URI 中使用密码字段，因为它们根本不安全。
	FPassword MaybeString

	// URI 的主机部分
	//
	// The host part of the URI. This can be a domain, or a string representation of an IP address.
	//
	// URI 的主机部分。这可以是域，也可以是 IP 地址的字符串表示形式。
	FHost string

	// URI 的端口部分, 可选
	//
	// The port part of the URI. This is optional, and so is represented here as a pointer type.
	//
	// URI 的端口部分。这是可选的，因此这里表示为指针类型。
	FPort *Port

	// 与 URI 关联的任何参数, 可选
	//
	// Any parameters associated with the URI.
	// These are used to provide information about requests that may be constructed from the URI.
	// (For more details, see RFC 3261 section 19.1.1).
	// These appear as a semicolon-separated list of key=value pairs following the host[:port] part.
	//
	// 与 URI 关联的任何参数。
	// 这些用于提供有关可能从 URI 构造的请求的信息。
	//（有关更多详细信息，请参阅 RFC 3261 第 19.1.1 节）。
	// 这些以分号分隔的 key=value 对列表的形式出现在 host[:port] 部分之后。
	//
	// 规则: ;开头 ;分隔 ?结尾
	//
	// 解析方法见 sip.parser.go 的
	// func ParseParams(){}
	FUriParams Params

	// URI 构造的请求中的任何标头, 可选
	//
	// Any headers to be included on requests constructed from this URI.
	// These appear as a '&'-separated list at the end of the URI, introduced by '?'.
	// Although the values of the map are MaybeStrings, they will never be NoString in practice as the parser
	// guarantees to not return blank values for header elements in SIP URIs.
	// You should not set the values of headers to NoString.
	//
	// 要包含在从此 URI 构造的请求中的任何标头。
	// 这些在 URI 末尾显示为一个以 '&' 分隔的列表，由 '?' 引入。
	// 虽然映射的值是 MaybeStrings，但实际上它们永远不会是 NoString，因为解析器保证不会为 SIP URI 中的标头元素返回空白值。
	// 您不应将标头的值设置为 NoString。
	//
	// 规则: ?开头 &分隔 没有结尾符合
	//
	// 解析方法见 sip.parser.go 的
	// func ParseParams(){}
	FHeaders Params
}

// User User
func (uri *URI) User() MaybeString {
	return uri.FUser
}

// Host Host
func (uri *URI) Host() string {
	return uri.FHost
}

// SetHost SetHost
func (uri *URI) SetHost(host string) {
	uri.FHost = host
}

// Generates the string representation of a SipUri struct.
func (uri *URI) String() string {
	var buffer bytes.Buffer

	// Compulsory protocol identifier.
	if uri.FIsEncrypted {
		buffer.WriteString("sips")
		buffer.WriteString(":")
	} else {
		buffer.WriteString("sip")
		buffer.WriteString(":")
	}

	// Optional userinfo part.
	if user, ok := uri.FUser.(String); ok && user.String() != "" {
		buffer.WriteString(uri.FUser.String())
		if pass, ok := uri.FPassword.(String); ok && pass.String() != "" {
			buffer.WriteString(":")
			buffer.WriteString(pass.String())
		}
		buffer.WriteString("@")
	}

	// Compulsory hostname.
	buffer.WriteString(uri.FHost)

	// Optional port number.
	if uri.FPort != nil {
		buffer.WriteString(fmt.Sprintf(":%d", *uri.FPort))
	}

	if (uri.FUriParams != nil) && uri.FUriParams.Length() > 0 {
		buffer.WriteString(";")
		buffer.WriteString(uri.FUriParams.ToString(';'))
	}

	if (uri.FHeaders != nil) && uri.FHeaders.Length() > 0 {
		buffer.WriteString("?")
		buffer.WriteString(uri.FHeaders.ToString('&'))
	}

	return buffer.String()
}

// Clone the Sip URI.
func (uri *URI) Clone() *URI {
	var newURI *URI
	if uri == nil {
		return newURI
	}

	newURI = &URI{
		FIsEncrypted: uri.FIsEncrypted,
		FUser:        uri.FUser,
		FPassword:    uri.FPassword,
		FHost:        uri.FHost,
		FUriParams:   cloneWithNil(uri.FUriParams),
		FHeaders:     cloneWithNil(uri.FHeaders),
	}
	if uri.FPort != nil {
		newURI.FPort = uri.FPort.Clone()
	}
	return newURI
}

// Equals Determine if the SIP URI is equal to the specified URI according to the rules laid down in RFC 3261 s. 19.1.4.
// TODO: The Equals method is not currently RFC-compliant; fix this!
func (uri *URI) Equals(val interface{}) bool {
	otherPtr, ok := val.(*URI)
	if !ok {
		return false
	}

	if uri == otherPtr {
		return true
	}
	if uri == nil && otherPtr != nil || uri != nil && otherPtr == nil {
		return false
	}

	other := *otherPtr
	result := uri.FIsEncrypted == other.FIsEncrypted &&
		uri.FUser == other.FUser &&
		uri.FPassword == other.FPassword &&
		uri.FHost == other.FHost &&
		Uint16PtrEq((*uint16)(uri.FPort), (*uint16)(other.FPort))

	if !result {
		return false
	}

	if uri.FUriParams != otherPtr.FUriParams {
		if uri.FUriParams == nil {
			result = result && otherPtr.FUriParams != nil
		} else {
			result = result && uri.FUriParams.Equals(otherPtr.FUriParams)
		}
	}

	if uri.FHeaders != otherPtr.FHeaders {
		if uri.FHeaders == nil {
			result = result && otherPtr.FHeaders != nil
		} else {
			result = result && uri.FHeaders.Equals(otherPtr.FHeaders)
		}
	}

	return result
}

func cloneWithNil(params Params) Params {
	if params == nil {
		return NewParams()
	}
	return params.Clone()
}
