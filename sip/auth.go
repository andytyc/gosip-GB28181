package sip

import (
	"crypto/md5"
	"encoding/hex"
	"fmt"
	"regexp"
)

/*
处理注册的授权(Auth), 这是SIP协议独有的通用处理机制

-----------------

******************************************************************/

// Authorization currently only Digest and MD5
//
// Authorization 授权目前只有Digest(SIP摘要鉴权算法)和MD5, 并记录所有的授权信息
type Authorization struct {
	// realm 一般是指sip帐号所在哪个域范围中，比如你是在河北域中，还是在河南域中，这个和IMS中明确定义的归属网络、拜访网络的概念非常类似
	//
	// 在前期SIP标准刚开始的那个时期，一些软交换厂商对终端的realm有严格限制，因为我们知道最常见的SIP摘要鉴权算法会使用realm做为参数项进行
	// 安全验证，这样如果终端的realm设置不正确，会导致验证响应值错误，而被软交换所拒绝。
	//
	// 注意:
	//
	// 但后期随着协议栈的完善，realm值已经不在需要终端配置，直接自动从软交换回应
	// 的401中取得正确的realm进行摘要鉴权算法参与，所以realm慢慢地被我们所忽略。
	realm string
	// nonce 随机数
	nonce string
	// algorithm 算法类型, eg: MD5
	algorithm string
	// username client用户名, 一般就是DeviceID
	username string
	// password client密嘛
	password string
	// uri 如: sip:192.168.0.1:5060
	uri      string
	response string
	method   string
	// other 记录非预期的key:value, 除了 realm, nonce, algorithm 以外的键值对
	other map[string]string
	// Data 记录所有的key:value, 包括:realm, nonce, algorithm 等键值对, 即: 存储所有的授权信息
	Data map[string]string
}

// AuthFromValue 根据 Authorization 请求头的值value,进行授权信息解析整理,然后返回授权对象
func AuthFromValue(value string) *Authorization {
	auth := &Authorization{
		algorithm: "MD5",
		other:     make(map[string]string),
		Data:      make(map[string]string),
	}

	re := regexp.MustCompile(`([\w]+)="([^"]+)"`)
	matches := re.FindAllStringSubmatch(value, -1)
	for _, match := range matches {

		switch match[1] {
		case "realm":
			auth.realm = match[2]
		case "algorithm":
			auth.algorithm = match[2]
		case "nonce":
			auth.nonce = match[2]
		default:
			auth.other[match[1]] = match[2]
		}
		auth.Data[match[1]] = match[2]
	}

	return auth
}

// Get 获取授权信息中某个key对应的value值
func (auth *Authorization) Get(key string) string {
	return auth.Data[key]
}

// SetUsername SetUsername
func (auth *Authorization) SetUsername(username string) *Authorization {
	auth.username = username

	return auth
}

// SetURI SetURI
func (auth *Authorization) SetURI(uri string) *Authorization {
	auth.uri = uri

	return auth
}

// SetMethod SetMethod
func (auth *Authorization) SetMethod(method string) *Authorization {
	auth.method = method

	return auth
}

// SetPassword SetPassword
func (auth *Authorization) SetPassword(password string) *Authorization {
	auth.password = password

	return auth
}

// CalcResponse CalcResponse
func (auth *Authorization) CalcResponse() string {
	auth.response = CalcResponse(
		auth.username,
		auth.realm,
		auth.password,
		auth.method,
		auth.uri,
		auth.nonce,
	)

	return auth.response
}

func (auth *Authorization) String() string {
	return fmt.Sprintf(
		`Digest realm="%s",algorithm=%s,nonce="%s",username="%s",uri="%s",response="%s"`,
		auth.realm,
		auth.algorithm,
		auth.nonce,
		auth.username,
		auth.uri,
		auth.response,
	)
}

/*
******************************************************************/

// CalcResponse calculates Authorization response https://www.ietf.org/rfc/rfc2617.txt
//
// CalcResponse 计算授权响应 https://www.ietf.org/rfc/rfc2617.txt
func CalcResponse(username string, realm string, password string, method string, uri string, nonce string) string {
	calcA1 := func() string {
		encoder := md5.New()
		encoder.Write([]byte(username + ":" + realm + ":" + password)) // 规则

		return hex.EncodeToString(encoder.Sum(nil)) // 生成一个md5
	}
	calcA2 := func() string {
		encoder := md5.New()
		encoder.Write([]byte(method + ":" + uri)) // 规则

		return hex.EncodeToString(encoder.Sum(nil)) // 生成一个md5
	}

	encoder := md5.New()
	encoder.Write([]byte(calcA1() + ":" + nonce + ":" + calcA2())) // 规则

	return hex.EncodeToString(encoder.Sum(nil)) // 生成一个md5
}
