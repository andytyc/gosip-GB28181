package sip

import (
	"fmt"
	"strings"
	"time"

	"github.com/panjjo/gosip/utils"
)

// 包括指令集

// DefaultProtocol DefaultProtocol
var DefaultProtocol = "udp"

// DefaultSipVersion DefaultSipVersion
var DefaultSipVersion = "SIP/2.0"

// Port number
type Port uint16

// NewPort NewPort
func NewPort(port int) *Port {
	newPort := Port(port)
	return &newPort
}

// Clone clone
func (port *Port) Clone() *Port {
	if port == nil {
		return nil
	}
	newPort := *port
	return &newPort
}

func (port *Port) String() string {
	if port == nil {
		return ""
	}
	return fmt.Sprintf("%d", *port)
}

// Equals Equals
func (port *Port) Equals(other interface{}) bool {
	if p, ok := other.(*Port); ok {
		return Uint16PtrEq((*uint16)(port), (*uint16)(p))
	}

	return false
}

// MaybeString 包裹接口 | 实现的结构有: String,Port
type MaybeString interface {
	String() string
	Equals(other interface{}) bool
}

// String 存储字符串
type String struct {
	Str string
}

// String 读取字符串的值
func (str String) String() string {
	return str.Str
}

// Equals Sting之间的比较(比较的是存储的字符串值是否一样)
func (str String) Equals(other interface{}) bool {
	if v, ok := other.(String); ok {
		return str.Str == v.Str
	}

	return false
}

// ContentTypeSDP SDP contenttype
var ContentTypeSDP = ContentType("application/sdp")

// ContentTypeXML XML contenttype
var ContentTypeXML = ContentType("Application/MANSCDP+xml")

var (
	// CatalogXML 获取设备列表xml样式
	CatalogXML = `<?xml version="1.0"?>
<Query>
<CmdType>Catalog</CmdType>
<SN>17430</SN>
<DeviceID>%s</DeviceID>
</Query>
	`
	// RecordInfoXML 获取录像文件列表xml样式
	RecordInfoXML = `<?xml version="1.0"?>
<Query>
<CmdType>RecordInfo</CmdType>
<SN>17430</SN>
<DeviceID>%s</DeviceID>
<StartTime>%s</StartTime>
<EndTime>%s</EndTime>
<Secrecy>0</Secrecy>
<Type>time</Type>
</Query>
`
	// DeviceInfoXML 查询设备详情xml样式
	DeviceInfoXML = `<?xml version="1.0"?>
<Query>
<CmdType>DeviceInfo</CmdType>
<SN>17430</SN>
<DeviceID>%s</DeviceID>
</Query>
`
)

// GetDeviceInfoXML 获取设备详情指令
func GetDeviceInfoXML(id string) string {
	return fmt.Sprintf(DeviceInfoXML, id)
}

// GetCatalogXML 获取NVR下设备列表指令
func GetCatalogXML(id string) string {
	return fmt.Sprintf(CatalogXML, id)
}

// GetRecordInfoXML 获取录像文件列表指令
func GetRecordInfoXML(id string, start, end int64) string {
	return fmt.Sprintf(RecordInfoXML, id, time.Unix(start, 0).Format("2006-01-02T15:04:05"), time.Unix(end, 0).Format("2006-01-02T15:04:05"))
}

//RFC3261BranchMagicCookie RFC3261BranchMagicCookie
const RFC3261BranchMagicCookie = "z9hG4bK"

// GenerateBranch returns random unique branch ID.
func GenerateBranch() string {
	return strings.Join([]string{
		RFC3261BranchMagicCookie,
		utils.RandString(32),
	}, "")
}
