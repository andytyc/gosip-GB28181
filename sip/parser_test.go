package sip

import (
	"testing"
)

func Test_isRequest(t *testing.T) {
	startLine := "REGISTER sip:34020000002000000001@192.168.0.66:5060 SIP/2.0"
	ok := isRequest(startLine)
	t.Log("ok :", ok)
}

func TestParseRequestLine(t *testing.T) {
	startLine := "REGISTER sip:34020000002000000001@192.168.0.66:5060 SIP/2.0"
	method, recipient, sipVersion, err := ParseRequestLine(startLine)
	if err != nil {
		t.Fatal("err :", err)
	}
	t.Log("method :", method, "recipient :", recipient, "sipVersion :", sipVersion)
}

func Test_isResponse(t *testing.T) {
	startLine := "SIP/2.0 401 Unauthorized"
	ok := isResponse(startLine)
	t.Log("ok :", ok)
}

func TestParseStatusLine(t *testing.T) {
	startLine := "SIP/2.0 401 Unauthorized"
	sipVersion, statusCode, reasonPhrase, err := ParseStatusLine(startLine)
	if err != nil {
		t.Fatal("err :", err)
	}
	t.Log("sipVersion :", sipVersion, "statusCode :", statusCode, "reasonPhrase :", reasonPhrase)
}
