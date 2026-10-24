package panel

import (
	"slices"
	"testing"
)

// Example from Alibaba Cloud's signature documentation.
func TestAliSign(t *testing.T) {
	_, sig := aliSign(map[string]string{
		"Format": "XML", "AccessKeyId": "testid", "Action": "DescribeDomainRecords", "SignatureMethod": "HMAC-SHA1",
		"DomainName": "example.com", "SignatureNonce": "f59ed6a9-83fc-473b-9cc6-99c95df3856e", "SignatureVersion": "1.0",
		"Version": "2015-01-09", "Timestamp": "2016-03-24T16:41:54Z",
	}, "testsecret")
	if sig != "uRpHwaSEt3J+6KQD//svCh/x+pI=" {
		t.Errorf("signature %s", sig)
	}
}

func TestZones(t *testing.T) {
	if z := zoneCandidates("a.b.example.com"); !slices.Equal(z, []string{"example.com", "b.example.com", "a.b.example.com"}) {
		t.Errorf("%v", z)
	}
	if rrOf("proxy.example.com", "example.com") != "proxy" || rrOf("example.com", "example.com") != "@" || rrOf("a.b.example.com", "example.com") != "a.b" {
		t.Error("rr")
	}
	if ipInText("fl=1\nip=203.0.113.9\nts=1", false) != "203.0.113.9" || ipInText("2001:db8::1\n", true) != "2001:db8::1" || ipInText("2001:db8::1", false) != "" {
		t.Error("ipInText")
	}
	if publicIP("10.0.0.1") || publicIP("100.64.1.1") || !publicIP("203.0.113.7") {
		t.Error("publicIP")
	}
}
