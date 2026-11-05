package proxyfront

import (
	"net"
	"testing"
)

func TestPrivateClient(t *testing.T) {
	for addr, want := range map[string]bool{"10.1.1.5:1": true, "192.168.1.9:2": true, "127.0.0.1:3": true, "203.0.113.7:4": false, "[::ffff:10.0.0.1]:5": true, "[2001:db8::1]:6": false} {
		a, _ := net.ResolveTCPAddr("tcp", addr)
		if privateClient(a) != want {
			t.Errorf("%s: want %v", addr, want)
		}
	}
}
