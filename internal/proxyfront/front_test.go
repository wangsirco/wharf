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

func TestRouteWildcard(t *testing.T) {
	f := &front{routes: map[string]Route{"node.example.net": {Backend: "n"}, "*.home.example.net": {Backend: "b"}}}
	for name, want := range map[string]string{"node.example.net": "n", "vault.home.example.net": "b", "a.b.home.example.net": "", "home.example.net": ""} {
		r, ok := f.route(name)
		if (want == "") == ok || r.Backend != want {
			t.Errorf("%s → %q %v", name, r.Backend, ok)
		}
	}
}
