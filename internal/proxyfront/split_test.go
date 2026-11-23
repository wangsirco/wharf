package proxyfront

import (
	"crypto/tls"
	"io"
	"net"
	"testing"
	"time"
)

// TestSplit: the panel's names reach the panel (with a PROXY header), the rest the router page.
func TestSplit(t *testing.T) {
	got := make(chan string, 4)
	listen := func(tag string) string {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { ln.Close() })
		go func() {
			for {
				c, err := ln.Accept()
				if err != nil {
					return
				}
				b := make([]byte, 12)
				_, _ = io.ReadFull(c, b)
				if string(b) == "\r\n\r\n\x00\r\nQUIT\n" {
					got <- tag + "+proxy"
				} else {
					got <- tag
				}
				c.Close()
			}
		}()
		return ln.Addr().String()
	}
	s := &Split{Panel: listen("panel"), Other: listen("luci")}
	s.SetNames([]string{"wharf.lan", "Wharf.Example.com"})
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	defer ln.Close()
	go s.Serve(ln)
	for name, want := range map[string]string{"wharf.lan": "panel+proxy", "wharf.example.com": "panel+proxy", "other.lan": "luci", "": "luci"} {
		c, err := net.Dial("tcp", ln.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		tc := tls.Client(c, &tls.Config{ServerName: name, InsecureSkipVerify: true})
		_ = tc.SetDeadline(time.Now().Add(2 * time.Second))
		go func() { _ = tc.Handshake() }()
		select {
		case g := <-got:
			if g != want {
				t.Errorf("%q went to %s, want %s", name, g, want)
			}
		case <-time.After(3 * time.Second):
			t.Errorf("%q: nothing arrived", name)
		}
		c.Close()
	}
}
