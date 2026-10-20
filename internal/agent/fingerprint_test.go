package agent

import (
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
)

func bannerServer(t *testing.T, greeting []byte) (string, int) {
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
			_, _ = c.Write(greeting)
			c.Close()
		}
	}()
	a := ln.Addr().(*net.TCPAddr)
	return a.IP.String(), a.Port
}

func hostPort(t *testing.T, url string) (string, int) {
	h, p, _ := net.SplitHostPort(strings.TrimPrefix(strings.TrimPrefix(url, "https://"), "http://"))
	n, _ := strconv.Atoi(p)
	return h, n
}

func TestFingerprint(t *testing.T) {
	ip, port := bannerServer(t, []byte("SSH-2.0-OpenSSH_9.2p1 Debian-2\r\n"))
	if s := Fingerprint(ip, port); s.Service != "SSH" || !strings.Contains(s.Detail, "OpenSSH_9.2") {
		t.Errorf("ssh: %+v", s)
	}
	ip, port = bannerServer(t, []byte{0x4a, 0, 0, 0, 10, '8', '.', '0', '.', '3', '6', 0, 1, 2})
	if s := Fingerprint(ip, port); s.Service != "MySQL" {
		t.Errorf("mysql: %+v", s)
	}
	page := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "nginx/1.25")
		_, _ = w.Write([]byte("<html><title>Jellyfin</title></html>"))
	})
	hs := httptest.NewServer(page)
	defer hs.Close()
	if s := Fingerprint(hostPort(t, hs.URL)); !strings.HasPrefix(s.Service, "HTTP") || !strings.Contains(s.Detail, "nginx") || !strings.Contains(s.Detail, "Jellyfin") {
		t.Errorf("http: %+v", s)
	}
	ts := httptest.NewTLSServer(page)
	defer ts.Close()
	if s := Fingerprint(hostPort(t, ts.URL)); !strings.HasPrefix(s.Service, "HTTPS") || !s.TLS {
		t.Errorf("https: %+v", s)
	}
	if _, err := fingerprintReq(DiagReq{Target: "8.8.8.8", Port: 22}); err == nil {
		t.Error("public target accepted")
	}
}
