package agent

import (
	"bytes"
	"crypto/tls"
	"errors"
	"net"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// Fingerprint identifies what a port-forward target actually runs: protocols that speak
// first (SSH, FTP, SMTP, VNC, MySQL…) are read from their banner; otherwise HTTP, TLS
// (then HTTP inside it) and RDP are tried. Only used on LAN targets of port forwards.

type ServiceInfo struct {
	Service string `json:"service"`          // SSH, HTTP, HTTPS, RDP, …; "" = unknown
	Detail  string `json:"detail,omitempty"` // banner / server header / title
	TLS     bool   `json:"tls,omitempty"`
	CertCN  string `json:"cert_cn,omitempty"`
	Open    bool   `json:"open"`
	Error   string `json:"error,omitempty"`

	plainToTLS bool
	server     string
}

func firstNonEmptyStr(v ...string) string {
	for _, s := range v {
		if s != "" {
			return s
		}
	}
	return ""
}

var titleRe = regexp.MustCompile(`(?is)<title[^>]*>\s*([^<]{1,120})`)

func Fingerprint(ip string, port int) ServiceInfo {
	addr := net.JoinHostPort(ip, strconv.Itoa(port))
	c, err := net.DialTimeout("tcp", addr, 2*time.Second)
	if err != nil {
		if strings.Contains(err.Error(), "refused") {
			return ServiceInfo{Error: "端口没有在监听（连接被拒绝）：设备上的服务可能没开"}
		}
		return ServiceInfo{Error: "连不上目标设备（离线或防火墙拦截）"}
	}
	info := ServiceInfo{Open: true}
	_ = c.SetReadDeadline(time.Now().Add(1500 * time.Millisecond))
	buf := make([]byte, 1024)
	n, _ := c.Read(buf)
	c.Close()
	if n > 0 {
		if s := banner(buf[:n]); s.Service != "" {
			s.Open = true
			return s
		}
	}
	if port == 3389 || port == 3388 {
		if rdp(addr) {
			return ServiceInfo{Service: "RDP", Detail: "Windows 远程桌面", Open: true}
		}
	}
	if s, ok := httpProbe(addr, nil); ok {
		// "plain HTTP request was sent to HTTPS port" (nginx), "HTTP request to an HTTPS server" (Go)
		if !s.plainToTLS {
			return s
		}
		if t, ok := tlsProbe(addr); ok {
			return t
		}
		// the server only completes TLS for a specific domain (SNI) we don't know
		return ServiceInfo{Service: "HTTPS（网页）", Detail: firstNonEmptyStr(s.server, "HTTPS 服务") + " · 需要正确的域名才能握手", TLS: true, Open: true}
	}
	if s, ok := tlsProbe(addr); ok {
		return s
	}
	if rdp(addr) {
		return ServiceInfo{Service: "RDP", Detail: "Windows 远程桌面", Open: true}
	}
	return info
}

func banner(b []byte) ServiceInfo {
	line := strings.TrimSpace(strings.SplitN(string(b), "\n", 2)[0])
	printable := strings.Map(func(r rune) rune {
		if r < 32 || r > 126 {
			return -1
		}
		return r
	}, line)
	switch {
	case strings.HasPrefix(line, "SSH-"):
		return ServiceInfo{Service: "SSH", Detail: truncateStr(printable, 100)}
	case strings.HasPrefix(line, "RFB "):
		return ServiceInfo{Service: "VNC", Detail: printable}
	case strings.HasPrefix(line, "220") && strings.Contains(strings.ToUpper(line), "FTP"):
		return ServiceInfo{Service: "FTP", Detail: truncateStr(printable, 100)}
	case strings.HasPrefix(line, "220") && (strings.Contains(strings.ToUpper(line), "SMTP") || strings.Contains(line, "ESMTP")):
		return ServiceInfo{Service: "SMTP", Detail: truncateStr(printable, 100)}
	case strings.HasPrefix(line, "220"):
		return ServiceInfo{Service: "FTP / SMTP", Detail: truncateStr(printable, 100)}
	case strings.HasPrefix(line, "+OK"):
		return ServiceInfo{Service: "POP3", Detail: truncateStr(printable, 100)}
	case strings.HasPrefix(line, "* OK"):
		return ServiceInfo{Service: "IMAP", Detail: truncateStr(printable, 100)}
	case len(b) > 5 && b[3] == 0 && b[4] == 10: // MySQL handshake v10 (sequence 0, protocol 10)
		v := b[5:]
		if i := bytes.IndexByte(v, 0); i > 0 {
			return ServiceInfo{Service: "MySQL", Detail: "版本 " + string(v[:i])}
		}
	case b[0] == 0xff && len(b) >= 3: // telnet IAC negotiation
		return ServiceInfo{Service: "Telnet", Detail: "明文远程登录，非常不安全"}
	case strings.HasPrefix(line, "-ERR") || strings.HasPrefix(line, "-NOAUTH"):
		return ServiceInfo{Service: "Redis", Detail: printable}
	}
	if printable != "" {
		return ServiceInfo{Service: "未知（有欢迎信息）", Detail: truncateStr(printable, 100)}
	}
	return ServiceInfo{}
}

func httpProbe(addr string, conf *tls.Config) (ServiceInfo, bool) {
	var c net.Conn
	var err error
	d := &net.Dialer{Timeout: 2 * time.Second}
	if conf != nil {
		c, err = tls.DialWithDialer(d, "tcp", addr, conf)
	} else {
		c, err = d.Dial("tcp", addr)
	}
	if err != nil {
		return ServiceInfo{}, false
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(3 * time.Second))
	host, _, _ := net.SplitHostPort(addr)
	_, _ = c.Write([]byte("GET / HTTP/1.0\r\nHost: " + host + "\r\nUser-Agent: Wharf-fingerprint\r\nAccept: */*\r\n\r\n"))
	buf := make([]byte, 16384)
	n := 0
	for n < len(buf) {
		m, err := c.Read(buf[n:])
		n += m
		if err != nil {
			break
		}
	}
	resp := string(buf[:n])
	if !strings.HasPrefix(resp, "HTTP/") {
		return ServiceInfo{}, false
	}
	svc := "HTTP（网页）"
	if conf != nil {
		svc = "HTTPS（网页）"
	}
	info := ServiceInfo{Service: svc, Open: true, TLS: conf != nil}
	status := strings.TrimSpace(strings.SplitN(resp, "\n", 2)[0])
	if conf == nil && strings.Contains(status, " 400") && strings.Contains(strings.ToLower(resp), "https") {
		info.plainToTLS = true
	}
	var parts []string
	for _, l := range strings.Split(resp, "\r\n") {
		if len(l) > 7 && strings.EqualFold(l[:7], "server:") {
			info.server = strings.TrimSpace(l[7:])
			parts = append(parts, info.server)
		}
		if l == "" {
			break
		}
	}
	if m := titleRe.FindStringSubmatch(resp); m != nil {
		parts = append(parts, "「"+strings.TrimSpace(m[1])+"」")
	}
	if len(parts) == 0 {
		parts = append(parts, status)
	}
	info.Detail = truncateStr(strings.Join(parts, " · "), 160)
	return info, true
}

func tlsProbe(addr string) (ServiceInfo, bool) {
	conf := &tls.Config{InsecureSkipVerify: true} //nolint:gosec // identifying a LAN service, not trusting it
	c, err := tls.DialWithDialer(&net.Dialer{Timeout: 2 * time.Second}, "tcp", addr, conf)
	if err != nil {
		return ServiceInfo{}, false
	}
	cn := ""
	if certs := c.ConnectionState().PeerCertificates; len(certs) > 0 {
		cn = certs[0].Subject.CommonName
		if cn == "" && len(certs[0].DNSNames) > 0 {
			cn = certs[0].DNSNames[0]
		}
	}
	c.Close()
	if s, ok := httpProbe(addr, conf); ok {
		s.CertCN = cn
		return s, true
	}
	return ServiceInfo{Service: "TLS 加密服务", Detail: "非网页的加密协议", TLS: true, CertCN: cn, Open: true}, true
}

// rdp sends an X.224 connection request; RDP answers with a TPKT header.
func rdp(addr string) bool {
	c, err := net.DialTimeout("tcp", addr, 2*time.Second)
	if err != nil {
		return false
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(2 * time.Second))
	req := []byte{0x03, 0x00, 0x00, 0x13, 0x0e, 0xe0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x08, 0x00, 0x03, 0x00, 0x00, 0x00}
	if _, err := c.Write(req); err != nil {
		return false
	}
	b := make([]byte, 4)
	n, _ := c.Read(b)
	return n >= 2 && b[0] == 0x03 && b[1] == 0x00
}

func fingerprintReq(req DiagReq) (ServiceInfo, error) {
	ip := net.ParseIP(strings.TrimSpace(req.Target))
	if ip == nil || !(ip.IsPrivate() || ip.IsLoopback()) {
		return ServiceInfo{}, errors.New("只能识别局域网设备上的服务")
	}
	if req.Port < 1 || req.Port > 65535 {
		return ServiceInfo{}, errors.New("端口无效")
	}
	return Fingerprint(ip.String(), req.Port), nil
}
