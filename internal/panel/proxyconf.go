package panel

import (
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/url"
	"slices"
	"strconv"
	"strings"
)

// Proxy extension: what nodes and users look like, and how they become an Xray
// configuration, a front configuration and share links. Pure functions; the
// handlers and the agent round-trip live in proxy.go.

type ProxyNode struct {
	ID        int64       `json:"id"`
	OwnerID   int64       `json:"owner_id"`
	OwnerName string      `json:"owner_name,omitempty"`
	Name      string      `json:"name"`
	Enabled   bool        `json:"enabled"`
	Protocol  string      `json:"protocol"`  // vless | vmess | trojan | shadowsocks | hysteria
	Transport string      `json:"transport"` // raw | xhttp | ws | grpc | httpupgrade | hysteria
	Security  string      `json:"security"`  // reality | tls | none
	Entry     string      `json:"entry"`     // sni (shared 443 via the front) | port (own WAN port)
	Port      int         `json:"port"`      // public port when entry=port
	Wan       string      `json:"wan"`       // WAN interface when entry=port ("" = every WAN)
	Domain    string      `json:"domain"`    // TLS: certificate / server name; also the address in links
	Params    ProxyParams `json:"params"`
	Note      string      `json:"note"`
	Created   int64       `json:"created"`
	Updated   int64       `json:"updated"`
}

type ProxyParams struct {
	Flow        string   `json:"flow,omitempty"` // xtls-rprx-vision
	Target      string   `json:"target,omitempty"`
	ServerNames []string `json:"server_names,omitempty"`
	PrivateKey  string   `json:"private_key,omitempty"`
	PublicKey   string   `json:"public_key,omitempty"`
	ShortIDs    []string `json:"short_ids,omitempty"`
	Fingerprint string   `json:"fingerprint,omitempty"` // client uTLS fingerprint in links
	Cert        string   `json:"cert,omitempty"`        // acme | self
	Path        string   `json:"path,omitempty"`        // ws / xhttp / httpupgrade path, grpc service name
	XHTTPMode   string   `json:"xhttp_mode,omitempty"`
	SSMethod    string   `json:"ss_method,omitempty"`
	SSKey       string   `json:"ss_key,omitempty"` // server key (base64)
	UpMbps      int      `json:"up_mbps,omitempty"`
	DownMbps    int      `json:"down_mbps,omitempty"`
}

type ProxyUser struct {
	ID         int64   `json:"id"`
	OwnerID    int64   `json:"owner_id"`
	OwnerName  string  `json:"owner_name,omitempty"`
	Name       string  `json:"name"`
	Secret     string  `json:"secret"` // UUID: VLESS / VMess id, Trojan / Hysteria password, seed of SS keys
	SubToken   string  `json:"sub_token"`
	Nodes      []int64 `json:"nodes"`
	LimitBytes int64   `json:"limit_bytes"` // 0 = unlimited
	ResetDay   int     `json:"reset_day"`   // 1..28: usage resets monthly on that day; 0 = never
	ExpireAt   int64   `json:"expire_at"`   // 0 = never
	IPLimit    int     `json:"ip_limit"`    // simultaneous source IPs; 0 = unlimited
	AllowLAN   bool    `json:"allow_lan"`   // may reach the home network through the proxy
	Enabled    bool    `json:"enabled"`
	Stopped    string  `json:"stopped"` // "" | quota | expired: paused automatically
	UsedUp     int64   `json:"used_up"`
	UsedDown   int64   `json:"used_down"`
	PeriodAt   int64   `json:"period_at"` // start of the current usage period
	Note       string  `json:"note"`
	Created    int64   `json:"created"`
}

func (u *ProxyUser) active(now int64) bool {
	return u.Enabled && u.Stopped == "" && (u.ExpireAt == 0 || u.ExpireAt > now)
}

// Fixed internal ports (all above 20000, nothing else on the router uses them).
const (
	proxyAPIPort   = 20085
	proxyFrontPort = 20443
	proxyHTTPPort  = 20080
	proxyPortBase  = 20100
)

func (n *ProxyNode) inner() int  { return proxyPortBase + int(n.ID) }
func (n *ProxyNode) tag() string { return "n" + strconv.FormatInt(n.ID, 10) }
func proxyEmail(uid, nid int64) string {
	return "u" + strconv.FormatInt(uid, 10) + "@n" + strconv.FormatInt(nid, 10)
}

// parseProxyEmail splits "u12@n3".
func parseProxyEmail(e string) (uid, nid int64, ok bool) {
	u, n, found := strings.Cut(e, "@")
	if !found || !strings.HasPrefix(u, "u") || !strings.HasPrefix(n, "n") {
		return 0, 0, false
	}
	a, err1 := strconv.ParseInt(u[1:], 10, 64)
	b, err2 := strconv.ParseInt(n[1:], 10, 64)
	return a, b, err1 == nil && err2 == nil
}

func (n *ProxyNode) udp() bool { return n.Protocol == "hysteria" }

// fwProto is the protocol of the node's WAN redirect.
func (n *ProxyNode) fwProto() string {
	switch {
	case n.Protocol == "hysteria":
		return "udp"
	case n.Protocol == "shadowsocks":
		return "tcp udp"
	}
	return "tcp"
}

var (
	proxyProtocols  = []string{"vless", "vmess", "trojan", "shadowsocks", "hysteria"}
	proxyTransports = []string{"raw", "xhttp", "ws", "grpc", "httpupgrade", "hysteria"}
	ssMethods       = map[string]int{"2022-blake3-aes-128-gcm": 16, "2022-blake3-aes-256-gcm": 32, "2022-blake3-chacha20-poly1305": 32}
	fingerprints    = []string{"chrome", "firefox", "safari", "ios", "edge", "random"}
)

// normalize checks a node's combination of choices and fills generated parameters.
func (n *ProxyNode) normalize() error {
	n.Name = clean(n.Name, 40)
	if n.Name == "" {
		return fmt.Errorf("请填写节点名称")
	}
	if !slices.Contains(proxyProtocols, n.Protocol) {
		return fmt.Errorf("不支持的协议 %q", n.Protocol)
	}
	if n.Transport == "tcp" || n.Transport == "" {
		n.Transport = "raw"
	}
	if !slices.Contains(proxyTransports, n.Transport) {
		return fmt.Errorf("不支持的传输方式 %q", n.Transport)
	}
	p := &n.Params
	switch n.Protocol {
	case "shadowsocks":
		n.Transport, n.Security = "raw", "none"
		if _, ok := ssMethods[p.SSMethod]; !ok {
			p.SSMethod = "2022-blake3-aes-128-gcm"
		}
		if k, err := base64.StdEncoding.DecodeString(p.SSKey); err != nil || len(k) != ssMethods[p.SSMethod] {
			p.SSKey = randKey(ssMethods[p.SSMethod])
		}
	case "hysteria":
		n.Transport, n.Security = "hysteria", "tls"
	default:
		if n.Transport == "hysteria" {
			return fmt.Errorf("hysteria 传输只用于 Hysteria 2 协议")
		}
	}
	switch n.Security {
	case "reality":
		if n.Protocol != "vless" && n.Protocol != "trojan" {
			return fmt.Errorf("REALITY 只能用于 VLESS 或 Trojan")
		}
		if n.Transport != "raw" && n.Transport != "xhttp" && n.Transport != "grpc" {
			return fmt.Errorf("REALITY 只支持 RAW、XHTTP、gRPC 传输")
		}
		p.Target = strings.TrimSpace(p.Target)
		if p.Target == "" {
			p.Target = "www.cloudflare.com:443"
		}
		if !strings.Contains(p.Target, ":") {
			p.Target += ":443"
		}
		host, port, _ := strings.Cut(p.Target, ":")
		if !hostnameOK(host) || portNum(port) <= 0 {
			return fmt.Errorf("伪装目标格式应为 域名:端口，例如 www.cloudflare.com:443")
		}
		var names []string
		for _, s := range p.ServerNames {
			if s = strings.ToLower(strings.TrimSpace(s)); s != "" && !slices.Contains(names, s) {
				if !hostnameOK(s) {
					return fmt.Errorf("SNI %q 格式不对", s)
				}
				names = append(names, s)
			}
		}
		if len(names) == 0 {
			names = []string{host}
		}
		p.ServerNames = names
		if p.PrivateKey == "" || p.PublicKey == "" {
			priv, pub, err := x25519Pair()
			if err != nil {
				return err
			}
			p.PrivateKey, p.PublicKey = priv, pub
		}
		if len(p.ShortIDs) == 0 {
			p.ShortIDs = []string{randHex(8)}
		}
		for _, s := range p.ShortIDs {
			if len(s) > 16 || len(s)%2 != 0 {
				return fmt.Errorf("shortId %q 必须是偶数位、最多 16 位的十六进制", s)
			}
			if _, err := hex.DecodeString(s); err != nil {
				return fmt.Errorf("shortId %q 不是十六进制", s)
			}
		}
		n.Domain = ""
	case "tls":
		n.Domain = strings.ToLower(strings.TrimSpace(n.Domain))
		if !hostnameOK(n.Domain) {
			return fmt.Errorf("TLS 节点需要一个域名（证书和客户端 SNI 都用它）")
		}
		if p.Cert != "self" {
			p.Cert = "acme"
		}
	case "none":
		if n.Protocol == "trojan" || n.Protocol == "hysteria" {
			return fmt.Errorf("%s 必须使用 TLS", n.Protocol)
		}
		n.Domain = strings.ToLower(strings.TrimSpace(n.Domain))
	default:
		return fmt.Errorf("不支持的安全层 %q", n.Security)
	}
	if n.Protocol == "vless" && n.Transport == "raw" && n.Security != "none" {
		p.Flow = "xtls-rprx-vision"
	} else {
		p.Flow = ""
	}
	if !slices.Contains(fingerprints, p.Fingerprint) {
		p.Fingerprint = "chrome"
	}
	switch n.Transport {
	case "ws", "xhttp", "httpupgrade":
		if p.Path == "" {
			p.Path = "/" + randHex(6)
		}
		if !strings.HasPrefix(p.Path, "/") {
			p.Path = "/" + p.Path
		}
	case "grpc":
		if p.Path == "" {
			p.Path = randHex(6)
		}
		p.Path = strings.Trim(p.Path, "/")
	default:
		p.Path = ""
	}
	if n.Transport == "xhttp" && !slices.Contains([]string{"auto", "packet-up", "stream-up", "stream-one"}, p.XHTTPMode) {
		p.XHTTPMode = "auto"
	}
	if n.Transport != "xhttp" {
		p.XHTTPMode = ""
	}
	if n.Entry != "port" {
		n.Entry = "sni"
	}
	if n.Entry == "sni" && (n.Security == "none" || n.udp()) {
		n.Entry = "port"
	}
	if n.Entry == "port" {
		if n.Port < 1 || n.Port > 65535 {
			return fmt.Errorf("请填写公网端口（1–65535）")
		}
	} else {
		n.Port = 443
		n.Wan = ""
	}
	if n.Security != "reality" {
		p.PrivateKey, p.PublicKey, p.ShortIDs, p.Target, p.ServerNames = "", "", nil, "", nil
	}
	if n.Security != "tls" {
		p.Cert = ""
	}
	if n.Protocol != "shadowsocks" {
		p.SSMethod, p.SSKey = "", ""
	}
	if n.Protocol != "hysteria" {
		p.UpMbps, p.DownMbps = 0, 0
	}
	n.Note = clean(n.Note, 200)
	return nil
}

// sharePort puts an SNI-shared node on the extension's shared public port (stored as 443).
func (n *ProxyNode) sharePort(port int) {
	if n.Entry == "sni" {
		n.Port = port
	}
}

// sniNames are the names the front routes to this node.
func (n *ProxyNode) sniNames() []string {
	if n.Entry != "sni" {
		return nil
	}
	if n.Security == "reality" {
		return n.Params.ServerNames
	}
	return []string{n.Domain}
}

func hostnameOK(h string) bool {
	if h == "" || len(h) > 253 || !strings.Contains(h, ".") {
		return false
	}
	for _, l := range strings.Split(h, ".") {
		if l == "" || len(l) > 63 || l[0] == '-' || l[len(l)-1] == '-' {
			return false
		}
		for _, c := range l {
			if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-') {
				return false
			}
		}
	}
	return true
}

func randHex(n int) string {
	b := make([]byte, n/2)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func randKey(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return base64.StdEncoding.EncodeToString(b)
}

func newUUID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	b[6] = b[6]&0x0f | 0x40
	b[8] = b[8]&0x3f | 0x80
	h := hex.EncodeToString(b)
	return h[:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:]
}

func newSubToken() string {
	b := make([]byte, 18)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

// x25519Pair returns a REALITY key pair as Xray prints it (raw URL base64).
func x25519Pair() (priv, pub string, err error) {
	k, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return "", "", err
	}
	return base64.RawURLEncoding.EncodeToString(k.Bytes()), base64.RawURLEncoding.EncodeToString(k.PublicKey().Bytes()), nil
}

// ssUserKey derives a user's Shadowsocks 2022 key for a node from the user's secret.
func ssUserKey(secret string, node *ProxyNode) string {
	h := sha256.Sum256([]byte("wharf-ss2022|" + secret + "|" + strconv.FormatInt(node.ID, 10)))
	return base64.StdEncoding.EncodeToString(h[:ssMethods[node.Params.SSMethod]])
}

// ---- Xray configuration ----

type proxyPolicy struct {
	BlockBT    bool
	BlockPorts []int
	BlockHosts []string // domains (and their subdomains) nobody may reach through the proxy
}

var privateCIDRs = []string{"0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16", "172.16.0.0/12",
	"192.168.0.0/16", "224.0.0.0/4", "255.255.255.255/32", "::1/128", "fc00::/7", "fe80::/10"}

type jm = map[string]any

func buildXray(nodes []*ProxyNode, users []*ProxyUser, pol proxyPolicy, frontHTTP bool, now int64) (string, error) {
	inbounds := []any{jm{"tag": "api", "listen": "127.0.0.1", "port": proxyAPIPort, "protocol": "tunnel", "settings": jm{"address": "127.0.0.1"}}}
	var lanEmails []string
	for _, n := range nodes {
		if !n.Enabled {
			continue
		}
		in, emails := buildInbound(n, users, frontHTTP, now)
		inbounds = append(inbounds, in)
		for _, u := range users {
			if u.AllowLAN && slices.Contains(u.Nodes, n.ID) && u.active(now) {
				lanEmails = append(lanEmails, proxyEmail(u.ID, n.ID))
			}
		}
		_ = emails
	}
	if len(inbounds) == 1 {
		return "", nil
	}
	rules := []any{jm{"inboundTag": []string{"api"}, "outboundTag": "api"}}
	if pol.BlockBT {
		rules = append(rules, jm{"protocol": []string{"bittorrent"}, "outboundTag": "blocked"})
	}
	if len(pol.BlockPorts) > 0 {
		var ps []string
		for _, p := range pol.BlockPorts {
			ps = append(ps, strconv.Itoa(p))
		}
		rules = append(rules, jm{"port": strings.Join(ps, ","), "outboundTag": "blocked"})
	}
	if len(pol.BlockHosts) > 0 {
		var ds []string
		for _, h := range pol.BlockHosts {
			ds = append(ds, "domain:"+h)
		}
		rules = append(rules, jm{"domain": ds, "outboundTag": "blocked"})
	}
	if len(lanEmails) > 0 {
		rules = append(rules, jm{"user": lanEmails, "ip": privateCIDRs, "outboundTag": "direct"})
	}
	rules = append(rules, jm{"ip": privateCIDRs, "outboundTag": "blocked"})
	cfg := jm{
		"log":   jm{"loglevel": "warning", "access": "/tmp/wharf-proxy/access.log", "error": "/tmp/wharf-proxy/error.log", "dnsLog": false},
		"api":   jm{"tag": "api", "services": []string{"StatsService", "HandlerService", "RoutingService"}},
		"stats": jm{},
		"policy": jm{
			"levels": jm{"0": jm{"statsUserUplink": true, "statsUserDownlink": true, "statsUserOnline": true, "handshake": 4, "connIdle": 300}},
			"system": jm{"statsInboundUplink": true, "statsInboundDownlink": true},
		},
		"inbounds": inbounds,
		"outbounds": []any{
			jm{"tag": "direct", "protocol": "freedom", "settings": jm{"domainStrategy": "UseIP"}},
			jm{"tag": "blocked", "protocol": "blackhole"},
		},
		"routing": jm{"domainStrategy": "IPIfNonMatch", "rules": rules},
	}
	b, err := json.MarshalIndent(cfg, "", "  ")
	return string(b), err
}

func buildInbound(n *ProxyNode, users []*ProxyUser, frontHTTP bool, now int64) (jm, []string) {
	p := n.Params
	var clients []any
	var emails []string
	for _, u := range users {
		if !u.active(now) || !slices.Contains(u.Nodes, n.ID) {
			continue
		}
		e := proxyEmail(u.ID, n.ID)
		emails = append(emails, e)
		switch n.Protocol {
		case "vless":
			c := jm{"id": u.Secret, "email": e}
			if p.Flow != "" {
				c["flow"] = p.Flow
			}
			clients = append(clients, c)
		case "vmess":
			clients = append(clients, jm{"id": u.Secret, "email": e})
		case "trojan":
			clients = append(clients, jm{"password": u.Secret, "email": e})
		case "shadowsocks":
			clients = append(clients, jm{"password": ssUserKey(u.Secret, n), "email": e})
		case "hysteria":
			clients = append(clients, jm{"auth": u.Secret, "email": e})
		}
	}
	if clients == nil {
		clients = []any{}
	}
	settings := jm{"clients": clients}
	switch n.Protocol {
	case "vless":
		settings["decryption"] = "none"
		if frontHTTP && n.Transport == "raw" && n.Security == "tls" {
			settings["fallbacks"] = []any{jm{"dest": fmt.Sprintf("127.0.0.1:%d", proxyHTTPPort)}}
		}
	case "trojan":
		if frontHTTP && n.Transport == "raw" && n.Security == "tls" {
			settings["fallbacks"] = []any{jm{"dest": fmt.Sprintf("127.0.0.1:%d", proxyHTTPPort)}}
		}
	case "shadowsocks":
		settings["method"], settings["password"], settings["network"] = p.SSMethod, p.SSKey, "tcp,udp"
	case "hysteria":
		settings["version"] = 2
	}
	stream := jm{"network": n.Transport, "security": n.Security}
	switch n.Security {
	case "reality":
		stream["realitySettings"] = jm{"target": p.Target, "serverNames": p.ServerNames, "privateKey": p.PrivateKey, "shortIds": p.ShortIDs, "show": false}
	case "tls":
		t := jm{"serverName": n.Domain, "minVersion": "1.2", "rejectUnknownSni": false,
			"certificates": []any{jm{"certificateFile": "@PROXYDIR@/certs/" + n.Domain + ".crt", "keyFile": "@PROXYDIR@/certs/" + n.Domain + ".key"}}}
		switch {
		case n.Protocol == "hysteria":
			t["alpn"] = []string{"h3"}
		case n.Transport == "grpc":
			t["alpn"] = []string{"h2"}
		case n.Transport == "xhttp":
			t["alpn"] = []string{"h2", "http/1.1"}
		default:
			t["alpn"] = []string{"http/1.1"}
		}
		stream["tlsSettings"] = t
	}
	switch n.Transport {
	case "ws":
		stream["wsSettings"] = jm{"path": p.Path}
	case "httpupgrade":
		stream["httpupgradeSettings"] = jm{"path": p.Path}
	case "xhttp":
		stream["xhttpSettings"] = jm{"path": p.Path, "mode": p.XHTTPMode}
	case "grpc":
		stream["grpcSettings"] = jm{"serviceName": p.Path}
	case "hysteria":
		h := jm{"version": 2}
		if frontHTTP {
			h["masquerade"] = jm{"type": "proxy", "url": fmt.Sprintf("http://127.0.0.1:%d", proxyHTTPPort), "rewriteHost": true}
		}
		stream["hysteriaSettings"] = h
	}
	listen := "0.0.0.0"
	if n.Entry == "sni" {
		listen = "127.0.0.1"
		stream["sockopt"] = jm{"acceptProxyProtocol": true}
	}
	in := jm{"tag": n.tag(), "listen": listen, "port": n.inner(), "protocol": n.Protocol, "settings": settings, "streamSettings": stream}
	if n.Protocol != "hysteria" {
		in["sniffing"] = jm{"enabled": true, "destOverride": []string{"http", "tls", "quic"}, "routeOnly": true}
	}
	return in, emails
}

// ---- front ----

type frontSite struct {
	Mode   string `json:"mode"` // builtin | html | proxy
	Proxy  string `json:"proxy"`
	Title  string `json:"title"`
	Domain string `json:"domain"` // the site's own name (gets a certificate; subscriptions are served here)
}

// frontFallback is where the front sends everything that is not for a node when it
// has taken WAN 443 over from an existing port forward.
type frontFallback struct {
	Backend     string
	Proxy       bool
	Transparent bool // connect from the client's own address (the server sees real visitors)
}

// acmeOK: the shared port is 443, where Let's Encrypt can validate (TLS-ALPN-01).
// panel: the panel's public names, routed to its loopback listener (panelname.go).
// berth: names the paired Berth registered (berth_api.go), passed through untouched; nodes
// and the panel's own names take precedence.
func buildFront(nodes []*ProxyNode, site frontSite, acmeEmail string, fb *frontFallback, acmeOK bool, panel *panelRoute, berth *berthSNIReg) (string, bool) {
	type route struct {
		SNI     []string `json:"sni"`
		Backend string   `json:"backend"`
		Proxy   bool     `json:"proxy"`
		LANOnly bool     `json:"lan_only,omitempty"`
	}
	var routes []route
	var acme []string
	need := false
	for _, n := range nodes {
		if !n.Enabled {
			continue
		}
		if n.Entry == "sni" {
			routes = append(routes, route{SNI: n.sniNames(), Backend: fmt.Sprintf("127.0.0.1:%d", n.inner()), Proxy: true})
			need = true
		}
		if n.Security == "tls" && n.Params.Cert == "acme" && !slices.Contains(acme, n.Domain) {
			acme = append(acme, n.Domain)
		}
	}
	if panel != nil && len(panel.names) > 0 { // TLS stays end to end: the panel answers with its own certificate
		routes = append(routes, route{SNI: panel.names, Backend: fmt.Sprintf("127.0.0.1:%d", panelProxyPort), Proxy: true, LANOnly: panel.lanOnly})
		need = true
	}
	if berth != nil && berth.Target != "" {
		var names []string
		for _, d := range berth.Domains {
			taken := false
			for _, r := range routes {
				for _, n := range r.SNI {
					taken = taken || sniOverlap(n, d)
				}
			}
			if !taken {
				names = append(names, d)
			}
		}
		if len(names) > 0 {
			routes = append(routes, route{SNI: names, Backend: berth.Target, Proxy: berth.ProxyProtocol})
			need = true
		}
	}
	if site.Domain != "" && !slices.Contains(acme, site.Domain) {
		acme = append(acme, site.Domain)
		need = true
	}
	if !need && len(acme) == 0 {
		return "", false
	}
	if !acmeOK {
		acme = nil
	}
	cfg := jm{
		"dir": "@PROXYDIR@", "listen": fmt.Sprintf(":%d", proxyFrontPort), "http_listen": fmt.Sprintf("127.0.0.1:%d", proxyHTTPPort),
		"routes": routes, "acme": acme, "acme_email": acmeEmail,
		"site": jm{"mode": site.Mode, "proxy": site.Proxy, "title": site.Title, "domain": site.Domain},
		"user": "nobody", // started as root only to keep CAP_NET_ADMIN for transparent connects
	}
	if fb != nil && fb.Backend != "" {
		cfg["fallback"], cfg["fallback_proxy"], cfg["fallback_transparent"] = fb.Backend, fb.Proxy, fb.Transparent
	}
	b, _ := json.MarshalIndent(cfg, "", "  ")
	return string(b), true
}

// ---- share links ----

// shareLink builds a client import link. pin is the SHA-256 of a self-signed certificate:
// Xray 26 clients pin it (pcs); allowInsecure stays for clients that only know that.
func shareLink(n *ProxyNode, u *ProxyUser, host, pin string) string {
	p := n.Params
	name := url.PathEscape(n.Name)
	addr := hostPort(host, n.Port)
	q := url.Values{}
	setTransport := func() {
		q.Set("type", map[string]string{"raw": "tcp"}[n.Transport])
		if q.Get("type") == "" {
			q.Set("type", n.Transport)
		}
		switch n.Transport {
		case "ws", "httpupgrade":
			q.Set("path", p.Path)
			if n.Domain != "" {
				q.Set("host", n.Domain)
			}
		case "xhttp":
			q.Set("path", p.Path)
			q.Set("mode", p.XHTTPMode)
			if n.Domain != "" {
				q.Set("host", n.Domain)
			}
		case "grpc":
			q.Set("serviceName", p.Path)
			q.Set("mode", "gun")
		}
	}
	setSecurity := func() {
		q.Set("security", n.Security)
		switch n.Security {
		case "reality":
			q.Set("sni", p.ServerNames[0])
			q.Set("fp", p.Fingerprint)
			q.Set("pbk", p.PublicKey)
			q.Set("sid", p.ShortIDs[0])
		case "tls":
			q.Set("sni", n.Domain)
			q.Set("fp", p.Fingerprint)
			if p.Cert == "self" {
				q.Set("allowInsecure", "1")
				if pin != "" {
					q.Set("pcs", pin)
				}
			}
		}
	}
	switch n.Protocol {
	case "vless":
		q.Set("encryption", "none")
		setTransport()
		setSecurity()
		if p.Flow != "" {
			q.Set("flow", p.Flow)
		}
		return "vless://" + u.Secret + "@" + addr + "?" + q.Encode() + "#" + name
	case "trojan":
		setTransport()
		setSecurity()
		return "trojan://" + url.PathEscape(u.Secret) + "@" + addr + "?" + q.Encode() + "#" + name
	case "vmess":
		v := jm{"v": "2", "ps": n.Name, "add": host, "port": strconv.Itoa(n.Port), "id": u.Secret, "aid": "0", "scy": "auto",
			"net": map[string]string{"raw": "tcp"}[n.Transport], "type": "none", "host": n.Domain, "path": p.Path, "tls": "", "sni": "", "fp": ""}
		if v["net"] == "" {
			v["net"] = n.Transport
		}
		if n.Security == "tls" {
			v["tls"], v["sni"], v["fp"] = "tls", n.Domain, p.Fingerprint
			if p.Cert == "self" {
				v["allowInsecure"] = true
			}
		}
		b, _ := json.Marshal(v)
		return "vmess://" + base64.StdEncoding.EncodeToString(b)
	case "shadowsocks":
		userinfo := base64.RawURLEncoding.EncodeToString([]byte(p.SSMethod + ":" + p.SSKey + ":" + ssUserKey(u.Secret, n)))
		return "ss://" + userinfo + "@" + addr + "#" + name
	case "hysteria":
		q.Set("sni", n.Domain)
		if p.Cert == "self" {
			q.Set("insecure", "1")
			if pin != "" {
				q.Set("pinSHA256", pin)
			}
		}
		return "hysteria2://" + url.PathEscape(u.Secret) + "@" + addr + "?" + q.Encode() + "#" + name
	}
	return ""
}

func hostPort(host string, port int) string {
	if strings.Contains(host, ":") && !strings.HasPrefix(host, "[") {
		host = "[" + host + "]"
	}
	return host + ":" + strconv.Itoa(port)
}

// nodeHost is the address clients use for a node.
// A node with a public certificate is reached by its domain (it has to resolve to us for
// the certificate anyway); a self-signed name is only the SNI.
func nodeHost(n *ProxyNode, def string) string {
	if n.Security == "tls" && n.Params.Cert == "acme" && n.Domain != "" {
		return n.Domain
	}
	return def
}

func subscription(nodes []*ProxyNode, u *ProxyUser, host string, pins map[string]string, now int64) string {
	var links []string
	for _, n := range nodes {
		if n.Enabled && slices.Contains(u.Nodes, n.ID) && u.active(now) {
			links = append(links, shareLink(n, u, nodeHost(n, host), pins[n.Domain]))
		}
	}
	return base64.StdEncoding.EncodeToString([]byte(strings.Join(links, "\n")))
}

func subInfo(u *ProxyUser) string {
	return fmt.Sprintf("upload=%d; download=%d; total=%d; expire=%d", u.UsedUp, u.UsedDown, u.LimitBytes, u.ExpireAt)
}
