package panel

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/wangsirco/wharf/internal/tlsutil"
)

func testNodes(t *testing.T) []*ProxyNode {
	t.Helper()
	specs := []ProxyNode{
		{Name: "Reality", Protocol: "vless", Transport: "raw", Security: "reality", Entry: "sni"},
		{Name: "Reality XHTTP", Protocol: "vless", Transport: "xhttp", Security: "reality", Entry: "port", Port: 8443,
			Params: ProxyParams{Target: "www.apple.com", ServerNames: []string{"www.apple.com", "images.apple.com"}}},
		{Name: "VLESS TLS", Protocol: "vless", Transport: "raw", Security: "tls", Entry: "sni", Domain: "xtls.example.com"},
		{Name: "VLESS WS", Protocol: "vless", Transport: "ws", Security: "tls", Entry: "port", Port: 2053, Domain: "ws.example.com", Params: ProxyParams{Cert: "self"}},
		{Name: "VLESS gRPC", Protocol: "vless", Transport: "grpc", Security: "tls", Entry: "sni", Domain: "grpc.example.com"},
		{Name: "VMess WS", Protocol: "vmess", Transport: "ws", Security: "tls", Entry: "port", Port: 2083, Domain: "vm.example.com"},
		{Name: "VMess plain", Protocol: "vmess", Transport: "raw", Security: "none", Entry: "port", Port: 20000},
		{Name: "Trojan", Protocol: "trojan", Transport: "raw", Security: "tls", Entry: "sni", Domain: "tj.example.com"},
		{Name: "Trojan Reality", Protocol: "trojan", Transport: "raw", Security: "reality", Entry: "port", Port: 9443},
		{Name: "HTTPUpgrade", Protocol: "vless", Transport: "httpupgrade", Security: "tls", Entry: "port", Port: 2087, Domain: "hu.example.com"},
		{Name: "SS 2022", Protocol: "shadowsocks", Entry: "port", Port: 8388},
		{Name: "SS 2022 256", Protocol: "shadowsocks", Entry: "port", Port: 8389, Params: ProxyParams{SSMethod: "2022-blake3-aes-256-gcm"}},
		{Name: "Hysteria2", Protocol: "hysteria", Entry: "port", Port: 8443, Domain: "hy.example.com"},
	}
	var out []*ProxyNode
	for i, s := range specs {
		n := s
		n.ID, n.Enabled = int64(i+1), true
		if err := n.normalize(); err != nil {
			t.Fatalf("%s: %v", n.Name, err)
		}
		out = append(out, &n)
	}
	return out
}

func TestProxyNormalizeRejects(t *testing.T) {
	bad := []ProxyNode{
		{Name: "x", Protocol: "vmess", Transport: "raw", Security: "reality", Entry: "sni"},
		{Name: "x", Protocol: "vless", Transport: "ws", Security: "reality", Entry: "sni"},
		{Name: "x", Protocol: "trojan", Transport: "raw", Security: "none", Entry: "port", Port: 1},
		{Name: "x", Protocol: "vless", Transport: "raw", Security: "tls", Entry: "sni", Domain: ""},
		{Name: "x", Protocol: "vless", Transport: "raw", Security: "none", Entry: "port", Port: 0},
		{Name: "", Protocol: "vless", Transport: "raw", Security: "reality", Entry: "sni"},
	}
	for i, n := range bad {
		if err := n.normalize(); err == nil {
			t.Errorf("case %d accepted", i)
		}
	}
}

func TestProxyLinks(t *testing.T) {
	nodes := testNodes(t)
	u := &ProxyUser{ID: 7, Name: "friend", Secret: newUUID(), Nodes: []int64{}, Enabled: true}
	for _, n := range nodes {
		u.Nodes = append(u.Nodes, n.ID)
	}
	for _, n := range nodes {
		l := shareLink(n, u, "home.example.com", "")
		if l == "" {
			t.Fatalf("%s: no link", n.Name)
		}
		t.Log(l)
	}
	vl := shareLink(nodes[0], u, "1.2.3.4", "")
	for _, want := range []string{"vless://" + u.Secret + "@1.2.3.4:443?", "security=reality", "flow=xtls-rprx-vision", "pbk=" + nodes[0].Params.PublicKey, "sni=www.cloudflare.com", "type=tcp"} {
		if !strings.Contains(vl, want) {
			t.Errorf("reality link %q lacks %q", vl, want)
		}
	}
	if h := nodeHost(nodes[2], "x"); h != "xtls.example.com" {
		t.Errorf("acme node should use its domain, got %s", h)
	}
	if h := nodeHost(nodes[3], "x"); h != "x" {
		t.Errorf("self-signed node should use the router address, got %s", h)
	}
}

// TestXrayAcceptsConfig runs the generated configuration through `xray run -test`
// when WHARF_XRAY points at an Xray binary.
func TestXrayAcceptsConfig(t *testing.T) {
	bin := os.Getenv("WHARF_XRAY")
	if bin == "" {
		t.Skip("set WHARF_XRAY to an xray binary")
	}
	nodes := testNodes(t)
	users := []*ProxyUser{
		{ID: 1, Name: "a", Secret: newUUID(), Enabled: true, AllowLAN: true},
		{ID: 2, Name: "b", Secret: newUUID(), Enabled: true},
		{ID: 3, Name: "expired", Secret: newUUID(), Enabled: true, ExpireAt: 1},
	}
	for _, u := range users {
		for _, n := range nodes {
			u.Nodes = append(u.Nodes, n.ID)
		}
	}
	cfg, err := buildXray(nodes, users, proxyPolicy{BlockBT: true, BlockPorts: []int{25}, BlockHosts: []string{"example.org"}}, true, 1000)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(cfg, proxyEmail(3, 1)) {
		t.Error("expired user is in the config")
	}
	dir := t.TempDir()
	_ = os.MkdirAll(filepath.Join(dir, "certs"), 0o755)
	for _, n := range nodes {
		if n.Domain != "" {
			c, k, _ := tlsutil.SelfSigned(n.Domain, "test")
			_ = os.WriteFile(filepath.Join(dir, "certs", n.Domain+".crt"), c, 0o644)
			_ = os.WriteFile(filepath.Join(dir, "certs", n.Domain+".key"), k, 0o600)
		}
	}
	p := filepath.Join(dir, "x.json")
	_ = os.WriteFile(p, []byte(strings.ReplaceAll(strings.ReplaceAll(cfg, "@PROXYDIR@", dir), "/tmp/wharf-proxy/", dir+"/")), 0o600)
	out, err := exec.Command(bin, "run", "-test", "-c", p).CombinedOutput()
	if err != nil {
		t.Fatalf("xray rejected the config: %v\n%s\n%s", err, out, cfg)
	}
	front, ok := buildFront(nodes, frontSite{Mode: "builtin", Domain: "home.example.com"}, "", nil, true)
	if !ok || !json.Valid([]byte(front)) {
		t.Fatalf("front: %v %s", ok, front)
	}
}
