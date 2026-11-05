package panel

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type fakeAddrConn struct {
	net.Conn
	addr string
}

func (c fakeAddrConn) RemoteAddr() net.Addr { a, _ := net.ResolveTCPAddr("tcp", c.addr); return a }

func selfCert(t *testing.T, names ...string) (certPEM, keyPEM []byte) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "CloudFlare Origin Certificate"}, DNSNames: names,
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(15 * 365 * 24 * time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	kb, _ := x509.MarshalECPrivateKey(key)
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kb})
}

func TestProxiedPanelNames(t *testing.T) {
	dir := t.TempDir()
	db, err := OpenDB(filepath.Join(dir, "o.db"))
	if err != nil {
		t.Fatal(err)
	}
	a := &App{db: db, cfg: Config{DataDir: dir}}
	_ = a.setSetting("panel.public_names", `["wharf.example.com","direct.example.com"]`)
	_ = a.setSetting("panel.proxied", `["wharf.example.com","stale.example.com"]`)
	if p := a.proxiedNames(); len(p) != 1 || p[0] != "wharf.example.com" {
		t.Fatalf("proxied %v", p)
	}

	// CF-Connecting-IP is believed only from Cloudflare's own addresses
	r := httptest.NewRequest("GET", "/", nil)
	r.Header.Set("CF-Connecting-IP", "203.0.113.9")
	r.RemoteAddr = "173.245.48.10:443"
	if a.clientIP(r) != "203.0.113.9" {
		t.Fatalf("from Cloudflare: %s", a.clientIP(r))
	}
	r.RemoteAddr = "198.51.100.4:5555"
	if a.clientIP(r) != "198.51.100.4" {
		t.Fatalf("spoofed header believed: %s", a.clientIP(r))
	}

	// the origin certificate: must cover the proxied names; served to Cloudflare only
	if err := os.MkdirAll(a.tlsDir(), 0o700); err != nil {
		t.Fatal(err)
	}
	c, k := selfCert(t, "other.example.org")
	if err := a.saveOriginCert(c, k, "pasted"); err == nil || !strings.Contains(err.Error(), "wharf.example.com") {
		t.Fatalf("wrong names accepted: %v", err)
	}
	c, k = selfCert(t, "*.example.com", "example.com")
	if err := a.saveOriginCert(c, k, "pasted"); err != nil {
		t.Fatal(err)
	}
	hello := func(name, from string) *tls.ClientHelloInfo {
		return &tls.ClientHelloInfo{ServerName: name, Conn: fakeAddrConn{addr: from}}
	}
	if a.OriginCertificate(hello("wharf.example.com", "173.245.48.10:443")) == nil {
		t.Fatal("Cloudflare should get the origin certificate")
	}
	if a.OriginCertificate(hello("wharf.example.com", "10.0.0.5:5000")) != nil {
		t.Fatal("a device at home must not get the origin certificate")
	}
	if a.OriginCertificate(hello("direct.example.com", "173.245.48.10:443")) != nil {
		t.Fatal("a name that is not proxied must not get it")
	}
}

func TestOriginRule(t *testing.T) {
	var stored []map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case "GET":
			b, _ := json.Marshal(map[string]any{"success": true, "result": map[string]any{"rules": append([]map[string]any{{
				"id": "x", "expression": `(http.host eq "shop.example.com")`, "action": "route", "description": "someone else's",
				"action_parameters": map[string]any{"origin": map[string]any{"port": 8080}}, "enabled": true}}, stored...)}})
			_, _ = w.Write(b)
		case "PUT":
			var body struct {
				Rules []map[string]any `json:"rules"`
			}
			b, _ := io.ReadAll(r.Body)
			_ = json.Unmarshal(b, &body)
			stored = nil
			for _, x := range body.Rules {
				if d, _ := x["description"].(string); strings.HasPrefix(d, originRuleTag) {
					stored = append(stored, x)
				}
			}
			if len(body.Rules) == 0 || body.Rules[0]["description"] != "someone else's" {
				t.Errorf("other rules lost: %s", b)
			}
			_, _ = w.Write([]byte(`{"success":true,"result":{}}`))
		}
	}))
	defer srv.Close()
	cfAPI = srv.URL
	defer func() { cfAPI = "https://api.cloudflare.com/client/v4" }()
	call := cfCall("tok")
	if err := cfOriginRule(call, "z1", []string{"wharf.example.com"}, "7080"); err != nil {
		t.Fatal(err)
	}
	if len(stored) != 1 || stored[0]["expression"] != `(http.host in {"wharf.example.com"})` {
		t.Fatalf("rule %v", stored)
	}
	if err := cfOriginRule(call, "z1", nil, "7080"); err != nil || len(stored) != 0 {
		t.Fatalf("rule not removed: %v %v", err, stored)
	}
}
