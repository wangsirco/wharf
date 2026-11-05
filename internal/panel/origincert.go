package panel

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"
)

// Panel names behind Cloudflare's proxy (orange cloud). Cloudflare terminates the
// visitor's TLS and connects to home itself, so:
//
//   - an Origin Rule on the zone sends these names to the panel's own port (the 443 split
//     hands every Cloudflare connection to the website forward, and that stays as it is);
//   - that port is opened on the WAN to Cloudflare's addresses only (rule owp_panel_cf);
//   - Cloudflare's connections get the Cloudflare origin certificate (pasted, or created
//     through the API, 15 years); anyone else asking for the name — devices at home, which
//     dnsmasq sends straight to the router — gets the Let's Encrypt one;
//   - CF-Connecting-IP is believed only on connections that come from Cloudflare's ranges,
//     so access control still sees the visitor.

const originRuleTag = "wharf panel" // description of our Origin Rule

// cloudflareV6: Cloudflare's published IPv6 ranges (www.cloudflare.com/ips-v6)
var cloudflareV6 = []string{"2400:cb00::/32", "2606:4700::/32", "2803:f800::/32", "2405:b500::/32", "2405:8100::/32", "2a06:98c0::/29", "2c0f:f248::/32"}

// proxiedNames: the public names set to go through Cloudflare's proxy.
func (a *App) proxiedNames() []string {
	var out []string
	_ = json.Unmarshal([]byte(a.setting("panel.proxied")), &out)
	pub := a.publicNames()
	return slices.DeleteFunc(out, func(n string) bool { return !slices.Contains(pub, n) })
}

// ---- Cloudflare's ranges ----

var cfNets struct {
	sync.Mutex
	at   time.Time
	nets []netip.Prefix
}

func (a *App) cloudflareNets() []netip.Prefix {
	cfNets.Lock()
	defer cfNets.Unlock()
	if time.Since(cfNets.at) < 10*time.Minute && cfNets.nets != nil {
		return cfNets.nets
	}
	var out []netip.Prefix
	for _, c := range append(a.cloudflareCIDRs(), cloudflareV6...) {
		if p, err := netip.ParsePrefix(c); err == nil {
			out = append(out, p)
		}
	}
	cfNets.nets, cfNets.at = out, time.Now()
	return out
}

func (a *App) fromCloudflare(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		host = addr
	}
	ip, err := netip.ParseAddr(host)
	if err != nil {
		return false
	}
	ip = ip.Unmap()
	return slices.ContainsFunc(a.cloudflareNets(), func(p netip.Prefix) bool { return p.Contains(ip) })
}

// cloudflareVisitor: the visitor behind a connection Cloudflare made ("" = not one).
func (a *App) cloudflareVisitor(r *http.Request) string {
	if len(a.proxiedNames()) == 0 || !a.fromCloudflare(r.RemoteAddr) {
		return ""
	}
	if v := strings.TrimSpace(r.Header.Get("CF-Connecting-IP")); net.ParseIP(v) != nil {
		return v
	}
	return ""
}

// ---- the origin certificate ----

var originCert struct {
	sync.RWMutex
	cert   *tls.Certificate
	leaf   *x509.Certificate
	names  []string
	exp    time.Time
	source string // pasted | api
	err    string
}

func (a *App) loadOriginCert() {
	pair, err := tls.LoadX509KeyPair(filepath.Join(a.tlsDir(), "origin.crt"), filepath.Join(a.tlsDir(), "origin.key"))
	src, _ := os.ReadFile(filepath.Join(a.tlsDir(), "origin.source"))
	originCert.Lock()
	defer originCert.Unlock()
	originCert.cert = nil
	if err != nil {
		return
	}
	if leaf, err := x509.ParseCertificate(pair.Certificate[0]); err == nil {
		originCert.cert, originCert.leaf, originCert.names, originCert.exp, originCert.source = &pair, leaf, leaf.DNSNames, leaf.NotAfter, strings.TrimSpace(string(src))
	}
}

// OriginCertificate answers Cloudflare's own connections for a proxied name (nil = not
// one: the next certificate in line answers).
func (a *App) OriginCertificate(h *tls.ClientHelloInfo) *tls.Certificate {
	if h.Conn == nil || !slices.Contains(a.proxiedNames(), strings.ToLower(h.ServerName)) || !a.fromCloudflare(h.Conn.RemoteAddr().String()) {
		return nil
	}
	originCert.RLock()
	defer originCert.RUnlock()
	if originCert.leaf != nil && originCert.leaf.VerifyHostname(h.ServerName) == nil {
		return originCert.cert
	}
	return nil
}

func (a *App) saveOriginCert(certPEM, keyPEM []byte, source string) error {
	pair, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return errors.New("证书和私钥不匹配，或者格式不对（需要 PEM：-----BEGIN CERTIFICATE----- / -----BEGIN PRIVATE KEY-----）")
	}
	leaf, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		return err
	}
	if time.Now().After(leaf.NotAfter) {
		return errors.New("这张证书已经过期")
	}
	for _, n := range a.proxiedNames() {
		if leaf.VerifyHostname(n) != nil {
			return fmt.Errorf("这张证书不包含 %s（证书里是 %s）", n, strings.Join(leaf.DNSNames, "、"))
		}
	}
	if err := os.WriteFile(filepath.Join(a.tlsDir(), "origin.key"), keyPEM, 0o600); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(a.tlsDir(), "origin.crt"), certPEM, 0o644); err != nil {
		return err
	}
	_ = os.WriteFile(filepath.Join(a.tlsDir(), "origin.source"), []byte(source), 0o644)
	a.loadOriginCert()
	return nil
}

// createOriginCert asks Cloudflare's Origin CA for a 15-year certificate for the proxied
// names (the token needs Zone → SSL and Certificates → Edit).
func (a *App) createOriginCert() error {
	ns := a.proxiedNames()
	if len(ns) == 0 {
		return errors.New("还没有设置走 Cloudflare 代理的域名")
	}
	token := a.cfTokenFor(ns[0])
	if token == "" {
		return errors.New("需要 Cloudflare 账户或令牌")
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{DNSNames: ns}, key)
	if err != nil {
		return err
	}
	var res struct {
		Certificate string `json:"certificate"`
	}
	body := map[string]any{"hostnames": ns, "requested_validity": 5475, "request_type": "origin-ecc",
		"csr": string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csr}))}
	if err := cfCall(token)("POST", "/certificates", body, &res); err != nil {
		return fmt.Errorf("%v（令牌需要「SSL 和证书 → 编辑」权限）", err)
	}
	kb, _ := x509.MarshalECPrivateKey(key)
	return a.saveOriginCert([]byte(res.Certificate), pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kb}), "api")
}

// ---- Cloudflare side: proxied records and the Origin Rule ----

var originRule struct {
	sync.Mutex
	err string
}

// syncCloudflareProxy makes Cloudflare match the settings: each public name's record
// proxied or not, and, per zone, one Origin Rule sending the proxied names to the
// panel's port. Rules that are not ours are kept as they are.
func (a *App) syncCloudflareProxy() error {
	pub, prox := a.publicNames(), a.proxiedNames()
	_, port, _ := net.SplitHostPort(a.cfg.Listen)
	var errs []string
	ddns, _ := a.ddnsList()
	zones := map[string][]string{} // zone id -> proxied names in it
	tokens := map[string]string{}
	for _, n := range pub {
		token := a.cfTokenFor(n)
		if token == "" {
			if slices.Contains(prox, n) {
				errs = append(errs, n+"：没有 Cloudflare 令牌")
			}
			continue
		}
		call := cfCall(token)
		zone, err := cfZone(call, n)
		if err != nil {
			if slices.Contains(prox, n) {
				errs = append(errs, n+"："+err.Error())
			}
			continue
		}
		want := slices.Contains(prox, n)
		if want {
			zones[zone] = append(zones[zone], n)
		} else if _, ok := zones[zone]; !ok {
			zones[zone] = nil // still visit it: an old rule may have to go
		}
		tokens[zone] = token
		// the DNS record's orange cloud: DDNS entries keep their own setting
		for _, d := range ddns {
			if d.Domain == n && d.Provider == "cloudflare" && d.Proxied != want {
				_, _ = a.db.Exec(`UPDATE ddns SET proxied=?, last_ip='' WHERE id=?`, want, d.ID)
				a.kickDDNS()
			}
		}
		var recs []cfRecord
		if call("GET", "/zones/"+zone+"/dns_records?name="+n, nil, &recs) == nil {
			for _, rec := range recs {
				if (rec.Type == "A" || rec.Type == "AAAA" || rec.Type == "CNAME") && rec.Proxied != want {
					if err := call("PATCH", "/zones/"+zone+"/dns_records/"+rec.ID, map[string]any{"proxied": want}, nil); err != nil {
						errs = append(errs, n+"：切换橙色云失败："+err.Error())
					}
				}
			}
		}
	}
	for zone, ns := range zones {
		if err := cfOriginRule(cfCall(tokens[zone]), zone, ns, port); err != nil {
			errs = append(errs, err.Error())
		}
	}
	originRule.Lock()
	originRule.err = strings.Join(errs, "；")
	originRule.Unlock()
	if len(errs) > 0 {
		return errors.New(strings.Join(errs, "；"))
	}
	return nil
}

// cfOriginRule keeps our rule in the zone's http_request_origin entry point: names -> port
// (no names = remove it).
func cfOriginRule(call func(string, string, any, any) error, zone string, names []string, port string) error {
	var rs struct {
		Rules []map[string]any `json:"rules"`
	}
	path := "/zones/" + zone + "/rulesets/phases/http_request_origin/entrypoint"
	if err := call("GET", path, nil, &rs); err != nil && !strings.Contains(err.Error(), "could not find") && !strings.Contains(strings.ToLower(err.Error()), "not found") {
		return fmt.Errorf("读取 Origin Rules 失败：%v（令牌需要「Origin Rules → 编辑」权限，创建令牌时手动加上）", err)
	}
	var keep []map[string]any
	had := false
	for _, r := range rs.Rules {
		if d, _ := r["description"].(string); strings.HasPrefix(d, originRuleTag) {
			had = true
			continue
		}
		// only what PUT accepts back
		keep = append(keep, map[string]any{"expression": r["expression"], "action": r["action"], "action_parameters": r["action_parameters"],
			"description": r["description"], "enabled": r["enabled"]})
	}
	if len(names) == 0 && !had {
		return nil
	}
	if len(names) > 0 {
		quoted := make([]string, len(names))
		for i, n := range names {
			quoted[i] = `"` + n + `"`
		}
		p := 7080
		fmt.Sscanf(port, "%d", &p)
		keep = append(keep, map[string]any{"expression": "(http.host in {" + strings.Join(quoted, " ") + "})", "action": "route",
			"action_parameters": map[string]any{"origin": map[string]any{"port": p}}, "description": originRuleTag + "（" + strings.Join(names, ", ") + "）", "enabled": true})
	}
	if err := call("PUT", path, map[string]any{"rules": keep}, nil); err != nil {
		return fmt.Errorf("写入 Origin Rule 失败：%v（令牌需要「Origin Rules → 编辑」权限）", err)
	}
	return nil
}

// applyProxiedNames: Cloudflare's side, then the WAN port for Cloudflare only.
func (a *App) applyProxiedNames() error {
	err := a.syncCloudflareProxy()
	var cf []string
	if len(a.proxiedNames()) > 0 {
		cf = a.cloudflareCIDRs()
	}
	if werr := a.agent.Do("POST", "/v1/panel/wan", map[string]any{"on": a.setting("panel.via_port") == "1", "cf": cf}, nil); werr != nil {
		return werr
	}
	if len(a.proxiedNames()) > 0 {
		originCert.RLock()
		missing := originCert.cert == nil
		originCert.RUnlock()
		if missing && a.setting("panel.origin_auto") == "1" {
			if cerr := a.createOriginCert(); cerr != nil {
				log.Printf("panel: origin certificate: %v", cerr)
			}
		}
	}
	return err
}

// POST /api/panel/origin {cert, key} — store a pasted origin certificate; {create: true}
// asks Cloudflare for one; {remove: true} forgets it (super).
func (a *App) handleOriginCert(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Cert   string `json:"cert"`
		Key    string `json:"key"`
		Create bool   `json:"create"`
		Remove bool   `json:"remove"`
	}
	if readJSON(r, &req) != nil {
		jsonErr(w, 400, "请求格式错误")
		return
	}
	var err error
	what := "上传 Cloudflare 源服务器证书"
	switch {
	case req.Remove:
		what = "删除 Cloudflare 源服务器证书"
		for _, f := range []string{"origin.crt", "origin.key", "origin.source"} {
			_ = os.Remove(filepath.Join(a.tlsDir(), f))
		}
		a.loadOriginCert()
	case req.Create:
		what = "申请 Cloudflare 源服务器证书"
		err = a.createOriginCert()
		if err == nil {
			_ = a.setSetting("panel.origin_auto", "1")
		}
	default:
		err = a.saveOriginCert([]byte(strings.TrimSpace(req.Cert)+"\n"), []byte(strings.TrimSpace(req.Key)+"\n"), "pasted")
		if err == nil {
			_ = a.setSetting("panel.origin_auto", "0")
		}
	}
	if err != nil {
		jsonErr(w, 400, err.Error())
		return
	}
	a.audit(actor{user: currentUser(r), ip: a.clientIP(r)}, "setting.update", "setting", "panel.origin", what, nil, nil, false)
	writeJSON(w, 200, a.panelNamesState(false))
}

func (a *App) originState() map[string]any {
	originCert.RLock()
	defer originCert.RUnlock()
	originRule.Lock()
	defer originRule.Unlock()
	prox := a.proxiedNames()
	if prox == nil {
		prox = []string{}
	}
	out := map[string]any{"proxied": prox, "origin_error": originRule.err}
	if originCert.cert != nil {
		out["origin_cert"] = map[string]any{"names": originCert.names, "expires": originCert.exp.Unix(), "source": originCert.source}
	}
	return out
}
