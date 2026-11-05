package panel

import (
	"context"
	"crypto"
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
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/acme"
)

// Names for the panel. Passkeys only work on a domain name with a certificate the
// browser trusts, never on an IP address, and a name is also how the panel is opened
// from outside:
//
//   - wharf.<LAN domain> (wharf.lan): dnsmasq answers it with the router's LAN address and
//     the panel's own certificate covers it; devices trust it once the panel's CA is installed.
//   - public names of the owner's (wharf.example.com, several allowed): dnsmasq answers them
//     at home too, and one Let's Encrypt certificate covers them all through a DNS-01
//     challenge on Cloudflare, so no device needs anything installed. From the internet they
//     are reached through the 443 SNI front (no port in the address; the front passes the
//     visitor's address on with the PROXY protocol, so access control still sees it) and / or
//     the panel's own port opened on the WAN.
//
// The dnsmasq records are uci "domain" sections owpn_local and owpn_p<i>.

const (
	localPanelHost = "wharf"
	// panelProxyPort: the panel's loopback TLS listener behind the 443 front (PROXY protocol v2)
	panelProxyPort = 20090
)

// PanelProxyPort is panelProxyPort for the panel's main.
const PanelProxyPort = panelProxyPort

// LocalPanelName is the panel's LAN name for a dnsmasq domain.
func LocalPanelName(domain string) string { return localPanelHost + "." + domain }

var names struct {
	sync.Mutex
	at     time.Time
	domain string
	lanIP  string
}

// lanInfo: the dnsmasq domain and the router's LAN address (cached for a minute).
func (a *App) lanInfo() (domain, ip string) {
	names.Lock()
	defer names.Unlock()
	if time.Since(names.at) < time.Minute && names.domain != "" {
		return names.domain, names.lanIP
	}
	names.domain = "lan"
	if dhcp, err := a.agent.UciConfig("dhcp"); err == nil {
		for _, s := range dhcp {
			if optStr(s, ".type") == "dnsmasq" && optStr(s, "domain") != "" {
				names.domain = optStr(s, "domain")
			}
		}
	}
	if nw, err := a.agent.UciConfig("network"); err == nil {
		v := optStr(nw["lan"], "ipaddr")
		if v == "" {
			if l := optList(nw["lan"], "ipaddr"); len(l) > 0 {
				v = l[0]
			}
		}
		v, _, _ = strings.Cut(v, "/")
		if net.ParseIP(v) != nil {
			names.lanIP = v
		}
	}
	names.at = time.Now()
	return names.domain, names.lanIP
}

func (a *App) localPanelName() string {
	d, _ := a.lanInfo()
	return LocalPanelName(d)
}

// publicNames: the owner's names for the panel (setting panel.public_names, a JSON list;
// 0.18.2 kept one name in panel.public_name).
func (a *App) publicNames() []string {
	var out []string
	_ = json.Unmarshal([]byte(a.setting("panel.public_names")), &out)
	if len(out) == 0 && a.setting("panel.public_name") != "" {
		out = []string{a.setting("panel.public_name")}
	}
	return out
}

// passkeyHosts are the names passkeys can be used on.
func (a *App) passkeyHosts() []string {
	return append([]string{a.localPanelName()}, a.publicNames()...)
}

// panelFrontRoute: what the 443 front should send to the panel (nil = nothing).
func (a *App) panelFrontRoute() []string {
	if a.setting("panel.via_443") != "1" {
		return nil
	}
	return a.publicNames()
}

// syncPanelNames keeps the dnsmasq records for the panel's names.
func (a *App) syncPanelNames() error {
	_, ip := a.lanInfo()
	if ip == "" {
		return errors.New("找不到路由器的局域网地址")
	}
	dhcp, err := a.agent.UciConfig("dhcp")
	if err != nil {
		return err
	}
	want := map[string]string{"owpn_local": a.localPanelName()}
	for i, n := range a.publicNames() {
		want["owpn_p"+strconv.Itoa(i)] = n
	}
	var changes []UciChange
	for sec := range dhcp {
		if (sec == "owpn_public" || strings.HasPrefix(sec, "owpn_p")) && want[sec] == "" {
			changes = append(changes, UciChange{Op: "delete", Config: "dhcp", Section: sec})
		}
	}
	for sec, name := range want {
		cur, ok := dhcp[sec]
		switch {
		case !ok:
			changes = append(changes, UciChange{Op: "add", Config: "dhcp", Type: "domain", Name: sec, Values: map[string]any{"name": name, "ip": ip}})
		case optStr(cur, "name") != name || optStr(cur, "ip") != ip:
			changes = append(changes, UciChange{Op: "set", Config: "dhcp", Section: sec, Values: map[string]any{"name": name, "ip": ip}})
		}
	}
	if len(changes) == 0 {
		return nil
	}
	_, err = a.agent.Apply(changes...)
	return err
}

// ---- public names: one Let's Encrypt certificate over Cloudflare DNS ----

var pubCert struct {
	sync.RWMutex
	names []string
	cert  *tls.Certificate
	exp   time.Time
	err   string
	busy  bool
}

func (a *App) tlsDir() string { return a.cfg.Path("tls") }

// PublicCertificate serves the Let's Encrypt certificate for a public name (nil = not one
// of them: the local certificate answers).
func (a *App) PublicCertificate(h *tls.ClientHelloInfo) *tls.Certificate {
	pubCert.RLock()
	defer pubCert.RUnlock()
	if pubCert.cert != nil && slices.ContainsFunc(pubCert.names, func(n string) bool { return strings.EqualFold(n, h.ServerName) }) {
		return pubCert.cert
	}
	return nil
}

// loadPublicCert picks up the stored certificate if it covers every public name.
func (a *App) loadPublicCert() {
	ns := a.publicNames()
	pair, err := tls.LoadX509KeyPair(filepath.Join(a.tlsDir(), "public.crt"), filepath.Join(a.tlsDir(), "public.key"))
	pubCert.Lock()
	defer pubCert.Unlock()
	pubCert.names, pubCert.cert = ns, nil
	if err != nil || len(ns) == 0 {
		return
	}
	leaf, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		return
	}
	for _, n := range ns {
		if leaf.VerifyHostname(n) != nil {
			return
		}
	}
	pubCert.cert, pubCert.exp = &pair, leaf.NotAfter
}

// cfTokenFor: the panel's own token, else the Cloudflare account, else a Cloudflare DDNS
// entry's token for the same domain.
func (a *App) cfTokenFor(name string) string {
	if t := a.setting("panel.cf_token"); t != "" {
		return t
	}
	if t := a.setting("cloudflare.token"); t != "" {
		return t
	}
	list, _ := a.ddnsList()
	zones := zoneCandidates(name)
	for _, d := range list {
		if t := cfTokenOf(d.Creds["token"]); d.Provider == "cloudflare" && t != "" {
			for _, z := range zoneCandidates(d.Domain) {
				if slices.Contains(zones, z) && strings.Contains(z, ".") {
					return t
				}
			}
		}
	}
	return ""
}

var acmeDirectory = acme.LetsEncryptURL

// obtainPublicCert gets (or renews) one certificate for every public name.
func (a *App) obtainPublicCert(ctx context.Context) error {
	ns := a.publicNames()
	if len(ns) == 0 {
		return nil
	}
	accountKey, err := loadOrCreateKey(filepath.Join(a.tlsDir(), "acme-account.key"))
	if err != nil {
		return err
	}
	cl := &acme.Client{Key: accountKey, DirectoryURL: acmeDirectory}
	if _, err := cl.Register(ctx, &acme.Account{}, acme.AcceptTOS); err != nil && !errors.Is(err, acme.ErrAccountAlreadyExists) {
		return fmt.Errorf("Let's Encrypt 注册失败：%v", err)
	}
	order, err := cl.AuthorizeOrder(ctx, acme.DomainIDs(ns...))
	if err != nil {
		return fmt.Errorf("Let's Encrypt：%v", err)
	}
	for _, zu := range order.AuthzURLs {
		z, err := cl.GetAuthorization(ctx, zu)
		if err != nil {
			return err
		}
		if z.Status == acme.StatusValid {
			continue
		}
		name := z.Identifier.Value
		token := a.cfTokenFor(name)
		if token == "" {
			return fmt.Errorf("%s：需要 Cloudflare 账户或令牌（区域 → DNS → 编辑）", name)
		}
		call := cfCall(token)
		zone, err := cfZone(call, name)
		if err != nil {
			return fmt.Errorf("%s：%v", name, err)
		}
		var ch *acme.Challenge
		for _, c := range z.Challenges {
			if c.Type == "dns-01" {
				ch = c
			}
		}
		if ch == nil {
			return errors.New("Let's Encrypt 没有提供 DNS 验证方式")
		}
		val, err := cl.DNS01ChallengeRecord(ch.Token)
		if err != nil {
			return err
		}
		rec := "_acme-challenge." + name
		var created struct {
			ID string `json:"id"`
		}
		if err := call("POST", "/zones/"+zone+"/dns_records", map[string]any{"type": "TXT", "name": rec, "content": val, "ttl": 60}, &created); err != nil {
			return fmt.Errorf("写入验证记录失败：%v", err)
		}
		defer func() { _ = call("DELETE", "/zones/"+zone+"/dns_records/"+created.ID, nil, nil) }()
		waitTXT(ctx, rec, val, 2*time.Minute)
		if _, err := cl.Accept(ctx, ch); err != nil {
			return err
		}
		if _, err := cl.WaitAuthorization(ctx, z.URI); err != nil {
			return fmt.Errorf("%s 验证没有通过：%v", name, err)
		}
	}
	if order, err = cl.WaitOrder(ctx, order.URI); err != nil {
		return err
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{DNSNames: ns}, key)
	if err != nil {
		return err
	}
	chain, _, err := cl.CreateOrderCert(ctx, order.FinalizeURL, csr, true)
	if err != nil {
		return fmt.Errorf("签发证书失败：%v", err)
	}
	var certPEM []byte
	for _, der := range chain {
		certPEM = append(certPEM, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})...)
	}
	kb, _ := x509.MarshalECPrivateKey(key)
	if err := os.WriteFile(filepath.Join(a.tlsDir(), "public.key"), pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kb}), 0o600); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(a.tlsDir(), "public.crt"), certPEM, 0o644); err != nil {
		return err
	}
	a.loadPublicCert()
	log.Printf("panel: Let's Encrypt certificate for %s", strings.Join(ns, ", "))
	return nil
}

// waitTXT polls a public resolver until the challenge record is visible (or time runs out:
// Let's Encrypt may still see it).
func waitTXT(ctx context.Context, name, val string, max time.Duration) {
	r := &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&net.Dialer{Timeout: 3 * time.Second}).DialContext(ctx, "udp", "1.1.1.1:53")
	}}
	end := time.Now().Add(max)
	for time.Now().Before(end) {
		if txt, err := r.LookupTXT(ctx, name); err == nil && slices.Contains(txt, val) {
			time.Sleep(5 * time.Second)
			return
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(5 * time.Second):
		}
	}
}

func loadOrCreateKey(path string) (crypto.Signer, error) {
	if b, err := os.ReadFile(path); err == nil {
		if blk, _ := pem.Decode(b); blk != nil {
			if k, err := x509.ParseECPrivateKey(blk.Bytes); err == nil {
				return k, nil
			}
		}
	}
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	kb, _ := x509.MarshalECPrivateKey(k)
	return k, os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kb}), 0o600)
}

// renewPublicCert runs in the background: new names, or under 30 days left.
func (a *App) renewPublicCert(force bool) {
	ns := a.publicNames()
	pubCert.Lock()
	need := len(ns) > 0 && (force || pubCert.cert == nil || !slices.Equal(pubCert.names, ns) || time.Until(pubCert.exp) < 30*24*time.Hour)
	if !need || pubCert.busy {
		pubCert.Unlock()
		return
	}
	pubCert.busy = true
	pubCert.Unlock()
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Minute)
	defer cancel()
	err := a.obtainPublicCert(ctx)
	pubCert.Lock()
	pubCert.busy, pubCert.err = false, ""
	if err != nil {
		pubCert.err = err.Error()
		log.Printf("panel: certificate for %v: %v", ns, err)
	}
	pubCert.Unlock()
}

// panelNamesLoop: dnsmasq records and the WAN port now and then, the certificate daily.
func (a *App) panelNamesLoop() {
	time.Sleep(10 * time.Second)
	a.loadPublicCert()
	for i := 0; ; i++ {
		if err := a.syncPanelNames(); err != nil {
			log.Printf("panel names: %v", err)
		}
		if i%96 == 0 { // daily (every 15 minutes otherwise)
			a.renewPublicCert(false)
		}
		time.Sleep(15 * time.Minute)
	}
}

// ---- HTTP ----

type nameStatus struct {
	Name     string   `json:"name"`
	Resolves []string `json:"resolves"` // what public DNS answers
	Points   bool     `json:"points"`   // ... at the router's WAN address
	DDNS     int64    `json:"ddns"`     // the DDNS entry keeping it up to date (0 = none)
}

func publicLookup(name string) []string {
	r := &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&net.Dialer{Timeout: 3 * time.Second}).DialContext(ctx, "udp", "1.1.1.1:53")
	}}
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()
	ips, _ := r.LookupHost(ctx, name)
	return ips
}

// GET /api/panel/names (super)
func (a *App) handlePanelNames(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, 200, a.panelNamesState(r.URL.Query().Get("dns") == "1"))
}

func (a *App) panelNamesState(withDNS bool) map[string]any {
	_, port, _ := net.SplitHostPort(a.cfg.Listen)
	var wanIPs []string
	for _, w := range a.wans() {
		if w.IPv4 != "" {
			wanIPs = append(wanIPs, w.IPv4)
		}
	}
	ddns, _ := a.ddnsList()
	var st []nameStatus
	for _, n := range a.publicNames() {
		s := nameStatus{Name: n, Resolves: []string{}}
		for _, d := range ddns {
			if d.Domain == n {
				s.DDNS = d.ID
			}
		}
		if withDNS {
			if ips := publicLookup(n); ips != nil {
				s.Resolves = ips
			}
			s.Points = slices.ContainsFunc(s.Resolves, func(ip string) bool { return slices.Contains(wanIPs, ip) })
		}
		st = append(st, s)
	}
	if st == nil {
		st = []nameStatus{}
	}
	ext, _ := a.proxyExt()
	pubCert.RLock()
	defer pubCert.RUnlock()
	out := map[string]any{"local": a.localPanelName(), "port": port, "names": st,
		"via_443": a.setting("panel.via_443") == "1", "via_port": a.setting("panel.via_port") == "1",
		"front_ready": ext.Installed, "wan_ips": wanIPs,
		"token_set": a.setting("panel.cf_token") != "", "account": a.setting("cloudflare.token") != "",
		"cert_busy": pubCert.busy, "cert_error": pubCert.err}
	if pubCert.cert != nil {
		out["cert_expires"] = pubCert.exp.Unix()
	}
	return out
}

// POST /api/panel/names {names, token, via_443, via_port} — the public names and how the
// internet reaches them (super).
func (a *App) handlePanelNamesSave(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Names   []string `json:"names"`
		Token   string   `json:"token"`
		Via443  bool     `json:"via_443"`
		ViaPort bool     `json:"via_port"`
	}
	if readJSON(r, &req) != nil {
		jsonErr(w, 400, "请求格式错误")
		return
	}
	var ns []string
	for _, n := range req.Names {
		n = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(n), "."))
		if n == "" || slices.Contains(ns, n) {
			continue
		}
		if !hostnameOK(n) || strings.HasSuffix(n, ".lan") || strings.HasSuffix(n, ".local") {
			jsonErr(w, 400, n+"：请填写你自己的公网域名，例如 wharf.example.com")
			return
		}
		if owner := onePanelOwner(n); owner != nil {
			jsonErr(w, 400, n+" 是 1Panel 网站「"+owner.Domain+"」的域名，请换一个")
			return
		}
		ns = append(ns, n)
	}
	if len(ns) > 8 {
		jsonErr(w, 400, "最多 8 个域名")
		return
	}
	if len(ns) > 0 && req.Via443 {
		if ext, _ := a.proxyExt(); !ext.Installed {
			jsonErr(w, 400, "通过 443 进入需要代理扩展的 443 分流器（「代理」页安装扩展）；也可以只用独立端口")
			return
		}
		nodes, _ := a.proxyNodes()
		for _, n := range nodes {
			for _, s := range n.sniNames() {
				if slices.Contains(ns, s) {
					jsonErr(w, 400, s+" 已被代理节点「"+n.Name+"」使用")
					return
				}
			}
		}
	}
	old := a.publicNames()
	_ = a.setSetting("panel.public_names", mustJSON(ns))
	_ = a.setSetting("panel.public_name", "")
	if t := strings.TrimSpace(req.Token); t != "" && !strings.HasPrefix(t, "••") {
		_ = a.setSetting("panel.cf_token", t)
	}
	if len(ns) == 0 {
		req.Via443, req.ViaPort = false, false
		_ = a.setSetting("panel.cf_token", "")
	}
	_ = a.setSetting("panel.via_443", boolStr(req.Via443))
	_ = a.setSetting("panel.via_port", boolStr(req.ViaPort))
	if err := a.syncPanelNames(); err != nil {
		log.Printf("panel names: %v", err)
	}
	if err := a.agent.Do("POST", "/v1/panel/wan", map[string]bool{"on": req.ViaPort}, nil); err != nil {
		jsonErr(w, 500, "开放面板端口失败："+err.Error())
		return
	}
	if ext, _ := a.proxyExt(); ext.Installed {
		if err := a.reapplyProxy(); err != nil {
			jsonErr(w, 400, "443 分流器更新失败："+err.Error())
			return
		}
	}
	a.loadPublicCert()
	go a.renewPublicCert(!slices.Equal(old, ns))
	a.audit(actor{user: currentUser(r), ip: a.clientIP(r)}, "setting.update", "setting", "panel.public_names",
		fmt.Sprintf("面板公网域名：%s（443：%v，独立端口：%v）", firstNonEmpty(strings.Join(ns, "、"), "无"), req.Via443, req.ViaPort), old, ns, false)
	time.Sleep(300 * time.Millisecond) // let the renewal mark itself busy
	writeJSON(w, 200, a.panelNamesState(false))
}

// POST /api/panel/names/ddns {name} — keep a public name pointed at home with a DDNS entry
// on the Cloudflare account (A record, checked every 5 minutes, refreshed daily).
func (a *App) handlePanelNameDDNS(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name string `json:"name"`
	}
	_ = readJSON(r, &req)
	if !slices.Contains(a.publicNames(), req.Name) {
		jsonErr(w, 400, "不是面板的公网域名")
		return
	}
	if a.setting("cloudflare.token") == "" {
		jsonErr(w, 400, "请先在「动态域名 DDNS」页连接 Cloudflare 账户")
		return
	}
	d := DDNS{Name: "面板 " + req.Name, Enabled: true, Provider: "cloudflare", Creds: map[string]string{"token": accountTokenMarker},
		Domain: req.Name, RType: "A", Source: DDNSSource{Mode: "auto", CheckMin: 5}, Interval: 1440, OnChange: true, TTL: 300}
	id, err := a.createDDNS(&d)
	if err != nil {
		jsonErr(w, 400, err.Error())
		return
	}
	a.audit(actor{user: currentUser(r), ip: a.clientIP(r)}, "ddns.save", "ddns", strconv.FormatInt(id, 10), "为面板域名 "+req.Name+" 添加 DDNS", nil, nil, false)
	go func() { _, _, _ = a.runDDNS(&d, true) }()
	writeJSON(w, 200, a.panelNamesState(false))
}
