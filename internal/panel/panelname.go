package panel

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/acme"
)

// Names for the panel. Passkeys only work on a domain name with a certificate the
// browser trusts, never on an IP address, so the panel can be reached as:
//
//   - wharf.<LAN domain> (wharf.lan): dnsmasq answers it with the router's LAN address and
//     the panel's own certificate covers it; devices trust it once the panel's CA is installed.
//   - a public name of the owner's (panel.example.com): dnsmasq answers it at home too, and
//     the certificate comes from Let's Encrypt through a DNS-01 challenge on Cloudflare,
//     so no device needs anything installed and no port has to be open.
//
// The dnsmasq records are uci "domain" sections owpn_local / owpn_public.

const localPanelHost = "wharf"

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

// passkeyHosts are the names passkeys can be used on.
func (a *App) passkeyHosts() []string {
	out := []string{a.localPanelName()}
	if p := a.setting("panel.public_name"); p != "" {
		out = append(out, p)
	}
	return out
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
	want := map[string]string{"owpn_local": a.localPanelName(), "owpn_public": a.setting("panel.public_name")}
	var changes []UciChange
	for sec, name := range want {
		cur, ok := dhcp[sec]
		switch {
		case name == "" && ok:
			changes = append(changes, UciChange{Op: "delete", Config: "dhcp", Section: sec})
		case name == "":
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

// ---- public name: Let's Encrypt over Cloudflare DNS ----

var pubCert struct {
	sync.RWMutex
	name string
	cert *tls.Certificate
	exp  time.Time
	err  string
	busy bool
}

func (a *App) tlsDir() string { return a.cfg.Path("tls") }

// PublicCertificate serves the Let's Encrypt certificate for the public name (nil = not
// this name, the local certificate answers).
func (a *App) PublicCertificate(h *tls.ClientHelloInfo) *tls.Certificate {
	pubCert.RLock()
	defer pubCert.RUnlock()
	if pubCert.cert != nil && strings.EqualFold(h.ServerName, pubCert.name) {
		return pubCert.cert
	}
	return nil
}

func (a *App) loadPublicCert() {
	name := a.setting("panel.public_name")
	pair, err := tls.LoadX509KeyPair(filepath.Join(a.tlsDir(), "public.crt"), filepath.Join(a.tlsDir(), "public.key"))
	pubCert.Lock()
	defer pubCert.Unlock()
	pubCert.name, pubCert.cert = name, nil
	if err != nil || name == "" {
		return
	}
	leaf, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil || leaf.VerifyHostname(name) != nil {
		return
	}
	pubCert.cert, pubCert.exp = &pair, leaf.NotAfter
}

// cfTokenFor: the token set for the panel, else a Cloudflare DDNS entry's token for the
// same domain.
func (a *App) cfTokenFor(name string) string {
	if t := a.setting("panel.cf_token"); t != "" {
		return t
	}
	list, _ := a.ddnsList()
	zones := zoneCandidates(name)
	for _, d := range list {
		if d.Provider == "cloudflare" && d.Creds["token"] != "" {
			for _, z := range zoneCandidates(d.Domain) {
				if slices.Contains(zones, z) && strings.Contains(z, ".") {
					return d.Creds["token"]
				}
			}
		}
	}
	return ""
}

var acmeDirectory = acme.LetsEncryptURL

// obtainPublicCert gets (or renews) the certificate for the public name.
func (a *App) obtainPublicCert(ctx context.Context) error {
	name := a.setting("panel.public_name")
	if name == "" {
		return nil
	}
	token := a.cfTokenFor(name)
	if token == "" {
		return errors.New("需要 Cloudflare API 令牌（Zone.DNS 编辑权限），或者在 DDNS 里有这个域名的 Cloudflare 记录")
	}
	call := cfCall(token)
	zone, err := cfZone(call, name)
	if err != nil {
		return err
	}
	accountKey, err := loadOrCreateKey(filepath.Join(a.tlsDir(), "acme-account.key"))
	if err != nil {
		return err
	}
	cl := &acme.Client{Key: accountKey, DirectoryURL: acmeDirectory}
	if _, err := cl.Register(ctx, &acme.Account{}, acme.AcceptTOS); err != nil && !errors.Is(err, acme.ErrAccountAlreadyExists) {
		return fmt.Errorf("Let's Encrypt 注册失败：%v", err)
	}
	order, err := cl.AuthorizeOrder(ctx, acme.DomainIDs(name))
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
			return fmt.Errorf("域名验证没有通过：%v", err)
		}
	}
	if order, err = cl.WaitOrder(ctx, order.URI); err != nil {
		return err
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{DNSNames: []string{name}}, key)
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
	log.Printf("panel: Let's Encrypt certificate for %s", name)
	return nil
}

// waitTXT polls public resolvers until the challenge record is visible (or time runs out:
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

// renewPublicCert runs in the background: a new name, or under 30 days left.
func (a *App) renewPublicCert(force bool) {
	name := a.setting("panel.public_name")
	pubCert.Lock()
	need := name != "" && (force || pubCert.cert == nil || pubCert.name != name || time.Until(pubCert.exp) < 30*24*time.Hour)
	if !need || pubCert.busy {
		pubCert.Unlock()
		return
	}
	pubCert.busy = true
	pubCert.Unlock()
	ctx, cancel := context.WithTimeout(context.Background(), 6*time.Minute)
	defer cancel()
	err := a.obtainPublicCert(ctx)
	pubCert.Lock()
	pubCert.busy, pubCert.err = false, ""
	if err != nil {
		pubCert.err = err.Error()
		log.Printf("panel: certificate for %s: %v", name, err)
	}
	pubCert.Unlock()
}

// panelNamesLoop: dnsmasq records now and then, the public certificate daily.
func (a *App) panelNamesLoop() {
	time.Sleep(10 * time.Second)
	a.loadPublicCert()
	for i := 0; ; i++ {
		if err := a.syncPanelNames(); err != nil {
			log.Printf("panel names: %v", err)
		}
		if i%96 == 0 { // daily (every 15 min otherwise)
			a.renewPublicCert(false)
		}
		time.Sleep(15 * time.Minute)
	}
}

// GET /api/panel/names (super)
func (a *App) handlePanelNames(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, 200, a.panelNamesState())
}

func (a *App) panelNamesState() map[string]any {
	_, port, _ := net.SplitHostPort(a.cfg.Listen)
	pubCert.RLock()
	defer pubCert.RUnlock()
	out := map[string]any{"local": a.localPanelName(), "port": port, "public": a.setting("panel.public_name"),
		"token_set": a.setting("panel.cf_token") != "", "token_from_ddns": a.setting("panel.cf_token") == "" && a.setting("panel.public_name") != "" && a.cfTokenFor(a.setting("panel.public_name")) != "",
		"cert_busy": pubCert.busy, "cert_error": pubCert.err}
	if pubCert.cert != nil {
		out["cert_expires"] = pubCert.exp.Unix()
	}
	return out
}

// POST /api/panel/names {public, token} — set or clear the public name (super).
func (a *App) handlePanelNamesSave(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Public string `json:"public"`
		Token  string `json:"token"`
	}
	if readJSON(r, &req) != nil {
		jsonErr(w, 400, "请求格式错误")
		return
	}
	name := strings.ToLower(strings.TrimSpace(req.Public))
	if name != "" && (!hostnameOK(name) || strings.HasSuffix(name, ".lan") || strings.HasSuffix(name, ".local")) {
		jsonErr(w, 400, "请填写你自己的公网域名，例如 panel.example.com")
		return
	}
	old := a.setting("panel.public_name")
	_ = a.setSetting("panel.public_name", name)
	if t := strings.TrimSpace(req.Token); t != "" && !strings.HasPrefix(t, "••") {
		_ = a.setSetting("panel.cf_token", t)
	}
	if name == "" {
		_ = a.setSetting("panel.cf_token", "")
	}
	if err := a.syncPanelNames(); err != nil {
		log.Printf("panel names: %v", err)
	}
	a.loadPublicCert()
	go a.renewPublicCert(name != old)
	a.audit(actor{user: currentUser(r), ip: a.clientIP(r)}, "setting.update", "setting", "panel.public_name", "设置面板公网域名 "+firstNonEmpty(name, "（清除）"), old, name, false)
	time.Sleep(300 * time.Millisecond) // let the renewal mark itself busy
	writeJSON(w, 200, a.panelNamesState())
}
