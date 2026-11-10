package panel

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/wangsirco/wharf/internal/sign"
	"github.com/wangsirco/wharf/internal/version"
)

// Berth integration. Berth is the same author's Linux server panel; once paired, the two
// panels call each other over a signed, audited channel:
//
//	Berth → Wharf  /api/ext/berth/v1/*   "Authorization: Bearer wharf_bth_…" + X-Berth-Ts/Nonce/Sig
//	Wharf → Berth  /api/ext/wharf/v1/*   "Authorization: Bearer berth_wrf_…" + X-Wharf-Ts/Nonce/Sig
//
// The signature is the agent's (internal/sign) keyed with sign.DeriveKey(token). Server to
// server, each side pins the other's certificate fingerprint taken at pairing, so a local
// CA on either side is fine. The protocol is written down in docs/BERTH.md.
//
// Pairing (super admin only):
//  1. Berth opens https://<wharf>/pair/berth?berth_url=…&berth_fp=…&code=…&cb=…
//  2. The super admin picks scopes, lifetime and the Berth host(s) and agrees; the browser
//     goes back to cb?state=<Berth's code>&code=<Wharf's one-time code>&wharf_url=…&wharf_fp=…
//  3. Berth posts {code, token: berth_wrf_…, name} to /api/ext/berth/v1/pair/exchange and
//     gets {token: wharf_bth_…}. From then on both hold a token for the other.
//
// Only one Berth is paired at a time. Wharf keeps a hash of its own token, and the signing
// key and Berth's token encrypted with a key file in the data directory.

const berthTokenPrefix = "wharf_bth_"

type berthScope struct {
	Key   string `json:"key"`
	Label string `json:"label"`
	Desc  string `json:"desc"`
}

var berthScopes = []berthScope{
	{"forwards", "端口映射", "在选定的 Berth 主机上新建、修改、删除由 Berth 创建的端口映射；可读取全部映射用于冲突检查"},
	{"sni", "443 分流", "让 443 分流把指定域名原样转给 Berth 主机（代理扩展开启时）"},
	{"ddns", "DDNS 协调", "读取 DDNS 状态，协调域名由谁维护，必要时让 Wharf 立即更新"},
	{"devices.read", "读取设备", "读取设备列表，用于在 Berth 里挑选内网地址"},
	{"traffic.read", "读取流量", "读取 Berth 主机的公网流量、外部连接、扫描与攻击来源"},
	{"bans", "封禁同步", "下发或撤回同步过来的封禁；读取 Wharf 里标为可同步的封禁"},
	{"alerts", "告警转交", "向 Wharf 投递告警，或接收 Wharf 转交的告警"},
	{"sso", "免登录跳转", "为已设置对应关系的 Berth 用户申请一次性登录票据"},
}

func validBerthScope(k string) bool {
	return slices.ContainsFunc(berthScopes, func(s berthScope) bool { return s.Key == k })
}

type berthTarget struct {
	IP   string `json:"ip"`
	MAC  string `json:"mac,omitempty"`
	Name string `json:"name,omitempty"`
}

type berthLink struct {
	ID        int64         `json:"id"`
	Name      string        `json:"name"`
	URL       string        `json:"url"`
	CertFP    string        `json:"cert_fp"`
	WharfURL  string        `json:"wharf_url"`
	Scopes    []string      `json:"scopes"`
	Targets   []berthTarget `json:"targets"`
	ExpiresAt int64         `json:"expires_at"` // 0 = never
	CreatedAt int64         `json:"created_at"`
	LastSeen  int64         `json:"last_seen_at"`
	Status    string        `json:"status"` // active | expired | invalid (Berth no longer accepts our token)
	LastError string        `json:"last_error"`

	tokenHash string
	signKey   []byte
	outToken  string
}

func (l *berthLink) has(scope string) bool { return slices.Contains(l.Scopes, scope) }

func (l *berthLink) state() string {
	if l.Status == "invalid" {
		return "invalid"
	}
	if l.ExpiresAt > 0 && time.Now().Unix() > l.ExpiresAt {
		return "expired"
	}
	return "active"
}

// label is how Berth appears as the actor in audit entries and alerts.
func (l *berthLink) label() string { return "Berth（" + l.Name + "）" }

// ---- secrets at rest ----

var berthKeyMu sync.Mutex

func (a *App) berthSecretKey() ([]byte, error) {
	berthKeyMu.Lock()
	defer berthKeyMu.Unlock()
	p := a.cfg.Path("berth.key")
	if b, err := os.ReadFile(p); err == nil && len(b) == 32 {
		return b, nil
	}
	k := make([]byte, 32)
	if _, err := rand.Read(k); err != nil {
		return nil, err
	}
	if err := os.WriteFile(p, k, 0o600); err != nil {
		return nil, err
	}
	return k, nil
}

func (a *App) berthSeal(plain []byte) (string, error) {
	k, err := a.berthSecretKey()
	if err != nil {
		return "", err
	}
	blk, _ := aes.NewCipher(k)
	g, _ := cipher.NewGCM(blk)
	nonce := make([]byte, g.NonceSize())
	_, _ = rand.Read(nonce)
	return base64.StdEncoding.EncodeToString(g.Seal(nonce, nonce, plain, nil)), nil
}

func (a *App) berthOpen(enc string) ([]byte, error) {
	k, err := a.berthSecretKey()
	if err != nil {
		return nil, err
	}
	raw, err := base64.StdEncoding.DecodeString(enc)
	if err != nil {
		return nil, err
	}
	blk, _ := aes.NewCipher(k)
	g, _ := cipher.NewGCM(blk)
	if len(raw) < g.NonceSize() {
		return nil, errors.New("密文损坏")
	}
	return g.Open(nil, raw[:g.NonceSize()], raw[g.NonceSize():], nil)
}

// ---- storage ----

const berthCols = `id, name, url, cert_fp, token_hash, outbound_token_enc, sign_key_enc, scopes, target_devices, COALESCE(expires_at,0), created_at, COALESCE(last_seen_at,0), wharf_url, status, last_error`

func (a *App) scanBerth(row interface{ Scan(...any) error }) (*berthLink, error) {
	var l berthLink
	var outEnc, keyEnc, scopes, targets string
	if err := row.Scan(&l.ID, &l.Name, &l.URL, &l.CertFP, &l.tokenHash, &outEnc, &keyEnc, &scopes, &targets, &l.ExpiresAt, &l.CreatedAt, &l.LastSeen,
		&l.WharfURL, &l.Status, &l.LastError); err != nil {
		return nil, err
	}
	_ = json.Unmarshal([]byte(scopes), &l.Scopes)
	_ = json.Unmarshal([]byte(targets), &l.Targets)
	if l.Scopes == nil {
		l.Scopes = []string{}
	}
	if l.Targets == nil {
		l.Targets = []berthTarget{}
	}
	if b, err := a.berthOpen(outEnc); err == nil {
		l.outToken = string(b)
	}
	if b, err := a.berthOpen(keyEnc); err == nil {
		l.signKey = b
	}
	return &l, nil
}

// berth returns the paired Berth, or nil.
func (a *App) berth() *berthLink {
	l, err := a.scanBerth(a.db.QueryRow(`SELECT ` + berthCols + ` FROM berth_link ORDER BY id DESC LIMIT 1`))
	if err != nil {
		return nil
	}
	return l
}

func (a *App) berthByToken(token string) *berthLink {
	l, err := a.scanBerth(a.db.QueryRow(`SELECT `+berthCols+` FROM berth_link WHERE token_hash=?`, tokenHash(token)))
	if err != nil {
		return nil
	}
	return l
}

// allowsTarget: Berth may only point mappings at the hosts chosen at pairing. A host
// chosen with its MAC also counts at the address DHCP gives it now.
func (a *App) berthAllowsTarget(l *berthLink, ip string) bool {
	for _, t := range l.Targets {
		if t.IP == ip {
			return true
		}
	}
	var devs []Device
	if a.agent.Do("GET", "/v1/devices", nil, &devs) == nil {
		for _, d := range devs {
			if d.IP != ip {
				continue
			}
			for _, t := range l.Targets {
				if t.MAC != "" && strings.EqualFold(t.MAC, d.MAC) {
					return true
				}
			}
		}
	}
	return false
}

// berthHostIPs: the Berth hosts' current addresses (for badges on the device page).
func (a *App) berthHostIPs(l *berthLink) map[string]bool {
	out := map[string]bool{}
	for _, t := range l.Targets {
		out[t.IP] = true
	}
	var devs []Device
	if a.agent.Do("GET", "/v1/devices", nil, &devs) == nil {
		for _, d := range devs {
			for _, t := range l.Targets {
				if t.MAC != "" && strings.EqualFold(t.MAC, d.MAC) && d.IP != "" {
					out[d.IP] = true
				}
			}
		}
	}
	return out
}

// ---- certificate pinning ----

func normFP(s string) string {
	return strings.ToLower(strings.NewReplacer(":", "", " ", "", "-", "").Replace(strings.TrimSpace(s)))
}

func validFP(s string) bool {
	if len(s) != 64 {
		return false
	}
	_, err := hex.DecodeString(s)
	return err == nil
}

// pinnedClient trusts a server whose certificate chain contains the pinned SHA-256
// fingerprint (leaf or CA), or that has a publicly valid certificate for its name.
func pinnedClient(fp string, timeout time.Duration) *http.Client {
	fp = normFP(fp)
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true, // replaced by VerifyConnection below
			MinVersion:         tls.VersionTLS12,
			VerifyConnection: func(cs tls.ConnectionState) error {
				for _, c := range cs.PeerCertificates {
					h := sha256.Sum256(c.Raw)
					if hex.EncodeToString(h[:]) == fp {
						return nil
					}
				}
				if len(cs.PeerCertificates) > 0 {
					opts := x509.VerifyOptions{DNSName: cs.ServerName, Intermediates: x509.NewCertPool()}
					for _, c := range cs.PeerCertificates[1:] {
						opts.Intermediates.AddCert(c)
					}
					if _, err := cs.PeerCertificates[0].Verify(opts); err == nil && cs.ServerName != "" {
						return nil
					}
				}
				return errors.New("对方证书与配对时记录的指纹不符")
			},
		},
		Proxy:                 nil,
		ResponseHeaderTimeout: timeout,
	}
	return &http.Client{Timeout: timeout, Transport: tr, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
}

// selfFingerprint: what Berth should pin for this panel — the local CA (stable across leaf
// renewals) when the panel serves its own certificates, else the configured certificate.
func (a *App) selfFingerprint() string {
	if a.CA != nil {
		return a.CA.CAFingerprint()
	}
	if a.cfg.TLS == "files" {
		if c, err := tls.LoadX509KeyPair(a.cfg.CertFile, a.cfg.KeyFile); err == nil && len(c.Certificate) > 0 {
			h := sha256.Sum256(c.Certificate[len(c.Certificate)-1])
			return hex.EncodeToString(h[:])
		}
	}
	return ""
}

// ---- outbound calls (Wharf → Berth) ----

type berthHTTPError struct {
	Code int
	Msg  string
}

func (e *berthHTTPError) Error() string { return e.Msg }

var berthClientHook func(fp string) *http.Client // tests

// berthCall signs and sends a request to Berth's /api/ext/wharf/v1 API.
func (a *App) berthCall(l *berthLink, method, path string, body, out any) error {
	if l == nil {
		return errors.New("尚未与 Berth 配对")
	}
	if l.outToken == "" {
		return errors.New("Berth 的令牌无法解密，请重新配对")
	}
	var raw []byte
	if body != nil {
		raw, _ = json.Marshal(body)
	}
	req, err := http.NewRequest(method, strings.TrimRight(l.URL, "/")+"/api/ext/wharf/v1"+path, bytes.NewReader(raw))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+l.outToken)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	sign.SignPrefixed(req, "X-Wharf", sign.DeriveKey(l.outToken), raw)
	c := pinnedClient(l.CertFP, 15*time.Second)
	if berthClientHook != nil {
		c = berthClientHook(l.CertFP)
	}
	resp, err := c.Do(req)
	if err != nil {
		a.berthNoteError(l, "连接 Berth 失败："+shortErr(err))
		return fmt.Errorf("连接 Berth 失败：%s", shortErr(err))
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if resp.StatusCode >= 300 {
		var e struct {
			Error string `json:"error"`
		}
		_ = json.Unmarshal(b, &e)
		msg := firstNonEmpty(e.Error, fmt.Sprintf("Berth 返回 %d", resp.StatusCode))
		if resp.StatusCode == 401 {
			_, _ = a.db.Exec(`UPDATE berth_link SET status='invalid', last_error=? WHERE id=?`, "Berth 不再接受 Wharf 的令牌："+msg, l.ID)
		}
		return &berthHTTPError{resp.StatusCode, msg}
	}
	_, _ = a.db.Exec(`UPDATE berth_link SET last_error='' WHERE id=? AND last_error<>''`, l.ID)
	if out != nil && len(b) > 0 {
		return json.Unmarshal(b, out)
	}
	return nil
}

func (a *App) berthNoteError(l *berthLink, msg string) {
	_, _ = a.db.Exec(`UPDATE berth_link SET last_error=? WHERE id=?`, truncate(msg, 300), l.ID)
}

// berthNotify tells Berth about something that happened on this side (best effort, async).
func (a *App) berthNotify(typ string, data map[string]any) {
	l := a.berth()
	if l == nil || l.state() != "active" {
		return
	}
	if data == nil {
		data = map[string]any{}
	}
	data["type"] = typ
	data["ts"] = time.Now().Unix()
	go func() {
		if err := a.berthCall(l, "POST", "/events", data, nil); err != nil {
			log.Printf("berth: event %s: %v", typ, err)
		}
	}()
}

// ---- inbound API (Berth → Wharf) ----

type berthCtxKey struct{}

type berthReq struct {
	link  *berthLink
	body  []byte
	actor string // X-Berth-Actor: who on Berth's side, for the audit summary

	fwdRef, fwdHost string // the site a mapping belongs to (forwards)
}

func berthFrom(r *http.Request) *berthReq {
	v, _ := r.Context().Value(berthCtxKey{}).(*berthReq)
	return v
}

// berthAPI authenticates a request from the paired Berth: token, signature, time window,
// nonce and scope. Failures are logged as blocked visits and count towards the limiter.
func (a *App) berthAPI(scope string, h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ip := a.clientIP(r)
		key := "berth:" + ip
		if a.limiter.blocked(key) {
			jsonErr(w, 429, "失败次数过多，请 15 分钟后再试")
			return
		}
		fail := func(code int, msg, why string) {
			a.limiter.record(key)
			a.logBlocked(r, ip, accessResult{reason: "Berth 接口：" + why})
			jsonErr(w, code, msg)
		}
		tok, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
		if !ok || !strings.HasPrefix(tok, berthTokenPrefix) {
			fail(401, "缺少对接令牌", "缺少令牌")
			return
		}
		l := a.berthByToken(tok)
		if l == nil || l.signKey == nil {
			fail(401, "对接令牌无效", "令牌无效")
			return
		}
		switch l.state() {
		case "expired":
			jsonErr(w, 401, "对接已过期，请重新配对")
			return
		case "invalid":
			// Berth answered 401 to us earlier, yet calls with a good token: it is alive again
			_, _ = a.db.Exec(`UPDATE berth_link SET status='active' WHERE id=?`, l.ID)
		}
		body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
		if err != nil {
			jsonErr(w, 400, "请求读取失败")
			return
		}
		nonce, err := sign.CheckPrefixed(r, "X-Berth", l.signKey, body)
		if err != nil {
			fail(401, "签名校验失败："+err.Error(), "签名错误（"+err.Error()+"）")
			return
		}
		now := time.Now().Unix()
		if res, err := a.db.Exec(`INSERT OR IGNORE INTO berth_nonce(nonce, seen_at) VALUES(?,?)`, nonce, now); err != nil {
			jsonErr(w, 500, err.Error())
			return
		} else if n, _ := res.RowsAffected(); n == 0 {
			fail(401, "重复的请求（nonce 已使用）", "重放")
			return
		}
		if scope != "" && !l.has(scope) {
			jsonErr(w, 403, "配对时没有授予「"+berthScopeLabel(scope)+"」权限")
			return
		}
		a.limiter.reset(key)
		_, _ = a.db.Exec(`UPDATE berth_link SET last_seen_at=? WHERE id=?`, now, l.ID)
		r.Body = io.NopCloser(bytes.NewReader(body))
		br := &berthReq{link: l, body: body, actor: clean(r.Header.Get("X-Berth-Actor"), 120)}
		h(w, r.WithContext(context.WithValue(r.Context(), berthCtxKey{}, br)))
	}
}

func berthScopeLabel(k string) string {
	for _, s := range berthScopes {
		if s.Key == k {
			return s.Label
		}
	}
	return k
}

// berthUser stands in for Berth in audit entries and permission checks: it has the super
// admin's reach, and the handlers narrow it (only its own mappings, only its hosts).
func berthUser(l *berthLink) *User {
	return &User{ID: 0, Username: l.label(), DisplayName: l.label(), Role: RoleSuper}
}

func (a *App) berthActor(r *http.Request) actor {
	br := berthFrom(r)
	return actor{user: berthUser(br.link), ip: a.clientIP(r), berth: br}
}

// summary appends who on Berth's side asked, when Berth said so.
func (br *berthReq) summary(s string) string {
	if br != nil && br.actor != "" {
		return s + "（" + br.actor + "）"
	}
	return s
}

// ---- pairing ----

type berthPending struct {
	BerthURL string
	BerthFP  string
	Scopes   []string
	Targets  []berthTarget
	Expires  int64 // link lifetime end (0 = never)
	WharfURL string
	By       *User
	IP       string
	until    time.Time
}

var berthPairing = struct {
	sync.Mutex
	m map[string]*berthPending
}{m: map[string]*berthPending{}}

func cleanBerthURL(s string) (string, error) {
	u, err := url.Parse(strings.TrimSpace(s))
	if err != nil || (u.Scheme != "https") || u.Host == "" || u.User != nil {
		return "", errors.New("Berth 地址必须是 https:// 开头的网址")
	}
	return "https://" + u.Host + strings.TrimRight(u.Path, "/"), nil
}

// GET /api/berth/pair/preview?berth_url=&berth_fp=&cb=
func (a *App) handleBerthPairPreview(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	bu, err := cleanBerthURL(q.Get("berth_url"))
	if err != nil {
		jsonErr(w, 400, err.Error())
		return
	}
	fp := normFP(q.Get("berth_fp"))
	if !validFP(fp) {
		jsonErr(w, 400, "Berth 证书指纹格式不对（应为 64 位十六进制 SHA-256）")
		return
	}
	if err := checkBerthCallback(bu, q.Get("cb")); err != nil {
		jsonErr(w, 400, err.Error())
		return
	}
	// match the Berth host among the devices by its address
	host := strings.Split(strings.TrimPrefix(bu, "https://"), "/")[0]
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	ips := []string{}
	if ip, err := netip.ParseAddr(host); err == nil {
		ips = append(ips, ip.String())
	} else {
		ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
		if addrs, err := net.DefaultResolver.LookupHost(ctx, host); err == nil {
			ips = addrs
		}
		cancel()
	}
	var devs []Device
	_ = a.agent.Do("GET", "/v1/devices", nil, &devs)
	metas := a.deviceMetas()
	type cand struct {
		berthTarget
		Online  bool `json:"online"`
		Matched bool `json:"matched"`
	}
	cands := []cand{}
	for _, d := range devs {
		if d.IP == "" {
			continue
		}
		id := a.identifyDevice(d.MAC, firstNonEmpty(d.StaticName, d.Hostname), metas[d.MAC].Type)
		cands = append(cands, cand{berthTarget{IP: d.IP, MAC: d.MAC, Name: displayName(metas[d.MAC].Alias, d.StaticName, d.Hostname, id)}, d.Online, slices.Contains(ips, d.IP)})
	}
	slices.SortFunc(cands, func(x, y cand) int {
		if x.Matched != y.Matched {
			return map[bool]int{true: -1, false: 1}[x.Matched]
		}
		return strings.Compare(x.Name, y.Name)
	})
	existing := a.berth()
	writeJSON(w, 200, map[string]any{"berth_url": bu, "berth_fp": fp, "scopes": berthScopes, "devices": cands, "resolved": ips,
		"paired": existing != nil, "paired_name": func() string {
			if existing != nil {
				return existing.Name
			}
			return ""
		}()})
}

// checkBerthCallback: the browser only goes back to Berth itself.
func checkBerthCallback(berthURL, cb string) error {
	u, err := url.Parse(cb)
	b, _ := url.Parse(berthURL)
	if err != nil || u.Scheme != "https" || u.Host == "" || b == nil || !strings.EqualFold(u.Host, b.Host) {
		return errors.New("回调地址必须在 Berth 自己的地址上")
	}
	return nil
}

// POST /api/berth/pair/approve {berth_url, berth_fp, code, cb, scopes, expires_days, targets}
func (a *App) handleBerthPairApprove(w http.ResponseWriter, r *http.Request) {
	var req struct {
		BerthURL    string        `json:"berth_url"`
		BerthFP     string        `json:"berth_fp"`
		Code        string        `json:"code"`
		CB          string        `json:"cb"`
		Scopes      []string      `json:"scopes"`
		ExpiresDays int           `json:"expires_days"`
		Targets     []berthTarget `json:"targets"`
	}
	if readJSON(r, &req) != nil {
		jsonErr(w, 400, "请求格式错误")
		return
	}
	bu, err := cleanBerthURL(req.BerthURL)
	if err != nil {
		jsonErr(w, 400, err.Error())
		return
	}
	fp := normFP(req.BerthFP)
	if !validFP(fp) {
		jsonErr(w, 400, "Berth 证书指纹格式不对")
		return
	}
	if err := checkBerthCallback(bu, req.CB); err != nil {
		jsonErr(w, 400, err.Error())
		return
	}
	if req.Code == "" || len(req.Code) > 128 {
		jsonErr(w, 400, "缺少 Berth 的配对码")
		return
	}
	if a.berth() != nil {
		jsonErr(w, 409, "已经和一个 Berth 配对；请先在「系统设置 → 集成」里解除配对")
		return
	}
	scopes := []string{}
	for _, s := range req.Scopes {
		if !validBerthScope(s) {
			jsonErr(w, 400, "未知权限 "+s)
			return
		}
		if !slices.Contains(scopes, s) {
			scopes = append(scopes, s)
		}
	}
	if len(scopes) == 0 {
		jsonErr(w, 400, "至少授予一项权限")
		return
	}
	targets, err := cleanTargets(req.Targets)
	if err != nil {
		jsonErr(w, 400, err.Error())
		return
	}
	if slices.Contains(scopes, "forwards") && len(targets) == 0 {
		jsonErr(w, 400, "授予「端口映射」时，至少选择一台 Berth 主机")
		return
	}
	var exp int64
	switch req.ExpiresDays {
	case 0:
	case 30, 90, 365:
		exp = time.Now().Add(time.Duration(req.ExpiresDays) * 24 * time.Hour).Unix()
	default:
		jsonErr(w, 400, "有效期只能是永久、30、90 或 365 天")
		return
	}
	wharfURL := "https://" + r.Host
	code := sign.RandomHex(20)
	berthPairing.Lock()
	for k, p := range berthPairing.m {
		if time.Now().After(p.until) {
			delete(berthPairing.m, k)
		}
	}
	berthPairing.m[code] = &berthPending{BerthURL: bu, BerthFP: fp, Scopes: scopes, Targets: targets, Expires: exp, WharfURL: wharfURL,
		By: currentUser(r), IP: a.clientIP(r), until: time.Now().Add(10 * time.Minute)}
	berthPairing.Unlock()

	cb, _ := url.Parse(req.CB)
	q := cb.Query()
	q.Set("state", req.Code)
	q.Set("code", code)
	q.Set("wharf_url", wharfURL)
	q.Set("wharf_fp", a.selfFingerprint())
	q.Set("wharf_name", a.setting("ui.name"))
	cb.RawQuery = q.Encode()
	writeJSON(w, 200, map[string]string{"redirect": cb.String()})
}

func cleanTargets(in []berthTarget) ([]berthTarget, error) {
	out := []berthTarget{}
	for _, t := range in {
		ip := net.ParseIP(t.IP).To4()
		if ip == nil || !ip.IsPrivate() {
			return nil, fmt.Errorf("Berth 主机地址 %s 不是内网 IPv4", t.IP)
		}
		mac := ""
		if t.MAC != "" {
			hw, err := net.ParseMAC(t.MAC)
			if err != nil {
				return nil, fmt.Errorf("MAC %s 无效", t.MAC)
			}
			mac = hw.String()
		}
		if !slices.ContainsFunc(out, func(x berthTarget) bool { return x.IP == ip.String() }) {
			out = append(out, berthTarget{IP: ip.String(), MAC: mac, Name: clean(t.Name, 40)})
		}
	}
	if len(out) > 8 {
		return nil, errors.New("最多选择 8 台 Berth 主机")
	}
	return out, nil
}

// POST /api/ext/berth/v1/pair/exchange {code, token, name} — server to server, no token yet.
func (a *App) handleBerthExchange(w http.ResponseWriter, r *http.Request) {
	ip := a.clientIP(r)
	key := "berth:" + ip
	if a.limiter.blocked(key) {
		jsonErr(w, 429, "失败次数过多，请 15 分钟后再试")
		return
	}
	var req struct {
		Code  string `json:"code"`
		Token string `json:"token"`
		Name  string `json:"name"`
	}
	if readJSON(r, &req) != nil {
		jsonErr(w, 400, "请求格式错误")
		return
	}
	berthPairing.Lock()
	p := berthPairing.m[req.Code]
	delete(berthPairing.m, req.Code)
	berthPairing.Unlock()
	if p == nil || time.Now().After(p.until) {
		a.limiter.record(key)
		a.logBlocked(r, ip, accessResult{reason: "Berth 配对：一次性码无效"})
		jsonErr(w, 401, "配对码无效或已过期，请在 Berth 里重新发起配对")
		return
	}
	if !strings.HasPrefix(req.Token, "berth_wrf_") || len(req.Token) < 30 || len(req.Token) > 200 {
		jsonErr(w, 400, "Berth 需要同时交给 Wharf 一个 berth_wrf_ 开头的令牌")
		return
	}
	if a.berth() != nil {
		jsonErr(w, 409, "Wharf 已经和一个 Berth 配对")
		return
	}
	name := clean(req.Name, 32)
	if name == "" {
		name = strings.TrimPrefix(p.BerthURL, "https://")
	}
	token := berthTokenPrefix + sign.RandomHex(24)
	outEnc, err1 := a.berthSeal([]byte(req.Token))
	keyEnc, err2 := a.berthSeal(sign.DeriveKey(token))
	if err := errors.Join(err1, err2); err != nil {
		jsonErr(w, 500, err.Error())
		return
	}
	var exp any
	if p.Expires > 0 {
		exp = p.Expires
	}
	now := time.Now().Unix()
	res, err := a.db.Exec(`INSERT INTO berth_link(name, url, cert_fp, token_hash, outbound_token_enc, sign_key_enc, scopes, target_devices, expires_at, created_at, last_seen_at, wharf_url)
		VALUES(?,?,?,?,?,?,?,?,?,?,?,?)`, name, p.BerthURL, p.BerthFP, tokenHash(token), outEnc, keyEnc, mustJSON(p.Scopes), mustJSON(p.Targets), exp, now, now, p.WharfURL)
	if err != nil {
		jsonErr(w, 500, err.Error())
		return
	}
	id, _ := res.LastInsertId()
	a.limiter.reset(key)
	a.audit(actor{user: p.By, ip: p.IP}, "berth.pair", "berth", strconv.FormatInt(id, 10),
		fmt.Sprintf("与 Berth「%s」（%s）配对，授予：%s", name, p.BerthURL, scopeLabels(p.Scopes)), nil, map[string]any{"url": p.BerthURL, "cert_fp": p.BerthFP, "scopes": p.Scopes, "targets": p.Targets}, false)
	go func() { // check the way back while Berth is still finishing its side
		time.Sleep(2 * time.Second)
		if l := a.berth(); l != nil {
			_ = a.berthCall(l, "GET", "/ping", nil, nil)
		}
	}()
	writeJSON(w, 200, map[string]any{"token": token, "scopes": p.Scopes, "targets": p.Targets, "expires_at": p.Expires,
		"wharf_name": a.setting("ui.name"), "wharf_url": p.WharfURL})
}

func scopeLabels(ss []string) string {
	var out []string
	for _, s := range ss {
		out = append(out, berthScopeLabel(s))
	}
	return strings.Join(out, "、")
}

// ---- management (super admin) ----

type berthUserMap struct {
	BerthUser string `json:"berth_user"`
	UserID    int64  `json:"wharf_user_id"`
	Username  string `json:"wharf_username"`
	Name      string `json:"wharf_name"`
	Super     bool   `json:"super"`
}

func (a *App) berthUserMaps() []berthUserMap {
	out := []berthUserMap{}
	rows, err := a.db.Query(`SELECT m.berth_user, m.wharf_user_id, COALESCE(u.username,''), COALESCE(u.display_name,''), COALESCE(u.role,'') FROM berth_user_map m
		LEFT JOIN users u ON u.id=m.wharf_user_id ORDER BY m.berth_user`)
	if err != nil {
		return out
	}
	defer rows.Close()
	for rows.Next() {
		var m berthUserMap
		var role string
		if rows.Scan(&m.BerthUser, &m.UserID, &m.Username, &m.Name, &role) == nil {
			m.Super = role == RoleSuper
			out = append(out, m)
		}
	}
	return out
}

// GET /api/berth
func (a *App) handleBerth(w http.ResponseWriter, r *http.Request) {
	out := map[string]any{"scopes": berthScopes, "link": nil, "users": a.berthUserMaps(), "self_fp": a.selfFingerprint()}
	if l := a.berth(); l != nil {
		l.Status = l.state()
		out["link"] = l
		var n int
		_ = a.db.QueryRow(`SELECT COUNT(*) FROM berth_bans WHERE origin='berth'`).Scan(&n)
		out["bans"] = n
		st, err := a.loadFwState()
		if err == nil {
			c := 0
			for id := range st.fw {
				if f := st.forward(id); f != nil && f.Kind == berthKind {
					c++
				}
			}
			out["forwards"] = c
		}
		out["sni"] = a.berthSNI()
	}
	writeJSON(w, 200, out)
}

// GET /api/berth/status — what any signed-in user needs for badges and the menu entry.
func (a *App) handleBerthStatus(w http.ResponseWriter, r *http.Request) {
	l := a.berth()
	if l == nil {
		writeJSON(w, 200, map[string]any{"paired": false})
		return
	}
	ips := []string{}
	for ip := range a.berthHostIPs(l) {
		ips = append(ips, ip)
	}
	slices.Sort(ips)
	writeJSON(w, 200, map[string]any{"paired": true, "name": l.Name, "url": l.URL, "state": l.state(), "hosts": ips})
}

// PUT /api/berth {scopes, targets} — scopes may only shrink; targets may change.
func (a *App) handleBerthUpdate(w http.ResponseWriter, r *http.Request) {
	l := a.berth()
	if l == nil {
		jsonErr(w, 404, "尚未与 Berth 配对")
		return
	}
	var req struct {
		Scopes  []string      `json:"scopes"`
		Targets []berthTarget `json:"targets"`
	}
	if readJSON(r, &req) != nil {
		jsonErr(w, 400, "请求格式错误")
		return
	}
	scopes := []string{}
	for _, s := range req.Scopes {
		if !l.has(s) {
			jsonErr(w, 400, "只能收窄权限；要增加「"+berthScopeLabel(s)+"」请重新配对")
			return
		}
		if !slices.Contains(scopes, s) {
			scopes = append(scopes, s)
		}
	}
	targets, err := cleanTargets(req.Targets)
	if err != nil {
		jsonErr(w, 400, err.Error())
		return
	}
	before := map[string]any{"scopes": l.Scopes, "targets": l.Targets}
	if _, err := a.db.Exec(`UPDATE berth_link SET scopes=?, target_devices=? WHERE id=?`, mustJSON(scopes), mustJSON(targets), l.ID); err != nil {
		jsonErr(w, 500, err.Error())
		return
	}
	after := map[string]any{"scopes": scopes, "targets": targets}
	a.audit(actor{user: currentUser(r), ip: a.clientIP(r)}, "berth.update", "berth", strconv.FormatInt(l.ID, 10),
		"修改 Berth 对接：权限 "+firstNonEmpty(scopeLabels(scopes), "（无）"), before, after, false)
	if !slices.Contains(scopes, "sni") && slices.Contains(l.Scopes, "sni") {
		a.clearBerthSNI()
	}
	a.berthNotify("link.updated", map[string]any{"scopes": scopes, "targets": targets})
	writeJSON(w, 200, map[string]bool{"ok": true})
}

// POST /api/berth/rotate — new tokens both ways, exchanged over the current channel.
func (a *App) handleBerthRotate(w http.ResponseWriter, r *http.Request) {
	l := a.berth()
	if l == nil {
		jsonErr(w, 404, "尚未与 Berth 配对")
		return
	}
	token := berthTokenPrefix + sign.RandomHex(24)
	var resp struct {
		Token string `json:"token"`
	}
	if err := a.berthCall(l, "POST", "/rotate", map[string]string{"token": token}, &resp); err != nil {
		jsonErr(w, 502, "Berth 没有接受新令牌："+err.Error())
		return
	}
	if !strings.HasPrefix(resp.Token, "berth_wrf_") {
		jsonErr(w, 502, "Berth 没有返回它的新令牌")
		return
	}
	outEnc, err1 := a.berthSeal([]byte(resp.Token))
	keyEnc, err2 := a.berthSeal(sign.DeriveKey(token))
	if err := errors.Join(err1, err2); err != nil {
		jsonErr(w, 500, err.Error())
		return
	}
	_, _ = a.db.Exec(`UPDATE berth_link SET token_hash=?, sign_key_enc=?, outbound_token_enc=?, status='active', last_error='' WHERE id=?`, tokenHash(token), keyEnc, outEnc, l.ID)
	a.audit(actor{user: currentUser(r), ip: a.clientIP(r)}, "berth.rotate", "berth", strconv.FormatInt(l.ID, 10), "轮换与 Berth「"+l.Name+"」的对接令牌", nil, nil, false)
	writeJSON(w, 200, map[string]bool{"ok": true})
}

// POST /api/berth/unpair {keep}
func (a *App) handleBerthUnpair(w http.ResponseWriter, r *http.Request) {
	l := a.berth()
	if l == nil {
		jsonErr(w, 404, "尚未与 Berth 配对")
		return
	}
	var req struct {
		Keep bool `json:"keep"`
	}
	_ = readJSON(r, &req)
	ac := actor{user: currentUser(r), ip: a.clientIP(r)}
	// tell Berth first (with the token that is about to go away); unpair anyway if it is unreachable
	notified := a.berthCall(l, "POST", "/unpair", map[string]bool{"keep": req.Keep}, nil) == nil
	msg, err := a.berthUnpair(ac, l, req.Keep)
	if err != nil {
		jsonErr(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true, "message": msg, "notified": notified})
}

// POST /api/ext/berth/v1/unpair {keep} — Berth ends the pairing from its side.
func (a *App) handleBerthExtUnpair(w http.ResponseWriter, r *http.Request) {
	br := berthFrom(r)
	var req struct {
		Keep bool `json:"keep"`
	}
	_ = json.Unmarshal(br.body, &req)
	msg, err := a.berthUnpair(a.berthActor(r), br.link, req.Keep)
	if err != nil {
		jsonErr(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true, "message": msg})
}

// berthUnpair removes the link. Berth's mappings either become ordinary forwards owned by
// the super admin (keep) or are deleted; its 443 names and bans go away.
func (a *App) berthUnpair(ac actor, l *berthLink, keep bool) (string, error) {
	kept, deleted := 0, 0
	if st, err := a.loadFwState(); err == nil {
		var superID int64
		_ = a.db.QueryRow(`SELECT id FROM users WHERE role='super' ORDER BY id LIMIT 1`).Scan(&superID)
		for id := range st.fw {
			f := st.forward(id)
			if f == nil || f.Kind != berthKind {
				continue
			}
			before := st.snap(id)
			if keep {
				meta := optionsOf(before.Meta)
				for _, k := range []string{"kind", "berth_ref", "berth_host", "berth_link"} {
					delete(meta, k)
				}
				meta["uid"] = strconv.FormatInt(superID, 10)
				if err := a.applyForward(id, before, optionsOf(before.Redirect), sectionOrNil(before.IPSet), meta, optStr(before.Redirect, "ipset"), a.currentSetEntries(id, before)); err == nil {
					_, _ = a.db.Exec(`UPDATE owned SET user_id=?, kind='forward' WHERE config='firewall' AND section=?`, superID, id)
					kept++
				}
			} else if err := a.applyForward(id, before, nil, nil, nil, "", nil); err == nil {
				a.audit(ac, "forward.delete", "forward", id, "解除 Berth 配对：删除映射 "+describe(f), before, nil, true)
				deleted++
			}
		}
	}
	a.clearBerthSNI()
	_, _ = a.db.Exec(`DELETE FROM berth_bans WHERE origin='berth'`)
	_, _ = a.db.Exec(`UPDATE berth_bans SET sync=0, remote_id=''`)
	_ = a.syncBerthBans()
	_, _ = a.db.Exec(`DELETE FROM ddns_owner`)
	_, _ = a.db.Exec(`DELETE FROM berth_user_map`)
	_ = a.setSetting("alerts.primary", "wharf")
	if _, err := a.db.Exec(`DELETE FROM berth_link WHERE id=?`, l.ID); err != nil {
		return "", err
	}
	msg := fmt.Sprintf("已解除与 Berth「%s」的配对", l.Name)
	if keep && kept > 0 {
		msg += fmt.Sprintf("；%d 条映射转为普通端口转发", kept)
	}
	if deleted > 0 {
		msg += fmt.Sprintf("；删除了 %d 条映射", deleted)
	}
	a.audit(ac, "berth.unpair", "berth", strconv.FormatInt(l.ID, 10), msg, map[string]any{"url": l.URL, "scopes": l.Scopes}, nil, false)
	return msg, nil
}

func sectionOrNil(s Section) map[string]any {
	if s == nil {
		return nil
	}
	return optionsOf(s)
}

// currentSetEntries recomputes a forward's source set from its metadata (unchanged spec).
func (a *App) currentSetEntries(id string, s fwdSnap) []string {
	if s.IPSet == nil {
		return nil
	}
	e, _, _ := a.setEntries(id, optStr(s.Meta, "mode"), optList(s.Meta, "region"), optList(s.Meta, "allow"), optList(s.Meta, "deny"))
	return e
}

// PUT /api/berth/users {berth_user, wharf_user_id, password} — 0 removes the mapping.
// Mapping onto a super admin needs the current super admin's password again.
func (a *App) handleBerthUserMap(w http.ResponseWriter, r *http.Request) {
	var req struct {
		BerthUser string `json:"berth_user"`
		UserID    int64  `json:"wharf_user_id"`
		Password  string `json:"password"`
	}
	if readJSON(r, &req) != nil {
		jsonErr(w, 400, "请求格式错误")
		return
	}
	bu := clean(req.BerthUser, 64)
	if bu == "" || strings.ContainsAny(bu, " /") {
		jsonErr(w, 400, "Berth 用户名无效")
		return
	}
	me := currentUser(r)
	ac := actor{user: me, ip: a.clientIP(r)}
	if req.UserID == 0 {
		_, _ = a.db.Exec(`DELETE FROM berth_user_map WHERE berth_user=?`, bu)
		a.audit(ac, "berth.user_map", "berth", bu, "删除 Berth 用户 "+bu+" 的对应", nil, nil, false)
		writeJSON(w, 200, a.berthUserMaps())
		return
	}
	u, err := a.getUser(req.UserID)
	if err != nil {
		jsonErr(w, 404, "Wharf 用户不存在")
		return
	}
	if u.Role == RoleSuper {
		if _, err := a.checkPassword(me.Username, req.Password); err != nil {
			writeJSON(w, 403, map[string]any{"error": "对应到超级管理员需要再输入一次你的密码", "confirm": true})
			return
		}
	}
	if _, err := a.db.Exec(`INSERT INTO berth_user_map(berth_user, wharf_user_id) VALUES(?,?) ON CONFLICT(berth_user) DO UPDATE SET wharf_user_id=excluded.wharf_user_id`, bu, u.ID); err != nil {
		jsonErr(w, 500, err.Error())
		return
	}
	a.audit(ac, "berth.user_map", "berth", bu, fmt.Sprintf("Berth 用户 %s 对应到 Wharf 用户 %s", bu, u.DisplayName), nil, map[string]any{"berth_user": bu, "wharf_user_id": u.ID}, false)
	writeJSON(w, 200, a.berthUserMaps())
}

// ---- single sign-on ----

type ssoTicket struct {
	userID    int64
	berthUser string
	returnTo  string
	audience  string
	until     time.Time
}

var berthTickets = struct {
	sync.Mutex
	m map[string]*ssoTicket
}{m: map[string]*ssoTicket{}}

// safeReturn keeps only paths inside this site.
func safeReturn(p string) string {
	if !strings.HasPrefix(p, "/") || strings.HasPrefix(p, "//") || strings.ContainsAny(p, "\\\r\n") || strings.HasPrefix(p, "/api/") {
		return "/"
	}
	return p
}

// POST /api/ext/berth/v1/sso/ticket {berth_user, return_to}
func (a *App) handleBerthSSOTicket(w http.ResponseWriter, r *http.Request) {
	br := berthFrom(r)
	var req struct {
		BerthUser string `json:"berth_user"`
		ReturnTo  string `json:"return_to"`
	}
	if json.Unmarshal(br.body, &req) != nil {
		jsonErr(w, 400, "请求格式错误")
		return
	}
	var uid int64
	if err := a.db.QueryRow(`SELECT wharf_user_id FROM berth_user_map WHERE berth_user=?`, req.BerthUser).Scan(&uid); err != nil {
		jsonErr(w, 403, "这个 Berth 用户在 Wharf 里没有设置对应的账号")
		return
	}
	u, err := a.getUser(uid)
	if err != nil || u.Disabled {
		jsonErr(w, 403, "对应的 Wharf 账号不存在或已停用")
		return
	}
	t := sign.RandomHex(24)
	aud := br.link.WharfURL
	berthTickets.Lock()
	for k, v := range berthTickets.m {
		if time.Now().After(v.until) {
			delete(berthTickets.m, k)
		}
	}
	berthTickets.m[t] = &ssoTicket{userID: u.ID, berthUser: req.BerthUser, returnTo: safeReturn(req.ReturnTo), audience: aud, until: time.Now().Add(60 * time.Second)}
	berthTickets.Unlock()
	writeJSON(w, 200, map[string]string{"url": aud + "/sso/berth?t=" + t})
}

// GET /sso/berth?t= — the browser arrives from Berth with a one-time ticket.
func (a *App) handleBerthSSO(w http.ResponseWriter, r *http.Request) {
	t := r.URL.Query().Get("t")
	berthTickets.Lock()
	tk := berthTickets.m[t]
	delete(berthTickets.m, t)
	berthTickets.Unlock()
	page := func(code int, title, msg, to string) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		w.WriteHeader(code)
		refresh := ""
		if to != "" {
			// a navigation started by this page is same-site, so the new (SameSite=Strict) cookie goes along
			refresh = `<meta http-equiv="refresh" content="0;url=` + htmlEscape(to) + `">`
		}
		fmt.Fprintf(w, `<!doctype html><html lang="zh-CN"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width">%s<title>%s</title></head>
<body style="font-family:system-ui;padding:3rem;color:#333"><h3>%s</h3><p>%s</p><p><a href="/">打开 Wharf</a></p></body></html>`, refresh, htmlEscape(title), htmlEscape(title), htmlEscape(msg))
	}
	if tk == nil || time.Now().After(tk.until) {
		ip := a.clientIP(r)
		a.limiter.record("berth:" + ip)
		a.logBlocked(r, ip, accessResult{reason: "Berth 跳转：票据无效"})
		page(401, "跳转链接已失效", "免登录链接只能用一次，60 秒内有效。请回到 Berth 再点一次。", "")
		return
	}
	if au, err := url.Parse(tk.audience); err != nil || !strings.EqualFold(au.Host, r.Host) {
		page(403, "地址不符", "这个链接是给 "+tk.audience+" 的，请从 Berth 重新打开。", "")
		return
	}
	u, err := a.getUser(tk.userID)
	if err != nil || u.Disabled {
		page(403, "账号不可用", "对应的 Wharf 账号不存在或已停用。", "")
		return
	}
	if _, err := a.createSession(w, r, u); err != nil {
		page(500, "登录失败", err.Error(), "")
		return
	}
	ip := a.clientIP(r)
	g := a.geo.Lookup(ip)
	_, _ = a.db.Exec(`INSERT INTO visitors(ts, user_id, username, ip, asn, as_org, country, region, city, ip_tz, tz_match, user_agent, path, reason)
		VALUES(?,?,?,?,?,?,?,?,?,?,'unknown',?,?,?)`, time.Now().Unix(), u.ID, u.Username, ip, g.ASN, g.ASOrg, g.Country, g.Region, g.City, g.TZ,
		truncate(r.UserAgent(), 300), "/sso/berth", "经 Berth 跳转（Berth 用户 "+tk.berthUser+"）")
	a.audit(actor{user: u, ip: ip}, "session.login", "session", strconv.FormatInt(u.ID, 10), "经 Berth 跳转登录（Berth 用户 "+tk.berthUser+"）", nil, nil, false)
	page(200, "正在打开 Wharf…", "", tk.returnTo)
}

func htmlEscape(s string) string {
	return strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;", `"`, "&quot;", "'", "&#39;").Replace(s)
}

// POST /api/berth/sso {return_to, ref} — open Berth as the signed-in user (Berth maps
// Wharf users to its own accounts and decides).
func (a *App) handleBerthSSOOut(w http.ResponseWriter, r *http.Request) {
	l := a.berth()
	if l == nil || l.state() != "active" {
		jsonErr(w, 404, "Berth 对接不可用")
		return
	}
	var req struct {
		ReturnTo string `json:"return_to"`
		Ref      string `json:"ref"`
	}
	_ = readJSON(r, &req)
	u := currentUser(r)
	var out struct {
		URL string `json:"url"`
	}
	if err := a.berthCall(l, "POST", "/sso/ticket", map[string]string{"wharf_user": u.Username, "return_to": safeReturn(firstNonEmpty(req.ReturnTo, "/")), "ref": clean(req.Ref, 200)}, &out); err != nil {
		jsonErr(w, 502, err.Error())
		return
	}
	if !strings.HasPrefix(out.URL, strings.TrimRight(l.URL, "/")+"/") {
		jsonErr(w, 502, "Berth 返回的跳转地址不在它自己的地址上")
		return
	}
	writeJSON(w, 200, out)
}

// GET /api/berth/host/{ip} — what runs on a Berth host (containers, VMs, sites), from Berth.
func (a *App) handleBerthHost(w http.ResponseWriter, r *http.Request) {
	l := a.berth()
	if l == nil || l.state() != "active" {
		jsonErr(w, 404, "Berth 对接不可用")
		return
	}
	ip := r.PathValue("ip")
	if !a.berthHostIPs(l)[ip] {
		jsonErr(w, 404, "这台设备不是 Berth 主机")
		return
	}
	var out json.RawMessage
	if err := a.berthCall(l, "GET", "/hosts/"+url.PathEscape(ip), nil, &out); err != nil {
		jsonErr(w, 502, err.Error())
		return
	}
	writeJSON(w, 200, out)
}

// ---- housekeeping ----

func (a *App) berthHousekeeping() {
	_, _ = a.db.Exec(`DELETE FROM berth_nonce WHERE seen_at < ?`, time.Now().Unix()-300)
	if n, _ := a.expireBerthBans(); n > 0 {
		_ = a.syncBerthBans()
	}
}

// GET /api/ext/berth/v1/ping — Berth checks the channel and reads what it was granted.
func (a *App) handleBerthPing(w http.ResponseWriter, r *http.Request) {
	l := berthFrom(r).link
	writeJSON(w, 200, map[string]any{"ok": true, "name": a.setting("ui.name"), "version": version.Version, "scopes": l.Scopes, "targets": l.Targets,
		"expires_at": l.ExpiresAt, "time": time.Now().Unix()})
}

// POST /api/ext/berth/v1/events {type, …} — Berth tells Wharf about changes on its side.
func (a *App) handleBerthEvent(w http.ResponseWriter, r *http.Request) {
	br := berthFrom(r)
	var ev map[string]any
	if json.Unmarshal(br.body, &ev) != nil {
		jsonErr(w, 400, "请求格式错误")
		return
	}
	typ, _ := ev["type"].(string)
	switch typ {
	case "ban.revoked": // Berth dropped a ban Wharf had sent: it is no longer synced
		id := fmt.Sprint(ev["id"])
		_, _ = a.db.Exec(`UPDATE berth_bans SET sync=0, remote_id='' WHERE origin='wharf' AND (remote_id=? OR CAST(id AS TEXT)=?)`, id, id)
	case "ddns.owner":
		d, _ := ev["domain"].(string)
		o, _ := ev["owner"].(string)
		if hostnameOK(d) && (o == "wharf" || o == "berth") {
			_, _ = a.db.Exec(`INSERT INTO ddns_owner(domain, owner) VALUES(?,?) ON CONFLICT(domain) DO UPDATE SET owner=excluded.owner`, strings.ToLower(d), o)
		}
	case "link.renamed":
		if n := clean(fmt.Sprint(ev["name"]), 32); n != "" && n != "<nil>" {
			_, _ = a.db.Exec(`UPDATE berth_link SET name=? WHERE id=?`, n, br.link.ID)
		}
	}
	writeJSON(w, 200, map[string]bool{"ok": true})
}

// GET /api/berth/ddns — names both panels keep a DDNS record for, so the owner can pick one.
func (a *App) handleBerthDDNSCompare(w http.ResponseWriter, r *http.Request) {
	l := a.berth()
	if l == nil || l.state() != "active" || !l.has("ddns") {
		writeJSON(w, 200, map[string]any{"available": false, "both": []string{}})
		return
	}
	var theirs struct {
		Items []struct {
			Domain string `json:"domain"`
		} `json:"items"`
	}
	if err := a.berthCall(l, "GET", "/ddns", nil, &theirs); err != nil {
		writeJSON(w, 200, map[string]any{"available": false, "error": err.Error(), "both": []string{}})
		return
	}
	mine, _ := a.ddnsList()
	owners := a.ddnsOwners()
	both := []string{}
	for _, t := range theirs.Items {
		d := strings.ToLower(t.Domain)
		if owners[d] != "" || slices.Contains(both, d) {
			continue
		}
		if slices.ContainsFunc(mine, func(x *DDNS) bool { return x.Domain == d }) {
			both = append(both, d)
		}
	}
	writeJSON(w, 200, map[string]any{"available": true, "both": both, "owners": owners})
}

// POST /api/berth/ddns {domain, owner}
func (a *App) handleBerthDDNSOwner(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Domain string `json:"domain"`
		Owner  string `json:"owner"`
	}
	if readJSON(r, &req) != nil || !hostnameOK(req.Domain) || (req.Owner != "wharf" && req.Owner != "berth") {
		jsonErr(w, 400, "请求格式错误")
		return
	}
	d := strings.ToLower(req.Domain)
	before := a.ddnsOwners()[d]
	if _, err := a.db.Exec(`INSERT INTO ddns_owner(domain, owner) VALUES(?,?) ON CONFLICT(domain) DO UPDATE SET owner=excluded.owner`, d, req.Owner); err != nil {
		jsonErr(w, 500, err.Error())
		return
	}
	a.audit(actor{user: currentUser(r), ip: a.clientIP(r)}, "berth.ddns", "ddns_owner", d,
		fmt.Sprintf("DDNS %s 改由 %s 维护", d, map[string]string{"wharf": "Wharf", "berth": "Berth"}[req.Owner]), before, req.Owner, false)
	a.berthNotify("ddns.owner", map[string]any{"domain": d, "owner": req.Owner})
	writeJSON(w, 200, map[string]any{"ok": true, "owners": a.ddnsOwners()})
}
