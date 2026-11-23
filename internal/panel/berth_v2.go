package panel

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"net/http/httptrace"
	"net/netip"
	"regexp"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/wangsirco/wharf/internal/sign"
)

// Berth pairing v2 (docs/BERTH.md §8–§10): how the two panels are connected right now,
// pairing by request from Berth on the LAN ("像连蓝牙"), and .lan names for Berth.

// ---- connection status ----

type berthConn struct {
	Kind      string  `json:"kind"` // lan | tailscale | public
	Via       string  `json:"via"`  // public only: direct | cloudflare | cloudfront | fastly | proxy
	URL       string  `json:"url"`
	IP        string  `json:"ip"`
	Country   string  `json:"country,omitempty"`
	LatencyMS float64 `json:"latency_ms"`
	JitterMS  float64 `json:"jitter_ms"`
	At        int64   `json:"at"`
	Error     string  `json:"error,omitempty"`
}

var berthConnCache struct {
	sync.Mutex
	linkID int64
	v      *berthConn
}

var (
	tailscale4 = netip.MustParsePrefix("100.64.0.0/10")
	tailscale6 = netip.MustParsePrefix("fd7a:115c:a1e0::/48")
)

// connKind: tailscale before LAN, since Tailscale's IPv6 range sits inside fc00::/7.
func connKind(ip netip.Addr) string {
	ip = ip.Unmap()
	switch {
	case tailscale4.Contains(ip) || tailscale6.Contains(ip):
		return "tailscale"
	case lanAddr(ip):
		return "lan"
	}
	return "public"
}

// viaOf: who stands between the panels on a public path, from the response headers.
func viaOf(pinned bool, h http.Header) string {
	switch {
	case pinned:
		return "direct"
	case h.Get("Cf-Ray") != "" || strings.EqualFold(h.Get("Server"), "cloudflare"):
		return "cloudflare"
	case h.Get("X-Amz-Cf-Id") != "":
		return "cloudfront"
	case h.Get("X-Served-By") != "" || h.Get("X-Fastly-Request-Id") != "":
		return "fastly"
	}
	return "proxy"
}

// measureBerth opens one connection (the first signed ping), then times three more pings
// on it: latency is the smallest, jitter the mean step between neighbours. The peer
// address is the one actually connected to, not a DNS answer.
func (a *App) measureBerth(l *berthLink) *berthConn {
	out := &berthConn{At: time.Now().Unix()}
	if l.outToken == "" {
		out.Error = "Berth 的令牌无法解密，请重新配对"
		return out
	}
	var pinned atomic.Bool
	tr := &http.Transport{TLSClientConfig: pinOrPublic(l.CertFP, &pinned), Proxy: nil, MaxIdleConnsPerHost: 1, ResponseHeaderTimeout: 8 * time.Second}
	defer tr.CloseIdleConnections()
	c := &http.Client{Timeout: 10 * time.Second, Transport: tr, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	if berthClientHook != nil {
		c = berthClientHook(l.CertFP)
	}
	var remote string
	ping := func(base string) (time.Duration, http.Header, error) {
		ctx := httptrace.WithClientTrace(context.Background(), &httptrace.ClientTrace{GotConn: func(ci httptrace.GotConnInfo) {
			if ci.Conn != nil {
				remote = ci.Conn.RemoteAddr().String()
			}
		}})
		req, err := berthRequest(ctx, l, base, "GET", "/ping", nil)
		if err != nil {
			return 0, nil, err
		}
		t0 := time.Now()
		resp, err := c.Do(req)
		if err != nil {
			return 0, nil, err
		}
		d := time.Since(t0)
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
		resp.Body.Close()
		if resp.StatusCode >= 300 {
			return d, resp.Header, fmt.Errorf("Berth 返回 %d", resp.StatusCode)
		}
		return d, resp.Header, nil
	}
	var hdr http.Header
	var err error
	var errs []string
	for _, base := range l.candidates() {
		if _, hdr, err = ping(base); err == nil {
			out.URL = base
			break
		}
		errs = append(errs, stepErr(base, err))
	}
	if out.URL == "" {
		out.Error = strings.Join(errs, "；")
		return out
	}
	var samples []float64
	for range 3 {
		d, _, err := ping(out.URL)
		if err != nil {
			break
		}
		samples = append(samples, float64(d.Microseconds())/1000)
	}
	if len(samples) > 0 {
		out.LatencyMS = math.Round(slices.Min(samples)*10) / 10
		var sum float64
		for i := 1; i < len(samples); i++ {
			sum += math.Abs(samples[i] - samples[i-1])
		}
		if len(samples) > 1 {
			out.JitterMS = math.Round(sum/float64(len(samples)-1)*10) / 10
		}
	}
	if host, _, err := net.SplitHostPort(remote); err == nil {
		out.IP = host
		if ip, err := netip.ParseAddr(host); err == nil {
			out.Kind = connKind(ip)
			if out.Kind == "public" {
				out.Via = viaOf(pinned.Load(), hdr)
				if a.geo != nil {
					out.Country = a.geo.LookupFast(host).Country // the local database only
				}
			}
		}
	}
	return out
}

// GET /api/berth/conn — measured at most every 25 s; the page asks every 30 s.
func (a *App) handleBerthConn(w http.ResponseWriter, r *http.Request) {
	l := a.berth()
	if l == nil || l.state() != "active" {
		writeJSON(w, 200, map[string]any{"conn": nil})
		return
	}
	berthConnCache.Lock()
	v := berthConnCache.v
	fresh := v != nil && berthConnCache.linkID == l.ID && time.Since(time.Unix(v.At, 0)) < 25*time.Second
	berthConnCache.Unlock()
	if !fresh || r.URL.Query().Get("now") == "1" {
		a.refreshPeer(l, false)
		v = a.measureBerth(a.berth())
		berthConnCache.Lock()
		berthConnCache.linkID, berthConnCache.v = l.ID, v
		berthConnCache.Unlock()
	}
	l = a.berth() // the measurement may have learnt Berth's names
	writeJSON(w, 200, map[string]any{"conn": v, "urls": l.candidates(), "key_auth": l.KeyAuth, "mode": l.Mode, "peer_lan": l.PeerLAN, "peer_public": l.PeerPub,
		"peer_protocol": l.PeerProto, "wharf": a.wharfNames()})
}

// ---- LAN discovery: Berth asks, the super admin allows ----

type berthAsk struct {
	ID      string   `json:"id"`
	Name    string   `json:"name"`
	URLs    []string `json:"urls"`
	BerthFP string   `json:"berth_fp"`
	IP      string   `json:"ip"`
	SAS     string   `json:"sas"`
	Created int64    `json:"created_at"`
	Expires int64    `json:"expires_at"`
	State   string   `json:"state"` // waiting | refused | allowed

	code      string // Berth's one-time code
	wharfURL  string // the address Berth reached Wharf at
	wharfCode string // given back once allowed, for pair/exchange
}

var berthDisc = struct {
	sync.Mutex
	until time.Time
	by    string
	asks  map[string]*berthAsk // by id
	hits  map[string][]time.Time
}{asks: map[string]*berthAsk{}, hits: map[string][]time.Time{}}

const (
	discWindow = 10 * time.Minute
	askLife    = 10 * time.Minute
)

// pairSAS: the six digits both panels show, so the admin can tell it is the same request.
// sha256("berth-wharf-sas" || code || berth_fp || wharf_fp), first 8 bytes as two
// big-endian uint32s, each mod 1000.
func pairSAS(code, berthFP, wharfFP string) string {
	h := sha256.Sum256([]byte("berth-wharf-sas" + code + berthFP + wharfFP))
	return fmt.Sprintf("%03d %03d", binary.BigEndian.Uint32(h[0:4])%1000, binary.BigEndian.Uint32(h[4:8])%1000)
}

func discPrune(now time.Time) {
	for k, q := range berthDisc.asks {
		if now.Unix() > q.Expires {
			delete(berthDisc.asks, k)
		}
	}
	for ip, ts := range berthDisc.hits {
		ts = slices.DeleteFunc(ts, func(t time.Time) bool { return now.Sub(t) > 10*time.Minute })
		if len(ts) == 0 {
			delete(berthDisc.hits, ip)
		} else {
			berthDisc.hits[ip] = ts
		}
	}
}

// discGate: only from the LAN, only while the window is open (asks may still be checked
// until they expire), at most 5 calls per source per 10 minutes. Anything else is a 404.
func (a *App) discGate(w http.ResponseWriter, r *http.Request, needWindow bool) (string, bool) {
	ip := a.clientIP(r)
	addr, err := netip.ParseAddr(ip)
	now := time.Now()
	berthDisc.Lock()
	defer berthDisc.Unlock()
	discPrune(now)
	open := now.Before(berthDisc.until)
	if err != nil || fromTunnel(r) || !lanAddr(addr) || (needWindow && !open) {
		http.NotFound(w, r)
		return "", false
	}
	if needWindow {
		if len(berthDisc.hits[ip]) >= 5 {
			jsonErr(w, 429, "申请太频繁，请 10 分钟后再试")
			return "", false
		}
		berthDisc.hits[ip] = append(berthDisc.hits[ip], now)
	}
	return ip, true
}

// POST /api/ext/berth/v1/pair/request {code, berth_name, berth_urls, berth_fp, wharf_fp}
func (a *App) handleBerthPairRequest(w http.ResponseWriter, r *http.Request) {
	ip, ok := a.discGate(w, r, true)
	if !ok {
		return
	}
	var req struct {
		Code      string   `json:"code"`
		BerthName string   `json:"berth_name"`
		BerthURLs []string `json:"berth_urls"`
		BerthFP   string   `json:"berth_fp"`
		WharfFP   string   `json:"wharf_fp"`
		Mode      string   `json:"mode"` // v3; discovery means the same LAN
	}
	if readJSON(r, &req) != nil {
		jsonErr(w, 400, "请求格式错误")
		return
	}
	if len(req.Code) < 20 || len(req.Code) > 128 {
		jsonErr(w, 400, "一次性码至少 20 位")
		return
	}
	fp, self := normFP(req.BerthFP), a.selfFingerprint()
	if !validFP(fp) {
		jsonErr(w, 400, "Berth 证书指纹格式不对")
		return
	}
	if self == "" || normFP(req.WharfFP) != self {
		a.logBlocked(r, ip, accessResult{reason: "Berth 申请绑定：看到的 Wharf 证书不对"})
		jsonErr(w, 400, "Berth 看到的 Wharf 证书指纹不对：中间可能有人换了证书")
		return
	}
	urls, err := cleanBerthURLs("", req.BerthURLs)
	if err != nil || len(urls) == 0 {
		jsonErr(w, 400, "berth_urls 至少要有一个 https:// 地址")
		return
	}
	if a.berth() != nil {
		jsonErr(w, 409, "Wharf 已经和一个 Berth 配对")
		return
	}
	now := time.Now()
	ask := &berthAsk{ID: sign.RandomHex(8), Name: firstNonEmpty(clean(req.BerthName, 32), "Berth"), URLs: urls, BerthFP: fp, IP: ip,
		SAS: pairSAS(req.Code, fp, self), Created: now.Unix(), Expires: now.Add(askLife).Unix(), State: "waiting",
		code: req.Code, wharfURL: "https://" + r.Host}
	berthDisc.Lock()
	n := 0
	for _, q := range berthDisc.asks {
		if q.code == req.Code {
			berthDisc.Unlock()
			jsonErr(w, 409, "这个一次性码已经用过")
			return
		}
		if q.State == "waiting" {
			n++
		}
	}
	if n >= 5 {
		berthDisc.Unlock()
		jsonErr(w, 429, "待处理的申请太多")
		return
	}
	berthDisc.asks[ask.ID] = ask
	berthDisc.Unlock()
	writeJSON(w, 200, map[string]any{"id": ask.ID, "sas": ask.SAS, "expires_at": ask.Expires})
}

// POST /api/ext/berth/v1/pair/request/status {code}
func (a *App) handleBerthPairRequestStatus(w http.ResponseWriter, r *http.Request) {
	if _, ok := a.discGate(w, r, false); !ok {
		return
	}
	var req struct {
		Code string `json:"code"`
	}
	if readJSON(r, &req) != nil || req.Code == "" {
		jsonErr(w, 400, "请求格式错误")
		return
	}
	berthDisc.Lock()
	defer berthDisc.Unlock()
	for _, q := range berthDisc.asks {
		if q.code != req.Code {
			continue
		}
		if q.State == "allowed" {
			writeJSON(w, 200, map[string]string{"state": "allowed", "code": q.wharfCode, "wharf_url": q.wharfURL})
			return
		}
		writeJSON(w, 200, map[string]string{"state": q.State})
		return
	}
	http.NotFound(w, r)
}

func discState() map[string]any {
	now := time.Now()
	discPrune(now)
	asks := []*berthAsk{}
	for _, q := range berthDisc.asks {
		if q.State == "waiting" {
			asks = append(asks, q)
		}
	}
	slices.SortFunc(asks, func(x, y *berthAsk) int { return int(x.Created - y.Created) })
	var until int64
	if now.Before(berthDisc.until) {
		until = berthDisc.until.Unix()
	}
	return map[string]any{"open_until": until, "requests": asks}
}

// GET /api/berth/discover
func (a *App) handleBerthDiscover(w http.ResponseWriter, r *http.Request) {
	berthDisc.Lock()
	out := discState()
	berthDisc.Unlock()
	out["self_fp"] = a.selfFingerprint()
	writeJSON(w, 200, out)
}

// POST /api/berth/discover {open}
func (a *App) handleBerthDiscoverSet(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Open bool `json:"open"`
	}
	if readJSON(r, &req) != nil {
		jsonErr(w, 400, "请求格式错误")
		return
	}
	if req.Open && a.berth() != nil {
		jsonErr(w, 409, "已经和一个 Berth 配对")
		return
	}
	u := currentUser(r)
	berthDisc.Lock()
	if req.Open {
		berthDisc.until, berthDisc.by = time.Now().Add(discWindow), u.Username
	} else {
		berthDisc.until = time.Time{}
		for _, q := range berthDisc.asks {
			if q.State == "waiting" {
				q.State = "refused"
			}
		}
	}
	out := discState()
	berthDisc.Unlock()
	if req.Open {
		a.audit(actor{user: u, ip: a.clientIP(r)}, "berth.discover", "berth", "", "允许局域网里的 Berth 申请绑定（10 分钟）", nil, nil, false)
	}
	writeJSON(w, 200, out)
}

func takeAsk(id string) *berthAsk {
	berthDisc.Lock()
	defer berthDisc.Unlock()
	discPrune(time.Now())
	if q := berthDisc.asks[id]; q != nil && q.State == "waiting" {
		return q
	}
	return nil
}

// GET /api/berth/discover/{id} — what to show in the allow dialog: scopes and Berth hosts.
func (a *App) handleBerthAskPreview(w http.ResponseWriter, r *http.Request) {
	q := takeAsk(r.PathValue("id"))
	if q == nil {
		jsonErr(w, 404, "申请已过期或已处理")
		return
	}
	cands, _ := a.berthCandidates(r.Context(), q.URLs, q.IP)
	writeJSON(w, 200, map[string]any{"request": q, "scopes": berthScopes, "devices": cands})
}

// POST /api/berth/discover/{id}/allow {scopes, expires_days, targets} — needs the admin to
// prove themselves again (password or passkey), whatever their sign-in mode.
func (a *App) handleBerthAskAllow(w http.ResponseWriter, r *http.Request) {
	u := currentUser(r)
	if !a.reauthedAlways(w, r) {
		return
	}
	var g berthGrant
	if readJSON(r, &g) != nil {
		jsonErr(w, 400, "请求格式错误")
		return
	}
	scopes, targets, exp, err := g.check()
	if err != nil {
		jsonErr(w, 400, err.Error())
		return
	}
	if a.berth() != nil {
		jsonErr(w, 409, "已经和一个 Berth 配对")
		return
	}
	berthDisc.Lock()
	discPrune(time.Now())
	q := berthDisc.asks[r.PathValue("id")]
	if q == nil || q.State != "waiting" {
		berthDisc.Unlock()
		jsonErr(w, 404, "申请已过期或已处理")
		return
	}
	q.wharfCode = berthPend(&berthPending{BerthURL: q.URLs[0], URLs: q.URLs, Mode: "lan", BerthFP: q.BerthFP, Scopes: scopes, Targets: targets, Expires: exp,
		WharfURL: q.wharfURL, By: u, IP: a.clientIP(r)})
	q.State = "allowed"
	berthDisc.until = time.Time{} // one Berth: the window closes
	for _, o := range berthDisc.asks {
		if o != q && o.State == "waiting" {
			o.State = "refused"
		}
	}
	berthDisc.Unlock()
	a.audit(actor{user: u, ip: a.clientIP(r)}, "berth.allow", "berth", q.ID,
		fmt.Sprintf("允许 Berth「%s」（%s）绑定，授予：%s", q.Name, q.IP, scopeLabels(scopes)), nil, map[string]any{"urls": q.URLs, "cert_fp": q.BerthFP, "sas": q.SAS}, false)
	writeJSON(w, 200, map[string]bool{"ok": true})
}

// POST /api/berth/discover/{id}/refuse
func (a *App) handleBerthAskRefuse(w http.ResponseWriter, r *http.Request) {
	berthDisc.Lock()
	q := berthDisc.asks[r.PathValue("id")]
	if q != nil && q.State == "waiting" {
		q.State = "refused"
	}
	berthDisc.Unlock()
	if q != nil {
		a.audit(actor{user: currentUser(r), ip: a.clientIP(r)}, "berth.refuse", "berth", q.ID, fmt.Sprintf("拒绝 Berth「%s」（%s）的绑定申请", q.Name, q.IP), nil, nil, false)
	}
	writeJSON(w, 200, map[string]bool{"ok": true})
}

// reauthedAlways: like reauthed, but password sign-ins prove themselves too.
func (a *App) reauthedAlways(w http.ResponseWriter, r *http.Request) bool {
	if c, err := r.Cookie(sessionCookie); err == nil {
		reauthDone.Lock()
		t, ok := reauthDone.m[tokenHash(c.Value)]
		reauthDone.Unlock()
		if ok && time.Now().Before(t) {
			return true
		}
	}
	jsonErr(w, 403, "请先验证身份")
	return false
}

// ---- .lan names for Berth (scope dns) ----

const berthDNSKind = "berth_dns"

var dnsLabelRe = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)

type berthName struct {
	Section string `json:"-"`
	Name    string `json:"name"`
	IP      string `json:"ip"`
}

// localSuffixes: .lan, plus the domain dnsmasq is configured with.
func localSuffixes(dh map[string]Section) []string {
	out := []string{"lan"}
	for _, s := range dh {
		if s[".type"] == "dnsmasq" {
			if d := strings.Trim(strings.ToLower(sectionStr(s, "domain")), "."); d != "" && !slices.Contains(out, d) {
				out = append(out, d)
			}
			break
		}
	}
	return out
}

func (a *App) berthNames(dh map[string]Section) []berthName {
	out := []berthName{}
	rows, err := a.db.Query(`SELECT section FROM owned WHERE config='dhcp' AND kind=?`, berthDNSKind)
	if err != nil {
		return out
	}
	defer rows.Close()
	for rows.Next() {
		var sec string
		if rows.Scan(&sec) == nil {
			if s := dh[sec]; s != nil && s[".type"] == "domain" {
				out = append(out, berthName{sec, optStr(s, "name"), optStr(s, "ip")})
			}
		}
	}
	slices.SortFunc(out, func(x, y berthName) int { return strings.Compare(x.Name, y.Name) })
	return out
}

// GET /api/ext/berth/v1/dns/names
func (a *App) handleBerthDNSNames(w http.ResponseWriter, r *http.Request) {
	dh, err := a.agent.UciConfig("dhcp")
	if err != nil {
		jsonErr(w, 502, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"items": a.berthNames(dh), "suffixes": localSuffixes(dh), "max": 5})
}

func checkLocalName(name string, suffixes []string) error {
	if len(name) > 253 {
		return errors.New("名字太长")
	}
	for _, suf := range suffixes {
		head, ok := strings.CutSuffix(name, "."+suf)
		if !ok || head == "" {
			continue
		}
		for _, lab := range strings.Split(head, ".") {
			if !dnsLabelRe.MatchString(lab) {
				return errors.New("名字只能用字母、数字和连字符")
			}
		}
		return nil
	}
	return fmt.Errorf("只能登记 .%s 结尾的名字", strings.Join(suffixes, " 或 ."))
}

// PUT /api/ext/berth/v1/dns/names/{name} {ip}
func (a *App) handleBerthDNSPut(w http.ResponseWriter, r *http.Request) {
	br := berthFrom(r)
	name := strings.ToLower(strings.TrimSuffix(r.PathValue("name"), "."))
	var req struct {
		IP string `json:"ip"`
	}
	if json.Unmarshal(br.body, &req) != nil {
		jsonErr(w, 400, "请求格式错误")
		return
	}
	dh, err := a.agent.UciConfig("dhcp")
	if err != nil {
		jsonErr(w, 502, err.Error())
		return
	}
	if err := checkLocalName(name, localSuffixes(dh)); err != nil {
		jsonErr(w, 400, err.Error())
		return
	}
	ip, err := netip.ParseAddr(req.IP)
	if err != nil || !a.berthHostIPs(br.link)[ip.Unmap().String()] {
		jsonErr(w, 403, "只能指向配对时选定的 Berth 主机")
		return
	}
	mine := a.berthNames(dh)
	var cur *berthName
	for i := range mine {
		if mine[i].Name == name {
			cur = &mine[i]
		}
	}
	if cur == nil {
		for _, s := range dh {
			if s[".type"] == "domain" && strings.EqualFold(optStr(s, "name"), name) {
				jsonErr(w, 409, "这个名字已经在路由器的「自定义解析」里，由别人登记")
				return
			}
		}
		if len(mine) >= 5 {
			jsonErr(w, 409, "最多登记 5 个名字")
			return
		}
	}
	ac := a.berthActor(r)
	var ch UciChange
	if cur != nil {
		if cur.IP == ip.String() {
			writeJSON(w, 200, map[string]any{"ok": true, "name": name, "ip": cur.IP})
			return
		}
		ch = UciChange{Op: "set", Config: "dhcp", Section: cur.Section, Values: map[string]any{"ip": ip.String()}}
	} else {
		ch = UciChange{Op: "add", Config: "dhcp", Type: "domain", Name: "owpb_" + sign.RandomHex(4), Values: map[string]any{"name": name, "ip": ip.String()}}
	}
	res, err := a.agent.Apply(ch)
	if err != nil {
		jsonErr(w, 502, err.Error())
		return
	}
	sec := res[0].Section
	if ch.Op == "add" {
		_, _ = a.db.Exec(`INSERT OR REPLACE INTO owned(config, section, kind, user_id, created_at) VALUES('dhcp',?,?,0,?)`, sec, berthDNSKind, time.Now().Unix())
	}
	a.audit(ac, "hosts.save", "uci", "dhcp."+sec, br.summary(fmt.Sprintf("Berth 登记本地域名 %s → %s", name, ip)), res[0].Before, res[0].After, true)
	writeJSON(w, 200, map[string]any{"ok": true, "name": name, "ip": ip.String()})
}

// DELETE /api/ext/berth/v1/dns/names/{name}
func (a *App) handleBerthDNSDelete(w http.ResponseWriter, r *http.Request) {
	br := berthFrom(r)
	name := strings.ToLower(strings.TrimSuffix(r.PathValue("name"), "."))
	dh, err := a.agent.UciConfig("dhcp")
	if err != nil {
		jsonErr(w, 502, err.Error())
		return
	}
	for _, n := range a.berthNames(dh) {
		if n.Name != name {
			continue
		}
		res, err := a.agent.Apply(UciChange{Op: "delete", Config: "dhcp", Section: n.Section})
		if err != nil {
			jsonErr(w, 502, err.Error())
			return
		}
		_, _ = a.db.Exec(`DELETE FROM owned WHERE config='dhcp' AND section=?`, n.Section)
		a.audit(a.berthActor(r), "hosts.save", "uci", "dhcp."+n.Section, br.summary("Berth 删除本地域名 "+name), res[0].Before, nil, true)
		writeJSON(w, 200, map[string]bool{"ok": true})
		return
	}
	jsonErr(w, 404, "没有由 Berth 登记的这个名字")
}

// dropBerthNames removes every name Berth registered (unpairing).
func (a *App) dropBerthNames(ac actor) int {
	dh, err := a.agent.UciConfig("dhcp")
	if err != nil {
		return 0
	}
	n := 0
	for _, x := range a.berthNames(dh) {
		if res, err := a.agent.Apply(UciChange{Op: "delete", Config: "dhcp", Section: x.Section}); err == nil {
			a.audit(ac, "hosts.save", "uci", "dhcp."+x.Section, "解除 Berth 配对：删除本地域名 "+x.Name, res[0].Before, nil, true)
			n++
		}
	}
	_, _ = a.db.Exec(`DELETE FROM owned WHERE config='dhcp' AND kind=?`, berthDNSKind)
	return n
}

// ownedKind: what kind of object Wharf recorded for a section (e.g. berth_dns, to mark
// names Berth registered on the DHCP and tools pages).
func (a *App) ownedKind(config, section string) string {
	var k string
	_ = a.db.QueryRow(`SELECT kind FROM owned WHERE config=? AND section=?`, config, section).Scan(&k)
	return k
}
