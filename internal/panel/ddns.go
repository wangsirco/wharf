package panel

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha256"
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
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// DDNS: keep DNS records pointing at the router. Each entry names a provider and
// its credentials, a record (any depth: home.example.com, a.b.example.com …), where the
// address comes from (a WAN interface, public "what is my IP" services, or both) and
// when to update (when the address changes and/or on a timer).

type DDNS struct {
	ID       int64             `json:"id"`
	Name     string            `json:"name"`
	Enabled  bool              `json:"enabled"`
	Provider string            `json:"provider"`
	Creds    map[string]string `json:"creds"`
	Domain   string            `json:"domain"`
	RType    string            `json:"rtype"` // A | AAAA | CNAME
	Source   DDNSSource        `json:"source"`
	Interval int               `json:"interval_min"` // 0 = no timer
	OnChange bool              `json:"on_change"`
	TTL      int               `json:"ttl"`
	Proxied  bool              `json:"proxied"` // Cloudflare orange cloud
	LastIP   string            `json:"last_ip"`
	LastOK   int64             `json:"last_ok"`
	LastRun  int64             `json:"last_run"`
	LastErr  string            `json:"last_err"`
	Created  int64             `json:"created"`
}

type DDNSSource struct {
	Mode  string   `json:"mode"`  // iface | api | auto (interface when its address is public, else the services)
	Iface string   `json:"iface"` // logical interface (wan, wan6, wanb …)
	APIs  []string `json:"apis"`  // service ids or custom http(s) URLs; tried in order
	// Target of a CNAME record: an existing dynamic name (another DDNS client keeps
	// it pointed at home), so a new subdomain needs no address of its own
	Target string `json:"target,omitempty"`
}

type ddnsProvider struct {
	ID     string   `json:"id"`
	Name   string   `json:"name"`
	Fields []string `json:"fields"` // credential keys
	Labels []string `json:"labels"`
	Help   string   `json:"help"`
}

var ddnsProviders = []ddnsProvider{
	{"cloudflare", "Cloudflare", []string{"token"}, []string{"API Token"}, "My Profile → API Tokens → 创建令牌，模板选「编辑区域 DNS」，区域选你的域名"},
	{"alidns", "阿里云 DNS", []string{"key_id", "key_secret"}, []string{"AccessKey ID", "AccessKey Secret"}, "RAM 访问控制里建一个只授权 AliyunDNSFullAccess 的子账号，用它的 AccessKey"},
	{"dnspod", "腾讯云 DNSPod", []string{"secret_id", "secret_key"}, []string{"SecretId", "SecretKey"}, "访问管理 → API 密钥（建议用只授权 QcloudDNSPodFullAccess 的子用户）"},
	{"godaddy", "GoDaddy", []string{"key", "secret"}, []string{"API Key", "API Secret"}, "developer.godaddy.com/keys 生成 Production 密钥"},
	{"porkbun", "Porkbun", []string{"apikey", "secretapikey"}, []string{"API Key", "Secret API Key"}, "Account → API Access 生成，并在域名设置里打开 API Access"},
	{"namecheap", "Namecheap", []string{"password"}, []string{"Dynamic DNS Password"}, "Domain List → Manage → Advanced DNS → 打开 Dynamic DNS 后显示的密码"},
	{"duckdns", "DuckDNS", []string{"token"}, []string{"Token"}, "duckdns.org 登录后首页显示的 token；域名填 xxx.duckdns.org"},
	{"dyndns2", "DynDNS 协议（No-IP / Dynu / HE.net / 花生壳等）", []string{"server", "username", "password"}, []string{"服务器（如 dynupdate.no-ip.com）", "用户名", "密码"}, "大多数动态域名服务都兼容这个协议，按服务商文档填写更新服务器"},
	{"webhook", "自定义网址", []string{"url", "method", "body"}, []string{"网址（可用 {ip} {domain} {type}）", "方法 GET / POST", "POST 内容（可选）"}, "例如 https://example.com/update?host={domain}&ip={ip}"},
}

// Public "what is my IP" services: plain-text answers unless noted.
var ipServices = []struct {
	ID, URL string
	V6      bool
}{
	{"ipify", "https://api.ipify.org", false},
	{"icanhazip", "https://ipv4.icanhazip.com", false},
	{"ipsb", "https://api-ipv4.ip.sb/ip", false},
	{"ddnspod", "https://ipv4.ddnspod.com", false}, // reachable from mainland China too
	{"cloudflare", "https://1.1.1.1/cdn-cgi/trace", false},
	{"ipify6", "https://api6.ipify.org", true},
	{"icanhazip6", "https://ipv6.icanhazip.com", true},
	{"ipsb6", "https://api-ipv6.ip.sb/ip", true},
	{"ddnspod6", "https://ipv6.ddnspod.com", true},
	{"cloudflare6", "https://[2606:4700:4700::1111]/cdn-cgi/trace", true},
}

const ddnsCols = `id, name, enabled, provider, creds, domain, rtype, source, interval_min, on_change, ttl, proxied, last_ip, last_ok, last_run, last_err, created`

func scanDDNS(row interface{ Scan(...any) error }) (*DDNS, error) {
	var d DDNS
	var creds, src string
	if err := row.Scan(&d.ID, &d.Name, &d.Enabled, &d.Provider, &creds, &d.Domain, &d.RType, &src, &d.Interval, &d.OnChange, &d.TTL, &d.Proxied,
		&d.LastIP, &d.LastOK, &d.LastRun, &d.LastErr, &d.Created); err != nil {
		return nil, err
	}
	_ = json.Unmarshal([]byte(creds), &d.Creds)
	_ = json.Unmarshal([]byte(src), &d.Source)
	if d.Creds == nil {
		d.Creds = map[string]string{}
	}
	return &d, nil
}

func (a *App) ddnsList() ([]*DDNS, error) {
	rows, err := a.db.Query(`SELECT ` + ddnsCols + ` FROM ddns ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []*DDNS{}
	for rows.Next() {
		d, err := scanDDNS(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	return out, rows.Err()
}

func providerOf(id string) *ddnsProvider {
	for i := range ddnsProviders {
		if ddnsProviders[i].ID == id {
			return &ddnsProviders[i]
		}
	}
	return nil
}

// GET /api/ddns
func (a *App) handleDDNS(w http.ResponseWriter, r *http.Request) {
	list, err := a.ddnsList()
	if err != nil {
		jsonErr(w, 500, err.Error())
		return
	}
	for _, d := range list {
		p := providerOf(d.Provider)
		for k, v := range d.Creds {
			if p != nil && (k == "server" || k == "username" || k == "url" || k == "method" || k == "body") {
				continue
			}
			d.Creds[k] = maskSecret(v)
		}
	}
	var svcs []map[string]any
	for _, s := range ipServices {
		svcs = append(svcs, map[string]any{"id": s.ID, "url": s.URL, "v6": s.V6})
	}
	var ifaces []string
	for _, wi := range a.wans() {
		ifaces = append(ifaces, wi.Interface)
	}
	var wan map[string]any
	if a.agent.Do("GET", "/v1/wan", nil, &wan) == nil {
		if _, ok := wan["wan6"]; ok && !slices.Contains(ifaces, "wan6") {
			ifaces = append(ifaces, "wan6")
		}
	}
	writeJSON(w, 200, map[string]any{"items": list, "providers": ddnsProviders, "ip_services": svcs, "ifaces": ifaces})
}

func (d *DDNS) normalize() error {
	d.Name = clean(d.Name, 40)
	d.Domain = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(d.Domain), "."))
	if d.Name == "" {
		d.Name = d.Domain
	}
	p := providerOf(d.Provider)
	if p == nil {
		return errors.New("请选择服务商")
	}
	if !hostnameOK(d.Domain) {
		return errors.New("域名格式不对（例如 home.example.com）")
	}
	switch d.RType {
	case "AAAA":
	case "CNAME":
		if !slices.Contains([]string{"cloudflare", "alidns", "dnspod"}, d.Provider) {
			return errors.New("CNAME 记录目前支持 Cloudflare、阿里云、DNSPod")
		}
		d.Source.Target = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(d.Source.Target), "."))
		if !hostnameOK(d.Source.Target) || d.Source.Target == d.Domain {
			return errors.New("CNAME 指向的域名格式不对（例如 home.example.net）")
		}
		d.OnChange = false // nothing to watch: the target follows the address itself
		if d.Interval == 0 {
			d.Interval = 1440
		}
	default:
		d.RType = "A"
	}
	if d.RType != "CNAME" {
		d.Source.Target = ""
	}
	switch d.Source.Mode {
	case "iface", "api", "auto":
	default:
		d.Source.Mode = "auto"
	}
	if d.Source.Mode != "api" && d.Source.Iface == "" {
		d.Source.Iface = map[string]string{"A": "wan", "AAAA": "wan6"}[d.RType]
	}
	var apis []string
	for _, s := range d.Source.APIs {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		known := false
		for _, x := range ipServices {
			known = known || x.ID == s
		}
		if !known && !strings.HasPrefix(s, "https://") && !strings.HasPrefix(s, "http://") {
			return fmt.Errorf("IP 查询服务 %q 不对", s)
		}
		apis = append(apis, s)
	}
	if len(apis) == 0 {
		if d.RType == "A" {
			apis = []string{"ipify", "ipsb", "cloudflare"}
		} else {
			apis = []string{"ipify6", "ipsb6", "cloudflare6"}
		}
	}
	d.Source.APIs = apis
	if d.Interval < 0 || d.Interval > 1440 {
		return errors.New("定时间隔应在 0–1440 分钟")
	}
	if d.Interval > 0 && d.Interval < 1 {
		d.Interval = 1
	}
	if !d.OnChange && d.Interval == 0 {
		return errors.New("至少选择一种更新方式：IP 变化时，或定时")
	}
	if d.TTL < 0 || d.TTL > 86400 {
		return errors.New("TTL 不对")
	}
	if d.TTL == 0 {
		d.TTL = 300
	}
	for _, k := range p.Fields {
		if k == "body" || (k == "method" && d.Provider == "webhook") {
			continue
		}
		if strings.TrimSpace(d.Creds[k]) == "" {
			return fmt.Errorf("请填写 %s", p.Labels[slices.Index(p.Fields, k)])
		}
	}
	for k := range d.Creds {
		if !slices.Contains(p.Fields, k) {
			delete(d.Creds, k)
		}
	}
	return nil
}

// POST /api/ddns  (create / update; masked credentials keep the stored value)
func (a *App) handleDDNSSave(w http.ResponseWriter, r *http.Request) {
	var d DDNS
	if err := readJSON(r, &d); err != nil {
		jsonErr(w, 400, "请求格式错误")
		return
	}
	var before *DDNS
	if d.ID != 0 {
		cur, err := scanDDNS(a.db.QueryRow(`SELECT `+ddnsCols+` FROM ddns WHERE id=?`, d.ID))
		if err != nil {
			jsonErr(w, 404, "不存在")
			return
		}
		before = cur
		for k, v := range d.Creds {
			if strings.HasPrefix(v, "••") {
				d.Creds[k] = cur.Creds[k]
			}
		}
	}
	if d.Creds == nil {
		d.Creds = map[string]string{}
	}
	if err := d.normalize(); err != nil {
		jsonErr(w, 400, err.Error())
		return
	}
	creds, src := mustJSON(d.Creds), mustJSON(d.Source)
	if d.ID == 0 {
		res, err := a.db.Exec(`INSERT INTO ddns(name, enabled, provider, creds, domain, rtype, source, interval_min, on_change, ttl, proxied, created)
			VALUES(?,?,?,?,?,?,?,?,?,?,?,?)`, d.Name, d.Enabled, d.Provider, creds, d.Domain, d.RType, src, d.Interval, d.OnChange, d.TTL, d.Proxied, time.Now().Unix())
		if err != nil {
			jsonErr(w, 500, err.Error())
			return
		}
		d.ID, _ = res.LastInsertId()
	} else {
		if _, err := a.db.Exec(`UPDATE ddns SET name=?, enabled=?, provider=?, creds=?, domain=?, rtype=?, source=?, interval_min=?, on_change=?, ttl=?, proxied=?,
			last_ip=CASE WHEN domain=? AND rtype=? AND provider=? THEN last_ip ELSE '' END WHERE id=?`,
			d.Name, d.Enabled, d.Provider, creds, d.Domain, d.RType, src, d.Interval, d.OnChange, d.TTL, d.Proxied, d.Domain, d.RType, d.Provider, d.ID); err != nil {
			jsonErr(w, 500, err.Error())
			return
		}
	}
	verb := "新增"
	if before != nil {
		verb = "修改"
	}
	a.audit(actor{user: currentUser(r), ip: a.clientIP(r)}, "ddns.save", "ddns", strconv.FormatInt(d.ID, 10),
		fmt.Sprintf("%s DDNS「%s」（%s · %s）", verb, d.Name, providerOf(d.Provider).Name, d.Domain), ddnsAudit(before), ddnsAudit(&d), false)
	a.kickDDNS()
	writeJSON(w, 200, map[string]any{"id": d.ID})
}

func ddnsAudit(d *DDNS) any {
	if d == nil {
		return nil
	}
	cp := *d
	cp.Creds = map[string]string{}
	for k, v := range d.Creds {
		cp.Creds[k] = maskSecret(v)
	}
	return cp
}

// DELETE /api/ddns/{id}
func (a *App) handleDDNSDelete(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
	d, err := scanDDNS(a.db.QueryRow(`SELECT `+ddnsCols+` FROM ddns WHERE id=?`, id))
	if err != nil {
		jsonErr(w, 404, "不存在")
		return
	}
	_, _ = a.db.Exec(`DELETE FROM ddns WHERE id=?`, id)
	_, _ = a.db.Exec(`DELETE FROM ddns_log WHERE ddns_id=?`, id)
	a.audit(actor{user: currentUser(r), ip: a.clientIP(r)}, "ddns.delete", "ddns", strconv.FormatInt(id, 10),
		fmt.Sprintf("删除 DDNS「%s」（%s，DNS 记录本身保留）", d.Name, d.Domain), ddnsAudit(d), nil, false)
	writeJSON(w, 200, map[string]bool{"ok": true})
}

// POST /api/ddns/{id}/run — update now
func (a *App) handleDDNSRun(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
	d, err := scanDDNS(a.db.QueryRow(`SELECT `+ddnsCols+` FROM ddns WHERE id=?`, id))
	if err != nil {
		jsonErr(w, 404, "不存在")
		return
	}
	ip, msg, err := a.runDDNS(d, true)
	if err != nil {
		writeJSON(w, 200, map[string]any{"ok": false, "ip": ip, "error": err.Error()})
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true, "ip": ip, "msg": msg})
}

// GET /api/ddns/{id}/log
func (a *App) handleDDNSLog(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
	rows, err := a.db.Query(`SELECT ts, ip, ok, msg FROM ddns_log WHERE ddns_id=? ORDER BY id DESC LIMIT 100`, id)
	if err != nil {
		jsonErr(w, 500, err.Error())
		return
	}
	defer rows.Close()
	type rec struct {
		TS  int64  `json:"ts"`
		IP  string `json:"ip"`
		OK  bool   `json:"ok"`
		Msg string `json:"msg"`
	}
	out := []rec{}
	for rows.Next() {
		var x rec
		if rows.Scan(&x.TS, &x.IP, &x.OK, &x.Msg) == nil {
			out = append(out, x)
		}
	}
	writeJSON(w, 200, map[string]any{"items": out})
}

// POST /api/ddns/detect {rtype, source} — what each source sees right now
func (a *App) handleDDNSDetect(w http.ResponseWriter, r *http.Request) {
	var req struct {
		RType  string     `json:"rtype"`
		Source DDNSSource `json:"source"`
	}
	if err := readJSON(r, &req); err != nil {
		jsonErr(w, 400, "请求格式错误")
		return
	}
	v6 := req.RType == "AAAA"
	type res struct {
		Source string `json:"source"`
		IP     string `json:"ip"`
		Error  string `json:"error,omitempty"`
		Public bool   `json:"public"`
	}
	var out []res
	if req.Source.Iface != "" {
		ip, err := a.ifaceIP(req.Source.Iface, v6)
		x := res{Source: "接口 " + req.Source.Iface, IP: ip}
		if err != nil {
			x.Error = err.Error()
		}
		x.Public = publicIP(ip)
		out = append(out, x)
	}
	var wg sync.WaitGroup
	apis := req.Source.APIs
	if len(apis) == 0 {
		for _, s := range ipServices {
			if s.V6 == v6 {
				apis = append(apis, s.ID)
			}
		}
	}
	results := make([]res, len(apis))
	for i, api := range apis {
		wg.Add(1)
		go func(i int, api string) {
			defer wg.Done()
			ip, err := a.apiIP(api, v6, a.ifaceDevice(req.Source.Iface))
			results[i] = res{Source: api, IP: ip, Public: publicIP(ip)}
			if err != nil {
				results[i].Error = err.Error()
			}
		}(i, api)
	}
	wg.Wait()
	writeJSON(w, 200, map[string]any{"results": append(out, results...)})
}

// ---- address detection ----

func publicIP(s string) bool {
	ip, err := netip.ParseAddr(s)
	if err != nil {
		return false
	}
	if ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsUnspecified() {
		return false
	}
	if ip.Is4() && netip.MustParsePrefix("100.64.0.0/10").Contains(ip) { // carrier-grade NAT
		return false
	}
	return true
}

func (a *App) ifaceDevice(iface string) string {
	if iface == "" {
		return ""
	}
	var st struct {
		Device string `json:"device"`
	}
	_ = a.agent.Do("GET", "/v1/iface?name="+url.QueryEscape(iface), nil, &st)
	return st.Device
}

func (a *App) ifaceIP(iface string, v6 bool) (string, error) {
	var st struct {
		Up     bool     `json:"up"`
		Device string   `json:"device"`
		IPv4   string   `json:"ipv4"`
		IPv6   []string `json:"ipv6"`
	}
	if err := a.agent.Do("GET", "/v1/iface?name="+url.QueryEscape(iface), nil, &st); err != nil {
		return "", err
	}
	if !st.Up {
		return "", fmt.Errorf("接口 %s 没有连接", iface)
	}
	if !v6 {
		if st.IPv4 == "" {
			return "", fmt.Errorf("接口 %s 没有 IPv4 地址", iface)
		}
		return st.IPv4, nil
	}
	for _, s := range st.IPv6 {
		s, _, _ = strings.Cut(s, "/")
		if publicIP(s) {
			return s, nil
		}
	}
	return "", fmt.Errorf("接口 %s 没有公网 IPv6 地址", iface)
}

var ipInText = func(body string, v6 bool) string {
	for _, l := range strings.Split(body, "\n") {
		l = strings.TrimSpace(l)
		if v, ok := strings.CutPrefix(l, "ip="); ok { // cloudflare trace
			l = v
		}
		if ip, err := netip.ParseAddr(l); err == nil && ip.Is6() == v6 && !ip.Is4In6() {
			return ip.String()
		}
	}
	return ""
}

// apiIP asks a public service, leaving through the given device (multi-WAN) when set.
func (a *App) apiIP(api string, v6 bool, dev string) (string, error) {
	u := api
	for _, s := range ipServices {
		if s.ID == api {
			u = s.URL
		}
	}
	network := "tcp4"
	if v6 {
		network = "tcp6"
	}
	d := &net.Dialer{Timeout: 8 * time.Second, Control: bindToDevice(dev)}
	tr := &http.Transport{DialContext: func(ctx context.Context, _, addr string) (net.Conn, error) { return d.DialContext(ctx, network, addr) },
		TLSHandshakeTimeout: 8 * time.Second}
	cl := &http.Client{Timeout: 12 * time.Second, Transport: tr}
	req, _ := http.NewRequest("GET", u, nil)
	req.Header.Set("User-Agent", "curl/8.5.0")
	resp, err := cl.Do(req)
	if err != nil {
		return "", errors.New(shortErr(err))
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 8<<10))
	if resp.StatusCode != 200 {
		return "", fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	ip := ipInText(string(b), v6)
	if ip == "" {
		return "", errors.New("回应里没有 IP 地址")
	}
	return ip, nil
}

// detect returns the address to publish.
func (a *App) detectIP(d *DDNS) (string, string, error) {
	v6 := d.RType == "AAAA"
	var firstErr error
	if d.Source.Mode != "api" {
		ip, err := a.ifaceIP(d.Source.Iface, v6)
		if err == nil && (d.Source.Mode == "iface" || publicIP(ip)) {
			return ip, "接口 " + d.Source.Iface, nil
		}
		if err != nil {
			firstErr = err
		}
		if d.Source.Mode == "iface" {
			return "", "", firstErr
		}
	}
	dev := ""
	if d.Source.Iface != "" {
		dev = a.ifaceDevice(d.Source.Iface)
	}
	for _, api := range d.Source.APIs {
		ip, err := a.apiIP(api, v6, dev)
		if err == nil {
			return ip, api, nil
		}
		if firstErr == nil {
			firstErr = fmt.Errorf("%s：%v", api, err)
		}
	}
	if firstErr == nil {
		firstErr = errors.New("没有可用的 IP 来源")
	}
	return "", "", firstErr
}

// ---- loop ----

var ddnsKick = make(chan struct{}, 1)

func (a *App) kickDDNS() {
	select {
	case ddnsKick <- struct{}{}:
	default:
	}
}

func (a *App) ddnsLoop() {
	time.Sleep(20 * time.Second)
	lastCheck := map[int64]time.Time{}
	for {
		list, _ := a.ddnsList()
		now := time.Now()
		for _, d := range list {
			if !d.Enabled {
				continue
			}
			due := d.Interval > 0 && now.Unix()-d.LastRun >= int64(d.Interval)*60
			// a CNAME is (re)written once its target changes; failures retry every 10 minutes
			due = due || (d.RType == "CNAME" && d.LastIP != d.Source.Target && now.Unix()-d.LastRun >= 600*int64(min(len(d.LastErr), 1)))
			// watching for changes: the interface every minute, public services every 5
			if !due && d.OnChange {
				every := time.Minute
				if d.Source.Mode == "api" {
					every = 5 * time.Minute
				}
				if now.Sub(lastCheck[d.ID]) < every && d.LastIP != "" {
					continue
				}
				lastCheck[d.ID] = now
			} else if !due {
				continue
			}
			_, _, _ = a.runDDNS(d, due)
		}
		select {
		case <-ddnsKick:
		case <-time.After(time.Minute):
		}
	}
}

// runDDNS detects the address and updates the record when it changed (or force).
func (a *App) runDDNS(d *DDNS, force bool) (string, string, error) {
	now := time.Now().Unix()
	ip, from, err := d.Source.Target, "", error(nil)
	if d.RType != "CNAME" {
		ip, from, err = a.detectIP(d)
	}
	logIt := func(ok bool, msg string) {
		_, _ = a.db.Exec(`INSERT INTO ddns_log(ddns_id, ts, ip, ok, msg) VALUES(?,?,?,?,?)`, d.ID, now, ip, ok, msg)
		_, _ = a.db.Exec(`DELETE FROM ddns_log WHERE ddns_id=? AND id <= (SELECT id FROM ddns_log WHERE ddns_id=? ORDER BY id DESC LIMIT 1 OFFSET 300)`, d.ID, d.ID)
	}
	fail := func(err error) (string, string, error) {
		_, _ = a.db.Exec(`UPDATE ddns SET last_run=?, last_err=? WHERE id=?`, now, err.Error(), d.ID)
		logIt(false, err.Error())
		if d.LastErr == "" && a.alertRules().DDNSFail { // only the first failure of a streak alerts
			a.notify("ddns", "DDNS 更新失败", fmt.Sprintf("%s：%v", d.Domain, err), false)
		}
		return ip, "", err
	}
	if err != nil {
		return fail(fmt.Errorf("获取 IP 失败：%v", err))
	}
	if ip == d.LastIP && !force {
		_, _ = a.db.Exec(`UPDATE ddns SET last_err='' WHERE id=? AND last_err<>''`, d.ID)
		return ip, "", nil
	}
	msg, err := ddnsUpdate(d, ip)
	if err != nil {
		return fail(err)
	}
	if from != "" {
		msg += "（IP 来自 " + from + "）"
	}
	_, _ = a.db.Exec(`UPDATE ddns SET last_ip=?, last_ok=?, last_run=?, last_err='' WHERE id=?`, ip, now, now, d.ID)
	if ip != d.LastIP {
		logIt(true, msg)
		if d.LastIP != "" {
			log.Printf("ddns: %s %s -> %s", d.Domain, d.LastIP, ip)
		}
	} else if force {
		logIt(true, msg)
	}
	return ip, msg, nil
}

// ---- providers ----

var ddnsHTTP = &http.Client{Timeout: 20 * time.Second}

func doJSON(req *http.Request, out any) error {
	resp, err := ddnsHTTP.Do(req)
	if err != nil {
		return errors.New(shortErr(err))
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode/100 != 2 {
		msg := strings.TrimSpace(string(b))
		if len(msg) > 200 {
			msg = msg[:200]
		}
		return fmt.Errorf("HTTP %d：%s", resp.StatusCode, msg)
	}
	if out != nil {
		if err := json.Unmarshal(b, out); err != nil {
			return fmt.Errorf("无法解析回应：%s", strings.TrimSpace(string(b[:min(len(b), 120)])))
		}
	}
	return nil
}

func ddnsUpdate(d *DDNS, ip string) (string, error) {
	switch d.Provider {
	case "cloudflare":
		return cfUpdate(d, ip)
	case "alidns":
		return aliUpdate(d, ip)
	case "dnspod":
		return dnspodUpdate(d, ip)
	case "godaddy":
		return godaddyUpdate(d, ip)
	case "porkbun":
		return porkbunUpdate(d, ip)
	case "namecheap":
		return namecheapUpdate(d, ip)
	case "duckdns":
		return duckUpdate(d, ip)
	case "dyndns2":
		return dyndns2Update(d, ip)
	case "webhook":
		return webhookUpdate(d, ip)
	}
	return "", errors.New("未知服务商")
}

// zoneCandidates: "a.b.example.com" -> example.com, b.example.com, a.b.example.com (shortest first)
func zoneCandidates(domain string) []string {
	parts := strings.Split(domain, ".")
	var out []string
	for i := len(parts) - 2; i >= 0; i-- {
		out = append(out, strings.Join(parts[i:], "."))
	}
	return out
}

func rrOf(domain, zone string) string {
	if domain == zone {
		return "@"
	}
	return strings.TrimSuffix(domain, "."+zone)
}

// cfCall returns a Cloudflare API caller for one token (also used for the panel's own
// certificate, panelcert.go).
func cfCall(token string) func(method, path string, body any, out any) error {
	api := cfAPI
	return func(method, path string, body any, out any) error {
		var rd io.Reader
		if body != nil {
			b, _ := json.Marshal(body)
			rd = bytes.NewReader(b)
		}
		req, _ := http.NewRequest(method, api+path, rd)
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("Content-Type", "application/json")
		var env struct {
			Success bool `json:"success"`
			Errors  []struct {
				Message string `json:"message"`
			} `json:"errors"`
			Result json.RawMessage `json:"result"`
		}
		if err := doJSON(req, &env); err != nil {
			return err
		}
		if !env.Success {
			var msgs []string
			for _, e := range env.Errors {
				msgs = append(msgs, e.Message)
			}
			return errors.New("Cloudflare：" + strings.Join(msgs, "；"))
		}
		if out != nil {
			return json.Unmarshal(env.Result, out)
		}
		return nil
	}
}

var cfAPI = "https://api.cloudflare.com/client/v4" // replaced in tests

// cfZone finds the zone a name belongs to.
func cfZone(call func(string, string, any, any) error, domain string) (string, error) {
	for _, z := range zoneCandidates(domain) {
		var zones []struct {
			ID string `json:"id"`
		}
		if err := call("GET", "/zones?name="+url.QueryEscape(z), nil, &zones); err != nil {
			return "", err
		}
		if len(zones) > 0 {
			return zones[0].ID, nil
		}
	}
	return "", errors.New("这个令牌下找不到该域名的区域（Zone）")
}

func cfUpdate(d *DDNS, ip string) (string, error) {
	call := cfCall(d.Creds["token"])
	zoneID, err := cfZone(call, d.Domain)
	if err != nil {
		return "", err
	}
	var recs []struct {
		ID      string `json:"id"`
		Content string `json:"content"`
		Proxied bool   `json:"proxied"`
		TTL     int    `json:"ttl"`
	}
	if err := call("GET", "/zones/"+zoneID+"/dns_records?type="+d.RType+"&name="+url.QueryEscape(d.Domain), nil, &recs); err != nil {
		return "", err
	}
	ttl := d.TTL
	if d.Proxied {
		ttl = 1
	}
	body := map[string]any{"type": d.RType, "name": d.Domain, "content": ip, "ttl": ttl, "proxied": d.Proxied, "comment": "Wharf DDNS"}
	if len(recs) == 0 {
		return "已新建记录 " + ip, call("POST", "/zones/"+zoneID+"/dns_records", body, nil)
	}
	if recs[0].Content == ip && recs[0].Proxied == d.Proxied {
		return "记录已是 " + ip, nil
	}
	return "已更新为 " + ip, call("PATCH", "/zones/"+zoneID+"/dns_records/"+recs[0].ID, body, nil)
}

func aliEnc(s string) string {
	return strings.NewReplacer("+", "%20", "*", "%2A", "%7E", "~").Replace(url.QueryEscape(s))
}

// aliSign returns the canonical query and its signature (RPC signature v1).
func aliSign(p map[string]string, secret string) (string, string) {
	keys := make([]string, 0, len(p))
	for k := range p {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var q []string
	for _, k := range keys {
		q = append(q, aliEnc(k)+"="+aliEnc(p[k]))
	}
	canon := strings.Join(q, "&")
	mac := hmac.New(sha1.New, []byte(secret+"&"))
	mac.Write([]byte("GET&%2F&" + aliEnc(canon)))
	return canon, base64.StdEncoding.EncodeToString(mac.Sum(nil))
}

// aliCall signs an Alibaba Cloud RPC request (signature v1, HMAC-SHA1).
func aliCall(d *DDNS, params map[string]string, out any) error {
	p := map[string]string{
		"Format": "JSON", "Version": "2015-01-09", "AccessKeyId": d.Creds["key_id"], "SignatureMethod": "HMAC-SHA1",
		"Timestamp": time.Now().UTC().Format("2006-01-02T15:04:05Z"), "SignatureVersion": "1.0", "SignatureNonce": randHex(16),
	}
	for k, v := range params {
		p[k] = v
	}
	canon, sig := aliSign(p, d.Creds["key_secret"])
	req, _ := http.NewRequest("GET", "https://alidns.aliyuncs.com/?"+canon+"&Signature="+aliEnc(sig), nil)
	resp, err := ddnsHTTP.Do(req)
	if err != nil {
		return errors.New(shortErr(err))
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	var e struct {
		Code    string `json:"Code"`
		Message string `json:"Message"`
	}
	if resp.StatusCode != 200 {
		_ = json.Unmarshal(b, &e)
		return fmt.Errorf("阿里云：%s %s", e.Code, e.Message)
	}
	return json.Unmarshal(b, out)
}

func aliUpdate(d *DDNS, ip string) (string, error) {
	var recs struct {
		DomainRecords struct {
			Record []struct {
				RecordId   string `json:"RecordId"`
				RR         string `json:"RR"`
				Value      string `json:"Value"`
				DomainName string `json:"DomainName"`
			} `json:"Record"`
		} `json:"DomainRecords"`
	}
	if err := aliCall(d, map[string]string{"Action": "DescribeSubDomainRecords", "SubDomain": d.Domain, "Type": d.RType}, &recs); err != nil {
		return "", err
	}
	ttl := strconv.Itoa(max(d.TTL, 600)) // the free edition's minimum
	if r := recs.DomainRecords.Record; len(r) > 0 {
		if r[0].Value == ip {
			return "记录已是 " + ip, nil
		}
		var out map[string]any
		return "已更新为 " + ip, aliCall(d, map[string]string{"Action": "UpdateDomainRecord", "RecordId": r[0].RecordId, "RR": r[0].RR, "Type": d.RType, "Value": ip, "TTL": ttl}, &out)
	}
	// no record yet: find the zone among the account's domains
	var lastErr error
	for _, z := range zoneCandidates(d.Domain) {
		var out map[string]any
		err := aliCall(d, map[string]string{"Action": "AddDomainRecord", "DomainName": z, "RR": rrOf(d.Domain, z), "Type": d.RType, "Value": ip, "TTL": ttl}, &out)
		if err == nil {
			return "已新建记录 " + ip, nil
		}
		lastErr = err
	}
	return "", lastErr
}

// dnspodCall signs a Tencent Cloud API 3.0 request (TC3-HMAC-SHA256).
func dnspodCall(d *DDNS, action string, payload map[string]any, out any) error {
	host, service := "dnspod.tencentcloudapi.com", "dnspod"
	body, _ := json.Marshal(payload)
	ts := time.Now().Unix()
	date := time.Unix(ts, 0).UTC().Format("2006-01-02")
	sum := func(b []byte) string { h := sha256.Sum256(b); return hex.EncodeToString(h[:]) }
	hm := func(key []byte, s string) []byte {
		m := hmac.New(sha256.New, key)
		m.Write([]byte(s))
		return m.Sum(nil)
	}
	canon := "POST\n/\n\ncontent-type:application/json; charset=utf-8\nhost:" + host + "\nx-tc-action:" + strings.ToLower(action) + "\n\ncontent-type;host;x-tc-action\n" + sum(body)
	scope := date + "/" + service + "/tc3_request"
	toSign := "TC3-HMAC-SHA256\n" + strconv.FormatInt(ts, 10) + "\n" + scope + "\n" + sum([]byte(canon))
	key := hm(hm(hm([]byte("TC3"+d.Creds["secret_key"]), date), service), "tc3_request")
	sig := hex.EncodeToString(hm(key, toSign))
	req, _ := http.NewRequest("POST", "https://"+host, bytes.NewReader(body))
	req.Header.Set("Authorization", "TC3-HMAC-SHA256 Credential="+d.Creds["secret_id"]+"/"+scope+", SignedHeaders=content-type;host;x-tc-action, Signature="+sig)
	req.Header.Set("Content-Type", "application/json; charset=utf-8")
	req.Header.Set("Host", host)
	req.Header.Set("X-TC-Action", action)
	req.Header.Set("X-TC-Version", "2021-03-23")
	req.Header.Set("X-TC-Timestamp", strconv.FormatInt(ts, 10))
	var env struct {
		Response json.RawMessage `json:"Response"`
	}
	if err := doJSON(req, &env); err != nil {
		return err
	}
	var e struct {
		Error *struct {
			Code    string `json:"Code"`
			Message string `json:"Message"`
		} `json:"Error"`
	}
	_ = json.Unmarshal(env.Response, &e)
	if e.Error != nil {
		return fmt.Errorf("DNSPod：%s %s", e.Error.Code, e.Error.Message)
	}
	return json.Unmarshal(env.Response, out)
}

func dnspodUpdate(d *DDNS, ip string) (string, error) {
	var lastErr error
	for _, z := range zoneCandidates(d.Domain) {
		sub := rrOf(d.Domain, z)
		var list struct {
			RecordList []struct {
				RecordId uint64 `json:"RecordId"`
				Value    string `json:"Value"`
				Line     string `json:"Line"`
			} `json:"RecordList"`
		}
		err := dnspodCall(d, "DescribeRecordList", map[string]any{"Domain": z, "Subdomain": sub, "RecordType": d.RType}, &list)
		if err != nil {
			if strings.Contains(err.Error(), "ResourceNotFound.NoDataOfRecord") {
				var out map[string]any
				if err := dnspodCall(d, "CreateRecord", map[string]any{"Domain": z, "SubDomain": sub, "RecordType": d.RType, "RecordLine": "默认", "Value": ip, "TTL": max(d.TTL, 600)}, &out); err != nil {
					return "", err
				}
				return "已新建记录 " + ip, nil
			}
			lastErr = err
			continue // probably not this zone
		}
		if len(list.RecordList) == 0 {
			continue
		}
		r := list.RecordList[0]
		if r.Value == ip {
			return "记录已是 " + ip, nil
		}
		var out map[string]any
		if err := dnspodCall(d, "ModifyRecord", map[string]any{"Domain": z, "SubDomain": sub, "RecordId": r.RecordId, "RecordType": d.RType,
			"RecordLine": firstNonEmpty(r.Line, "默认"), "Value": ip, "TTL": max(d.TTL, 600)}, &out); err != nil {
			return "", err
		}
		return "已更新为 " + ip, nil
	}
	if lastErr == nil {
		lastErr = errors.New("账号下找不到该域名")
	}
	return "", lastErr
}

func godaddyUpdate(d *DDNS, ip string) (string, error) {
	var lastErr error
	for _, z := range zoneCandidates(d.Domain) {
		body, _ := json.Marshal([]map[string]any{{"data": ip, "ttl": max(d.TTL, 600)}})
		req, _ := http.NewRequest("PUT", "https://api.godaddy.com/v1/domains/"+z+"/records/"+d.RType+"/"+url.PathEscape(rrOf(d.Domain, z)), bytes.NewReader(body))
		req.Header.Set("Authorization", "sso-key "+d.Creds["key"]+":"+d.Creds["secret"])
		req.Header.Set("Content-Type", "application/json")
		if err := doJSON(req, nil); err != nil {
			lastErr = err
			continue
		}
		return "已更新为 " + ip, nil
	}
	return "", lastErr
}

func porkbunUpdate(d *DDNS, ip string) (string, error) {
	auth := map[string]any{"apikey": d.Creds["apikey"], "secretapikey": d.Creds["secretapikey"]}
	var lastErr error
	for _, z := range zoneCandidates(d.Domain) {
		sub := rrOf(d.Domain, z)
		if sub == "@" {
			sub = ""
		}
		var list struct {
			Status  string `json:"status"`
			Message string `json:"message"`
			Records []struct {
				Content string `json:"content"`
			} `json:"records"`
		}
		b, _ := json.Marshal(auth)
		req, _ := http.NewRequest("POST", "https://api.porkbun.com/api/json/v3/dns/retrieveByNameType/"+z+"/"+d.RType+"/"+sub, bytes.NewReader(b))
		if err := doJSON(req, &list); err != nil || list.Status != "SUCCESS" {
			lastErr = fmt.Errorf("Porkbun：%s", firstNonEmpty(list.Message, errString(err)))
			continue
		}
		body := map[string]any{"apikey": auth["apikey"], "secretapikey": auth["secretapikey"], "content": ip, "ttl": strconv.Itoa(max(d.TTL, 600))}
		path := "editByNameType/" + z + "/" + d.RType + "/" + sub
		msg := "已更新为 " + ip
		if len(list.Records) == 0 {
			body["name"], body["type"] = sub, d.RType
			path, msg = "create/"+z, "已新建记录 "+ip
		} else if list.Records[0].Content == ip {
			return "记录已是 " + ip, nil
		}
		b, _ = json.Marshal(body)
		req, _ = http.NewRequest("POST", "https://api.porkbun.com/api/json/v3/dns/"+path, bytes.NewReader(b))
		var res struct {
			Status  string `json:"status"`
			Message string `json:"message"`
		}
		if err := doJSON(req, &res); err != nil || res.Status != "SUCCESS" {
			return "", fmt.Errorf("Porkbun：%s", firstNonEmpty(res.Message, errString(err)))
		}
		return msg, nil
	}
	return "", lastErr
}

func namecheapUpdate(d *DDNS, ip string) (string, error) {
	if d.RType != "A" {
		return "", errors.New("Namecheap 的动态 DNS 只支持 A 记录")
	}
	var lastErr error
	for _, z := range zoneCandidates(d.Domain) {
		u := "https://dynamicdns.park-your-domain.com/update?host=" + url.QueryEscape(rrOf(d.Domain, z)) + "&domain=" + url.QueryEscape(z) +
			"&password=" + url.QueryEscape(d.Creds["password"]) + "&ip=" + ip
		resp, err := ddnsHTTP.Get(u)
		if err != nil {
			return "", errors.New(shortErr(err))
		}
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
		resp.Body.Close()
		s := string(b)
		if strings.Contains(s, "<ErrCount>0</ErrCount>") {
			return "已更新为 " + ip, nil
		}
		if i, j := strings.Index(s, "<Err1>"), strings.Index(s, "</Err1>"); i >= 0 && j > i {
			lastErr = errors.New("Namecheap：" + s[i+6:j])
		} else {
			lastErr = errors.New("Namecheap 返回了无法识别的结果")
		}
	}
	return "", lastErr
}

func duckUpdate(d *DDNS, ip string) (string, error) {
	sub, ok := strings.CutSuffix(d.Domain, ".duckdns.org")
	if !ok {
		return "", errors.New("DuckDNS 的域名应以 .duckdns.org 结尾")
	}
	if i := strings.LastIndexByte(sub, '.'); i >= 0 {
		sub = sub[i+1:]
	}
	key := "ip"
	if d.RType == "AAAA" {
		key = "ipv6"
	}
	resp, err := ddnsHTTP.Get("https://www.duckdns.org/update?domains=" + url.QueryEscape(sub) + "&token=" + url.QueryEscape(d.Creds["token"]) + "&" + key + "=" + ip)
	if err != nil {
		return "", errors.New(shortErr(err))
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
	if strings.TrimSpace(string(b)) != "OK" {
		return "", errors.New("DuckDNS 返回 " + strings.TrimSpace(string(b)) + "（检查 token 和域名）")
	}
	return "已更新为 " + ip, nil
}

func dyndns2Update(d *DDNS, ip string) (string, error) {
	server := strings.TrimSpace(d.Creds["server"])
	if !strings.HasPrefix(server, "http://") && !strings.HasPrefix(server, "https://") {
		server = "https://" + server
	}
	u, err := url.Parse(server)
	if err != nil || u.Host == "" {
		return "", errors.New("更新服务器地址不对")
	}
	if u.Path == "" || u.Path == "/" {
		u.Path = "/nic/update"
	}
	q := u.Query()
	q.Set("hostname", d.Domain)
	q.Set("myip", ip)
	u.RawQuery = q.Encode()
	req, _ := http.NewRequest("GET", u.String(), nil)
	req.SetBasicAuth(d.Creds["username"], d.Creds["password"])
	req.Header.Set("User-Agent", "Wharf-DDNS/1.0")
	resp, err := ddnsHTTP.Do(req)
	if err != nil {
		return "", errors.New(shortErr(err))
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	s := strings.TrimSpace(string(b))
	switch {
	case strings.HasPrefix(s, "good"):
		return "已更新为 " + ip, nil
	case strings.HasPrefix(s, "nochg"):
		return "记录已是 " + ip, nil
	}
	hints := map[string]string{"badauth": "用户名或密码错误", "nohost": "账号下没有这个域名", "notfqdn": "域名格式不对", "abuse": "被服务商判定为滥用", "911": "服务商故障，稍后再试"}
	for k, v := range hints {
		if strings.HasPrefix(s, k) {
			return "", errors.New(v + "（" + k + "）")
		}
	}
	return "", fmt.Errorf("服务器返回：%s", firstNonEmpty(s, resp.Status))
}

func webhookUpdate(d *DDNS, ip string) (string, error) {
	rep := strings.NewReplacer("{ip}", ip, "{domain}", d.Domain, "{type}", d.RType)
	u := rep.Replace(d.Creds["url"])
	if !strings.HasPrefix(u, "https://") && !strings.HasPrefix(u, "http://") {
		return "", errors.New("网址应以 http:// 或 https:// 开头")
	}
	method := strings.ToUpper(strings.TrimSpace(d.Creds["method"]))
	if method != "POST" {
		method = "GET"
	}
	var body io.Reader
	if method == "POST" {
		body = strings.NewReader(rep.Replace(d.Creds["body"]))
	}
	req, err := http.NewRequest(method, u, body)
	if err != nil {
		return "", err
	}
	if method == "POST" && strings.HasPrefix(strings.TrimSpace(d.Creds["body"]), "{") {
		req.Header.Set("Content-Type", "application/json")
	}
	if err := doJSON(req, nil); err != nil {
		return "", err
	}
	return "已调用网址，IP " + ip, nil
}
