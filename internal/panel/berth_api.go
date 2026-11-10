package panel

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/netip"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// The API Berth calls (/api/ext/berth/v1/*). Every handler runs behind berthAPI, which has
// already checked token, signature, nonce and scope; berthFrom(r) carries the link.

const berthKind = "berth"

// ---- port forwards (scope forwards) ----

type berthFwdReq struct {
	Name           string   `json:"name"`
	Proto          string   `json:"proto"`
	WanPort        string   `json:"wan_port"`
	TargetIP       string   `json:"target_ip"`
	TargetPort     string   `json:"target_port"`
	Wan            string   `json:"wan"`
	Mode           string   `json:"mode"` // all | restrict
	AllowCountries []string `json:"allow_countries"`
	Allow          []string `json:"allow"`
	Deny           []string `json:"deny"`
	BerthRef       string   `json:"berth_ref"`
	BerthHost      string   `json:"berth_host"`
	Note           string   `json:"note"`
	Enabled        *bool    `json:"enabled"`
}

type berthFwdView struct {
	ID         string   `json:"id"`
	Name       string   `json:"name"`
	Proto      string   `json:"proto"`
	WanPort    string   `json:"wan_port"`
	Wan        string   `json:"wan"`
	TargetIP   string   `json:"target_ip"`
	TargetPort string   `json:"target_port"`
	Enabled    bool     `json:"enabled"`
	Mode       string   `json:"mode"`
	Regions    []string `json:"allow_countries"`
	Kind       string   `json:"kind"` // "" (Wharf's own) | berth | proxy
	BerthRef   string   `json:"berth_ref,omitempty"`
	BerthHost  string   `json:"berth_host,omitempty"`
	Note       string   `json:"note,omitempty"`
}

func berthView(f *Forward) berthFwdView {
	return berthFwdView{ID: f.ID, Name: firstNonEmpty(f.Note, f.DeviceName, f.Name), Proto: f.Proto, WanPort: f.WanPort, Wan: f.Wan, TargetIP: f.LanIP,
		TargetPort: f.LanPort, Enabled: f.Enabled, Mode: f.Mode, Regions: f.Regions, Kind: f.Kind, BerthRef: f.BerthRef, BerthHost: f.BerthHost, Note: f.Note}
}

// GET /api/ext/berth/v1/forwards
func (a *App) handleBerthForwards(w http.ResponseWriter, r *http.Request) {
	st, err := a.loadFwState()
	if err != nil {
		jsonErr(w, 502, err.Error())
		return
	}
	out := []berthFwdView{}
	for id := range st.fw {
		if f := st.forward(id); f != nil {
			out = append(out, berthView(f))
		}
	}
	sort.Slice(out, func(i, j int) bool { return portNum(out[i].WanPort) < portNum(out[j].WanPort) })
	writeJSON(w, 200, map[string]any{"items": out})
}

// toForward turns Berth's request into the panel's own forward request.
func (a *App) berthToForward(l *berthLink, b berthFwdReq, id, rev string) (forwardReq, error) {
	ip := strings.TrimSpace(b.TargetIP)
	if !a.berthAllowsTarget(l, ip) {
		return forwardReq{}, fmt.Errorf("目标 %s 不是配对时选定的 Berth 主机", ip)
	}
	dev := b.BerthHost
	for _, t := range l.Targets {
		if t.IP == ip && t.Name != "" {
			dev = t.Name
		}
	}
	mode := firstNonEmpty(b.Mode, "all")
	enabled := b.Enabled == nil || *b.Enabled
	req := forwardReq{ID: id, Rev: rev, LanIP: ip, LanPort: firstNonEmpty(b.TargetPort, b.WanPort), WanPort: b.WanPort, Wan: b.Wan,
		Proto: b.Proto, Note: firstNonEmpty(b.Note, b.Name), DeviceName: firstNonEmpty(dev, "Berth"), Enabled: enabled, Mode: mode,
		Regions: b.AllowCountries, Allow: b.Allow, Deny: b.Deny}
	for _, t := range l.Targets {
		if t.IP == ip {
			req.DeviceMAC = t.MAC
		}
	}
	for i, c := range req.Regions {
		req.Regions[i] = strings.ToUpper(strings.TrimSpace(c))
	}
	if err := req.normalize(); err != nil {
		return req, err
	}
	return req, nil
}

func (a *App) berthForwardSave(w http.ResponseWriter, r *http.Request, id string) {
	br := berthFrom(r)
	var b berthFwdReq
	if json.Unmarshal(br.body, &b) != nil {
		jsonErr(w, 400, "请求格式错误")
		return
	}
	st, err := a.loadFwState()
	if err != nil {
		jsonErr(w, 502, err.Error())
		return
	}
	rev := ""
	if id != "" {
		f := st.forward(id)
		if f == nil {
			jsonErr(w, 404, "端口映射不存在")
			return
		}
		if f.Kind != berthKind {
			jsonErr(w, 403, "只能修改由 Berth 创建的映射")
			return
		}
		rev = f.Rev
		if b.BerthRef == "" {
			b.BerthRef = f.BerthRef
		}
		if b.BerthHost == "" {
			b.BerthHost = f.BerthHost
		}
	}
	req, err := a.berthToForward(br.link, b, id, rev)
	if err != nil {
		jsonErr(w, 400, err.Error())
		return
	}
	wp, _ := strconv.Atoi(req.WanPort)
	issues := a.forwardIssues(berthUser(br.link), st, a.wans(), a.listeners(), id, req.Wan, wp, req.Proto, req.LanIP)
	summary := forwardSummary(req)
	if r.URL.Query().Get("plan") == "1" {
		sid := firstNonEmpty(id, "owpr_<新>")
		changes := []string{"firewall." + sid + "（redirect：WAN " + req.WanPort + " → " + req.LanIP + ":" + req.LanPort + "）", "owpfwd." + sid + "（Berth 元数据）"}
		if req.Mode == "restrict" || len(req.Deny) > 0 {
			changes = append(changes, "firewall."+ipsetSection(sid)+"（来源限制 ipset）")
		}
		if issues == nil {
			issues = []portIssue{}
		}
		writeJSON(w, 200, map[string]any{"summary": summary, "issues": issues, "changes": changes, "ok": firstError(issues) == nil})
		return
	}
	if err := firstError(issues); err != nil {
		writeJSON(w, 409, map[string]any{"error": err.Error(), "issues": issues})
		return
	}
	ac := a.berthActor(r)
	br.fwdRef, br.fwdHost = clean(b.BerthRef, 120), clean(b.BerthHost, 40)
	raw, _ := json.Marshal(req)
	out, err := runForward(a, ac, raw)
	if err != nil {
		jsonErr(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, out)
}

// POST /api/ext/berth/v1/forwards[?plan=1]
func (a *App) handleBerthForwardCreate(w http.ResponseWriter, r *http.Request) {
	a.berthForwardSave(w, r, "")
}

// PUT /api/ext/berth/v1/forwards/{id}
func (a *App) handleBerthForwardUpdate(w http.ResponseWriter, r *http.Request) {
	a.berthForwardSave(w, r, r.PathValue("id"))
}

// DELETE /api/ext/berth/v1/forwards/{id}
func (a *App) handleBerthForwardDelete(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	st, err := a.loadFwState()
	if err != nil {
		jsonErr(w, 502, err.Error())
		return
	}
	f := st.forward(id)
	if f == nil {
		jsonErr(w, 404, "端口映射不存在")
		return
	}
	if f.Kind != berthKind {
		jsonErr(w, 403, "只能删除由 Berth 创建的映射")
		return
	}
	raw, _ := json.Marshal(fwdIDReq{ID: id, Rev: f.Rev})
	if _, err := runForwardDelete(a, a.berthActor(r), raw); err != nil {
		jsonErr(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, map[string]bool{"ok": true})
}

// ---- 443 by name (scope sni) ----

type berthSNIReg struct {
	Target        string   `json:"target"` // ip:port on a Berth host
	Domains       []string `json:"domains"`
	ProxyProtocol bool     `json:"proxy_protocol"`
}

func (a *App) berthSNI() *berthSNIReg {
	var s berthSNIReg
	if json.Unmarshal([]byte(a.setting("berth.sni")), &s) != nil || len(s.Domains) == 0 {
		return nil
	}
	return &s
}

func (a *App) clearBerthSNI() {
	if a.setting("berth.sni") == "" {
		return
	}
	_ = a.setSetting("berth.sni", "")
	if ext, err := a.proxyExt(); err == nil && ext.Installed {
		if err := a.reapplyProxy(); err != nil {
			log.Printf("berth: clearing 443 names: %v", err)
		}
	}
}

// sniMatch: does name fall under pattern (exact, or "*.zone" for one more label)?
func sniMatch(pattern, name string) bool {
	if pattern == name {
		return true
	}
	if rest, ok := strings.CutPrefix(pattern, "*."); ok {
		if n, ok := strings.CutSuffix(name, "."+rest); ok && n != "" && !strings.Contains(n, ".") {
			return true
		}
	}
	return false
}

func sniOverlap(a, b string) bool { return sniMatch(a, b) || sniMatch(b, a) }

type sniConflict struct {
	Domain string `json:"domain"`
	Owner  string `json:"owner"`
}

// berthSNIConflicts lists who already holds each name, by priority:
// proxy nodes > Berth > 1Panel sites > the camouflage site; the panel's own names too.
func (a *App) berthSNIConflicts(domains []string) []sniConflict {
	var out []sniConflict
	nodes, _ := a.proxyNodes()
	ps := a.proxySettings()
	for _, d := range domains {
		for _, n := range nodes {
			for _, s := range n.sniNames() {
				if sniOverlap(s, d) {
					out = append(out, sniConflict{d, "代理节点「" + n.Name + "」"})
				}
			}
		}
		for _, p := range a.publicNames() {
			if sniOverlap(p, d) {
				out = append(out, sniConflict{d, "Wharf 面板域名"})
			}
		}
		if s := onePanelOwner(strings.TrimPrefix(d, "*.")); s != nil {
			out = append(out, sniConflict{d, "1Panel 网站「" + s.Domain + "」"})
		}
		if ps.Site.Domain != "" && sniOverlap(ps.Site.Domain, d) {
			out = append(out, sniConflict{d, "伪装站点"})
		}
	}
	return out
}

// GET /api/ext/berth/v1/sni
func (a *App) handleBerthSNIGet(w http.ResponseWriter, r *http.Request) {
	reg := a.berthSNI()
	if reg == nil {
		reg = &berthSNIReg{Domains: []string{}}
	}
	ext, err := a.proxyExt()
	front := err == nil && ext.Installed && ext.Running["front"] && a.proxySettings().port() == 443
	writeJSON(w, 200, map[string]any{"target": reg.Target, "domains": reg.Domains, "proxy_protocol": reg.ProxyProtocol, "front": front})
}

// PUT /api/ext/berth/v1/sni {target, domains, proxy_protocol} — replaces Berth's list.
func (a *App) handleBerthSNIPut(w http.ResponseWriter, r *http.Request) {
	br := berthFrom(r)
	var req berthSNIReg
	if json.Unmarshal(br.body, &req) != nil {
		jsonErr(w, 400, "请求格式错误")
		return
	}
	ext, err := a.proxyExt()
	if err != nil || !ext.Installed || !ext.Running["front"] || a.proxySettings().port() != 443 {
		writeJSON(w, 409, map[string]string{"error": "443 未被占用，请改用端口映射", "code": "no_front"})
		return
	}
	domains := []string{}
	for _, d := range req.Domains {
		d = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(d), "."))
		if !hostnameOK(strings.TrimPrefix(d, "*.")) {
			jsonErr(w, 400, "域名格式不对："+d)
			return
		}
		if !slices.Contains(domains, d) {
			domains = append(domains, d)
		}
	}
	if len(domains) > 64 {
		jsonErr(w, 400, "最多登记 64 个域名")
		return
	}
	before := a.setting("berth.sni")
	ac := a.berthActor(r)
	if len(domains) == 0 {
		a.clearBerthSNI()
		a.audit(ac, "berth.sni", "setting", "berth.sni", br.summary("撤销 Berth 登记的全部 443 域名"), before, "", false)
		writeJSON(w, 200, map[string]any{"ok": true, "domains": domains})
		return
	}
	host, port, err := net.SplitHostPort(req.Target)
	if p, _ := strconv.Atoi(port); err != nil || p < 1 || p > 65535 {
		jsonErr(w, 400, "target 应为 内网IP:端口")
		return
	}
	if !a.berthAllowsTarget(br.link, host) {
		jsonErr(w, 400, "目标 "+host+" 不是配对时选定的 Berth 主机")
		return
	}
	if c := a.berthSNIConflicts(domains); len(c) > 0 {
		writeJSON(w, 409, map[string]any{"error": fmt.Sprintf("%s 已被%s占用", c[0].Domain, c[0].Owner), "conflicts": c})
		return
	}
	reg := berthSNIReg{Target: req.Target, Domains: domains, ProxyProtocol: req.ProxyProtocol}
	_ = a.setSetting("berth.sni", mustJSON(reg))
	if err := a.reapplyProxy(); err != nil {
		_ = a.setSetting("berth.sni", before)
		_ = a.reapplyProxy()
		jsonErr(w, 500, "443 分流没有更新："+err.Error())
		return
	}
	a.audit(ac, "berth.sni", "setting", "berth.sni", br.summary(fmt.Sprintf("Berth 登记 443 域名 %s → %s", strings.Join(domains, "、"), req.Target)), before, mustJSON(reg), false)
	writeJSON(w, 200, map[string]any{"ok": true, "domains": domains})
}

// ---- DDNS (scope ddns) ----

func (a *App) ddnsOwners() map[string]string {
	out := map[string]string{}
	rows, err := a.db.Query(`SELECT domain, owner FROM ddns_owner`)
	if err != nil {
		return out
	}
	defer rows.Close()
	for rows.Next() {
		var d, o string
		if rows.Scan(&d, &o) == nil {
			out[d] = o
		}
	}
	return out
}

func (a *App) ddnsOwnedByBerth(domain string) bool { return a.ddnsOwners()[domain] == "berth" }

// GET /api/ext/berth/v1/ddns
func (a *App) handleBerthDDNS(w http.ResponseWriter, r *http.Request) {
	list, err := a.ddnsList()
	if err != nil {
		jsonErr(w, 500, err.Error())
		return
	}
	owners := a.ddnsOwners()
	type item struct {
		ID       int64  `json:"id"`
		Name     string `json:"name"`
		Domain   string `json:"domain"`
		RType    string `json:"rtype"`
		Provider string `json:"provider"`
		Enabled  bool   `json:"enabled"`
		LastIP   string `json:"last_ip"`
		LastOK   int64  `json:"last_ok"`
		LastErr  string `json:"last_err"`
		Owner    string `json:"owner"`
	}
	items := []item{}
	for _, d := range list {
		items = append(items, item{d.ID, d.Name, d.Domain, d.RType, d.Provider, d.Enabled, d.LastIP, d.LastOK, d.LastErr, firstNonEmpty(owners[d.Domain], "wharf")})
	}
	writeJSON(w, 200, map[string]any{"items": items, "owners": owners})
}

// POST /api/ext/berth/v1/ddns/claim {domain, owner}
// owner=wharf for a name Wharf has no entry for yet: an entry is made from the account of
// an existing entry in the same zone (Berth's new site gets its record from the router).
func (a *App) handleBerthDDNSClaim(w http.ResponseWriter, r *http.Request) {
	br := berthFrom(r)
	var req struct {
		Domain string `json:"domain"`
		Owner  string `json:"owner"`
	}
	if json.Unmarshal(br.body, &req) != nil {
		jsonErr(w, 400, "请求格式错误")
		return
	}
	d := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(req.Domain), "."))
	if !hostnameOK(d) {
		jsonErr(w, 400, "域名格式不对")
		return
	}
	if req.Owner != "wharf" && req.Owner != "berth" {
		jsonErr(w, 400, "owner 只能是 wharf 或 berth")
		return
	}
	list, _ := a.ddnsList()
	var existing, sameZone *DDNS
	for _, e := range list {
		if e.Domain == d && e.RType != "AAAA" {
			existing = e
		}
	}
	created := int64(0)
	if req.Owner == "wharf" && existing == nil {
		zones := zoneCandidates(d)
		best := 0
		for _, e := range list {
			if e.RType == "CNAME" || e.Provider == "webhook" || e.Provider == "dyndns2" || e.Provider == "duckdns" {
				continue
			}
			for _, z := range zoneCandidates(e.Domain) {
				if z != e.Domain && z != d && slices.Contains(zones, z) && len(z) > best { // a zone both names sit in
					sameZone, best = e, len(z)
				}
			}
		}
		if sameZone == nil {
			jsonErr(w, 409, "Wharf 里没有这个域名所在区域的 DDNS 账号；请先在 Wharf 的 DDNS 页面为同一区域加一条")
			return
		}
		n := &DDNS{Name: "Berth · " + d, Enabled: true, Provider: sameZone.Provider, Creds: sameZone.Creds, Domain: d, RType: "A",
			Source: sameZone.Source, Interval: sameZone.Interval, OnChange: sameZone.OnChange, TTL: sameZone.TTL, Proxied: false}
		if err := n.normalize(); err != nil {
			jsonErr(w, 400, err.Error())
			return
		}
		id, err := a.createDDNS(n)
		if err != nil {
			jsonErr(w, 500, err.Error())
			return
		}
		created = id
		a.kickDDNS()
	}
	before := a.ddnsOwners()[d]
	if _, err := a.db.Exec(`INSERT INTO ddns_owner(domain, owner) VALUES(?,?) ON CONFLICT(domain) DO UPDATE SET owner=excluded.owner`, d, req.Owner); err != nil {
		jsonErr(w, 500, err.Error())
		return
	}
	msg := fmt.Sprintf("DDNS %s 改由 %s 维护", d, map[string]string{"wharf": "Wharf", "berth": "Berth"}[req.Owner])
	if created > 0 {
		msg += "（新建 DDNS 条目 #" + strconv.FormatInt(created, 10) + "）"
	}
	a.audit(a.berthActor(r), "berth.ddns", "ddns_owner", d, br.summary(msg), before, req.Owner, false)
	writeJSON(w, 200, map[string]any{"ok": true, "domain": d, "owner": req.Owner, "ddns_id": created})
}

// POST /api/ext/berth/v1/ddns/{id}/run
func (a *App) handleBerthDDNSRun(w http.ResponseWriter, r *http.Request) {
	d, err := scanDDNS(a.db.QueryRow(`SELECT `+ddnsCols+` FROM ddns WHERE id=?`, pathID(r)))
	if err != nil {
		jsonErr(w, 404, "DDNS 条目不存在")
		return
	}
	if a.ddnsOwnedByBerth(d.Domain) {
		jsonErr(w, 409, "这个域名由 Berth 维护")
		return
	}
	ip, msg, err := a.runDDNS(d, true)
	if err != nil {
		jsonErr(w, 502, err.Error())
		return
	}
	writeJSON(w, 200, map[string]string{"ip": ip, "message": msg})
}

// ---- devices and traffic (scopes devices.read, traffic.read) ----

// GET /api/ext/berth/v1/devices
func (a *App) handleBerthDevices(w http.ResponseWriter, r *http.Request) {
	var devs []Device
	if err := a.agent.Do("GET", "/v1/devices", nil, &devs); err != nil {
		jsonErr(w, 502, err.Error())
		return
	}
	metas := a.deviceMetas()
	type dev struct {
		Name   string `json:"name"`
		IP     string `json:"ip"`
		MAC    string `json:"mac"`
		Type   string `json:"type"`
		Vendor string `json:"vendor,omitempty"`
		Online bool   `json:"online"`
		Static bool   `json:"static"`
	}
	out := []dev{}
	for _, d := range devs {
		m := metas[d.MAC]
		id := a.identifyDevice(d.MAC, firstNonEmpty(d.StaticName, d.Hostname), m.Type)
		out = append(out, dev{displayName(m.Alias, d.StaticName, d.Hostname, id), d.IP, d.MAC, id.Type, id.Vendor, d.Online, d.Static})
	}
	writeJSON(w, 200, map[string]any{"items": out})
}

// berthHostKeys: the traffic keys of a Berth host (its MAC, and "ip:" when it is unknown).
func (a *App) berthHostKeys(w http.ResponseWriter, r *http.Request) (string, []string, bool) {
	br := berthFrom(r)
	ip := r.PathValue("ip")
	if !a.berthHostIPs(br.link)[ip] {
		jsonErr(w, 403, "只能读取配对时选定的 Berth 主机")
		return "", nil, false
	}
	keys := []string{"ip:" + ip}
	var devs []Device
	if a.agent.Do("GET", "/v1/devices", nil, &devs) == nil {
		for _, d := range devs {
			if d.IP == ip && d.MAC != "" {
				keys = append(keys, strings.ToLower(d.MAC))
			}
		}
	}
	return ip, keys, true
}

func inList(n int) string { return strings.TrimSuffix(strings.Repeat("?,", n), ",") }

// GET /api/ext/berth/v1/hosts/{ip}/traffic?range=24h|7d|30d
func (a *App) handleBerthHostTraffic(w http.ResponseWriter, r *http.Request) {
	ip, keys, ok := a.berthHostKeys(w, r)
	if !ok {
		return
	}
	since := time.Now().Unix() - rangeSecs(r.URL.Query().Get("range"))
	args := []any{}
	for _, k := range keys {
		args = append(args, k)
	}
	args = append(args, since/3600*3600)
	type point struct {
		T    int64 `json:"t"`
		Up   int64 `json:"up"`
		Down int64 `json:"down"`
	}
	series := []point{}
	var up, down int64
	if q, err := a.db.Query(`SELECT hour, SUM(up), SUM(down) FROM traffic_hour WHERE mac IN (`+inList(len(keys))+`) AND hour >= ? GROUP BY hour ORDER BY hour`, args...); err == nil {
		for q.Next() {
			var p point
			if q.Scan(&p.T, &p.Up, &p.Down) == nil {
				series = append(series, p)
				up, down = up+p.Up, down+p.Down
			}
		}
		q.Close()
	}
	type remote struct {
		IP      string `json:"ip"`
		Domain  string `json:"domain,omitempty"`
		Country string `json:"country"`
		Org     string `json:"org"`
		Inbound bool   `json:"inbound"`
		Up      int64  `json:"up"`
		Down    int64  `json:"down"`
		Conns   int64  `json:"conns"`
	}
	remotes := []remote{}
	countries := map[string]*point{}
	if q, err := a.db.Query(`SELECT remote, MAX(domain), MAX(inbound), SUM(up), SUM(down), SUM(conns) FROM flow_hour WHERE mac IN (`+inList(len(keys))+`) AND hour >= ?
		GROUP BY remote ORDER BY SUM(up+down) DESC LIMIT 500`, args...); err == nil {
		for q.Next() {
			var x remote
			if q.Scan(&x.IP, &x.Domain, &x.Inbound, &x.Up, &x.Down, &x.Conns) == nil {
				g := a.geo.LookupFast(x.IP)
				x.Country, x.Org = g.Country, g.ASOrg
				c := countries[g.Country]
				if c == nil {
					c = &point{}
					countries[g.Country] = c
				}
				c.Up, c.Down = c.Up+x.Up, c.Down+x.Down
				if len(remotes) < 100 {
					remotes = append(remotes, x)
				}
			}
		}
		q.Close()
	}
	type cstat struct {
		Country string `json:"country"`
		Name    string `json:"name"`
		Up      int64  `json:"up"`
		Down    int64  `json:"down"`
	}
	cs := []cstat{}
	for k, v := range countries {
		cs = append(cs, cstat{k, a.countryName(k), v.Up, v.Down})
	}
	sort.Slice(cs, func(i, j int) bool { return cs[i].Up+cs[i].Down > cs[j].Up+cs[j].Down })
	writeJSON(w, 200, map[string]any{"ip": ip, "up": up, "down": down, "series": series, "remotes": remotes, "countries": cs})
}

// GET /api/ext/berth/v1/hosts/{ip}/inbound?range=24h — connections that came in through
// port forwards, per remote address, with the same verdicts as the forward detail page.
func (a *App) handleBerthHostInbound(w http.ResponseWriter, r *http.Request) {
	ip, _, ok := a.berthHostKeys(w, r)
	if !ok {
		return
	}
	since := time.Now().Unix() - rangeSecs(r.URL.Query().Get("range"))
	type fwd struct {
		ID      string `json:"id"`
		WanPort string `json:"wan_port"`
		LanPort string `json:"target_port"`
		Proto   string `json:"proto"`
		Kind    string `json:"kind"`
		Service string `json:"service,omitempty"`
	}
	fwds := []fwd{}
	if st, err := a.loadFwState(); err == nil {
		for id := range st.fw {
			f := st.forward(id)
			if f == nil || f.LanIP != ip {
				continue
			}
			x := fwd{ID: id, WanPort: f.WanPort, LanPort: f.LanPort, Proto: f.Proto, Kind: f.Kind}
			if lo, _, ok := portRange(f.LanPort); ok {
				x.Service = a.fingerprint(ip, lo, strings.Fields(f.Proto), false).Service
			}
			fwds = append(fwds, x)
		}
	}
	type remote struct {
		IP      string `json:"ip"`
		Country string `json:"country"`
		Org     string `json:"org"`
		Conns   int64  `json:"conns"`
		Up      int64  `json:"up"`
		Down    int64  `json:"down"`
		First   int64  `json:"first"`
		Last    int64  `json:"last"`
		Probes  int64  `json:"probes"`
		Short   int64  `json:"short"`
		Verdict string `json:"verdict"` // scanner | brute | user
	}
	out := []remote{}
	var scanners, brutes int
	if q, err := a.db.Query(`SELECT remote, COUNT(*), SUM(up), SUM(down), MIN(start), MAX(end), `+classSQL+` FROM fwd_conns WHERE ip=? AND end >= ?
		GROUP BY remote ORDER BY COUNT(*) DESC LIMIT 300`, ip, since); err == nil {
		for q.Next() {
			var x remote
			var bulk, long int64
			if q.Scan(&x.IP, &x.Conns, &x.Up, &x.Down, &x.First, &x.Last, &x.Probes, &x.Short, &bulk, &long) != nil {
				continue
			}
			g := a.geo.LookupFast(x.IP)
			x.Country, x.Org = g.Country, g.ASOrg
			switch {
			case scannerOrg(g.ASOrg) || (x.Conns >= 3 && x.Probes*10 >= x.Conns*8):
				x.Verdict = "scanner"
				scanners++
			case x.Short >= 10:
				x.Verdict = "brute"
				brutes++
			default:
				x.Verdict = "user"
			}
			out = append(out, x)
		}
		q.Close()
	}
	writeJSON(w, 200, map[string]any{"ip": ip, "forwards": fwds, "remotes": out, "scanners": scanners, "brute": brutes})
}

// ---- alerts (scope alerts) ----

var berthAlertSeen = struct {
	sync.Mutex
	m map[string]time.Time
}{m: map[string]time.Time{}}

// POST /api/ext/berth/v1/alerts {level, title, body, link, dedupe_key}
func (a *App) handleBerthAlert(w http.ResponseWriter, r *http.Request) {
	br := berthFrom(r)
	var req struct {
		Level     string `json:"level"`
		Title     string `json:"title"`
		Body      string `json:"body"`
		Link      string `json:"link"`
		DedupeKey string `json:"dedupe_key"`
	}
	if json.Unmarshal(br.body, &req) != nil || strings.TrimSpace(req.Title) == "" {
		jsonErr(w, 400, "请求格式错误（需要 title）")
		return
	}
	if a.setting("alerts.primary") == "berth" {
		writeJSON(w, 409, map[string]string{"error": "主通知方是 Berth，Wharf 不代发", "code": "not_primary"})
		return
	}
	key := firstNonEmpty(req.DedupeKey, req.Title)
	berthAlertSeen.Lock()
	for k, t := range berthAlertSeen.m {
		if time.Since(t) > 10*time.Minute {
			delete(berthAlertSeen.m, k)
		}
	}
	if _, dup := berthAlertSeen.m[key]; dup {
		berthAlertSeen.Unlock()
		writeJSON(w, 200, map[string]any{"ok": true, "deduped": true})
		return
	}
	berthAlertSeen.m[key] = time.Now()
	berthAlertSeen.Unlock()
	body := truncate(strings.TrimSpace(req.Body), 2000)
	if l := strings.TrimSpace(req.Link); strings.HasPrefix(l, "https://") {
		body += "\n" + truncate(l, 300)
	}
	go a.notify("berth", truncate("[Berth · "+br.link.Name+"] "+strings.TrimSpace(req.Title), 200), body, req.Level == "crit" || req.Level == "critical")
	writeJSON(w, 200, map[string]any{"ok": true})
}

// forwardAlertToBerth: with Berth as the main notifier, Wharf's own alerts go there
// instead of to Wharf's channels. Approval prompts stay here: only this panel can act on them.
func (a *App) forwardAlertToBerth(kind, title, body string, urgent bool) bool {
	if kind == "approval" || kind == "berth" || a.setting("alerts.primary") != "berth" {
		return false
	}
	l := a.berth()
	if l == nil || l.state() != "active" || !l.has("alerts") {
		return false
	}
	level := map[bool]string{true: "crit", false: "warn"}[urgent]
	err := a.berthCall(l, "POST", "/alerts", map[string]string{"level": level, "title": title, "body": body, "kind": kind,
		"dedupe_key": "wharf:" + kind + ":" + title, "source": a.setting("ui.name")}, nil)
	result := "已转交 Berth"
	if err != nil {
		result = "转交 Berth 失败：" + truncate(err.Error(), 120)
	}
	_, _ = a.db.Exec(`INSERT INTO alert_log(ts, kind, title, body, result) VALUES(?,?,?,?,?)`, time.Now().Unix(), kind, title, body, result)
	return err == nil // on failure Wharf's own channels still send it
}

// ---- bans (scope bans) ----

type berthBan struct {
	ID        int64  `json:"id"`
	CIDR      string `json:"cidr"`
	Reason    string `json:"reason"`
	Source    string `json:"source"`
	ExpiresAt int64  `json:"expires_at"` // 0 = never
	CreatedAt int64  `json:"created_at"`
	Origin    string `json:"origin"` // berth | wharf
	Sync      bool   `json:"sync"`   // a Wharf ban that is also on Berth
	RemoteID  string `json:"remote_id,omitempty"`
	CreatedBy string `json:"created_by,omitempty"`
}

func (a *App) listBans(where string, args ...any) []berthBan {
	out := []berthBan{}
	rows, err := a.db.Query(`SELECT id, cidr, COALESCE(reason,''), COALESCE(source,''), COALESCE(expires_at,0), created_at, origin, sync, remote_id, created_by
		FROM berth_bans `+where+` ORDER BY id DESC`, args...)
	if err != nil {
		return out
	}
	defer rows.Close()
	for rows.Next() {
		var b berthBan
		if rows.Scan(&b.ID, &b.CIDR, &b.Reason, &b.Source, &b.ExpiresAt, &b.CreatedAt, &b.Origin, &b.Sync, &b.RemoteID, &b.CreatedBy) == nil {
			out = append(out, b)
		}
	}
	return out
}

// checkBan: never ban private ranges, the router's own public address, or anyone signed
// in to the panel right now; at most a /16 at a time.
func (a *App) checkBan(cidr string, me string) (string, error) {
	s := strings.TrimSpace(cidr)
	var p netip.Prefix
	var err error
	if strings.Contains(s, "/") {
		p, err = netip.ParsePrefix(s)
	} else {
		var ad netip.Addr
		ad, err = netip.ParseAddr(s)
		if err == nil {
			p = netip.PrefixFrom(ad, ad.BitLen())
		}
	}
	if err != nil {
		return "", errors.New("地址格式不对：" + cidr)
	}
	p = p.Masked()
	ad := p.Addr().Unmap()
	if !ad.Is4() {
		return "", errors.New("暂只支持封禁 IPv4 地址")
	}
	if p.Bits() < 16 {
		return "", errors.New("一次最多封禁 /16 网段")
	}
	if ad.IsPrivate() || ad.IsLoopback() || ad.IsLinkLocalUnicast() || ad.IsMulticast() || ad.IsUnspecified() ||
		netip.MustParsePrefix("100.64.0.0/10").Overlaps(p) || netip.MustParsePrefix("0.0.0.0/8").Overlaps(p) {
		return "", errors.New("不能封禁内网或保留地址")
	}
	for _, w := range a.wans() {
		if x, err := netip.ParseAddr(w.IPv4); err == nil && p.Contains(x) {
			return "", errors.New("不能封禁路由器自己的公网地址")
		}
	}
	ips := []string{}
	if me != "" {
		ips = append(ips, me)
	}
	if rows, err := a.db.Query(`SELECT DISTINCT ip FROM sessions WHERE seen_at > ?`, time.Now().Add(-sessionIdle).Unix()); err == nil {
		for rows.Next() {
			var s string
			if rows.Scan(&s) == nil {
				ips = append(ips, s)
			}
		}
		rows.Close()
	}
	for _, s := range ips {
		if x, err := netip.ParseAddr(s); err == nil && p.Contains(x.Unmap()) {
			return "", errors.New("这个网段里有正在使用面板的人（" + s + "），不能封禁")
		}
	}
	return p.String(), nil
}

func parseExpiry(s string) (int64, error) {
	if s == "" {
		return 0, nil
	}
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		return 0, errors.New("expires_at 应为 RFC 3339 时间")
	}
	if t.Before(time.Now()) {
		return 0, errors.New("到期时间已经过去")
	}
	return t.Unix(), nil
}

// GET /api/ext/berth/v1/bans — Wharf's bans marked to sync.
func (a *App) handleBerthBans(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, 200, map[string]any{"items": a.listBans(`WHERE origin='wharf' AND sync=1`)})
}

// POST /api/ext/berth/v1/bans {cidr, reason, source, expires_at, id}
func (a *App) handleBerthBanAdd(w http.ResponseWriter, r *http.Request) {
	br := berthFrom(r)
	var req struct {
		CIDR      string `json:"cidr"`
		Reason    string `json:"reason"`
		Source    string `json:"source"`
		ExpiresAt string `json:"expires_at"`
		ID        any    `json:"id"` // Berth's own id for this ban
	}
	if json.Unmarshal(br.body, &req) != nil {
		jsonErr(w, 400, "请求格式错误")
		return
	}
	cidr, err := a.checkBan(req.CIDR, "")
	if err != nil {
		jsonErr(w, 400, err.Error())
		return
	}
	exp, err := parseExpiry(req.ExpiresAt)
	if err != nil {
		jsonErr(w, 400, err.Error())
		return
	}
	remote := ""
	if req.ID != nil {
		remote = truncate(fmt.Sprint(req.ID), 64)
	}
	src := clean(firstNonEmpty(req.Source, "berth:"+br.link.Name), 80)
	var exists int64
	if a.db.QueryRow(`SELECT id FROM berth_bans WHERE origin='berth' AND cidr=?`, cidr).Scan(&exists) == nil {
		_, _ = a.db.Exec(`UPDATE berth_bans SET reason=?, source=?, expires_at=?, remote_id=? WHERE id=?`, clean(req.Reason, 120), src, nullInt(exp), remote, exists)
		writeJSON(w, 200, map[string]any{"id": exists, "updated": true})
		_ = a.syncBerthBans()
		return
	}
	res, err := a.db.Exec(`INSERT INTO berth_bans(cidr, reason, source, expires_at, created_at, origin, sync, remote_id, created_by) VALUES(?,?,?,?,?,'berth',0,?,?)`,
		cidr, clean(req.Reason, 120), src, nullInt(exp), time.Now().Unix(), remote, br.link.label())
	if err != nil {
		jsonErr(w, 500, err.Error())
		return
	}
	id, _ := res.LastInsertId()
	if err := a.syncBerthBans(); err != nil {
		_, _ = a.db.Exec(`DELETE FROM berth_bans WHERE id=?`, id)
		jsonErr(w, 502, "防火墙没有更新："+err.Error())
		return
	}
	a.audit(a.berthActor(r), "ban.add", "ban", strconv.FormatInt(id, 10), br.summary(fmt.Sprintf("Berth 同步封禁 %s（%s）", cidr, firstNonEmpty(req.Reason, src))), nil, map[string]any{"cidr": cidr, "source": src}, false)
	writeJSON(w, 200, map[string]any{"id": id})
}

// DELETE /api/ext/berth/v1/bans/{id} — only bans that came from Berth (Wharf id, or
// "remote:<Berth's id>").
func (a *App) handleBerthBanDelete(w http.ResponseWriter, r *http.Request) {
	ref := r.PathValue("id")
	var bans []berthBan
	if rid, ok := strings.CutPrefix(ref, "remote:"); ok {
		bans = a.listBans(`WHERE origin='berth' AND remote_id=?`, rid)
	} else {
		bans = a.listBans(`WHERE origin='berth' AND id=?`, ref)
	}
	if len(bans) == 0 {
		jsonErr(w, 404, "没有这条由 Berth 同步来的封禁")
		return
	}
	b := bans[0]
	_, _ = a.db.Exec(`DELETE FROM berth_bans WHERE id=?`, b.ID)
	_ = a.syncBerthBans()
	a.audit(a.berthActor(r), "ban.delete", "ban", strconv.FormatInt(b.ID, 10), berthFrom(r).summary("Berth 撤回封禁 "+b.CIDR), b, nil, false)
	writeJSON(w, 200, map[string]bool{"ok": true})
}

func nullInt(v int64) any {
	if v == 0 {
		return nil
	}
	return v
}
