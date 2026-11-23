package panel

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"log"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Berth v3 (docs/BERTH.md §9): one name per side and kind (lan / public), the link uses the
// chosen pair only, single sign-on to the name the browser can reach, and Wharf's
// statistics for Berth's overview (scope stats).

// ---- names ----

type panelNames struct {
	LAN    string `json:"lan"`
	Public string `json:"public"`
	LanFP  string `json:"lan_fp"`
}

func (a *App) wharfNames() panelNames {
	return panelNames{LAN: a.lanURL(), Public: a.publicURL(), LanFP: a.selfFingerprint()}
}

// GET /api/ext/berth/v1/names
func (a *App) handleBerthNames(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, 200, a.wharfNames())
}

// modeURL: Berth's name for the chosen kind of link (v3 peers only).
func (l *berthLink) modeURL() string {
	if l.PeerProto < 3 {
		return ""
	}
	switch l.Mode {
	case "lan":
		return l.PeerLAN
	case "public":
		return l.PeerPub
	}
	return ""
}

func cleanPeerName(s string) string {
	if s == "" {
		return ""
	}
	u, err := cleanBerthURL(s)
	if err != nil {
		return ""
	}
	return u
}

var peerNamesAt sync.Map // link id → time of the last GET /names

// refreshPeer reads Berth's protocol (from a ping) and, for v3, its names; at most every
// 5 minutes unless forced. Called after pairing, after link.updated and while measuring.
func (a *App) refreshPeer(l *berthLink, force bool) {
	if v, ok := peerNamesAt.Load(l.ID); ok && !force && time.Since(v.(time.Time)) < 5*time.Minute {
		return
	}
	peerNamesAt.Store(l.ID, time.Now())
	var ping struct {
		Protocol int `json:"protocol"`
	}
	if err := a.berthCall(l, "GET", "/ping", nil, &ping); err != nil {
		return
	}
	if ping.Protocol != l.PeerProto {
		_, _ = a.db.Exec(`UPDATE berth_link SET peer_protocol=? WHERE id=?`, ping.Protocol, l.ID)
		l.PeerProto = ping.Protocol
	}
	if l.PeerProto < 3 {
		return
	}
	var n panelNames
	if err := a.berthCall(l, "GET", "/names", nil, &n); err != nil {
		log.Printf("berth: names: %v", err)
		return
	}
	lan, pub := cleanPeerName(n.LAN), cleanPeerName(n.Public)
	if lan != l.PeerLAN || pub != l.PeerPub {
		mode := l.Mode
		if mode == "" { // a v2 pairing meets a v3 Berth: pick the kind of the address in use
			mode = map[bool]string{true: "lan", false: "public"}[berthURLRank(l.URL) < 2]
		}
		_, _ = a.db.Exec(`UPDATE berth_link SET peer_lan=?, peer_public=?, mode=? WHERE id=?`, lan, pub, mode, l.ID)
		l.PeerLAN, l.PeerPub, l.Mode = lan, pub, mode
	}
}

// berthNotifyNames: Wharf's names changed — Berth reads them again after link.updated.
func (a *App) berthNotifyNames() {
	if l := a.berth(); l != nil {
		a.berthNotify("link.updated", map[string]any{"scopes": l.Scopes, "targets": l.Targets, "names": a.wharfNames()})
	}
}

// POST /api/berth/mode {mode} — switch between the LAN and the public pair of names;
// the tokens stay, Berth is told (event link.mode).
func (a *App) handleBerthMode(w http.ResponseWriter, r *http.Request) {
	l := a.berth()
	if l == nil {
		jsonErr(w, 404, "尚未与 Berth 配对")
		return
	}
	var req struct {
		Mode string `json:"mode"`
	}
	if readJSON(r, &req) != nil || (req.Mode != "lan" && req.Mode != "public") {
		jsonErr(w, 400, "互联方式只能是 lan 或 public")
		return
	}
	a.refreshPeer(l, true)
	if l.PeerProto < 3 {
		jsonErr(w, 400, "Berth 还是旧版本，不支持切换互联方式；请先升级 Berth")
		return
	}
	if (req.Mode == "lan" && l.PeerLAN == "") || (req.Mode == "public" && l.PeerPub == "") {
		jsonErr(w, 400, map[string]string{"lan": "Berth 还没有内网名字，请先在 Berth 里设置", "public": "Berth 还没有公网名字，请先在 Berth 里设置"}[req.Mode])
		return
	}
	if req.Mode == "public" && a.publicURL() == "" {
		jsonErr(w, 400, "Wharf 还没有公网名字：先在「外网访问」里设置")
		return
	}
	before := l.Mode
	if _, err := a.db.Exec(`UPDATE berth_link SET mode=?, last_error='' WHERE id=?`, req.Mode, l.ID); err != nil {
		jsonErr(w, 500, err.Error())
		return
	}
	berthConnCache.Lock()
	berthConnCache.v = nil
	berthConnCache.Unlock()
	label := map[string]string{"lan": "内网互联", "public": "公网互联"}
	a.audit(actor{user: currentUser(r), ip: a.clientIP(r)}, "berth.mode", "berth", strconv.FormatInt(l.ID, 10), "与 Berth 改为"+label[req.Mode], before, req.Mode, false)
	l.Mode = req.Mode
	go func() {
		if err := a.berthCall(l, "POST", "/events", map[string]any{"type": "link.mode", "mode": req.Mode, "ts": time.Now().Unix()}, nil); err != nil {
			log.Printf("berth: link.mode: %v", err)
		}
	}()
	writeJSON(w, 200, map[string]any{"ok": true, "mode": req.Mode})
}

// stepErr says which step of reaching Berth failed, in words: name, connection, certificate.
func stepErr(base string, err error) string {
	host := urlHost(base)
	if u, e := url.Parse(base); e == nil {
		host = u.Host
	}
	var dns *net.DNSError
	var op *net.OpError
	var cert x509.UnknownAuthorityError
	var host509 x509.HostnameError
	switch {
	case errors.As(err, &dns):
		return "解析不到 " + urlHost(base) + "（这台路由器查不到这个名字）"
	case errors.As(err, &cert), errors.As(err, &host509), strings.Contains(err.Error(), "指纹"), strings.Contains(err.Error(), "certificate"):
		return host + " 的证书不对：" + shortErr(err)
	case errors.As(err, &op) && op.Op == "dial":
		return host + " 连不上：" + shortErr(err)
	case errors.Is(err, context.DeadlineExceeded) || strings.Contains(err.Error(), "Timeout"):
		return host + " 没有响应（超时）"
	}
	var re tls.RecordHeaderError
	if errors.As(err, &re) {
		return host + " 不是 HTTPS"
	}
	return host + " " + shortErr(err)
}

// ---- single sign-on to the name the browser can reach ----

// ssoBase: Wharf's address for via (lan | public); the other one when that is missing.
func (a *App) ssoBase(via string) (string, string) {
	n := a.wharfNames()
	if via == "public" && n.Public != "" {
		return n.Public, "public"
	}
	if via == "lan" && n.LAN != "" {
		return n.LAN, "lan"
	}
	if n.LAN != "" && via != "public" {
		return n.LAN, "lan"
	}
	if n.Public != "" {
		return n.Public, "public"
	}
	return n.LAN, "lan"
}

// ---- statistics for Berth (scope stats) ----

// asBerth runs one of Wharf's own read endpoints for Berth: same JSON as Wharf's pages.
func (a *App) asBerth(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		br := berthFrom(r)
		h(w, r.WithContext(context.WithValue(r.Context(), userKey, berthUser(br.link))))
	}
}

// GET /api/ext/berth/v1/stats/forwards/{id} — only mappings Berth made.
func (a *App) handleBerthForwardStatsOwn(w http.ResponseWriter, r *http.Request) {
	st, err := a.loadFwState()
	if err != nil {
		jsonErr(w, 502, err.Error())
		return
	}
	if f := st.forward(r.PathValue("id")); f == nil || f.Kind != berthKind {
		jsonErr(w, 404, "不是 Berth 建的映射")
		return
	}
	a.asBerth(a.handleForwardStats)(w, r)
}

// GET /api/ext/berth/v1/stats/dns — 404 when NextDNS is not set up.
func (a *App) handleBerthDNSStats(w http.ResponseWriter, r *http.Request) {
	if _, err := a.nextdns(); err != nil {
		jsonErr(w, 404, "Wharf 没有连接 NextDNS")
		return
	}
	a.asBerth(a.handleNextDNSSummary)(w, r)
}

var statsCache struct {
	sync.Mutex
	at time.Time
	v  map[string]any
}

// GET /api/ext/berth/v1/stats/summary — the four numbers, a day of traffic and the tops,
// cached 25 s (Berth asks at most every 30 s while its overview is open).
func (a *App) handleBerthStatsSummary(w http.ResponseWriter, r *http.Request) {
	statsCache.Lock()
	defer statsCache.Unlock()
	if statsCache.v != nil && time.Since(statsCache.at) < 25*time.Second {
		writeJSON(w, 200, statsCache.v)
		return
	}
	now := time.Now().Unix()
	day := now - 86400
	out := map[string]any{}

	online, total := 0, 0
	var devs []Device
	if a.agent.Do("GET", "/v1/devices", nil, &devs) == nil {
		for _, d := range devs {
			if d.IP == "" {
				continue
			}
			total++
			if d.Online {
				online++
			}
		}
	}
	out["devices"] = map[string]int{"online": online, "total": total}

	var up, down int64
	_ = a.db.QueryRow(`SELECT COALESCE(SUM(up),0), COALESCE(SUM(down),0) FROM traffic_hour WHERE hour >= ?`, todayStart()).Scan(&up, &down)
	out["today"] = map[string]int64{"up": up, "down": down}

	var vis, countries, blocked int
	_ = a.db.QueryRow(`SELECT COUNT(*), COUNT(DISTINCT NULLIF(country,'')), COALESCE(SUM(blocked),0) FROM visitors WHERE ts >= ?`, day).Scan(&vis, &countries, &blocked)
	out["visitors_24h"] = map[string]int{"count": vis, "countries": countries}
	var dnsBlocked int64
	_ = a.db.QueryRow(`SELECT COALESCE(SUM(blocked),0) FROM dns_hour WHERE hour >= ?`, day/3600*3600).Scan(&dnsBlocked)
	out["blocked_24h"] = map[string]int64{"attacks": int64(blocked), "dns": dnsBlocked}

	type pt struct {
		T    int64 `json:"t"`
		Up   int64 `json:"up"`
		Down int64 `json:"down"`
	}
	series := []pt{}
	if rows, err := a.db.Query(`SELECT hour, SUM(up), SUM(down) FROM traffic_hour WHERE hour >= ? GROUP BY hour ORDER BY hour`, day/3600*3600+3600); err == nil {
		for rows.Next() {
			var p pt
			if rows.Scan(&p.T, &p.Up, &p.Down) == nil {
				series = append(series, p)
			}
		}
		rows.Close()
	}
	out["series_24h"] = series

	type topDev struct {
		MAC  string `json:"mac"`
		Name string `json:"name"`
		IP   string `json:"ip"`
		Type string `json:"type"`
		Down int64  `json:"down"`
		Up   int64  `json:"up"`
	}
	tops := []topDev{}
	metas := a.deviceMetas()
	if rows, err := a.db.Query(`SELECT t.mac, SUM(t.up), SUM(t.down), COALESCE(d.name,''), COALESCE(d.ip,'') FROM traffic_hour t
		LEFT JOIN devices_seen d ON d.mac=t.mac WHERE t.hour >= ? GROUP BY t.mac ORDER BY SUM(t.up+t.down) DESC LIMIT 5`, todayStart()); err == nil {
		for rows.Next() {
			var d topDev
			if rows.Scan(&d.MAC, &d.Up, &d.Down, &d.Name, &d.IP) == nil {
				m := metas[d.MAC]
				id := a.identifyDevice(d.MAC, d.Name, m.Type)
				d.Type, d.Name = id.Type, displayName(m.Alias, "", d.Name, id)
				tops = append(tops, d)
			}
		}
		rows.Close()
	}
	out["top_devices"] = tops

	type cc struct {
		CC    string `json:"cc"`
		Count int    `json:"count"`
	}
	ccs := []cc{}
	if rows, err := a.db.Query(`SELECT country, COUNT(*) FROM visitors WHERE ts >= ? AND country<>'' GROUP BY country ORDER BY COUNT(*) DESC LIMIT 5`, day); err == nil {
		for rows.Next() {
			var c cc
			if rows.Scan(&c.CC, &c.Count) == nil {
				ccs = append(ccs, c)
			}
		}
		rows.Close()
	}
	out["top_countries"] = ccs
	out["pages"] = map[string]string{"traffic": "/traffic", "visitors": "/visitors", "world": "/world", "devices": "/devices", "device": "/devices/{mac}", "dns": "/dns"}
	out["filters"] = map[string][]string{
		"/traffic":  {"range=1h|today|7d|30d|90d"},
		"/visitors": {"cc=<国家代码>", "q=<IP / 运营商 / 用户 / 城市>", "match=blocked|suspect|match|mismatch", "range=1h|24h|7d|30d"},
		"/world":    {"range=1h|24h|7d"},
		"/devices":  {"q=<名称 / IP / MAC>"},
		"/dns":      {"range=1h|1d|7d|30d", "q=<域名>"},
	}
	statsCache.at, statsCache.v = time.Now(), out
	writeJSON(w, 200, out)
}
