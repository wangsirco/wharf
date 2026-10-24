package panel

import (
	"fmt"
	"log"
	"net/http"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Proxy extension: usage accounting, limits, access records and the dashboard data.

type proxyMinute struct {
	Minute int64               `json:"minute"`
	Users  map[string][2]int64 `json:"users"`
	Access []struct {
		Email  string `json:"email"`
		IP     string `json:"ip"`
		Dest   string `json:"dest"`
		Port   int    `json:"port"`
		Net    string `json:"net"`
		Status string `json:"status"`
		Count  int    `json:"count"`
		First  int64  `json:"first"`
		Last   int64  `json:"last"`
	} `json:"access"`
}

type proxyLive struct {
	TS     int64                       `json:"ts"`
	Users  map[string][2]float64       `json:"users"`
	Online map[string]map[string]int64 `json:"online"`
	Ports  map[string][2]float64       `json:"ports"` // Xray inbound port -> bytes/s (conntrack)
	IPs    map[string][2]float64       `json:"ips"`   // client address -> bytes/s (conntrack)
}

type proxyStatsResp struct {
	Boot    int64         `json:"boot"`
	Minutes []proxyMinute `json:"minutes"`
	Live    proxyLive     `json:"live"`
}

func (a *App) proxyLoop() {
	cursor, _ := strconv.ParseInt(a.setting("proxy.cursor"), 10, 64)
	blocked := map[string]time.Time{}
	tick := 0
	for {
		time.Sleep(30 * time.Second)
		tick++
		var r proxyStatsResp
		if err := a.agent.Do("GET", "/v1/proxy/stats?after="+strconv.FormatInt(cursor, 10), nil, &r); err != nil {
			continue
		}
		if len(r.Minutes) > 0 {
			cursor = a.storeProxyMinutes(r.Minutes)
			_ = a.setSetting("proxy.cursor", strconv.FormatInt(cursor, 10))
		}
		a.storeProxyIPs(r.Live.Online)
		a.enforceIPLimits(r.Live.Online, blocked)
		a.enforceProxyLimits()
		if tick%2880 == 10 && a.proxySettings().share() == "cloudflare" && a.refreshCloudflare() {
			if err := a.reapplyProxy(); err != nil {
				log.Printf("proxy: reapply after Cloudflare ranges changed: %v", err)
			}
		}
		if tick%120 == 1 {
			days := a.proxySettings().AccessDays
			_, _ = a.db.Exec(`DELETE FROM proxy_access WHERE ts < ?`, time.Now().Unix()-int64(days)*86400)
			_, _ = a.db.Exec(`DELETE FROM proxy_access WHERE id <= (SELECT id FROM proxy_access ORDER BY id DESC LIMIT 1 OFFSET 2000000)`)
			_, _ = a.db.Exec(`DELETE FROM proxy_traffic WHERE hour < ?`, time.Now().Unix()-400*86400)
			_, _ = a.db.Exec(`DELETE FROM proxy_ips WHERE last < ?`, time.Now().Unix()-int64(days)*86400)
		}
	}
}

func (a *App) storeProxyMinutes(mins []proxyMinute) int64 {
	var cursor int64
	tx, err := a.db.Begin()
	if err != nil {
		return 0
	}
	defer tx.Rollback()
	for _, m := range mins {
		hour := m.Minute / 3600 * 3600
		for email, d := range m.Users {
			uid, nid, ok := parseProxyEmail(email)
			if !ok {
				continue
			}
			_, _ = tx.Exec(`INSERT INTO proxy_traffic(hour, user_id, node_id, up, down) VALUES(?,?,?,?,?)
				ON CONFLICT(hour, user_id, node_id) DO UPDATE SET up=up+excluded.up, down=down+excluded.down`, hour, uid, nid, d[0], d[1])
			_, _ = tx.Exec(`UPDATE proxy_users SET used_up=used_up+?, used_down=used_down+? WHERE id=?`, d[0], d[1], uid)
		}
		for _, x := range m.Access {
			uid, nid, ok := parseProxyEmail(x.Email)
			if !ok {
				continue
			}
			_, _ = tx.Exec(`INSERT INTO proxy_access(ts, last, user_id, node_id, ip, dest, port, net, status, count) VALUES(?,?,?,?,?,?,?,?,?,?)`,
				x.First, x.Last, uid, nid, x.IP, clean(x.Dest, 253), x.Port, x.Net, x.Status, x.Count)
		}
		cursor = max(cursor, m.Minute)
	}
	if tx.Commit() != nil {
		return 0
	}
	return cursor
}

func (a *App) storeProxyIPs(online map[string]map[string]int64) {
	for email, ips := range online {
		uid, _, ok := parseProxyEmail(email)
		if !ok {
			continue
		}
		for ip, seen := range ips {
			_, _ = a.db.Exec(`INSERT INTO proxy_ips(user_id, ip, first, last) VALUES(?,?,?,?)
				ON CONFLICT(user_id, ip) DO UPDATE SET last=max(last, excluded.last)`, uid, ip, seen, seen)
		}
	}
}

// onlineByUser folds Xray's per email (user × node) online lists into per user.
func onlineByUser(online map[string]map[string]int64) map[int64]map[string]int64 {
	out := map[int64]map[string]int64{}
	for email, ips := range online {
		uid, _, ok := parseProxyEmail(email)
		if !ok {
			continue
		}
		if out[uid] == nil {
			out[uid] = map[string]int64{}
		}
		for ip, t := range ips {
			out[uid][ip] = max(out[uid][ip], t)
		}
	}
	return out
}

// enforceIPLimits: a user online from more addresses than allowed keeps the ones that
// came first; the newest are refused until Xray restarts (and an alert goes out).
func (a *App) enforceIPLimits(online map[string]map[string]int64, blocked map[string]time.Time) {
	if len(online) == 0 {
		return
	}
	users, err := a.proxyUsers()
	if err != nil {
		return
	}
	by := onlineByUser(online)
	for _, u := range users {
		ips := by[u.ID]
		if u.IPLimit <= 0 || len(ips) <= u.IPLimit {
			continue
		}
		type seen struct {
			ip    string
			first int64
		}
		var list []seen
		for ip := range ips {
			var first int64
			_ = a.db.QueryRow(`SELECT first FROM proxy_ips WHERE user_id=? AND ip=?`, u.ID, ip).Scan(&first)
			list = append(list, seen{ip, first})
		}
		sort.Slice(list, func(i, j int) bool { return list[i].first < list[j].first })
		var cut []string
		for _, s := range list[u.IPLimit:] {
			k := strconv.FormatInt(u.ID, 10) + "|" + s.ip
			if t, ok := blocked[k]; ok && time.Since(t) < 6*time.Hour {
				continue
			}
			if err := a.agent.Do("POST", "/v1/proxy/block", map[string]string{"ip": s.ip}, nil); err == nil {
				blocked[k] = time.Now()
				cut = append(cut, s.ip)
			}
		}
		if len(cut) > 0 {
			log.Printf("proxy: user %d over IP limit, refused %v", u.ID, cut)
			a.notify("proxy", "代理用户超出同时在线 IP 限制",
				fmt.Sprintf("「%s」同时从 %d 个 IP 连接（限制 %d），已拒绝：%s", u.Name, len(ips), u.IPLimit, strings.Join(cut, "、")), false)
		}
	}
}

// nextReset is the first monthly reset after the period start.
func nextReset(periodAt int64, day int) int64 {
	t := time.Unix(periodAt, 0)
	r := time.Date(t.Year(), t.Month(), day, 0, 0, 0, 0, time.Local)
	if !r.After(t) {
		r = r.AddDate(0, 1, 0)
	}
	return r.Unix()
}

// enforceProxyLimits pauses users over quota or past expiry and resets monthly usage.
func (a *App) enforceProxyLimits() {
	users, err := a.proxyUsers()
	if err != nil {
		return
	}
	now := time.Now().Unix()
	changed := false
	for _, u := range users {
		was := *u
		if u.ResetDay > 0 && now >= nextReset(u.PeriodAt, u.ResetDay) {
			u.UsedUp, u.UsedDown, u.PeriodAt = 0, 0, now
			if u.Stopped == "quota" {
				u.Stopped = ""
			}
		}
		if u.Stopped == "" && u.LimitBytes > 0 && u.UsedUp+u.UsedDown >= u.LimitBytes {
			u.Stopped = "quota"
			a.notify("proxy", "代理用户流量用完", fmt.Sprintf("「%s」已用 %s，达到上限，已自动暂停", u.Name, humanBytes(u.UsedUp+u.UsedDown)), false)
		}
		if u.Stopped == "" && u.ExpireAt > 0 && u.ExpireAt <= now {
			u.Stopped = "expired"
			a.notify("proxy", "代理用户已到期", fmt.Sprintf("「%s」已到期，已自动暂停", u.Name), false)
		}
		if u.Stopped != was.Stopped || u.PeriodAt != was.PeriodAt {
			_, _ = a.db.Exec(`UPDATE proxy_users SET stopped=?, used_up=?, used_down=?, period_at=? WHERE id=?`, u.Stopped, u.UsedUp, u.UsedDown, u.PeriodAt, u.ID)
			changed = changed || u.Stopped != was.Stopped
		}
	}
	if changed {
		if err := a.reapplyProxy(); err != nil {
			log.Printf("proxy: reapply after limits: %v", err)
		}
	}
}

func humanBytes(b int64) string {
	f := float64(b)
	for _, u := range []string{"B", "KB", "MB", "GB", "TB"} {
		if f < 1024 || u == "TB" {
			if u == "B" {
				return fmt.Sprintf("%.0f %s", f, u)
			}
			return fmt.Sprintf("%.1f %s", f, u)
		}
		f /= 1024
	}
	return ""
}

// ---- dashboard ----

type visibility struct {
	nodes map[int64]*ProxyNode
	users map[int64]*ProxyUser
}

func (a *App) proxyVisibility(u *User) visibility {
	v := visibility{nodes: map[int64]*ProxyNode{}, users: map[int64]*ProxyUser{}}
	nodes, _ := a.proxyNodes()
	users, _ := a.proxyUsers()
	for _, n := range visibleNodes(u, nodes) {
		v.nodes[n.ID] = n
	}
	for _, p := range visibleUsers(u, users) {
		v.users[p.ID] = p
	}
	return v
}

// GET /api/proxy/live — current rates and who is online
func (a *App) handleProxyLive(w http.ResponseWriter, r *http.Request) {
	u := currentUser(r)
	var st proxyStatsResp
	if err := a.agent.Do("GET", "/v1/proxy/stats?after=9999999999", nil, &st); err != nil {
		jsonErr(w, 502, err.Error())
		return
	}
	v := a.proxyVisibility(u)
	type rate struct {
		Up   float64 `json:"up"`
		Down float64 `json:"down"`
	}
	nodes, users := map[int64]*rate{}, map[int64]*rate{}
	var total rate
	add := func(m map[int64]*rate, id int64, d [2]float64) {
		if m[id] == nil {
			m[id] = &rate{}
		}
		m[id].Up += d[0]
		m[id].Down += d[1]
	}
	// rates per node from the connection table (Xray's own counters lag behind spliced connections)
	for p, d := range st.Live.Ports {
		port, _ := strconv.Atoi(p)
		nid := int64(port - proxyPortBase)
		if v.nodes[nid] != nil {
			add(nodes, nid, d)
			total.Up += d[0]
			total.Down += d[1]
		}
	}
	// rates per user: client address -> the user(s) online from it
	ipUser := map[string]int64{}
	for email, ips := range st.Live.Online {
		if uid, _, ok := parseProxyEmail(email); ok {
			for ip := range ips {
				ipUser[ip] = uid
			}
		}
	}
	for ip, d := range st.Live.IPs {
		if uid := ipUser[ip]; uid != 0 && v.users[uid] != nil {
			add(users, uid, d)
		}
	}
	for email, d := range st.Live.Users { // users connected through the front have no address in conntrack
		uid, _, ok := parseProxyEmail(email)
		if ok && v.users[uid] != nil && users[uid] == nil {
			add(users, uid, d)
		}
	}
	type onlineIP struct {
		IP      string  `json:"ip"`
		Seen    int64   `json:"seen"`
		Country string  `json:"country"`
		City    string  `json:"city"`
		ASOrg   string  `json:"as_org"`
		Nodes   []int64 `json:"nodes"`
	}
	online := map[int64][]onlineIP{}
	byIP := map[string]map[int64][]int64{} // ip -> uid -> nodes
	for email, ips := range st.Live.Online {
		uid, nid, ok := parseProxyEmail(email)
		if !ok || v.users[uid] == nil {
			continue
		}
		for ip := range ips {
			if byIP[ip] == nil {
				byIP[ip] = map[int64][]int64{}
			}
			byIP[ip][uid] = append(byIP[ip][uid], nid)
		}
	}
	for uid, ips := range onlineByUser(st.Live.Online) {
		if v.users[uid] == nil {
			continue
		}
		for ip, seen := range ips {
			g := a.geo.LookupFast(ip)
			nodes := byIP[ip][uid]
			slices.Sort(nodes)
			online[uid] = append(online[uid], onlineIP{IP: ip, Seen: seen, Country: g.Country, City: g.City, ASOrg: g.ASOrg, Nodes: nodes})
		}
		sort.Slice(online[uid], func(i, j int) bool { return online[uid][i].Seen > online[uid][j].Seen })
	}
	writeJSON(w, 200, map[string]any{"ts": st.Live.TS, "total": total, "nodes": nodes, "users": users, "online": online})
}

// GET /api/proxy/stats?range=24h|7d|30d — hourly series per node, totals per user
func (a *App) handleProxyStats(w http.ResponseWriter, r *http.Request) {
	u := currentUser(r)
	v := a.proxyVisibility(u)
	hours := map[string]int64{"24h": 24, "7d": 168, "30d": 720}[r.URL.Query().Get("range")]
	if hours == 0 {
		hours = 24
	}
	now := time.Now().Unix()
	since := (now/3600 - hours + 1) * 3600
	rows, err := a.db.Query(`SELECT hour, user_id, node_id, up, down FROM proxy_traffic WHERE hour >= ?`, min(since, monthStart(now)))
	if err != nil {
		jsonErr(w, 500, err.Error())
		return
	}
	defer rows.Close()
	type point struct {
		Hour int64 `json:"hour"`
		Up   int64 `json:"up"`
		Down int64 `json:"down"`
	}
	series := map[int64]map[int64]*point{} // node -> hour -> point
	type tot struct {
		Up   int64 `json:"up"`
		Down int64 `json:"down"`
	}
	nodeTot, userTot := map[int64]*tot{}, map[int64]*tot{}
	var today, month, rng tot
	dayStart := dayStartOf(now)
	for rows.Next() {
		var p point
		var uid, nid int64
		if rows.Scan(&p.Hour, &uid, &nid, &p.Up, &p.Down) != nil {
			continue
		}
		if v.nodes[nid] != nil {
			if p.Hour >= since {
				if series[nid] == nil {
					series[nid] = map[int64]*point{}
				}
				if series[nid][p.Hour] == nil {
					series[nid][p.Hour] = &point{Hour: p.Hour}
				}
				series[nid][p.Hour].Up += p.Up
				series[nid][p.Hour].Down += p.Down
				if nodeTot[nid] == nil {
					nodeTot[nid] = &tot{}
				}
				nodeTot[nid].Up += p.Up
				nodeTot[nid].Down += p.Down
				rng.Up += p.Up
				rng.Down += p.Down
			}
			if p.Hour >= dayStart {
				today.Up += p.Up
				today.Down += p.Down
			}
			if p.Hour >= monthStart(now) {
				month.Up += p.Up
				month.Down += p.Down
			}
		}
		if v.users[uid] != nil && p.Hour >= since {
			if userTot[uid] == nil {
				userTot[uid] = &tot{}
			}
			userTot[uid].Up += p.Up
			userTot[uid].Down += p.Down
		}
	}
	out := map[int64][]point{}
	for nid, m := range series {
		var list []point
		for h := since; h <= now; h += 3600 {
			if p := m[h]; p != nil {
				list = append(list, *p)
			} else {
				list = append(list, point{Hour: h})
			}
		}
		out[nid] = list
	}
	writeJSON(w, 200, map[string]any{"since": since, "series": out, "nodes": nodeTot, "users": userTot, "today": today, "month": month, "range": rng})
}

func dayStartOf(ts int64) int64 {
	t := time.Unix(ts, 0)
	return time.Date(t.Year(), t.Month(), t.Day(), 0, 0, 0, 0, time.Local).Unix()
}

func monthStart(ts int64) int64 {
	t := time.Unix(ts, 0)
	return time.Date(t.Year(), t.Month(), 1, 0, 0, 0, 0, time.Local).Unix()
}

// GET /api/proxy/access?user=&node=&q=&before=&limit=
func (a *App) handleProxyAccess(w http.ResponseWriter, r *http.Request) {
	u := currentUser(r)
	v := a.proxyVisibility(u)
	q := r.URL.Query()
	where := []string{"1=1"}
	var args []any
	if id, _ := strconv.ParseInt(q.Get("user"), 10, 64); id > 0 {
		where, args = append(where, "user_id=?"), append(args, id)
	}
	if id, _ := strconv.ParseInt(q.Get("node"), 10, 64); id > 0 {
		where, args = append(where, "node_id=?"), append(args, id)
	}
	if before, _ := strconv.ParseInt(q.Get("before"), 10, 64); before > 0 {
		where, args = append(where, "id<?"), append(args, before)
	}
	if s := strings.TrimSpace(q.Get("q")); s != "" {
		where, args = append(where, "(dest LIKE ? OR ip LIKE ?)"), append(args, "%"+s+"%", "%"+s+"%")
	}
	if q.Get("status") == "rejected" {
		where = append(where, "status IN ('rejected','blocked')")
	}
	if u.Role != RoleSuper {
		ids := []string{"0"}
		for id := range v.users {
			ids = append(ids, strconv.FormatInt(id, 10))
		}
		where = append(where, "user_id IN ("+strings.Join(ids, ",")+")")
	}
	limit, _ := strconv.Atoi(q.Get("limit"))
	if limit <= 0 || limit > 500 {
		limit = 200
	}
	rows, err := a.db.Query(`SELECT id, ts, last, user_id, node_id, ip, dest, port, net, status, count FROM proxy_access WHERE `+
		strings.Join(where, " AND ")+` ORDER BY id DESC LIMIT `+strconv.Itoa(limit), args...)
	if err != nil {
		jsonErr(w, 500, err.Error())
		return
	}
	defer rows.Close()
	type rec struct {
		ID      int64  `json:"id"`
		TS      int64  `json:"ts"`
		Last    int64  `json:"last"`
		UserID  int64  `json:"user_id"`
		User    string `json:"user"`
		NodeID  int64  `json:"node_id"`
		Node    string `json:"node"`
		IP      string `json:"ip"`
		Country string `json:"country"`
		City    string `json:"city"`
		Dest    string `json:"dest"`
		Port    int    `json:"port"`
		Net     string `json:"net"`
		Status  string `json:"status"`
		Count   int    `json:"count"`
		Service string `json:"service,omitempty"`
	}
	out := []rec{}
	for rows.Next() {
		var x rec
		if rows.Scan(&x.ID, &x.TS, &x.Last, &x.UserID, &x.NodeID, &x.IP, &x.Dest, &x.Port, &x.Net, &x.Status, &x.Count) != nil {
			continue
		}
		if p := v.users[x.UserID]; p != nil {
			x.User = p.Name
		}
		if n := v.nodes[x.NodeID]; n != nil {
			x.Node = n.Name
		}
		g := a.geo.LookupFast(x.IP)
		x.Country, x.City = g.Country, g.City
		if a.rules != nil {
			if res, ok := a.rules.Domain(x.Dest); ok {
				x.Service = res.Service
			}
		}
		out = append(out, x)
	}
	writeJSON(w, 200, map[string]any{"items": out})
}

// GET /api/proxy/users/{id}/ips — every address the user connected from
func (a *App) handleProxyIPs(w http.ResponseWriter, r *http.Request) {
	u := currentUser(r)
	id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if _, err := a.puserFor(u, id); err != nil {
		jsonErr(w, 404, err.Error())
		return
	}
	rows, err := a.db.Query(`SELECT ip, first, last FROM proxy_ips WHERE user_id=? ORDER BY last DESC LIMIT 200`, id)
	if err != nil {
		jsonErr(w, 500, err.Error())
		return
	}
	defer rows.Close()
	type ipRec struct {
		IP      string `json:"ip"`
		First   int64  `json:"first"`
		Last    int64  `json:"last"`
		Country string `json:"country"`
		Region  string `json:"region"`
		City    string `json:"city"`
		ASN     uint   `json:"asn"`
		ASOrg   string `json:"as_org"`
	}
	out := []ipRec{}
	for rows.Next() {
		var x ipRec
		if rows.Scan(&x.IP, &x.First, &x.Last) == nil {
			g := a.geo.LookupFast(x.IP)
			x.Country, x.Region, x.City, x.ASN, x.ASOrg = g.Country, g.Region, g.City, g.ASN, g.ASOrg
			out = append(out, x)
		}
	}
	writeJSON(w, 200, map[string]any{"items": out})
}

// GET /api/proxy/log
func (a *App) handleProxyLog(w http.ResponseWriter, r *http.Request) {
	var out map[string]any
	if err := a.agent.Do("GET", "/v1/proxy/log?lines=200", nil, &out); err != nil {
		jsonErr(w, 502, err.Error())
		return
	}
	writeJSON(w, 200, out)
}
