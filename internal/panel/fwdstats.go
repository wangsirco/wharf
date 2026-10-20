package panel

import (
	"fmt"
	"net"
	"net/http"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Port forward usage: how much each forward carried, what runs behind it, and who
// connects — with each connection classed as scan / failed login / session / bulk
// transfer, and each remote IP given a verdict (scanner, brute force, real user…).
//
// Sources: flow_hour (hourly bytes + connection counts per device / remote / port, already
// collected for traffic stats) and fwd_conns (every finished inbound connection).

// Connection classes. Thresholds are deliberately simple and explained in the UI.
const (
	probeBytes = 600      // a SYN, a banner and a close: nothing was exchanged
	bulkBytes  = 10 << 20 // ≥ 10 MB in one connection
	longSecs   = 300      // ≥ 5 minutes
)

// sshFailSQL: a short, small SSH connection — what a failed password attempt looks like.
const classSQL = `
	SUM(CASE WHEN up+down < 600 OR down < 80 THEN 1 ELSE 0 END),
	SUM(CASE WHEN NOT (up+down < 600 OR down < 80) AND end-start < 60 AND up+down < 15000 THEN 1 ELSE 0 END),
	SUM(CASE WHEN up+down >= 10485760 THEN 1 ELSE 0 END),
	SUM(CASE WHEN end-start >= 300 THEN 1 ELSE 0 END)`

var scannerOrgs = []string{"censys", "shodan", "shadowserver", "palo alto", "recyber", "driftnet", "onyphe", "binaryedge", "stretchoid",
	"internet measurement", "alpha strike", "leakix", "criminal ip", "ai spera", "netsystemsresearch", "intrinsec", "cyber", "expanse",
	"bitsight", "rapid7", "project sonar", "academic", "university of michigan", "probe", "scan"}

func scannerOrg(org string) bool {
	o := strings.ToLower(org)
	for _, s := range scannerOrgs {
		if strings.Contains(o, s) {
			return true
		}
	}
	return false
}

type fwdTarget struct {
	f      *Forward
	keys   []string // flow_hour device keys (mac and/or ip:)
	lo, hi int
	protos []string
}

func (t fwdTarget) portSQL() (string, []any) {
	ph := strings.TrimSuffix(strings.Repeat("?,", len(t.protos)), ",")
	args := []any{t.lo, t.hi}
	for _, p := range t.protos {
		args = append(args, p)
	}
	return "port BETWEEN ? AND ? AND proto IN (" + ph + ")", args
}

// forwardTargets resolves the forwards the user may see to their LAN device keys and ports.
func (a *App) forwardTargets(u *User) (map[string]fwdTarget, error) {
	st, err := a.loadFwState()
	if err != nil {
		return nil, err
	}
	macByIP := map[string]string{}
	var devs []Device
	if a.agent.Do("GET", "/v1/devices", nil, &devs) == nil {
		for _, d := range devs {
			if d.IP != "" {
				macByIP[d.IP] = strings.ToLower(d.MAC)
			}
		}
	}
	out := map[string]fwdTarget{}
	for id := range st.fw {
		f := st.forward(id)
		if f == nil {
			continue
		}
		f.OwnerID = a.owner("firewall", id)
		if u.Role != RoleSuper && f.OwnerID != u.ID {
			continue
		}
		lo, hi, ok := portRange(f.LanPort)
		if !ok {
			continue
		}
		t := fwdTarget{f: f, lo: lo, hi: hi, protos: strings.Fields(f.Proto), keys: []string{"ip:" + f.LanIP}}
		for _, m := range []string{strings.ToLower(f.DeviceMAC), macByIP[f.LanIP]} {
			if m != "" && !slices.Contains(t.keys, m) {
				t.keys = append(t.keys, m)
			}
		}
		if len(t.protos) == 0 {
			t.protos = []string{"tcp", "udp"}
		}
		out[id] = t
	}
	return out, nil
}

func rangeSecs(r string) int64 {
	switch r {
	case "7d":
		return 7 * 86400
	case "30d":
		return 30 * 86400
	}
	return 86400
}

type fwdUsage struct {
	Up      int64 `json:"up"`
	Down    int64 `json:"down"`
	Conns   int64 `json:"conns"`
	Remotes int64 `json:"remotes"`
	Probes  int64 `json:"probes"`
	Live    int   `json:"live"`
}

// GET /api/forwards/usage?range=24h — per forward totals for the list.
func (a *App) handleForwardUsage(w http.ResponseWriter, r *http.Request) {
	targets, err := a.forwardTargets(currentUser(r))
	if err != nil {
		jsonErr(w, 502, err.Error())
		return
	}
	since := time.Now().Unix() - rangeSecs(r.URL.Query().Get("range"))
	type row struct {
		mac, proto      string
		port            int
		up, down, conns int64
	}
	var rows []row
	if q, err := a.db.Query(`SELECT mac, port, proto, SUM(up), SUM(down), SUM(conns) FROM flow_hour WHERE inbound=1 AND hour >= ? GROUP BY mac, port, proto`,
		since/3600*3600); err == nil {
		for q.Next() {
			var x row
			if q.Scan(&x.mac, &x.port, &x.proto, &x.up, &x.down, &x.conns) == nil {
				rows = append(rows, x)
			}
		}
		q.Close()
	}
	type crow struct {
		ip, proto              string
		port                   int
		remotes, probes, conns int64
	}
	var crows []crow
	if q, err := a.db.Query(`SELECT ip, port, proto, COUNT(DISTINCT remote), SUM(CASE WHEN up+down < 600 OR down < 80 THEN 1 ELSE 0 END), COUNT(*)
		FROM fwd_conns WHERE end >= ? GROUP BY ip, port, proto`, since); err == nil {
		for q.Next() {
			var x crow
			if q.Scan(&x.ip, &x.port, &x.proto, &x.remotes, &x.probes, &x.conns) == nil {
				crows = append(crows, x)
			}
		}
		q.Close()
	}
	var live []struct {
		IP    string `json:"ip"`
		Port  int    `json:"port"`
		Proto string `json:"proto"`
	}
	_ = a.agent.Do("GET", "/v1/forward-live", nil, &live)
	out := map[string]fwdUsage{}
	for id, t := range targets {
		var u fwdUsage
		for _, x := range rows {
			if slices.Contains(t.keys, x.mac) && x.port >= t.lo && x.port <= t.hi && slices.Contains(t.protos, x.proto) {
				u.Up, u.Down, u.Conns = u.Up+x.up, u.Down+x.down, u.Conns+x.conns
			}
		}
		for _, x := range crows {
			if x.ip == t.f.LanIP && x.port >= t.lo && x.port <= t.hi && slices.Contains(t.protos, x.proto) {
				u.Remotes += x.remotes
				u.Probes += x.probes
			}
		}
		for _, l := range live {
			if l.IP == t.f.LanIP && l.Port >= t.lo && l.Port <= t.hi && slices.Contains(t.protos, l.Proto) {
				u.Live++
			}
		}
		out[id] = u
	}
	writeJSON(w, 200, out)
}

// ---- service fingerprint cache ----

type svcInfo struct {
	Service string `json:"service"`
	Detail  string `json:"detail,omitempty"`
	TLS     bool   `json:"tls,omitempty"`
	CertCN  string `json:"cert_cn,omitempty"`
	Open    bool   `json:"open"`
	Error   string `json:"error,omitempty"`
	Checked int64  `json:"checked"`
}

var (
	svcMu    sync.Mutex
	svcCache = map[string]svcInfo{}
)

var udpServices = map[int]string{51820: "WireGuard VPN", 1194: "OpenVPN", 500: "IPsec VPN", 4500: "IPsec VPN", 3478: "STUN / TURN", 53: "DNS",
	27015: "Steam 游戏服务器", 19132: "Minecraft 基岩版", 25565: "Minecraft", 9987: "TeamSpeak", 41641: "Tailscale", 443: "QUIC / HTTP3", 123: "NTP"}

func (a *App) fingerprint(ip string, port int, proto []string, refresh bool) svcInfo {
	if !slices.Contains(proto, "tcp") {
		s := svcInfo{Service: udpServices[port], Open: true, Checked: time.Now().Unix()}
		if s.Service == "" {
			s.Service, s.Detail = "UDP 服务", "UDP 无法主动识别，只能按端口推测"
		}
		return s
	}
	key := ip + ":" + strconv.Itoa(port)
	svcMu.Lock()
	c, ok := svcCache[key]
	svcMu.Unlock()
	if ok && !refresh && time.Now().Unix()-c.Checked < 1800 {
		return c
	}
	var s svcInfo
	if err := a.agent.Do("POST", "/v1/diag", map[string]any{"tool": "fingerprint", "target": ip, "port": port}, &s); err != nil {
		s.Error = agentMsg(err)
	}
	s.Checked = time.Now().Unix()
	svcMu.Lock()
	svcCache[key] = s
	svcMu.Unlock()
	return s
}

// ---- detail ----

type remoteStat struct {
	IP       string  `json:"ip"`
	Conns    int64   `json:"conns"`
	Up       int64   `json:"up"`
	Down     int64   `json:"down"`
	Secs     int64   `json:"secs"`
	First    int64   `json:"first"`
	Last     int64   `json:"last"`
	Probes   int64   `json:"probes"`
	Short    int64   `json:"short"` // short + small (failed logins for SSH)
	Bulk     int64   `json:"bulk"`
	Long     int64   `json:"long"`
	Country  string  `json:"country,omitempty"`
	CName    string  `json:"country_name,omitempty"`
	City     string  `json:"city,omitempty"`
	ASN      uint    `json:"asn,omitempty"`
	ASOrg    string  `json:"as_org,omitempty"`
	Verdict  string  `json:"verdict"` // scanner | brute | probe | user | bulk | light | lan
	Live     int     `json:"live,omitempty"`
	ProbePct float64 `json:"probe_pct"`
}

type connRow struct {
	Start  int64  `json:"start"`
	End    int64  `json:"end"`
	Remote string `json:"remote"`
	RPort  int    `json:"rport"`
	Port   int    `json:"port"`
	Proto  string `json:"proto"`
	Up     int64  `json:"up"`
	Down   int64  `json:"down"`
	Class  string `json:"class"` // probe | short | session | long | bulk | live
	CC     string `json:"country,omitempty"`
}

type insight struct {
	Level  string `json:"level"`
	Title  string `json:"title"`
	Detail string `json:"detail"`
}

func connClass(up, down, secs int64) string {
	switch {
	case up+down < probeBytes || down < 80:
		return "probe"
	case up+down >= bulkBytes:
		return "bulk"
	case secs >= longSecs:
		return "long"
	case secs < 60 && up+down < 15000:
		return "short"
	}
	return "session"
}

// GET /api/forwards/{id}/stats?range=24h|7d|30d[&refresh=1]
func (a *App) handleForwardStats(w http.ResponseWriter, r *http.Request) {
	targets, err := a.forwardTargets(currentUser(r))
	if err != nil {
		jsonErr(w, 502, err.Error())
		return
	}
	t, ok := targets[r.PathValue("id")]
	if !ok {
		jsonErr(w, 404, "端口转发不存在，或你没有权限查看")
		return
	}
	rng := r.URL.Query().Get("range")
	secs := rangeSecs(rng)
	now := time.Now().Unix()
	since := now - secs
	f := t.f
	svc := a.fingerprint(f.LanIP, t.lo, t.protos, r.URL.Query().Get("refresh") == "1")
	isSSH := svc.Service == "SSH"

	// usage over time (hourly; daily for 30 days)
	bucket := int64(3600)
	if secs > 7*86400 {
		bucket = 86400
	}
	tz := int64(0)
	if bucket == 86400 { // calendar days in local time
		_, off := time.Now().Zone()
		tz = int64(off)
	}
	pw, pargs := t.portSQL()
	keyPH := strings.TrimSuffix(strings.Repeat("?,", len(t.keys)), ",")
	args := []any{tz, bucket, bucket, tz}
	for _, k := range t.keys {
		args = append(args, k)
	}
	args = append(args, since/3600*3600)
	args = append(args, pargs...)
	type point struct {
		T     int64 `json:"t"`
		Up    int64 `json:"up"`
		Down  int64 `json:"down"`
		Conns int64 `json:"conns"`
	}
	series := map[int64]*point{}
	var total point
	if q, err := a.db.Query(`SELECT (hour+?)/?*?-?, SUM(up), SUM(down), SUM(conns) FROM flow_hour WHERE inbound=1 AND mac IN (`+keyPH+`) AND hour >= ? AND `+pw+` GROUP BY 1`, args...); err == nil {
		for q.Next() {
			var p point
			if q.Scan(&p.T, &p.Up, &p.Down, &p.Conns) == nil {
				series[p.T] = &p
				total.Up, total.Down, total.Conns = total.Up+p.Up, total.Down+p.Down, total.Conns+p.Conns
			}
		}
		q.Close()
	}
	points := []point{}
	for b := (since+tz)/bucket*bucket - tz; b <= now; b += bucket {
		if p := series[b]; p != nil {
			points = append(points, *p)
		} else {
			points = append(points, point{T: b})
		}
	}

	// who connected
	cargs := append([]any{f.LanIP, since}, pargs...)
	remotes := map[string]*remoteStat{}
	var order []*remoteStat
	var distinct int64
	_ = a.db.QueryRow(`SELECT COUNT(DISTINCT remote) FROM fwd_conns WHERE ip=? AND end >= ? AND `+pw, cargs...).Scan(&distinct)
	if q, err := a.db.Query(`SELECT remote, COUNT(*), SUM(up), SUM(down), SUM(end-start), MIN(start), MAX(end), `+classSQL+`
		FROM fwd_conns WHERE ip=? AND end >= ? AND `+pw+` GROUP BY remote ORDER BY COUNT(*) DESC LIMIT 300`, cargs...); err == nil {
		for q.Next() {
			var s remoteStat
			if q.Scan(&s.IP, &s.Conns, &s.Up, &s.Down, &s.Secs, &s.First, &s.Last, &s.Probes, &s.Short, &s.Bulk, &s.Long) == nil {
				remotes[s.IP] = &s
				order = append(order, &s)
			}
		}
		q.Close()
	}
	// connections still open
	var live []struct {
		Start  int64  `json:"start"`
		IP     string `json:"ip"`
		Port   int    `json:"port"`
		Proto  string `json:"proto"`
		Remote string `json:"remote"`
		RPort  int    `json:"rport"`
		Up     int64  `json:"up"`
		Down   int64  `json:"down"`
	}
	_ = a.agent.Do("GET", "/v1/forward-live", nil, &live)
	var liveRows []connRow
	for _, l := range live {
		if l.IP != f.LanIP || l.Port < t.lo || l.Port > t.hi || !slices.Contains(t.protos, l.Proto) {
			continue
		}
		liveRows = append(liveRows, connRow{Start: l.Start, End: now, Remote: l.Remote, RPort: l.RPort, Port: l.Port, Proto: l.Proto, Up: l.Up, Down: l.Down, Class: "live"})
		s := remotes[l.Remote]
		if s == nil {
			s = &remoteStat{IP: l.Remote, First: l.Start, Last: now}
			remotes[l.Remote] = s
			order = append(order, s)
			distinct++
		}
		s.Live++
		s.Up, s.Down, s.Last = s.Up+l.Up, s.Down+l.Down, now // open connections count too
	}
	var probes, shorts, conns int64
	countries := map[string]int64{}
	var scanners, brutes []string
	for _, s := range order {
		probes, shorts, conns = probes+s.Probes, shorts+s.Short, conns+s.Conns
		g := a.geo.LookupFast(s.IP)
		s.Country, s.City, s.ASN, s.ASOrg = g.Country, g.City, g.ASN, g.ASOrg
		if g.Country != "" {
			s.CName = a.countryName(g.Country)
			countries[s.CName] += s.Conns
		}
		if s.Conns > 0 {
			s.ProbePct = round1(100 * float64(s.Probes) / float64(s.Conns))
		}
		switch {
		case isPrivateIP(s.IP):
			s.Verdict = "lan"
		case scannerOrg(s.ASOrg) && s.Bulk == 0 && s.Long == 0:
			s.Verdict = "scanner"
			scanners = append(scanners, s.IP)
		case isSSH && s.Short >= 8 && s.Long == 0 && s.Bulk == 0:
			s.Verdict = "brute"
			brutes = append(brutes, s.IP)
		case s.Bulk > 0:
			s.Verdict = "bulk"
		case s.Long > 0 || s.Live > 0 || (s.Conns > 0 && s.Probes < s.Conns && s.Down > 50000):
			s.Verdict = "user"
		case s.Conns > 0 && s.Probes == s.Conns:
			s.Verdict = "probe"
		default:
			s.Verdict = "light"
		}
	}
	rank := map[string]int{"user": 0, "bulk": 1, "brute": 2, "light": 3, "probe": 4, "scanner": 5, "lan": 6}
	sort.SliceStable(order, func(i, j int) bool {
		if order[i].Live != order[j].Live {
			return order[i].Live > order[j].Live
		}
		if rank[order[i].Verdict] != rank[order[j].Verdict] {
			return rank[order[i].Verdict] < rank[order[j].Verdict]
		}
		return order[i].Up+order[i].Down > order[j].Up+order[j].Down
	})
	if len(order) > 200 {
		order = order[:200]
	}

	// latest connections, newest first
	var recent []connRow
	if q, err := a.db.Query(`SELECT start, end, remote, rport, port, proto, up, down FROM fwd_conns WHERE ip=? AND end >= ? AND `+pw+` ORDER BY end DESC LIMIT 150`, cargs...); err == nil {
		for q.Next() {
			var c connRow
			if q.Scan(&c.Start, &c.End, &c.Remote, &c.RPort, &c.Port, &c.Proto, &c.Up, &c.Down) == nil {
				c.Class = connClass(c.Up, c.Down, c.End-c.Start)
				if s := remotes[c.Remote]; s != nil {
					c.CC = s.Country
				}
				recent = append(recent, c)
			}
		}
		q.Close()
	}
	sort.Slice(liveRows, func(i, j int) bool { return liveRows[i].Up+liveRows[i].Down > liveRows[j].Up+liveRows[j].Down })
	for i := range liveRows {
		if s := remotes[liveRows[i].Remote]; s != nil {
			liveRows[i].CC = s.Country
		}
	}

	// plain-language findings
	var ins []insight
	period := map[string]string{"7d": "7 天", "30d": "30 天"}[rng]
	if period == "" {
		period = "24 小时"
	}
	if conns > 0 {
		pct := 100 * float64(probes) / float64(conns)
		lvl := "info"
		if pct >= 80 {
			lvl = "warn"
		}
		ins = append(ins, insight{lvl, fmt.Sprintf("过去 %s：%d 次连接，来自 %d 个 IP", period, conns, distinct),
			fmt.Sprintf("其中 %.0f%% 是扫描 / 探测（连上就断，没有交换数据）。暴露在公网的端口都会被全网扫描器持续敲门，这是常态；需要关注的是下面的暴力破解和陌生的长时间会话。", pct)})
	} else if total.Conns == 0 && len(liveRows) == 0 {
		ins = append(ins, insight{"info", "这段时间没有人连过这个转发", "如果它已经不用了，可以停用或删除，减少暴露面。"})
	}
	var cf int
	for _, s := range order {
		if s.ASN == 13335 {
			cf++
		}
	}
	if len(order) > 0 && cf*10 >= len(order)*8 {
		ins = append(ins, insight{"info", "这个转发前面是 Cloudflare 代理",
			"连进来的几乎都是 Cloudflare 的节点 IP，不是真实访客；真实访客 IP 要在网站日志里看（CF-Connecting-IP 头）。可以把来源限制为 Cloudflare 的 IP 段，防止别人绕过 Cloudflare 直连。"})
	}
	if len(brutes) > 0 {
		ins = append(ins, insight{"error", fmt.Sprintf("疑似 SSH 暴力破解：%d 个 IP", len(brutes)),
			fmt.Sprintf("这些 IP 反复建立短连接（像在一次次试密码），例如 %s。建议：只允许密钥登录、关闭密码登录，并在转发里限制来源地区或加入黑名单。", strings.Join(brutes[:min(3, len(brutes))], "、"))})
	}
	if len(scanners) > 0 {
		ins = append(ins, insight{"info", fmt.Sprintf("%d 个 IP 属于已知的网络扫描机构", len(scanners)), "如 Censys、Shodan、Shadowserver 等：它们给全网做安全测绘，本身无害，但说明这个端口已被公开收录。"})
	}
	risky := map[string]string{"Telnet": "Telnet 是明文协议，账号密码会被直接看到，强烈建议关闭这个转发",
		"Redis": "Redis 暴露在公网极易被入侵（常见挖矿木马入口）", "MySQL": "数据库不应直接暴露在公网，建议改用 VPN 访问",
		"RDP": "远程桌面是勒索病毒的主要入口，建议改用 VPN 或限制来源", "VNC": "VNC 加密和认证都很弱，建议改用 VPN 或限制来源",
		"SSH": "SSH 暴露在公网会被持续爆破：请确认已关闭密码登录、只用密钥",
		"FTP": "FTP 是明文协议，账号密码和文件都可被窃听，建议改用 SFTP 或限制来源", "FTP / SMTP": "明文协议，账号密码可被窃听，建议限制来源",
		"POP3": "明文收信协议，建议改用加密端口", "IMAP": "明文收信协议，建议改用加密端口", "HTTP（网页）": "明文网页：登录密码会以明文传输，建议改用 HTTPS"}
	if msg, ok := risky[svc.Service]; ok {
		lvl := "warn"
		if f.Mode == "restrict" {
			lvl = "info"
			msg += "（已限制来源，风险较低）"
		}
		ins = append(ins, insight{lvl, "暴露的服务：" + svc.Service, msg})
	}
	if svc.Error != "" {
		ins = append(ins, insight{"warn", "转发目标没有响应", svc.Error})
	}
	type cc struct {
		Name  string `json:"name"`
		Conns int64  `json:"conns"`
	}
	var cl []cc
	for k, v := range countries {
		cl = append(cl, cc{k, v})
	}
	sort.Slice(cl, func(i, j int) bool { return cl[i].Conns > cl[j].Conns })
	if len(cl) > 12 {
		cl = cl[:12]
	}
	if liveRows == nil {
		liveRows = []connRow{}
	}
	writeJSON(w, 200, map[string]any{
		"forward": f, "service": svc, "range": rng, "bucket": bucket, "points": points,
		"total":   map[string]any{"up": total.Up, "down": total.Down, "conns": total.Conns, "remotes": distinct, "probes": probes, "short": shorts},
		"remotes": order, "recent": recent, "live": liveRows, "countries": cl, "insights": ins,
		"thresholds": map[string]any{"probe_bytes": probeBytes, "bulk_bytes": bulkBytes, "long_secs": longSecs},
	})
}

func isPrivateIP(s string) bool {
	ip := net.ParseIP(s)
	return ip != nil && (ip.IsPrivate() || ip.IsLoopback())
}
