package panel

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/netip"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/wangsirco/wharf/internal/rules"
)

// ---- identification (rules + geo, cached) ----

type ident struct {
	rules.Result
	Country   string `json:"country"`
	ASOrg     string `json:"as_org"`
	Guess     bool   `json:"guess"`     // named by our own probe (模拟判定), not by a rule
	Uncertain bool   `json:"uncertain"` // shown greyed out under 其他
}

type identCache struct {
	mu sync.Mutex
	m  map[string]ident
}

func (a *App) identify(domain, remote string) ident {
	key := domain + "|" + remote
	if v, ok := a.idc.get(key); ok {
		return v
	}
	var out ident
	g := a.geo.LookupFast(remote) // no timezone polygon search: only country / ASN are needed
	out.Country, out.ASOrg = g.Country, g.ASOrg
	if m := a.rules; m != nil {
		ip, _ := netip.ParseAddr(remote)
		out.Result = m.Identify(domain, ip, g.ASN, g.ASOrg)
	}
	switch out.By {
	case "domain", "keyword", "ip", "asn":
	default:
		a.nameUnknown(&out, domain, remote, g.ASOrg)
	}
	a.idc.put(key, out)
	return out
}

// nameUnknown names a target no rule matched, in order of confidence:
//  1. a probe matched it to a known service via its certificate / reverse DNS
//  2. a readable name: the page title or the certificate's organisation
//  3. a guess: "可能是 <cert name / rDNS / network operator>"  (uncertain)
//  4. the raw domain or IP                                     (uncertain)
//
// Everything except (1) goes to 其他.
func (a *App) nameUnknown(out *ident, domain, remote, asOrg string) {
	out.Category, out.Sub, out.By = "其他", "其他", ""
	if remote != "" {
		if p := a.bestProbe(remote); p != nil && p.Status == "ok" {
			var d probeDetail
			_ = json.Unmarshal([]byte(p.Detail), &d)
			out.Guess, out.By = true, "probe"
			switch {
			case d.Service != "":
				out.Service, out.Category, out.Sub = d.Service, d.Category, d.Category
				if a.rules == nil {
					return
				}
				if r, ok := a.rules.Domain(strings.TrimPrefix(firstNonEmpty(d.CertCN, firstOf(d.CertSANs)), "*.")); ok {
					out.Sub, out.Company = r.Sub, r.Company
				}
				return
			case usefulTitle(d.Title): // older probes may hold error-page titles
				out.Service = d.Title
				return
			case d.CertOrg != "":
				out.Service = d.CertOrg
				return
			}
			if n := firstNonEmpty(strings.TrimPrefix(d.CertCN, "*."), strings.TrimPrefix(firstOf(d.CertSANs), "*."), firstOf(d.RDNS)); n != "" {
				out.Service, out.Uncertain = "可能是 "+n, true
				return
			}
		}
	}
	out.Uncertain = true
	switch {
	case domain != "":
		out.Service = domain
	case asOrg != "":
		out.Service = "可能是 " + asOrg + " 的服务器"
	default:
		out.Service = remote
	}
}

func firstNonEmpty(v ...string) string {
	for _, s := range v {
		if s != "" {
			return s
		}
	}
	return ""
}

func firstOf(v []string) string {
	if len(v) > 0 {
		return v[0]
	}
	return ""
}

func (c *identCache) get(k string) (ident, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	v, ok := c.m[k]
	return v, ok
}

func (c *identCache) put(k string, v ident) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.m == nil || len(c.m) > 200000 {
		c.m = map[string]ident{}
	}
	c.m[k] = v
}

func (c *identCache) reset() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.m = nil
}

// ---- range parsing ----

// timeRange reads from/to (unix) or range=today|7d|30d|90d; capped at 90 days.
func timeRange(r *http.Request) (int64, int64) {
	q := r.URL.Query()
	now := time.Now()
	to := now.Unix()
	var from int64
	switch q.Get("range") {
	case "today":
		y, m, d := now.Date()
		from = time.Date(y, m, d, 0, 0, 0, 0, now.Location()).Unix()
	case "1h":
		from = to - 3600
	case "24h":
		from = to - 86400
	case "30d":
		from = to - 30*86400
	case "90d":
		from = to - 90*86400
	default:
		from = to - 7*86400
	}
	if v, err := strconv.ParseInt(q.Get("from"), 10, 64); err == nil && v > 0 {
		from = v
	}
	if v, err := strconv.ParseInt(q.Get("to"), 10, 64); err == nil && v > 0 {
		to = v
	}
	if to-from > 90*86400 {
		from = to - 90*86400
	}
	if from >= to {
		from = to - 3600
	}
	return from, to
}

// ---- device traffic (volume over time) ----

type point struct {
	T    int64 `json:"t"`
	Up   int64 `json:"up"`
	Down int64 `json:"down"`
}

// GET /api/devices/{mac}/traffic?range=|from=&to=
func (a *App) handleDeviceTraffic(w http.ResponseWriter, r *http.Request) {
	mac := r.PathValue("mac")
	from, to := timeRange(r)
	span := to - from
	loc := time.Local

	var series []point
	var step int64
	if span <= 6*3600 {
		step = 60
		rows, err := a.db.Query(`SELECT minute, up, down FROM traffic_min WHERE mac=? AND minute>=? AND minute<? ORDER BY minute`, mac, from, to)
		if err != nil {
			jsonErr(w, 500, err.Error())
			return
		}
		for rows.Next() {
			var p point
			_ = rows.Scan(&p.T, &p.Up, &p.Down)
			series = append(series, p)
		}
		rows.Close()
	}

	// hourly rows feed totals, heatmap and longer series
	rows, err := a.db.Query(`SELECT hour, up, down FROM traffic_hour WHERE mac=? AND hour>=? AND hour<? ORDER BY hour`, mac, from-from%3600, to)
	if err != nil {
		jsonErr(w, 500, err.Error())
		return
	}
	var heat [7][24]int64
	var byHour [24]int64
	var totalUp, totalDown int64
	daily := map[int64]*point{}
	var hourly []point
	for rows.Next() {
		var p point
		_ = rows.Scan(&p.T, &p.Up, &p.Down)
		totalUp += p.Up
		totalDown += p.Down
		t := time.Unix(p.T, 0).In(loc)
		heat[int(t.Weekday())][t.Hour()] += p.Up + p.Down
		byHour[t.Hour()] += p.Up + p.Down
		hourly = append(hourly, p)
		day := time.Date(t.Year(), t.Month(), t.Day(), 0, 0, 0, 0, loc).Unix()
		if daily[day] == nil {
			daily[day] = &point{T: day}
		}
		daily[day].Up += p.Up
		daily[day].Down += p.Down
	}
	rows.Close()
	if step == 0 {
		if span <= 8*86400 {
			step, series = 3600, hourly
		} else {
			step = 86400
			for _, p := range daily {
				series = append(series, *p)
			}
			sort.Slice(series, func(i, j int) bool { return series[i].T < series[j].T })
		}
	}
	peak := 0
	for h := range byHour {
		if byHour[h] > byHour[peak] {
			peak = h
		}
	}
	svcs, cats := a.flowAgg(mac, from, to, "", "", 12)
	writeJSON(w, 200, map[string]any{
		"from": from, "to": to, "step": step, "series": series,
		"up": totalUp, "down": totalDown, "heatmap": heat, "by_hour": byHour, "peak_hour": peak,
		"services": svcs, "categories": cats,
	})
}

// ---- breakdown by service / category / company / country ----

type agg struct {
	Name      string `json:"name"`
	Category  string `json:"category,omitempty"`
	Sub       string `json:"sub,omitempty"`
	Company   string `json:"company,omitempty"`
	Guess     bool   `json:"guess,omitempty"`
	Uncertain bool   `json:"uncertain,omitempty"`
	Bytes     int64  `json:"bytes"`
	Up        int64  `json:"up"`
	Down      int64  `json:"down"`
	Requests  int64  `json:"requests"`
	Conns     int64  `json:"conns"`
}

type aggMap map[string]*agg

func (m aggMap) add(key string, init func() *agg, f func(*agg)) {
	x := m[key]
	if x == nil {
		x = init()
		m[key] = x
	}
	f(x)
}

func (m aggMap) top(n int, by func(*agg) int64) []*agg {
	out := make([]*agg, 0, len(m))
	for _, v := range m {
		out = append(out, v)
	}
	sort.Slice(out, func(i, j int) bool { return by(out[i]) > by(out[j]) })
	if n > 0 && len(out) > n {
		out = out[:n]
	}
	return out
}

func byBytes(a *agg) int64    { return a.Bytes }
func byRequests(a *agg) int64 { return a.Requests*1_000_000_000 + a.Bytes }

// flowBreakdown aggregates flow bytes by service for a device (mac="" = all devices).
func (a *App) flowBreakdown(mac string, from, to int64, category, company string, n int) []*agg {
	svcs, _ := a.flowAgg(mac, from, to, category, company, n)
	return svcs
}

// flowAgg aggregates outbound flow bytes for a device (mac="" = all) by service and by category.
func (a *App) flowAgg(mac string, from, to int64, category, company string, n int) (services, categories []*agg) {
	q := `SELECT domain, remote, SUM(up), SUM(down), SUM(conns) FROM flow_hour WHERE hour>=? AND hour<? AND inbound=0`
	args := []any{from - from%3600, to}
	if mac != "" {
		q += ` AND mac=?`
		args = append(args, mac)
	}
	rows, err := a.db.Query(q+` GROUP BY domain, remote`, args...)
	if err != nil {
		return nil, nil
	}
	defer rows.Close()
	m, cats := aggMap{}, aggMap{}
	for rows.Next() {
		var domain, remote string
		var up, down, conns int64
		_ = rows.Scan(&domain, &remote, &up, &down, &conns)
		id := a.identify(domain, remote)
		if (category != "" && id.Category != category) || (company != "" && id.Company != company) {
			continue
		}
		name := svcName(id)
		add := func(x *agg) {
			x.Up += up
			x.Down += down
			x.Bytes += up + down
			x.Conns += conns
		}
		m.add(name, func() *agg { return id.newAgg(name) }, add)
		cats.add(id.Category, func() *agg { return &agg{Name: id.Category} }, add)
	}
	return m.top(n, byBytes), cats.top(0, byBytes)
}

type domainRow struct {
	Domain    string    `json:"domain"`
	Service   string    `json:"service"`
	Category  string    `json:"category"`
	Sub       string    `json:"sub"`
	Guess     bool      `json:"guess"`
	Uncertain bool      `json:"uncertain"`
	Company   string    `json:"company"`
	Requests  int64     `json:"requests"`
	Blocked   int64     `json:"blocked"`
	Bytes     int64     `json:"bytes"`
	LastSeen  int64     `json:"last_seen"`
	NextDNS   *ndDomain `json:"nextdns,omitempty"`
}

type remoteRow struct {
	Sub       string `json:"sub"`
	Guess     bool   `json:"guess"`
	Uncertain bool   `json:"uncertain"`
	IP        string `json:"ip"`
	Port      int    `json:"port"`
	Proto     string `json:"proto"`
	Inbound   bool   `json:"inbound"`
	Service   string `json:"service"`
	Category  string `json:"category"`
	Company   string `json:"company"`
	By        string `json:"by"`
	Country   string `json:"country"`
	ASOrg     string `json:"as_org"`
	Bytes     int64  `json:"bytes"`
	Conns     int64  `json:"conns"`
	Probe     *Probe `json:"probe,omitempty"`
}

// GET /api/devices/{mac}/profile?range=|from&to&category=&company=
func (a *App) handleDeviceProfile(w http.ResponseWriter, r *http.Request) {
	mac := r.PathValue("mac")
	from, to := timeRange(r)
	fcat, fco := r.URL.Query().Get("category"), r.URL.Query().Get("company")
	h0 := from - from%3600

	cats, subs, services, companies, countries := aggMap{}, aggMap{}, aggMap{}, aggMap{}, aggMap{}
	domains := map[string]*domainRow{}
	remotes := map[string]*remoteRow{}
	var reqByHour [24]int64
	var totalReq, totalBlocked, totalBytes int64

	// DNS lookups: what the device asked for (works even for encrypted traffic)
	rows, err := a.db.Query(`SELECT hour, domain, count, blocked FROM dns_hour WHERE mac=? AND hour>=? AND hour<?`, mac, h0, to)
	if err != nil {
		jsonErr(w, 500, err.Error())
		return
	}
	for rows.Next() {
		var hour, cnt, blk int64
		var d string
		_ = rows.Scan(&hour, &d, &cnt, &blk)
		id := a.identify(d, "")
		if !id.matches(fcat, fco) {
			continue
		}
		totalReq += cnt
		totalBlocked += blk
		reqByHour[time.Unix(hour, 0).Hour()] += cnt
		dr := domains[d]
		if dr == nil {
			dr = &domainRow{Domain: d, Service: id.Service, Category: id.Category, Sub: id.Sub, Guess: id.Guess, Uncertain: id.Uncertain, Company: id.Company}
			domains[d] = dr
		}
		dr.Requests += cnt
		dr.Blocked += blk
		if hour > dr.LastSeen {
			dr.LastSeen = hour
		}
		name := svcName(id)
		cats.add(id.Category, func() *agg { return &agg{Name: id.Category} }, func(x *agg) { x.Requests += cnt })
		subs.add(id.Category+"/"+id.Sub, func() *agg { return &agg{Name: id.Sub, Category: id.Category} }, func(x *agg) { x.Requests += cnt })
		services.add(name, func() *agg { return id.newAgg(name) }, func(x *agg) { x.Requests += cnt })
		if id.Company != "" {
			companies.add(id.Company, func() *agg { return &agg{Name: id.Company} }, func(x *agg) { x.Requests += cnt })
		}
	}
	rows.Close()

	// Flows: where the bytes went
	rows, err = a.db.Query(`SELECT hour, remote, port, proto, inbound, domain, up, down, conns FROM flow_hour WHERE mac=? AND hour>=? AND hour<?`, mac, h0, to)
	if err != nil {
		jsonErr(w, 500, err.Error())
		return
	}
	for rows.Next() {
		var hour, up, down, conns int64
		var remote, proto, d string
		var port, inbound int
		_ = rows.Scan(&hour, &remote, &port, &proto, &inbound, &d, &up, &down, &conns)
		id := a.identify(d, remote)
		if !id.matches(fcat, fco) {
			continue
		}
		b := up + down
		totalBytes += b
		name := svcName(id)
		if inbound == 0 {
			cats.add(id.Category, func() *agg { return &agg{Name: id.Category} }, func(x *agg) { x.Bytes += b; x.Up += up; x.Down += down; x.Conns += conns })
			subs.add(id.Category+"/"+id.Sub, func() *agg { return &agg{Name: id.Sub, Category: id.Category} }, func(x *agg) { x.Bytes += b; x.Conns += conns })
			services.add(name, func() *agg { return id.newAgg(name) }, func(x *agg) {
				x.Bytes += b
				x.Up += up
				x.Down += down
				x.Conns += conns
			})
			if id.Company != "" {
				companies.add(id.Company, func() *agg { return &agg{Name: id.Company} }, func(x *agg) { x.Bytes += b; x.Conns += conns })
			}
		}
		if id.Country != "" {
			countries.add(id.Country, func() *agg { return &agg{Name: a.countryName(id.Country)} }, func(x *agg) { x.Bytes += b; x.Conns += conns })
		}
		if d != "" {
			if dr := domains[d]; dr != nil {
				dr.Bytes += b
			} else {
				domains[d] = &domainRow{Domain: d, Service: id.Service, Category: id.Category, Sub: id.Sub, Guess: id.Guess, Uncertain: id.Uncertain,
					Company: id.Company, Bytes: b, LastSeen: hour}
			}
		}
		key := fmt.Sprintf("%s|%d|%s|%d", remote, port, proto, inbound)
		rr := remotes[key]
		if rr == nil {
			rr = &remoteRow{Sub: id.Sub, Guess: id.Guess, Uncertain: id.Uncertain, IP: remote, Port: port, Proto: proto, Inbound: inbound == 1, Service: id.Service, Category: id.Category,
				Company: id.Company, By: id.By, Country: id.Country, ASOrg: id.ASOrg}
			remotes[key] = rr
		}
		rr.Bytes += b
		rr.Conns += conns
	}
	rows.Close()

	dl := make([]*domainRow, 0, len(domains))
	for _, v := range domains {
		dl = append(dl, v)
	}
	sort.Slice(dl, func(i, j int) bool {
		if dl[i].Requests != dl[j].Requests {
			return dl[i].Requests > dl[j].Requests
		}
		return dl[i].Bytes > dl[j].Bytes
	})
	if len(dl) > 300 {
		dl = dl[:300]
	}
	for _, d := range dl {
		d.NextDNS = a.nextdnsDomain(d.Domain)
	}
	rl := make([]*remoteRow, 0, len(remotes))
	for _, v := range remotes {
		rl = append(rl, v)
	}
	sort.Slice(rl, func(i, j int) bool { return rl[i].Bytes > rl[j].Bytes })
	if len(rl) > 200 {
		rl = rl[:200]
	}
	for _, rr := range rl {
		if rr.Guess || rr.Uncertain {
			rr.Probe = a.cachedProbe(rr.IP, rr.Port)
		}
	}

	catList := cats.top(0, byBytes)
	writeJSON(w, 200, map[string]any{
		"from": from, "to": to,
		"requests": totalReq, "blocked": totalBlocked, "bytes": totalBytes,
		"categories":        catList,
		"categories_by_req": cats.top(0, byRequests),
		"services":          services.top(40, byBytes),
		"services_by_req":   services.top(40, byRequests),
		"companies":         companies.top(20, byBytes),
		"countries":         countries.top(20, byBytes),
		"domains":           dl,
		"remotes":           rl,
		"requests_by_hour":  reqByHour,
		"summary":           profileSummary(catList, services.top(5, byBytes), countries.top(3, byBytes), totalBytes, reqByHour),
		"rules_version":     a.rulesVersion(),
	})
}

func (id ident) newAgg(name string) *agg {
	return &agg{Name: name, Category: id.Category, Sub: id.Sub, Company: id.Company, Guess: id.Guess, Uncertain: id.Uncertain}
}

func (id ident) matches(category, company string) bool {
	return (category == "" || id.Category == category) && (company == "" || id.Company == company)
}

func svcName(id ident) string {
	if id.Service == "" {
		return "未识别"
	}
	return id.Service
}

// profileSummary writes a short, plain-language description of the device's habits.
func profileSummary(cats, svcs, countries []*agg, total int64, reqByHour [24]int64) []string {
	var out []string
	if total > 0 && len(cats) > 0 {
		var parts []string
		for _, c := range cats {
			if pct := float64(c.Bytes) * 100 / float64(total); pct >= 8 && len(parts) < 3 {
				parts = append(parts, fmt.Sprintf("%s（%.0f%%）", c.Name, pct))
			}
		}
		if len(parts) > 0 {
			out = append(out, "流量主要用于 "+strings.Join(parts, "、"))
		}
	}
	if len(svcs) > 0 {
		var names []string
		for _, s := range svcs {
			if s.Name != "未识别" && !s.Uncertain && len(names) < 3 {
				names = append(names, s.Name)
			}
		}
		if len(names) > 0 {
			out = append(out, "最常用的服务："+strings.Join(names, "、"))
		}
	}
	if len(countries) > 0 && total > 0 {
		c := countries[0]
		out = append(out, fmt.Sprintf("%.0f%% 的流量流向 %s", float64(c.Bytes)*100/float64(total), c.Name))
	}
	var sum int64
	peak := 0
	for h, v := range reqByHour {
		sum += v
		if v > reqByHour[peak] {
			peak = h
		}
	}
	if sum > 0 {
		var night int64
		for _, h := range []int{0, 1, 2, 3, 4, 5} {
			night += reqByHour[h]
		}
		out = append(out, fmt.Sprintf("最活跃的时段是 %02d:00–%02d:00", peak, (peak+1)%24))
		if float64(night)/float64(sum) > 0.25 {
			out = append(out, "凌晨（0–6 点）仍有大量网络活动，可能是自动任务或后台同步")
		}
	}
	return out
}

// GET /api/traffic/overview?range=
func (a *App) handleTrafficOverview(w http.ResponseWriter, r *http.Request) {
	from, to := timeRange(r)
	rows, err := a.db.Query(`SELECT t.mac, SUM(t.up), SUM(t.down), COALESCE(d.name,''), COALESCE(d.ip,''), COALESCE(d.last_seen,0)
		FROM traffic_hour t LEFT JOIN devices_seen d ON d.mac=t.mac WHERE t.hour>=? AND t.hour<? GROUP BY t.mac ORDER BY SUM(t.up+t.down) DESC`, from-from%3600, to)
	if err != nil {
		jsonErr(w, 500, err.Error())
		return
	}
	type dev struct {
		MAC      string `json:"mac"`
		Name     string `json:"name"`
		IP       string `json:"ip"`
		Type     string `json:"type"`
		Up       int64  `json:"up"`
		Down     int64  `json:"down"`
		LastSeen int64  `json:"last_seen"`
	}
	metas := a.deviceMetas()
	var devs []dev
	var up, down int64
	for rows.Next() {
		var d dev
		_ = rows.Scan(&d.MAC, &d.Up, &d.Down, &d.Name, &d.IP, &d.LastSeen)
		m := metas[d.MAC]
		id := a.identifyDevice(d.MAC, d.Name, m.Type)
		d.Type = id.Type
		d.Name = displayName(m.Alias, "", d.Name, id)
		up += d.Up
		down += d.Down
		devs = append(devs, d)
	}
	rows.Close()

	// volume over time for all devices: hourly up to 2 days, daily beyond
	step := int64(3600)
	if to-from > 2*86400 {
		step = 86400
	}
	buckets := map[int64]*point{}
	if rs, err := a.db.Query(`SELECT hour, SUM(up), SUM(down) FROM traffic_hour WHERE hour>=? AND hour<? GROUP BY hour`, from-from%3600, to); err == nil {
		for rs.Next() {
			var h, u, dn int64
			if rs.Scan(&h, &u, &dn) != nil {
				continue
			}
			k := h
			if step == 86400 {
				t := time.Unix(h, 0)
				k = time.Date(t.Year(), t.Month(), t.Day(), 0, 0, 0, 0, time.Local).Unix()
			}
			if buckets[k] == nil {
				buckets[k] = &point{T: k}
			}
			buckets[k].Up += u
			buckets[k].Down += dn
		}
		rs.Close()
	}
	// a complete axis (zeros included) so a fresh day still reads as 0–23 h
	var series []point
	start := from - from%3600
	end := to
	if step == 3600 && to-from <= 86400 && from == todayStart() {
		end = from + 86400
	}
	for t := start; t < end; {
		k := t
		if step == 86400 {
			x := time.Unix(t, 0)
			k = time.Date(x.Year(), x.Month(), x.Day(), 0, 0, 0, 0, time.Local).Unix()
		}
		if p := buckets[k]; p != nil {
			series = append(series, *p)
		} else {
			series = append(series, point{T: k})
		}
		if step == 86400 {
			x := time.Unix(k, 0)
			t = time.Date(x.Year(), x.Month(), x.Day()+1, 0, 0, 0, 0, time.Local).Unix()
		} else {
			t += step
		}
	}

	svcs, cats := a.flowAgg("", from, to, "", "", 15)
	writeJSON(w, 200, map[string]any{"from": from, "to": to, "up": up, "down": down, "devices": devs, "services": svcs, "categories": cats,
		"series": series, "step": step})
}

// GET /api/rules/catalog
func (a *App) handleCatalog(w http.ResponseWriter, r *http.Request) {
	companies := map[string]bool{}
	for _, e := range rules.Catalog {
		companies[e.Company] = true
	}
	for _, e := range rules.Extras {
		companies[e.Company] = true
	}
	var cl []string
	for c := range companies {
		if c != "其他" {
			cl = append(cl, c)
		}
	}
	sort.Strings(cl)
	var svcs []rules.Service
	if a.rules != nil {
		svcs = a.rules.Services()
	}
	writeJSON(w, 200, map[string]any{"categories": rules.Categories, "companies": cl, "version": a.rulesVersion(),
		"services": svcs, "updated_at": a.setting("rules.updated_at")})
}

func (a *App) rulesVersion() string {
	if a.rules == nil {
		return ""
	}
	return a.rules.Version()
}

// namedCountries replaces ISO codes with Chinese names from the offline database.
func (a *App) namedCountries(list []*agg) []*agg {
	rs, err := a.geo.Regions()
	if err != nil {
		return list
	}
	names := make(map[string]string, len(rs))
	for _, r := range rs {
		names[r.Code] = r.Name
	}
	for _, c := range list {
		if n := names[c.Name]; n != "" {
			c.Name = n
		}
	}
	return list
}
