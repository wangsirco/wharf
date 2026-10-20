package panel

import (
	"encoding/json"
	"math"
	"net/http"
	"sort"
	"time"
)

// GET /api/network?range= — WAN status, latency / loss per target, outages, speed tests.
func (a *App) handleNetwork(w http.ResponseWriter, r *http.Request) {
	from, to := timeRange(r)
	out := map[string]any{"from": from, "to": to}
	var wan json.RawMessage
	if err := a.agent.Do("GET", "/v1/wan", nil, &wan); err == nil {
		out["wan"] = wan
	}

	// bucket size keeps charts at a few hundred points
	span := to - from
	step := int64(60)
	switch {
	case span > 7*86400:
		step = 3600
	case span > 86400:
		step = 900
	case span > 6*3600:
		step = 300
	}
	type pt struct {
		T      int64   `json:"t"`
		Avg    float64 `json:"avg"`
		Max    float64 `json:"max"`
		Loss   float64 `json:"loss"` // percent
		Jitter float64 `json:"jitter"`
	}
	type acc struct {
		sum, max, jit  float64
		ok, sent, lost int
	}
	series := map[string]map[int64]*acc{}
	minuteDown := map[int64]bool{} // every target lost everything this minute
	minuteTargets := map[int64][2]int{}
	rows, err := a.db.Query(`SELECT minute, target, sent, lost, avg, max, jitter FROM netq_min WHERE minute>=? AND minute<? ORDER BY minute`, from, to)
	if err != nil {
		jsonErr(w, 500, err.Error())
		return
	}
	for rows.Next() {
		var m int64
		var t string
		var sent, lost int
		var avg, mx, jit float64
		if rows.Scan(&m, &t, &sent, &lost, &avg, &mx, &jit) != nil {
			continue
		}
		if series[t] == nil {
			series[t] = map[int64]*acc{}
		}
		k := m - m%step
		x := series[t][k]
		if x == nil {
			x = &acc{}
			series[t][k] = x
		}
		x.sent += sent
		x.lost += lost
		if sent > lost {
			x.sum += avg
			x.jit += jit
			x.ok++
			if mx > x.max {
				x.max = mx
			}
		}
		c := minuteTargets[m]
		c[0]++
		if sent > 0 && lost == sent {
			c[1]++
		}
		minuteTargets[m] = c
	}
	rows.Close()
	for m, c := range minuteTargets {
		if c[0] >= 2 && c[1] == c[0] {
			minuteDown[m] = true
		}
	}

	type targetOut struct {
		Target string  `json:"target"`
		Points []pt    `json:"points"`
		Avg    float64 `json:"avg"`  // over range
		Loss   float64 `json:"loss"` // percent over range
		Now    float64 `json:"now"`  // latest bucket avg
	}
	var targets []targetOut
	for t, b := range series {
		tg := targetOut{Target: t}
		var keys []int64
		for k := range b {
			keys = append(keys, k)
		}
		sort.Slice(keys, func(i, j int) bool { return keys[i] < keys[j] })
		var sum float64
		var ok, sent, lost int
		for _, k := range keys {
			x := b[k]
			p := pt{T: k, Max: round1(x.max)}
			if x.ok > 0 {
				p.Avg, p.Jitter = round1(x.sum/float64(x.ok)), round1(x.jit/float64(x.ok))
				sum += x.sum
				ok += x.ok
			}
			if x.sent > 0 {
				p.Loss = round1(float64(x.lost) * 100 / float64(x.sent))
			}
			sent += x.sent
			lost += x.lost
			tg.Points = append(tg.Points, p)
		}
		if ok > 0 {
			tg.Avg = round1(sum / float64(ok))
		}
		if sent > 0 {
			tg.Loss = round1(float64(lost) * 100 / float64(sent))
		}
		if n := len(tg.Points); n > 0 {
			tg.Now = tg.Points[n-1].Avg
		}
		targets = append(targets, tg)
	}
	sort.Slice(targets, func(i, j int) bool { return targets[i].Target < targets[j].Target })
	// many ISP gateways never answer ping: hide a target that is always silent while others work
	bestLoss := 100.0
	for _, t := range targets {
		if t.Loss < bestLoss {
			bestLoss = t.Loss
		}
	}
	var shown []targetOut
	var silent []string
	for _, t := range targets {
		if t.Loss >= 100 && bestLoss < 50 {
			silent = append(silent, t.Target)
			continue
		}
		shown = append(shown, t)
	}
	out["targets"], out["silent"], out["step"] = shown, silent, step

	// outages: runs of minutes where every target was unreachable
	var downs []int64
	for m := range minuteDown {
		downs = append(downs, m)
	}
	sort.Slice(downs, func(i, j int) bool { return downs[i] < downs[j] })
	type outage struct {
		From    int64 `json:"from"`
		To      int64 `json:"to"`
		Minutes int   `json:"minutes"`
	}
	var outages []outage
	for _, m := range downs {
		if n := len(outages); n > 0 && m-outages[n-1].To <= 60 {
			outages[n-1].To = m + 60
			outages[n-1].Minutes++
			continue
		}
		outages = append(outages, outage{m, m + 60, 1})
	}
	out["outages"] = outages

	type ev struct {
		TS     int64  `json:"ts"`
		Kind   string `json:"kind"`
		Detail string `json:"detail"`
	}
	var evs []ev
	if rs, err := a.db.Query(`SELECT ts, kind, detail FROM wan_events WHERE ts>=? AND ts<? ORDER BY ts DESC LIMIT 100`, from, to); err == nil {
		for rs.Next() {
			var e ev
			if rs.Scan(&e.TS, &e.Kind, &e.Detail) == nil {
				evs = append(evs, e)
			}
		}
		rs.Close()
	}
	out["events"] = evs
	out["speedtests"] = a.speedtests(20)
	writeJSON(w, 200, out)
}

type speedRow struct {
	TS       int64   `json:"ts"`
	Down     float64 `json:"down_mbps"`
	Up       float64 `json:"up_mbps"`
	Latency  float64 `json:"latency_ms"`
	Server   string  `json:"server"`
	Error    string  `json:"error,omitempty"`
	Username string  `json:"username"`
}

func (a *App) speedtests(n int) []speedRow {
	var out []speedRow
	rows, err := a.db.Query(`SELECT ts, down, up, latency, server, error, username FROM speedtests ORDER BY id DESC LIMIT ?`, n)
	if err != nil {
		return out
	}
	defer rows.Close()
	for rows.Next() {
		var s speedRow
		if rows.Scan(&s.TS, &s.Down, &s.Up, &s.Latency, &s.Server, &s.Error, &s.Username) == nil {
			out = append(out, s)
		}
	}
	return out
}

// POST /api/network/speedtest — runs on the router (~20 s).
func (a *App) handleSpeedtest(w http.ResponseWriter, r *http.Request) {
	u := currentUser(r)
	if a.beacons.blocked("speed:" + u.Username) {
		jsonErr(w, 429, "测速太频繁，请一分钟后再试")
		return
	}
	for i := 0; i < 50; i++ { // one per minute per user
		a.beacons.record("speed:" + u.Username)
	}
	engine := "cloudflare"
	if r.URL.Query().Get("engine") == "ookla" {
		engine = "ookla"
	}
	var res speedRow
	if err := a.agent.Do("POST", "/v1/speedtest?engine="+engine, nil, &res); err != nil {
		jsonErr(w, 502, err.Error())
		return
	}
	res.Username = u.Username
	if res.TS == 0 {
		res.TS = time.Now().Unix()
	}
	_, _ = a.db.Exec(`INSERT INTO speedtests(ts, down, up, latency, server, error, username) VALUES(?,?,?,?,?,?,?)`,
		res.TS, res.Down, res.Up, res.Latency, res.Server, res.Error, res.Username)
	writeJSON(w, 200, res)
}

func round1(v float64) float64 { return math.Round(v*10) / 10 }
