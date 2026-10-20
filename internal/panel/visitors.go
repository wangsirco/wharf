package panel

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// POST /api/beacon  (public) — the SPA sends this on every page load.
// The server time is the access time; the browser reports its own clock and timezone.
func (a *App) handleBeacon(w http.ResponseWriter, r *http.Request) {
	ip := a.clientIP(r)
	if a.beacons.blocked("b:" + ip) {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	a.beacons.record("b:" + ip)

	var req struct {
		TZ        string `json:"tz"`         // Intl.DateTimeFormat().resolvedOptions().timeZone
		Offset    *int   `json:"offset"`     // minutes east of UTC (= -Date.getTimezoneOffset())
		LocalTime string `json:"local_time"` // browser local clock, ISO-like string
		Path      string `json:"path"`
		IPSB      *struct {
			IP          string `json:"ip"`
			ASN         int    `json:"asn"`
			Org         string `json:"asn_organization"`
			ISP         string `json:"isp"`
			CountryCode string `json:"country_code"`
			Country     string `json:"country"`
			Region      string `json:"region"`
			City        string `json:"city"`
			Timezone    string `json:"timezone"`
			Offset      int    `json:"offset"`
		} `json:"ipsb"`
	}
	_ = readJSON(r, &req)

	now := time.Now()
	g := a.geo.Lookup(ip)
	var ipOffset *int
	if g.TZ != "" {
		if off, ok := OffsetMinutes(g.TZ, now); ok {
			ipOffset = &off
		}
	}
	match := tzMatch(req.Offset, ipOffset)

	// ip.sb result comes from the browser and is advisory only; a different IP than
	// the one we see usually means a split-routing proxy.
	ipsb, ipsbMatch := "", ""
	if req.IPSB != nil && req.IPSB.IP != "" {
		b, _ := json.Marshal(req.IPSB)
		ipsb = truncate(string(b), 1000)
		ipsbMatch = "diff"
		if req.IPSB.IP == ip {
			ipsbMatch = "same"
		}
	}

	var uid any
	username := ""
	if s := a.loadSession(r); s != nil {
		uid, username = s.user.ID, s.user.Username
	}
	_, _ = a.db.Exec(`INSERT INTO visitors(ts, user_id, username, ip, asn, as_org, country, region, city, ip_tz, ip_offset, client_tz, client_offset, client_time, tz_match, user_agent, path, mac, ipsb, ipsb_match)
		VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		now.Unix(), uid, username, ip, g.ASN, g.ASOrg, g.Country, g.Region, g.City, g.TZ, ipOffset,
		truncate(req.TZ, 64), req.Offset, truncate(req.LocalTime, 64), match, truncate(r.UserAgent(), 300), truncate(req.Path, 200),
		a.lanMAC(ip), ipsb, ipsbMatch)
	w.WriteHeader(http.StatusNoContent)
}

// tzMatch compares the browser's current UTC offset with the offset of the IP's
// location. A mismatch suggests a proxy/VPN (or a traveller with an unchanged clock).
func tzMatch(client, ip *int) string {
	if client == nil || ip == nil {
		return "unknown"
	}
	if *client == *ip {
		return "match"
	}
	return "mismatch"
}

type Visitor struct {
	ID           int64  `json:"id"`
	TS           int64  `json:"ts"`
	UserID       *int64 `json:"user_id"`
	Username     string `json:"username"`
	IP           string `json:"ip"`
	ASN          int64  `json:"asn"`
	ASOrg        string `json:"as_org"`
	Country      string `json:"country"`
	Region       string `json:"region"`
	City         string `json:"city"`
	IPTZ         string `json:"ip_tz"`
	IPOffset     *int   `json:"ip_offset"`
	ClientTZ     string `json:"client_tz"`
	ClientOffset *int   `json:"client_offset"`
	ClientTime   string `json:"client_time"`
	TZMatch      string `json:"tz_match"`
	UserAgent    string `json:"user_agent"`
	Path         string `json:"path"`
	Blocked      bool   `json:"blocked"`
	Reason       string `json:"reason"`
	MAC          string `json:"mac"`
	IPSB         string `json:"ipsb"`
	IPSBMatch    string `json:"ipsb_match"`
}

// GET /api/visitors?q=&match=&before_id=&limit=
func (a *App) handleVisitors(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	var conds []string
	var args []any
	if v := q.Get("q"); v != "" {
		conds = append(conds, "(ip LIKE ? OR as_org LIKE ? OR username LIKE ? OR city LIKE ?)")
		for i := 0; i < 4; i++ {
			args = append(args, "%"+v+"%")
		}
	}
	switch v := q.Get("match"); v {
	case "":
	case "blocked":
		conds = append(conds, "blocked=1")
	case "suspect":
		conds = append(conds, "(tz_match='mismatch' OR ipsb_match='diff')")
	default:
		conds = append(conds, "tz_match=?")
		args = append(args, v)
	}
	if v := q.Get("before_id"); v != "" {
		conds = append(conds, "id < ?")
		args = append(args, v)
	}
	limit, _ := strconv.Atoi(q.Get("limit"))
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	where := ""
	if len(conds) > 0 {
		where = "WHERE " + strings.Join(conds, " AND ")
	}
	rows, err := a.db.Query(`SELECT id, ts, user_id, username, ip, asn, as_org, country, region, city, ip_tz, ip_offset, client_tz, client_offset, client_time, tz_match, user_agent, path, blocked, reason, mac, ipsb, ipsb_match
		FROM visitors `+where+` ORDER BY id DESC LIMIT `+strconv.Itoa(limit), args...)
	if err != nil {
		jsonErr(w, 500, err.Error())
		return
	}
	defer rows.Close()
	out := []Visitor{}
	for rows.Next() {
		var v Visitor
		if err := rows.Scan(&v.ID, &v.TS, &v.UserID, &v.Username, &v.IP, &v.ASN, &v.ASOrg, &v.Country, &v.Region, &v.City, &v.IPTZ, &v.IPOffset,
			&v.ClientTZ, &v.ClientOffset, &v.ClientTime, &v.TZMatch, &v.UserAgent, &v.Path, &v.Blocked, &v.Reason, &v.MAC, &v.IPSB, &v.IPSBMatch); err != nil {
			jsonErr(w, 500, err.Error())
			return
		}
		out = append(out, v)
	}
	writeJSON(w, 200, map[string]any{"items": out, "geo_ready": a.geo.Ready()})
}
