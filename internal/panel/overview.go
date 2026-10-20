package panel

import (
	"net/http"
	"sort"
	"strconv"
	"time"
)

func todayStart() int64 {
	y, m, d := time.Now().Date()
	return time.Date(y, m, d, 0, 0, 0, 0, time.Local).Unix()
}

// GET /api/overview — numbers for the dashboard / big screen.
func (a *App) handleOverview(w http.ResponseWriter, r *http.Request) {
	u := currentUser(r)
	t0 := todayStart()
	out := map[string]any{}

	var up, down int64
	_ = a.db.QueryRow(`SELECT COALESCE(SUM(up),0), COALESCE(SUM(down),0) FROM traffic_hour WHERE hour >= ?`, t0).Scan(&up, &down)
	var req, blk int64
	_ = a.db.QueryRow(`SELECT COALESCE(SUM(count),0), COALESCE(SUM(blocked),0) FROM dns_hour WHERE hour >= ?`, t0).Scan(&req, &blk)
	out["today"] = map[string]int64{"up": up, "down": down, "dns_requests": req, "dns_blocked": blk}

	var devs []Device
	if err := a.agent.Do("GET", "/v1/devices", nil, &devs); err == nil {
		online, total := 0, 0
		for _, d := range devs {
			if d.IP == "" {
				continue
			}
			total++
			if d.Online {
				online++
			}
		}
		var newCount int
		_ = a.db.QueryRow(`SELECT COUNT(*) FROM devices_seen WHERE first_seen > ?`, a.newSince()).Scan(&newCount)
		var pst agentPolicyStatus
		_ = a.agent.Do("GET", "/v1/policy/status", nil, &pst)
		blocked := 0
		for _, s := range pst {
			if s.Blocked {
				blocked++
			}
		}
		out["devices"] = map[string]int{"online": online, "total": total, "new_24h": newCount, "controlled": len(pst), "blocked": blocked}
	}
	if u.Role == RoleSuper {
		var pending int
		_ = a.db.QueryRow(`SELECT COUNT(*) FROM approvals WHERE status='pending'`).Scan(&pending)
		out["approvals_pending"] = pending
		var denied int
		_ = a.db.QueryRow(`SELECT COUNT(*) FROM visitors WHERE blocked=1 AND ts >= ?`, time.Now().Unix()-86400).Scan(&denied)
		out["visitors_denied_24h"] = denied
	}
	if u.Can("traffic.view") {
		out["services_today"], out["categories_today"] = a.flowAgg("", t0, time.Now().Unix(), "", "", 10)
	}
	writeJSON(w, 200, out)
}

type event struct {
	TS     int64  `json:"ts"`
	Kind   string `json:"kind"`  // new_device | left | back | control | schedule | forward | access | approval | rules | login
	Level  string `json:"level"` // info | warn | alert
	Title  string `json:"title"`
	Detail string `json:"detail,omitempty"`
	MAC    string `json:"mac,omitempty"`
	Link   string `json:"link,omitempty"`
}

// GET /api/events?limit=
func (a *App) handleEvents(w http.ResponseWriter, r *http.Request) {
	u := currentUser(r)
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	if limit <= 0 || limit > 200 {
		limit = 40
	}
	since := time.Now().Unix() - 7*86400
	var evs []event

	names := map[string]string{}
	var devs []Device
	if a.agent.Do("GET", "/v1/devices", nil, &devs) == nil {
		for _, d := range devs {
			names[d.MAC] = firstNonEmpty(d.StaticName, d.Hostname)
		}
	}
	metas := a.deviceMetas()
	nameOf := func(mac, fallback string) string {
		return firstNonEmpty(metas[mac].Alias, names[mac], fallback, mac)
	}

	started, _ := strconv.ParseInt(a.setting("collect.started"), 10, 64)
	if rows, err := a.db.Query(`SELECT mac, name, ip, first_seen FROM devices_seen WHERE first_seen >= ? AND first_seen > ? ORDER BY first_seen DESC LIMIT 50`, since, started+3600); err == nil {
		for rows.Next() {
			var mac, name, ip string
			var ts int64
			if rows.Scan(&mac, &name, &ip, &ts) == nil {
				evs = append(evs, event{TS: ts, Kind: "new_device", Level: "warn", Title: "新设备接入：" + nameOf(mac, name),
					Detail: ip + " · " + mac, MAC: mac, Link: "/devices/" + mac})
			}
		}
		rows.Close()
	}

	if u.Can("devices.view") {
		evs = append(evs, a.presenceEvents(since, nameOf)...)
	}

	// audit-derived events; normal admins only see their own actions
	q := `SELECT ts, user_id, username, action, target_id, summary FROM audit WHERE ts >= ? AND
		(action LIKE 'device.policy%' OR action LIKE 'forward.%' OR action IN ('rules.update','approval.reject','nextdns.per_device','device.meta.save'))`
	args := []any{since}
	if u.Role != RoleSuper {
		q += ` AND user_id = ?`
		args = append(args, u.ID)
	}
	if rows, err := a.db.Query(q+` ORDER BY id DESC LIMIT 100`, args...); err == nil {
		for rows.Next() {
			var ts, uid int64
			var user, action, target, summary string
			if rows.Scan(&ts, &uid, &user, &action, &target, &summary) != nil {
				continue
			}
			e := event{TS: ts, Title: summary, Detail: "由 " + user + " 操作", Level: "info"}
			switch {
			case len(action) > 13 && action[:13] == "device.policy":
				e.Kind, e.Level, e.Link = "control", "warn", "/controls"
			case len(action) > 8 && action[:8] == "forward.":
				e.Kind, e.Link = "forward", "/forwards"
			case action == "rules.update":
				e.Kind = "rules"
			default:
				e.Kind = "approval"
			}
			evs = append(evs, e)
		}
		rows.Close()
	}

	var pst agentPolicyStatus
	if a.agent.Do("GET", "/v1/policy/status", nil, &pst) == nil {
		now := time.Now().Unix()
		for mac, s := range pst {
			if s.Blocked && s.Reason == "schedule" {
				evs = append(evs, event{TS: now, Kind: "schedule", Level: "warn", Title: "定时断网中：" + nameOf(mac, ""), MAC: mac, Link: "/devices/" + mac + "?tab=control"})
			}
		}
	}

	if u.Role == RoleSuper {
		if rows, err := a.db.Query(`SELECT ts, ip, reason, country FROM visitors WHERE blocked=1 AND ts >= ? ORDER BY id DESC LIMIT 20`, time.Now().Unix()-86400); err == nil {
			for rows.Next() {
				var ts int64
				var ip, reason, country string
				if rows.Scan(&ts, &ip, &reason, &country) == nil {
					evs = append(evs, event{TS: ts, Kind: "access", Level: "alert", Title: "面板访问被拒绝：" + ip, Detail: reason, Link: "/visitors"})
				}
			}
			rows.Close()
		}
		if rows, err := a.db.Query(`SELECT ts, username, summary FROM approvals WHERE status='pending' ORDER BY id DESC LIMIT 20`); err == nil {
			for rows.Next() {
				var ts int64
				var user, summary string
				if rows.Scan(&ts, &user, &summary) == nil {
					evs = append(evs, event{TS: ts, Kind: "approval", Level: "alert", Title: "待审批：" + summary, Detail: "申请人 " + user, Link: "/approvals"})
				}
			}
			rows.Close()
		}
	}
	sort.Slice(evs, func(i, j int) bool { return evs[i].TS > evs[j].TS })
	if len(evs) > limit {
		evs = evs[:limit]
	}
	writeJSON(w, 200, evs)
}
