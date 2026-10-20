package panel

import (
	"log"
	"net"
	"net/http"
	"strconv"
	"time"
)

// Device presence: "left the network" / "back on the network" events.
//
// The agent reports when each device was last confirmed reachable (it re-ARPs idle
// neighbours every 30 s). A device that has not been confirmed for presence.away_minutes
// (default 10, so phones dozing on Wi-Fi don't flap) is recorded as having left at the
// moment it was last seen; when it shows up again a "back" event records how long it was away.

type presenceRow struct {
	state    string // home | away
	lastSeen int64
}

func (a *App) presenceLoop() {
	time.Sleep(45 * time.Second) // let the agent finish its first probe round
	for {
		func() {
			defer func() {
				if r := recover(); r != nil {
					log.Printf("presence: %v", r)
				}
			}()
			a.presenceTick(time.Now().Unix())
		}()
		time.Sleep(time.Minute)
	}
}

func (a *App) presenceTick(now int64) {
	var devs []Device
	if err := a.agent.Do("GET", "/v1/devices", nil, &devs); err != nil {
		return
	}
	awayAfter := int64(a.settingInt("presence.away_minutes")) * 60
	if awayAfter < 180 {
		awayAfter = 600
	}
	known := map[string]presenceRow{}
	if rows, err := a.db.Query(`SELECT mac, state, last_seen FROM device_presence`); err == nil {
		for rows.Next() {
			var mac string
			var r presenceRow
			if rows.Scan(&mac, &r.state, &r.lastSeen) == nil {
				known[mac] = r
			}
		}
		rows.Close()
	}
	tracking := false // agents before 0.11 report no last_seen at all
	for _, d := range devs {
		tracking = tracking || d.LastSeen > 0
	}
	if !tracking {
		return
	}
	listed := map[string]bool{}
	for _, d := range devs {
		listed[d.MAC] = true
		// LastSeen 0 = never confirmed since tracking started: already away (time unknown)
		prev, seenBefore := known[d.MAC]
		if d.LastSeen == 0 && seenBefore {
			d.LastSeen = prev.lastSeen // the agent restarted and forgot; keep what we know
		}
		state := "home"
		if now-d.LastSeen >= awayAfter {
			state = "away"
		}
		switch {
		case !seenBefore:
			// first sighting: baseline only, no event
		case prev.state == "home" && state == "away":
			// the agent forgets last-seen times when it restarts; fall back to ours
			a.presenceEvent(max(d.LastSeen, prev.lastSeen), d.MAC, d.IP, "left", 0)
		case prev.state == "away" && state == "home":
			away := int64(0) // unknown when it left
			if prev.lastSeen > 0 {
				away = d.LastSeen - prev.lastSeen
			}
			a.presenceEvent(now, d.MAC, d.IP, "back", away)
		}
		if !seenBefore || prev.state != state || prev.lastSeen != d.LastSeen {
			_, _ = a.db.Exec(`INSERT INTO device_presence(mac, state, last_seen, changed_at) VALUES(?,?,?,?)
				ON CONFLICT(mac) DO UPDATE SET state=excluded.state, last_seen=excluded.last_seen,
				changed_at=CASE WHEN device_presence.state<>excluded.state THEN excluded.changed_at ELSE device_presence.changed_at END`,
				d.MAC, state, d.LastSeen, now)
		}
	}
	// a device whose lease and neighbour entry are both gone is no longer listed at all
	for mac, prev := range known {
		if !listed[mac] && prev.state == "home" && now-prev.lastSeen >= awayAfter {
			a.presenceEvent(prev.lastSeen, mac, "", "left", 0)
			_, _ = a.db.Exec(`UPDATE device_presence SET state='away', changed_at=? WHERE mac=?`, now, mac)
		}
	}
}

func (a *App) presenceEvent(ts int64, mac, ip, kind string, away int64) {
	_, _ = a.db.Exec(`INSERT INTO device_events(ts, mac, ip, kind, away_secs) VALUES(?,?,?,?,?)`, ts, mac, ip, kind, away)
}

// presenceEvents feeds the dashboard event list.
func (a *App) presenceEvents(since int64, nameOf func(mac, fallback string) string) []event {
	var out []event
	rows, err := a.db.Query(`SELECT ts, mac, ip, kind, away_secs FROM device_events WHERE ts >= ? ORDER BY ts DESC LIMIT 100`, since)
	if err != nil {
		return nil
	}
	defer rows.Close()
	for rows.Next() {
		var ts, away int64
		var mac, ip, kind string
		if rows.Scan(&ts, &mac, &ip, &kind, &away) != nil {
			continue
		}
		e := event{TS: ts, Kind: kind, Level: "info", MAC: mac, Link: "/devices/" + mac}
		if kind == "left" {
			e.Title, e.Detail = "离开网络："+nameOf(mac, ip), "最后在线 "+time.Unix(ts, 0).Format("15:04")+" · "+ip
		} else {
			e.Title, e.Detail = "回到网络："+nameOf(mac, ip), ip
			if away > 0 {
				e.Detail = "离开了 " + awayText(away) + " · " + ip
			}
		}
		out = append(out, e)
	}
	return out
}

func awayText(sec int64) string {
	switch {
	case sec < 3600:
		return strconv.FormatInt(max(sec/60, 1), 10) + " 分钟"
	case sec < 86400:
		h, m := sec/3600, sec%3600/60
		if m == 0 {
			return strconv.FormatInt(h, 10) + " 小时"
		}
		return strconv.FormatInt(h, 10) + " 小时 " + strconv.FormatInt(m, 10) + " 分"
	}
	return strconv.FormatInt(sec/86400, 10) + " 天 " + strconv.FormatInt(sec%86400/3600, 10) + " 小时"
}

// GET /api/devices/{mac}/presence — recent arrivals and departures of one device.
func (a *App) handleDevicePresence(w http.ResponseWriter, r *http.Request) {
	hw, err := net.ParseMAC(r.PathValue("mac"))
	if err != nil {
		jsonErr(w, 400, "MAC 无效")
		return
	}
	mac := hw.String()
	type ev struct {
		TS   int64  `json:"ts"`
		Kind string `json:"kind"`
		IP   string `json:"ip"`
		Away int64  `json:"away_secs"`
	}
	out := map[string]any{"events": []ev{}}
	var state string
	var last, changed int64
	if a.db.QueryRow(`SELECT state, last_seen, changed_at FROM device_presence WHERE mac=?`, mac).Scan(&state, &last, &changed) == nil {
		out["state"], out["last_seen"], out["since"] = state, last, changed
	}
	rows, err := a.db.Query(`SELECT ts, kind, ip, away_secs FROM device_events WHERE mac=? ORDER BY ts DESC LIMIT 30`, mac)
	if err == nil {
		var list []ev
		for rows.Next() {
			var e ev
			if rows.Scan(&e.TS, &e.Kind, &e.IP, &e.Away) == nil {
				list = append(list, e)
			}
		}
		rows.Close()
		if list != nil {
			out["events"] = list
		}
	}
	// live view from the agent: a device can be gone for a few minutes before it counts as "left"
	var devs []Device
	if a.agent.Do("GET", "/v1/devices", nil, &devs) == nil {
		for _, d := range devs {
			if d.MAC == mac {
				out["online"] = d.Online
				if d.LastSeen > 0 {
					out["last_seen"] = d.LastSeen
				}
			}
		}
	}
	out["away_minutes"] = a.settingInt("presence.away_minutes")
	out["now"] = time.Now().Unix()
	writeJSON(w, 200, out)
}
