package panel

import (
	"fmt"
	"log"
	"net/http"
	"strconv"
	"time"
)

// Traffic collection: the agent aggregates per-minute counters; the panel pulls
// them every 30 s and keeps minute rows for 48 h and hourly rows for the
// configured retention (retention.traffic_days / retention.traffic_mb).

type agentMinute struct {
	Seq    int64 `json:"seq"`
	Minute int64 `json:"minute"`
	Hosts  []struct {
		IP, MAC  string
		Up, Down int64
	} `json:"hosts"`
	Flows []struct {
		IP, MAC, Remote, Proto, Domain string
		Port                           int
		Inbound                        bool
		Up, Down                       int64
		Conns                          int
	} `json:"flows"`
	DNS []struct {
		IP, MAC, Domain string
		Count, Blocked  int
	} `json:"dns"`
	Names map[string]string `json:"names"`
	Net   []struct {
		Target                string
		Sent, Lost            int
		Min, Avg, Max, Jitter float64
	} `json:"net"`
	Events []struct {
		TS           int64
		Kind, Detail string
	} `json:"events"`
	Conns []struct {
		Start, End     int64
		IP, MAC, Proto string
		Remote         string
		Port, RPort    int
		Up, Down       int64
		Early          bool
	} `json:"conns"`
	ConnsDropped int `json:"conns_dropped"`
}

func devKey(mac, ip string) string {
	if mac != "" {
		return mac
	}
	return "ip:" + ip
}

func (a *App) collectOnce() error {
	boot, seq := a.setting("collect.boot"), int64(a.settingInt("collect.seq"))
	var resp struct {
		Boot    string        `json:"boot"`
		Minutes []agentMinute `json:"minutes"`
	}
	if err := a.agent.Do("GET", "/v1/collect?after="+strconv.FormatInt(seq, 10), nil, &resp); err != nil {
		return err
	}
	if resp.Boot != boot { // agent restarted: its sequence starts over
		if seq != 0 {
			_ = a.setSetting("collect.boot", resp.Boot)
			_ = a.setSetting("collect.seq", "0")
			return a.collectOnce()
		}
		_ = a.setSetting("collect.boot", resp.Boot)
	}
	if len(resp.Minutes) == 0 {
		return nil
	}
	if a.setting("collect.started") == "" {
		start := resp.Minutes[0].Minute
		var first int64 // earlier installs: collection began with the oldest device row
		if a.db.QueryRow(`SELECT COALESCE(MIN(first_seen),0) FROM devices_seen`).Scan(&first) == nil && first > 0 && first < start {
			start = first
		}
		_ = a.setSetting("collect.started", strconv.FormatInt(start, 10))
	}
	dnsFromAgent := a.setting("dns.source") != "nextdns" // otherwise the NextDNS puller fills dns_hour
	tx, err := a.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for _, m := range resp.Minutes {
		if !dnsFromAgent {
			m.DNS = nil
		}
		hour := m.Minute - m.Minute%3600
		for _, h := range m.Hosts {
			k := devKey(h.MAC, h.IP)
			if _, err := tx.Exec(`INSERT INTO traffic_min(minute, mac, up, down) VALUES(?,?,?,?)
				ON CONFLICT(mac, minute) DO UPDATE SET up=up+excluded.up, down=down+excluded.down`, m.Minute, k, h.Up, h.Down); err != nil {
				return err
			}
			if _, err := tx.Exec(`INSERT INTO traffic_hour(hour, mac, up, down) VALUES(?,?,?,?)
				ON CONFLICT(mac, hour) DO UPDATE SET up=up+excluded.up, down=down+excluded.down`, hour, k, h.Up, h.Down); err != nil {
				return err
			}
			if _, err := tx.Exec(`INSERT INTO devices_seen(mac, name, ip, first_seen, last_seen) VALUES(?,?,?,?,?)
				ON CONFLICT(mac) DO UPDATE SET ip=excluded.ip, last_seen=excluded.last_seen,
				name=CASE WHEN excluded.name<>'' THEN excluded.name ELSE name END`,
				k, m.Names[h.MAC], h.IP, m.Minute, m.Minute); err != nil {
				return err
			}
		}
		for _, f := range m.Flows {
			in := 0
			if f.Inbound {
				in = 1
			}
			if _, err := tx.Exec(`INSERT INTO flow_hour(hour, mac, remote, port, proto, inbound, domain, up, down, conns) VALUES(?,?,?,?,?,?,?,?,?,?)
				ON CONFLICT(mac, hour, remote, port, proto, inbound) DO UPDATE SET up=up+excluded.up, down=down+excluded.down,
				conns=conns+excluded.conns, domain=CASE WHEN excluded.domain<>'' THEN excluded.domain ELSE domain END`,
				hour, devKey(f.MAC, f.IP), f.Remote, f.Port, f.Proto, in, f.Domain, f.Up, f.Down, f.Conns); err != nil {
				return err
			}
		}
		for _, c := range m.Conns {
			if _, err := tx.Exec(`INSERT INTO fwd_conns(start, end, ip, mac, port, proto, remote, rport, up, down) VALUES(?,?,?,?,?,?,?,?,?,?)`,
				c.Start, c.End, c.IP, c.MAC, c.Port, c.Proto, c.Remote, c.RPort, c.Up, c.Down); err != nil {
				return err
			}
		}
		for _, n := range m.Net {
			if _, err := tx.Exec(`INSERT OR REPLACE INTO netq_min(minute, target, sent, lost, min, avg, max, jitter) VALUES(?,?,?,?,?,?,?,?)`,
				m.Minute, n.Target, n.Sent, n.Lost, n.Min, n.Avg, n.Max, n.Jitter); err != nil {
				return err
			}
		}
		for _, e := range m.Events {
			if _, err := tx.Exec(`INSERT INTO wan_events(ts, kind, detail) VALUES(?,?,?)`, e.TS, e.Kind, e.Detail); err != nil {
				return err
			}
		}
		for _, d := range m.DNS {
			if _, err := tx.Exec(`INSERT INTO dns_hour(hour, mac, domain, count, blocked) VALUES(?,?,?,?,?)
				ON CONFLICT(mac, hour, domain) DO UPDATE SET count=count+excluded.count, blocked=blocked+excluded.blocked`,
				hour, devKey(d.MAC, d.IP), d.Domain, d.Count, d.Blocked); err != nil {
				return err
			}
		}
		seq = m.Seq
	}
	if _, err := tx.Exec(`INSERT INTO settings(key, value) VALUES('collect.seq', ?) ON CONFLICT(key) DO UPDATE SET value=excluded.value`,
		strconv.FormatInt(seq, 10)); err != nil {
		return err
	}
	return tx.Commit()
}

func (a *App) collector() {
	failing := false
	for {
		if err := a.collectOnce(); err != nil {
			if !failing {
				log.Printf("collect: %v", err)
			}
			failing = true
		} else {
			failing = false
		}
		time.Sleep(30 * time.Second)
	}
}

// trafficRetention trims traffic tables by age and by total size.
func (a *App) trafficRetention() {
	now := time.Now().Unix()
	_, _ = a.db.Exec(`DELETE FROM traffic_min WHERE minute < ?`, now-48*3600)
	cut := now - int64(a.settingInt("retention.traffic_days"))*86400
	for _, t := range []string{"traffic_hour", "flow_hour", "dns_hour"} {
		_, _ = a.db.Exec(fmt.Sprintf(`DELETE FROM %s WHERE hour < ?`, t), cut)
	}
	_, _ = a.db.Exec(`DELETE FROM probes WHERE ts < ?`, now-30*86400)
	_, _ = a.db.Exec(`DELETE FROM fwd_conns WHERE end < ?`, now-30*86400)
	// internet scanners can open thousands of connections a day: keep the newest 1.5 million
	_, _ = a.db.Exec(`DELETE FROM fwd_conns WHERE id <= (SELECT id FROM fwd_conns ORDER BY id DESC LIMIT 1 OFFSET 1500000)`)
	_, _ = a.db.Exec(`DELETE FROM netq_min WHERE minute < ?`, cut)
	_, _ = a.db.Exec(`DELETE FROM wan_events WHERE ts < ?`, now-365*86400)
	limit := int64(a.settingInt("retention.traffic_mb")) << 20
	for i := 0; i < 60 && a.dbUsedBytes() > limit; i++ {
		var oldest int64
		if a.db.QueryRow(`SELECT MIN(hour) FROM flow_hour`).Scan(&oldest) != nil || oldest == 0 {
			break
		}
		// drop the oldest day of detail first; hourly totals are tiny and kept longer
		for _, t := range []string{"flow_hour", "dns_hour"} {
			_, _ = a.db.Exec(fmt.Sprintf(`DELETE FROM %s WHERE hour < ?`, t), oldest+86400)
		}
	}
}

// dbUsedBytes is the database size excluding free pages.
func (a *App) dbUsedBytes() int64 {
	var pages, free, size int64
	_ = a.db.QueryRow(`PRAGMA page_count`).Scan(&pages)
	_ = a.db.QueryRow(`PRAGMA freelist_count`).Scan(&free)
	_ = a.db.QueryRow(`PRAGMA page_size`).Scan(&size)
	return (pages - free) * size
}

// ---- live ----

type liveHost struct {
	MAC      string  `json:"mac"`
	IP       string  `json:"ip"`
	Up       float64 `json:"up"`
	Down     float64 `json:"down"`
	UpTotal  uint64  `json:"up_total"`
	DownTot  uint64  `json:"down_total"`
	LastSeen int64   `json:"last_seen"`
}

// GET /api/traffic/live — current per-device rates (bytes/s), keyed by MAC.
func (a *App) handleTrafficLive(w http.ResponseWriter, r *http.Request) {
	var resp struct {
		TS    int64 `json:"ts"`
		Hosts map[string]struct {
			Up       float64 `json:"up"`
			Down     float64 `json:"down"`
			UpTotal  uint64  `json:"up_total"`
			DownTot  uint64  `json:"down_total"`
			LastSeen int64   `json:"last_seen"`
		} `json:"hosts"`
	}
	if err := a.agent.Do("GET", "/v1/traffic/live", nil, &resp); err != nil {
		jsonErr(w, 502, err.Error())
		return
	}
	var neigh map[string]string
	_ = a.agent.Do("GET", "/v1/neigh", nil, &neigh)
	out := map[string]liveHost{}
	for ip, h := range resp.Hosts {
		k := devKey(neigh[ip], ip)
		out[k] = liveHost{MAC: k, IP: ip, Up: h.Up, Down: h.Down, UpTotal: h.UpTotal, DownTot: h.DownTot, LastSeen: h.LastSeen}
	}
	writeJSON(w, 200, map[string]any{"ts": resp.TS, "hosts": out})
}

// newSince is the first_seen threshold for "new device": devices already present
// during the first hour of collection are the baseline, not new arrivals.
func (a *App) newSince() int64 {
	started, _ := strconv.ParseInt(a.setting("collect.started"), 10, 64)
	t := time.Now().Unix() - 86400
	if b := started + 3600; b > t {
		return b
	}
	return t
}
