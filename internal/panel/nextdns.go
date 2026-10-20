package panel

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/netip"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"
)

// NextDNS integration (https://nextdns.github.io/api/).
//
// The router's nextdns CLI sits behind dnsmasq, so per-device attribution comes
// from our own dnsmasq log. NextDNS adds what only it knows: why a query was
// blocked (which blocklist / parental rule), tracker owners and profile-wide
// analytics. With dns.source=nextdns the per-device query counts are taken from
// NextDNS logs instead (useful once "addmac" lets NextDNS see each device).

const nextdnsAPI = "https://api.nextdns.io"

var (
	nextdnsKeyRe     = regexp.MustCompile(`^[0-9a-f]{40}$`)
	nextdnsProfileRe = regexp.MustCompile(`^[0-9a-z]{4,12}$`)
)

func init() {
	settingDefaults["nextdns.api_key"] = ""
	settingDefaults["nextdns.profile"] = ""
	settingDefaults["dns.source"] = "dnsmasq"
}

type nextdnsClient struct {
	key, profile string
	http         *http.Client
}

func (a *App) nextdns() (*nextdnsClient, error) {
	key := a.setting("nextdns.api_key")
	if key == "" {
		return nil, errors.New("尚未配置 NextDNS API Key")
	}
	profile := a.setting("nextdns.profile")
	if profile == "" {
		// default to the profile the router's nextdns CLI uses
		if cfg, err := a.agent.UciConfig("nextdns"); err == nil {
			for _, s := range cfg {
				if p := optStr(s, "profile"); p != "" {
					profile = p
					break
				}
			}
		}
	}
	if profile == "" {
		return nil, errors.New("尚未配置 NextDNS profile")
	}
	return &nextdnsClient{key: key, profile: profile, http: &http.Client{Timeout: 20 * time.Second}}, nil
}

func (c *nextdnsClient) get(path string, q url.Values, out any) error {
	u := fmt.Sprintf("%s/profiles/%s%s", nextdnsAPI, c.profile, path)
	if len(q) > 0 {
		u += "?" + q.Encode()
	}
	req, _ := http.NewRequest("GET", u, nil)
	req.Header.Set("X-Api-Key", c.key)
	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("NextDNS 不可达：%w", err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 16<<20))
	if resp.StatusCode != 200 {
		var e struct {
			Errors []struct {
				Code, Detail string
			} `json:"errors"`
		}
		_ = json.Unmarshal(b, &e)
		if resp.StatusCode == 403 || resp.StatusCode == 401 {
			return errors.New("NextDNS API Key 无效或没有该 profile 的权限")
		}
		if len(e.Errors) > 0 {
			return fmt.Errorf("NextDNS：%s %s", e.Errors[0].Code, e.Errors[0].Detail)
		}
		return fmt.Errorf("NextDNS：HTTP %d", resp.StatusCode)
	}
	return json.Unmarshal(b, out)
}

type ndLog struct {
	Timestamp time.Time `json:"timestamp"`
	Domain    string    `json:"domain"`
	Root      string    `json:"root"`
	Tracker   string    `json:"tracker"`
	Encrypted bool      `json:"encrypted"`
	Protocol  string    `json:"protocol"`
	ClientIP  string    `json:"clientIp"`
	Device    *struct {
		ID, Name, Model string
	} `json:"device"`
	Status  string `json:"status"` // default | blocked | allowed | relayed | error
	Reasons []struct {
		ID, Name string
	} `json:"reasons"`
}

// ---- background pull of logs ----

func (a *App) nextdnsPuller() {
	time.Sleep(time.Minute)
	failing := false
	for {
		if a.setting("nextdns.api_key") != "" {
			if err := a.nextdnsPullOnce(); err != nil {
				if !failing {
					log.Printf("nextdns: %v", err)
				}
				failing = true
			} else {
				failing = false
			}
		}
		time.Sleep(time.Minute)
	}
}

func (a *App) nextdnsPullOnce() error {
	c, err := a.nextdns()
	if err != nil {
		return err
	}
	from := a.setting("nextdns.cursor_ts")
	if from == "" {
		from = time.Now().Add(-10 * time.Minute).UTC().Format(time.RFC3339)
	}
	useForDevices := a.setting("dns.source") == "nextdns"
	var neigh map[string]string
	if useForDevices {
		_ = a.agent.Do("GET", "/v1/neigh", nil, &neigh)
	}
	names := map[string]string{} // lower(device name) -> mac
	if useForDevices {
		if rows, err := a.db.Query(`SELECT mac, name FROM devices_seen WHERE name<>''`); err == nil {
			for rows.Next() {
				var m, n string
				if rows.Scan(&m, &n) == nil {
					names[strings.ToLower(n)] = m
				}
			}
			rows.Close()
		}
	}
	cursor, last := "", from
	for page := 0; page < 20; page++ {
		q := url.Values{"from": {from}, "sort": {"asc"}, "limit": {"1000"}}
		if cursor != "" {
			q.Set("cursor", cursor)
		}
		var resp struct {
			Data []ndLog `json:"data"`
			Meta struct {
				Pagination struct {
					Cursor *string `json:"cursor"`
				} `json:"pagination"`
			} `json:"meta"`
		}
		if err := c.get("/logs", q, &resp); err != nil {
			return err
		}
		tx, err := a.db.Begin()
		if err != nil {
			return err
		}
		for _, l := range resp.Data {
			if !l.Timestamp.After(mustTime(from)) {
				continue
			}
			last = l.Timestamp.UTC().Format(time.RFC3339Nano)
			d := strings.TrimSuffix(strings.ToLower(l.Domain), ".")
			if l.Status == "blocked" || l.Status == "allowed" || l.Tracker != "" {
				var reasons []string
				for _, r := range l.Reasons {
					reasons = append(reasons, r.Name)
				}
				_, _ = tx.Exec(`INSERT INTO nextdns_domains(domain, status, reasons, tracker, last_seen, hits) VALUES(?,?,?,?,?,1)
					ON CONFLICT(domain) DO UPDATE SET status=excluded.status, reasons=CASE WHEN excluded.reasons<>'' THEN excluded.reasons ELSE reasons END,
					tracker=CASE WHEN excluded.tracker<>'' THEN excluded.tracker ELSE tracker END, last_seen=excluded.last_seen, hits=hits+1`,
					d, l.Status, strings.Join(reasons, "、"), l.Tracker, l.Timestamp.Unix())
			}
			if useForDevices {
				mac := ""
				if ip, err := netip.ParseAddr(l.ClientIP); err == nil && ip.IsPrivate() {
					mac = devKey(neigh[l.ClientIP], l.ClientIP)
				} else if l.Device != nil {
					if m, ok := names[strings.ToLower(l.Device.Name)]; ok {
						mac = m
					} else {
						mac = "nextdns:" + l.Device.Name
					}
				}
				if mac != "" {
					blk := 0
					if l.Status == "blocked" {
						blk = 1
					}
					ts := l.Timestamp.Unix()
					_, _ = tx.Exec(`INSERT INTO dns_hour(hour, mac, domain, count, blocked) VALUES(?,?,?,?,?)
						ON CONFLICT(mac, hour, domain) DO UPDATE SET count=count+excluded.count, blocked=blocked+excluded.blocked`,
						ts-ts%3600, mac, d, 1-blk, blk)
				}
			}
		}
		if _, err := tx.Exec(`INSERT INTO settings(key, value) VALUES('nextdns.cursor_ts', ?) ON CONFLICT(key) DO UPDATE SET value=excluded.value`, last); err != nil {
			tx.Rollback()
			return err
		}
		if err := tx.Commit(); err != nil {
			return err
		}
		if resp.Meta.Pagination.Cursor == nil || *resp.Meta.Pagination.Cursor == "" || len(resp.Data) == 0 {
			break
		}
		cursor = *resp.Meta.Pagination.Cursor
	}
	return nil
}

func mustTime(s string) time.Time {
	t, err := time.Parse(time.RFC3339Nano, s)
	if err != nil {
		return time.Time{}
	}
	return t
}

// nextdnsInfo returns what NextDNS knows about a domain (block reasons / tracker).
type ndDomain struct {
	Status  string `json:"status"`
	Reasons string `json:"reasons"`
	Tracker string `json:"tracker"`
}

func (a *App) nextdnsDomain(d string) *ndDomain {
	var x ndDomain
	if a.db.QueryRow(`SELECT status, reasons, tracker FROM nextdns_domains WHERE domain=?`, d).Scan(&x.Status, &x.Reasons, &x.Tracker) != nil {
		return nil
	}
	return &x
}

// ---- analytics (proxied, cached 60 s) ----

type ndCacheEntry struct {
	at   time.Time
	data any
}

var (
	ndCacheMu sync.Mutex
	ndCache   = map[string]ndCacheEntry{}
)

// GET /api/nextdns/summary?range=1d|7d|30d
func (a *App) handleNextDNSSummary(w http.ResponseWriter, r *http.Request) {
	c, err := a.nextdns()
	if err != nil {
		writeJSON(w, 200, map[string]any{"configured": false, "error": err.Error()})
		return
	}
	rng := r.URL.Query().Get("range")
	if rng != "7d" && rng != "30d" && rng != "1h" {
		rng = "1d"
	}
	key := c.profile + rng
	ndCacheMu.Lock()
	if e, ok := ndCache[key]; ok && time.Since(e.at) < time.Minute {
		ndCacheMu.Unlock()
		writeJSON(w, 200, e.data)
		return
	}
	ndCacheMu.Unlock()

	from := "-" + rng
	type part struct {
		name, path string
		q          url.Values
	}
	parts := []part{
		{"status", "/analytics/status", url.Values{"from": {from}}},
		{"domains", "/analytics/domains", url.Values{"from": {from}, "limit": {"15"}}},
		{"blocked", "/analytics/domains", url.Values{"from": {from}, "limit": {"15"}, "status": {"blocked"}}},
		{"reasons", "/analytics/reasons", url.Values{"from": {from}, "limit": {"10"}}},
		{"devices", "/analytics/devices", url.Values{"from": {from}, "limit": {"20"}}},
		{"protocols", "/analytics/protocols", url.Values{"from": {from}}},
		{"destinations", "/analytics/destinations", url.Values{"from": {from}, "type": {"countries"}, "limit": {"10"}}},
		{"series", "/analytics/status;series", url.Values{"from": {from}, "interval": {seriesInterval(rng)}}},
	}
	out := map[string]any{"configured": true, "profile": c.profile, "range": rng}
	var mu sync.Mutex
	var wg sync.WaitGroup
	var firstErr error
	for _, p := range parts {
		wg.Add(1)
		go func(p part) {
			defer wg.Done()
			var resp map[string]any
			err := c.get(p.path, p.q, &resp)
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				if firstErr == nil {
					firstErr = err
				}
				return
			}
			out[p.name] = resp["data"]
			if p.name == "series" {
				out["series_meta"] = resp["meta"]
			}
		}(p)
	}
	wg.Wait()
	if firstErr != nil && out["status"] == nil {
		writeJSON(w, 200, map[string]any{"configured": true, "error": firstErr.Error()})
		return
	}
	var setup struct {
		AddMAC bool `json:"addmac"`
	}
	if cfg, err := a.agent.UciConfig("dhcp"); err == nil {
		for _, s := range cfg {
			if s[".type"] == "dnsmasq" && optStr(s, "addmac") == "1" {
				setup.AddMAC = true
			}
		}
	}
	out["per_device"] = setup.AddMAC
	ndCacheMu.Lock()
	ndCache[key] = ndCacheEntry{time.Now(), out}
	ndCacheMu.Unlock()
	writeJSON(w, 200, out)
}

func seriesInterval(rng string) string {
	switch rng {
	case "1h":
		return "300"
	case "7d":
		return "21600"
	case "30d":
		return "86400"
	}
	return "3600"
}

// GET /api/nextdns/logs?status=blocked&search=&device=
func (a *App) handleNextDNSLogs(w http.ResponseWriter, r *http.Request) {
	c, err := a.nextdns()
	if err != nil {
		jsonErr(w, 400, err.Error())
		return
	}
	q := url.Values{"limit": {"100"}}
	for _, k := range []string{"status", "search", "device", "cursor"} {
		if v := r.URL.Query().Get(k); v != "" {
			q.Set(k, v)
		}
	}
	var resp map[string]any
	if err := c.get("/logs", q, &resp); err != nil {
		jsonErr(w, 502, err.Error())
		return
	}
	writeJSON(w, 200, resp)
}

// POST /api/nextdns/per-device {enable} — dnsmasq add-mac so NextDNS can tell devices apart.
func (a *App) handleNextDNSPerDevice(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Enable bool `json:"enable"`
	}
	_ = readJSON(r, &req)
	cfg, err := a.agent.UciConfig("dhcp")
	if err != nil {
		jsonErr(w, 502, err.Error())
		return
	}
	for id, s := range cfg {
		if s[".type"] != "dnsmasq" {
			continue
		}
		var ch UciChange
		if req.Enable {
			ch = UciChange{Op: "set", Config: "dhcp", Section: id, Values: map[string]any{"addmac": "1"}}
		} else if optStr(s, "addmac") != "" {
			ch = UciChange{Op: "delete", Config: "dhcp", Section: id, Options: []string{"addmac"}}
		} else {
			break
		}
		res, err := a.agent.Apply(ch)
		if err != nil {
			jsonErr(w, 502, err.Error())
			return
		}
		a.audit(actor{user: currentUser(r), ip: a.clientIP(r)}, "nextdns.per_device", "uci", "dhcp."+id,
			map[bool]string{true: "开启 NextDNS 按设备识别（dnsmasq add-mac）", false: "关闭 NextDNS 按设备识别"}[req.Enable],
			res[0].Before, res[0].After, true)
		break
	}
	ndCacheMu.Lock()
	ndCache = map[string]ndCacheEntry{}
	ndCacheMu.Unlock()
	writeJSON(w, 200, map[string]bool{"ok": true})
}

// POST /api/nextdns/test {api_key, profile} — validate before saving.
func (a *App) handleNextDNSTest(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Key     string `json:"api_key"`
		Profile string `json:"profile"`
	}
	_ = readJSON(r, &req)
	if req.Key == "" {
		req.Key = a.setting("nextdns.api_key")
	}
	cl := &nextdnsClient{key: req.Key, http: &http.Client{Timeout: 15 * time.Second}}
	hr, _ := http.NewRequest("GET", nextdnsAPI+"/profiles", nil)
	hr.Header.Set("X-Api-Key", cl.key)
	resp, err := cl.http.Do(hr)
	if err != nil {
		jsonErr(w, 502, "NextDNS 不可达："+err.Error())
		return
	}
	defer resp.Body.Close()
	var out struct {
		Data []struct {
			ID, Name, Role string
		} `json:"data"`
	}
	if resp.StatusCode != 200 || json.NewDecoder(resp.Body).Decode(&out) != nil {
		jsonErr(w, 400, "API Key 无效")
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true, "profiles": out.Data})
}

func validNextDNSSetting(key, value string) (bool, error) {
	switch key {
	case "nextdns.api_key":
		if value != "" && !nextdnsKeyRe.MatchString(value) {
			return true, errors.New("NextDNS API Key 格式不正确（40 位十六进制）")
		}
		return true, nil
	case "nextdns.profile":
		if value != "" && !nextdnsProfileRe.MatchString(value) {
			return true, errors.New("NextDNS profile ID 格式不正确")
		}
		return true, nil
	case "dns.source":
		if value != "dnsmasq" && value != "nextdns" {
			return true, errors.New("DNS 数据来源只能是 dnsmasq 或 nextdns")
		}
		return true, nil
	}
	return false, nil
}

// maskSecret hides all but the last 4 characters.
func maskSecret(v string) string {
	if len(v) <= 4 {
		return strings.Repeat("•", len(v))
	}
	return strings.Repeat("•", 8) + v[len(v)-4:]
}
