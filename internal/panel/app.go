package panel

import (
	"database/sql"
	"encoding/json"
	"io"
	"io/fs"
	"log"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode/utf8"

	"github.com/wangsirco/wharf/internal/rules"
	"github.com/wangsirco/wharf/internal/tlsutil"
)

type App struct {
	cfg     Config
	db      *sql.DB
	agent   *AgentClient
	geo     *Geo
	secure  bool // cookies marked Secure (panel served over TLS)
	proxies []*net.IPNet
	limiter *loginLimiter
	beacons *loginLimiter
	web     fs.FS

	rules      *rules.Matcher
	idc        identCache
	hints      dnsHintCache
	neigh      neighCache
	blockedLog *loginLimiter
	policyMu   sync.Mutex
	policyAt   time.Time
	policyVal  accessPolicy
	pve        pveCache
	probes     probeIndex

	CA *tlsutil.LocalCA // set by main when the panel serves its own certificate (tls=auto)

	webCur atomic.Pointer[webState] // UI being served: built-in, or a newer downloaded bundle
}

func NewApp(cfg Config, db *sql.DB, web fs.FS) *App {
	a := &App{
		cfg: cfg, db: db, agent: NewAgentClient(cfg.Agent), web: web,
		secure:     cfg.TLS != "off",
		limiter:    newLimiter(8, 15*time.Minute),
		beacons:    newLimiter(60, time.Minute),
		blockedLog: newLimiter(1, time.Minute),
		geo:        NewGeo(cfg.Path("geo")),
		pve:        pveCache{kick: make(chan struct{}, 1)},
	}
	if m, err := rules.Default(cfg.Path("rules.json.gz")); err == nil {
		a.rules = m
	} else {
		log.Printf("rules: %v", err)
	}
	for _, p := range cfg.TrustedProxies {
		if !strings.Contains(p, "/") {
			p += map[bool]string{true: "/128", false: "/32"}[strings.Contains(p, ":")]
		}
		if _, n, err := net.ParseCIDR(p); err == nil {
			a.proxies = append(a.proxies, n)
		}
	}
	return a
}

// clientIP returns the peer address, or the forwarded address when the peer is a trusted proxy.
func (a *App) clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	peer := net.ParseIP(host)
	trusted := false
	for _, n := range a.proxies {
		if peer != nil && n.Contains(peer) {
			trusted = true
			break
		}
	}
	if !trusted {
		return host
	}
	if v := strings.TrimSpace(r.Header.Get("CF-Connecting-IP")); net.ParseIP(v) != nil {
		return v
	}
	// right-most address that is not itself a trusted proxy
	parts := strings.Split(r.Header.Get("X-Forwarded-For"), ",")
	for i := len(parts) - 1; i >= 0; i-- {
		ip := net.ParseIP(strings.TrimSpace(parts[i]))
		if ip == nil {
			continue
		}
		inProxy := false
		for _, n := range a.proxies {
			if n.Contains(ip) {
				inProxy = true
			}
		}
		if !inProxy {
			return ip.String()
		}
	}
	if v := strings.TrimSpace(r.Header.Get("X-Real-IP")); net.ParseIP(v) != nil {
		return v
	}
	return host
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func jsonErr(w http.ResponseWriter, code int, msg string) {
	writeJSON(w, code, map[string]string{"error": msg})
}

func readJSON(r *http.Request, v any) error {
	return json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(v)
}

func truncate(s string, n int) string {
	if utf8.RuneCountInString(s) <= n {
		return s
	}
	return string([]rune(s)[:n])
}

func pathID(r *http.Request) int64 {
	id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
	return id
}

func mustJSON(v any) string {
	if v == nil {
		return ""
	}
	b, _ := json.Marshal(v)
	return string(b)
}

// ---- settings ----

var settingDefaults = map[string]string{
	"approval.required":         `["device.static.delete", "forward.delete"]`,
	"approval.expire_hours":     "24",
	"approval.forward_open_all": "1", // admins opening a forward to everyone need approval
	"retention.audit_days":      "365",
	"retention.visitor_days":    "90",
	"retention.traffic_days":    "7",
	"retention.traffic_mb":      "1024",
	"rules.update_hours":        "72",
	"presence.away_minutes":     "10",              // unseen this long = left the network
	"ui.name":                   "Wharf",           // panel name on the login page, sidebar and browser tab
	"ui.subtitle":               "OpenWrt 控制面板",    //
	"update.repo":               "wangsirco/wharf", // GitHub owner/name the online update uses
	"update.check":              "1",
}

func (a *App) setting(key string) string {
	var v string
	if a.db.QueryRow(`SELECT value FROM settings WHERE key=?`, key).Scan(&v) == nil {
		return v
	}
	return settingDefaults[key]
}

func (a *App) settingInt(key string) int {
	n, _ := strconv.Atoi(a.setting(key))
	return n
}

func (a *App) setSetting(key, value string) error {
	a.policyMu.Lock()
	a.policyAt = time.Time{} // invalidate cached access policy
	a.policyMu.Unlock()
	_, err := a.db.Exec(`INSERT INTO settings(key, value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value`, key, value)
	return err
}

func (a *App) allSettings() map[string]string {
	out := map[string]string{}
	for k, v := range settingDefaults {
		out[k] = v
	}
	rows, err := a.db.Query(`SELECT key, value FROM settings`)
	if err != nil {
		return out
	}
	defer rows.Close()
	for rows.Next() {
		var k, v string
		if rows.Scan(&k, &v) == nil {
			out[k] = v
		}
	}
	return out
}

// ---- housekeeping ----

func (a *App) housekeeping() {
	for {
		now := time.Now()
		day := int64(24 * 3600)
		_, _ = a.db.Exec(`DELETE FROM audit WHERE ts < ?`, now.Unix()-int64(a.settingInt("retention.audit_days"))*day)
		_, _ = a.db.Exec(`DELETE FROM visitors WHERE ts < ?`, now.Unix()-int64(a.settingInt("retention.visitor_days"))*day)
		_, _ = a.db.Exec(`DELETE FROM sessions WHERE seen_at < ?`, now.Add(-sessionIdle).Unix())
		_, _ = a.db.Exec(`DELETE FROM alert_log WHERE ts < ?`, now.Unix()-90*86400)
		_, _ = a.db.Exec(`DELETE FROM device_events WHERE ts < ?`, now.Unix()-90*86400)
		_, _ = a.db.Exec(`UPDATE approvals SET status='expired' WHERE status='pending' AND ts < ?`,
			now.Unix()-int64(a.settingInt("approval.expire_hours"))*3600)
		a.trafficRetention()
		time.Sleep(10 * time.Minute)
	}
}

func (a *App) Start() {
	a.loadWebOverride()
	go a.housekeeping()
	go a.geo.AutoUpdate()
	go a.collector()
	go a.autoProbe()
	go a.rulesAutoUpdate()
	go a.nextdnsPuller()
	go a.pveLoop()
	go a.cacheLoop()
	go a.geoWarmLoop()
	go a.updateLoop()
	go a.presenceLoop()
	go a.monitorLoop()
	go a.alertEngine()
	log.Printf("panel ready")
}

// cacheLoop refreshes in-memory lookups that request handlers read without
// touching the database (see probeIndex for why).
func (a *App) cacheLoop() {
	for {
		a.loadProbeIndex()
		a.refreshDNSHints()
		time.Sleep(5 * time.Minute)
	}
}
