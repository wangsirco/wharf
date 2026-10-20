package panel

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"slices"
	"strings"
	"sync"
	"time"
)

// Panel access control (who may open the panel at all).
//
//	LAN clients (private source IP, panel running next to the agent): by device MAC,
//	  mode all | whitelist | blacklist.
//	WAN clients: mode all | restrict (allowed regions "NZ" / "NZ/Auckland").
//	Always: allow_ips (override) and deny_ips (single IPs or CIDRs).
//	Browser timezone (optional allow-list) is checked at login, since only the browser knows it.
//
// Decisions only use the server-observed IP and the offline database; values the
// browser reports (timezone, ip.sb) are advisory except for the login timezone gate.

type accessPolicy struct {
	LanMode   string   // all | whitelist | blacklist
	LanMACs   []string //
	WanMode   string   // all | restrict
	Regions   []string // NZ, NZ/Auckland
	Timezones []string // IANA names; empty = no check
	AllowIPs  []netip.Prefix
	DenyIPs   []netip.Prefix
}

var accessSettingDefaults = map[string]string{
	"access.lan.mode":      "all",
	"access.lan.macs":      "[]",
	"access.wan.mode":      "restrict",
	"access.wan.regions":   `["NZ"]`,
	"access.wan.timezones": "[]",
	"access.allow_ips":     "[]",
	"access.deny_ips":      "[]",
	"access.ipsb":          "1",
}

func init() {
	for k, v := range accessSettingDefaults {
		settingDefaults[k] = v
	}
}

func parsePrefixes(list []string) ([]netip.Prefix, error) {
	var out []netip.Prefix
	for _, s := range list {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		if !strings.Contains(s, "/") {
			a, err := netip.ParseAddr(s)
			if err != nil {
				return nil, fmt.Errorf("无效 IP：%s", s)
			}
			out = append(out, netip.PrefixFrom(a, a.BitLen()))
			continue
		}
		p, err := netip.ParsePrefix(s)
		if err != nil {
			return nil, fmt.Errorf("无效 IP 段：%s", s)
		}
		out = append(out, p.Masked())
	}
	return out, nil
}

func (a *App) settingList(key string) []string {
	var out []string
	_ = json.Unmarshal([]byte(a.setting(key)), &out)
	return out
}

// policyFrom builds a policy from a settings getter (current settings or a draft).
func policyFrom(get func(string) string) accessPolicy {
	list := func(k string) []string {
		var out []string
		_ = json.Unmarshal([]byte(get(k)), &out)
		return out
	}
	p := accessPolicy{
		LanMode: get("access.lan.mode"), LanMACs: list("access.lan.macs"),
		WanMode: get("access.wan.mode"), Regions: list("access.wan.regions"),
		Timezones: list("access.wan.timezones"),
	}
	p.AllowIPs, _ = parsePrefixes(list("access.allow_ips"))
	p.DenyIPs, _ = parsePrefixes(list("access.deny_ips"))
	return p
}

// policy is read on every request, so it is cached briefly (setSetting invalidates it).
func (a *App) policy() accessPolicy {
	a.policyMu.Lock()
	defer a.policyMu.Unlock()
	if time.Since(a.policyAt) < 5*time.Second {
		return a.policyVal
	}
	a.policyVal, a.policyAt = policyFrom(a.setting), time.Now()
	return a.policyVal
}

func inPrefixes(ip netip.Addr, ps []netip.Prefix) bool {
	for _, p := range ps {
		if p.Contains(ip) {
			return true
		}
	}
	return false
}

// panelIsLocal: LAN-by-MAC rules only make sense when the panel sits on the router's LAN.
func (a *App) panelIsLocal() bool {
	u, err := url.Parse(a.cfg.Agent.URL)
	if err != nil {
		return false
	}
	ip := net.ParseIP(u.Hostname())
	return ip != nil && (ip.IsLoopback() || ip.IsPrivate())
}

// neighbour cache: LAN IP -> MAC from the agent
type neighCache struct {
	mu   sync.Mutex
	at   time.Time
	data map[string]string
}

func (a *App) macOf(ip string) string {
	c := &a.neigh
	c.mu.Lock()
	defer c.mu.Unlock()
	if time.Since(c.at) > 15*time.Second || c.data[ip] == "" && time.Since(c.at) > 2*time.Second {
		var m map[string]string
		if err := a.agent.Do("GET", "/v1/neigh", nil, &m); err == nil {
			c.data, c.at = m, time.Now()
		}
	}
	return c.data[ip]
}

type accessResult struct {
	ok     bool
	reason string
	mac    string
}

func (a *App) checkAccess(ipStr string) accessResult {
	return a.checkAccessWith(a.policy(), ipStr)
}

func (a *App) checkAccessWith(p accessPolicy, ipStr string) accessResult {
	ip, err := netip.ParseAddr(ipStr)
	if err != nil {
		return accessResult{false, "无法识别来源 IP", ""}
	}
	ip = ip.Unmap()
	if ip.IsLoopback() {
		return accessResult{ok: true}
	}
	if inPrefixes(ip, p.DenyIPs) {
		return accessResult{false, "IP 在黑名单中", ""}
	}
	if inPrefixes(ip, p.AllowIPs) {
		return accessResult{ok: true}
	}
	if ip.IsPrivate() || ip.IsLinkLocalUnicast() {
		if !a.panelIsLocal() || p.LanMode == "all" {
			return accessResult{ok: true}
		}
		mac := a.macOf(ip.String())
		listed := mac != "" && slices.ContainsFunc(p.LanMACs, func(m string) bool { return strings.EqualFold(m, mac) })
		switch p.LanMode {
		case "whitelist":
			if !listed {
				return accessResult{false, "内网设备不在白名单中", mac}
			}
		case "blacklist":
			if listed {
				return accessResult{false, "内网设备在黑名单中", mac}
			}
		}
		return accessResult{ok: true, mac: mac}
	}
	if p.WanMode != "restrict" {
		return accessResult{ok: true}
	}
	if !a.geo.Ready() {
		// fail open rather than locking everyone out before the database is downloaded
		return accessResult{ok: true, reason: "IP 库未就绪，未做地区检查"}
	}
	country, region := a.geo.RegionOf(ip.String())
	if country != "" && (slices.Contains(p.Regions, country) || (region != "" && slices.Contains(p.Regions, region))) {
		return accessResult{ok: true}
	}
	where := country
	if region != "" {
		where = region
	}
	if where == "" {
		where = "未知地区"
	}
	return accessResult{false, "来源地区不在允许范围：" + where, ""}
}

// timezoneAllowed is checked at login for WAN clients when a timezone allow-list is set.
func (a *App) timezoneAllowed(ipStr, tz string) bool {
	tzs := a.settingList("access.wan.timezones")
	if len(tzs) == 0 {
		return true
	}
	if ip, err := netip.ParseAddr(ipStr); err == nil && (ip.IsLoopback() || ip.IsPrivate()) {
		return true
	}
	return slices.Contains(tzs, tz)
}

const deniedPage = `<!doctype html><html lang="zh-CN"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>拒绝访问</title>
<style>body{margin:0;min-height:100vh;display:grid;place-items:center;font-family:system-ui,-apple-system,"PingFang SC","Microsoft YaHei",sans-serif;background:#f6f7f9;color:#1f2329}
@media(prefers-color-scheme:dark){body{background:#17181b;color:#e8e9eb}.c{background:#202227!important;border-color:#2c2f35!important}}
.c{background:#fff;border:1px solid #e6e8eb;border-radius:16px;padding:40px 36px;max-width:380px;text-align:center}
.i{width:48px;height:48px;border-radius:12px;background:#fdecec;color:#d93026;display:grid;place-items:center;margin:0 auto 16px;font-size:24px;font-weight:700}
h1{font-size:20px;margin:0 0 8px}p{margin:0;color:#7a7f87;font-size:14px;line-height:1.6}code{font-size:12px}</style></head>
<body><div class="c"><div class="i">!</div><h1>拒绝访问</h1><p>你所在的网络或设备没有访问此面板的权限。</p><p style="margin-top:12px"><code>%s</code></p></div></body></html>`

// accessGate wraps the whole handler.
func (a *App) accessGate(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip := a.clientIP(r)
		res := a.checkAccess(ip)
		if res.ok {
			h.ServeHTTP(w, r)
			return
		}
		a.logBlocked(r, ip, res)
		if strings.HasPrefix(r.URL.Path, "/api/") {
			writeJSON(w, http.StatusForbidden, map[string]any{"error": "拒绝访问：" + res.reason, "blocked": true})
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		w.WriteHeader(http.StatusForbidden)
		fmt.Fprintf(w, deniedPage, ip)
	})
}

func (a *App) logBlocked(r *http.Request, ip string, res accessResult) {
	key := "blk:" + ip
	if a.blockedLog.blocked(key) {
		return
	}
	a.blockedLog.record(key)
	g := a.geo.Lookup(ip)
	_, _ = a.db.Exec(`INSERT INTO visitors(ts, ip, asn, as_org, country, region, city, ip_tz, tz_match, user_agent, path, blocked, reason, mac)
		VALUES(?,?,?,?,?,?,?,?,'unknown',?,?,1,?,?)`,
		time.Now().Unix(), ip, g.ASN, g.ASOrg, g.Country, g.Region, g.City, g.TZ,
		truncate(r.UserAgent(), 300), truncate(r.URL.Path, 200), res.reason, res.mac)
}

// ---- settings validation for access.* ----

func validAccessSetting(key, value string) (bool, error) {
	if _, ok := accessSettingDefaults[key]; !ok {
		return false, nil
	}
	list := func() ([]string, error) {
		var l []string
		if json.Unmarshal([]byte(value), &l) != nil {
			return nil, fmt.Errorf("%s 必须是 JSON 数组", key)
		}
		return l, nil
	}
	switch key {
	case "access.lan.mode":
		if value != "all" && value != "whitelist" && value != "blacklist" {
			return true, fmt.Errorf("无效的内网模式")
		}
	case "access.wan.mode":
		if value != "all" && value != "restrict" {
			return true, fmt.Errorf("无效的公网模式")
		}
	case "access.ipsb":
		if value != "0" && value != "1" {
			return true, fmt.Errorf("access.ipsb 只能是 0 或 1")
		}
	case "access.lan.macs":
		l, err := list()
		if err != nil {
			return true, err
		}
		for _, m := range l {
			if hw, err := net.ParseMAC(m); err != nil || len(hw) != 6 {
				return true, fmt.Errorf("无效 MAC：%s", m)
			}
		}
	case "access.wan.regions":
		l, err := list()
		if err != nil {
			return true, err
		}
		for _, k := range l {
			if !validRegionKey(k) {
				return true, fmt.Errorf("无效地区：%s", k)
			}
		}
	case "access.wan.timezones":
		l, err := list()
		if err != nil {
			return true, err
		}
		for _, tz := range l {
			if _, err := time.LoadLocation(tz); err != nil || tz == "" || tz == "Local" {
				return true, fmt.Errorf("无效时区：%s", tz)
			}
		}
	case "access.allow_ips", "access.deny_ips":
		l, err := list()
		if err != nil {
			return true, err
		}
		if _, err := parsePrefixes(l); err != nil {
			return true, err
		}
	}
	return true, nil
}

// ResetAccess makes the panel reachable again (used from the LuCI page).
func ResetAccess(a *App) error {
	for k, v := range map[string]string{"access.lan.mode": "all", "access.wan.mode": "all", "access.deny_ips": "[]"} {
		if err := a.setSetting(k, v); err != nil {
			return err
		}
	}
	return nil
}

// lanMAC returns the MAC of a LAN client (for logging), "" for WAN clients.
func (a *App) lanMAC(ipStr string) string {
	ip, err := netip.ParseAddr(ipStr)
	if err != nil || !ip.Unmap().IsPrivate() || !a.panelIsLocal() {
		return ""
	}
	return a.macOf(ip.Unmap().String())
}

// GET /api/access/me — what the panel sees about the current visitor.
func (a *App) handleAccessMe(w http.ResponseWriter, r *http.Request) {
	ip := a.clientIP(r)
	g := a.geo.Lookup(ip)
	country, region := a.geo.RegionOf(ip)
	writeJSON(w, 200, map[string]any{
		"ip": ip, "country": country, "region": region, "as_org": g.ASOrg, "tz": g.TZ,
		"mac": a.lanMAC(ip), "local": a.panelIsLocal(),
	})
}
