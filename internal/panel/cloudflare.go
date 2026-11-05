package panel

import (
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Cloudflare account: one API token for everything the panel does there (DDNS records,
// the panel's own names and their certificate). With it the panel can list the account's
// domains and their records, so a record is picked or created instead of typed.
//
// Signing in with the Cloudflare account itself (OAuth) needs an OAuth client registered
// with Cloudflare and a fixed callback address, which a panel at wharf.lan or an IP
// cannot offer; the token page opens pre-filled instead (cfTokenURL), one click away.

// cfTokenURL opens Cloudflare's "create token" page with the right permissions chosen:
// read the zones, edit their DNS records, and create origin certificates. (Origin Rules,
// for panel names behind the orange cloud, cannot be pre-filled: added by hand.)
const cfTokenURL = "https://dash.cloudflare.com/profile/api-tokens?permissionGroupKeys=" +
	"%5B%7B%22key%22%3A%22zone%22%2C%22type%22%3A%22read%22%7D%2C%7B%22key%22%3A%22dns%22%2C%22type%22%3A%22edit%22%7D%2C" +
	"%7B%22key%22%3A%22ssl_and_certificates%22%2C%22type%22%3A%22edit%22%7D%5D" +
	"&accountId=%2A&zoneId=all&name=Wharf"

// cfAccountToken is the stored account token (set by the App so DDNS can use it).
var cfAccountToken = func() string { return "" }

// accountTokenMarker in a DDNS entry's credentials means "use the account token".
const accountTokenMarker = "@account"

func cfTokenOf(t string) string {
	if t == accountTokenMarker || t == "" {
		return cfAccountToken()
	}
	return t
}

type cfZoneInfo struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

type cfRecord struct {
	ID      string `json:"id"`
	Type    string `json:"type"`
	Name    string `json:"name"`
	Content string `json:"content"`
	Proxied bool   `json:"proxied"`
	TTL     int    `json:"ttl"`
}

var cfZonesCache struct {
	sync.Mutex
	token string
	at    time.Time
	zones []cfZoneInfo
	err   string
}

// cfZones lists the zones the token can see (cached for 5 minutes).
func cfZones(token string, fresh bool) ([]cfZoneInfo, error) {
	cfZonesCache.Lock()
	defer cfZonesCache.Unlock()
	if !fresh && cfZonesCache.token == token && time.Since(cfZonesCache.at) < 5*time.Minute && cfZonesCache.zones != nil {
		return cfZonesCache.zones, nil
	}
	call := cfCall(token)
	var out []cfZoneInfo
	for page := 1; page <= 10; page++ {
		var zs []cfZoneInfo
		if err := call("GET", "/zones?per_page=50&page="+strconv.Itoa(page), nil, &zs); err != nil {
			return nil, err
		}
		out = append(out, zs...)
		if len(zs) < 50 {
			break
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	cfZonesCache.token, cfZonesCache.at, cfZonesCache.zones = token, time.Now(), out
	return out, nil
}

// GET /api/cloudflare — the account connection and its domains (super).
func (a *App) handleCloudflare(w http.ResponseWriter, r *http.Request) {
	tok := a.setting("cloudflare.token")
	out := map[string]any{"connected": tok != "", "token": maskSecret(tok), "create_url": cfTokenURL, "zones": []cfZoneInfo{}}
	if tok != "" {
		zs, err := cfZones(tok, r.URL.Query().Get("fresh") == "1")
		if err != nil {
			out["error"] = err.Error()
		} else {
			out["zones"] = zs
		}
	}
	writeJSON(w, 200, out)
}

// POST /api/cloudflare {token} — connect (checked against Cloudflare) or disconnect ("").
func (a *App) handleCloudflareSave(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Token string `json:"token"`
	}
	if readJSON(r, &req) != nil {
		jsonErr(w, 400, "请求格式错误")
		return
	}
	tok := strings.TrimSpace(req.Token)
	if tok != "" {
		var v struct {
			Status string `json:"status"`
		}
		if err := cfCall(tok)("GET", "/user/tokens/verify", nil, &v); err != nil {
			jsonErr(w, 400, "令牌无效："+err.Error())
			return
		}
		if v.Status != "active" {
			jsonErr(w, 400, "令牌状态是 "+v.Status+"，不能使用")
			return
		}
		zs, err := cfZones(tok, true)
		if err != nil {
			jsonErr(w, 400, "令牌没有读取域名的权限："+err.Error())
			return
		}
		if len(zs) == 0 {
			jsonErr(w, 400, "这个令牌看不到任何域名：创建时「区域资源」请选「所有区域」或你的域名")
			return
		}
	}
	if tok == "" && a.cfAccountInUse() {
		jsonErr(w, 400, "还有 DDNS 记录或面板域名在使用 Cloudflare 账户，请先删除它们或换成单独的令牌")
		return
	}
	_ = a.setSetting("cloudflare.token", tok)
	what := "连接 Cloudflare 账户"
	if tok == "" {
		what = "断开 Cloudflare 账户"
	}
	a.audit(actor{user: currentUser(r), ip: a.clientIP(r)}, "setting.update", "setting", "cloudflare.token", what, nil, nil, false)
	a.handleCloudflare(w, r)
}

func (a *App) cfAccountInUse() bool {
	list, _ := a.ddnsList()
	for _, d := range list {
		if d.Provider == "cloudflare" && d.Creds["token"] == accountTokenMarker {
			return true
		}
	}
	return len(a.publicNames()) > 0 && a.setting("panel.cf_token") == ""
}

// GET /api/cloudflare/records?zone=<id> — the zone's address records (super).
func (a *App) handleCloudflareRecords(w http.ResponseWriter, r *http.Request) {
	tok := a.setting("cloudflare.token")
	if tok == "" {
		jsonErr(w, 400, "还没有连接 Cloudflare 账户")
		return
	}
	zone := r.URL.Query().Get("zone")
	if zone == "" || strings.ContainsAny(zone, "/?&#") {
		jsonErr(w, 400, "请选择域名")
		return
	}
	var recs []cfRecord
	if err := cfCall(tok)("GET", "/zones/"+url.PathEscape(zone)+"/dns_records?per_page=500", nil, &recs); err != nil {
		jsonErr(w, 400, err.Error())
		return
	}
	out := []cfRecord{}
	for _, x := range recs {
		if x.Type == "A" || x.Type == "AAAA" || x.Type == "CNAME" {
			out = append(out, x)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	writeJSON(w, 200, out)
}
