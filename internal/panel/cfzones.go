package panel

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
)

// Cloudflare page, the rest: what the token can do, the domains with attack mode, cache
// purge and the last week's edge statistics, and Access (an email code before anyone
// even sees the panel's login page).
//
// Berth (the server panel) can manage the same Cloudflare account. Everything here is
// read live from Cloudflare, so both panels always show the same state; Wharf only
// creates and deletes its own objects (its tunnel, records pointing at it, Access apps
// named "Wharf · …") and lists the others read-only.

var zoneIDRe = regexp.MustCompile(`^[a-f0-9]{32}$`)

// GET /api/cloudflare/caps?fresh=1
func (a *App) handleCFCaps(w http.ResponseWriter, r *http.Request) {
	tok, err := a.cfToken()
	if err != nil {
		writeJSON(w, 200, map[string]any{"connected": false})
		return
	}
	writeJSON(w, 200, map[string]any{"connected": true, "caps": cfCapabilities(tok, r.URL.Query().Get("fresh") == "1")})
}

type cfZoneRow struct {
	ID       string   `json:"id"`
	Name     string   `json:"name"`
	Status   string   `json:"status"`
	Plan     string   `json:"plan"`
	Paused   bool     `json:"paused"`
	Security string   `json:"security_level,omitempty"` // essentially_off | low | medium | high | under_attack
	UsedBy   []string `json:"used_by"`                  // what of Wharf's is under this domain
	Berth    []string `json:"berth,omitempty"`          // Berth's names under it (when paired)
}

// GET /api/cloudflare/zones
func (a *App) handleCFZones(w http.ResponseWriter, r *http.Request) {
	tok, err := a.cfToken()
	if err != nil {
		jsonErr(w, 400, err.Error())
		return
	}
	var zs []struct {
		ID     string `json:"id"`
		Name   string `json:"name"`
		Status string `json:"status"`
		Paused bool   `json:"paused"`
		Plan   struct {
			Name string `json:"name"`
		} `json:"plan"`
	}
	if err := cfDo(tok, "GET", "/zones?per_page=50", nil, &zs); err != nil {
		jsonErr(w, 400, err.Error())
		return
	}
	// what Wharf has under each domain
	type use struct{ name, what string }
	var uses []use
	for _, n := range a.publicNames() {
		uses = append(uses, use{n, "面板域名 " + n})
	}
	for _, rt := range a.tunnelConf().Routes {
		uses = append(uses, use{rt.Hostname, "隧道 " + rt.Hostname})
	}
	if list, err := a.ddnsList(); err == nil {
		for _, d := range list {
			if d.Provider == "cloudflare" {
				uses = append(uses, use{d.Domain, "DDNS " + d.Domain})
			}
		}
	}
	var berthNames []string
	if reg := a.berthSNI(); reg != nil {
		berthNames = reg.Domains
	}
	under := func(name, zone string) bool { return name == zone || strings.HasSuffix(name, "."+zone) }
	out := make([]cfZoneRow, len(zs))
	var wg sync.WaitGroup
	for i, z := range zs {
		out[i] = cfZoneRow{ID: z.ID, Name: z.Name, Status: z.Status, Plan: z.Plan.Name, Paused: z.Paused, UsedBy: []string{}}
		for _, u := range uses {
			if under(strings.TrimPrefix(u.name, "*."), z.Name) {
				out[i].UsedBy = append(out[i].UsedBy, u.what)
			}
		}
		for _, n := range berthNames {
			if under(strings.TrimPrefix(n, "*."), z.Name) {
				out[i].Berth = append(out[i].Berth, n)
			}
		}
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			var s struct {
				Value string `json:"value"`
			}
			if cfDo(tok, "GET", "/zones/"+out[i].ID+"/settings/security_level", nil, &s) == nil {
				out[i].Security = s.Value
			}
		}(i)
	}
	wg.Wait()
	sort.Slice(out, func(i, j int) bool {
		return len(out[i].UsedBy) > len(out[j].UsedBy) || (len(out[i].UsedBy) == len(out[j].UsedBy) && out[i].Name < out[j].Name)
	})
	writeJSON(w, 200, out)
}

// POST /api/cloudflare/zones/{id}/attack {on}
func (a *App) handleCFAttack(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	var req struct {
		On bool `json:"on"`
	}
	if !zoneIDRe.MatchString(id) || readJSON(r, &req) != nil {
		jsonErr(w, 400, "请求格式错误")
		return
	}
	tok, err := a.cfToken()
	if err != nil {
		jsonErr(w, 400, err.Error())
		return
	}
	var cur struct {
		Value string `json:"value"`
	}
	if err := cfDo(tok, "GET", "/zones/"+id+"/settings/security_level", nil, &cur); err != nil {
		jsonErr(w, 400, permHint(err, "区域 · Zone Settings · 编辑"))
		return
	}
	next := "under_attack"
	if !req.On {
		next = a.setting("cf.prev_security." + id)
		if next == "" || next == "under_attack" {
			next = "medium"
		}
	} else if cur.Value != "under_attack" {
		_ = a.setSetting("cf.prev_security."+id, cur.Value)
	}
	if err := cfDo(tok, "PATCH", "/zones/"+id+"/settings/security_level", map[string]string{"value": next}, nil); err != nil {
		jsonErr(w, 400, permHint(err, "区域 · Zone Settings · 编辑"))
		return
	}
	what := "开启受攻击模式"
	if !req.On {
		what = "关闭受攻击模式（恢复为 " + next + "）"
	}
	a.audit(actor{user: currentUser(r), ip: a.clientIP(r)}, "cloudflare.attack", "zone", id, what+"："+a.zoneName(tok, id), map[string]string{"security_level": cur.Value}, map[string]string{"security_level": next}, false)
	writeJSON(w, 200, map[string]string{"security_level": next})
}

// POST /api/cloudflare/zones/{id}/purge
func (a *App) handleCFPurge(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if !zoneIDRe.MatchString(id) {
		jsonErr(w, 400, "请求格式错误")
		return
	}
	tok, err := a.cfToken()
	if err != nil {
		jsonErr(w, 400, err.Error())
		return
	}
	if err := cfDo(tok, "POST", "/zones/"+id+"/purge_cache", map[string]bool{"purge_everything": true}, nil); err != nil {
		jsonErr(w, 400, permHint(err, "区域 · Cache Purge · 清除"))
		return
	}
	a.audit(actor{user: currentUser(r), ip: a.clientIP(r)}, "cloudflare.purge", "zone", id, "清除 Cloudflare 缓存："+a.zoneName(tok, id), nil, nil, false)
	writeJSON(w, 200, map[string]bool{"ok": true})
}

// GET /api/cloudflare/zones/{id}/stats — the last 7 days at Cloudflare's edge
func (a *App) handleCFStats(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if !zoneIDRe.MatchString(id) {
		jsonErr(w, 400, "请求格式错误")
		return
	}
	tok, err := a.cfToken()
	if err != nil {
		jsonErr(w, 400, err.Error())
		return
	}
	since := time.Now().AddDate(0, 0, -7).Format("2006-01-02")
	var out struct {
		Viewer struct {
			Zones []struct {
				Days []struct {
					Dimensions struct {
						Date string `json:"date"`
					} `json:"dimensions"`
					Sum struct {
						Requests       int64 `json:"requests"`
						Bytes          int64 `json:"bytes"`
						CachedRequests int64 `json:"cachedRequests"`
						Threats        int64 `json:"threats"`
					} `json:"sum"`
					Uniq struct {
						Uniques int64 `json:"uniques"`
					} `json:"uniq"`
				} `json:"httpRequests1dGroups"`
			} `json:"zones"`
		} `json:"viewer"`
	}
	q := `query($z:String!,$d:Date!){viewer{zones(filter:{zoneTag:$z}){httpRequests1dGroups(limit:8,filter:{date_geq:$d},orderBy:[date_ASC]){dimensions{date} sum{requests bytes cachedRequests threats} uniq{uniques}}}}}`
	if err := cfGraphQL(tok, q, map[string]any{"z": id, "d": since}, &out); err != nil {
		jsonErr(w, 400, permHint(err, "区域 · Analytics · 读取"))
		return
	}
	type day struct {
		Date     string `json:"date"`
		Requests int64  `json:"requests"`
		Bytes    int64  `json:"bytes"`
		Cached   int64  `json:"cached"`
		Threats  int64  `json:"threats"`
		Uniques  int64  `json:"uniques"`
	}
	days := []day{}
	if len(out.Viewer.Zones) > 0 {
		for _, d := range out.Viewer.Zones[0].Days {
			days = append(days, day{d.Dimensions.Date, d.Sum.Requests, d.Sum.Bytes, d.Sum.CachedRequests, d.Sum.Threats, d.Uniq.Uniques})
		}
	}
	writeJSON(w, 200, days)
}

func permHint(err error, perm string) string {
	if isDenied(err) {
		return "令牌缺少「" + perm + "」权限，请在 Cloudflare 给这个令牌加上"
	}
	return err.Error()
}

func (a *App) zoneName(tok, id string) string {
	if zs, err := cfZones(tok, false); err == nil {
		for _, z := range zs {
			if z.ID == id {
				return z.Name
			}
		}
	}
	return id
}

// ---- Access ----

type cfAccessApp struct {
	ID              string   `json:"id"`
	Name            string   `json:"name"`
	Domain          string   `json:"domain"`
	Type            string   `json:"type"`
	SessionDuration string   `json:"session_duration"`
	Emails          []string `json:"emails,omitempty"` // Wharf's apps: who may pass
	Mine            bool     `json:"mine"`
}

const accessPrefix = "Wharf · "

// GET /api/cloudflare/access
func (a *App) handleCFAccess(w http.ResponseWriter, r *http.Request) {
	tok, err := a.cfToken()
	if err != nil {
		jsonErr(w, 400, err.Error())
		return
	}
	acc, err := cfAccountOf(tok)
	if err != nil {
		jsonErr(w, 400, err.Error())
		return
	}
	var apps []cfAccessApp
	if err := cfDo(tok, "GET", "/accounts/"+acc.ID+"/access/apps?per_page=100", nil, &apps); err != nil {
		writeJSON(w, 200, map[string]any{"apps": []cfAccessApp{}, "error": permHint(err, "账户 · Access: Apps and Policies · 编辑"), "denied": isDenied(err)})
		return
	}
	out := []cfAccessApp{}
	for _, x := range apps {
		if x.Type != "self_hosted" {
			continue
		}
		x.Mine = strings.HasPrefix(x.Name, accessPrefix)
		if x.Mine {
			x.Emails = accessEmails(tok, acc.ID, x.ID)
		}
		out = append(out, x)
	}
	// names that can be protected: the panel's public / tunnel names
	names := append(append([]string{}, a.publicNames()...), a.tunnelPanelNames()...)
	writeJSON(w, 200, map[string]any{"apps": out, "names": names, "account": acc})
}

func accessEmails(tok, acc, app string) []string {
	var pols []struct {
		Include []map[string]map[string]string `json:"include"`
	}
	if cfDo(tok, "GET", "/accounts/"+acc+"/access/apps/"+app+"/policies", nil, &pols) != nil {
		return nil
	}
	var out []string
	for _, p := range pols {
		for _, inc := range p.Include {
			if e := inc["email"]["email"]; e != "" {
				out = append(out, e)
			}
			if d := inc["email_domain"]["domain"]; d != "" {
				out = append(out, "@"+d)
			}
		}
	}
	return out
}

var emailRe = regexp.MustCompile(`^[^@\s]+@[^@\s]+\.[^@\s]+$|^@[^@\s]+\.[^@\s]+$`)

// POST /api/cloudflare/access {hostname, emails, hours}: protect a name (create or update)
func (a *App) handleCFAccessSave(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Hostname string   `json:"hostname"`
		Emails   []string `json:"emails"`
		Hours    int      `json:"hours"`
	}
	if readJSON(r, &req) != nil {
		jsonErr(w, 400, "请求格式错误")
		return
	}
	host := strings.ToLower(strings.TrimSpace(req.Hostname))
	if !fqdnRe.MatchString(host) {
		jsonErr(w, 400, "名字不对")
		return
	}
	var include []map[string]any
	var emails []string
	for _, e := range req.Emails {
		e = strings.ToLower(strings.TrimSpace(e))
		if e == "" {
			continue
		}
		if !emailRe.MatchString(e) {
			jsonErr(w, 400, "邮箱格式不对："+e)
			return
		}
		emails = append(emails, e)
		if strings.HasPrefix(e, "@") {
			include = append(include, map[string]any{"email_domain": map[string]string{"domain": e[1:]}})
		} else {
			include = append(include, map[string]any{"email": map[string]string{"email": e}})
		}
	}
	if len(include) == 0 {
		jsonErr(w, 400, "至少填一个允许的邮箱")
		return
	}
	if req.Hours <= 0 || req.Hours > 720 {
		req.Hours = 24
	}
	tok, err := a.cfToken()
	if err != nil {
		jsonErr(w, 400, err.Error())
		return
	}
	acc, err := cfAccountOf(tok)
	if err != nil {
		jsonErr(w, 400, err.Error())
		return
	}
	var apps []cfAccessApp
	if err := cfDo(tok, "GET", "/accounts/"+acc.ID+"/access/apps?per_page=100", nil, &apps); err != nil {
		jsonErr(w, 400, accessErr(err))
		return
	}
	var app *cfAccessApp
	for i := range apps {
		if strings.EqualFold(apps[i].Domain, host) {
			if !strings.HasPrefix(apps[i].Name, accessPrefix) {
				jsonErr(w, 409, host+" 已经有别人建的 Access 应用「"+apps[i].Name+"」（可能是 Berth 或你在 Cloudflare 后台建的），Wharf 不改它")
				return
			}
			app = &apps[i]
		}
	}
	body := map[string]any{"name": accessPrefix + host, "domain": host, "type": "self_hosted", "session_duration": jsonHours(req.Hours), "app_launcher_visible": false}
	if app == nil {
		var created cfAccessApp
		if err := cfDo(tok, "POST", "/accounts/"+acc.ID+"/access/apps", body, &created); err != nil {
			jsonErr(w, 400, accessErr(err))
			return
		}
		app = &created
	} else if err := cfDo(tok, "PUT", "/accounts/"+acc.ID+"/access/apps/"+app.ID, body, nil); err != nil {
		jsonErr(w, 400, accessErr(err))
		return
	}
	// one policy, rewritten each time
	var pols []struct {
		ID string `json:"id"`
	}
	_ = cfDo(tok, "GET", "/accounts/"+acc.ID+"/access/apps/"+app.ID+"/policies", nil, &pols)
	pol := map[string]any{"name": "Wharf 允许", "decision": "allow", "include": include, "precedence": 1}
	if len(pols) > 0 {
		err = cfDo(tok, "PUT", "/accounts/"+acc.ID+"/access/apps/"+app.ID+"/policies/"+pols[0].ID, pol, nil)
	} else {
		err = cfDo(tok, "POST", "/accounts/"+acc.ID+"/access/apps/"+app.ID+"/policies", pol, nil)
	}
	if err != nil {
		jsonErr(w, 400, accessErr(err))
		return
	}
	a.audit(actor{user: currentUser(r), ip: a.clientIP(r)}, "cloudflare.access", "access", host, "Cloudflare Access 保护 "+host+"："+strings.Join(emails, "、"), nil, map[string]any{"emails": emails, "hours": req.Hours}, false)
	writeJSON(w, 200, map[string]bool{"ok": true})
}

// DELETE /api/cloudflare/access?id=
func (a *App) handleCFAccessDelete(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("id")
	if id == "" || strings.ContainsAny(id, "/?#&") {
		jsonErr(w, 400, "请求格式错误")
		return
	}
	tok, err := a.cfToken()
	if err != nil {
		jsonErr(w, 400, err.Error())
		return
	}
	acc, err := cfAccountOf(tok)
	if err != nil {
		jsonErr(w, 400, err.Error())
		return
	}
	var app cfAccessApp
	if err := cfDo(tok, "GET", "/accounts/"+acc.ID+"/access/apps/"+url.PathEscape(id), nil, &app); err != nil {
		jsonErr(w, 400, accessErr(err))
		return
	}
	if !strings.HasPrefix(app.Name, accessPrefix) {
		jsonErr(w, 403, "这个 Access 应用不是 Wharf 建的，请到建它的地方去改")
		return
	}
	if err := cfDo(tok, "DELETE", "/accounts/"+acc.ID+"/access/apps/"+url.PathEscape(id), nil, nil); err != nil {
		jsonErr(w, 400, accessErr(err))
		return
	}
	a.audit(actor{user: currentUser(r), ip: a.clientIP(r)}, "cloudflare.access.delete", "access", app.Domain, "取消 Cloudflare Access 保护："+app.Domain, nil, nil, false)
	writeJSON(w, 200, map[string]bool{"ok": true})
}

func jsonHours(h int) string {
	b, _ := json.Marshal(h)
	return string(b) + "h"
}

func accessErr(err error) string {
	if isDenied(err) {
		return "令牌缺少「账户 · Access: Apps and Policies · 编辑」权限"
	}
	var ce *cfErr
	if errors.As(err, &ce) && (strings.Contains(strings.ToLower(ce.Msg), "not enabled") || strings.Contains(strings.ToLower(ce.Msg), "organization")) {
		return "这个 Cloudflare 账户还没开通 Zero Trust：到 Cloudflare 后台左侧「Zero Trust」里选免费方案、起一个团队名，开通后再回来"
	}
	return err.Error()
}
