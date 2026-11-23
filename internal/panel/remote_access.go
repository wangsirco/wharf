package panel

import (
	"fmt"
	"log"
	"net/http"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/wangsirco/wharf/internal/sign"
)

// The remote-access page does the whole Cloudflare tunnel for the panel in one step and
// undoes it in one step (docs/BERTH.md §10), and helps people carry their passkeys to a
// new name: a passkey only works on the name it was added on.

var labelRe = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)

// POST /api/remote/tunnel {label, zone_id, access, emails, replace}: the panel through the
// tunnel — tunnel, proxied DNS record, route, Access with Berth's interface let through,
// and Berth told. A failure undoes what was done.
func (a *App) handleRemoteTunnelOpen(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Label   string   `json:"label"`
		ZoneID  string   `json:"zone_id"`
		Access  bool     `json:"access"`
		Emails  []string `json:"emails"`
		Replace bool     `json:"replace"`
	}
	if readJSON(r, &req) != nil {
		jsonErr(w, 400, "请求格式错误")
		return
	}
	label := strings.ToLower(strings.TrimSpace(req.Label))
	if !labelRe.MatchString(label) {
		jsonErr(w, 400, "名字只能用小写字母、数字和连字符，例如 wharf")
		return
	}
	if !zoneIDRe.MatchString(req.ZoneID) {
		jsonErr(w, 400, "请选择一个域名")
		return
	}
	tok, err := a.cfToken()
	if err != nil {
		jsonErr(w, 400, err.Error())
		return
	}
	caps := cfCapabilities(tok, false)
	var missing []string
	if !caps.Zones {
		missing = append(missing, "区域 · Zone · 读取")
	}
	if !caps.DNS {
		missing = append(missing, "区域 · DNS · 编辑")
	}
	if !caps.Tunnel {
		missing = append(missing, "账户 · Cloudflare Tunnel · 编辑")
	}
	if req.Access && caps.Access != "ok" {
		if caps.Access == "not_enabled" {
			jsonErr(w, 400, "要邮箱验证，Cloudflare 账户需要先开通 Zero Trust（免费方案即可）；或者先不勾邮箱验证")
			return
		}
		missing = append(missing, "账户 · Access: Apps and Policies · 编辑")
	}
	if len(missing) > 0 {
		jsonErr(w, 400, "令牌缺少权限："+strings.Join(missing, "、")+"。点「更换令牌」换一个带这些权限的")
		return
	}
	zone := a.zoneName(tok, req.ZoneID)
	if zone == "" {
		jsonErr(w, 400, "这个令牌看不到所选的域名")
		return
	}
	host := label + "." + zone
	_, rt, err := a.addTunnelRoute(tok, tunnelRoute{Hostname: host, Kind: "panel"}, req.Replace)
	if err != nil {
		replyErr(w, err)
		return
	}
	var emails []string
	if req.Access {
		if emails, err = a.saveAccess(tok, host, req.Emails, 24); err != nil {
			// all or nothing: take the name off the tunnel again
			if _, _, e := a.removeTunnelRoute(tok, host); e != nil {
				log.Printf("remote: undo tunnel route %s: %v", host, e)
			}
			_ = a.deleteAccess(tok, host)
			jsonErr(w, 400, "邮箱验证没设好，已撤回刚才的改动："+err.Error())
			return
		}
	}
	what := "通过 Cloudflare 隧道开放面板：" + host
	if req.Access {
		what += "（邮箱验证：" + strings.Join(emails, "、") + "）"
	}
	a.audit(actor{user: currentUser(r), ip: a.clientIP(r)}, "tunnel.route.add", "tunnel", host, what, nil, map[string]any{"route": rt, "access": emails}, false)
	writeJSON(w, 200, map[string]any{"ok": true, "hostname": host, "url": "https://" + host})
}

// DELETE /api/remote/tunnel?hostname= — stop opening the panel through the tunnel: the
// Access apps, the route, the DNS record; Berth is told.
func (a *App) handleRemoteTunnelClose(w http.ResponseWriter, r *http.Request) {
	host := strings.ToLower(r.URL.Query().Get("hostname"))
	if fromTunnel(r) && strings.EqualFold(hostOnly(r.Host), host) {
		jsonErr(w, 400, "你正是通过这个名字打开的面板，停止后就进不来了。请换一个地址（例如家里的 wharf.lan）打开后再停止")
		return
	}
	tok, err := a.cfToken()
	if err != nil {
		jsonErr(w, 400, err.Error())
		return
	}
	isPanel := false
	for _, rt := range a.tunnelConf().Routes {
		if rt.Hostname == host && rt.Kind == "panel" {
			isPanel = true
		}
	}
	if !isPanel {
		jsonErr(w, 404, "隧道上没有面板的这个名字")
		return
	}
	if caps := cfCapabilities(tok, false); caps.Access == "ok" {
		if err := a.deleteAccess(tok, host); err != nil {
			jsonErr(w, 400, "Access 应用没删掉："+err.Error())
			return
		}
	}
	gone, _, err := a.removeTunnelRoute(tok, host)
	if err != nil {
		replyErr(w, err)
		return
	}
	a.audit(actor{user: currentUser(r), ip: a.clientIP(r)}, "tunnel.route.delete", "tunnel", host, "停止经 Cloudflare 隧道开放面板："+host, gone, nil, false)
	writeJSON(w, 200, map[string]bool{"ok": true})
}

// GET /api/remote/tailscale
func (a *App) handleRemoteTailscale(w http.ResponseWriter, r *http.Request) {
	var st map[string]any
	if err := a.agent.Do("GET", "/v1/tailscale", nil, &st); err != nil {
		writeJSON(w, 200, map[string]any{"installed": false, "error": agentMsg(err)})
		return
	}
	writeJSON(w, 200, st)
}

// ---- carrying the sign-in to another of the panel's names ----

type hopTicket struct {
	userID int64
	host   string
	path   string
	until  time.Time
}

var hops = struct {
	sync.Mutex
	m map[string]*hopTicket
}{m: map[string]*hopTicket{}}

// baseFor: the address of one of the panel's names (with the port when it needs one).
func (a *App) baseFor(host string) string {
	if host == a.localPanelName() {
		return a.lanURL()
	}
	if slices.Contains(a.tunnelPanelNames(), host) || slices.Contains(a.proxiedNames(), host) || a.setting("panel.via_443") == "1" || a.lan443() {
		return "https://" + host
	}
	return withPort(host, a.panelPort())
}

// POST /api/me/hop {to, path} — a one-time link (60 s, once) that opens another of the
// panel's own names already signed in, e.g. to add a passkey there.
func (a *App) handleHop(w http.ResponseWriter, r *http.Request) {
	var req struct {
		To   string `json:"to"`
		Path string `json:"path"`
	}
	if readJSON(r, &req) != nil {
		jsonErr(w, 400, "请求格式错误")
		return
	}
	host := strings.ToLower(strings.TrimSpace(req.To))
	if !slices.Contains(a.passkeyHosts(), host) {
		jsonErr(w, 400, "只能跳到面板自己的名字")
		return
	}
	u := currentUser(r)
	t := sign.RandomHex(24)
	hops.Lock()
	for k, v := range hops.m {
		if time.Now().After(v.until) {
			delete(hops.m, k)
		}
	}
	hops.m[t] = &hopTicket{userID: u.ID, host: host, path: safeReturn(firstNonEmpty(req.Path, "/")), until: time.Now().Add(60 * time.Second)}
	hops.Unlock()
	writeJSON(w, 200, map[string]string{"url": a.baseFor(host) + "/hop/" + t})
}

// GET /hop/{t}
func (a *App) handleHopIn(w http.ResponseWriter, r *http.Request) {
	t := r.PathValue("t")
	hops.Lock()
	tk := hops.m[t]
	delete(hops.m, t)
	hops.Unlock()
	page := func(code int, title, msg, to string) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		w.WriteHeader(code)
		refresh := ""
		if to != "" {
			refresh = `<meta http-equiv="refresh" content="0;url=` + htmlEscape(to) + `">`
		}
		fmt.Fprintf(w, `<!doctype html><html lang="zh-CN"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width">%s<title>%s</title></head>
<body style="font-family:system-ui;padding:3rem;color:#333"><h3>%s</h3><p>%s</p><p><a href="/">打开 Wharf</a></p></body></html>`, refresh, htmlEscape(title), htmlEscape(title), htmlEscape(msg))
	}
	ip := a.clientIP(r)
	if tk == nil || time.Now().After(tk.until) {
		a.limiter.record("hop:" + ip)
		page(401, "链接已失效", "这个链接只能用一次，60 秒内有效。请回到原来的页面再点一次。", "")
		return
	}
	if !strings.EqualFold(hostOnly(r.Host), tk.host) {
		page(403, "地址不符", "这个链接是给 "+tk.host+" 的。", "")
		return
	}
	u, err := a.getUser(tk.userID)
	if err != nil || u.Disabled {
		page(403, "账号不可用", "账号不存在或已停用。", "")
		return
	}
	if _, err := a.createSession(w, r, u); err != nil {
		page(500, "登录失败", err.Error(), "")
		return
	}
	a.audit(actor{user: u, ip: ip}, "session.login", "session", strconv.FormatInt(u.ID, 10), "从面板的另一个地址带着登录状态打开 "+tk.host, nil, nil, false)
	page(200, "正在打开…", "", tk.path)
}

// passkeyHereMsg: why a strict sign-in cannot finish on this name, and what to do.
func (a *App) passkeyHereMsg(u *User, here string) string {
	where := a.usablePasskeyHosts(u.ID)
	return fmt.Sprintf("这个账号的 Passkey 在 %s 上，在 %s 用不了（Passkey 跟着名字走）。请先从 %s 登录，在「我的账号」里点「去 %s 添加 Passkey」，以后这个地址也能用。",
		strings.Join(where, "、"), here, strings.Join(where, " 或 "), here)
}
