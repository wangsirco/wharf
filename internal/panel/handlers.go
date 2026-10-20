package panel

import (
	"encoding/json"
	"fmt"
	"io/fs"
	"log"
	"mime"
	"net/http"
	"os"
	"path"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/wangsirco/wharf/internal/rules"
)

func (a *App) Routes() http.Handler {
	m := http.NewServeMux()

	// public
	m.HandleFunc("POST /api/login", a.handleLogin)
	m.HandleFunc("POST /api/logout", a.handleLogout)
	m.HandleFunc("GET /api/me", a.handleMe)
	m.HandleFunc("POST /api/beacon", a.handleBeacon)
	m.HandleFunc("GET /api/public/config", a.handlePublicConfig)
	m.HandleFunc("GET /manifest.webmanifest", a.handleManifest)
	m.HandleFunc("GET /ca.crt", a.handleCACert)

	// any logged-in user
	m.HandleFunc("GET /api/meta", a.auth("", a.handleMeta))
	m.HandleFunc("POST /api/me/password", a.auth("", a.handleChangePassword))
	m.HandleFunc("POST /api/me/onboarded", a.auth("", a.handleOnboarded))
	m.HandleFunc("PUT /api/me/profile", a.auth("", a.handleMyProfile))
	m.HandleFunc("GET /api/my/approvals", a.auth("", a.handleMyApprovals))
	m.HandleFunc("POST /api/actions/{key}", a.auth("", a.handleAction))
	m.HandleFunc("GET /api/system", a.auth("dashboard.view", a.handleSystem))
	m.HandleFunc("GET /api/devices", a.auth("devices.view", a.handleDevices))
	m.HandleFunc("GET /api/forwards", a.auth("forwards.view", a.handleForwards))
	m.HandleFunc("GET /api/forwards/targets", a.auth("forwards.manage", a.handleForwardTargets))
	m.HandleFunc("GET /api/geo/regions", a.auth("", a.handleRegions))
	m.HandleFunc("GET /api/simple/devices", a.auth("devices.view", a.handleSimpleDevices))
	m.HandleFunc("GET /api/geo/flows", a.auth("traffic.view", a.handleGeoFlows))
	m.HandleFunc("GET /api/network", a.auth("dashboard.view", a.handleNetwork))
	m.HandleFunc("POST /api/network/speedtest", a.auth("dashboard.view", a.handleSpeedtest))
	m.HandleFunc("GET /api/overview", a.auth("dashboard.view", a.handleOverview))
	m.HandleFunc("GET /api/events", a.auth("dashboard.view", a.handleEvents))
	m.HandleFunc("GET /api/device-types", a.auth("", a.handleDeviceTypes))
	m.HandleFunc("GET /api/nextdns/summary", a.auth("traffic.view", a.handleNextDNSSummary))
	m.HandleFunc("GET /api/nextdns/logs", a.auth("traffic.view", a.handleNextDNSLogs))
	m.HandleFunc("POST /api/nextdns/per-device", a.super(a.handleNextDNSPerDevice))
	m.HandleFunc("POST /api/nextdns/test", a.super(a.handleNextDNSTest))
	m.HandleFunc("POST /api/pve/test", a.super(a.handlePVETest))
	m.HandleFunc("GET /api/forwards/ports", a.auth("forwards.view", a.handleForwardPorts))
	m.HandleFunc("GET /api/forwards/usage", a.auth("forwards.view", a.handleForwardUsage))
	m.HandleFunc("GET /api/forwards/{id}/stats", a.auth("forwards.view", a.handleForwardStats))
	m.HandleFunc("GET /api/update", a.super(a.handleUpdate))
	m.HandleFunc("POST /api/update/check", a.super(a.handleUpdateCheck))
	m.HandleFunc("POST /api/update/apply", a.super(a.handleUpdateApply))
	m.HandleFunc("GET /api/update/status", a.super(a.handleUpdateStatus))
	m.HandleFunc("POST /api/update/rollback-web", a.super(a.handleUpdateRollbackWeb))
	m.HandleFunc("GET /api/system/hw", a.auth("system.view", a.handleSystemHW))
	m.HandleFunc("GET /api/system/services", a.auth("system.view", a.handleServices))
	m.HandleFunc("GET /api/system/log", a.auth("system.view", a.handleSystemLog))
	m.HandleFunc("GET /api/system/reboot-schedule", a.auth("system.view", a.handleRebootSchedule))
	m.HandleFunc("GET /api/system/backup", a.super(a.handleBackup))
	m.HandleFunc("POST /api/system/restore", a.super(a.handleRestore))
	m.HandleFunc("GET /api/upnp", a.auth("system.view", a.handleUPnP))
	m.HandleFunc("GET /api/deps", a.auth("system.view", a.handleDeps))
	m.HandleFunc("POST /api/deps", a.super(a.handleDepsAction))
	m.HandleFunc("POST /api/tools/diag", a.auth("tools.diag", a.handleDiag))
	m.HandleFunc("GET /api/tools/iperf-server", a.auth("tools.diag", a.handleIperfServer))
	m.HandleFunc("GET /api/tools/speed/down", a.auth("tools.diag", a.handleSpeedDown))
	m.HandleFunc("POST /api/tools/speed/up", a.auth("tools.diag", a.handleSpeedUp))
	m.HandleFunc("GET /api/tools/captures", a.auth("tools.capture", a.handleCaptures))
	m.HandleFunc("POST /api/tools/captures", a.auth("tools.capture", a.handleCaptureStart))
	m.HandleFunc("POST /api/tools/captures/{id}/{op}", a.auth("tools.capture", a.handleCaptureOp))
	m.HandleFunc("GET /api/tools/captures/{id}/analysis", a.auth("tools.capture", a.handleCaptureAnalysis))
	m.HandleFunc("GET /api/tools/captures/{id}/download", a.auth("tools.capture", a.handleCaptureDownload))
	m.HandleFunc("GET /api/monitors", a.auth("tools.diag", a.handleMonitors))
	m.HandleFunc("POST /api/monitors", a.auth("tools.diag", a.handleMonitorSave))
	m.HandleFunc("DELETE /api/monitors/{id}", a.auth("tools.diag", a.handleMonitorDelete))
	m.HandleFunc("POST /api/monitors/{id}/run", a.auth("tools.diag", a.handleMonitorRun))
	m.HandleFunc("GET /api/monitors/{id}/history", a.auth("tools.diag", a.handleMonitorHistory))
	m.HandleFunc("GET /api/monitors/{id}/export", a.auth("tools.diag", a.handleMonitorExport))
	m.HandleFunc("GET /api/hosts", a.auth("system.view", a.handleHosts))
	m.HandleFunc("GET /api/pve/status", a.super(a.handlePVEStatus))
	m.HandleFunc("GET /api/policies", a.auth("access.manage", a.handlePolicies))
	m.HandleFunc("GET /api/devices/{mac}/policy", a.auth("access.manage", a.handleDevicePolicy))
	m.HandleFunc("GET /api/traffic/live", a.auth("devices.view", a.handleTrafficLive))
	m.HandleFunc("GET /api/traffic/overview", a.auth("traffic.view", a.handleTrafficOverview))
	m.HandleFunc("GET /api/devices/{mac}/traffic", a.auth("traffic.view", a.handleDeviceTraffic))
	m.HandleFunc("GET /api/devices/{mac}/profile", a.auth("traffic.view", a.handleDeviceProfile))
	m.HandleFunc("GET /api/devices/{mac}/presence", a.auth("devices.view", a.handleDevicePresence))
	m.HandleFunc("GET /api/rules/catalog", a.auth("traffic.view", a.handleCatalog))
	m.HandleFunc("POST /api/probe", a.auth("traffic.view", a.handleProbe))

	// super admin only
	m.HandleFunc("GET /api/users", a.super(a.handleUsers))
	m.HandleFunc("POST /api/users", a.super(a.handleUserCreate))
	m.HandleFunc("PUT /api/users/{id}", a.super(a.handleUserUpdate))
	m.HandleFunc("POST /api/users/{id}/password", a.super(a.handleUserPassword))
	m.HandleFunc("GET /api/audit", a.super(a.handleAuditList))
	m.HandleFunc("POST /api/audit/{id}/restore", a.super(a.handleAuditRestore))
	m.HandleFunc("GET /api/approvals", a.super(a.handleApprovals))
	m.HandleFunc("POST /api/approvals/{id}/{decision}", a.super(a.handleApprovalDecide))
	m.HandleFunc("GET /api/visitors", a.super(a.handleVisitors))
	m.HandleFunc("GET /api/settings", a.super(a.handleSettings))
	m.HandleFunc("GET /api/alerts", a.super(a.handleAlerts))
	m.HandleFunc("PUT /api/alerts/rules", a.super(a.handleAlertRules))
	m.HandleFunc("POST /api/alerts/channels", a.super(a.handleAlertChannelAdd))
	m.HandleFunc("DELETE /api/alerts/channels/{id}", a.super(a.handleAlertChannelDelete))
	m.HandleFunc("POST /api/alerts/channels/{id}/toggle", a.super(a.handleAlertChannelToggle))
	m.HandleFunc("POST /api/alerts/test", a.super(a.handleAlertTest))
	m.HandleFunc("GET /api/access/me", a.super(a.handleAccessMe))
	m.HandleFunc("PUT /api/settings", a.super(a.handleSettingsUpdate))
	m.HandleFunc("GET /api/agent/status", a.super(a.handleAgentStatus))
	m.HandleFunc("POST /api/geo/update", a.super(a.handleGeoUpdate))
	m.HandleFunc("POST /api/rules/update", a.super(a.handleRulesUpdate))

	m.HandleFunc("/api/", func(w http.ResponseWriter, r *http.Request) { jsonErr(w, 404, "not found") })
	m.HandleFunc("/", a.handleStatic)
	return a.securityHeaders(a.accessGate(a.demoWrap(m)))
}

func (a *App) securityHeaders(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hd := w.Header()
		hd.Set("X-Content-Type-Options", "nosniff")
		hd.Set("X-Frame-Options", "DENY")
		hd.Set("Referrer-Policy", "no-referrer")
		hd.Set("Content-Security-Policy", "default-src 'self'; connect-src 'self' https://api.ip.sb; img-src 'self' data:; style-src 'self' 'unsafe-inline'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
		// HSTS only with a real certificate: with the local CA it would stop browsers
		// from letting the user past the warning on devices that haven't installed it yet
		if r.TLS != nil && a.cfg.TLS == "files" {
			hd.Set("Strict-Transport-Security", "max-age=31536000")
		}
		h.ServeHTTP(w, r)
	})
}

func init() { _ = mime.AddExtensionType(".webmanifest", "application/manifest+json") }

// handleStatic serves the embedded SPA, falling back to index.html for client routes.
func (a *App) handleStatic(w http.ResponseWriter, r *http.Request) {
	p := strings.TrimPrefix(path.Clean(r.URL.Path), "/")
	if p == "" {
		p = "index.html"
	}
	web := a.webState().fs
	if st, err := fs.Stat(web, p); err != nil || st.IsDir() {
		p = "index.html"
	}
	if strings.HasPrefix(p, "assets/") {
		w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
	} else {
		w.Header().Set("Cache-Control", "no-cache")
	}
	http.ServeFileFS(w, r, web, p)
}

// ---- session ----

func (a *App) handleLogin(w http.ResponseWriter, r *http.Request) {
	var req struct{ Username, Password, TZ string }
	if readJSON(r, &req) != nil {
		jsonErr(w, 400, "请求格式错误")
		return
	}
	ip := a.clientIP(r)
	keys := []string{"ip:" + ip, "user:" + strings.ToLower(req.Username)}
	if a.limiter.blocked(keys...) {
		jsonErr(w, 429, "失败次数过多，请 15 分钟后再试")
		return
	}
	if !a.timezoneAllowed(ip, req.TZ) {
		jsonErr(w, 403, "拒绝访问：当前时区不在允许范围")
		return
	}
	u, err := a.checkPassword(req.Username, req.Password)
	if err != nil {
		a.limiter.record(keys...)
		jsonErr(w, 401, err.Error())
		return
	}
	a.limiter.reset(keys...)
	csrf, err := a.createSession(w, r, u)
	if err != nil {
		jsonErr(w, 500, err.Error())
		return
	}
	a.audit(actor{user: u, ip: ip}, "session.login", "session", strconv.FormatInt(u.ID, 10), "登录", nil, nil, false)
	writeJSON(w, 200, map[string]any{"user": u, "csrf": csrf})
}

func (a *App) handleLogout(w http.ResponseWriter, r *http.Request) {
	a.destroySession(w, r)
	writeJSON(w, 200, map[string]bool{"ok": true})
}

func (a *App) handleMe(w http.ResponseWriter, r *http.Request) {
	s := a.loadSession(r)
	if s == nil {
		jsonErr(w, 401, "未登录")
		return
	}
	writeJSON(w, 200, map[string]any{"user": s.user, "csrf": s.csrf, "onboarded": a.setting(onboardKey(s.user.ID)) == "1"})
}

func onboardKey(id int64) string { return "onboarded." + strconv.FormatInt(id, 10) }

// POST /api/me/onboarded — the welcome wizard was finished or skipped.
func (a *App) handleOnboarded(w http.ResponseWriter, r *http.Request) {
	_ = a.setSetting(onboardKey(currentUser(r).ID), "1")
	writeJSON(w, 200, map[string]bool{"ok": true})
}

// PUT /api/me/profile {display_name} — anyone may rename themselves.
func (a *App) handleMyProfile(w http.ResponseWriter, r *http.Request) {
	var req struct {
		DisplayName string `json:"display_name"`
	}
	if readJSON(r, &req) != nil {
		jsonErr(w, 400, "请求格式错误")
		return
	}
	name := clean(req.DisplayName, 64)
	if name == "" {
		jsonErr(w, 400, "称呼不能为空")
		return
	}
	u, err := a.getUser(currentUser(r).ID)
	if err != nil {
		jsonErr(w, 404, "用户不存在")
		return
	}
	if u.DisplayName != name {
		before := u.auditView()
		u.DisplayName = name
		if err := a.saveUser(u); err != nil {
			jsonErr(w, 500, err.Error())
			return
		}
		a.audit(actor{user: u, ip: a.clientIP(r)}, "user.profile.self", "user", strconv.FormatInt(u.ID, 10), "修改自己的称呼为 "+name, before, u.auditView(), true)
	}
	writeJSON(w, 200, u)
}

func (a *App) handleChangePassword(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Old string `json:"old"`
		New string `json:"new"`
	}
	if readJSON(r, &req) != nil {
		jsonErr(w, 400, "请求格式错误")
		return
	}
	u := currentUser(r)
	if _, err := a.checkPassword(u.Username, req.Old); err != nil {
		jsonErr(w, 400, "原密码错误")
		return
	}
	if err := a.setPassword(u.ID, req.New); err != nil {
		jsonErr(w, 400, err.Error())
		return
	}
	if u.Role == RoleSuper {
		_ = os.Remove(a.cfg.Path("initial_password"))
	}
	a.audit(actor{user: u, ip: a.clientIP(r)}, "user.password.self", "user", strconv.FormatInt(u.ID, 10), "修改自己的密码", nil, nil, false)
	a.destroySession(w, r)
	writeJSON(w, 200, map[string]bool{"ok": true})
}

func (a *App) handleMeta(w http.ResponseWriter, r *http.Request) {
	var acts []*Action
	for _, act := range actions {
		acts = append(acts, act)
	}
	slices.SortFunc(acts, func(x, y *Action) int { return strings.Compare(x.Key, y.Key) })
	writeJSON(w, 200, map[string]any{"permissions": Permissions, "quotas": Quotas, "actions": acts})
}

func (a *App) handleSystem(w http.ResponseWriter, r *http.Request) {
	var out json.RawMessage
	if err := a.agent.Do("GET", "/v1/system", nil, &out); err != nil {
		jsonErr(w, 502, err.Error())
		return
	}
	writeJSON(w, 200, out)
}

func (a *App) handleAgentStatus(w http.ResponseWriter, r *http.Request) {
	var out map[string]any
	if err := a.agent.Do("GET", "/v1/ping", nil, &out); err != nil {
		writeJSON(w, 200, map[string]any{"ok": false, "error": err.Error(), "url": a.cfg.Agent.URL})
		return
	}
	out["ok"], out["url"] = true, a.cfg.Agent.URL
	writeJSON(w, 200, out)
}

func (a *App) handleGeoUpdate(w http.ResponseWriter, r *http.Request) {
	if err := a.geo.Update(); err != nil {
		jsonErr(w, 502, err.Error())
		return
	}
	writeJSON(w, 200, map[string]bool{"ok": true})
}

// ---- users (super) ----

func (a *App) handleUsers(w http.ResponseWriter, r *http.Request) {
	list, err := a.listUsers()
	if err != nil {
		jsonErr(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, list)
}

type userEdit struct {
	Username    string         `json:"username"`
	DisplayName *string        `json:"display_name"`
	Password    string         `json:"password"`
	Perms       []string       `json:"perms"`
	Quotas      map[string]int `json:"quotas"`
	Grants      *ForwardGrants `json:"grants"`
	Disabled    *bool          `json:"disabled"`
}

func (e *userEdit) validate() error {
	for _, p := range e.Perms {
		if !validPerm(p) {
			return fmt.Errorf("未知权限 %s", p)
		}
	}
	for k, v := range e.Quotas {
		if !slices.ContainsFunc(Quotas, func(q QuotaDef) bool { return q.Key == k }) {
			return fmt.Errorf("未知配额 %s", k)
		}
		if v < -1 || v > 10000 {
			return fmt.Errorf("配额 %s 超出范围", k)
		}
	}
	if e.Grants != nil {
		if err := e.Grants.validate(); err != nil {
			return err
		}
	}
	if e.DisplayName != nil {
		n := strings.TrimSpace(*e.DisplayName)
		if n == "" || len([]rune(n)) > 64 {
			return fmt.Errorf("名称长度需为 1-64")
		}
		e.DisplayName = &n
	}
	return nil
}

func (a *App) handleUserCreate(w http.ResponseWriter, r *http.Request) {
	var req userEdit
	if readJSON(r, &req) != nil {
		jsonErr(w, 400, "请求格式错误")
		return
	}
	if err := req.validate(); err != nil {
		jsonErr(w, 400, err.Error())
		return
	}
	display := ""
	if req.DisplayName != nil {
		display = *req.DisplayName
	}
	if req.Grants != nil {
		if err := a.grantOverlap(0, *req.Grants); err != nil {
			jsonErr(w, 409, err.Error())
			return
		}
	}
	// every user created here is a normal admin; the only super admin is the bootstrap account
	u, err := a.createUser(req.Username, display, req.Password, RoleAdmin)
	if err != nil {
		jsonErr(w, 400, err.Error())
		return
	}
	if req.Grants != nil {
		u.Grants = *req.Grants
	}
	if req.Perms != nil || req.Quotas != nil || req.Grants != nil {
		u.Perms, u.Quotas = orEmpty(req.Perms), orEmptyMap(req.Quotas)
		_ = a.saveUser(u)
	}
	a.audit(actor{user: currentUser(r), ip: a.clientIP(r)}, "user.create", "user", strconv.FormatInt(u.ID, 10),
		fmt.Sprintf("新增管理员 %s（%s）", u.Username, u.DisplayName), nil, u.auditView(), false)
	writeJSON(w, 200, u)
}

func (a *App) handleUserUpdate(w http.ResponseWriter, r *http.Request) {
	var req userEdit
	if readJSON(r, &req) != nil {
		jsonErr(w, 400, "请求格式错误")
		return
	}
	if err := req.validate(); err != nil {
		jsonErr(w, 400, err.Error())
		return
	}
	u, err := a.getUser(pathID(r))
	if err != nil {
		jsonErr(w, 404, "用户不存在")
		return
	}
	before := u.auditView()
	if req.DisplayName != nil {
		u.DisplayName = *req.DisplayName
	}
	if u.Role != RoleSuper {
		if req.Perms != nil {
			u.Perms = req.Perms
		}
		if req.Quotas != nil {
			u.Quotas = req.Quotas
		}
		if req.Grants != nil {
			if err := a.grantOverlap(u.ID, *req.Grants); err != nil {
				jsonErr(w, 409, err.Error())
				return
			}
			u.Grants = *req.Grants
		}
		if req.Disabled != nil {
			u.Disabled = *req.Disabled
		}
	} else if req.Disabled != nil && *req.Disabled {
		jsonErr(w, 400, "不能停用超级管理员")
		return
	}
	if sameJSON(before, u.auditView()) {
		writeJSON(w, 200, u)
		return
	}
	if err := a.saveUser(u); err != nil {
		jsonErr(w, 500, err.Error())
		return
	}
	if u.Disabled {
		_, _ = a.db.Exec(`DELETE FROM sessions WHERE user_id=?`, u.ID)
	}
	a.audit(actor{user: currentUser(r), ip: a.clientIP(r)}, "user.update", "user", strconv.FormatInt(u.ID, 10),
		fmt.Sprintf("修改管理员 %s", u.Username), before, u.auditView(), true)
	writeJSON(w, 200, u)
}

func (a *App) handleUserPassword(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Password string `json:"password"`
	}
	if readJSON(r, &req) != nil {
		jsonErr(w, 400, "请求格式错误")
		return
	}
	u, err := a.getUser(pathID(r))
	if err != nil {
		jsonErr(w, 404, "用户不存在")
		return
	}
	if err := a.setPassword(u.ID, req.Password); err != nil {
		jsonErr(w, 400, err.Error())
		return
	}
	a.audit(actor{user: currentUser(r), ip: a.clientIP(r)}, "user.password.reset", "user", strconv.FormatInt(u.ID, 10),
		fmt.Sprintf("重置 %s 的密码", u.Username), nil, nil, false)
	writeJSON(w, 200, map[string]bool{"ok": true})
}

func orEmpty(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

func orEmptyMap(m map[string]int) map[string]int {
	if m == nil {
		return map[string]int{}
	}
	return m
}

// ---- settings (super) ----

func (a *App) handleSettings(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, 200, a.publicSettings())
}

var secretSettings = []string{"nextdns.api_key", "pve.token"}

// publicSettings hides secrets and internal cursors.
func (a *App) publicSettings() map[string]string {
	s := a.allSettings()
	for _, sk := range secretSettings {
		if k := s[sk]; k != "" {
			s[sk] = maskSecret(k)
		}
	}
	for k := range s {
		if strings.HasPrefix(k, "collect.") || strings.HasPrefix(k, "onboarded.") || k == "nextdns.cursor_ts" {
			delete(s, k)
		}
	}
	return s
}

func validSetting(key, value string) error {
	if handled, err := validAccessSetting(key, value); handled {
		return err
	}
	if handled, err := validNextDNSSetting(key, value); handled {
		return err
	}
	if handled, err := validPVESetting(key, value); handled {
		return err
	}
	if handled, err := validUpdateSetting(key, value); handled {
		return err
	}
	switch key {
	case "ui.name", "ui.subtitle":
		v := strings.TrimSpace(value)
		max := map[string]int{"ui.name": 24, "ui.subtitle": 40}[key]
		if (key == "ui.name" && v == "") || len([]rune(v)) > max || v != value || !brandRe.MatchString(v) {
			return fmt.Errorf("名称需为 1-%d 个字符，不能包含 < > \" ' &", max)
		}
		return nil
	case "presence.away_minutes":
		if n, err := strconv.Atoi(value); err != nil || n < 3 || n > 240 {
			return fmt.Errorf("离开判定时间需为 3-240 分钟")
		}
		return nil
	case "rules.update_hours":
		switch value {
		case "0", "6", "12", "24", "72", "168":
			return nil
		}
		return fmt.Errorf("规则更新间隔只能是 0/6/12/24/72/168 小时")
	case "approval.forward_open_all":
		if value != "0" && value != "1" {
			return fmt.Errorf("%s 只能是 0 或 1", key)
		}
		return nil
	case "approval.required":
		var list []string
		if json.Unmarshal([]byte(value), &list) != nil {
			return fmt.Errorf("approval.required 必须是 JSON 数组")
		}
		for _, k := range list {
			if actions[k] == nil {
				return fmt.Errorf("未知操作 %s", k)
			}
		}
		return nil
	case "approval.expire_hours", "retention.audit_days", "retention.visitor_days", "retention.traffic_days", "retention.traffic_mb":
		n, err := strconv.Atoi(value)
		if err != nil || n < 1 || n > 100000 {
			return fmt.Errorf("%s 必须是正整数", key)
		}
		return nil
	}
	return fmt.Errorf("未知设置 %s", key)
}

func (a *App) handleSettingsUpdate(w http.ResponseWriter, r *http.Request) {
	var req map[string]string
	if readJSON(r, &req) != nil {
		jsonErr(w, 400, "请求格式错误")
		return
	}
	force := req["_force"] == "1"
	delete(req, "_force")
	for k, v := range req {
		if err := validSetting(k, v); err != nil {
			jsonErr(w, 400, err.Error())
			return
		}
	}
	// refuse (unless forced) an access policy that would lock out the admin saving it
	draft := policyFrom(func(k string) string {
		if v, ok := req[k]; ok {
			return v
		}
		return a.setting(k)
	})
	if res := a.checkAccessWith(draft, a.clientIP(r)); !res.ok && !force {
		writeJSON(w, 409, map[string]string{"error": "保存后你自己将无法访问面板：" + res.reason, "lockout": "1"})
		return
	}
	ac := actor{user: currentUser(r), ip: a.clientIP(r)}
	for k, v := range req {
		old := a.setting(k)
		if old == v {
			continue
		}
		if err := a.setSetting(k, v); err != nil {
			jsonErr(w, 500, err.Error())
			return
		}
		if strings.HasPrefix(k, "pve.") {
			defer a.pveKick()
		}
		if containsStr(secretSettings, k) { // never store the secret in the audit log
			a.audit(ac, "setting.update", "setting", k, "修改密钥 "+k, maskSecret(old), maskSecret(v), false)
			continue
		}
		if k == "nextdns.profile" {
			_ = a.setSetting("nextdns.cursor_ts", "")
		}
		a.audit(ac, "setting.update", "setting", k, "修改设置 "+k, old, v, true)
	}
	writeJSON(w, 200, a.publicSettings())
}

func (a *App) handlePublicConfig(w http.ResponseWriter, r *http.Request) {
	out := map[string]any{"ipsb": a.setting("access.ipsb") == "1", "name": a.setting("ui.name"), "subtitle": a.setting("ui.subtitle")}
	if a.CA != nil {
		out["cert"] = map[string]string{"name": a.CA.CAName(), "sha256": a.CA.CAFingerprint()}
	}
	writeJSON(w, 200, out)
}

// GET /ca.crt — the local CA to install on phones and computers (public data).
func (a *App) handleCACert(w http.ResponseWriter, r *http.Request) {
	if a.CA == nil {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "application/x-x509-ca-cert")
	// inline: iOS only offers to install the profile when it is not forced to download
	w.Header().Set("Content-Disposition", `inline; filename="Wharf-CA.crt"`)
	w.Header().Set("Cache-Control", "no-cache")
	_, _ = w.Write(a.CA.CADER())
}

// GET /manifest.webmanifest — generated so "add to home screen" uses the custom name.
func (a *App) handleManifest(w http.ResponseWriter, r *http.Request) {
	name := a.setting("ui.name")
	w.Header().Set("Content-Type", "application/manifest+json")
	w.Header().Set("Cache-Control", "no-cache")
	writeJSONRaw(w, map[string]any{
		"name": strings.TrimSpace(name + " " + a.setting("ui.subtitle")), "short_name": name, "description": "OpenWrt 多管理员控制面板",
		"start_url": "/", "scope": "/", "display": "standalone", "background_color": "#0b1220", "theme_color": "#1d5fe0",
		"icons": []map[string]string{
			{"src": "/icon-192.png", "sizes": "192x192", "type": "image/png"},
			{"src": "/icon-512.png", "sizes": "512x512", "type": "image/png"},
			{"src": "/icon-maskable.png", "sizes": "512x512", "type": "image/png", "purpose": "maskable"},
		},
	})
}

func writeJSONRaw(w http.ResponseWriter, v any) { _ = json.NewEncoder(w).Encode(v) }

var brandRe = regexp.MustCompile(`^[^<>"'&\x00-\x1f]*$`)

// POST /api/rules/update — rebuild the rule database from blackmatrix7 (online).
func (a *App) handleRulesUpdate(w http.ResponseWriter, r *http.Request) {
	c, err := a.updateRules()
	if err != nil {
		jsonErr(w, 502, err.Error())
		return
	}
	a.audit(actor{user: currentUser(r), ip: a.clientIP(r)}, "rules.update", "setting", "rules", "更新内容识别规则库 "+c.Version, nil, nil, false)
	writeJSON(w, 200, map[string]any{"version": c.Version, "missing": c.Missing, "updated_at": a.setting("rules.updated_at")})
}

func (a *App) updateRules() (*rules.Compiled, error) {
	c, err := rules.Build(&http.Client{Timeout: 60 * time.Second})
	if err != nil {
		return nil, err
	}
	if err := c.Write(a.cfg.Path("rules.json.gz")); err != nil {
		return nil, err
	}
	m, err := rules.Default(a.cfg.Path("rules.json.gz"))
	if err != nil {
		return nil, err
	}
	a.rules = m
	a.idc.reset()
	_ = a.setSetting("rules.updated_at", strconv.FormatInt(time.Now().Unix(), 10))
	return c, nil
}

// rulesAutoUpdate refreshes the rule database every rules.update_hours (0 = off),
// like AdGuard Home's filter update interval.
func (a *App) rulesAutoUpdate() {
	time.Sleep(5 * time.Minute)
	for {
		h := a.settingInt("rules.update_hours")
		last, _ := strconv.ParseInt(a.setting("rules.updated_at"), 10, 64)
		if h > 0 && time.Since(time.Unix(last, 0)) >= time.Duration(h)*time.Hour {
			if c, err := a.updateRules(); err != nil {
				log.Printf("rules auto-update: %v", err)
			} else {
				log.Printf("rules auto-updated to %s", c.Version)
			}
		}
		time.Sleep(time.Hour)
	}
}

// SetSettingCLI changes one setting from the command line, validated and audited as "system".
func SetSettingCLI(a *App, key, value string) error {
	if err := validSetting(key, value); err != nil {
		return err
	}
	old := a.setting(key)
	if err := a.setSetting(key, value); err != nil {
		return err
	}
	sys := &User{ID: 0, Username: "system"}
	if containsStr(secretSettings, key) {
		a.audit(actor{user: sys, ip: "cli"}, "setting.update", "setting", key, "命令行设置密钥 "+key, maskSecret(old), maskSecret(value), false)
	} else {
		a.audit(actor{user: sys, ip: "cli"}, "setting.update", "setting", key, "命令行修改设置 "+key, old, value, true)
	}
	return nil
}
