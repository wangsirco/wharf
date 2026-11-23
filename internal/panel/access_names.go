package panel

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"regexp"
	"slices"
	"strings"
	"time"
)

// One name at home, one outside, no ports (Wharf ⇄ Berth v3 §1–2):
//
//   - LAN: https://wharf.lan — the label is the setting panel.lan_host (default "wharf"),
//     the zone dnsmasq's domain. With panel.lan443 on, the agent's splitter takes the
//     router's LAN 443 for the panel's names and hands everything else (LuCI by IP) to
//     uhttpd (agent/lan443.go); otherwise the name carries the panel's port.
//   - public: the first of: a public name through 443 or proxied by Cloudflare, a tunnel
//     name, a public name on the panel's own port.
//   - fallback: https://<LAN IP>:<port>, never shown first.

var lanHostRe = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,30}[a-z0-9])?$`)

func (a *App) lanHost() string {
	if h := a.setting("panel.lan_host"); lanHostRe.MatchString(h) {
		return h
	}
	return localPanelHost
}

func (a *App) lan443() bool { return a.setting("panel.lan443") == "1" }

func (a *App) panelPort() string {
	_, port, _ := net.SplitHostPort(a.cfg.Listen)
	return port
}

func withPort(host, port string) string {
	if port == "" || port == "443" {
		return "https://" + host
	}
	return "https://" + host + ":" + port
}

// lanURL: the panel's address at home.
func (a *App) lanURL() string {
	if a.lan443() {
		return "https://" + a.localPanelName()
	}
	return withPort(a.localPanelName(), a.panelPort())
}

// publicURL: the panel's address from outside, "" when there is none.
func (a *App) publicURL() string {
	ns := a.publicNames()
	proxied := a.proxiedNames()
	for _, n := range ns {
		if a.setting("panel.via_443") == "1" || slices.Contains(proxied, n) {
			return "https://" + n
		}
	}
	if t := a.tunnelPanelNames(); len(t) > 0 {
		return "https://" + t[0]
	}
	if len(ns) > 0 && a.setting("panel.via_port") == "1" {
		return withPort(ns[0], a.panelPort())
	}
	return ""
}

func (a *App) fallbackURL() string {
	_, ip := a.lanInfo()
	if ip == "" {
		return ""
	}
	return withPort(ip, a.panelPort())
}

// knownHost: a name the panel answers to as itself (no move to the LAN name from here).
func (a *App) knownHost(host string) bool {
	h := strings.ToLower(host)
	if hh, _, err := net.SplitHostPort(h); err == nil {
		h = hh
	}
	return slices.Contains(a.passkeyHosts(), h)
}

// syncLAN443 tells the agent which names are the panel's and whether 443 is shared.
func (a *App) syncLAN443() error {
	_, ip := a.lanInfo()
	names := append([]string{a.localPanelName()}, a.publicNames()...)
	return a.agent.Do("POST", "/v1/lan443", map[string]any{"enabled": a.lan443(), "names": names, "lan_ip": ip}, nil)
}

// RefreshCert is set by main: re-issue the local certificate when the LAN name changes.
var RefreshCert func()

// LANName is the panel's LAN name for the local certificate.
func (a *App) LANName() string { return a.localPanelName() }

// GET /api/panel/primary (no sign-in: the login page uses it too) — where to move to.
func (a *App) handlePanelPrimary(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, 200, map[string]any{"lan": a.lanURL(), "known": a.knownHost(r.Host) || fromTunnel(r)})
}

type lan443State struct {
	Enabled   bool     `json:"enabled"`
	Names     []string `json:"names"`
	Listening bool     `json:"listening"`
	Redirect  bool     `json:"redirect"`
	Other     bool     `json:"other"`
	Error     string   `json:"error"`
}

// GET /api/panel/access — the 访问地址 card.
func (a *App) handlePanelAccess(w http.ResponseWriter, r *http.Request) {
	var st lan443State
	agentErr := a.agent.Do("GET", "/v1/lan443", nil, &st)
	d, _ := a.lanInfo()
	out := map[string]any{"lan": a.lanURL(), "lan_name": a.localPanelName(), "lan_host": a.lanHost(), "domain": d, "lan443": a.lan443(),
		"public": a.publicURL(), "public_names": a.publicNames(), "fallback": a.fallbackURL(), "port": a.panelPort(), "splitter": st}
	if agentErr != nil {
		out["splitter_error"] = "路由器上的 Agent 还不支持（需要 0.25.0 或更新）"
	}
	writeJSON(w, 200, out)
}

// PUT /api/panel/access {lan443, lan_host}
func (a *App) handlePanelAccessSave(w http.ResponseWriter, r *http.Request) {
	var req struct {
		LAN443  *bool   `json:"lan443"`
		LANHost *string `json:"lan_host"`
	}
	if readJSON(r, &req) != nil {
		jsonErr(w, 400, "请求格式错误")
		return
	}
	ac := actor{user: currentUser(r), ip: a.clientIP(r)}
	if req.LANHost != nil {
		h := strings.ToLower(strings.TrimSpace(*req.LANHost))
		if !lanHostRe.MatchString(h) {
			jsonErr(w, 400, "名字只能用小写字母、数字和连字符，最长 32 个字符")
			return
		}
		if h != a.lanHost() {
			before := a.localPanelName()
			if err := a.setSetting("panel.lan_host", h); err != nil {
				jsonErr(w, 500, err.Error())
				return
			}
			if err := a.syncPanelNames(); err != nil {
				jsonErr(w, 502, "改名没有写进路由器 DNS："+err.Error())
				return
			}
			if RefreshCert != nil {
				RefreshCert()
			}
			a.audit(ac, "setting.update", "setting", "panel.lan_host", fmt.Sprintf("内网名字 %s 改为 %s", before, a.localPanelName()), before, a.localPanelName(), false)
			a.berthNotifyNames()
		}
	}
	if req.LAN443 != nil && *req.LAN443 != a.lan443() {
		v := map[bool]string{true: "1", false: "0"}[*req.LAN443]
		if err := a.setSetting("panel.lan443", v); err != nil {
			jsonErr(w, 500, err.Error())
			return
		}
		if err := a.syncLAN443(); err != nil {
			_ = a.setSetting("panel.lan443", map[bool]string{true: "0", false: "1"}[*req.LAN443])
			jsonErr(w, 502, "路由器没能完成："+err.Error())
			return
		}
		_ = a.syncPanelNames() // public names at home now point at the LAN address
		what := map[bool]string{true: "开启「内网名字不带端口」（路由器 443 端口分流）", false: "关闭「内网名字不带端口」"}[*req.LAN443]
		a.audit(ac, "setting.update", "setting", "panel.lan443", what, nil, v, false)
		a.berthNotifyNames()
	} else {
		_ = a.syncLAN443()
	}
	a.handlePanelAccess(w, r)
}

// lan443Loop keeps the splitter's names in step (names change, the agent restarts).
func (a *App) lan443Loop() {
	time.Sleep(15 * time.Second)
	for {
		if err := a.syncLAN443(); err != nil && !errors.Is(err, context.Canceled) {
			log.Printf("lan443: %v", err)
		}
		time.Sleep(10 * time.Minute)
	}
}
