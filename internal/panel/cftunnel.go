package panel

import (
	"context"
	"encoding/json"
	"errors"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"
)

// Cloudflare Tunnel: no port opened, no home address exposed, works without a public IP.
// The panel owns one tunnel per router ("wharf-<router>"), remotely managed: its routes
// (hostname -> service) live at Cloudflare, cloudflared on the router (agent/tunnel.go)
// only holds the token. Routes are the panel itself (through a unix socket that only
// cloudflared can open, so the visitor address it reports can be trusted) and, if
// wanted, services at home (http://192.168.1.10:8080).
//
// Tunnels of other tools in the same account (Berth names its own "berth-…") are listed
// read-only and never touched.

const tunnelSocket = "/var/run/wharf-tunnel.sock"

type tunnelRoute struct {
	Hostname string `json:"hostname"`
	Kind     string `json:"kind"`    // panel | lan
	Service  string `json:"service"` // lan: http(s)://ip:port
	NoVerify bool   `json:"no_verify,omitempty"`
	ZoneID   string `json:"zone_id"`
	RecordID string `json:"record_id,omitempty"`
	Created  int64  `json:"created"`
}

type tunnelConf struct {
	AccountID string        `json:"account_id"`
	ID        string        `json:"id"`
	Name      string        `json:"name"`
	Created   int64         `json:"created"`
	Routes    []tunnelRoute `json:"routes"`
}

var tunnelMu sync.Mutex

func (a *App) tunnelConf() tunnelConf {
	var c tunnelConf
	_ = json.Unmarshal([]byte(a.setting("cf.tunnel")), &c)
	if c.Routes == nil {
		c.Routes = []tunnelRoute{}
	}
	return c
}

func (a *App) saveTunnelConf(c tunnelConf) error {
	b, _ := json.Marshal(c)
	return a.setSetting("cf.tunnel", string(b))
}

// tunnelPanelNames: names that reach the panel through the tunnel (passkeys work on them).
func (a *App) tunnelPanelNames() []string {
	var out []string
	for _, r := range a.tunnelConf().Routes {
		if r.Kind == "panel" {
			out = append(out, r.Hostname)
		}
	}
	return out
}

// ---- the socket cloudflared hands panel visitors to ----

type tunnelCtxKey struct{}

func fromTunnel(r *http.Request) bool { v, _ := r.Context().Value(tunnelCtxKey{}).(bool); return v }

// ServeTunnel listens on the unix socket for cloudflared (owner nobody, mode 0600).
func (a *App) ServeTunnel(h http.Handler) {
	_ = os.Remove(tunnelSocket)
	ln, err := net.Listen("unix", tunnelSocket)
	if err != nil {
		log.Printf("panel: tunnel socket: %v", err)
		return
	}
	uid, gid := 65534, 65534
	_ = os.Chown(tunnelSocket, uid, gid)
	_ = os.Chmod(tunnelSocket, 0o600)
	srv := &http.Server{
		Handler: h, ReadHeaderTimeout: 10 * time.Second, ReadTimeout: 30 * time.Second, WriteTimeout: 120 * time.Second, IdleTimeout: 120 * time.Second,
		ConnContext: func(ctx context.Context, _ net.Conn) context.Context {
			return context.WithValue(ctx, tunnelCtxKey{}, true)
		},
	}
	_ = srv.Serve(ln)
}

// ---- Cloudflare side ----

type cfTunnel struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Status      string `json:"status"` // healthy | degraded | down | inactive
	CreatedAt   string `json:"created_at"`
	Connections []struct {
		ColoName string `json:"colo_name"`
		OriginIP string `json:"origin_ip"`
	} `json:"connections"`
}

var tunnelNameRe = regexp.MustCompile(`[^a-z0-9-]+`)

func (a *App) defaultTunnelName() string {
	h, _ := os.Hostname()
	h = strings.Trim(tunnelNameRe.ReplaceAllString(strings.ToLower(h), "-"), "-")
	if h == "" {
		h = "router"
	}
	return "wharf-" + h
}

func (a *App) cfToken() (string, error) {
	tok := a.setting("cloudflare.token")
	if tok == "" {
		return "", errors.New("还没有连接 Cloudflare 账号")
	}
	return tok, nil
}

// ensureTunnel creates the tunnel if there is none (or it was deleted at Cloudflare) and
// hands its token to the router.
func (a *App) ensureTunnel(tok string, c *tunnelConf) error {
	acc, err := cfAccountOf(tok)
	if err != nil {
		return err
	}
	if c.ID != "" && c.AccountID == acc.ID {
		var t struct {
			DeletedAt *string `json:"deleted_at"`
		}
		if err := cfDo(tok, "GET", "/accounts/"+acc.ID+"/cfd_tunnel/"+c.ID, nil, &t); err == nil && t.DeletedAt == nil {
			return a.pushTunnelToken(tok, c)
		}
	}
	name := a.defaultTunnelName()
	var t cfTunnel
	if err := cfDo(tok, "POST", "/accounts/"+acc.ID+"/cfd_tunnel", map[string]any{"name": name, "config_src": "cloudflare"}, &t); err != nil {
		if isDenied(err) {
			return errors.New("令牌没有「账户 · Cloudflare Tunnel · 编辑」权限，请在 Cloudflare 给令牌加上")
		}
		// a tunnel of that name left over from before: take it
		var list []cfTunnel
		if e2 := cfDo(tok, "GET", "/accounts/"+acc.ID+"/cfd_tunnel?is_deleted=false&name="+url.QueryEscape(name), nil, &list); e2 != nil || len(list) == 0 {
			return err
		}
		t = list[0]
	}
	c.AccountID, c.ID, c.Name, c.Created = acc.ID, t.ID, name, time.Now().Unix()
	if err := a.saveTunnelConf(*c); err != nil {
		return err
	}
	return a.pushTunnelToken(tok, c)
}

func (a *App) pushTunnelToken(tok string, c *tunnelConf) error {
	var token string
	if err := cfDo(tok, "GET", "/accounts/"+c.AccountID+"/cfd_tunnel/"+c.ID+"/token", nil, &token); err != nil {
		return err
	}
	var st struct {
		HasToken bool `json:"has_token"`
	}
	_ = a.agent.Do("GET", "/v1/tunnel", nil, &st)
	if st.HasToken && a.setting("cf.tunnel_token_for") == c.ID {
		return nil
	}
	if err := a.agent.Do("POST", "/v1/tunnel", map[string]string{"action": "token", "token": token}, nil); err != nil {
		return errors.New("把隧道令牌交给路由器失败：" + agentMsg(err))
	}
	return a.setSetting("cf.tunnel_token_for", c.ID)
}

// pushTunnelConfig writes the routes to Cloudflare.
func (a *App) pushTunnelConfig(tok string, c tunnelConf) error {
	ingress := []map[string]any{}
	for _, r := range c.Routes {
		in := map[string]any{"hostname": r.Hostname}
		if r.Kind == "panel" {
			in["service"] = "unix:" + tunnelSocket
		} else {
			in["service"] = r.Service
			if r.NoVerify {
				in["originRequest"] = map[string]any{"noTLSVerify": true}
			}
		}
		ingress = append(ingress, in)
	}
	ingress = append(ingress, map[string]any{"service": "http_status:404"})
	return cfDo(tok, "PUT", "/accounts/"+c.AccountID+"/cfd_tunnel/"+c.ID+"/configurations", map[string]any{"config": map[string]any{"ingress": ingress}}, nil)
}

type cfDNSRec struct {
	ID      string `json:"id"`
	Type    string `json:"type"`
	Name    string `json:"name"`
	Content string `json:"content"`
	Proxied bool   `json:"proxied"`
	Comment string `json:"comment"`
}

// pointToTunnel makes hostname a proxied CNAME to the tunnel. An existing record that
// points elsewhere is only replaced with replace=true.
func pointToTunnel(tok, zoneID, hostname, tunnelID string, replace bool) (string, error) {
	target := tunnelID + ".cfargotunnel.com"
	var recs []cfDNSRec
	if err := cfDo(tok, "GET", "/zones/"+zoneID+"/dns_records?name="+url.QueryEscape(hostname), nil, &recs); err != nil {
		return "", err
	}
	rec := map[string]any{"type": "CNAME", "name": hostname, "content": target, "proxied": true, "ttl": 1, "comment": "Wharf tunnel"}
	for _, r := range recs {
		if r.Type == "CNAME" && strings.EqualFold(r.Content, target) {
			return r.ID, nil
		}
	}
	if len(recs) > 0 && !replace {
		r := recs[0]
		return "", &conflictErr{msg: "已经有一条记录 " + r.Type + " " + r.Name + " → " + r.Content + "，替换成指向隧道吗？"}
	}
	for _, r := range recs {
		if err := cfDo(tok, "DELETE", "/zones/"+zoneID+"/dns_records/"+r.ID, nil, nil); err != nil {
			return "", err
		}
	}
	var out cfDNSRec
	if err := cfDo(tok, "POST", "/zones/"+zoneID+"/dns_records", rec, &out); err != nil {
		return "", err
	}
	return out.ID, nil
}

type conflictErr struct{ msg string }

func (e *conflictErr) Error() string { return e.msg }

// ---- HTTP ----

// GET /api/cloudflare/tunnel
func (a *App) handleTunnel(w http.ResponseWriter, r *http.Request) {
	c := a.tunnelConf()
	out := map[string]any{"conf": c, "default_name": a.defaultTunnelName(), "socket": tunnelSocket}
	var st json.RawMessage
	if err := a.agent.Do("GET", "/v1/tunnel", nil, &st); err == nil {
		out["router"] = st
	} else {
		out["router_error"] = agentMsg(err)
	}
	if tok := a.setting("cloudflare.token"); tok != "" {
		if acc, err := cfAccountOf(tok); err == nil {
			var list []cfTunnel
			if err := cfDo(tok, "GET", "/accounts/"+acc.ID+"/cfd_tunnel?is_deleted=false&per_page=50", nil, &list); err == nil {
				out["tunnels"] = list
			} else {
				out["tunnels_error"] = err.Error()
				out["tunnels_denied"] = isDenied(err)
			}
		}
	}
	writeJSON(w, 200, out)
}

// POST /api/cloudflare/tunnel/router {action: install|update|uninstall|restart}
func (a *App) handleTunnelRouter(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Action string `json:"action"`
	}
	if readJSON(r, &req) != nil {
		jsonErr(w, 400, "请求格式错误")
		return
	}
	if req.Action == "uninstall" && len(a.tunnelConf().Routes) > 0 {
		jsonErr(w, 400, "隧道上还有公开的名字，请先删掉它们")
		return
	}
	var st json.RawMessage
	if err := a.agent.Do("POST", "/v1/tunnel", map[string]string{"action": req.Action}, &st); err != nil {
		jsonErr(w, 400, agentMsg(err))
		return
	}
	if req.Action == "uninstall" {
		_ = a.setSetting("cf.tunnel_token_for", "")
	}
	a.audit(actor{user: currentUser(r), ip: a.clientIP(r)}, "tunnel."+req.Action, "tunnel", "cloudflared", map[string]string{
		"install": "安装 cloudflared", "update": "更新 cloudflared", "uninstall": "删除 cloudflared", "restart": "重启 Cloudflare 隧道"}[req.Action], nil, nil, false)
	writeJSON(w, 200, st)
}

var fqdnRe = regexp.MustCompile(`^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$`)

// POST /api/cloudflare/tunnel/routes {hostname, kind, service, no_verify, replace}
func (a *App) handleTunnelRouteAdd(w http.ResponseWriter, r *http.Request) {
	var req struct {
		tunnelRoute
		Replace bool `json:"replace"`
	}
	if readJSON(r, &req) != nil {
		jsonErr(w, 400, "请求格式错误")
		return
	}
	rt := req.tunnelRoute
	rt.Hostname = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(rt.Hostname)), ".")
	if !fqdnRe.MatchString(rt.Hostname) {
		jsonErr(w, 400, "名字不对，例如 wharf.example.com")
		return
	}
	switch rt.Kind {
	case "panel":
		rt.Service, rt.NoVerify = "", false
	case "lan":
		u, err := url.Parse(strings.TrimSpace(rt.Service))
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Hostname() == "" || (u.Path != "" && u.Path != "/") {
			jsonErr(w, 400, "服务地址写成 http://192.168.1.10:8080 这样")
			return
		}
		ip := net.ParseIP(u.Hostname())
		if ip == nil || !(ip.IsPrivate() || ip.IsLoopback()) {
			jsonErr(w, 400, "只能是家里的地址（内网 IP）")
			return
		}
		rt.Service = u.Scheme + "://" + u.Host
	default:
		jsonErr(w, 400, "请选择要公开什么")
		return
	}
	tok, err := a.cfToken()
	if err != nil {
		jsonErr(w, 400, err.Error())
		return
	}
	tunnelMu.Lock()
	defer tunnelMu.Unlock()
	c := a.tunnelConf()
	for _, x := range c.Routes {
		if x.Hostname == rt.Hostname {
			jsonErr(w, 409, rt.Hostname+" 已经在隧道上了")
			return
		}
	}
	if slicesContains(a.publicNames(), rt.Hostname) {
		jsonErr(w, 409, rt.Hostname+" 已经是面板的公网域名（橙色云 / 直连），一个名字只能走一种方式")
		return
	}
	zoneID, err := cfZone(cfCall(tok), rt.Hostname)
	if err != nil {
		jsonErr(w, 400, err.Error())
		return
	}
	var st struct {
		Installed bool `json:"installed"`
	}
	if err := a.agent.Do("GET", "/v1/tunnel", nil, &st); err != nil || !st.Installed {
		jsonErr(w, 400, "路由器上还没有装 cloudflared，先点「安装」")
		return
	}
	if err := a.ensureTunnel(tok, &c); err != nil {
		jsonErr(w, 400, err.Error())
		return
	}
	rec, err := pointToTunnel(tok, zoneID, rt.Hostname, c.ID, req.Replace)
	if err != nil {
		var ce *conflictErr
		if errors.As(err, &ce) {
			writeJSON(w, 409, map[string]any{"error": ce.msg, "conflict": true})
			return
		}
		jsonErr(w, 400, err.Error())
		return
	}
	rt.ZoneID, rt.RecordID, rt.Created = zoneID, rec, time.Now().Unix()
	c.Routes = append(c.Routes, rt)
	if err := a.pushTunnelConfig(tok, c); err != nil {
		jsonErr(w, 400, err.Error())
		return
	}
	if err := a.saveTunnelConf(c); err != nil {
		jsonErr(w, 500, err.Error())
		return
	}
	what := "经 Cloudflare 隧道公开面板：" + rt.Hostname
	if rt.Kind == "lan" {
		what = "经 Cloudflare 隧道公开 " + rt.Service + "：" + rt.Hostname
	}
	a.audit(actor{user: currentUser(r), ip: a.clientIP(r)}, "tunnel.route.add", "tunnel", rt.Hostname, what, nil, rt, false)
	writeJSON(w, 200, map[string]any{"ok": true, "conf": c})
}

// DELETE /api/cloudflare/tunnel/routes?hostname=
func (a *App) handleTunnelRouteDelete(w http.ResponseWriter, r *http.Request) {
	host := r.URL.Query().Get("hostname")
	tok, err := a.cfToken()
	if err != nil {
		jsonErr(w, 400, err.Error())
		return
	}
	tunnelMu.Lock()
	defer tunnelMu.Unlock()
	c := a.tunnelConf()
	var keep []tunnelRoute
	var gone *tunnelRoute
	for i := range c.Routes {
		if c.Routes[i].Hostname == host {
			gone = &c.Routes[i]
		} else {
			keep = append(keep, c.Routes[i])
		}
	}
	if gone == nil {
		jsonErr(w, 404, "隧道上没有这个名字")
		return
	}
	if gone.Kind == "panel" && fromTunnel(r) && strings.EqualFold(hostOnly(r.Host), host) {
		jsonErr(w, 400, "你正是通过这个名字打开的面板，删掉就进不来了。请换一个地址打开后再删")
		return
	}
	if keep == nil {
		keep = []tunnelRoute{}
	}
	c.Routes = keep
	if err := a.pushTunnelConfig(tok, c); err != nil {
		jsonErr(w, 400, err.Error())
		return
	}
	if gone.RecordID != "" {
		if err := cfDo(tok, "DELETE", "/zones/"+gone.ZoneID+"/dns_records/"+gone.RecordID, nil, nil); err != nil && !strings.Contains(err.Error(), "81044") {
			log.Printf("tunnel: delete DNS record of %s: %v", host, err)
		}
	}
	_ = a.saveTunnelConf(c)
	a.audit(actor{user: currentUser(r), ip: a.clientIP(r)}, "tunnel.route.delete", "tunnel", host, "从 Cloudflare 隧道撤下 "+host, gone, nil, false)
	writeJSON(w, 200, map[string]any{"ok": true, "conf": c})
}

// DELETE /api/cloudflare/tunnel — remove the tunnel at Cloudflare and stop it on the router.
func (a *App) handleTunnelDelete(w http.ResponseWriter, r *http.Request) {
	tok, err := a.cfToken()
	if err != nil {
		jsonErr(w, 400, err.Error())
		return
	}
	tunnelMu.Lock()
	defer tunnelMu.Unlock()
	c := a.tunnelConf()
	if len(c.Routes) > 0 {
		jsonErr(w, 400, "隧道上还有公开的名字，请先删掉它们")
		return
	}
	_ = a.agent.Do("POST", "/v1/tunnel", map[string]string{"action": "token", "token": ""}, nil)
	if c.ID != "" {
		_ = cfDo(tok, "DELETE", "/accounts/"+c.AccountID+"/cfd_tunnel/"+c.ID+"/connections", nil, nil)
		if err := cfDo(tok, "DELETE", "/accounts/"+c.AccountID+"/cfd_tunnel/"+c.ID, nil, nil); err != nil && !strings.Contains(strings.ToLower(err.Error()), "not found") {
			jsonErr(w, 400, err.Error())
			return
		}
	}
	_ = a.setSetting("cf.tunnel", "")
	_ = a.setSetting("cf.tunnel_token_for", "")
	a.audit(actor{user: currentUser(r), ip: a.clientIP(r)}, "tunnel.delete", "tunnel", c.Name, "删除 Cloudflare 隧道 "+c.Name, nil, nil, false)
	writeJSON(w, 200, map[string]bool{"ok": true})
}

func hostOnly(h string) string {
	if x, _, err := net.SplitHostPort(h); err == nil {
		return x
	}
	return h
}

func slicesContains(l []string, s string) bool {
	for _, x := range l {
		if strings.EqualFold(x, s) {
			return true
		}
	}
	return false
}
