package panel

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Network interfaces: status, public address, outages, editing with the agent's
// confirm-or-roll-back guard.

const secretMarker = "\x00set" // the agent's placeholder for a secret that is set

type pendingInfo struct {
	Token    string   `json:"token"`
	Configs  []string `json:"configs"`
	Deadline int64    `json:"deadline"`
	Started  int64    `json:"started"`
	Summary  string   `json:"summary,omitempty"`
}

type netHealth struct {
	Health *struct {
		TS        int64           `json:"ts"`
		Internet  bool            `json:"internet"`
		Gateway   string          `json:"gateway"`
		GatewayOK bool            `json:"gateway_ok"`
		Targets   map[string]bool `json:"targets"`
		DownSince int64           `json:"down_since"`
		Checked   bool            `json:"checked"`
	} `json:"health"`
	Wans []struct {
		Up        bool   `json:"up"`
		Proto     string `json:"proto"`
		Device    string `json:"device"`
		Uptime    int64  `json:"uptime"`
		IPv4      string `json:"ipv4"`
		Gateway   string `json:"gateway"`
		Interface string `json:"interface"`
	} `json:"wans"`
	Pending  *pendingInfo   `json:"pending"`
	Rollback map[string]any `json:"rollback"`
}

var healthCache struct {
	sync.Mutex
	at  time.Time
	val netHealth
	err error
}

func (a *App) netHealth() (netHealth, error) {
	healthCache.Lock()
	defer healthCache.Unlock()
	if time.Since(healthCache.at) < 4*time.Second {
		return healthCache.val, healthCache.err
	}
	var h netHealth
	err := a.agent.Do("GET", "/v1/net/health", nil, &h)
	healthCache.at, healthCache.val, healthCache.err = time.Now(), h, err
	return h, err
}

func invalidateHealth() {
	healthCache.Lock()
	healthCache.at = time.Time{}
	healthCache.Unlock()
}

// GET /api/net/health — small and frequent: drives the "外网断了" banner and the
// "改动等待确认" bar on every page.
func (a *App) handleNetHealth(w http.ResponseWriter, r *http.Request) {
	h, err := a.netHealth()
	if err != nil {
		jsonErr(w, 502, "读不到路由器状态")
		return
	}
	u := currentUser(r)
	out := map[string]any{"wans": h.Wans}
	if h.Health != nil {
		out["internet"] = h.Health.Internet
		out["checked"] = h.Health.Checked
		out["down_since"] = h.Health.DownSince
		out["gateway"] = h.Health.Gateway
		out["gateway_ok"] = h.Health.GatewayOK
		out["ts"] = h.Health.TS
	}
	if u.Can("network.manage") || u.Can("firewall.manage") {
		out["pending"] = h.Pending
		out["rollback"] = h.Rollback
	}
	writeJSON(w, 200, out)
}

var pubCache struct {
	sync.Mutex
	at time.Time
	ip string
}

// publicIPv4 asks a public service which address the home leaves the internet with
// (needed when the WAN itself has a private / CGNAT address behind a modem).
func publicIPv4() string {
	pubCache.Lock()
	defer pubCache.Unlock()
	if time.Since(pubCache.at) < 5*time.Minute {
		return pubCache.ip
	}
	pubCache.at = time.Now()
	c := &http.Client{Timeout: 4 * time.Second}
	for _, u := range []string{"https://api.ipify.org", "https://ipv4.icanhazip.com", "https://ipv4.ddnspod.com"} {
		resp, err := c.Get(u)
		if err != nil {
			continue
		}
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 256))
		resp.Body.Close()
		if ip, err := netip.ParseAddr(strings.TrimSpace(string(b))); err == nil && ip.Is4() {
			pubCache.ip = ip.String()
			return pubCache.ip
		}
	}
	pubCache.ip = ""
	return ""
}

func addrOnly(cidr string) string {
	a, _, _ := strings.Cut(cidr, "/")
	return a
}

func strList(v any) []string {
	switch t := v.(type) {
	case string:
		return strings.Fields(t)
	case []any:
		var out []string
		for _, x := range t {
			out = append(out, fmt.Sprint(x))
		}
		return out
	case []string:
		return t
	}
	return nil
}

func sectionStr(s Section, k string) string {
	if s == nil {
		return ""
	}
	if v, ok := s[k]; ok && v != nil {
		if l, ok := v.([]any); ok {
			return strings.Join(strList(l), " ")
		}
		return fmt.Sprint(v)
	}
	return ""
}

// zonesOf maps interface -> firewall zone names.
func zonesOf(fw map[string]Section) map[string][]string {
	out := map[string][]string{}
	for _, s := range fw {
		if s[".type"] != "zone" {
			continue
		}
		for _, n := range strList(s["network"]) {
			out[n] = append(out[n], sectionStr(s, "name"))
		}
	}
	return out
}

// GET /api/net/interfaces
func (a *App) handleNetInterfaces(w http.ResponseWriter, r *http.Request) {
	var ov struct {
		Interfaces []map[string]any `json:"interfaces"`
		Devices    []map[string]any `json:"devices"`
		Pending    *pendingInfo     `json:"pending"`
		Firewall   string           `json:"firewall"`
		Protos     []string         `json:"protos"`
	}
	if err := a.agent.Do("GET", "/v1/net", nil, &ov); err != nil {
		jsonErr(w, 502, "读不到路由器的接口："+err.Error())
		return
	}
	fw, _ := a.agent.UciConfig("firewall")
	zones := zonesOf(fw)
	var zoneNames []string
	for _, s := range fw {
		if s[".type"] == "zone" {
			zoneNames = append(zoneNames, sectionStr(s, "name"))
		}
	}
	sort.Strings(zoneNames)
	var wan map[string]json.RawMessage
	_ = a.agent.Do("GET", "/v1/wan", nil, &wan)
	pub := ""
	for _, it := range ov.Interfaces {
		name := fmt.Sprint(it["name"])
		it["zones"] = zones[name]
		role := "other"
		zs := zones[name]
		switch {
		case slices.Contains(zs, "wan") || strings.HasPrefix(name, "wan"):
			role = "wan"
			if p := fmt.Sprint(it["proto"]); strings.HasPrefix(p, "dhcpv6") || p == "6in4" || p == "6to4" || p == "6rd" || p == "dslite" {
				role = "wan6"
			}
		case slices.Contains(zs, "lan") || strings.HasPrefix(name, "lan"):
			role = "lan"
		}
		it["role"] = role
		if role == "wan" {
			for _, c := range strList(it["ipv4"]) {
				ip := addrOnly(c)
				switch {
				case publicIP(ip):
					it["public"] = map[string]string{"ip": ip, "kind": "direct"}
				case ip != "":
					if pub == "" {
						pub = publicIPv4()
					}
					kind := "nat"
					if p, err := netip.ParseAddr(ip); err == nil && netip.MustParsePrefix("100.64.0.0/10").Contains(p) {
						kind = "cgnat"
					}
					it["public"] = map[string]string{"ip": pub, "kind": kind}
				}
			}
		}
	}
	// outages: pair down/up events of the last 30 days
	type outage struct {
		From int64  `json:"from"`
		To   int64  `json:"to"`
		Kind string `json:"kind"`
		Note string `json:"note"`
	}
	var outs []outage
	if rs, err := a.db.Query(`SELECT ts, kind, detail FROM wan_events WHERE ts>=? ORDER BY ts`, time.Now().Unix()-30*86400); err == nil {
		var open *outage
		for rs.Next() {
			var ts int64
			var kind, det string
			if rs.Scan(&ts, &kind, &det) != nil {
				continue
			}
			switch kind {
			case "down":
				if open == nil {
					open = &outage{From: ts, Kind: "down", Note: det}
				}
			case "up":
				if open != nil {
					open.To = ts
					outs = append(outs, *open)
					open = nil
				}
			case "reconnect":
				outs = append(outs, outage{From: ts, To: ts, Kind: "reconnect", Note: det})
			}
		}
		rs.Close()
		if open != nil {
			outs = append(outs, *open)
		}
	}
	slices.Reverse(outs)
	if len(outs) > 30 {
		outs = outs[:30]
	}
	h, _ := a.netHealth()
	out := map[string]any{"interfaces": ov.Interfaces, "devices": ov.Devices, "pending": ov.Pending, "firewall": ov.Firewall,
		"protos": ov.Protos, "zones": zoneNames, "outages": outs, "mwan3": wan["mwan3"], "health": h.Health, "rollback": h.Rollback}
	writeJSON(w, 200, out)
}

// POST /api/net/diagnose {iface}
func (a *App) handleNetDiagnose(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Iface string `json:"iface"`
	}
	_ = readJSON(r, &req)
	var d json.RawMessage
	if err := a.agent.Do("POST", "/v1/net/diagnose", map[string]string{"iface": req.Iface}, &d); err != nil {
		jsonErr(w, 502, err.Error())
		return
	}
	writeJSON(w, 200, d)
}

// POST /api/net/interfaces/{name}/action {action: restart|up|down}
func (a *App) handleNetIfaceAction(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	var req struct {
		Action string `json:"action"`
	}
	_ = readJSON(r, &req)
	if err := a.agent.Do("POST", "/v1/net/iface", map[string]string{"name": name, "action": req.Action}, nil); err != nil {
		jsonErr(w, 400, agentMsg(err))
		return
	}
	label := map[string]string{"restart": "重启", "up": "启动", "down": "停止"}[req.Action]
	a.audit(actor{user: currentUser(r), ip: a.clientIP(r)}, "net.iface."+req.Action, "interface", name, label+"接口 "+name, nil, nil, false)
	invalidateHealth()
	writeJSON(w, 200, map[string]bool{"ok": true})
}

// guardedApply sends changes through the agent's confirm-or-roll-back path and
// audits every section it touched.
func (a *App) guardedApply(r *http.Request, action, summary string, seconds int, changes []UciChange) (*pendingInfo, error) {
	var res struct {
		Results []UciResult  `json:"results"`
		Pending *pendingInfo `json:"pending"`
	}
	if err := a.agent.Do("POST", "/v1/uci/guarded", map[string]any{"changes": changes, "seconds": seconds, "summary": summary}, &res); err != nil {
		return nil, errors.New(agentMsg(err))
	}
	ac := actor{user: currentUser(r), ip: a.clientIP(r)}
	for _, x := range res.Results {
		a.audit(ac, action, "uci", x.Config+"."+x.Section, summary, x.Before, x.After, true)
	}
	invalidateHealth()
	return res.Pending, nil
}

// POST /api/net/confirm {token} · POST /api/net/rollback {token}
func (a *App) handleNetConfirm(keep bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		u := currentUser(r)
		if !u.Can("network.manage") && !u.Can("firewall.manage") {
			jsonErr(w, 403, "没有权限")
			return
		}
		var req struct {
			Token string `json:"token"`
		}
		_ = readJSON(r, &req)
		path := "/v1/uci/confirm"
		if !keep {
			path = "/v1/uci/rollback"
		}
		if err := a.agent.Do("POST", path, map[string]string{"token": req.Token}, nil); err != nil {
			jsonErr(w, 409, agentMsg(err))
			return
		}
		what := "确认保留网络改动"
		if !keep {
			what = "撤销网络改动"
		}
		a.audit(actor{user: u, ip: a.clientIP(r)}, "net.confirm", "uci", req.Token, what, nil, nil, false)
		invalidateHealth()
		writeJSON(w, 200, map[string]bool{"ok": true})
	}
}

// ---- interface editing ----

// options the form edits, per protocol; others are left as they are
var protoOpts = map[string][]string{
	"static": {"ipaddr", "netmask", "gateway", "broadcast", "ip6addr", "ip6gw"},
	"dhcp":   {"hostname", "clientid", "vendorid", "broadcast"},
	"pppoe":  {"username", "password", "service", "ac", "keepalive", "host_uniq"},
	"dhcpv6": {"reqaddress", "reqprefix", "ip6prefix"},
}
var commonOpts = []string{"proto", "device", "auto", "metric", "mtu", "peerdns", "dns", "macaddr", "ipv6", "ip6assign", "delegate", "force_link", "defaultroute"}

var (
	strictMACRe = regexp.MustCompile(`^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$`)
	devRe       = regexp.MustCompile(`^@?[A-Za-z0-9_.:-]{1,32}$`)
	textOkRe    = regexp.MustCompile(`^[^\x00-\x1f'"\\]{0,128}$`)
)

func validIfaceValue(k string, v any) error {
	s := fmt.Sprint(v)
	bad := func(what string) error { return fmt.Errorf("%s 不正确：%s", what, s) }
	switch k {
	case "proto":
		if !regexp.MustCompile(`^[a-z0-9_-]{1,20}$`).MatchString(s) {
			return bad("协议")
		}
	case "ipaddr", "gateway", "broadcast":
		for _, x := range strList(v) {
			p, err := netip.ParseAddr(addrOnly(x))
			if err != nil || !p.Is4() {
				return bad("IPv4 地址")
			}
		}
	case "netmask":
		p, err := netip.ParseAddr(s)
		if err != nil || !p.Is4() {
			return bad("子网掩码")
		}
		m := p.As4()
		n := uint32(m[0])<<24 | uint32(m[1])<<16 | uint32(m[2])<<8 | uint32(m[3])
		if n != 0 && (^n+1)&^n != 0 {
			return bad("子网掩码")
		}
	case "dns":
		for _, x := range strList(v) {
			if _, err := netip.ParseAddr(x); err != nil {
				return fmt.Errorf("DNS 服务器不正确：%s", x)
			}
		}
	case "ip6addr", "ip6gw", "ip6prefix":
		for _, x := range strList(v) {
			if _, err := netip.ParseAddr(addrOnly(x)); err != nil {
				return bad("IPv6 地址")
			}
		}
	case "mtu":
		n, err := strconv.Atoi(s)
		if s != "" && (err != nil || n < 576 || n > 9200) {
			return bad("MTU（576–9200）")
		}
	case "metric", "ip6assign", "keepalive":
		if s != "" && !regexp.MustCompile(`^[0-9 ]{1,12}$`).MatchString(s) {
			return bad(k)
		}
	case "macaddr":
		if s != "" && !strictMACRe.MatchString(s) {
			return bad("MAC 地址")
		}
	case "device":
		for _, x := range strList(v) {
			if !devRe.MatchString(x) {
				return bad("网口")
			}
		}
	case "auto", "peerdns", "ipv6", "delegate", "force_link", "defaultroute":
		if s != "0" && s != "1" && s != "" && s != "auto" {
			return bad(k)
		}
	default:
		if !textOkRe.MatchString(s) {
			return bad(k)
		}
	}
	return nil
}

type ifaceReq struct {
	Name   string         `json:"name"`
	Values map[string]any `json:"values"`
	Zone   *string        `json:"zone"` // nil = leave; "" = no zone
}

// ifaceChanges turns the form into uci changes for network.<name> (+ firewall zone).
func (a *App) ifaceChanges(name string, cur Section, req ifaceReq) ([]UciChange, error) {
	set := map[string]any{}
	var del []string
	proto := fmt.Sprint(req.Values["proto"])
	if proto == "" || proto == "<nil>" {
		proto = sectionStr(cur, "proto")
	}
	allowed := append(append([]string{}, commonOpts...), protoOpts[proto]...)
	for k, v := range req.Values {
		if !slices.Contains(allowed, k) {
			continue
		}
		if k == "password" && (v == nil || fmt.Sprint(v) == "" || fmt.Sprint(v) == secretMarker) {
			continue // unchanged secret
		}
		if v == nil || fmt.Sprint(v) == "" || (fmt.Sprint(v) == "[]") {
			if cur != nil && cur[k] != nil {
				del = append(del, k)
			}
			continue
		}
		if err := validIfaceValue(k, v); err != nil {
			return nil, err
		}
		if l, ok := v.([]any); ok {
			set[k] = strList(l)
		} else {
			set[k] = fmt.Sprint(v)
		}
	}
	// switching protocol drops the options that belong to the old one (like LuCI)
	if old := sectionStr(cur, "proto"); cur != nil && old != proto {
		for p, opts := range protoOpts {
			if p == proto {
				continue
			}
			for _, o := range opts {
				if cur[o] != nil && !slices.Contains(protoOpts[proto], o) && !slices.Contains(del, o) {
					del = append(del, o)
				}
			}
		}
	}
	if proto == "static" {
		ip := sectionStr(cur, "ipaddr")
		if v, given := req.Values["ipaddr"]; given {
			ip = ""
			if v != nil {
				ip = strings.TrimSpace(fmt.Sprint(v))
			}
		}
		if ip == "" {
			return nil, errors.New("静态地址需要填写 IP 地址")
		}
	}
	var ch []UciChange
	if cur == nil {
		set["proto"] = proto
		ch = append(ch, UciChange{Op: "add", Config: "network", Type: "interface", Name: name, Values: set})
	} else {
		if len(set) > 0 {
			ch = append(ch, UciChange{Op: "set", Config: "network", Section: name, Values: set})
		}
		if len(del) > 0 {
			ch = append(ch, UciChange{Op: "delete", Config: "network", Section: name, Options: del})
		}
	}
	if req.Zone != nil {
		zc, err := a.zoneMembership(name, *req.Zone)
		if err != nil {
			return nil, err
		}
		ch = append(ch, zc...)
	}
	return ch, nil
}

// zoneMembership moves interface name into zone (or out of all zones when zone = "").
func (a *App) zoneMembership(name, zone string) ([]UciChange, error) {
	fw, err := a.agent.UciConfig("firewall")
	if err != nil {
		return nil, err
	}
	var ch []UciChange
	found := zone == ""
	for sec, s := range fw {
		if s[".type"] != "zone" {
			continue
		}
		nets := strList(s["network"])
		has := slices.Contains(nets, name)
		want := sectionStr(s, "name") == zone
		if want {
			found = true
		}
		switch {
		case want && !has:
			ch = append(ch, UciChange{Op: "set", Config: "firewall", Section: sec, Values: map[string]any{"network": append(nets, name)}})
		case !want && has:
			nets = slices.DeleteFunc(nets, func(x string) bool { return x == name })
			if len(nets) == 0 {
				ch = append(ch, UciChange{Op: "delete", Config: "firewall", Section: sec, Options: []string{"network"}})
			} else {
				ch = append(ch, UciChange{Op: "set", Config: "firewall", Section: sec, Values: map[string]any{"network": nets}})
			}
		}
	}
	if !found {
		return nil, fmt.Errorf("没有名为 %s 的防火墙区域", zone)
	}
	return ch, nil
}

// PUT /api/net/interfaces/{name}
func (a *App) handleNetIfaceSave(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	var req ifaceReq
	if readJSON(r, &req) != nil {
		jsonErr(w, 400, "请求格式错误")
		return
	}
	net, err := a.agent.UciConfig("network")
	if err != nil {
		jsonErr(w, 502, err.Error())
		return
	}
	cur := net[name]
	if cur == nil || cur[".type"] != "interface" {
		jsonErr(w, 404, "没有这个接口")
		return
	}
	ch, err := a.ifaceChanges(name, cur, req)
	if err != nil {
		jsonErr(w, 400, err.Error())
		return
	}
	if len(ch) == 0 {
		writeJSON(w, 200, map[string]any{"ok": true})
		return
	}
	secs := 90
	if name == "lan" || sectionStr(cur, "ipaddr") != fmt.Sprint(req.Values["ipaddr"]) && req.Values["ipaddr"] != nil {
		secs = 240 // time to open the panel on the new address and confirm there
	}
	p, err := a.guardedApply(r, "net.iface.save", "修改接口 "+name, secs, ch)
	if err != nil {
		jsonErr(w, 409, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true, "pending": p})
}

var ifNameRe = regexp.MustCompile(`^[a-z][a-z0-9_]{0,14}$`)

// POST /api/net/interfaces {name, values, zone}
func (a *App) handleNetIfaceAdd(w http.ResponseWriter, r *http.Request) {
	var req ifaceReq
	if readJSON(r, &req) != nil {
		jsonErr(w, 400, "请求格式错误")
		return
	}
	req.Name = strings.ToLower(strings.TrimSpace(req.Name))
	if !ifNameRe.MatchString(req.Name) || req.Name == "loopback" {
		jsonErr(w, 400, "接口名只能用小写字母、数字和下划线，字母开头，最多 15 个字符")
		return
	}
	net, err := a.agent.UciConfig("network")
	if err != nil {
		jsonErr(w, 502, err.Error())
		return
	}
	if _, ok := net[req.Name]; ok {
		jsonErr(w, 409, "已经有这个名字的配置")
		return
	}
	ch, err := a.ifaceChanges(req.Name, nil, req)
	if err != nil {
		jsonErr(w, 400, err.Error())
		return
	}
	p, err := a.guardedApply(r, "net.iface.add", "新增接口 "+req.Name, 90, ch)
	if err != nil {
		jsonErr(w, 409, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true, "pending": p})
}

// DELETE /api/net/interfaces/{name}
func (a *App) handleNetIfaceDelete(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	if name == "lan" || name == "loopback" {
		jsonErr(w, 400, "不能删除这个接口")
		return
	}
	net, err := a.agent.UciConfig("network")
	if err != nil {
		jsonErr(w, 502, err.Error())
		return
	}
	if s := net[name]; s == nil || s[".type"] != "interface" {
		jsonErr(w, 404, "没有这个接口")
		return
	}
	ch := []UciChange{{Op: "delete", Config: "network", Section: name}}
	zc, err := a.zoneMembership(name, "")
	if err == nil {
		ch = append(ch, zc...)
	}
	// its DHCP pool goes too
	if dh, err := a.agent.UciConfig("dhcp"); err == nil {
		for sec, s := range dh {
			if s[".type"] == "dhcp" && sectionStr(s, "interface") == name {
				ch = append(ch, UciChange{Op: "delete", Config: "dhcp", Section: sec})
			}
		}
	}
	p, err := a.guardedApply(r, "net.iface.delete", "删除接口 "+name, 90, ch)
	if err != nil {
		jsonErr(w, 409, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true, "pending": p})
}

// zone tidy-up: networks listed in a zone that no longer exist (left behind by old setups)
func orphanNetworks(fw map[string]Section, net map[string]Section) map[string][]string {
	out := map[string][]string{}
	for _, s := range fw {
		if s[".type"] != "zone" {
			continue
		}
		for _, n := range strList(s["network"]) {
			if x := net[n]; x == nil || x[".type"] != "interface" {
				out[sectionStr(s, "name")] = append(out[sectionStr(s, "name")], n)
			}
		}
	}
	return out
}
