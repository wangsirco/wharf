package panel

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/netip"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
)

// DHCP / DNS and firewall pages. Like the rest of Wharf, uci is the only source
// of truth: what LuCI shows and what Wharf shows are always the same.

// ---- DHCP / DNS ----

// dnsUpstreamHint names what sits behind a dnsmasq upstream like 127.0.0.1#5342.
func dnsUpstreamHint(servers []string) string {
	for _, s := range servers {
		host, port, _ := strings.Cut(s, "#")
		if host != "127.0.0.1" && host != "::1" {
			continue
		}
		switch port {
		case "5342":
			return "NextDNS 插件"
		case "6053", "6153", "5335":
			return "SmartDNS 插件"
		case "7874":
			return "OpenClash"
		case "15353", "15355":
			return "PassWall"
		case "5053", "5054":
			return "AdGuard Home / mosdns"
		}
		return "本机 " + port + " 端口上的 DNS 服务"
	}
	return ""
}

// GET /api/net/dhcp
func (a *App) handleNetDHCP(w http.ResponseWriter, r *http.Request) {
	dh, err := a.agent.UciConfig("dhcp")
	if err != nil {
		jsonErr(w, 502, err.Error())
		return
	}
	net, _ := a.agent.UciConfig("network")
	var pools, hosts, domains []map[string]any
	var dnsmasq map[string]any
	for sec, s := range dh {
		switch s[".type"] {
		case "dhcp":
			iface := sectionStr(s, "interface")
			p := map[string]any{"section": sec, "interface": iface, "start": sectionStr(s, "start"), "limit": sectionStr(s, "limit"),
				"leasetime": sectionStr(s, "leasetime"), "ignore": sectionStr(s, "ignore") == "1", "force": sectionStr(s, "force") == "1",
				"dhcpv4": sectionStr(s, "dhcpv4"), "dhcpv6": sectionStr(s, "dhcpv6"), "ra": sectionStr(s, "ra")}
			var dns, gw []string
			var other []string
			for _, o := range strList(s["dhcp_option"]) {
				code, val, _ := strings.Cut(o, ",")
				switch code {
				case "6", "option:dns-server":
					dns = append(dns, strings.Split(val, ",")...)
				case "3", "option:router":
					gw = append(gw, val)
				default:
					other = append(other, o)
				}
			}
			p["dns"], p["gateway"], p["other_options"] = dns, strings.Join(gw, ","), other
			if n := net[iface]; n != nil {
				p["subnet"] = sectionStr(n, "ipaddr") + "/" + sectionStr(n, "netmask")
				p["proto"] = sectionStr(n, "proto")
			}
			pools = append(pools, p)
		case "host":
			hosts = append(hosts, map[string]any{"section": sec, "name": sectionStr(s, "name"), "mac": strList(s["mac"]), "ip": sectionStr(s, "ip"),
				"leasetime": sectionStr(s, "leasetime"), "managed": strings.HasPrefix(sec, "owp")})
		case "domain":
			domains = append(domains, map[string]any{"section": sec, "name": sectionStr(s, "name"), "ip": sectionStr(s, "ip"), "managed": strings.HasPrefix(sec, "owp")})
		case "dnsmasq":
			if dnsmasq != nil {
				continue
			}
			servers := strList(s["server"])
			dnsmasq = map[string]any{"section": sec, "server": servers, "noresolv": sectionStr(s, "noresolv") == "1", "cachesize": sectionStr(s, "cachesize"),
				"domain": sectionStr(s, "domain"), "local": sectionStr(s, "local"), "rebind_protection": sectionStr(s, "rebind_protection") != "0",
				"rebind_domain": strList(s["rebind_domain"]), "filter_aaaa": sectionStr(s, "filter_aaaa") == "1", "localservice": sectionStr(s, "localservice") != "0",
				"address": strList(s["address"]), "upstream_hint": dnsUpstreamHint(servers), "logqueries": sectionStr(s, "logqueries") == "1"}
		}
	}
	sort.Slice(pools, func(i, j int) bool { return fmt.Sprint(pools[i]["interface"]) < fmt.Sprint(pools[j]["interface"]) })
	sort.Slice(hosts, func(i, j int) bool { return ipLess(fmt.Sprint(hosts[i]["ip"]), fmt.Sprint(hosts[j]["ip"])) })
	sort.Slice(domains, func(i, j int) bool { return fmt.Sprint(domains[i]["name"]) < fmt.Sprint(domains[j]["name"]) })
	var leases any
	var lr struct {
		Result any `json:"result"`
	}
	if a.agent.Do("POST", "/v1/luci/rpc", map[string]any{"object": "luci-rpc", "method": "getDHCPLeases", "params": map[string]any{}}, &lr) == nil {
		leases = lr.Result
	}
	var ifaces []string
	for n, s := range net {
		if s[".type"] == "interface" && n != "loopback" {
			ifaces = append(ifaces, n)
		}
	}
	sort.Strings(ifaces)
	writeJSON(w, 200, map[string]any{"pools": pools, "hosts": hosts, "domains": domains, "dnsmasq": dnsmasq, "leases": leases, "interfaces": ifaces})
}

func ipLess(a, b string) bool {
	x, e1 := netip.ParseAddr(a)
	y, e2 := netip.ParseAddr(b)
	if e1 != nil || e2 != nil {
		return a < b
	}
	return x.Less(y)
}

var leaseRe = regexp.MustCompile(`^(\d+[smhdw]?|infinite)$`)

// PUT /api/net/dhcp/pool/{section} · POST /api/net/dhcp/pool {interface,…}
func (a *App) handleNetDHCPPool(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Interface string   `json:"interface"`
		Start     string   `json:"start"`
		Limit     string   `json:"limit"`
		Leasetime string   `json:"leasetime"`
		Ignore    bool     `json:"ignore"`
		Force     bool     `json:"force"`
		DNS       []string `json:"dns"`
		Gateway   string   `json:"gateway"`
	}
	if readJSON(r, &req) != nil {
		jsonErr(w, 400, "请求格式错误")
		return
	}
	dh, err := a.agent.UciConfig("dhcp")
	if err != nil {
		jsonErr(w, 502, err.Error())
		return
	}
	for _, n := range []string{req.Start, req.Limit} {
		if v, err := strconv.Atoi(n); err != nil || v < 1 || v > 65000 {
			jsonErr(w, 400, "起始地址和数量要填 1–65000 的数字")
			return
		}
	}
	if req.Leasetime == "" {
		req.Leasetime = "12h"
	}
	if !leaseRe.MatchString(req.Leasetime) {
		jsonErr(w, 400, "租期格式如 12h、30m、7d 或 infinite")
		return
	}
	for _, d := range req.DNS {
		if _, err := netip.ParseAddr(strings.TrimSpace(d)); err != nil {
			jsonErr(w, 400, "下发的 DNS 不正确："+d)
			return
		}
	}
	if req.Gateway != "" {
		if _, err := netip.ParseAddr(req.Gateway); err != nil {
			jsonErr(w, 400, "下发的网关不正确")
			return
		}
	}
	sec := r.PathValue("section")
	var cur Section
	if sec != "" {
		cur = dh[sec]
		if cur == nil || cur[".type"] != "dhcp" {
			jsonErr(w, 404, "没有这个地址池")
			return
		}
	}
	// keep dhcp options the form does not edit
	var opts []string
	for _, o := range strList(cur["dhcp_option"]) {
		code, _, _ := strings.Cut(o, ",")
		if code != "6" && code != "3" && code != "option:dns-server" && code != "option:router" {
			opts = append(opts, o)
		}
	}
	var dns []string
	for _, d := range req.DNS {
		if d = strings.TrimSpace(d); d != "" {
			dns = append(dns, d)
		}
	}
	if len(dns) > 0 {
		opts = append(opts, "6,"+strings.Join(dns, ","))
	}
	if req.Gateway != "" {
		opts = append(opts, "3,"+req.Gateway)
	}
	vals := map[string]any{"start": req.Start, "limit": req.Limit, "leasetime": req.Leasetime, "ignore": b01(req.Ignore), "force": b01(req.Force)}
	var ch []UciChange
	if sec == "" {
		if req.Interface == "" {
			jsonErr(w, 400, "选择接口")
			return
		}
		for _, s := range dh {
			if s[".type"] == "dhcp" && sectionStr(s, "interface") == req.Interface {
				jsonErr(w, 409, "这个接口已经有地址池")
				return
			}
		}
		vals["interface"] = req.Interface
		if len(opts) > 0 {
			vals["dhcp_option"] = opts
		}
		ch = append(ch, UciChange{Op: "add", Config: "dhcp", Type: "dhcp", Name: req.Interface, Values: vals})
	} else {
		if len(opts) > 0 {
			vals["dhcp_option"] = opts
		}
		ch = append(ch, UciChange{Op: "set", Config: "dhcp", Section: sec, Values: vals})
		if len(opts) == 0 && cur["dhcp_option"] != nil {
			ch = append(ch, UciChange{Op: "delete", Config: "dhcp", Section: sec, Options: []string{"dhcp_option"}})
		}
	}
	a.applyAudited(w, r, "net.dhcp.pool", "DHCP 地址池 "+nz(req.Interface, sec), ch)
}

func b01(b bool) string {
	if b {
		return "1"
	}
	return "0"
}

func nz(s, def string) string {
	if s == "" {
		return def
	}
	return s
}

// applyAudited applies changes right away (no confirm step) and audits them.
func (a *App) applyAudited(w http.ResponseWriter, r *http.Request, action, summary string, ch []UciChange) {
	res, err := a.agent.Apply(ch...)
	if err != nil {
		jsonErr(w, 409, agentMsg(err))
		return
	}
	ac := actor{user: currentUser(r), ip: a.clientIP(r)}
	for _, x := range res {
		a.audit(ac, action, "uci", x.Config+"."+x.Section, summary, x.Before, x.After, true)
	}
	writeJSON(w, 200, map[string]any{"ok": true})
}

// PUT /api/net/dns
func (a *App) handleNetDNS(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Server           []string `json:"server"`
		Noresolv         bool     `json:"noresolv"`
		Cachesize        string   `json:"cachesize"`
		Domain           string   `json:"domain"`
		RebindProtection bool     `json:"rebind_protection"`
		RebindDomain     []string `json:"rebind_domain"`
		FilterAAAA       bool     `json:"filter_aaaa"`
		Localservice     bool     `json:"localservice"`
	}
	if readJSON(r, &req) != nil {
		jsonErr(w, 400, "请求格式错误")
		return
	}
	dh, err := a.agent.UciConfig("dhcp")
	if err != nil {
		jsonErr(w, 502, err.Error())
		return
	}
	sec := ""
	for n, s := range dh {
		if s[".type"] == "dnsmasq" {
			sec = n
			break
		}
	}
	if sec == "" {
		jsonErr(w, 404, "没有 dnsmasq 配置")
		return
	}
	srvRe := regexp.MustCompile(`^(/[^/\s]*/)?[0-9a-fA-F.:]+(#\d{1,5})?$|^/[^/\s]+/#?$`)
	var servers []string
	for _, s := range req.Server {
		if s = strings.TrimSpace(s); s == "" {
			continue
		}
		if !srvRe.MatchString(s) {
			jsonErr(w, 400, "上游 DNS 格式不正确："+s+"（如 223.5.5.5、127.0.0.1#5342、/lan.example/192.168.1.2）")
			return
		}
		servers = append(servers, s)
	}
	if req.Noresolv && len(servers) == 0 {
		jsonErr(w, 400, "不使用运营商 DNS 时，至少要填一个上游 DNS")
		return
	}
	if req.Cachesize != "" {
		if n, err := strconv.Atoi(req.Cachesize); err != nil || n < 0 || n > 100000 {
			jsonErr(w, 400, "缓存条数 0–100000")
			return
		}
	}
	domRe := regexp.MustCompile(`^[a-zA-Z0-9.-]{0,63}$`)
	if !domRe.MatchString(req.Domain) {
		jsonErr(w, 400, "本地域名不正确")
		return
	}
	var rebind []string
	for _, d := range req.RebindDomain {
		if d = strings.TrimSpace(d); d != "" {
			if !regexp.MustCompile(`^[a-zA-Z0-9.*-]{1,100}$`).MatchString(d) {
				jsonErr(w, 400, "允许重绑定的域名不正确："+d)
				return
			}
			rebind = append(rebind, d)
		}
	}
	vals := map[string]any{"noresolv": b01(req.Noresolv), "rebind_protection": b01(req.RebindProtection), "filter_aaaa": b01(req.FilterAAAA), "localservice": b01(req.Localservice)}
	var del []string
	cur := dh[sec]
	setOrDel := func(k string, v any, empty bool) {
		if empty {
			if cur[k] != nil {
				del = append(del, k)
			}
			return
		}
		vals[k] = v
	}
	setOrDel("server", servers, len(servers) == 0)
	setOrDel("cachesize", req.Cachesize, req.Cachesize == "")
	setOrDel("rebind_domain", rebind, len(rebind) == 0)
	if req.Domain != "" {
		vals["domain"] = req.Domain
		vals["local"] = "/" + req.Domain + "/"
	}
	ch := []UciChange{{Op: "set", Config: "dhcp", Section: sec, Values: vals}}
	if len(del) > 0 {
		ch = append(ch, UciChange{Op: "delete", Config: "dhcp", Section: sec, Options: del})
	}
	a.applyAudited(w, r, "net.dns", "DNS 设置", ch)
}

// PUT /api/net/dhcp/host {section?, name, mac[], ip, leasetime} · DELETE /api/net/dhcp/host/{section}
func (a *App) handleNetDHCPHost(w http.ResponseWriter, r *http.Request) {
	dh, err := a.agent.UciConfig("dhcp")
	if err != nil {
		jsonErr(w, 502, err.Error())
		return
	}
	if r.Method == http.MethodDelete {
		sec := r.PathValue("section")
		if s := dh[sec]; s == nil || s[".type"] != "host" {
			jsonErr(w, 404, "没有这条静态分配")
			return
		}
		a.applyAudited(w, r, "net.dhcp.host.delete", "删除静态分配 "+sectionStr(dh[sec], "ip"), []UciChange{{Op: "delete", Config: "dhcp", Section: sec}})
		return
	}
	var req struct {
		Section   string   `json:"section"`
		Name      string   `json:"name"`
		MAC       []string `json:"mac"`
		IP        string   `json:"ip"`
		Leasetime string   `json:"leasetime"`
	}
	if readJSON(r, &req) != nil {
		jsonErr(w, 400, "请求格式错误")
		return
	}
	var macs []string
	for _, m := range req.MAC {
		m = strings.ToUpper(strings.TrimSpace(m))
		if m == "" {
			continue
		}
		if !strictMACRe.MatchString(m) {
			jsonErr(w, 400, "MAC 地址不正确："+m)
			return
		}
		macs = append(macs, m)
	}
	if len(macs) == 0 {
		jsonErr(w, 400, "填写设备的 MAC 地址")
		return
	}
	ip, err := netip.ParseAddr(strings.TrimSpace(req.IP))
	if err != nil || !ip.Is4() {
		jsonErr(w, 400, "IP 地址不正确")
		return
	}
	if req.Leasetime != "" && !leaseRe.MatchString(req.Leasetime) {
		jsonErr(w, 400, "租期格式如 12h、7d 或 infinite")
		return
	}
	name := strings.TrimSpace(req.Name)
	if !regexp.MustCompile(`^[A-Za-z0-9._-]{0,63}$`).MatchString(name) {
		jsonErr(w, 400, "主机名只能用字母、数字、点、横线和下划线")
		return
	}
	for sec, s := range dh {
		if s[".type"] != "host" || sec == req.Section {
			continue
		}
		if sectionStr(s, "ip") == ip.String() {
			jsonErr(w, 409, ip.String()+" 已经分配给 "+nz(sectionStr(s, "name"), strings.Join(strList(s["mac"]), " ")))
			return
		}
		for _, m := range strList(s["mac"]) {
			if slices.Contains(macs, strings.ToUpper(m)) {
				jsonErr(w, 409, m+" 已经有一条静态分配（"+sectionStr(s, "ip")+"）")
				return
			}
		}
	}
	vals := map[string]any{"mac": macs, "ip": ip.String()}
	if name != "" {
		vals["name"] = name
		vals["dns"] = "1"
	}
	if req.Leasetime != "" {
		vals["leasetime"] = req.Leasetime
	}
	var ch []UciChange
	if req.Section == "" {
		ch = []UciChange{{Op: "add", Config: "dhcp", Type: "host", Values: vals}}
	} else {
		cur := dh[req.Section]
		if cur == nil || cur[".type"] != "host" {
			jsonErr(w, 404, "没有这条静态分配")
			return
		}
		ch = []UciChange{{Op: "set", Config: "dhcp", Section: req.Section, Values: vals}}
		var del []string
		if name == "" && cur["name"] != nil {
			del = append(del, "name", "dns")
		}
		if req.Leasetime == "" && cur["leasetime"] != nil {
			del = append(del, "leasetime")
		}
		if len(del) > 0 {
			ch = append(ch, UciChange{Op: "delete", Config: "dhcp", Section: req.Section, Options: del})
		}
	}
	a.applyAudited(w, r, "net.dhcp.host", "静态分配 "+ip.String()+" → "+strings.Join(macs, " "), ch)
}

// ---- firewall ----

var policies = []string{"ACCEPT", "REJECT", "DROP"}

func wharfRule(sec string, s Section) bool {
	name := sectionStr(s, "name")
	return strings.HasPrefix(sec, "owp") || strings.HasPrefix(name, "OWP|") || strings.HasPrefix(name, "Wharf") || strings.HasPrefix(name, "owp")
}

// GET /api/net/firewall
func (a *App) handleNetFirewall(w http.ResponseWriter, r *http.Request) {
	fw, err := a.agent.UciConfig("firewall")
	if err != nil {
		jsonErr(w, 502, err.Error())
		return
	}
	net, _ := a.agent.UciConfig("network")
	var zones, fwds, rules, includes []map[string]any
	var defaults map[string]any
	redirects := map[string]int{"wharf": 0, "other": 0}
	for sec, s := range fw {
		idx, _ := s[".index"].(float64)
		switch s[".type"] {
		case "defaults":
			defaults = map[string]any{"section": sec, "input": sectionStr(s, "input"), "output": sectionStr(s, "output"), "forward": sectionStr(s, "forward"),
				"syn_flood": sectionStr(s, "syn_flood") == "1" || sectionStr(s, "synflood_protect") == "1", "drop_invalid": sectionStr(s, "drop_invalid") == "1",
				"flow_offloading": sectionStr(s, "flow_offloading") == "1", "flow_offloading_hw": sectionStr(s, "flow_offloading_hw") == "1", "fullcone": sectionStr(s, "fullcone") == "1"}
		case "zone":
			zones = append(zones, map[string]any{"section": sec, "name": sectionStr(s, "name"), "network": strList(s["network"]), "input": sectionStr(s, "input"),
				"output": sectionStr(s, "output"), "forward": sectionStr(s, "forward"), "masq": sectionStr(s, "masq") == "1", "mtu_fix": sectionStr(s, "mtu_fix") == "1",
				"index": idx, "device": strList(s["device"]), "subnet": strList(s["subnet"])})
		case "forwarding":
			fwds = append(fwds, map[string]any{"section": sec, "src": sectionStr(s, "src"), "dest": sectionStr(s, "dest"), "enabled": sectionStr(s, "enabled") != "0", "index": idx})
		case "rule":
			rules = append(rules, map[string]any{"section": sec, "name": sectionStr(s, "name"), "src": sectionStr(s, "src"), "dest": sectionStr(s, "dest"),
				"proto": strList(s["proto"]), "src_ip": strList(s["src_ip"]), "dest_ip": strList(s["dest_ip"]), "src_port": sectionStr(s, "src_port"),
				"dest_port": sectionStr(s, "dest_port"), "target": sectionStr(s, "target"), "family": sectionStr(s, "family"), "enabled": sectionStr(s, "enabled") != "0",
				"icmp_type": strList(s["icmp_type"]), "src_mac": strList(s["src_mac"]), "ipset": sectionStr(s, "ipset"), "extra": sectionStr(s, "extra"),
				"managed": wharfRule(sec, s), "index": idx})
		case "redirect":
			if wharfRule(sec, s) {
				redirects["wharf"]++
			} else {
				redirects["other"]++
			}
		case "include":
			includes = append(includes, map[string]any{"section": sec, "path": sectionStr(s, "path"), "type": sectionStr(s, "type"), "enabled": sectionStr(s, "enabled") != "0", "managed": strings.HasPrefix(sec, "owp")})
		}
	}
	byIndex := func(l []map[string]any) {
		sort.SliceStable(l, func(i, j int) bool { return l[i]["index"].(float64) < l[j]["index"].(float64) })
	}
	byIndex(zones)
	byIndex(fwds)
	byIndex(rules)
	var ifaces []string
	for n, s := range net {
		if s[".type"] == "interface" && n != "loopback" {
			ifaces = append(ifaces, n)
		}
	}
	sort.Strings(ifaces)
	var sys struct {
		Firewall string `json:"firewall"`
	}
	_ = a.agent.Do("GET", "/v1/ping", nil, &sys)
	writeJSON(w, 200, map[string]any{"defaults": defaults, "zones": zones, "forwardings": fwds, "rules": rules, "includes": includes,
		"redirects": redirects, "interfaces": ifaces, "orphans": orphanNetworks(fw, net), "flavor": sys.Firewall})
}

func validPolicy(s string) bool { return slices.Contains(policies, s) }

// PUT /api/net/firewall/defaults
func (a *App) handleFwDefaults(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Input, Output, Forward string
		SynFlood               bool `json:"syn_flood"`
		DropInvalid            bool `json:"drop_invalid"`
		FlowOffloading         bool `json:"flow_offloading"`
		FlowOffloadingHW       bool `json:"flow_offloading_hw"`
	}
	if readJSON(r, &req) != nil || !validPolicy(req.Input) || !validPolicy(req.Output) || !validPolicy(req.Forward) {
		jsonErr(w, 400, "请求格式错误")
		return
	}
	fw, err := a.agent.UciConfig("firewall")
	if err != nil {
		jsonErr(w, 502, err.Error())
		return
	}
	sec := ""
	for n, s := range fw {
		if s[".type"] == "defaults" {
			sec = n
		}
	}
	if sec == "" {
		jsonErr(w, 404, "没有默认设置")
		return
	}
	vals := map[string]any{"input": req.Input, "output": req.Output, "forward": req.Forward, "syn_flood": b01(req.SynFlood), "drop_invalid": b01(req.DropInvalid),
		"flow_offloading": b01(req.FlowOffloading), "flow_offloading_hw": b01(req.FlowOffloadingHW && req.FlowOffloading)}
	a.fwGuarded(w, r, "fw.defaults", "防火墙默认策略", []UciChange{{Op: "set", Config: "firewall", Section: sec, Values: vals}})
}

func (a *App) fwGuarded(w http.ResponseWriter, r *http.Request, action, summary string, ch []UciChange) {
	p, err := a.guardedApply(r, action, summary, 90, ch)
	if err != nil {
		jsonErr(w, 409, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true, "pending": p})
}

var zoneNameRe = regexp.MustCompile(`^[a-zA-Z][a-zA-Z0-9_]{0,10}$`)

// PUT /api/net/firewall/zone/{section} · POST /api/net/firewall/zone · DELETE …/{section}
func (a *App) handleFwZone(w http.ResponseWriter, r *http.Request) {
	fw, err := a.agent.UciConfig("firewall")
	if err != nil {
		jsonErr(w, 502, err.Error())
		return
	}
	sec := r.PathValue("section")
	if r.Method == http.MethodDelete {
		z := fw[sec]
		if z == nil || z[".type"] != "zone" {
			jsonErr(w, 404, "没有这个区域")
			return
		}
		name := sectionStr(z, "name")
		if name == "lan" || name == "wan" {
			jsonErr(w, 400, "lan / wan 区域不能删除")
			return
		}
		ch := []UciChange{{Op: "delete", Config: "firewall", Section: sec}}
		for n, s := range fw {
			if s[".type"] == "forwarding" && (sectionStr(s, "src") == name || sectionStr(s, "dest") == name) {
				ch = append(ch, UciChange{Op: "delete", Config: "firewall", Section: n})
			}
		}
		a.fwGuarded(w, r, "fw.zone.delete", "删除防火墙区域 "+name, ch)
		return
	}
	var req struct {
		Name                   string   `json:"name"`
		Network                []string `json:"network"`
		Input, Output, Forward string
		Masq                   bool `json:"masq"`
		MTUFix                 bool `json:"mtu_fix"`
	}
	if readJSON(r, &req) != nil || !validPolicy(req.Input) || !validPolicy(req.Output) || !validPolicy(req.Forward) {
		jsonErr(w, 400, "请求格式错误")
		return
	}
	if !zoneNameRe.MatchString(req.Name) {
		jsonErr(w, 400, "区域名用字母开头，最多 11 个字母 / 数字 / 下划线")
		return
	}
	for n, s := range fw {
		if s[".type"] == "zone" && sectionStr(s, "name") == req.Name && n != sec {
			jsonErr(w, 409, "已经有同名区域")
			return
		}
	}
	vals := map[string]any{"name": req.Name, "input": req.Input, "output": req.Output, "forward": req.Forward, "masq": b01(req.Masq), "mtu_fix": b01(req.MTUFix)}
	var ch []UciChange
	if sec == "" {
		if len(req.Network) > 0 {
			vals["network"] = req.Network
		}
		ch = append(ch, UciChange{Op: "add", Config: "firewall", Type: "zone", Values: vals})
	} else {
		z := fw[sec]
		if z == nil || z[".type"] != "zone" {
			jsonErr(w, 404, "没有这个区域")
			return
		}
		if old := sectionStr(z, "name"); old != req.Name && (old == "lan" || old == "wan") {
			jsonErr(w, 400, "lan / wan 区域不能改名")
			return
		}
		ch = append(ch, UciChange{Op: "set", Config: "firewall", Section: sec, Values: vals})
		if len(req.Network) > 0 {
			ch[0].Values["network"] = req.Network
		} else if z["network"] != nil {
			ch = append(ch, UciChange{Op: "delete", Config: "firewall", Section: sec, Options: []string{"network"}})
		}
		// an interface lives in one zone: take it out of the others
		for n, s := range fw {
			if s[".type"] != "zone" || n == sec {
				continue
			}
			nets := strList(s["network"])
			keep := slices.DeleteFunc(slices.Clone(nets), func(x string) bool { return slices.Contains(req.Network, x) })
			if len(keep) != len(nets) {
				if len(keep) == 0 {
					ch = append(ch, UciChange{Op: "delete", Config: "firewall", Section: n, Options: []string{"network"}})
				} else {
					ch = append(ch, UciChange{Op: "set", Config: "firewall", Section: n, Values: map[string]any{"network": keep}})
				}
			}
		}
	}
	a.fwGuarded(w, r, "fw.zone.save", "防火墙区域 "+req.Name, ch)
}

// POST /api/net/firewall/forwarding {src, dest} · DELETE …/{section}
func (a *App) handleFwForwarding(w http.ResponseWriter, r *http.Request) {
	fw, err := a.agent.UciConfig("firewall")
	if err != nil {
		jsonErr(w, 502, err.Error())
		return
	}
	if r.Method == http.MethodDelete {
		sec := r.PathValue("section")
		s := fw[sec]
		if s == nil || s[".type"] != "forwarding" {
			jsonErr(w, 404, "没有这条转发")
			return
		}
		a.fwGuarded(w, r, "fw.forwarding.delete", "取消区域转发 "+sectionStr(s, "src")+" → "+sectionStr(s, "dest"), []UciChange{{Op: "delete", Config: "firewall", Section: sec}})
		return
	}
	var req struct{ Src, Dest string }
	if readJSON(r, &req) != nil || req.Src == "" || req.Dest == "" || req.Src == req.Dest {
		jsonErr(w, 400, "选择来源和目标区域")
		return
	}
	names := map[string]bool{}
	for n, s := range fw {
		if s[".type"] == "zone" {
			names[sectionStr(s, "name")] = true
		}
		if s[".type"] == "forwarding" && sectionStr(s, "src") == req.Src && sectionStr(s, "dest") == req.Dest {
			_ = n
			jsonErr(w, 409, "已经允许了")
			return
		}
	}
	if !names[req.Src] || !names[req.Dest] {
		jsonErr(w, 400, "区域不存在")
		return
	}
	a.fwGuarded(w, r, "fw.forwarding.add", "允许区域转发 "+req.Src+" → "+req.Dest,
		[]UciChange{{Op: "add", Config: "firewall", Type: "forwarding", Values: map[string]any{"src": req.Src, "dest": req.Dest}}})
}

var (
	portSpecRe = regexp.MustCompile(`^(\d{1,5}([-:]\d{1,5})?)( \d{1,5}([-:]\d{1,5})?)*$`)
	ruleNameRe = regexp.MustCompile(`^[^\x00-\x1f'"\\]{1,64}$`)
	protoSet   = []string{"tcp", "udp", "icmp", "all", "tcpudp", "esp", "gre", "igmp", "ah", "sctp", "icmpv6"}
)

type fwRuleReq struct {
	Name     string   `json:"name"`
	Src      string   `json:"src"`
	Dest     string   `json:"dest"`
	Proto    []string `json:"proto"`
	SrcIP    []string `json:"src_ip"`
	DestIP   []string `json:"dest_ip"`
	SrcPort  string   `json:"src_port"`
	DestPort string   `json:"dest_port"`
	Target   string   `json:"target"`
	Family   string   `json:"family"`
	Enabled  *bool    `json:"enabled"`
	ICMPType []string `json:"icmp_type"`
}

func (q *fwRuleReq) values(zones map[string]bool) (map[string]any, []string, error) {
	if !ruleNameRe.MatchString(q.Name) {
		return nil, nil, errors.New("给规则起个名字")
	}
	if strings.HasPrefix(q.Name, "OWP|") || strings.HasPrefix(q.Name, "Wharf") {
		return nil, nil, errors.New("这个名字前缀留给 Wharf 自己的规则")
	}
	if q.Src != "" && q.Src != "*" && !zones[q.Src] {
		return nil, nil, errors.New("来源区域不存在")
	}
	if q.Dest != "" && q.Dest != "*" && !zones[q.Dest] {
		return nil, nil, errors.New("目标区域不存在")
	}
	if !slices.Contains([]string{"ACCEPT", "REJECT", "DROP", "MARK", "NOTRACK"}, q.Target) {
		return nil, nil, errors.New("动作不正确")
	}
	if q.Family != "" && q.Family != "ipv4" && q.Family != "ipv6" && q.Family != "any" {
		return nil, nil, errors.New("IP 版本不正确")
	}
	for _, p := range q.Proto {
		if !slices.Contains(protoSet, p) {
			return nil, nil, errors.New("协议不正确：" + p)
		}
	}
	for _, p := range []string{q.SrcPort, q.DestPort} {
		if p != "" && !portSpecRe.MatchString(p) {
			return nil, nil, errors.New("端口格式如 80、8000-8080 或 80 443")
		}
	}
	for _, l := range [][]string{q.SrcIP, q.DestIP} {
		for _, x := range l {
			x = strings.TrimPrefix(x, "!")
			if _, err := netip.ParsePrefix(x); err != nil {
				if _, err := netip.ParseAddr(x); err != nil {
					return nil, nil, errors.New("IP 或网段不正确：" + x)
				}
			}
		}
	}
	vals := map[string]any{"name": q.Name, "target": q.Target}
	var del []string
	put := func(k string, v any, empty bool) {
		if empty {
			del = append(del, k)
		} else {
			vals[k] = v
		}
	}
	put("src", q.Src, q.Src == "")
	put("dest", q.Dest, q.Dest == "")
	put("proto", q.Proto, len(q.Proto) == 0)
	put("src_ip", q.SrcIP, len(q.SrcIP) == 0)
	put("dest_ip", q.DestIP, len(q.DestIP) == 0)
	put("src_port", q.SrcPort, q.SrcPort == "")
	put("dest_port", q.DestPort, q.DestPort == "")
	put("family", q.Family, q.Family == "" || q.Family == "any")
	put("icmp_type", q.ICMPType, len(q.ICMPType) == 0)
	if q.Enabled != nil {
		put("enabled", "0", *q.Enabled)
	}
	return vals, del, nil
}

// POST /api/net/firewall/rule · PUT …/{section} · DELETE …/{section} · POST …/{section}/toggle {enabled}
func (a *App) handleFwRule(w http.ResponseWriter, r *http.Request) {
	fw, err := a.agent.UciConfig("firewall")
	if err != nil {
		jsonErr(w, 502, err.Error())
		return
	}
	sec := r.PathValue("section")
	cur := fw[sec]
	if sec != "" {
		if cur == nil || cur[".type"] != "rule" {
			jsonErr(w, 404, "没有这条规则")
			return
		}
		if wharfRule(sec, cur) {
			jsonErr(w, 400, "这条规则由 Wharf 自己管理（端口转发、封禁、面板访问等），请在对应页面修改")
			return
		}
	}
	if r.Method == http.MethodDelete {
		a.fwGuarded(w, r, "fw.rule.delete", "删除防火墙规则 "+sectionStr(cur, "name"), []UciChange{{Op: "delete", Config: "firewall", Section: sec}})
		return
	}
	if strings.HasSuffix(r.URL.Path, "/toggle") {
		var t struct {
			Enabled bool `json:"enabled"`
		}
		_ = readJSON(r, &t)
		ch := []UciChange{{Op: "delete", Config: "firewall", Section: sec, Options: []string{"enabled"}}}
		what := "启用"
		if !t.Enabled {
			ch = []UciChange{{Op: "set", Config: "firewall", Section: sec, Values: map[string]any{"enabled": "0"}}}
			what = "停用"
		} else if cur["enabled"] == nil {
			writeJSON(w, 200, map[string]any{"ok": true})
			return
		}
		a.fwGuarded(w, r, "fw.rule.toggle", what+"防火墙规则 "+sectionStr(cur, "name"), ch)
		return
	}
	var req fwRuleReq
	if readJSON(r, &req) != nil {
		jsonErr(w, 400, "请求格式错误")
		return
	}
	zones := map[string]bool{}
	for _, s := range fw {
		if s[".type"] == "zone" {
			zones[sectionStr(s, "name")] = true
		}
	}
	vals, del, err := req.values(zones)
	if err != nil {
		jsonErr(w, 400, err.Error())
		return
	}
	var ch []UciChange
	if sec == "" {
		ch = []UciChange{{Op: "add", Config: "firewall", Type: "rule", Values: vals}}
	} else {
		ch = []UciChange{{Op: "set", Config: "firewall", Section: sec, Values: vals}}
		var d []string
		for _, k := range del {
			if cur[k] != nil {
				d = append(d, k)
			}
		}
		if len(d) > 0 {
			ch = append(ch, UciChange{Op: "delete", Config: "firewall", Section: sec, Options: d})
		}
	}
	a.fwGuarded(w, r, "fw.rule.save", "防火墙规则 "+req.Name, ch)
}

// POST /api/net/firewall/tidy — drop zone entries for interfaces that no longer exist
func (a *App) handleFwTidy(w http.ResponseWriter, r *http.Request) {
	fw, err := a.agent.UciConfig("firewall")
	if err != nil {
		jsonErr(w, 502, err.Error())
		return
	}
	net, _ := a.agent.UciConfig("network")
	var ch []UciChange
	for sec, s := range fw {
		if s[".type"] != "zone" {
			continue
		}
		nets := strList(s["network"])
		keep := slices.DeleteFunc(slices.Clone(nets), func(n string) bool { x := net[n]; return x == nil || x[".type"] != "interface" })
		if len(keep) != len(nets) {
			if len(keep) == 0 {
				ch = append(ch, UciChange{Op: "delete", Config: "firewall", Section: sec, Options: []string{"network"}})
			} else {
				ch = append(ch, UciChange{Op: "set", Config: "firewall", Section: sec, Values: map[string]any{"network": keep}})
			}
		}
	}
	if len(ch) == 0 {
		writeJSON(w, 200, map[string]any{"ok": true})
		return
	}
	a.fwGuarded(w, r, "fw.tidy", "清理防火墙区域里不存在的接口", ch)
}

var _ = json.Marshal
