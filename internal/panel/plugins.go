package panel

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strconv"
	"strings"
)

// Plugin compatibility layer: installed LuCI apps redrawn in Wharf's design,
// their services and ports, and an app store on the router's own opkg feeds.

type pluginInfo struct {
	Pkg         string `json:"pkg"`
	Version     string `json:"version"`
	Desc        string `json:"desc"`
	InstalledAt int64  `json:"installed_at"`
	Size        int64  `json:"size"`
	Title       string `json:"title"`
	Category    string `json:"category"`
	Pages       []struct {
		Path   string `json:"path"`
		Title  string `json:"title"`
		Order  int    `json:"order"`
		Kind   string `json:"kind"`
		Target string `json:"target"`
	} `json:"pages"`
	Services []struct {
		Name    string `json:"name"`
		Enabled bool   `json:"enabled"`
		Running bool   `json:"running"`
	} `json:"services"`
	Configs []string `json:"configs"`
	Procs   []struct {
		PID  int    `json:"pid"`
		Name string `json:"name"`
		Exe  string `json:"exe"`
	} `json:"procs"`
	Ports []struct {
		Port  int    `json:"port"`
		Proto string `json:"proto"`
		Bind  string `json:"bind"`
		Proc  string `json:"proc"`
	} `json:"ports"`
	I18n    bool     `json:"i18n"`
	ByWharf bool     `json:"by_wharf"`
	Depends []string `json:"depends"`
}

// appMeta: friendly Chinese names and one-line explanations for common apps.
type appMeta struct {
	Name, Desc, Group string
	Covered           string // Wharf page that already does this job
}

var knownApps = map[string]appMeta{
	"openclash":     {"OpenClash", "Clash 内核的代理 / 分流，支持订阅、规则和策略组", "proxy", ""},
	"passwall":      {"PassWall", "多协议代理 / 分流（Xray、sing-box 等）", "proxy", ""},
	"passwall2":     {"PassWall 2", "PassWall 的新版分支，分流规则更灵活", "proxy", ""},
	"ssr-plus":      {"ShadowSocksR Plus+", "SS / SSR / V2Ray 代理", "proxy", ""},
	"homeproxy":     {"HomeProxy", "基于 sing-box 的代理", "proxy", ""},
	"nikki":         {"Nikki", "mihomo（Clash Meta）内核的代理", "proxy", ""},
	"mihomo":        {"Mihomo", "mihomo（Clash Meta）内核的代理", "proxy", ""},
	"bypass":        {"Bypass", "代理 / 分流", "proxy", ""},
	"vssr":          {"Hello World (vssr)", "代理 / 分流", "proxy", ""},
	"nextdns":       {"NextDNS", "加密 DNS，按设备过滤和统计", "dns", ""},
	"smartdns":      {"SmartDNS", "多上游测速、返回最快的 DNS 结果", "dns", ""},
	"adguardhome":   {"AdGuard Home", "去广告 DNS，自带网页后台", "dns", ""},
	"mosdns":        {"MosDNS", "可编排的 DNS 转发 / 分流", "dns", ""},
	"dnsproxy":      {"DNS Proxy", "DoH / DoT DNS 转发", "dns", ""},
	"mwan3":         {"多线负载均衡 mwan3", "多条宽带同时用：负载均衡、故障切换、按规则分流", "net", ""},
	"mwan3helper":   {"MWAN3 分流助手", "给 mwan3 提供国内 / 国外 IP 列表", "net", ""},
	"syncdial":      {"多线多拨", "同一条宽带拨多个 PPPoE，叠加带宽", "net", ""},
	"oaf":           {"应用过滤 OAF", "按应用（游戏、视频、社交）限制设备上网", "net", ""},
	"appfilter":     {"应用过滤 OAF", "按应用（游戏、视频、社交）限制设备上网", "net", ""},
	"upnp":          {"UPnP", "让游戏机、下载软件自动映射端口", "net", "/tools"},
	"ddns":          {"动态域名 DDNS（OpenWrt）", "Wharf 已自带 DDNS", "net", "/ddns"},
	"firewall":      {"防火墙（OpenWrt）", "Wharf 已自带防火墙页面", "net", "/firewall"},
	"opkg":          {"软件包（OpenWrt）", "Wharf 的插件商店已能安装 / 卸载插件", "system", "/plugins?tab=store"},
	"wol":           {"网络唤醒", "Wharf 的网络工具已自带", "net", "/tools"},
	"nlbwmon":       {"带宽监控 nlbwmon", "Wharf 的流量统计更详细", "net", "/traffic"},
	"ttyd":          {"网页终端 ttyd", "浏览器里打开路由器的命令行", "system", ""},
	"samba4":        {"网络共享 Samba", "把路由器上的硬盘共享给电脑 / 电视", "nas", ""},
	"dockerman":     {"Docker 管理", "在路由器上跑容器", "nas", ""},
	"diskman":       {"磁盘管理", "分区、格式化、挂载硬盘", "nas", ""},
	"hd-idle":       {"硬盘休眠", "硬盘空闲时自动休眠", "nas", ""},
	"vlmcsd":        {"KMS 激活服务器", "局域网内激活 Windows / Office", "service", ""},
	"pushbot":       {"全能推送", "设备上下线、IP 变化推送到微信 / Telegram", "service", "/alerts"},
	"ddnsto":        {"DDNSTO 远程访问", "免公网 IP 的远程穿透", "service", ""},
	"homebox":       {"Homebox 内网测速", "浏览器里测内网速度", "service", "/tools"},
	"zerotier":      {"ZeroTier", "虚拟局域网，异地组网", "vpn", ""},
	"tailscale":     {"Tailscale", "基于 WireGuard 的异地组网", "vpn", ""},
	"wireguard":     {"WireGuard", "高性能 VPN", "vpn", ""},
	"frpc":          {"frp 客户端", "内网穿透", "vpn", ""},
	"frps":          {"frp 服务端", "内网穿透服务端", "vpn", ""},
	"nps":           {"NPS 客户端", "内网穿透", "vpn", ""},
	"aria2":         {"Aria2 下载", "多线程 / BT 下载", "nas", ""},
	"transmission":  {"Transmission", "BT 下载", "nas", ""},
	"qbittorrent":   {"qBittorrent", "BT 下载", "nas", ""},
	"alist":         {"AList", "多网盘挂载与文件列表", "nas", ""},
	"unishare":      {"统一文件共享", "Samba / WebDAV 一处设置", "nas", ""},
	"cifs-mount":    {"挂载网络共享", "把 NAS 的共享目录挂到路由器上", "nas", ""},
	"nfs":           {"NFS 共享", "NFS 文件共享", "nas", ""},
	"argon-config":  {"Argon 主题设置", "LuCI 主题外观（与 Wharf 无关）", "system", ""},
	"quickstart":    {"iStoreOS 首页向导", "iStoreOS 自带的首页", "system", ""},
	"store":         {"iStore 应用商店", "iStoreOS 自带的应用商店", "system", ""},
	"cpufreq":       {"CPU 性能调节", "调整 CPU 频率与系统调优", "system", ""},
	"fan":           {"风扇控制", "按温度控制风扇", "system", ""},
	"filetransfer":  {"文件传输", "上传 / 下载路由器上的文件", "system", ""},
	"ota":           {"系统 OTA 升级", "iStoreOS 固件在线升级", "system", ""},
	"linkease":      {"易有云", "远程访问路由器上的文件", "nas", ""},
	"netdata":       {"Netdata", "实时性能监控", "system", ""},
	"statistics":    {"统计图表 collectd", "系统资源历史曲线", "system", "/system"},
	"banip":         {"banIP", "按 IP 列表 / 国家封禁", "net", "/access"},
	"adblock":       {"Adblock", "DNS 去广告", "dns", ""},
	"sqm":           {"SQM 智能队列", "降低打游戏 / 视频时的延迟（bufferbloat）", "net", ""},
	"eqos":          {"设备限速 eqos", "按 IP 限制上下行速度", "net", ""},
	"nft-qos":       {"QoS 限速", "按 IP 限速", "net", ""},
	"accesscontrol": {"上网时间控制", "按时间段禁止设备上网", "net", "/controls"},
	"watchcat":      {"断网自动重启", "网络不通时自动重启接口或路由器", "net", ""},
	"netwatchdog":   {"网络看门狗", "断网时自动处理", "net", ""},
	"openvpn":       {"OpenVPN", "VPN", "vpn", ""},
	"ipsec-vpnd":    {"IPSec VPN 服务器", "手机直连回家", "vpn", ""},
	"softethervpn":  {"SoftEther VPN", "多协议 VPN", "vpn", ""},
	"udpxy":         {"udpxy", "IPTV 组播转 HTTP", "service", ""},
	"msd_lite":      {"msd_lite", "IPTV 组播转 HTTP", "service", ""},
	"turboacc":      {"Turbo ACC 网络加速", "软件流量分载、全锥 NAT", "net", ""},
	"natmap":        {"NATMap", "无公网 IP 时打洞映射端口", "net", ""},
	"lucky":         {"Lucky", "端口转发、反向代理、DDNS 多合一", "service", ""},
	"uhttpd":        {"uHTTPd 网页服务器", "LuCI 使用的网页服务器", "system", ""},
	"acme":          {"ACME 证书", "Let's Encrypt 证书", "service", ""},
	"smartinfo":     {"硬盘健康 S.M.A.R.T.", "查看硬盘健康", "nas", ""},
}

var groupLabel = map[string]string{"proxy": "代理", "dns": "DNS", "net": "网络", "nas": "存储与下载", "vpn": "组网与穿透", "service": "服务", "system": "系统"}

func appKey(pkg string) string { return strings.TrimPrefix(pkg, "luci-app-") }

// conflict groups: two of these running at once fight over the same traffic
var exclusiveGroups = map[string][]string{
	"proxy": {"openclash", "passwall", "passwall2", "ssr-plus", "homeproxy", "nikki", "mihomo", "bypass", "vssr"},
	"dns":   {"nextdns", "smartdns", "adguardhome", "mosdns", "dnsproxy", "adblock"},
}

// ports Wharf itself relies on (panel, agent, proxy front, panel name listener)
func (a *App) wharfPorts() map[int]string {
	out := map[int]string{20443: "Wharf 443 分流器", 20090: "Wharf 面板（经 443）"}
	if _, p, ok := strings.Cut(a.cfg.Listen, ":"); ok {
		if n, err := strconv.Atoi(p); err == nil {
			out[n] = "Wharf 面板"
		}
	}
	if u := a.cfg.Agent.URL; u != "" {
		if i := strings.LastIndex(u, ":"); i > 0 {
			if n, err := strconv.Atoi(strings.TrimRight(u[i+1:], "/")); err == nil {
				out[n] = "Wharf 代理程序（agent）"
			}
		}
	}
	return out
}

func (a *App) plugins(fresh bool) ([]pluginInfo, error) {
	var list []pluginInfo
	path := "/v1/plugins"
	if fresh {
		path += "?fresh=1"
	}
	err := a.agent.Do("GET", path, nil, &list)
	return list, err
}

// wanOpenPorts returns "port/proto" opened to the WAN by firewall rules (input).
func wanOpenPorts(fw map[string]Section) map[string]string {
	out := map[string]string{}
	for sec, s := range fw {
		if s[".type"] != "rule" || sectionStr(s, "src") != "wan" || sectionStr(s, "dest") != "" || sectionStr(s, "target") != "ACCEPT" || sectionStr(s, "enabled") == "0" {
			continue
		}
		protos := strList(s["proto"])
		if len(protos) == 0 || slices.Contains(protos, "tcpudp") || slices.Contains(protos, "all") {
			protos = []string{"tcp", "udp"}
		}
		for _, spec := range strings.Fields(sectionStr(s, "dest_port")) {
			lo, hi := spec, spec
			if a, b, ok := strings.Cut(strings.ReplaceAll(spec, ":", "-"), "-"); ok {
				lo, hi = a, b
			}
			l, _ := strconv.Atoi(lo)
			h, _ := strconv.Atoi(hi)
			if h-l > 2000 {
				continue
			}
			for p := l; p <= h && p > 0; p++ {
				for _, pr := range protos {
					out[strconv.Itoa(p)+"/"+pr] = sec
				}
			}
		}
	}
	return out
}

// GET /api/plugins
func (a *App) handlePlugins(w http.ResponseWriter, r *http.Request) {
	list, err := a.plugins(r.URL.Query().Get("fresh") == "1")
	if err != nil {
		jsonErr(w, 502, "读不到插件："+agentMsg(err))
		return
	}
	fw, _ := a.agent.UciConfig("firewall")
	open := wanOpenPorts(fw)
	wp := a.wharfPorts()
	running := map[string]bool{}
	for _, p := range list {
		for _, s := range p.Services {
			if s.Running {
				running[appKey(p.Pkg)] = true
			}
		}
	}
	var out []map[string]any
	for _, p := range list {
		k := appKey(p.Pkg)
		m := knownApps[k]
		var warnings []string
		for g, members := range exclusiveGroups {
			if !slices.Contains(members, k) || !running[k] {
				continue
			}
			for _, o := range members {
				if o != k && running[o] {
					what := map[string]string{"proxy": "两个代理插件同时运行会争抢流量，通常只能开一个", "dns": "两个 DNS 插件同时接管解析，可能互相覆盖"}[g]
					warnings = append(warnings, fmt.Sprintf("和 %s 同时在运行：%s", nz(knownApps[o].Name, o), what))
				}
			}
		}
		var ports []map[string]any
		for _, pt := range p.Ports {
			pm := map[string]any{"port": pt.Port, "proto": pt.Proto, "bind": pt.Bind, "proc": pt.Proc}
			local := pt.Bind == "127.0.0.1" || pt.Bind == "::1"
			pm["local"] = local
			if sec, ok := open[strconv.Itoa(pt.Port)+"/"+pt.Proto]; ok && !local {
				pm["wan_open"] = true
				pm["wan_rule"] = sec
			}
			if who, ok := wp[pt.Port]; ok {
				warnings = append(warnings, fmt.Sprintf("占用了 %d 端口，和 %s 冲突", pt.Port, who))
			}
			ports = append(ports, pm)
		}
		out = append(out, map[string]any{"pkg": p.Pkg, "version": p.Version, "desc": p.Desc, "installed_at": p.InstalledAt, "size": p.Size,
			"title": nz(m.Name, p.Title), "luci_title": p.Title, "about": m.Desc, "group": m.Group, "group_label": groupLabel[m.Group],
			"covered": m.Covered, "category": p.Category, "pages": p.Pages, "services": p.Services, "configs": p.Configs, "procs": p.Procs,
			"ports": ports, "i18n": p.I18n, "by_wharf": p.ByWharf, "warnings": warnings, "depends": p.Depends})
	}
	writeJSON(w, 200, map[string]any{"plugins": out})
}

// pluginOf finds an installed plugin by package name.
func (a *App) pluginOf(pkg string) (*pluginInfo, error) {
	list, err := a.plugins(false)
	if err != nil {
		return nil, err
	}
	for i := range list {
		if list[i].Pkg == pkg {
			return &list[i], nil
		}
	}
	return nil, fmt.Errorf("没有安装 %s", pkg)
}

// POST /api/plugins/service {pkg, name, action}
func (a *App) handlePluginService(w http.ResponseWriter, r *http.Request) {
	var req struct{ Pkg, Name, Action string }
	if readJSON(r, &req) != nil {
		jsonErr(w, 400, "请求格式错误")
		return
	}
	p, err := a.pluginOf(req.Pkg)
	if err != nil {
		jsonErr(w, 404, err.Error())
		return
	}
	ok := false
	for _, s := range p.Services {
		if s.Name == req.Name {
			ok = true
		}
	}
	if !ok {
		jsonErr(w, 400, "这个服务不属于该插件")
		return
	}
	if err := a.agent.Do("POST", "/v1/plugins/service", map[string]string{"name": req.Name, "action": req.Action}, nil); err != nil {
		jsonErr(w, 400, agentMsg(err))
		return
	}
	label := map[string]string{"start": "启动", "stop": "停止", "restart": "重启", "enable": "设为开机启动", "disable": "取消开机启动"}[req.Action]
	a.audit(actor{user: currentUser(r), ip: a.clientIP(r)}, "plugin.service", "plugin", req.Pkg, label+" "+req.Name, nil, nil, false)
	writeJSON(w, 200, map[string]bool{"ok": true})
}

var secretOptRe = regexp.MustCompile(`(?i)(pass|secret|token|psk|private|key$|_key|uuid)`)

// GET /api/plugins/form?pkg=&model= — a CBI page's form tree
func (a *App) handlePluginForm(w http.ResponseWriter, r *http.Request) {
	pkg, model := r.URL.Query().Get("pkg"), r.URL.Query().Get("model")
	p, err := a.pluginOf(pkg)
	if err != nil {
		jsonErr(w, 404, err.Error())
		return
	}
	if !a.modelOfPlugin(p, model) {
		jsonErr(w, 400, "这个页面不属于该插件")
		return
	}
	var tree json.RawMessage
	if err := a.agent.Do("GET", "/v1/plugins/form?model="+model, nil, &tree); err != nil {
		jsonErr(w, 502, agentMsg(err))
		return
	}
	if !currentUser(r).Can("plugins.manage") {
		tree = maskFormSecrets(tree)
	}
	writeJSON(w, 200, map[string]any{"tree": tree})
}

// modelOfPlugin: the model is one of the plugin's pages, or a sub page under the same directory.
func (a *App) modelOfPlugin(p *pluginInfo, model string) bool {
	for _, pg := range p.Pages {
		if pg.Target == model {
			return true
		}
		if d := strings.SplitN(pg.Target, "/", 2)[0]; d != "" && strings.HasPrefix(model, d+"/") {
			return true
		}
	}
	return false
}

// maskFormSecrets blanks password fields and secret-looking options for read-only users.
func maskFormSecrets(raw json.RawMessage) json.RawMessage {
	var t map[string]any
	if json.Unmarshal(raw, &t) != nil {
		return raw
	}
	var walk func(any)
	walk = func(n any) {
		switch v := n.(type) {
		case map[string]any:
			if opt, _ := v["option"].(string); opt != "" {
				if pw, _ := v["password"].(bool); pw || secretOptRe.MatchString(opt) {
					if vals, ok := v["values"].(map[string]any); ok {
						for k, x := range vals {
							if fmt.Sprint(x) != "" {
								vals[k] = "••••••"
							}
						}
					}
				}
			}
			for _, c := range v {
				walk(c)
			}
		case []any:
			for _, c := range v {
				walk(c)
			}
		}
	}
	walk(t)
	b, _ := json.Marshal(t)
	return b
}

// GET /api/plugins/uci?pkg=&config= — a plugin's config for its JS view (secrets masked for read-only users)
func (a *App) handlePluginUci(w http.ResponseWriter, r *http.Request) {
	cfg := r.URL.Query().Get("config")
	if !regexp.MustCompile(`^[a-zA-Z0-9_-]{1,40}$`).MatchString(cfg) || cfg == "owp" || cfg == "rpcd" || cfg == "uhttpd" || cfg == "dropbear" {
		jsonErr(w, 400, "不能读取这个配置")
		return
	}
	all, err := a.agent.UciConfig(cfg)
	if err != nil {
		writeJSON(w, 200, map[string]any{})
		return
	}
	if !currentUser(r).Can("plugins.manage") {
		for _, s := range all {
			for k, v := range s {
				if !strings.HasPrefix(k, ".") && secretOptRe.MatchString(k) && fmt.Sprint(v) != "" {
					s[k] = "••••••"
				}
			}
		}
	}
	writeJSON(w, 200, all)
}

// GET /api/plugins/i18n · GET /api/plugins/file?path= · POST /api/plugins/rpc
func (a *App) handlePluginI18n(w http.ResponseWriter, r *http.Request) {
	var raw json.RawMessage
	if err := a.agent.Do("GET", "/v1/luci/i18n", nil, &raw); err != nil {
		jsonErr(w, 502, agentMsg(err))
		return
	}
	w.Header().Set("Cache-Control", "private, max-age=600")
	writeJSON(w, 200, raw)
}

func (a *App) handlePluginFile(w http.ResponseWriter, r *http.Request) {
	var out struct {
		Source string `json:"source"`
	}
	if err := a.agent.Do("GET", "/v1/luci/file?path="+urlQueryEscape(r.URL.Query().Get("path")), nil, &out); err != nil {
		jsonErr(w, 404, agentMsg(err))
		return
	}
	writeJSON(w, 200, out)
}

func (a *App) handlePluginRPC(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Object string         `json:"object"`
		Method string         `json:"method"`
		Params map[string]any `json:"params"`
	}
	if readJSON(r, &req) != nil {
		jsonErr(w, 400, "请求格式错误")
		return
	}
	var out json.RawMessage
	if err := a.agent.Do("POST", "/v1/luci/rpc", req, &out); err != nil {
		jsonErr(w, 400, agentMsg(err))
		return
	}
	writeJSON(w, 200, out)
}

// PUT /api/plugins/save {pkg, changes: [{op, config, section, type, values, options}]}
func (a *App) handlePluginSave(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Pkg     string      `json:"pkg"`
		Title   string      `json:"title"`
		Changes []UciChange `json:"changes"`
	}
	if readJSON(r, &req) != nil || len(req.Changes) == 0 {
		jsonErr(w, 400, "没有改动")
		return
	}
	p, err := a.pluginOf(req.Pkg)
	if err != nil {
		jsonErr(w, 404, err.Error())
		return
	}
	for _, c := range req.Changes {
		if !slices.Contains(p.Configs, c.Config) && !a.configUsedBy(p, c.Config) {
			jsonErr(w, 400, "配置 "+c.Config+" 不属于这个插件")
			return
		}
		for k, v := range c.Values {
			if s := fmt.Sprint(v); s == "••••••" || s == secretMarker {
				delete(c.Values, k) // masked secret: unchanged
			}
			if strings.ContainsAny(k, ".' \"") {
				jsonErr(w, 400, "选项名不正确："+k)
				return
			}
		}
		if c.Op == "set" && len(c.Values) == 0 {
			continue
		}
	}
	res, err := a.agent.Apply(req.Changes...)
	if err != nil {
		jsonErr(w, 409, agentMsg(err))
		return
	}
	ac := actor{user: currentUser(r), ip: a.clientIP(r)}
	title := nz(knownApps[appKey(p.Pkg)].Name, p.Title)
	for _, x := range res {
		a.audit(ac, "plugin.save", "uci", x.Config+"."+x.Section, "修改插件 "+title+" 设置"+strings.TrimSpace(" "+req.Title), x.Before, x.After, true)
	}
	writeJSON(w, 200, map[string]any{"ok": true, "results": len(res)})
}

// configUsedBy: a config the plugin's backend owns (e.g. luci-app-mwan3 edits "mwan3"
// which ships in the mwan3 package).
func (a *App) configUsedBy(p *pluginInfo, cfg string) bool {
	k := appKey(p.Pkg)
	return cfg == k || strings.HasPrefix(cfg, k) || slices.ContainsFunc(p.Depends, func(d string) bool { return d == cfg })
}

// POST /api/plugins/port {pkg, port, proto, open}
func (a *App) handlePluginPort(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Pkg   string `json:"pkg"`
		Port  int    `json:"port"`
		Proto string `json:"proto"`
		Open  bool   `json:"open"`
	}
	if readJSON(r, &req) != nil || req.Port < 1 || req.Port > 65535 || (req.Proto != "tcp" && req.Proto != "udp") {
		jsonErr(w, 400, "请求格式错误")
		return
	}
	p, err := a.pluginOf(req.Pkg)
	if err != nil {
		jsonErr(w, 404, err.Error())
		return
	}
	held := false
	for _, pt := range p.Ports {
		if pt.Port == req.Port && pt.Proto == req.Proto {
			held = true
		}
	}
	if !held && req.Open {
		jsonErr(w, 400, "这个端口不是该插件在用的")
		return
	}
	if _, clash := a.wharfPorts()[req.Port]; clash {
		jsonErr(w, 400, "这是 Wharf 自己的端口")
		return
	}
	sec := fmt.Sprintf("owpplug_%d_%s", req.Port, req.Proto)
	title := nz(knownApps[appKey(p.Pkg)].Name, p.Title)
	var ch []UciChange
	if req.Open {
		ch = []UciChange{{Op: "add", Config: "firewall", Type: "rule", Name: sec, Values: map[string]any{
			"name": fmt.Sprintf("Wharf 插件 %s %d/%s", title, req.Port, req.Proto), "src": "wan", "proto": req.Proto,
			"dest_port": strconv.Itoa(req.Port), "target": "ACCEPT"}}}
	} else {
		fw, _ := a.agent.UciConfig("firewall")
		if fw[sec] == nil {
			jsonErr(w, 400, "这个端口不是 Wharf 开放的，请在防火墙页面修改")
			return
		}
		ch = []UciChange{{Op: "delete", Config: "firewall", Section: sec}}
	}
	what := "向外网开放"
	if !req.Open {
		what = "关闭外网访问"
	}
	a.applyAudited(w, r, "plugin.port", fmt.Sprintf("%s：%s %d/%s", title, what, req.Port, req.Proto), ch)
}

// ---- store ----

// GET /api/store
func (a *App) handleStore(w http.ResponseWriter, r *http.Request) {
	var st struct {
		Apps []struct {
			Pkg       string   `json:"pkg"`
			Version   string   `json:"version"`
			Size      int64    `json:"size"`
			Desc      string   `json:"desc"`
			Depends   []string `json:"depends"`
			Feed      string   `json:"feed"`
			Installed string   `json:"installed"`
			I18n      string   `json:"i18n"`
		} `json:"apps"`
		ListsAt   int64           `json:"lists_at"`
		Arch      string          `json:"arch"`
		FreeBytes int64           `json:"free_bytes"`
		Job       json.RawMessage `json:"job"`
	}
	if err := a.agent.Do("GET", "/v1/store", nil, &st); err != nil {
		jsonErr(w, 502, agentMsg(err))
		return
	}
	var apps []map[string]any
	for _, x := range st.Apps {
		k := appKey(x.Pkg)
		m := knownApps[k]
		apps = append(apps, map[string]any{"pkg": x.Pkg, "version": x.Version, "size": x.Size, "desc": x.Desc, "feed": x.Feed, "installed": x.Installed,
			"i18n": x.I18n, "name": nz(m.Name, k), "about": m.Desc, "group": nz(m.Group, "other"), "group_label": nz(groupLabel[m.Group], "其他"),
			"covered": m.Covered, "known": m.Name != ""})
	}
	writeJSON(w, 200, map[string]any{"apps": apps, "lists_at": st.ListsAt, "arch": st.Arch, "free_bytes": st.FreeBytes, "job": st.Job})
}

// GET /api/store/check?pkg= — what installing would do, and whether it fits
func (a *App) handleStoreCheck(w http.ResponseWriter, r *http.Request) {
	pkg := r.URL.Query().Get("pkg")
	var c struct {
		Pkg       string   `json:"pkg"`
		Installs  []string `json:"installs"`
		Bytes     int64    `json:"bytes"`
		FreeBytes int64    `json:"free_bytes"`
		Errors    []string `json:"errors"`
		Output    string   `json:"output"`
	}
	if err := a.agent.Do("GET", "/v1/store/check?pkg="+urlQueryEscape(pkg), nil, &c); err != nil {
		jsonErr(w, 400, agentMsg(err))
		return
	}
	verdict := "ok"
	var notes []string
	if len(c.Errors) > 0 {
		verdict = "block"
		notes = append(notes, "opkg 报告无法安装（依赖缺失、架构不符或文件冲突），详见下方输出")
	}
	if c.Bytes*3 > c.FreeBytes { // packages unpack to roughly 2–3× their download size
		verdict = "block"
		notes = append(notes, fmt.Sprintf("系统分区空间不够：需要约 %s，只剩 %s", humanBytes(c.Bytes*3), humanBytes(c.FreeBytes)))
	} else if c.Bytes*6 > c.FreeBytes && verdict == "ok" {
		verdict = "warn"
		notes = append(notes, fmt.Sprintf("装完后系统分区剩余空间会比较紧张（剩 %s）", humanBytes(c.FreeBytes-c.Bytes*3)))
	}
	if len(c.Installs) == 0 && len(c.Errors) == 0 {
		notes = append(notes, "已经安装，不需要额外的软件包")
	}
	k := appKey(pkg)
	if m := knownApps[k]; m.Covered != "" {
		if verdict == "ok" {
			verdict = "warn"
		}
		notes = append(notes, "Wharf 已经自带了这个功能（"+m.Covered+"），一般不需要再装")
	}
	if list, err := a.plugins(false); err == nil {
		for g, members := range exclusiveGroups {
			if !slices.Contains(members, k) {
				continue
			}
			for _, p := range list {
				o := appKey(p.Pkg)
				if o != k && slices.Contains(members, o) {
					if verdict == "ok" {
						verdict = "warn"
					}
					what := map[string]string{"proxy": "两个代理插件同时开启会争抢流量，装好后只启用一个", "dns": "两个 DNS 插件同时接管解析可能互相覆盖"}[g]
					notes = append(notes, "已经装了 "+nz(knownApps[o].Name, o)+"："+what)
				}
			}
		}
	}
	if k == "adguardhome" || k == "mosdns" || k == "smartdns" {
		notes = append(notes, "DNS 插件会接管 dnsmasq 的上游，Wharf 的「DNS 拦截」统计会看到它作为唯一的上游")
	}
	writeJSON(w, 200, map[string]any{"check": c, "verdict": verdict, "notes": notes})
}

// POST /api/store {action: update|install|remove, pkgs}
func (a *App) handleStoreAction(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Action string   `json:"action"`
		Pkgs   []string `json:"pkgs"`
	}
	if readJSON(r, &req) != nil {
		jsonErr(w, 400, "请求格式错误")
		return
	}
	if err := a.agent.Do("POST", "/v1/store", req, nil); err != nil {
		jsonErr(w, 409, agentMsg(err))
		return
	}
	if req.Action != "update" {
		what := map[string]string{"install": "安装插件", "remove": "卸载插件"}[req.Action]
		a.audit(actor{user: currentUser(r), ip: a.clientIP(r)}, "store."+req.Action, "plugin", strings.Join(req.Pkgs, " "), what+" "+strings.Join(req.Pkgs, " "), nil, nil, false)
	}
	writeJSON(w, 202, map[string]bool{"ok": true})
}

// GET /api/store/job
func (a *App) handleStoreJob(w http.ResponseWriter, r *http.Request) {
	var j json.RawMessage
	if err := a.agent.Do("GET", "/v1/store/job", nil, &j); err != nil {
		jsonErr(w, 502, agentMsg(err))
		return
	}
	writeJSON(w, 200, j)
}

func urlQueryEscape(s string) string { return url.QueryEscape(s) }
