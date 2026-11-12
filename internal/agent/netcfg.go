package agent

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Network interfaces as netifd sees them, plus the physical links under them.

type NetLink struct {
	Name     string   `json:"name"`
	Type     string   `json:"type"` // ethernet | bridge | wireless | vlan | tunnel | other
	MAC      string   `json:"mac,omitempty"`
	Present  bool     `json:"present"`
	Up       bool     `json:"up"`
	Carrier  bool     `json:"carrier"`
	Speed    int      `json:"speed,omitempty"` // Mbit/s, 0 = unknown
	Duplex   string   `json:"duplex,omitempty"`
	MTU      int      `json:"mtu,omitempty"`
	Members  []string `json:"members,omitempty"` // bridge ports
	Bridge   string   `json:"bridge,omitempty"`  // bridge this port belongs to
	Physical bool     `json:"physical"`
	RX       uint64   `json:"rx"`
	TX       uint64   `json:"tx"`
	RXErr    uint64   `json:"rx_errors"`
	TXErr    uint64   `json:"tx_errors"`
	Driver   string   `json:"driver,omitempty"`
}

type NetIfaceStat struct {
	Name      string   `json:"name"`
	Proto     string   `json:"proto"`
	Device    string   `json:"device"`    // configured device (eth0, br-lan, @wan …)
	L3        string   `json:"l3_device"` // device carrying the addresses (pppoe-wan …)
	Up        bool     `json:"up"`
	Pending   bool     `json:"pending"`
	Available bool     `json:"available"`
	Autostart bool     `json:"autostart"`
	Dynamic   bool     `json:"dynamic"`
	Uptime    int64    `json:"uptime"`
	Metric    int      `json:"metric"`
	IPv4      []string `json:"ipv4"` // address/prefix
	IPv6      []string `json:"ipv6"`
	Prefix6   []string `json:"prefix6"`
	Gateway   string   `json:"gateway,omitempty"`
	Gateway6  string   `json:"gateway6,omitempty"`
	DNS       []string `json:"dns"`
	Errors    []string `json:"errors,omitempty"`
	Config    Section  `json:"config"`
}

type NetOverview struct {
	Interfaces []NetIfaceStat `json:"interfaces"`
	Devices    []NetLink      `json:"devices"`
	Pending    *PendingApply  `json:"pending,omitempty"`
	Firewall   string         `json:"firewall"`
	Protos     []string       `json:"protos"` // interface protocols this router can run
}

func netProtos() []string {
	out := []string{"static", "none"}
	m, _ := filepath.Glob("/lib/netifd/proto/*.sh")
	for _, f := range m {
		out = append(out, strings.TrimSuffix(filepath.Base(f), ".sh"))
	}
	sort.Strings(out)
	return out
}

type ifDump struct {
	Interface []struct {
		Name      string `json:"interface"`
		Up        bool   `json:"up"`
		Pending   bool   `json:"pending"`
		Available bool   `json:"available"`
		Autostart bool   `json:"autostart"`
		Dynamic   bool   `json:"dynamic"`
		Uptime    int64  `json:"uptime"`
		L3        string `json:"l3_device"`
		Proto     string `json:"proto"`
		Device    string `json:"device"`
		Metric    int    `json:"metric"`
		V4        []struct {
			Address string `json:"address"`
			Mask    int    `json:"mask"`
		} `json:"ipv4-address"`
		V6 []struct {
			Address string `json:"address"`
			Mask    int    `json:"mask"`
		} `json:"ipv6-address"`
		P6 []struct {
			Address string `json:"address"`
			Mask    int    `json:"mask"`
		} `json:"ipv6-prefix"`
		Route []struct {
			Target  string `json:"target"`
			Mask    int    `json:"mask"`
			Nexthop string `json:"nexthop"`
		} `json:"route"`
		DNS    []string `json:"dns-server"`
		Errors []struct {
			Subsystem string `json:"subsystem"`
			Code      string `json:"code"`
		} `json:"errors"`
	} `json:"interface"`
}

func netInterfaces() []NetIfaceStat {
	var d ifDump
	_ = ubusCall("network.interface", "dump", nil, &d)
	cfg, _ := uciGetConfig("network")
	var out []NetIfaceStat
	seen := map[string]bool{}
	for _, i := range d.Interface {
		if i.Name == "loopback" {
			continue
		}
		seen[i.Name] = true
		s := NetIfaceStat{Name: i.Name, Proto: i.Proto, Device: i.Device, L3: i.L3, Up: i.Up, Pending: i.Pending,
			Available: i.Available, Autostart: i.Autostart, Dynamic: i.Dynamic, Uptime: i.Uptime, Metric: i.Metric,
			DNS: i.DNS, Config: redactSection(cfg[i.Name])}
		if s.Device == "" && s.Config != nil {
			s.Device = fmt.Sprint(s.Config["device"])
		}
		for _, a := range i.V4 {
			s.IPv4 = append(s.IPv4, fmt.Sprintf("%s/%d", a.Address, a.Mask))
		}
		for _, a := range i.V6 {
			s.IPv6 = append(s.IPv6, fmt.Sprintf("%s/%d", a.Address, a.Mask))
		}
		for _, a := range i.P6 {
			s.Prefix6 = append(s.Prefix6, fmt.Sprintf("%s/%d", a.Address, a.Mask))
		}
		for _, r := range i.Route {
			if r.Mask == 0 && r.Target == "0.0.0.0" {
				s.Gateway = r.Nexthop
			} else if r.Mask == 0 && r.Target == "::" {
				s.Gateway6 = r.Nexthop
			}
		}
		for _, e := range i.Errors {
			s.Errors = append(s.Errors, e.Subsystem+": "+e.Code)
		}
		out = append(out, s)
	}
	// configured but unknown to netifd (e.g. a protocol package is missing)
	for name, sec := range cfg {
		if sec[".type"] != "interface" || seen[name] || name == "loopback" {
			continue
		}
		out = append(out, NetIfaceStat{Name: name, Proto: fmt.Sprint(sec["proto"]), Config: redactSection(sec),
			Errors: []string{"netifd: 接口未加载（协议软件包可能缺失）"}})
	}
	sort.Slice(out, func(a, b int) bool { return ifaceOrder(out[a].Name) < ifaceOrder(out[b].Name) })
	return out
}

// ifaceOrder puts lan, wan, wan6 first, then the rest by name.
func ifaceOrder(n string) string {
	switch {
	case n == "lan":
		return "0"
	case n == "wan":
		return "1"
	case n == "wan6":
		return "2"
	case strings.HasPrefix(n, "wan"):
		return "3" + n
	case strings.HasPrefix(n, "lan"):
		return "4" + n
	}
	return "5" + n
}

// redactSection hides secrets (PPPoE passwords, WireGuard keys …); the panel shows "已设置".
func redactSection(s Section) Section {
	if s == nil {
		return nil
	}
	out := Section{}
	for k, v := range s {
		if isSecretOption(k) {
			if fmt.Sprint(v) != "" {
				out[k] = "\x00set"
			}
			continue
		}
		out[k] = v
	}
	return out
}

func isSecretOption(k string) bool {
	k = strings.ToLower(k)
	return k == "password" || k == "key" || k == "private_key" || k == "preshared_key" || strings.HasSuffix(k, "_password") || k == "psk"
}

var speedRe = regexp.MustCompile(`^(-?\d+)([FH])$`)

func netDevices() []NetLink {
	var st map[string]struct {
		Type     string   `json:"type"`
		DevType  string   `json:"devtype"`
		Present  bool     `json:"present"`
		Up       bool     `json:"up"`
		Carrier  bool     `json:"carrier"`
		Speed    string   `json:"speed"`
		MTU      int      `json:"mtu"`
		MAC      string   `json:"macaddr"`
		Members  []string `json:"bridge-members"`
		External bool     `json:"external"`
		Stats    struct {
			RX    uint64 `json:"rx_bytes"`
			TX    uint64 `json:"tx_bytes"`
			RXErr uint64 `json:"rx_errors"`
			TXErr uint64 `json:"tx_errors"`
		} `json:"statistics"`
	}
	_ = ubusCall("network.device", "status", nil, &st)
	bridgeOf := map[string]string{}
	for n, d := range st {
		for _, m := range d.Members {
			bridgeOf[m] = n
		}
	}
	var out []NetLink
	for n, d := range st {
		if n == "lo" {
			continue
		}
		l := NetLink{Name: n, MAC: d.MAC, Present: d.Present, Up: d.Up, Carrier: d.Carrier, MTU: d.MTU, Members: d.Members,
			Bridge: bridgeOf[n], RX: d.Stats.RX, TX: d.Stats.TX, RXErr: d.Stats.RXErr, TXErr: d.Stats.TXErr}
		if m := speedRe.FindStringSubmatch(d.Speed); m != nil {
			if v, _ := strconv.Atoi(m[1]); v > 0 {
				l.Speed = v
				l.Duplex = map[string]string{"F": "full", "H": "half"}[m[2]]
			}
		}
		_, err := os.Stat("/sys/class/net/" + n + "/device")
		l.Physical = err == nil
		if lnk, err := os.Readlink("/sys/class/net/" + n + "/device/driver"); err == nil {
			l.Driver = lnk[strings.LastIndex(lnk, "/")+1:]
		}
		switch {
		case d.DevType == "bridge" || d.Type == "bridge":
			l.Type = "bridge"
		case d.DevType == "wlan" || fileExists("/sys/class/net/"+n+"/wireless") || fileExists("/sys/class/net/"+n+"/phy80211"):
			l.Type = "wireless"
		case d.DevType == "vlan" || strings.Contains(d.Type, "VLAN"):
			l.Type = "vlan"
		case l.Physical:
			l.Type = "ethernet"
		case strings.HasPrefix(n, "pppoe-") || strings.HasPrefix(n, "tun") || strings.HasPrefix(n, "wg") || strings.HasPrefix(n, "ppp"):
			l.Type = "tunnel"
		default:
			l.Type = "other"
		}
		out = append(out, l)
	}
	sort.Slice(out, func(a, b int) bool { return out[a].Name < out[b].Name })
	return out
}

func fileExists(p string) bool { _, err := os.Stat(p); return err == nil }

func GetNetOverview() NetOverview {
	return NetOverview{Interfaces: netInterfaces(), Devices: netDevices(), Pending: CurrentPending(), Firewall: FirewallFlavor(), Protos: netProtos()}
}

var ifNameRe = regexp.MustCompile(`^[A-Za-z0-9_]{1,15}$`)

// IfaceAction restarts, starts or stops one logical interface. A restart runs a
// moment after the reply so the panel gets its answer even when the request
// itself travels over that interface.
func IfaceAction(name, action string) error {
	if !ifNameRe.MatchString(name) || name == "loopback" {
		return errors.New("接口名不正确")
	}
	if sec, _ := uciGetSection("network", name); sec == nil || sec[".type"] != "interface" {
		return errors.New("没有这个接口")
	}
	switch action {
	case "restart":
		go func() {
			time.Sleep(700 * time.Millisecond)
			_, _ = run(30*time.Second, "ifup", name) // ifup = down + up for an active interface
		}()
	case "up":
		return ubusCall("network.interface."+name, "up", nil, nil)
	case "down":
		go func() {
			time.Sleep(700 * time.Millisecond)
			_ = ubusCall("network.interface."+name, "down", nil, nil)
		}()
	default:
		return errors.New("未知操作")
	}
	return nil
}

// ---- outage diagnosis ----

type DiagStep struct {
	ID     string `json:"id"`
	Label  string `json:"label"`
	Status string `json:"status"` // ok | warn | fail | skip
	Detail string `json:"detail"`
	Ms     int64  `json:"ms"`
}

type WanDiag struct {
	Iface   string     `json:"iface"`
	At      int64      `json:"at"`
	Steps   []DiagStep `json:"steps"`
	Who     string     `json:"who"` // ok | home | account | isp | dns | web
	Verdict string     `json:"verdict"`
	Advice  string     `json:"advice"`
}

// DiagnoseWAN walks the chain cable → address → gateway → internet → DNS → web
// and says whose problem it is.
func DiagnoseWAN(iface string) WanDiag {
	if iface == "" {
		iface = "wan"
	}
	d := WanDiag{Iface: iface, At: time.Now().Unix()}
	step := func(id, label string, f func() (string, string)) string {
		t := time.Now()
		st, det := f()
		d.Steps = append(d.Steps, DiagStep{id, label, st, det, time.Since(t).Milliseconds()})
		return st
	}
	skipRest := func(ids ...[2]string) {
		for _, s := range ids {
			d.Steps = append(d.Steps, DiagStep{s[0], s[1], "skip", "上一步没通过，跳过", 0})
		}
	}
	verdict := func(who, v, adv string) WanDiag { d.Who, d.Verdict, d.Advice = who, v, adv; return d }
	later := [][2]string{{"addr", "获取地址"}, {"gateway", "运营商网关"}, {"internet", "外网"}, {"dns", "域名解析"}, {"web", "打开网页"}}

	cfg, _ := uciGetSection("network", iface)
	if cfg == nil {
		return verdict("home", "没有名为 "+iface+" 的接口", "")
	}
	proto := fmt.Sprint(cfg["proto"])
	dev := fmt.Sprint(cfg["device"])
	if dev == "" || dev == "<nil>" {
		dev = fmt.Sprint(cfg["ifname"])
	}
	w := WANStatus(iface)

	// 1. link
	if step("link", "网线 / 光猫信号", func() (string, string) {
		var st struct {
			Present bool   `json:"present"`
			Carrier bool   `json:"carrier"`
			Speed   string `json:"speed"`
		}
		if err := ubusCall("network.device", "status", map[string]any{"name": dev}, &st); err != nil || !st.Present {
			return "fail", "找不到网口 " + dev
		}
		if !st.Carrier {
			return "fail", dev + " 没有链路信号"
		}
		sp := ""
		if m := speedRe.FindStringSubmatch(st.Speed); m != nil && m[1] != "-1" {
			sp = "，" + m[1] + " Mbps"
		}
		return "ok", dev + " 已连接" + sp
	}) == "fail" {
		skipRest(later...)
		return verdict("home", "WAN 口没有信号：问题在家里这一侧（网线或光猫）",
			"检查光猫是否通电、网线两头是否插紧。光猫上的 PON / LOS 灯如果红色或在闪，是光纤线路的问题，需要联系运营商。")
	}

	// 2. address
	if step("addr", "获取地址", func() (string, string) {
		if w.Up && w.IPv4 != "" {
			return "ok", fmt.Sprintf("%s（%s），已连上 %s", w.IPv4, protoLabel(proto), fmtDur(w.Uptime))
		}
		if w.Up && strings.HasPrefix(proto, "dhcpv6") {
			return "ok", "IPv6 接口已连接"
		}
		return "fail", protoLabel(proto) + " 没有拿到地址"
	}) == "fail" {
		skipRest(later[1:]...)
		log := recentLog(proto)
		switch {
		case proto == "pppoe" && regexp.MustCompile(`(?i)(authentication failed|auth.*fail|CHAP.*fail|PAP.*fail)`).MatchString(log):
			return verdict("account", "宽带账号或密码被运营商拒绝", "核对接口里的 PPPoE 账号密码；如果没改过，可能是欠费或账号被锁，联系运营商。")
		case proto == "pppoe" && strings.Contains(log, "PADO"):
			return verdict("isp", "运营商的拨号服务器没有回应（PPPoE 超时）", "先重启光猫；仍然不行就是运营商那边的故障，等待恢复或联系客服报修。")
		case proto == "pppoe":
			return verdict("isp", "PPPoE 拨号没有成功", "先重启光猫，再在这里重启 WAN 接口；仍不行请联系运营商。")
		default:
			return verdict("isp", "光猫或运营商没有给路由器分配地址", "先重启光猫，再在这里重启 WAN 接口；仍然不行多半是运营商的故障。")
		}
	}

	// 3. gateway
	gwState := step("gateway", "运营商网关", func() (string, string) {
		if w.Gateway == "" {
			return "warn", "没有默认网关（点对点链路）"
		}
		if pingAny([]string{w.Gateway}, 2) {
			return "ok", w.Gateway + " 有回应"
		}
		if st := neighState(w.Gateway); st != "" && st != "FAILED" && st != "INCOMPLETE" {
			return "warn", w.Gateway + " 不回 ping，但 ARP 能找到它（很多运营商网关就是这样）"
		}
		if proto == "pppoe" {
			return "warn", w.Gateway + " 不回 ping"
		}
		return "fail", w.Gateway + " 没有回应"
	})
	if gwState == "fail" {
		skipRest(later[2:]...)
		return verdict("isp", "路由器到运营商网关不通：是运营商的问题", "地址拿到了但运营商的网关不回应，通常是运营商网络故障。可以先重启光猫，否则等待恢复或联系运营商。")
	}

	// 4. internet
	if step("internet", "外网", func() (string, string) {
		ok := []string{}
		var mu sync.Mutex
		var wg sync.WaitGroup
		for _, t := range []string{"1.1.1.1", "223.5.5.5", "8.8.8.8"} {
			wg.Add(1)
			go func(t string) {
				defer wg.Done()
				if pingAny([]string{t}, 2) {
					mu.Lock()
					ok = append(ok, t)
					mu.Unlock()
				}
			}(t)
		}
		wg.Wait()
		if len(ok) == 0 {
			return "fail", "1.1.1.1、223.5.5.5、8.8.8.8 都没有回应"
		}
		sort.Strings(ok)
		return "ok", strings.Join(ok, "、") + " 有回应"
	}) == "fail" {
		skipRest(later[3:]...)
		return verdict("isp", "运营商网关之后的网络不通：是运营商的问题", "家里到运营商这一段是好的，再往外就不通了。属于运营商网络故障，等待恢复或联系客服报修。")
	}

	// 5. DNS
	upstream := uciValue("dhcp.@dnsmasq[0].server")
	if step("dns", "域名解析", func() (string, string) {
		if resolveVia("127.0.0.1:53", "www.apple.com") {
			return "ok", "路由器能解析域名"
		}
		if resolveVia("223.5.5.5:53", "www.apple.com") {
			return "fail", "路由器自己的 DNS 失败，直接问公共 DNS 是好的（上游：" + nz(upstream, "默认") + "）"
		}
		return "fail", "域名解析失败"
	}) == "fail" {
		skipRest(later[4:]...)
		return verdict("dns", "外网是通的，但域名解析失败：问题在家里的 DNS 设置", "上网要先把网址变成 IP。检查 DNS 上游（"+nz(upstream, "默认")+"）和 DNS 类插件（NextDNS、SmartDNS、OpenClash）是否在运行。")
	}

	// 6. web
	if step("web", "打开网页", func() (string, string) {
		for _, u := range []string{"http://connect.rom.miui.com/generate_204", "http://www.gstatic.com/generate_204", "http://captive.apple.com/hotspot-detect.html"} {
			if httpOK(u) {
				return "ok", "能打开网页"
			}
		}
		return "fail", "能解析域名，但网页请求都失败"
	}) == "fail" {
		return verdict("web", "能连通但打不开网页", "可能是代理插件（OpenClash / PassWall）接管了流量但节点不可用，或运营商在拦截。先关掉代理插件试试。")
	}
	return verdict("ok", "网络正常", "")
}

func protoLabel(p string) string {
	switch p {
	case "dhcp":
		return "DHCP 自动获取"
	case "static":
		return "静态地址"
	case "pppoe":
		return "PPPoE 拨号"
	case "dhcpv6":
		return "DHCPv6"
	}
	return p
}

func nz(s, def string) string {
	if s == "" {
		return def
	}
	return s
}

func fmtDur(sec int64) string {
	switch {
	case sec < 60:
		return fmt.Sprintf("%d 秒", sec)
	case sec < 3600:
		return fmt.Sprintf("%d 分钟", sec/60)
	case sec < 86400:
		return fmt.Sprintf("%d 小时 %d 分", sec/3600, sec%3600/60)
	}
	return fmt.Sprintf("%d 天 %d 小时", sec/86400, sec%86400/3600)
}

func pingAny(targets []string, count int) bool {
	for _, t := range targets {
		ctx, cancel := context.WithTimeout(context.Background(), time.Duration(count*2+2)*time.Second)
		out, _ := runCtx(ctx, "ping", "-c", strconv.Itoa(count), "-W", "2", t)
		cancel()
		if pingRe.Match(out) {
			return true
		}
	}
	return false
}

func neighState(ip string) string {
	out, _ := run(3*time.Second, "ip", "neigh", "show", ip)
	f := strings.Fields(string(out))
	if len(f) == 0 {
		return ""
	}
	return f[len(f)-1]
}

func resolveVia(server, host string) bool {
	r := &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, "udp", server)
	}}
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()
	ips, err := r.LookupHost(ctx, host)
	return err == nil && len(ips) > 0
}

func httpOK(u string) bool {
	c := &http.Client{Timeout: 5 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := c.Get(u)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
	return resp.StatusCode < 500
}

// recentLog returns recent system log lines of the WAN protocol daemon.
func recentLog(proto string) string {
	out, _ := run(5*time.Second, "logread", "-l", "300")
	var keep []string
	for _, l := range strings.Split(string(out), "\n") {
		if (proto == "pppoe" && strings.Contains(l, "pppd")) || strings.Contains(l, "udhcpc") || strings.Contains(l, "netifd") {
			keep = append(keep, l)
		}
	}
	if len(keep) > 60 {
		keep = keep[len(keep)-60:]
	}
	return strings.Join(keep, "\n")
}
