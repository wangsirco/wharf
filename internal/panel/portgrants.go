package panel

import (
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// Port forward grants: the super admin can limit a normal admin to port ranges
// (optionally on one WAN interface) and to LAN target address ranges. No ranges
// means "unrestricted", which keeps accounts created before grants existed working.

type PortGrant struct {
	WAN  string `json:"wan"` // network interface ("wan", "wan2"); "" = every WAN
	From int    `json:"from"`
	To   int    `json:"to"`
}

type ForwardGrants struct {
	Ports []PortGrant `json:"ports"`
	LAN   []string    `json:"lan"` // 192.168.1.50, 192.168.1.64/28, 192.168.1.100-192.168.1.120
}

var ifaceRe = regexp.MustCompile(`^[A-Za-z0-9_]{1,15}$`)

func (g *ForwardGrants) normalize() {
	if g.Ports == nil {
		g.Ports = []PortGrant{}
	}
	if g.LAN == nil {
		g.LAN = []string{}
	}
	sort.Slice(g.Ports, func(i, j int) bool {
		if g.Ports[i].WAN != g.Ports[j].WAN {
			return g.Ports[i].WAN < g.Ports[j].WAN
		}
		return g.Ports[i].From < g.Ports[j].From
	})
}

func (g *ForwardGrants) validate() error {
	g.normalize()
	if len(g.Ports) > 64 || len(g.LAN) > 64 {
		return errors.New("端口段或 IP 段数量过多")
	}
	for _, p := range g.Ports {
		if p.From < 1 || p.To > 65535 || p.From > p.To {
			return fmt.Errorf("端口段 %d-%d 无效（1-65535，起始不能大于结束）", p.From, p.To)
		}
		if p.WAN != "" && !ifaceRe.MatchString(p.WAN) {
			return fmt.Errorf("WAN 接口名 %q 无效", p.WAN)
		}
	}
	for i := range g.Ports {
		for j := i + 1; j < len(g.Ports); j++ {
			if grantsOverlap(g.Ports[i], g.Ports[j]) {
				return fmt.Errorf("端口段 %s 与 %s 重叠，请合并", g.Ports[i], g.Ports[j])
			}
		}
	}
	for i, s := range g.LAN {
		r, err := parseLANRange(s)
		if err != nil {
			return err
		}
		g.LAN[i] = r.String()
	}
	return nil
}

func (p PortGrant) String() string {
	s := strconv.Itoa(p.From)
	if p.To != p.From {
		s += "-" + strconv.Itoa(p.To)
	}
	if p.WAN != "" {
		s = p.WAN + ":" + s
	}
	return s
}

func wanOverlap(a, b string) bool { return a == "" || b == "" || a == b }

func grantsOverlap(a, b PortGrant) bool {
	return wanOverlap(a.WAN, b.WAN) && a.From <= b.To && b.From <= a.To
}

// lanRange is an inclusive IPv4 range.
type lanRange struct{ lo, hi netip.Addr }

func (r lanRange) String() string {
	if r.lo == r.hi {
		return r.lo.String()
	}
	return r.lo.String() + "-" + r.hi.String()
}

func (r lanRange) contains(ip netip.Addr) bool {
	return ip.Compare(r.lo) >= 0 && ip.Compare(r.hi) <= 0
}

func parseLANRange(s string) (lanRange, error) {
	s = strings.TrimSpace(s)
	bad := fmt.Errorf("内网 IP 段 %q 无效（支持 192.168.1.50、192.168.1.64/28、192.168.1.100-192.168.1.120）", s)
	var r lanRange
	switch {
	case strings.Contains(s, "/"):
		p, err := netip.ParsePrefix(s)
		if err != nil || !p.Addr().Is4() {
			return r, bad
		}
		p = p.Masked()
		r.lo = p.Addr()
		r.hi = lastAddr(p)
	case strings.Contains(s, "-"):
		a, b, _ := strings.Cut(s, "-")
		lo, err1 := netip.ParseAddr(strings.TrimSpace(a))
		hi, err2 := netip.ParseAddr(strings.TrimSpace(b))
		if err1 != nil || err2 != nil || !lo.Is4() || !hi.Is4() || lo.Compare(hi) > 0 {
			return r, bad
		}
		r.lo, r.hi = lo, hi
	default:
		ip, err := netip.ParseAddr(s)
		if err != nil || !ip.Is4() {
			return r, bad
		}
		r.lo, r.hi = ip, ip
	}
	if !r.lo.IsPrivate() || !r.hi.IsPrivate() {
		return r, fmt.Errorf("内网 IP 段 %s 必须是私有地址", s)
	}
	return r, nil
}

func lastAddr(p netip.Prefix) netip.Addr {
	b := p.Addr().As4()
	n := uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
	n |= (1 << (32 - p.Bits())) - 1
	return netip.AddrFrom4([4]byte{byte(n >> 24), byte(n >> 16), byte(n >> 8), byte(n)})
}

// lanAllowed reports whether ip is inside the user's LAN ranges (empty = any).
func (g ForwardGrants) lanAllowed(ip string) bool {
	if len(g.LAN) == 0 {
		return true
	}
	a, err := netip.ParseAddr(ip)
	if err != nil {
		return false
	}
	for _, s := range g.LAN {
		if r, err := parseLANRange(s); err == nil && r.contains(a) {
			return true
		}
	}
	return false
}

// portAllowed reports whether a WAN port on a WAN interface is inside the grants.
// A forward on every WAN (wan "") needs a grant that also covers every WAN.
func (g ForwardGrants) portAllowed(wan string, port int) bool {
	if len(g.Ports) == 0 {
		return true
	}
	for _, p := range g.Ports {
		if port >= p.From && port <= p.To && (p.WAN == "" || p.WAN == wan) {
			return true
		}
	}
	return false
}

// grantOverlap refuses port ranges already given to another admin.
func (a *App) grantOverlap(userID int64, g ForwardGrants) error {
	users, err := a.listUsers()
	if err != nil {
		return err
	}
	for _, o := range users {
		if o.ID == userID || o.Role == RoleSuper {
			continue
		}
		for _, mine := range g.Ports {
			for _, theirs := range o.Grants.Ports {
				if grantsOverlap(mine, theirs) {
					return fmt.Errorf("端口段 %s 与「%s」已分配的 %s 重叠", mine, o.DisplayName, theirs)
				}
			}
		}
	}
	return nil
}

// ---- router facts ----

type wanInfo struct {
	Interface string `json:"interface"`
	Device    string `json:"device"`
	IPv4      string `json:"ipv4"`
	Up        bool   `json:"up"`
	Proto     string `json:"proto"`
}

func (a *App) wans() []wanInfo {
	var out []wanInfo
	_ = a.agent.Do("GET", "/v1/wans", nil, &out)
	return out
}

type listener struct {
	Port  int    `json:"port"`
	Proto string `json:"proto"`
	Proc  string `json:"proc"`
	Local bool   `json:"local"`
}

func (a *App) listeners() []listener {
	var out []listener
	_ = a.agent.Do("GET", "/v1/listen", nil, &out)
	return out
}

// wanOfRedirect returns the WAN interface a redirect is bound to ("" = all).
func wanOfRedirect(r, meta Section, wans []wanInfo) string {
	if meta != nil {
		if w := optStr(meta, "wan"); w != "" {
			return w
		}
	}
	if f := strings.Fields(optStr(r, "extra")); len(f) == 2 && f[0] == "-i" {
		for _, w := range wans {
			if w.Device == f[1] {
				return w.Interface
			}
		}
		return "dev:" + f[1]
	}
	return ""
}

// ---- conflict checks ----

type portIssue struct {
	Level string `json:"level"` // error | warn
	Msg   string `json:"msg"`
}

// forwardIssues checks a (wan, port, proto, lan ip) choice for user u. skipID is the
// forward being edited. Errors block saving; warnings are shown but allowed.
func (a *App) forwardIssues(u *User, st *fwState, wans []wanInfo, lis []listener, skipID, wan string, port int, proto, lanIP string) []portIssue {
	var out []portIssue
	add := func(level, f string, args ...any) { out = append(out, portIssue{level, fmt.Sprintf(f, args...)}) }
	if wan != "" {
		known := false
		for _, w := range wans {
			known = known || w.Interface == wan
		}
		if !known {
			add("error", "WAN 接口 %s 不存在", wan)
		}
	}
	if u.Role != RoleSuper {
		if !u.Grants.portAllowed(wan, port) {
			add("error", "端口 %d 不在分配给你的端口段内（%s）", port, grantList(u.Grants.Ports))
		}
		if lanIP != "" && !u.Grants.lanAllowed(lanIP) {
			add("error", "目标 %s 不在允许你转发的内网 IP 段内（%s）", lanIP, strings.Join(u.Grants.LAN, "、"))
		}
		// ranges given to someone else are reserved for them
		if users, err := a.listUsers(); err == nil {
			for _, o := range users {
				if o.ID == u.ID {
					continue
				}
				for _, g := range o.Grants.Ports {
					if grantsOverlap(g, PortGrant{WAN: wan, From: port, To: port}) {
						add("error", "端口 %d 已分配给其他管理员", port)
					}
				}
			}
		}
	}
	for id, s := range st.fw {
		if id == skipID || !isWanRedirect(s) {
			continue
		}
		lo, hi, ok := portRange(optStr(s, "src_dport"))
		if !ok || port < lo || port > hi || !protoOverlap(proto, optStr(s, "proto")) || !wanOverlap(wan, wanOfRedirect(s, st.owp[id], wans)) {
			continue
		}
		if !a.canTouch(u, "firewall", id) { // don't reveal other admins' rules
			add("error", "WAN 端口 %d 已被占用", port)
			continue
		}
		state := ""
		if optStr(s, "enabled") == "0" {
			state = "（已停用）"
		}
		add("error", "WAN 端口 %d 已被「%s」%s占用", port, displayRule(s, st.owp[id]), state)
	}
	if _, p, err := net.SplitHostPort(a.cfg.Listen); err == nil && p == strconv.Itoa(port) {
		add("error", "端口 %d 是本面板自己的端口", port)
	}
	for _, l := range lis {
		if l.Port == port && !l.Local && protoOverlap(proto, l.Proto) {
			add("warn", "路由器自身的 %s 正在监听 %s %d；转发后从公网将访问不到它", firstNonEmpty(l.Proc, "服务"), strings.ToUpper(l.Proto), port)
		}
	}
	// a free port inside someone else's grant: the super admin may use it, but should know
	if u.Role == RoleSuper {
		if users, err := a.listUsers(); err == nil {
			for _, o := range users {
				for _, g := range o.Grants.Ports {
					if grantsOverlap(g, PortGrant{WAN: wan, From: port, To: port}) {
						add("warn", "端口 %d 属于分配给「%s」的端口段 %s", port, o.DisplayName, g)
					}
				}
			}
		}
	}
	return out
}

func displayRule(r, meta Section) string {
	if meta != nil && optStr(meta, "device") != "" {
		return optStr(meta, "device")
	}
	return firstNonEmpty(optStr(r, "name"), "未命名规则")
}

func grantList(ps []PortGrant) string {
	var s []string
	for _, p := range ps {
		s = append(s, p.String())
	}
	return strings.Join(s, "、")
}

func firstError(issues []portIssue) error {
	for _, i := range issues {
		if i.Level == "error" {
			return errors.New(i.Msg)
		}
	}
	return nil
}

// ---- GET /api/forwards/ports ----

type usedPort struct {
	Port    int    `json:"port"`
	To      int    `json:"to,omitempty"`
	Proto   string `json:"proto"`
	WAN     string `json:"wan"`
	Mine    bool   `json:"mine"`
	Enabled bool   `json:"enabled"`
	Label   string `json:"label,omitempty"` // only for rules the viewer may see
}

type grantView struct {
	PortGrant
	Free int `json:"free"` // ports in the range not used by any forward
	Next int `json:"next"` // first free port, 0 = full
}

// handleForwardPorts tells the form which ports are usable:
// ?wan=&port=&proto=&lan_ip=&id= adds a live check of one choice;
// ?size=N (super) suggests the next free block of N ports for allocation.
func (a *App) handleForwardPorts(w http.ResponseWriter, r *http.Request) {
	u := currentUser(r)
	q := r.URL.Query()
	st, err := a.loadFwState()
	if err != nil {
		jsonErr(w, 502, err.Error())
		return
	}
	wans, lis := a.wans(), a.listeners()
	if wans == nil {
		wans = []wanInfo{}
	}

	var used []usedPort
	for id, s := range st.fw {
		if !isWanRedirect(s) {
			continue
		}
		lo, hi, ok := portRange(optStr(s, "src_dport"))
		if !ok {
			continue
		}
		up := usedPort{Port: lo, Proto: normProto(optStr(s, "proto")), WAN: wanOfRedirect(s, st.owp[id], wans),
			Mine: a.owner("firewall", id) == u.ID, Enabled: optStr(s, "enabled") != "0"}
		if hi != lo {
			up.To = hi
		}
		if u.Role == RoleSuper || up.Mine {
			up.Label = displayRule(s, st.owp[id])
		}
		used = append(used, up)
	}
	sort.Slice(used, func(i, j int) bool { return used[i].Port < used[j].Port })
	taken := func(wan string, p int) bool {
		for _, x := range used {
			hi := max(x.To, x.Port)
			if p >= x.Port && p <= hi && wanOverlap(wan, x.WAN) {
				return true
			}
		}
		if _, lp, err := net.SplitHostPort(a.cfg.Listen); err == nil && lp == strconv.Itoa(p) {
			return true
		}
		return false
	}

	out := map[string]any{"wans": wans, "used": used, "restricted": u.Role != RoleSuper && len(u.Grants.Ports) > 0,
		"lan": u.Grants.LAN, "lan_restricted": u.Role != RoleSuper && len(u.Grants.LAN) > 0}
	var listen []listener
	for _, l := range lis {
		if !l.Local {
			listen = append(listen, l)
		}
	}
	out["router"] = listen

	grants := []grantView{}
	if u.Role != RoleSuper {
		for _, g := range u.Grants.Ports {
			v := grantView{PortGrant: g}
			for p := g.From; p <= g.To; p++ {
				if !taken(g.WAN, p) {
					v.Free++
					if v.Next == 0 {
						v.Next = p
					}
				}
			}
			grants = append(grants, v)
		}
	}
	out["grants"] = grants

	type alloc struct {
		UserID int64  `json:"user_id"`
		User   string `json:"user"`
		PortGrant
	}
	allocs := []alloc{}
	if users, err := a.listUsers(); err == nil {
		for _, o := range users {
			for _, g := range o.Grants.Ports {
				allocs = append(allocs, alloc{o.ID, o.DisplayName, g})
			}
		}
	}
	if u.Role == RoleSuper {
		out["allocations"] = allocs
	}
	// ?size=N: first block of N ports from 10000 up that nobody uses, listens on or owns
	if size, _ := strconv.Atoi(q.Get("size")); size > 0 && size <= 5000 {
		exclude := u.ID
		if u.Role == RoleSuper {
			exclude, _ = strconv.ParseInt(q.Get("exclude_user"), 10, 64)
		}
		wan := q.Get("wan")
		blocked := func(p int) bool {
			if taken(wan, p) {
				return true
			}
			for _, al := range allocs {
				if al.UserID != exclude && grantsOverlap(al.PortGrant, PortGrant{WAN: wan, From: p, To: p}) {
					return true
				}
			}
			for _, l := range listen {
				if l.Port == p {
					return true
				}
			}
			return false
		}
		run := 0
		for p := 10000; p <= 65535; p++ {
			if blocked(p) {
				run = 0
				continue
			}
			if run++; run == size {
				out["suggest"] = PortGrant{WAN: wan, From: p - size + 1, To: p}
				break
			}
		}
	}

	if port, _ := strconv.Atoi(q.Get("port")); port > 0 {
		issues := []portIssue{}
		if port > 65535 {
			issues = append(issues, portIssue{"error", "端口范围是 1-65535"})
		} else {
			issues = append(issues, a.forwardIssues(u, st, wans, lis, q.Get("id"), q.Get("wan"), port, normProto(q.Get("proto")), q.Get("lan_ip"))...)
		}
		out["check"] = map[string]any{"port": port, "ok": firstError(issues) == nil, "issues": issues}
	}
	writeJSON(w, 200, out)
}
