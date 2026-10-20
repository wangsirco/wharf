package panel

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Device access policies live in uci config "owpdev" (one named section per MAC)
// and are compiled into firewall rules by the agent.

type PolicySchedule struct {
	Days  []int  `json:"days"`
	Start string `json:"start"`
	End   string `json:"end"`
}

type DevicePolicy struct {
	MAC         string           `json:"mac"`
	Name        string           `json:"name"`
	Block       bool             `json:"block"`
	Mode        string           `json:"mode"` // none | blacklist | whitelist
	Targets     []string         `json:"targets"`
	Schedules   []PolicySchedule `json:"schedules"`
	Captive     bool             `json:"captive"`
	ForceDNS    bool             `json:"force_dns"`
	RouterPorts []string         `json:"router_ports"`
	// read-only
	Exists    bool   `json:"exists"`
	OwnerID   int64  `json:"owner_id"`
	OwnerName string `json:"owner_name"`
	Editable  bool   `json:"editable"`
	Status    *struct {
		Blocked bool   `json:"blocked"`
		Reason  string `json:"reason"`
	} `json:"status"`
}

func policySection(mac string) string {
	return "owpd_" + strings.ReplaceAll(strings.ToLower(mac), ":", "")
}

func scheduleString(s PolicySchedule) string {
	d := make([]string, len(s.Days))
	for i, x := range s.Days {
		d[i] = strconv.Itoa(x)
	}
	return fmt.Sprintf("days=%s;start=%s;end=%s", strings.Join(d, ","), s.Start, s.End)
}

func parseScheduleString(v string) PolicySchedule {
	var s PolicySchedule
	for _, part := range strings.Split(v, ";") {
		k, val, _ := strings.Cut(part, "=")
		switch k {
		case "days":
			for _, d := range strings.Split(val, ",") {
				if n, err := strconv.Atoi(d); err == nil {
					s.Days = append(s.Days, n)
				}
			}
		case "start":
			s.Start = val
		case "end":
			s.End = val
		}
	}
	return s
}

func policyFromSection(s Section) DevicePolicy {
	p := DevicePolicy{MAC: optStr(s, "mac"), Name: optStr(s, "name"), Block: optStr(s, "block") == "1", Mode: optStr(s, "mode"),
		Targets: optList(s, "target"), Captive: optStr(s, "captive") != "0", ForceDNS: optStr(s, "force_dns") != "0",
		RouterPorts: optList(s, "router_port"), Schedules: []PolicySchedule{}, Exists: true}
	if p.Mode == "" {
		p.Mode = "none"
	}
	for _, v := range optList(s, "schedule") {
		p.Schedules = append(p.Schedules, parseScheduleString(v))
	}
	return p
}

type agentPolicyStatus map[string]struct {
	Blocked bool   `json:"blocked"`
	Reason  string `json:"reason"`
}

func (a *App) decoratePolicy(u *User, p *DevicePolicy, st agentPolicyStatus, names map[int64]string) {
	sec := policySection(p.MAC)
	p.OwnerID = a.owner("owpdev", sec)
	p.OwnerName = names[p.OwnerID]
	p.Editable = u.Can("access.manage") && (!p.Exists || a.canTouch(u, "owpdev", sec))
	if s, ok := st[strings.ToLower(p.MAC)]; ok {
		p.Status = &struct {
			Blocked bool   `json:"blocked"`
			Reason  string `json:"reason"`
		}{s.Blocked, s.Reason}
	}
}

// GET /api/policies
func (a *App) handlePolicies(w http.ResponseWriter, r *http.Request) {
	all, err := a.agent.UciConfig("owpdev")
	if err != nil {
		jsonErr(w, 502, err.Error())
		return
	}
	var st agentPolicyStatus
	_ = a.agent.Do("GET", "/v1/policy/status", nil, &st)
	u, names := currentUser(r), a.userNames()
	out := []DevicePolicy{}
	for _, s := range all {
		if s[".type"] != "device" {
			continue
		}
		p := policyFromSection(s)
		a.decoratePolicy(u, &p, st, names)
		out = append(out, p)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].MAC < out[j].MAC })
	writeJSON(w, 200, out)
}

// GET /api/devices/{mac}/policy
func (a *App) handleDevicePolicy(w http.ResponseWriter, r *http.Request) {
	hw, err := net.ParseMAC(r.PathValue("mac"))
	if err != nil {
		jsonErr(w, 400, "MAC 无效")
		return
	}
	all, err := a.agent.UciConfig("owpdev")
	if err != nil {
		jsonErr(w, 502, err.Error())
		return
	}
	p := DevicePolicy{MAC: hw.String(), Mode: "none", Captive: true, ForceDNS: true, Targets: []string{}, Schedules: []PolicySchedule{}, RouterPorts: []string{}}
	if s := all[policySection(hw.String())]; s != nil {
		p = policyFromSection(s)
	}
	var st agentPolicyStatus
	_ = a.agent.Do("GET", "/v1/policy/status", nil, &st)
	a.decoratePolicy(currentUser(r), &p, st, a.userNames())
	writeJSON(w, 200, p)
}

var domainRe = regexp.MustCompile(`^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$`)

type expanded struct{ domains, cidrs []string }

// expandTargets turns "service:YouTube", "domain:x.com", "ip:1.2.3.0/24" into domains and CIDRs.
func (a *App) expandTargets(targets []string) (expanded, error) {
	var e expanded
	seen := map[string]bool{}
	addD := func(d string) {
		if !seen["d"+d] {
			seen["d"+d] = true
			e.domains = append(e.domains, d)
		}
	}
	for _, t := range targets {
		kind, v, _ := strings.Cut(t, ":")
		v = strings.TrimSpace(v)
		switch kind {
		case "service":
			if a.rules == nil {
				return e, errors.New("规则库未加载")
			}
			ds, cs := a.rules.Targets(v)
			if len(ds)+len(cs) == 0 {
				return e, fmt.Errorf("未知服务：%s", v)
			}
			for _, d := range ds {
				addD(d)
			}
			e.cidrs = append(e.cidrs, cs...)
		case "domain":
			v = strings.TrimPrefix(strings.ToLower(v), "*.")
			if !domainRe.MatchString(v) {
				return e, fmt.Errorf("无效域名：%s", v)
			}
			addD(v)
		case "ip":
			ps, err := parsePrefixes([]string{v})
			if err != nil || len(ps) == 0 || !ps[0].Addr().Is4() {
				return e, fmt.Errorf("无效 IP / IP 段：%s", v)
			}
			e.cidrs = append(e.cidrs, ps[0].String())
		default:
			return e, fmt.Errorf("无效目标：%s", t)
		}
	}
	return e, nil
}

func (p *DevicePolicy) normalize() error {
	hw, err := net.ParseMAC(p.MAC)
	if err != nil || len(hw) != 6 {
		return errors.New("MAC 无效")
	}
	p.MAC = hw.String()
	p.Name = clean(p.Name, 64)
	if p.Mode == "" {
		p.Mode = "none"
	}
	if p.Mode != "none" && p.Mode != "blacklist" && p.Mode != "whitelist" {
		return errors.New("无效的名单模式")
	}
	if p.Mode == "none" {
		p.Targets = nil
	}
	if p.Mode == "whitelist" && len(p.Targets) == 0 {
		return errors.New("白名单模式至少需要一个允许的目标")
	}
	if len(p.Targets) > 200 || len(p.Schedules) > 10 || len(p.RouterPorts) > 20 {
		return errors.New("条目过多")
	}
	for i := range p.Schedules {
		s := &p.Schedules[i]
		if len(s.Days) == 0 {
			return errors.New("定时规则需要至少选择一天")
		}
		for _, d := range s.Days {
			if d < 0 || d > 6 {
				return errors.New("无效的星期")
			}
		}
		slices.Sort(s.Days)
		s.Days = slices.Compact(s.Days)
		st, err1 := time.Parse("15:04", s.Start)
		en, err2 := time.Parse("15:04", s.End)
		if err1 != nil || err2 != nil || st.Equal(en) {
			return errors.New("定时规则的开始 / 结束时间无效")
		}
	}
	for _, port := range p.RouterPorts {
		if n, err := strconv.Atoi(port); err != nil || n < 1 || n > 65535 {
			return fmt.Errorf("无效端口：%s", port)
		}
	}
	return nil
}

func policySummary(p DevicePolicy) string {
	who := p.Name
	if who == "" {
		who = p.MAC
	}
	var parts []string
	if p.Block {
		parts = append(parts, "断网")
	}
	switch p.Mode {
	case "blacklist":
		parts = append(parts, fmt.Sprintf("黑名单 %d 项", len(p.Targets)))
	case "whitelist":
		parts = append(parts, fmt.Sprintf("白名单 %d 项", len(p.Targets)))
	}
	if len(p.Schedules) > 0 {
		parts = append(parts, fmt.Sprintf("定时断网 %d 条", len(p.Schedules)))
	}
	if len(p.RouterPorts) > 0 {
		parts = append(parts, "禁止访问路由器端口 "+strings.Join(p.RouterPorts, ","))
	}
	if len(parts) == 0 {
		parts = append(parts, "不限制")
	}
	return fmt.Sprintf("设备管控 %s：%s", who, strings.Join(parts, "，"))
}

func preparePolicy(a *App, u *User, raw json.RawMessage) (string, error) {
	var p DevicePolicy
	if json.Unmarshal(raw, &p) != nil {
		return "", errors.New("请求格式错误")
	}
	if err := p.normalize(); err != nil {
		return "", err
	}
	if _, err := a.expandTargets(p.Targets); err != nil {
		return "", err
	}
	all, err := a.agent.UciConfig("owpdev")
	if err != nil {
		return "", err
	}
	if all[policySection(p.MAC)] != nil && !a.canTouch(u, "owpdev", policySection(p.MAC)) {
		return "", errors.New("该设备的管控规则由其他管理员创建，你无法修改")
	}
	return policySummary(p), nil
}

func runPolicy(a *App, ac actor, raw json.RawMessage) (any, error) {
	var p DevicePolicy
	_ = json.Unmarshal(raw, &p)
	_ = p.normalize()
	ex, err := a.expandTargets(p.Targets)
	if err != nil {
		return nil, err
	}
	sec := policySection(p.MAC)
	all, err := a.agent.UciConfig("owpdev")
	if err != nil {
		return nil, err
	}
	have := all[sec]
	want := map[string]any{
		"mac": p.MAC, "name": p.Name, "block": boolStr(p.Block), "mode": p.Mode,
		"captive": boolStr(p.Captive), "force_dns": boolStr(p.ForceDNS),
	}
	lists := map[string][]string{"target": p.Targets, "domain": ex.domains, "cidr": ex.cidrs, "router_port": p.RouterPorts}
	for _, s := range p.Schedules {
		lists["schedule"] = append(lists["schedule"], scheduleString(s))
	}
	for k, v := range lists {
		if len(v) > 0 {
			want[k] = v
		}
	}
	changes := sectionChanges("owpdev", sec, "device", have, want)
	res, err := a.agent.Apply(changes...)
	if err != nil {
		return nil, err
	}
	if have == nil {
		_, _ = a.db.Exec(`INSERT OR REPLACE INTO owned(config, section, kind, user_id, created_at) VALUES('owpdev',?,?,?,?)`,
			sec, "policy", ac.user.ID, time.Now().Unix())
	}
	after := res[len(res)-1].After
	if now, err := a.agent.UciConfig("owpdev"); err == nil {
		after = now[sec]
	}
	a.audit(ac, "device.policy.save", "uci", "owpdev."+sec, policySummary(p), have, after, true)
	return nil, nil
}

func boolStr(b bool) string {
	if b {
		return "1"
	}
	return "0"
}

// sectionChanges moves a named section from "have" to "want" (nil = delete).
func sectionChanges(config, section, typ string, have Section, want map[string]any) []UciChange {
	switch {
	case want == nil && have != nil:
		return []UciChange{{Op: "delete", Config: config, Section: section}}
	case want != nil && have == nil:
		return []UciChange{{Op: "add", Config: config, Type: typ, Name: section, Values: want}}
	case want != nil:
		ch := []UciChange{{Op: "set", Config: config, Section: section, Values: want}}
		var extra []string
		for k := range optionsOf(have) {
			if _, ok := want[k]; !ok {
				extra = append(extra, k)
			}
		}
		if len(extra) > 0 {
			sort.Strings(extra)
			ch = append(ch, UciChange{Op: "delete", Config: config, Section: section, Options: extra})
		}
		return ch
	}
	return nil
}

func preparePolicyDelete(a *App, u *User, raw json.RawMessage) (string, error) {
	var req struct {
		MAC string `json:"mac"`
	}
	if json.Unmarshal(raw, &req) != nil {
		return "", errors.New("请求格式错误")
	}
	hw, err := net.ParseMAC(req.MAC)
	if err != nil {
		return "", errors.New("MAC 无效")
	}
	all, err := a.agent.UciConfig("owpdev")
	if err != nil {
		return "", err
	}
	s := all[policySection(hw.String())]
	if s == nil {
		return "", errors.New("该设备没有管控规则")
	}
	if !a.canTouch(u, "owpdev", policySection(hw.String())) {
		return "", errors.New("只能删除自己创建的管控规则")
	}
	p := policyFromSection(s)
	who := p.Name
	if who == "" {
		who = p.MAC
	}
	return "解除设备管控 " + who, nil
}

func runPolicyDelete(a *App, ac actor, raw json.RawMessage) (any, error) {
	summary, err := preparePolicyDelete(a, ac.user, raw)
	if err != nil {
		return nil, err
	}
	var req struct {
		MAC string `json:"mac"`
	}
	_ = json.Unmarshal(raw, &req)
	hw, _ := net.ParseMAC(req.MAC)
	sec := policySection(hw.String())
	all, _ := a.agent.UciConfig("owpdev")
	if _, err := a.agent.Apply(UciChange{Op: "delete", Config: "owpdev", Section: sec}); err != nil {
		return nil, err
	}
	a.audit(ac, "device.policy.delete", "uci", "owpdev."+sec, summary, all[sec], nil, true)
	return nil, nil
}

// guard: an admin must not cut themselves off the panel via router_port.
func (a *App) policySelfCheck(r *http.Request, raw json.RawMessage) error {
	var p DevicePolicy
	if json.Unmarshal(raw, &p) != nil {
		return nil
	}
	hw, err := net.ParseMAC(p.MAC)
	if err != nil {
		return nil
	}
	mine := a.lanMAC(a.clientIP(r))
	if mine == "" || !strings.EqualFold(mine, hw.String()) {
		return nil
	}
	_, port, _ := net.SplitHostPort(a.cfg.Listen)
	if slices.Contains(p.RouterPorts, port) {
		return errors.New("不能禁止你当前使用的设备访问面板端口")
	}
	return nil
}

func init() {
	registerAction(&Action{Key: "device.policy.save", Label: "设置设备管控（断网 / 名单 / 定时）", Perm: "access.manage", Prepare: preparePolicy, Run: runPolicy,
		Check: func(a *App, r *http.Request, raw json.RawMessage) error { return a.policySelfCheck(r, raw) }})
	registerAction(&Action{Key: "device.policy.delete", Label: "解除设备管控", Perm: "access.manage", Prepare: preparePolicyDelete, Run: runPolicyDelete})
}
