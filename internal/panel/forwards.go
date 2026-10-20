package panel

import (
	"crypto/sha1"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/bits"
	"net"
	"net/http"
	"net/netip"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/wangsirco/wharf/internal/sign"
)

// A port forward is three uci sections that share one id:
//
//	firewall.<id>          redirect  (standard fw3 options only; name = structured comment)
//	firewall.owps_<sfx>    ipset     (only when the source is restricted)
//	owpfwd.<id>            forward   (panel metadata: owner, device, note, allow/deny spec)
//
// Metadata lives in its own config so saving a forward does not trigger the owp service reload.
//
// Forwards created by the panel use named sections "owpr_<hex>" so ids never shift.

type Forward struct {
	ID         string   `json:"id"`
	Rev        string   `json:"rev"` // content fingerprint, guards against editing a shifted anonymous section
	Name       string   `json:"name"`
	Proto      string   `json:"proto"`
	WanPort    string   `json:"wan_port"`
	Wan        string   `json:"wan"` // WAN interface the forward is bound to; "" = every WAN
	LanIP      string   `json:"lan_ip"`
	LanPort    string   `json:"lan_port"`
	Enabled    bool     `json:"enabled"`
	Managed    bool     `json:"managed"`
	DeviceName string   `json:"device_name"`
	DeviceNow  string   `json:"device_now,omitempty"` // the device's current display name (alias may have changed)
	VMTag      string   `json:"vm_tag,omitempty"`
	Online     *bool    `json:"online,omitempty"`
	DeviceMAC  string   `json:"device_mac"`
	Note       string   `json:"note"`
	Mode       string   `json:"mode"` // all | restrict
	Regions    []string `json:"regions"`
	Allow      []string `json:"allow"`
	Deny       []string `json:"deny"`
	OwnerID    int64    `json:"owner_id"`
	OwnerName  string   `json:"owner_name"`
	Editable   bool     `json:"editable"`
	Created    int64    `json:"created"`
}

func optStr(s Section, k string) string {
	switch v := s[k].(type) {
	case string:
		return v
	case []any:
		var p []string
		for _, x := range v {
			p = append(p, fmt.Sprint(x))
		}
		return strings.Join(p, " ")
	}
	return ""
}

func optList(s Section, k string) []string {
	switch v := s[k].(type) {
	case string:
		return strings.Fields(v)
	case []any:
		out := []string{}
		for _, x := range v {
			out = append(out, fmt.Sprint(x))
		}
		return out
	}
	return []string{}
}

func sectionRev(s Section) string {
	h := sha1.Sum([]byte(mustJSON(optionsOf(s))))
	return hex.EncodeToString(h[:6])
}

func setSuffix(id string) string    { return strings.TrimPrefix(id, "owpr_") }
func ipsetSection(id string) string { return "owps_" + setSuffix(id) }
func ipsetName(id string) string    { return "owp_" + setSuffix(id) }

func isWanRedirect(s Section) bool {
	if s[".type"] != "redirect" || optStr(s, "src") != "wan" {
		return false
	}
	t := optStr(s, "target")
	return t == "" || t == "DNAT"
}

func normProto(p string) string {
	p = strings.ToLower(strings.TrimSpace(p))
	switch p {
	case "", "tcpudp", "tcp udp", "all":
		return "tcp udp"
	}
	return p
}

type fwState struct {
	fw  map[string]Section
	owp map[string]Section
}

func (a *App) loadFwState() (*fwState, error) {
	fw, err := a.agent.UciConfig("firewall")
	if err != nil {
		return nil, err
	}
	owp, err := a.agent.UciConfig("owpfwd")
	if err != nil {
		owp = map[string]Section{}
	}
	return &fwState{fw, owp}, nil
}

func (st *fwState) forward(id string) *Forward {
	r := st.fw[id]
	if r == nil || !isWanRedirect(r) {
		return nil
	}
	f := &Forward{
		ID: id, Rev: sectionRev(r), Name: optStr(r, "name"), Proto: normProto(optStr(r, "proto")),
		WanPort: optStr(r, "src_dport"), LanIP: optStr(r, "dest_ip"), LanPort: optStr(r, "dest_port"),
		Enabled: optStr(r, "enabled") != "0", Mode: "all", Regions: []string{}, Allow: []string{}, Deny: []string{},
	}
	if f.LanPort == "" {
		f.LanPort = f.WanPort
	}
	if m := st.owp[id]; m != nil && m[".type"] == "forward" {
		f.Managed = true
		f.DeviceName, f.DeviceMAC, f.Note, f.Wan = optStr(m, "device"), optStr(m, "mac"), optStr(m, "note"), optStr(m, "wan")
		if optStr(m, "mode") == "restrict" {
			f.Mode = "restrict"
		}
		f.Regions, f.Allow, f.Deny = optList(m, "region"), optList(m, "allow"), optList(m, "deny")
		f.Created, _ = strconv.ParseInt(optStr(m, "created"), 10, 64)
	}
	return f
}

// GET /api/forwards
func (a *App) handleForwards(w http.ResponseWriter, r *http.Request) {
	st, err := a.loadFwState()
	if err != nil {
		jsonErr(w, 502, err.Error())
		return
	}
	u := currentUser(r)
	names := a.userNames()
	// current names of the target devices, by MAC and by IP
	type devNow struct {
		name, tag string
		online    bool
	}
	byMAC, byIP := map[string]devNow{}, map[string]devNow{}
	var devs []Device
	if a.agent.Do("GET", "/v1/devices", nil, &devs) == nil {
		metas := a.deviceMetas()
		for _, d := range devs {
			id := a.identifyDevice(d.MAC, firstNonEmpty(d.StaticName, d.Hostname), metas[d.MAC].Type)
			v := devNow{displayName(metas[d.MAC].Alias, d.StaticName, d.Hostname, id), id.VMTag, d.Online}
			byMAC[d.MAC] = v
			if d.IP != "" {
				byIP[d.IP] = v
			}
		}
	}
	out := []*Forward{}
	for id := range st.fw {
		f := st.forward(id)
		if f == nil {
			continue
		}
		f.OwnerID = a.owner("firewall", id)
		if u.Role != RoleSuper && f.OwnerID != u.ID {
			continue
		}
		f.OwnerName = names[f.OwnerID]
		v, ok := byMAC[strings.ToLower(f.DeviceMAC)]
		if !ok {
			v, ok = byIP[f.LanIP]
		}
		if ok {
			f.DeviceNow, f.VMTag = v.name, v.tag
			f.Online = &v.online
		}
		f.Editable = u.Can("forwards.manage") && a.canTouch(u, "firewall", id)
		out = append(out, f)
	}
	sort.Slice(out, func(i, j int) bool { return portNum(out[i].WanPort) < portNum(out[j].WanPort) })
	quota := u.Quota("max_forwards")
	used := 0
	for _, f := range out {
		if f.OwnerID == u.ID {
			used++
		}
	}
	writeJSON(w, 200, map[string]any{"items": out, "quota": quota, "used": used})
}

func (a *App) userNames() map[int64]string {
	names := map[int64]string{}
	rows, err := a.db.Query(`SELECT id, display_name FROM users`)
	if err != nil {
		return names
	}
	defer rows.Close()
	for rows.Next() {
		var id int64
		var n string
		if rows.Scan(&id, &n) == nil {
			names[id] = n
		}
	}
	return names
}

func portNum(p string) int {
	lo, _, _ := portRange(p)
	return lo
}

// portRange parses "443", "8000-8010" or "8000:8010".
func portRange(p string) (int, int, bool) {
	p = strings.TrimSpace(p)
	if p == "" {
		return 0, 0, false
	}
	lo, hi, found := strings.Cut(strings.ReplaceAll(p, ":", "-"), "-")
	a, err1 := strconv.Atoi(lo)
	b := a
	var err2 error
	if found {
		b, err2 = strconv.Atoi(hi)
	}
	if err1 != nil || err2 != nil || a < 1 || b > 65535 || a > b {
		return 0, 0, false
	}
	return a, b, true
}

func protoOverlap(a, b string) bool {
	for _, x := range strings.Fields(normProto(a)) {
		if slices.Contains(strings.Fields(normProto(b)), x) {
			return true
		}
	}
	return false
}

// GET /api/forwards/targets — LAN devices a forward can point at, named the same way
// as on the device pages (alias, DHCP name, hypervisor guest name, vendor + type).
func (a *App) handleForwardTargets(w http.ResponseWriter, r *http.Request) {
	var list []Device
	if err := a.agent.Do("GET", "/v1/devices", nil, &list); err != nil {
		jsonErr(w, 502, err.Error())
		return
	}
	type target struct {
		IP       string `json:"ip"`
		MAC      string `json:"mac"`
		Name     string `json:"name"`
		Hostname string `json:"hostname,omitempty"`
		Type     string `json:"type"`
		Vendor   string `json:"vendor,omitempty"`
		VMTag    string `json:"vm_tag,omitempty"`
		Note     string `json:"note,omitempty"`
		Online   bool   `json:"online"`
		Static   bool   `json:"static"`
	}
	metas := a.deviceMetas()
	out := []target{}
	for _, d := range list {
		if d.IP == "" {
			continue
		}
		m := metas[d.MAC]
		id := a.identifyDevice(d.MAC, firstNonEmpty(d.StaticName, d.Hostname), m.Type)
		out = append(out, target{IP: d.IP, MAC: d.MAC, Name: displayName(m.Alias, d.StaticName, d.Hostname, id),
			Hostname: firstNonEmpty(d.StaticName, d.Hostname), Type: id.Type, Vendor: id.Vendor, VMTag: id.VMTag,
			Note: m.Note, Online: d.Online, Static: d.Static})
	}
	writeJSON(w, 200, out)
}

// GET /api/geo/regions
func (a *App) handleRegions(w http.ResponseWriter, r *http.Request) {
	rs, err := a.geo.Regions()
	if err != nil {
		jsonErr(w, 503, err.Error())
		return
	}
	writeJSON(w, 200, rs)
}

// ---- save ----

type forwardReq struct {
	ID         string   `json:"id"`  // empty = create
	Rev        string   `json:"rev"` // required for edits
	LanIP      string   `json:"lan_ip"`
	DeviceMAC  string   `json:"device_mac"`
	DeviceName string   `json:"device_name"`
	LanPort    string   `json:"lan_port"`
	WanPort    string   `json:"wan_port"`
	Wan        string   `json:"wan"`
	Proto      string   `json:"proto"`
	Note       string   `json:"note"`
	Enabled    bool     `json:"enabled"`
	Mode       string   `json:"mode"`
	Regions    []string `json:"regions"`
	Allow      []string `json:"allow"`
	Deny       []string `json:"deny"`
}

// clean normalizes free text (names, notes): control characters become spaces, runs of
// whitespace collapse, length is capped. Quotes are kept — "Chloe's iPhone" is a normal
// name, and uci / fw3 escape them correctly (verified with fw3 print).
func clean(s string, n int) string {
	s = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return ' '
		}
		return r
	}, s)
	return truncate(strings.Join(strings.Fields(s), " "), n)
}

// commentField is clean() for one field of the fw3 comment, where "|" separates fields.
func commentField(s string, n int) string { return clean(strings.ReplaceAll(s, "|", "/"), n) }

// fwdComment builds the fw3 "name": OWP|uid=2|user=alice|dev=NAS|192.168.1.88:80>wan:443/tcp|note=...
// User name and id are separate fields because names can be long; total kept under ~200 bytes.
func fwdComment(uid int64, user, dev, lanIP, lanPort, wan, wanPort, proto, note string) string {
	p := strings.ReplaceAll(normProto(proto), " ", "+")
	head := fmt.Sprintf("OWP|uid=%d|user=%s|dev=%s|%s:%s>%s:%s/%s", uid, commentField(user, 24), commentField(dev, 32), lanIP, lanPort, firstNonEmpty(wan, "wan"), wanPort, p)
	if note = commentField(note, 64); note != "" {
		for len(head)+len("|note=")+len(note) > 200 && note != "" {
			note = truncate(note, len([]rune(note))-1)
		}
		if note != "" {
			head += "|note=" + note
		}
	}
	return head
}

func (req *forwardReq) normalize() error {
	req.Proto = normProto(req.Proto)
	if req.Wan != "" && !ifaceRe.MatchString(req.Wan) {
		return errors.New("WAN 接口名无效")
	}
	if req.Proto != "tcp" && req.Proto != "udp" && req.Proto != "tcp udp" {
		return errors.New("协议只能是 TCP、UDP 或 TCP+UDP")
	}
	if _, _, ok := portRange(req.WanPort); !ok || strings.ContainsAny(req.WanPort, "-:") {
		return errors.New("WAN 端口必须是 1-65535 的单个端口")
	}
	if _, _, ok := portRange(req.LanPort); !ok || strings.ContainsAny(req.LanPort, "-:") {
		return errors.New("内网端口必须是 1-65535 的单个端口")
	}
	ip := net.ParseIP(req.LanIP).To4()
	if ip == nil || !ip.IsPrivate() {
		return errors.New("目标必须是内网 IPv4 设备")
	}
	req.LanIP = ip.String()
	if req.DeviceMAC != "" {
		hw, err := net.ParseMAC(req.DeviceMAC)
		if err != nil {
			return errors.New("设备 MAC 无效")
		}
		req.DeviceMAC = hw.String()
	}
	req.DeviceName = clean(req.DeviceName, 32)
	req.Note = clean(req.Note, 64)
	if req.Mode != "all" && req.Mode != "restrict" {
		return errors.New("无效的来源限制模式")
	}
	for _, k := range req.Regions {
		if !validRegionKey(k) {
			return fmt.Errorf("无效地区：%s", k)
		}
	}
	for _, l := range [][]string{req.Allow, req.Deny} {
		ps, err := parsePrefixes(l)
		if err != nil {
			return err
		}
		for _, p := range ps {
			if !p.Addr().Is4() {
				return errors.New("暂只支持 IPv4 地址 / 网段")
			}
		}
	}
	if req.Mode == "restrict" && len(req.Regions)+len(req.Allow) == 0 {
		return errors.New("「仅允许指定来源」至少需要选择一个地区或填写一个 IP 段")
	}
	if req.Mode == "all" {
		req.Regions, req.Allow = []string{}, []string{}
	}
	if req.Regions == nil {
		req.Regions = []string{}
	}
	if req.Allow == nil {
		req.Allow = []string{}
	}
	if req.Deny == nil {
		req.Deny = []string{}
	}
	return nil
}

func prepareForward(a *App, u *User, raw json.RawMessage) (string, error) {
	var req forwardReq
	if json.Unmarshal(raw, &req) != nil {
		return "", errors.New("请求格式错误")
	}
	if err := req.normalize(); err != nil {
		return "", err
	}
	st, err := a.loadFwState()
	if err != nil {
		return "", err
	}
	if req.ID != "" {
		f := st.forward(req.ID)
		if f == nil {
			return "", errors.New("端口转发不存在")
		}
		if f.Rev != req.Rev {
			return "", errors.New("该规则在路由器上已被修改，请刷新后重试")
		}
		if !a.canTouch(u, "firewall", req.ID) {
			return "", errors.New("只能修改自己创建的端口转发")
		}
	} else if q := u.Quota("max_forwards"); q >= 0 {
		n := 0
		for id := range st.fw {
			if st.forward(id) != nil && a.owner("firewall", id) == u.ID {
				n++
			}
		}
		if n >= q {
			return "", fmt.Errorf("已达到端口转发上限（%d 条）", q)
		}
	}
	// grants, conflicts with other forwards (enabled or not), the panel's own port
	wp, _ := strconv.Atoi(req.WanPort)
	if err := firstError(a.forwardIssues(u, st, a.wans(), nil, req.ID, req.Wan, wp, req.Proto, req.LanIP)); err != nil {
		return "", err
	}
	return forwardSummary(req), nil
}

func forwardSummary(req forwardReq) string {
	verb := "新增"
	if req.ID != "" {
		verb = "修改"
	}
	src := "所有人"
	if req.Mode == "restrict" {
		src = "仅 " + strings.Join(append(append([]string{}, req.Regions...), req.Allow...), "、")
	}
	if len(req.Deny) > 0 {
		src += "，拉黑 " + strings.Join(req.Deny, "、")
	}
	dev := req.DeviceName
	if dev == "" {
		dev = req.LanIP
	}
	wan := "WAN"
	if req.Wan != "" {
		wan = req.Wan
	}
	return fmt.Sprintf("%s端口转发 %s %s:%s → %s %s/%s（%s）", verb, dev, req.LanIP, req.LanPort, wan, req.WanPort,
		strings.ReplaceAll(req.Proto, " ", "+"), src)
}

func forwardNeedsApproval(a *App, raw json.RawMessage) bool {
	var req forwardReq
	_ = json.Unmarshal(raw, &req)
	return req.Mode == "all" && a.setting("approval.forward_open_all") == "1"
}

// setEntries computes the ipset contents and redirect match for a spec.
// Returns (entries, match) where match is "", "<set>" or "!<set>".
func (a *App) setEntries(id string, mode string, regions, allow, deny []string) ([]string, string, error) {
	denyP, _ := parsePrefixes(deny)
	if mode == "restrict" {
		allowP, _ := parsePrefixes(allow)
		if len(regions) > 0 {
			sets, err := a.geo.RegionSets(regions)
			if err != nil {
				return nil, "", err
			}
			for _, k := range regions {
				ps, _ := parsePrefixes(sets[k])
				allowP = append(allowP, ps...)
			}
		}
		// blacklist always wins: subtract deny ranges from the allowed ranges
		out := subtractPrefixes(mergePrefixes(allowP), denyP)
		ss := make([]string, len(out))
		for i, p := range out {
			ss[i] = p.String()
		}
		return ss, ipsetName(id), nil
	}
	if len(denyP) == 0 {
		return nil, "", nil
	}
	out := mergePrefixes(denyP)
	ss := make([]string, len(out))
	for i, p := range out {
		ss[i] = p.String()
	}
	return ss, "!" + ipsetName(id), nil
}

// subtractPrefixes returns allow minus deny (IPv4).
func subtractPrefixes(allow, deny []netip.Prefix) []netip.Prefix {
	if len(deny) == 0 {
		return allow
	}
	type rng struct{ lo, hi uint64 }
	toR := func(p netip.Prefix) rng {
		a4 := p.Masked().Addr().As4()
		lo := uint64(binary.BigEndian.Uint32(a4[:]))
		return rng{lo, lo + (1 << (32 - p.Bits())) - 1}
	}
	d := make([]rng, 0, len(deny))
	for _, p := range mergePrefixes(deny) {
		d = append(d, toR(p))
	}
	var keep []netip.Prefix
	for _, p := range allow {
		parts := []rng{toR(p)}
		for _, dr := range d {
			var next []rng
			for _, r := range parts {
				if dr.hi < r.lo || dr.lo > r.hi {
					next = append(next, r)
					continue
				}
				if dr.lo > r.lo {
					next = append(next, rng{r.lo, dr.lo - 1})
				}
				if dr.hi < r.hi {
					next = append(next, rng{dr.hi + 1, r.hi})
				}
			}
			parts = next
		}
		for _, r := range parts {
			keep = append(keep, rangeToPrefixes(r.lo, r.hi)...)
		}
	}
	return mergePrefixes(keep)
}

// rangeToPrefixes splits [lo, hi] into the minimal list of aligned CIDR blocks.
func rangeToPrefixes(lo, hi uint64) []netip.Prefix {
	var out []netip.Prefix
	for lo <= hi {
		size := 32
		if lo != 0 {
			size = min(32, bits.TrailingZeros64(lo))
		}
		for size > 0 && lo+(1<<size)-1 > hi {
			size--
		}
		var b [4]byte
		binary.BigEndian.PutUint32(b[:], uint32(lo))
		out = append(out, netip.PrefixFrom(netip.AddrFrom4(b), 32-size))
		lo += 1 << size
	}
	return out
}

type fwdSnap struct {
	Redirect Section `json:"redirect"`
	IPSet    Section `json:"ipset"`
	Meta     Section `json:"meta"`
}

func (st *fwState) snap(id string) fwdSnap {
	return fwdSnap{Redirect: st.fw[id], IPSet: st.fw[ipsetSection(id)], Meta: st.owp[id]}
}

// applyForward moves the three sections of a forward from their current state to the desired state.
func (a *App) applyForward(id string, cur fwdSnap, redirect, ipset, meta map[string]any, setMatch string, entries []string) error {
	var changes []UciChange
	add := func(config, section, typ string, have Section, want map[string]any) {
		switch {
		case want == nil && have != nil:
			changes = append(changes, UciChange{Op: "delete", Config: config, Section: section})
		case want != nil && have == nil:
			changes = append(changes, UciChange{Op: "add", Config: config, Type: typ, Name: section, Values: want})
		case want != nil:
			changes = append(changes, UciChange{Op: "set", Config: config, Section: section, Values: want})
			var extra []string
			for k := range optionsOf(have) {
				if _, ok := want[k]; !ok {
					extra = append(extra, k)
				}
			}
			if len(extra) > 0 {
				sort.Strings(extra)
				changes = append(changes, UciChange{Op: "delete", Config: config, Section: section, Options: extra})
			}
		}
	}
	if ipset != nil {
		var r struct {
			Path string `json:"path"`
		}
		if err := a.agent.Do("POST", "/v1/ipset", map[string]any{"name": ipsetName(id), "entries": entries}, &r); err != nil {
			return err
		}
		ipset["loadfile"] = r.Path
	}
	if redirect != nil && setMatch != "" {
		redirect["ipset"] = setMatch
	}
	add("firewall", ipsetSection(id), "ipset", cur.IPSet, ipset)
	add("firewall", id, "redirect", cur.Redirect, redirect)
	add("owpfwd", id, "forward", cur.Meta, meta)
	if len(changes) == 0 {
		return nil
	}
	if _, err := a.agent.Apply(changes...); err != nil {
		return err
	}
	if ipset == nil && cur.IPSet != nil {
		_ = a.agent.Do("POST", "/v1/ipset", map[string]any{"name": ipsetName(id), "remove": true}, nil)
	}
	return nil
}

func runForward(a *App, ac actor, raw json.RawMessage) (any, error) {
	var req forwardReq
	_ = json.Unmarshal(raw, &req)
	_ = req.normalize()
	st, err := a.loadFwState()
	if err != nil {
		return nil, err
	}
	id := req.ID
	if id == "" {
		id = "owpr_" + sign.RandomHex(4)
	}
	before := st.snap(id)

	ownerID, ownerName := ac.user.ID, ac.user.Username
	if req.ID != "" {
		if o := a.owner("firewall", id); o != 0 {
			if ou, err := a.getUser(o); err == nil {
				ownerID, ownerName = ou.ID, ou.Username
			}
		}
	}

	// start from the existing redirect so options we don't manage (reflection, etc.) survive
	redirect := map[string]any{}
	if before.Redirect != nil {
		for k, v := range optionsOf(before.Redirect) {
			redirect[k] = v
		}
		delete(redirect, "ipset")
	}
	for k, v := range map[string]any{
		"name": fwdComment(ownerID, ownerName, req.DeviceName, req.LanIP, req.LanPort, req.Wan, req.WanPort, req.Proto, req.Note),
		"src":  "wan", "dest": "lan", "target": "DNAT", "proto": req.Proto,
		"src_dport": req.WanPort, "dest_ip": req.LanIP, "dest_port": req.LanPort,
		"enabled": map[bool]string{true: "1", false: "0"}[req.Enabled],
	} {
		redirect[k] = v
	}
	// bind to one WAN with fw3's standard "extra" option (-i <device>); leave foreign extras alone
	if ex := strings.Fields(optStr(redirect, "extra")); len(ex) == 2 && ex[0] == "-i" {
		delete(redirect, "extra")
	}
	if req.Wan != "" {
		dev := ""
		for _, w := range a.wans() {
			if w.Interface == req.Wan {
				dev = w.Device
			}
		}
		if dev == "" {
			return nil, fmt.Errorf("无法确定 WAN 接口 %s 的网卡", req.Wan)
		}
		redirect["extra"] = "-i " + dev
	}
	meta := map[string]any{
		"uid": strconv.FormatInt(ownerID, 10), "user": ownerName, "device": req.DeviceName, "mac": req.DeviceMAC, "wan": req.Wan,
		"note": req.Note, "mode": req.Mode, "region": req.Regions, "allow": req.Allow, "deny": req.Deny,
		"created": strconv.FormatInt(time.Now().Unix(), 10),
	}
	if before.Meta != nil && optStr(before.Meta, "created") != "" {
		meta["created"] = optStr(before.Meta, "created")
	}
	for _, k := range []string{"region", "allow", "deny"} {
		if len(meta[k].([]string)) == 0 {
			delete(meta, k)
		}
	}
	if req.Wan == "" {
		delete(meta, "wan")
	}
	entries, match, err := a.setEntries(id, req.Mode, req.Regions, req.Allow, req.Deny)
	if err != nil {
		return nil, err
	}
	var ipset map[string]any
	if match != "" {
		ipset = map[string]any{"name": ipsetName(id), "match": "src_net", "storage": "hash", "family": "ipv4", "maxelem": "1048576"}
	}
	if err := a.applyForward(id, before, redirect, ipset, meta, match, entries); err != nil {
		return nil, err
	}
	if req.ID == "" {
		_, _ = a.db.Exec(`INSERT OR REPLACE INTO owned(config, section, kind, user_id, created_at) VALUES('firewall',?,?,?,?)`,
			id, "forward", ac.user.ID, time.Now().Unix())
	}
	after, _ := a.loadFwState()
	req.ID = map[bool]string{true: "", false: id}[before.Redirect == nil]
	a.audit(ac, "forward.save", "forward", id, forwardSummary(req), nilIfEmpty(before), nilIfEmpty(after.snap(id)), true)
	return map[string]string{"id": id}, nil
}

func nilIfEmpty(s fwdSnap) any {
	if s.Redirect == nil && s.IPSet == nil && s.Meta == nil {
		return nil
	}
	return s
}

type fwdIDReq struct {
	ID      string `json:"id"`
	Rev     string `json:"rev"`
	Enabled bool   `json:"enabled"`
}

func prepareForwardRef(a *App, u *User, raw json.RawMessage, verb string) (*Forward, error) {
	var req fwdIDReq
	if json.Unmarshal(raw, &req) != nil || req.ID == "" {
		return nil, errors.New("请求格式错误")
	}
	st, err := a.loadFwState()
	if err != nil {
		return nil, err
	}
	f := st.forward(req.ID)
	if f == nil {
		return nil, errors.New("端口转发不存在")
	}
	if f.Rev != req.Rev {
		return nil, errors.New("该规则在路由器上已被修改，请刷新后重试")
	}
	if !a.canTouch(u, "firewall", req.ID) {
		return nil, fmt.Errorf("只能%s自己创建的端口转发", verb)
	}
	return f, nil
}

func describe(f *Forward) string {
	n := f.DeviceName
	if n == "" {
		n = f.Name
	}
	return fmt.Sprintf("%s %s:%s → WAN %s", n, f.LanIP, f.LanPort, f.WanPort)
}

func prepareForwardDelete(a *App, u *User, raw json.RawMessage) (string, error) {
	f, err := prepareForwardRef(a, u, raw, "删除")
	if err != nil {
		return "", err
	}
	return "删除端口转发 " + describe(f), nil
}

func runForwardDelete(a *App, ac actor, raw json.RawMessage) (any, error) {
	var req fwdIDReq
	_ = json.Unmarshal(raw, &req)
	st, err := a.loadFwState()
	if err != nil {
		return nil, err
	}
	before := st.snap(req.ID)
	f := st.forward(req.ID)
	if err := a.applyForward(req.ID, before, nil, nil, nil, "", nil); err != nil {
		return nil, err
	}
	a.audit(ac, "forward.delete", "forward", req.ID, "删除端口转发 "+describe(f), before, nil, true)
	return nil, nil
}

func prepareForwardToggle(a *App, u *User, raw json.RawMessage) (string, error) {
	f, err := prepareForwardRef(a, u, raw, "启停")
	if err != nil {
		return "", err
	}
	var req fwdIDReq
	_ = json.Unmarshal(raw, &req)
	return map[bool]string{true: "启用", false: "停用"}[req.Enabled] + "端口转发 " + describe(f), nil
}

func runForwardToggle(a *App, ac actor, raw json.RawMessage) (any, error) {
	var req fwdIDReq
	_ = json.Unmarshal(raw, &req)
	summary, err := prepareForwardToggle(a, ac.user, raw)
	if err != nil {
		return nil, err
	}
	st, err := a.loadFwState()
	if err != nil {
		return nil, err
	}
	before := st.snap(req.ID)
	if _, err := a.agent.Apply(UciChange{Op: "set", Config: "firewall", Section: req.ID,
		Values: map[string]any{"enabled": map[bool]string{true: "1", false: "0"}[req.Enabled]}}); err != nil {
		return nil, err
	}
	after, _ := a.loadFwState()
	a.audit(ac, "forward.toggle", "forward", req.ID, summary, before, after.snap(req.ID), true)
	return nil, nil
}

// restoreForward brings all three sections back to the audit entry's "before" state.
func (a *App) restoreForward(ac actor, e *AuditEntry, force bool) (string, error) {
	id := e.TargetID
	var before, after fwdSnap
	_ = json.Unmarshal(e.Before, &before)
	_ = json.Unmarshal(e.After, &after)
	st, err := a.loadFwState()
	if err != nil {
		return "", err
	}
	cur := st.snap(id)
	if !force && !(sameSection(cur.Redirect, after.Redirect) && sameSection(cur.Meta, after.Meta)) {
		return "路由器上的当前配置与该记录修改后的值不一致", nil
	}
	if before.Redirect == nil && cur.Redirect == nil {
		return "", errors.New("该端口转发已不存在，无需还原")
	}
	var redirect, ipset, meta map[string]any
	var entries []string
	match := ""
	if before.Redirect != nil {
		redirect = optionsOf(before.Redirect)
		delete(redirect, "ipset")
	}
	if before.Meta != nil {
		meta = optionsOf(before.Meta)
	}
	if before.IPSet != nil {
		ipset = optionsOf(before.IPSet)
		mode := optStr(before.Meta, "mode")
		entries, match, err = a.setEntries(id, mode, optList(before.Meta, "region"), optList(before.Meta, "allow"), optList(before.Meta, "deny"))
		if err != nil {
			return "", err
		}
		if match == "" { // spec no longer needs a set; keep the redirect's original match anyway
			match = optStr(before.Redirect, "ipset")
		}
	}
	if err := a.applyForward(id, cur, redirect, ipset, meta, match, entries); err != nil {
		return "", err
	}
	now, _ := a.loadFwState()
	a.audit(ac, "forward.restore", "forward", id, fmt.Sprintf("还原端口转发 %s（审计 #%d）", id, e.ID), nilIfEmpty(cur), nilIfEmpty(now.snap(id)), true)
	return "", nil
}

func init() {
	registerAction(&Action{Key: "forward.save", Label: "新增/修改端口转发", Perm: "forwards.manage",
		Prepare: prepareForward, Run: runForward, NeedsApproval: forwardNeedsApproval})
	registerAction(&Action{Key: "forward.toggle", Label: "启用/停用端口转发", Perm: "forwards.manage",
		Prepare: prepareForwardToggle, Run: runForwardToggle})
	registerAction(&Action{Key: "forward.delete", Label: "删除端口转发", Perm: "forwards.manage",
		Prepare: prepareForwardDelete, Run: runForwardDelete})
}
