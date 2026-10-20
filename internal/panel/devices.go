package panel

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/wangsirco/wharf/internal/sign"
)

type Device struct {
	MAC         string `json:"mac"`
	IP          string `json:"ip"`
	Hostname    string `json:"hostname"`
	StaticName  string `json:"static_name"`
	LeaseExpiry int64  `json:"lease_expiry"`
	NeighState  string `json:"neigh_state"`
	Online      bool   `json:"online"`
	LastSeen    int64  `json:"last_seen,omitempty"`
	Static      bool   `json:"static"`
	StaticID    string `json:"static_id,omitempty"`
	// panel annotations
	OwnerID   int64  `json:"owner_id,omitempty"`
	OwnerName string `json:"owner_name,omitempty"`
	Editable  bool   `json:"editable"`
	Name      string `json:"name"` // best display name
	Alias     string `json:"alias"`
	Note      string `json:"note"`
	devIdent
	FirstSeen  int64  `json:"first_seen"`
	IsNew      bool   `json:"is_new"`
	Controlled bool   `json:"controlled"`
	Blocked    bool   `json:"blocked"`
	BlockedBy  string `json:"blocked_by"` // manual | schedule
}

// owner returns the panel user that created a router section, 0 if none.
func (a *App) owner(config, section string) int64 {
	var uid int64
	_ = a.db.QueryRow(`SELECT user_id FROM owned WHERE config=? AND section=?`, config, section).Scan(&uid)
	return uid
}

// canTouch: super admins may change anything; admins only objects they own.
func (a *App) canTouch(u *User, config, section string) bool {
	return u.Role == RoleSuper || (section != "" && a.owner(config, section) == u.ID)
}

// GET /api/devices
func (a *App) handleDevices(w http.ResponseWriter, r *http.Request) {
	var list []Device
	if err := a.agent.Do("GET", "/v1/devices", nil, &list); err != nil {
		jsonErr(w, 502, err.Error())
		return
	}
	u := currentUser(r)
	names := map[int64]string{}
	if rows, err := a.db.Query(`SELECT id, display_name FROM users`); err == nil {
		for rows.Next() {
			var id int64
			var n string
			if rows.Scan(&id, &n) == nil {
				names[id] = n
			}
		}
		rows.Close()
	}
	metas := a.deviceMetas()
	first := map[string]int64{}
	if rows, err := a.db.Query(`SELECT mac, first_seen FROM devices_seen`); err == nil {
		for rows.Next() {
			var m string
			var t int64
			if rows.Scan(&m, &t) == nil {
				first[m] = t
			}
		}
		rows.Close()
	}
	var pst agentPolicyStatus
	_ = a.agent.Do("GET", "/v1/policy/status", nil, &pst)
	newSince := a.newSince()
	for i := range list {
		d := &list[i]
		meta := metas[d.MAC]
		d.Alias, d.Note = meta.Alias, meta.Note
		d.devIdent = a.identifyDevice(d.MAC, firstNonEmpty(d.StaticName, d.Hostname), meta.Type)
		d.Name = displayName(d.Alias, d.StaticName, d.Hostname, d.devIdent)
		d.FirstSeen = first[d.MAC]
		d.IsNew = d.FirstSeen > newSince
		if st, ok := pst[d.MAC]; ok {
			d.Controlled, d.Blocked, d.BlockedBy = true, st.Blocked, st.Reason
		}
		if d.StaticID != "" {
			d.OwnerID = a.owner("dhcp", d.StaticID)
			d.OwnerName = names[d.OwnerID]
			d.Editable = u.Can("devices.manage") && a.canTouch(u, "dhcp", d.StaticID)
		} else {
			d.Editable = u.Can("devices.manage")
		}
	}
	writeJSON(w, 200, list)
}

// ---- static host (DHCP reservation) actions ----

var hostnameRe = regexp.MustCompile(`^[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?$`)

type staticHostReq struct {
	Section string `json:"section"` // empty = create
	MAC     string `json:"mac"`
	IP      string `json:"ip"`
	Name    string `json:"name"`
}

func (a *App) countOwned(u *User, config, kind string) (int, error) {
	all, err := a.agent.UciConfig(config)
	if err != nil {
		return 0, err
	}
	rows, err := a.db.Query(`SELECT section FROM owned WHERE config=? AND kind=? AND user_id=?`, config, kind, u.ID)
	if err != nil {
		return 0, err
	}
	defer rows.Close()
	n := 0
	for rows.Next() {
		var s string
		if rows.Scan(&s) == nil && all[s] != nil {
			n++
		}
	}
	return n, nil
}

func prepareStaticHost(a *App, u *User, raw json.RawMessage) (string, error) {
	var req staticHostReq
	if err := json.Unmarshal(raw, &req); err != nil {
		return "", errors.New("请求格式错误")
	}
	hw, err := net.ParseMAC(req.MAC)
	if err != nil || len(hw) != 6 {
		return "", errors.New("MAC 地址无效")
	}
	ip := net.ParseIP(req.IP).To4()
	if ip == nil || !ip.IsPrivate() {
		return "", errors.New("IP 必须是内网 IPv4 地址")
	}
	if !hostnameRe.MatchString(req.Name) {
		return "", errors.New("名称只能包含字母、数字和 -，最长 63 位")
	}
	all, err := a.agent.UciConfig("dhcp")
	if err != nil {
		return "", err
	}
	if req.Section != "" {
		s := all[req.Section]
		if s == nil || s[".type"] != "host" {
			return "", errors.New("静态绑定不存在")
		}
		// anonymous section ids can shift; make sure it is still the same host
		if !strings.EqualFold(optStr(s, "mac"), hw.String()) {
			return "", errors.New("该静态绑定在路由器上已变化，请刷新后重试")
		}
		if !a.canTouch(u, "dhcp", req.Section) {
			return "", errors.New("只能修改自己创建的静态绑定")
		}
	} else if q := u.Quota("max_static_hosts"); q >= 0 {
		n, err := a.countOwned(u, "dhcp", "static_host")
		if err != nil {
			return "", err
		}
		if n >= q {
			return "", fmt.Errorf("已达到静态绑定上限（%d 条）", q)
		}
	}
	for id, s := range all {
		if s[".type"] != "host" || id == req.Section {
			continue
		}
		if strings.EqualFold(optStr(s, "mac"), hw.String()) {
			return "", errors.New("该 MAC 已有静态绑定")
		}
		if optStr(s, "ip") == ip.String() {
			return "", errors.New("该 IP 已被其他设备绑定")
		}
	}
	return staticHostSummary(req.Section, hw.String(), ip.String(), req.Name), nil
}

func runStaticHost(a *App, ac actor, raw json.RawMessage) (any, error) {
	var req staticHostReq
	_ = json.Unmarshal(raw, &req)
	hw, _ := net.ParseMAC(req.MAC)
	values := map[string]any{"name": req.Name, "mac": hw.String(), "ip": net.ParseIP(req.IP).To4().String()}
	ch := UciChange{Op: "set", Config: "dhcp", Section: req.Section, Values: values}
	if req.Section == "" {
		ch = UciChange{Op: "add", Config: "dhcp", Type: "host", Name: "owph_" + sign.RandomHex(4), Values: values}
	}
	res, err := a.agent.Apply(ch)
	if err != nil {
		return nil, err
	}
	sec := res[0].Section
	if req.Section == "" {
		_, _ = a.db.Exec(`INSERT OR REPLACE INTO owned(config, section, kind, user_id, created_at) VALUES('dhcp',?,?,?,?)`,
			sec, "static_host", ac.user.ID, time.Now().Unix())
	}
	summary := staticHostSummary(req.Section, values["mac"].(string), values["ip"].(string), req.Name)
	a.audit(ac, "device.static.save", "uci", "dhcp."+sec, summary, res[0].Before, res[0].After, true)
	return map[string]string{"section": sec}, nil
}

func staticHostSummary(section, mac, ip, name string) string {
	verb := "新增"
	if section != "" {
		verb = "修改"
	}
	return fmt.Sprintf("%s静态绑定 %s → %s（%s）", verb, mac, ip, name)
}

type sectionReq struct {
	Section string `json:"section"`
	MAC     string `json:"mac"`
}

func prepareStaticDelete(a *App, u *User, raw json.RawMessage) (string, error) {
	var req sectionReq
	if json.Unmarshal(raw, &req) != nil || req.Section == "" {
		return "", errors.New("请求格式错误")
	}
	all, err := a.agent.UciConfig("dhcp")
	if err != nil {
		return "", err
	}
	s := all[req.Section]
	if s == nil || s[".type"] != "host" {
		return "", errors.New("静态绑定不存在")
	}
	if !strings.EqualFold(optStr(s, "mac"), req.MAC) {
		return "", errors.New("该静态绑定在路由器上已变化，请刷新后重试")
	}
	if !a.canTouch(u, "dhcp", req.Section) {
		return "", errors.New("只能删除自己创建的静态绑定")
	}
	return fmt.Sprintf("删除静态绑定 %v → %v（%v）", s["mac"], s["ip"], s["name"]), nil
}

func runStaticDelete(a *App, ac actor, raw json.RawMessage) (any, error) {
	var req sectionReq
	_ = json.Unmarshal(raw, &req)
	summary, err := prepareStaticDelete(a, ac.user, raw)
	if err != nil {
		return nil, err
	}
	res, err := a.agent.Apply(UciChange{Op: "delete", Config: "dhcp", Section: req.Section})
	if err != nil {
		return nil, err
	}
	a.audit(ac, "device.static.delete", "uci", "dhcp."+req.Section, summary, res[0].Before, nil, true)
	return nil, nil
}

func init() {
	registerAction(&Action{Key: "device.static.save", Label: "新增/修改静态绑定", Perm: "devices.manage", Prepare: prepareStaticHost, Run: runStaticHost})
	registerAction(&Action{Key: "device.static.delete", Label: "删除静态绑定", Perm: "devices.manage", Prepare: prepareStaticDelete, Run: runStaticDelete})
}
