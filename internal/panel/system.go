package panel

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/wangsirco/wharf/internal/sign"
)

// System maintenance and small tools. Router-changing operations are actions:
// normal admins with system.manage always go through super-admin approval.

func always(*App, json.RawMessage) bool { return true }

// GET /api/system/hw — CPU / temperature / disks plus the basic system info.
func (a *App) handleSystemHW(w http.ResponseWriter, r *http.Request) {
	var hw, sys json.RawMessage
	if err := a.agent.Do("GET", "/v1/sys/hw", nil, &hw); err != nil {
		jsonErr(w, 502, err.Error())
		return
	}
	_ = a.agent.Do("GET", "/v1/system", nil, &sys)
	writeJSON(w, 200, map[string]any{"hw": hw, "system": sys})
}

// GET /api/system/services
func (a *App) handleServices(w http.ResponseWriter, r *http.Request) {
	var out json.RawMessage
	if err := a.agent.Do("GET", "/v1/sys/services", nil, &out); err != nil {
		jsonErr(w, 502, err.Error())
		return
	}
	writeJSON(w, 200, out)
}

// GET /api/system/log?source=system|kernel&lines=&q=
func (a *App) handleSystemLog(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	var out json.RawMessage
	path := fmt.Sprintf("/v1/sys/log?source=%s&lines=%s&q=%s", url.QueryEscape(q.Get("source")), url.QueryEscape(q.Get("lines")), url.QueryEscape(q.Get("q")))
	if err := a.agent.Do("GET", path, nil, &out); err != nil {
		jsonErr(w, 502, err.Error())
		return
	}
	writeJSON(w, 200, out)
}

// GET /api/system/reboot-schedule
func (a *App) handleRebootSchedule(w http.ResponseWriter, r *http.Request) {
	var out json.RawMessage
	if err := a.agent.Do("GET", "/v1/sys/reboot-schedule", nil, &out); err != nil {
		jsonErr(w, 502, err.Error())
		return
	}
	writeJSON(w, 200, out)
}

// GET /api/system/backup — super only; the archive holds every secret on the router.
func (a *App) handleBackup(w http.ResponseWriter, r *http.Request) {
	var out struct {
		Name string `json:"name"`
		Data []byte `json:"data"`
	}
	if err := a.agent.Do("GET", "/v1/sys/backup", nil, &out); err != nil {
		jsonErr(w, 502, err.Error())
		return
	}
	a.audit(actor{user: currentUser(r), ip: a.clientIP(r)}, "system.backup", "system", "backup",
		fmt.Sprintf("下载配置备份（%d KB）", len(out.Data)/1024), nil, nil, false)
	w.Header().Set("Content-Type", "application/gzip")
	w.Header().Set("Content-Disposition", `attachment; filename="`+out.Name+`"`)
	_, _ = w.Write(out.Data)
}

// POST /api/system/restore {data: base64, check: bool} — super only. check=true
// only lists what would be restored; otherwise the router restores and reboots.
func (a *App) handleRestore(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Data  string `json:"data"`
		Check bool   `json:"check"`
		Name  string `json:"name"`
	}
	if json.NewDecoder(io.LimitReader(r.Body, 60<<20)).Decode(&req) != nil || req.Data == "" {
		jsonErr(w, 400, "请选择备份文件（不超过 40 MB）")
		return
	}
	if _, err := base64.StdEncoding.DecodeString(req.Data); err != nil {
		jsonErr(w, 400, "文件编码错误")
		return
	}
	action := "apply"
	if req.Check {
		action = "check"
	}
	var out struct {
		Files []string `json:"files"`
	}
	if err := a.agent.Do("POST", "/v1/sys/restore", map[string]string{"action": action, "data": req.Data}, &out); err != nil {
		var ae *AgentError
		if errors.As(err, &ae) {
			jsonErr(w, 400, ae.Msg)
			return
		}
		jsonErr(w, 502, err.Error())
		return
	}
	if !req.Check {
		a.audit(actor{user: currentUser(r), ip: a.clientIP(r)}, "system.restore", "system", "restore",
			fmt.Sprintf("从备份 %s 恢复配置（%d 个文件）并重启", clean(req.Name, 80), len(out.Files)), nil, out.Files, false)
	}
	writeJSON(w, 200, out)
}

// GET /api/upnp
func (a *App) handleUPnP(w http.ResponseWriter, r *http.Request) {
	var out struct {
		Enabled bool `json:"enabled"`
		Running bool `json:"running"`
		Rules   []struct {
			Num      string `json:"num"`
			Proto    string `json:"proto"`
			ExtPort  int    `json:"extport"`
			IntAddr  string `json:"intaddr"`
			IntPort  int    `json:"intport"`
			HostHint string `json:"host_hint"`
			Descr    string `json:"descr"`
			Expires  int    `json:"expires"`
			Device   string `json:"device"`
			MAC      string `json:"mac"`
		} `json:"rules"`
	}
	if err := a.agent.Do("GET", "/v1/upnp", nil, &out); err != nil {
		jsonErr(w, 502, err.Error())
		return
	}
	if len(out.Rules) > 0 {
		byIP := map[string]Device{}
		var devs []Device
		if a.agent.Do("GET", "/v1/devices", nil, &devs) == nil {
			metas := a.deviceMetas()
			for _, d := range devs {
				id := a.identifyDevice(d.MAC, firstNonEmpty(d.StaticName, d.Hostname), metas[d.MAC].Type)
				d.Name = displayName(metas[d.MAC].Alias, d.StaticName, d.Hostname, id)
				byIP[d.IP] = d
			}
		}
		for i := range out.Rules {
			d := byIP[out.Rules[i].IntAddr]
			out.Rules[i].Device, out.Rules[i].MAC = firstNonEmpty(d.Name, out.Rules[i].HostHint), d.MAC
		}
	}
	writeJSON(w, 200, out)
}

// ---- actions ----

var serviceLabels = map[string]string{"on": "开启", "off": "关闭", "restart": "重启"}

type serviceReq struct {
	Name   string `json:"name"`
	Action string `json:"action"`
}

func (a *App) serviceList() ([]struct {
	Name     string `json:"name"`
	Label    string `json:"label"`
	Enabled  bool   `json:"enabled"`
	Running  bool   `json:"running"`
	Critical bool   `json:"critical"`
}, error) {
	var list []struct {
		Name     string `json:"name"`
		Label    string `json:"label"`
		Enabled  bool   `json:"enabled"`
		Running  bool   `json:"running"`
		Critical bool   `json:"critical"`
	}
	err := a.agent.Do("GET", "/v1/sys/services", nil, &list)
	return list, err
}

func prepareService(a *App, u *User, raw json.RawMessage) (string, error) {
	var req serviceReq
	if json.Unmarshal(raw, &req) != nil || serviceLabels[req.Action] == "" {
		return "", errors.New("请求格式错误")
	}
	list, err := a.serviceList()
	if err != nil {
		return "", err
	}
	for _, s := range list {
		if s.Name == req.Name {
			return serviceLabels[req.Action] + "服务 " + s.Label, nil
		}
	}
	return "", errors.New("服务不存在或不支持")
}

func runService(a *App, ac actor, raw json.RawMessage) (any, error) {
	var req serviceReq
	_ = json.Unmarshal(raw, &req)
	summary, err := prepareService(a, ac.user, raw)
	if err != nil {
		return nil, err
	}
	var before any
	if list, err := a.serviceList(); err == nil {
		for _, s := range list {
			if s.Name == req.Name {
				before = map[string]bool{"enabled": s.Enabled, "running": s.Running}
			}
		}
	}
	var after struct {
		Enabled bool `json:"enabled"`
		Running bool `json:"running"`
	}
	err = a.agent.Do("POST", "/v1/sys/service", req, &after)
	a.audit(ac, "system.service", "system", "service."+req.Name, summary, before, after, false)
	return after, err
}

func prepareReboot(a *App, u *User, raw json.RawMessage) (string, error) {
	return "重启路由器", nil
}

func runReboot(a *App, ac actor, raw json.RawMessage) (any, error) {
	a.audit(ac, "system.reboot", "system", "reboot", "重启路由器", nil, nil, false)
	return nil, a.agent.Do("POST", "/v1/sys/reboot", map[string]any{}, nil)
}

type rebootSchedule struct {
	Enabled bool   `json:"enabled"`
	Time    string `json:"time"`
	Days    []int  `json:"days"`
}

var weekday = []string{"日", "一", "二", "三", "四", "五", "六"}

func (s rebootSchedule) String() string {
	if !s.Enabled {
		return "关闭定时重启"
	}
	when := "每天"
	if len(s.Days) > 0 && len(s.Days) < 7 {
		var ds []string
		for _, d := range s.Days {
			if d >= 0 && d < 7 {
				ds = append(ds, "周"+weekday[d])
			}
		}
		when = strings.Join(ds, "、")
	}
	return "定时重启：" + when + " " + s.Time
}

var hhmm = regexp.MustCompile(`^([01]\d|2[0-3]):[0-5]\d$`)

func prepareRebootSchedule(a *App, u *User, raw json.RawMessage) (string, error) {
	var s rebootSchedule
	if json.Unmarshal(raw, &s) != nil || (s.Enabled && !hhmm.MatchString(s.Time)) {
		return "", errors.New("时间格式应为 HH:MM")
	}
	return s.String(), nil
}

func runRebootSchedule(a *App, ac actor, raw json.RawMessage) (any, error) {
	var s, before, after rebootSchedule
	_ = json.Unmarshal(raw, &s)
	_ = a.agent.Do("GET", "/v1/sys/reboot-schedule", nil, &before)
	if err := a.agent.Do("POST", "/v1/sys/reboot-schedule", map[string]any{"schedule": s}, &after); err != nil {
		return nil, err
	}
	a.audit(ac, "system.reboot_schedule", "system", "reboot_schedule", s.String(), before, after, false)
	return after, nil
}

type numReq struct {
	Num   string `json:"num"`
	Label string `json:"label"`
}

func prepareUPnPDelete(a *App, u *User, raw json.RawMessage) (string, error) {
	var req numReq
	if json.Unmarshal(raw, &req) != nil || req.Num == "" {
		return "", errors.New("请求格式错误")
	}
	return "删除 UPnP 映射 " + clean(req.Label, 80), nil
}

func runUPnPDelete(a *App, ac actor, raw json.RawMessage) (any, error) {
	var req numReq
	_ = json.Unmarshal(raw, &req)
	s, _ := prepareUPnPDelete(a, ac.user, raw)
	if err := a.agent.Do("POST", "/v1/upnp/delete", map[string]string{"num": req.Num}, nil); err != nil {
		return nil, err
	}
	a.audit(ac, "upnp.delete", "system", "upnp."+req.Num, s, req.Label, nil, false)
	return nil, nil
}

type wolReq struct {
	MAC  string `json:"mac"`
	Name string `json:"name"`
}

func prepareWOL(a *App, u *User, raw json.RawMessage) (string, error) {
	var req wolReq
	if json.Unmarshal(raw, &req) != nil {
		return "", errors.New("请求格式错误")
	}
	if _, err := net.ParseMAC(req.MAC); err != nil {
		return "", errors.New("MAC 无效")
	}
	return "网络唤醒 " + firstNonEmpty(clean(req.Name, 40), req.MAC), nil
}

func runWOL(a *App, ac actor, raw json.RawMessage) (any, error) {
	var req wolReq
	_ = json.Unmarshal(raw, &req)
	hw, _ := net.ParseMAC(req.MAC)
	s, _ := prepareWOL(a, ac.user, raw)
	if err := a.agent.Do("POST", "/v1/wol", map[string]string{"mac": hw.String()}, nil); err != nil {
		return nil, err
	}
	a.audit(ac, "wol.send", "system", hw.String(), s, nil, nil, false)
	return nil, nil
}

// ---- custom hosts: uci dhcp "domain" sections (dnsmasq address records) ----

var hostNameRe = regexp.MustCompile(`^(?i)[a-z0-9]([a-z0-9-]{0,62})(\.[a-z0-9]([a-z0-9-]{0,62}))*$`)

type customHost struct {
	Section  string `json:"section"`
	Name     string `json:"name"`
	IP       string `json:"ip"`
	OwnerID  int64  `json:"owner_id,omitempty"`
	Editable bool   `json:"editable"`
}

// GET /api/hosts
func (a *App) handleHosts(w http.ResponseWriter, r *http.Request) {
	u := currentUser(r)
	all, err := a.agent.UciConfig("dhcp")
	if err != nil {
		jsonErr(w, 502, err.Error())
		return
	}
	list := []customHost{}
	for name, s := range all {
		if s[".type"] != "domain" {
			continue
		}
		h := customHost{Section: name, Name: optStr(s, "name"), IP: optStr(s, "ip"), OwnerID: a.owner("dhcp", name)}
		h.Editable = u.Can("system.manage") && a.canTouch(u, "dhcp", name)
		list = append(list, h)
	}
	writeJSON(w, 200, list)
}

type hostReq struct {
	Section string `json:"section"`
	Name    string `json:"name"`
	IP      string `json:"ip"`
	Delete  bool   `json:"delete"`
}

func prepareHost(a *App, u *User, raw json.RawMessage) (string, error) {
	var req hostReq
	if json.Unmarshal(raw, &req) != nil {
		return "", errors.New("请求格式错误")
	}
	if req.Section != "" {
		all, err := a.agent.UciConfig("dhcp")
		if err != nil {
			return "", err
		}
		if s := all[req.Section]; s == nil || s[".type"] != "domain" {
			return "", errors.New("记录不存在，请刷新")
		}
		if !a.canTouch(u, "dhcp", req.Section) {
			return "", errors.New("只能修改自己创建的记录")
		}
	}
	if req.Delete {
		return "删除自定义解析 " + clean(req.Name, 80), nil
	}
	if len(req.Name) > 253 || !hostNameRe.MatchString(req.Name) {
		return "", errors.New("域名格式不正确")
	}
	if net.ParseIP(req.IP) == nil {
		return "", errors.New("IP 地址无效")
	}
	verb := "新增"
	if req.Section != "" {
		verb = "修改"
	}
	return fmt.Sprintf("%s自定义解析 %s → %s", verb, req.Name, req.IP), nil
}

func runHost(a *App, ac actor, raw json.RawMessage) (any, error) {
	var req hostReq
	_ = json.Unmarshal(raw, &req)
	summary, err := prepareHost(a, ac.user, raw)
	if err != nil {
		return nil, err
	}
	var ch UciChange
	switch {
	case req.Delete:
		ch = UciChange{Op: "delete", Config: "dhcp", Section: req.Section}
	case req.Section != "":
		ch = UciChange{Op: "set", Config: "dhcp", Section: req.Section, Values: map[string]any{"name": strings.ToLower(req.Name), "ip": req.IP}}
	default:
		ch = UciChange{Op: "add", Config: "dhcp", Type: "domain", Name: "owpn_" + sign.RandomHex(4), Values: map[string]any{"name": strings.ToLower(req.Name), "ip": req.IP}}
	}
	res, err := a.agent.Apply(ch)
	if err != nil {
		return nil, err
	}
	sec := res[0].Section
	if ch.Op == "add" {
		_, _ = a.db.Exec(`INSERT OR REPLACE INTO owned(config, section, kind, user_id, created_at) VALUES('dhcp',?,?,?,?)`,
			sec, "custom_host", ac.user.ID, time.Now().Unix())
	}
	var after any
	if !req.Delete {
		after = res[0].After
	}
	a.audit(ac, "hosts.save", "uci", "dhcp."+sec, summary, res[0].Before, after, true)
	return nil, nil
}

func init() {
	registerAction(&Action{Key: "system.service", Label: "开关插件服务", Perm: "system.manage", Prepare: prepareService, Run: runService, NeedsApproval: always})
	registerAction(&Action{Key: "system.reboot", Label: "重启路由器", Perm: "system.manage", Prepare: prepareReboot, Run: runReboot, NeedsApproval: always})
	registerAction(&Action{Key: "system.reboot_schedule", Label: "设置定时重启", Perm: "system.manage", Prepare: prepareRebootSchedule, Run: runRebootSchedule, NeedsApproval: always})
	registerAction(&Action{Key: "upnp.delete", Label: "删除 UPnP 映射", Perm: "system.manage", Prepare: prepareUPnPDelete, Run: runUPnPDelete})
	registerAction(&Action{Key: "wol.send", Label: "网络唤醒", Perm: "tools.wol", Prepare: prepareWOL, Run: runWOL})
	registerAction(&Action{Key: "hosts.save", Label: "修改自定义解析", Perm: "system.manage", Prepare: prepareHost, Run: runHost})
}
