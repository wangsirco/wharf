package panel

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/wangsirco/wharf/internal/oui"
)

// Device identity: what kind of device is this? Signals, strongest first:
// a type the admin set, the DHCP hostname, the MAC vendor, and which platforms
// the device talks to (Apple push, Android/Google services, Windows Update...).

var DeviceTypes = []string{"手机", "平板", "电脑", "手表", "电视/投屏", "智能音箱", "摄像头", "智能家电", "路由/AP", "NAS/服务器", "虚拟机", "游戏机", "打印机", "物联网", "未知"}

type devIdent struct {
	Type   string `json:"type"`
	OS     string `json:"os"`
	Vendor string `json:"vendor"`
	By     string `json:"type_by"` // manual | hostname | vendor | dns | random | ""
	Random bool   `json:"random_mac"`
	// virtual machines: VMTag is the platform label shown next to the name
	// ("PVE 虚拟机 #105"); GuestName comes from the hypervisor's own config.
	VMTag     string `json:"vm_tag,omitempty"`
	GuestName string `json:"guest_name,omitempty"`
}

type hostRule struct {
	re      *regexp.Regexp
	typ, os string
}

var hostRules = []hostRule{
	{regexp.MustCompile(`iphone`), "手机", "iOS"},
	{regexp.MustCompile(`ipad`), "平板", "iPadOS"},
	{regexp.MustCompile(`(^|[^a-z])watch`), "手表", "watchOS"},
	{regexp.MustCompile(`appletv|apple-tv`), "电视/投屏", "tvOS"},
	{regexp.MustCompile(`homepod`), "智能音箱", "audioOS"},
	{regexp.MustCompile(`macbook|imac|mac-?mini|mac-?studio|mac-?pro|^mac$|s-mac|-mac$`), "电脑", "macOS"},
	{regexp.MustCompile(`\d{1,2}-?pro-?max|\d{2}-?plus$|\d{2}-?mini$`), "手机", ""},
	{regexp.MustCompile(`galaxy|android|pixel|redmi|^mi-|xiaomi-|huawei|honor|oppo|vivo|oneplus|realme|s\d{2}-ultra|^sm-`), "手机", "Android"},
	{regexp.MustCompile(`^desktop-|^laptop-|^win-|windows`), "电脑", "Windows"},
	{regexp.MustCompile(`^[a-z]{3}-(al|tl|an|nx|lx)\d{2}`), "手机", "Android"}, // Huawei / Honor model codes
	{regexp.MustCompile(`camera|indoorcam|outdoorcam|cam-|-cam|cam$|ipc|chuangmi|mxiang|floodlight|doorbell|imilab|xiaovv|ezviz|hikvision|dahua`), "摄像头", ""},
	{regexp.MustCompile(`webos|lgwebos|bravia|androidtv|roku|chromecast|firetv|fire-tv|shield|mitv|-tv$|^tv-|television`), "电视/投屏", ""},
	{regexp.MustCompile(`echo|nest-|google-home|xiaoai|speaker|sonos`), "智能音箱", ""},
	{regexp.MustCompile(`refrigerator|fridge|washer|dryer|aircon|purifier|vacuum|roborock|dreame|ecovacs|robot|dishwasher|oven|heater|fan-`), "智能家电", ""},
	{regexp.MustCompile(`miwifi|router|^ap-|xiaoqiang|openwrt|unifi|tplink|tp-link|asus-rt|netgear|mesh`), "路由/AP", ""},
	{regexp.MustCompile(`nas|synology|diskstation|truenas|unraid|qnap|server|debian|ubuntu|pve|proxmox|-srv|homeassistant`), "NAS/服务器", "Linux"},
	{regexp.MustCompile(`ps4|ps5|playstation|xbox|nintendo|switch`), "游戏机", ""},
	{regexp.MustCompile(`printer|^hp|epson|canon|brother`), "打印机", ""},
	{regexp.MustCompile(`esp_|esp32|esp8266|tuya|shelly|sonoff|tasmota|yeelight|philips-hue|plug|light|bulb`), "物联网", ""},
}

type vendorRule struct {
	match   string
	typ, os string
}

var vendorRules = []vendorRule{
	{"ring", "摄像头", ""}, {"mo xiang", "摄像头", ""}, {"chuangmi", "摄像头", ""}, {"hikvision", "摄像头", ""}, {"dahua", "摄像头", ""},
	{"espressif", "物联网", ""}, {"tuya", "物联网", ""}, {"shelly", "物联网", ""}, {"yeelink", "物联网", ""}, {"lumi united", "物联网", ""},
	{"proxmox", "虚拟机", "Linux"}, {"vmware", "虚拟机", ""}, {"qemu", "虚拟机", ""}, {"parallels", "虚拟机", ""},
	{"raspberry", "NAS/服务器", "Linux"}, {"synology", "NAS/服务器", "DSM"}, {"qnap", "NAS/服务器", "QTS"},
	{"sony interactive", "游戏机", ""}, {"nintendo", "游戏机", ""},
	{"sonos", "智能音箱", ""}, {"roku", "电视/投屏", ""}, {"lg innotek", "电视/投屏", ""}, {"tcl", "电视/投屏", ""},
	{"amazon", "智能音箱", ""}, {"ubiquiti", "路由/AP", ""}, {"dyson", "智能家电", ""}, {"quectel", "物联网", ""},
	{"smart innovation", "物联网", ""}, {"dell", "电脑", ""}, {"lenovo", "电脑", ""}, {"hp inc", "电脑", ""}, {"tp-link", "路由/AP", ""}, {"beijing xiaomi", "", ""},
	{"apple", "", ""}, {"samsung", "", ""}, {"intel", "电脑", ""}, {"liteon", "电脑", ""}, {"azurewave", "电脑", ""},
}

// dnsHints summarises which platforms each device talks to (cached).
type dnsHintCache struct {
	mu sync.Mutex
	at time.Time
	m  map[string]map[string]int64
}

// dnsHints returns the cached per-device platform hints (memory only; refreshed by cacheLoop).
func (a *App) dnsHints() map[string]map[string]int64 {
	c := &a.hints
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.m
}

func (a *App) refreshDNSHints() {
	if a.db == nil {
		return
	}
	m := map[string]map[string]int64{}
	rows, err := a.db.Query(`SELECT mac,
		CASE WHEN domain LIKE '%apple.com' OR domain LIKE '%icloud.com' OR domain LIKE '%mzstatic.com' OR domain LIKE '%apple-dns.net' THEN 'apple'
		     WHEN domain LIKE '%android%' OR domain LIKE '%googleapis.com' OR domain LIKE '%gstatic.com' OR domain LIKE '%gvt1.com' THEN 'google'
		     WHEN domain LIKE '%windowsupdate.com' OR domain LIKE '%msftconnecttest.com' OR domain LIKE '%msedge.net' OR domain LIKE '%microsoft.com' THEN 'windows'
		     WHEN domain LIKE '%xiaomi.com' OR domain LIKE '%mi.com' OR domain LIKE '%miui.com' THEN 'xiaomi'
		     ELSE '' END AS k, SUM(count)
		FROM dns_hour WHERE hour >= ? GROUP BY mac, k`, time.Now().Unix()-3*86400)
	if err == nil {
		for rows.Next() {
			var mac, k string
			var n int64
			if rows.Scan(&mac, &k, &n) == nil {
				if m[mac] == nil {
					m[mac] = map[string]int64{}
				}
				m[mac][k] += n
				m[mac]["_all"] += n
			}
		}
		rows.Close()
	}
	c := &a.hints
	c.mu.Lock()
	c.m, c.at = m, time.Now()
	c.mu.Unlock()
}

// vendorRe caches word-boundary matchers ("ring" must not match "Manufacturing").
var vendorRe = map[string]*regexp.Regexp{}

func init() {
	for _, r := range vendorRules {
		vendorRe[r.match] = regexp.MustCompile(`\b` + regexp.QuoteMeta(r.match) + `\b`)
	}
}

// Friendly brand names for common OUI vendors.
var brands = []struct{ prefix, name string }{
	{"beijing xiaomi", "小米"}, {"xiaomi", "小米"}, {"shanghai imilab", "小米生态·创米"}, {"shanghai mo xiang", "小米生态·摩象"},
	{"lumi united", "小米生态·绿米"}, {"yeelink", "Yeelight"}, {"ugreen", "绿联"}, {"seiko epson", "Epson"}, {"intel", "Intel"},
	{"sony interactive", "Sony PlayStation"}, {"lg innotek", "LG"}, {"lg electronics", "LG"}, {"samsung", "Samsung"},
	{"huawei", "华为"}, {"honor", "荣耀"}, {"tp-link", "TP-Link"}, {"espressif", "乐鑫 ESP"}, {"murata", "Murata（无线模块）"},
	{"proxmox", "PVE 虚拟机"}, {"quectel", "移远（4G 模块）"}, {"azurewave", "AzureWave（无线网卡）"}, {"liteon", "Lite-On（无线网卡）"},
	{"hon hai", "富士康"}, {"tuya", "涂鸦"}, {"smart innovation", "Smart Innovation"},
}

func brandOf(vendor string) string {
	v := strings.ToLower(vendor)
	for _, b := range brands {
		if strings.HasPrefix(v, b.prefix) {
			return b.name
		}
	}
	return vendor
}

func (a *App) identifyDevice(mac, hostname, manualType string) (id devIdent) {
	id = devIdent{Vendor: oui.Vendor(mac), Random: oui.Random(mac)}
	h := strings.ToLower(hostname)
	v := strings.ToLower(id.Vendor)
	defer func() { id.Vendor = brandOf(id.Vendor) }()
	if manualType != "" {
		id.Type, id.By = manualType, "manual"
	}
	if g, ok := a.pveGuest(mac); ok {
		kind := "虚拟机"
		if g.Kind == "lxc" {
			kind = "容器"
		}
		id.VMTag, id.GuestName = fmt.Sprintf("PVE %s #%d", kind, g.VMID), g.Name
		if id.Type == "" && h == "" {
			id.Type, id.By = "虚拟机", "pve"
		}
	} else {
		id.VMTag = vmPlatform(v)
	}
	for _, r := range hostRules {
		if h != "" && r.re.MatchString(h) {
			if id.Type == "" {
				id.Type, id.By = r.typ, "hostname"
			}
			id.OS = r.os
			break
		}
	}
	if id.Type == "" || id.OS == "" {
		for _, r := range vendorRules {
			if v != "" && vendorRe[r.match].MatchString(v) {
				if id.Type == "" && r.typ != "" {
					id.Type, id.By = r.typ, "vendor"
				}
				if id.OS == "" {
					id.OS = r.os
				}
				break
			}
		}
	}
	// which platform does it talk to?
	if hm := a.dnsHints()[mac]; hm != nil && hm["_all"] >= 20 {
		share := func(k string) float64 { return float64(hm[k]) / float64(hm["_all"]) }
		switch {
		case share("apple") > 0.25:
			if id.OS == "" {
				switch id.Type {
				case "手机":
					id.OS = "iOS"
				case "平板":
					id.OS = "iPadOS"
				case "电脑":
					id.OS = "macOS"
				default:
					id.OS = "iOS / macOS"
				}
			}
			if id.Type == "" {
				id.Type, id.By = map[bool]string{true: "手机", false: "电脑"}[id.Random], "dns"
			}
		case share("windows") > 0.2:
			if id.OS == "" {
				id.OS = "Windows"
			}
			if id.Type == "" {
				id.Type, id.By = "电脑", "dns"
			}
		case share("google") > 0.3 && share("apple") < 0.05:
			if id.OS == "" {
				id.OS = "Android"
			}
			if id.Type == "" && id.Random {
				id.Type, id.By = "手机", "dns"
			}
		}
	}
	if id.Type == "" && id.Random {
		// randomised "private" MACs are almost always phones, tablets or laptops
		id.Type, id.By = "手机", "random"
	}
	if id.Type == "" && strings.Contains(v, "apple") {
		id.Type, id.By = "电脑", "vendor"
	}
	if id.Type == "" {
		id.Type = "未知"
	}
	if id.OS == "" && strings.Contains(v, "apple") {
		switch id.Type {
		case "手机":
			id.OS = "iOS"
		case "电脑":
			id.OS = "macOS"
		}
	}
	return id
}

// ---- panel-side device metadata (alias, type override, note) ----

type deviceMeta struct {
	Alias string `json:"alias"`
	Type  string `json:"type"`
	Note  string `json:"note"`
}

func (a *App) deviceMetas() map[string]deviceMeta {
	out := map[string]deviceMeta{}
	rows, err := a.db.Query(`SELECT mac, alias, type, note FROM device_meta`)
	if err != nil {
		return out
	}
	defer rows.Close()
	for rows.Next() {
		var mac string
		var m deviceMeta
		if rows.Scan(&mac, &m.Alias, &m.Type, &m.Note) == nil {
			out[mac] = m
		}
	}
	return out
}

func (a *App) deviceMeta(mac string) (deviceMeta, bool) {
	var m deviceMeta
	err := a.db.QueryRow(`SELECT alias, type, note FROM device_meta WHERE mac=?`, mac).Scan(&m.Alias, &m.Type, &m.Note)
	return m, err == nil
}

type metaReq struct {
	MAC string `json:"mac"`
	deviceMeta
}

func prepareMeta(a *App, u *User, raw json.RawMessage) (string, error) {
	var req metaReq
	if json.Unmarshal(raw, &req) != nil {
		return "", errors.New("请求格式错误")
	}
	if _, err := net.ParseMAC(req.MAC); err != nil {
		return "", errors.New("MAC 无效")
	}
	if req.Type != "" && !containsStr(DeviceTypes, req.Type) {
		return "", errors.New("未知设备类型")
	}
	return "修改设备信息 " + req.MAC + "：" + firstNonEmpty(clean(req.Alias, 40), "（清除别名）"), nil
}

func containsStr(l []string, s string) bool {
	for _, x := range l {
		if x == s {
			return true
		}
	}
	return false
}

func runMeta(a *App, ac actor, raw json.RawMessage) (any, error) {
	var req metaReq
	_ = json.Unmarshal(raw, &req)
	hw, _ := net.ParseMAC(req.MAC)
	mac := hw.String()
	before, had := a.deviceMeta(mac)
	after := deviceMeta{Alias: clean(req.Alias, 40), Type: req.Type, Note: clean(req.Note, 200)}
	if _, err := a.db.Exec(`INSERT INTO device_meta(mac, alias, type, note, updated_at) VALUES(?,?,?,?,?)
		ON CONFLICT(mac) DO UPDATE SET alias=excluded.alias, type=excluded.type, note=excluded.note, updated_at=excluded.updated_at`,
		mac, after.Alias, after.Type, after.Note, time.Now().Unix()); err != nil {
		return nil, err
	}
	var b any
	if had {
		b = before
	}
	s, _ := prepareMeta(a, ac.user, raw)
	a.audit(ac, "device.meta.save", "device_meta", mac, s, b, after, true)
	return nil, nil
}

func (a *App) restoreDeviceMeta(ac actor, e *AuditEntry, force bool) (string, error) {
	var before, after deviceMeta
	_ = json.Unmarshal(e.Before, &before)
	_ = json.Unmarshal(e.After, &after)
	cur, _ := a.deviceMeta(e.TargetID)
	if !force && cur != after {
		return "当前设备信息已被再次修改", nil
	}
	if _, err := a.db.Exec(`INSERT INTO device_meta(mac, alias, type, note, updated_at) VALUES(?,?,?,?,?)
		ON CONFLICT(mac) DO UPDATE SET alias=excluded.alias, type=excluded.type, note=excluded.note, updated_at=excluded.updated_at`,
		e.TargetID, before.Alias, before.Type, before.Note, time.Now().Unix()); err != nil {
		return "", err
	}
	a.audit(ac, "device.meta.restore", "device_meta", e.TargetID, "还原设备信息 "+e.TargetID, cur, before, true)
	return "", nil
}

// GET /api/device-types
func (a *App) handleDeviceTypes(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, 200, DeviceTypes)
}

func init() {
	registerAction(&Action{Key: "device.meta.save", Label: "修改设备名称 / 类型", Perm: "devices.manage", Prepare: prepareMeta, Run: runMeta})
}

// vmPlatform labels a guest NIC by its virtual MAC prefix.
func vmPlatform(vendor string) string {
	for _, p := range [][2]string{{"proxmox", "PVE 虚拟机"}, {"vmware", "VMware 虚拟机"}, {"parallels", "Parallels 虚拟机"}, {"qemu", "QEMU 虚拟机"}, {"xensource", "Xen 虚拟机"}} {
		if strings.Contains(vendor, p[0]) {
			return p[1]
		}
	}
	return ""
}

// displayName picks the best name: alias, DHCP reservation, DHCP hostname, the
// hypervisor's guest name, then a description built from the vendor/type.
func displayName(alias, static, hostname string, id devIdent) string {
	return firstNonEmpty(alias, static, hostname, id.GuestName, fallbackName(id))
}

// fallbackName names a device that has no alias or DHCP hostname.
func fallbackName(id devIdent) string {
	switch {
	case id.GuestName != "":
		return id.GuestName
	case id.VMTag != "":
		return "未命名虚拟机"
	case id.Vendor != "" && strings.Contains(id.Vendor, id.Type):
		return id.Vendor
	case id.Vendor != "" && id.Type != "未知":
		return id.Vendor + " " + id.Type
	case id.Vendor != "":
		return id.Vendor + " 设备"
	case id.Random:
		return "未知手机 / 平板（隐私 MAC）"
	}
	return ""
}
