package panel

import (
	"net/http"
	"regexp"
	"slices"
	"strings"
	"sync"
	"time"
)

// Device fingerprints collected by the agent (agent/identity.go): DHCP option lists,
// mDNS names / services / models and UPnP descriptions. identifyDevice reads them
// through fpOf; this file keeps the cache and drives the agent.

type deviceFP struct {
	DHCPOpts   string   `json:"dhcp_opts,omitempty"`
	DHCPVendor string   `json:"dhcp_vendor,omitempty"`
	DHCPName   string   `json:"dhcp_name,omitempty"`
	DHCPSeen   int64    `json:"dhcp_seen,omitempty"`
	LocalName  string   `json:"local_name,omitempty"`
	Model      string   `json:"model,omitempty"`
	Friendly   string   `json:"friendly,omitempty"`
	Maker      string   `json:"maker,omitempty"`
	Services   []string `json:"services,omitempty"`
	NetSeen    int64    `json:"net_seen,omitempty"`
}

var fpCache struct {
	sync.Mutex
	m map[string]deviceFP
}

func (a *App) refreshFP() {
	var m map[string]deviceFP
	if a.agent.Do("GET", "/v1/identity", nil, &m) == nil {
		fpCache.Lock()
		fpCache.m = m
		fpCache.Unlock()
	}
}

func fpOf(mac string) (deviceFP, bool) {
	fpCache.Lock()
	defer fpCache.Unlock()
	f, ok := fpCache.m[mac]
	return f, ok
}

// identityLoop keeps dnsmasq's DHCP detail log as the setting says and asks the agent
// to probe the LAN every 10 minutes.
func (a *App) identityLoop() {
	time.Sleep(20 * time.Second)
	for i := 0; ; i++ {
		_ = a.agent.Do("POST", "/v1/identity/dhcplog", map[string]bool{"on": a.setting("identity.dhcp_log") == "1"}, nil)
		if a.setting("identity.probe") == "1" && i%2 == 0 {
			_ = a.agent.Do("POST", "/v1/identity/probe", nil, nil)
			time.Sleep(15 * time.Second) // the probe takes a few seconds
		}
		a.refreshFP()
		time.Sleep(5 * time.Minute)
	}
}

// GET /api/devices/fingerprints — the raw signals (super admin; for the "how was this
// recognised" view and troubleshooting).
func (a *App) handleFingerprints(w http.ResponseWriter, r *http.Request) {
	a.refreshFP()
	fpCache.Lock()
	defer fpCache.Unlock()
	writeJSON(w, 200, fpCache.m)
}

// ---- classification ----

type fpClass struct {
	typ, os, by  string
	model, maker string
	name         string // a usable name the device gave itself
}

// Apple model identifiers -> marketing names (the recent ones people still use).
var appleModels = map[string]string{
	"iPhone14,2": "iPhone 13 Pro", "iPhone14,3": "iPhone 13 Pro Max", "iPhone14,4": "iPhone 13 mini", "iPhone14,5": "iPhone 13",
	"iPhone14,6": "iPhone SE (3rd)", "iPhone14,7": "iPhone 14", "iPhone14,8": "iPhone 14 Plus", "iPhone15,2": "iPhone 14 Pro",
	"iPhone15,3": "iPhone 14 Pro Max", "iPhone15,4": "iPhone 15", "iPhone15,5": "iPhone 15 Plus", "iPhone16,1": "iPhone 15 Pro",
	"iPhone16,2": "iPhone 15 Pro Max", "iPhone17,1": "iPhone 16 Pro", "iPhone17,2": "iPhone 16 Pro Max", "iPhone17,3": "iPhone 16",
	"iPhone17,4": "iPhone 16 Plus", "iPhone17,5": "iPhone 16e", "iPhone18,1": "iPhone 17 Pro", "iPhone18,2": "iPhone 17 Pro Max",
	"iPhone18,3": "iPhone 17", "iPhone18,4": "iPhone Air",
	"AppleTV11,1": "Apple TV 4K", "AppleTV14,1": "Apple TV 4K", "AudioAccessory5,1": "HomePod mini", "AudioAccessory6,1": "HomePod",
}

var uuidLike = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-`)

func appleModel(m string) (typ, os, pretty string) {
	pretty = appleModels[m]
	switch {
	case strings.HasPrefix(m, "iPhone"):
		return "手机", "iOS", firstNonEmpty(pretty, "iPhone")
	case strings.HasPrefix(m, "iPad"):
		return "平板", "iPadOS", "iPad"
	case strings.HasPrefix(m, "MacBookAir"):
		return "电脑", "macOS", "MacBook Air"
	case strings.HasPrefix(m, "MacBookPro"):
		return "电脑", "macOS", "MacBook Pro"
	case strings.HasPrefix(m, "Macmini"):
		return "电脑", "macOS", "Mac mini"
	case strings.HasPrefix(m, "iMac"):
		return "电脑", "macOS", "iMac"
	case strings.HasPrefix(m, "Mac"):
		return "电脑", "macOS", "Mac"
	case strings.HasPrefix(m, "AppleTV"):
		return "电视/投屏", "tvOS", firstNonEmpty(pretty, "Apple TV")
	case strings.HasPrefix(m, "AudioAccessory"):
		return "智能音箱", "audioOS", firstNonEmpty(pretty, "HomePod")
	case strings.HasPrefix(m, "Watch"):
		return "手表", "watchOS", "Apple Watch"
	}
	return "", "", ""
}

// classifyFP turns the raw signals into a type, system and model. Strongest first:
// a model the device states, the names it uses on the LAN, its services, then the
// DHCP fingerprint (which tells the operating system, not the exact device).
func classifyFP(f deviceFP, random bool) (c fpClass) {
	set := func(typ, os, by string) {
		if c.typ == "" && typ != "" {
			c.typ, c.by = typ, by
		}
		if c.os == "" {
			c.os = os
		}
	}
	has := func(svc ...string) bool {
		for _, s := range svc {
			if slices.Contains(f.Services, s) {
				return true
			}
		}
		return false
	}
	// names the device uses for itself
	local := f.LocalName
	if uuidLike.MatchString(strings.ToLower(local)) {
		local = ""
	}
	c.name = firstNonEmpty(f.Friendly, local)

	if t, os, pretty := appleModel(f.Model); t != "" {
		set(t, os, "mdns")
		c.model, c.maker = pretty, "Apple"
	} else if f.Model != "" && !strings.HasSuffix(f.Model, "AP") { // "J517AP" is an Apple board id, not a model
		c.model = f.Model
	}
	text := strings.ToLower(strings.Join([]string{local, f.Friendly, f.Model}, " "))
	for _, r := range hostRules {
		if text != "  " && r.re.MatchString(text) {
			set(r.typ, r.os, "mdns")
			break
		}
	}
	switch {
	case has("_googlecast._tcp"):
		if regexp.MustCompile(`(?i)nest (audio|mini|hub)|google home|speaker`).MatchString(f.Model) {
			set("智能音箱", "", "mdns")
		} else {
			set("电视/投屏", "Google TV", "mdns")
		}
	case has("_ipp._tcp", "_ipps._tcp", "_printer._tcp", "_pdl-datastream._tcp"):
		set("打印机", "", "mdns")
	case has("_hap._tcp", "_matter._tcp") && !has("_companion-link._tcp", "_airplay._tcp"):
		set("物联网", "", "mdns")
	case has("_companion-link._tcp") && c.typ == "": // an Apple device that keeps its model to itself
		set("", "iOS / macOS", "mdns")
	}
	if f.Maker != "" {
		c.maker = firstNonEmpty(c.maker, f.Maker)
		mm := strings.ToLower(f.Maker + " " + f.Model)
		switch {
		case strings.Contains(mm, "playstation") || strings.Contains(mm, "xbox") || strings.Contains(mm, "nintendo"):
			set("游戏机", "", "upnp")
		case regexp.MustCompile(`\btv\b|bravia|webos|tizen|roku`).MatchString(mm):
			set("电视/投屏", "", "upnp")
		case strings.Contains(mm, "sonos"):
			set("智能音箱", "", "upnp")
		}
	}

	// DHCP: the options a client asks for (and its vendor class) give away its system
	o, v := f.DHCPOpts, f.DHCPVendor
	phone := map[bool]string{true: "手机", false: ""}[random]
	switch {
	case strings.HasPrefix(v, "android-dhcp-"):
		set(phone, "Android "+strings.TrimPrefix(v, "android-dhcp-"), "dhcp")
	case strings.HasPrefix(v, "MSFT"):
		set("电脑", "Windows", "dhcp")
	case strings.HasPrefix(v, "udhcp"):
		set("物联网", "Linux", "dhcp")
	case strings.HasPrefix(o, "1,121,3,6,15,"):
		if strings.Contains(","+o+",", ",95,") || strings.HasSuffix(o, ",44,46") {
			set("电脑", "macOS", "dhcp")
		} else {
			set(phone, "iOS / iPadOS", "dhcp")
		}
	case strings.HasPrefix(o, "1,3,6,15,26,28,51,58,59"):
		set(phone, "Android", "dhcp")
	case strings.HasPrefix(o, "1,3,6,15,31,33,43,44,46,47"):
		set("电脑", "Windows", "dhcp")
	case strings.HasPrefix(o, "1,28,2,3,15,6,119,12") || strings.HasPrefix(o, "1,28,2,121,15,6,12,40,41,42"):
		set("", "Linux", "dhcp")
	case o == "1,3,28,6" || o == "1,3,28,6,15,44,46,47,31,33,121,43":
		set("物联网", "", "dhcp")
	}
	return c
}
