package panel

import "testing"

// Samples as collected from real devices.
func TestClassifyFP(t *testing.T) {
	cases := []struct {
		name   string
		fp     deviceFP
		random bool
		typ    string
		os     string
		model  string
	}{
		{"Galaxy (DHCP)", deviceFP{DHCPOpts: "1,3,6,15,26,28,51,58,59,43,114,108", DHCPVendor: "android-dhcp-16"}, true, "手机", "Android 16", ""},
		{"iPhone (DHCP)", deviceFP{DHCPOpts: "1,121,3,6,15,108,114,119,252"}, true, "手机", "iOS / iPadOS", ""},
		{"Mac (DHCP)", deviceFP{DHCPOpts: "1,121,3,6,15,108,114,119,252,95,44,46"}, true, "电脑", "macOS", ""},
		{"Windows (DHCP)", deviceFP{DHCPOpts: "1,3,6,15,31,33,43,44,46,47,119,121,249,252", DHCPVendor: "MSFT 5.0"}, false, "电脑", "Windows", ""},
		{"Mac mini (mDNS)", deviceFP{LocalName: "Alexs-Mac-mini", Model: "Mac16,10", Services: []string{"_airplay._tcp", "_companion-link._tcp"}}, false, "电脑", "macOS", "Mac"},
		{"iPhone 17 Pro (mDNS)", deviceFP{LocalName: "Sams-iPhone", Model: "iPhone18,1"}, true, "手机", "iOS", "iPhone 17 Pro"},
		{"iPad (board id)", deviceFP{LocalName: "Alexs-iPad-Pro", Model: "J517AP", Services: []string{"_companion-link._tcp"}}, true, "平板", "iPadOS", ""},
		{"Apple TV", deviceFP{LocalName: "Living-Room-Apple-TV", Model: "AppleTV14,1"}, false, "电视/投屏", "tvOS", "Apple TV 4K"},
		{"Google TV", deviceFP{LocalName: "5f0c9a1e-7d2b-4c3a-9e8f-1a2b3c4d5e6f", Model: "Google TV Streamer", Friendly: "Living Room TV", Maker: "Google", Services: []string{"_googlecast._tcp"}}, true, "电视/投屏", "Google TV", "Google TV Streamer"},
		{"Epson", deviceFP{LocalName: "EPSON123ABC", Model: "EPSON ET-3950 Series", Services: []string{"_ipp._tcp", "_printer._tcp"}}, false, "打印机", "", "EPSON ET-3950 Series"},
		{"PS5", deviceFP{LocalName: "PS5-123ABC", Services: []string{"_spotify-connect._tcp"}}, false, "游戏机", "", ""},
		{"HomeKit camera", deviceFP{LocalName: "Indoorcam", Model: "T8400", Services: []string{"_hap._tcp"}}, false, "摄像头", "", "T8400"},
	}
	for _, c := range cases {
		got := classifyFP(c.fp, c.random)
		if got.typ != c.typ || got.os != c.os || got.model != c.model {
			t.Errorf("%s: got %q %q %q, want %q %q %q", c.name, got.typ, got.os, got.model, c.typ, c.os, c.model)
		}
	}
	if n := classifyFP(deviceFP{LocalName: "5f0c9a1e-7d2b-4c3a-9e8f-1a2b3c4d5e6f", Friendly: "客厅电视"}, false).name; n != "客厅电视" {
		t.Errorf("name %q", n)
	}
}
