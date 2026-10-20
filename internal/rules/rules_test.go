package rules

import (
	"net/netip"
	"testing"
)

func TestIdentify(t *testing.T) {
	m, err := Default("")
	if err != nil {
		t.Fatal(err)
	}
	cases := map[string]string{
		"www.youtube.com":                   "YouTube",
		"rr3---sn-a5mekn6z.googlevideo.com": "YouTube",
		"music.apple.com":                   "Apple Music",
		"www.apple.com":                     "Apple",
		"sns-img-qc.xhscdn.com":             "小红书",
		"api.openai.com":                    "OpenAI API",
		"chatgpt.com":                       "ChatGPT",
		"grok.com":                          "Grok",
		"chat.deepseek.com":                 "DeepSeek",
		"claude.ai":                         "Claude",
		"teams.microsoft.com":               "Microsoft Teams",
		"login.microsoftonline.com":         "Microsoft",
		"open.spotify.com":                  "Spotify",
		"api.bilibili.com":                  "哔哩哔哩",
		"steamcdn-a.akamaihd.net":           "Steam",
		"weixin.qq.com":                     "微信",
		"nextdns.io":                        "NextDNS",
		"unknown-example-zzz.net":           "",
	}
	for d, want := range cases {
		r, _ := m.Domain(d)
		if r.Service != want {
			t.Errorf("%s: got %q (%s/%s), want %q", d, r.Service, r.Category, r.Company, want)
		}
	}
	if r := m.Identify("", netip.MustParseAddr("91.108.56.1"), 0, ""); r.Service != "Telegram" {
		t.Errorf("telegram ip: %+v", r)
	}
	if r := m.Identify("", netip.MustParseAddr("203.0.113.1"), 15169, "Google LLC"); r.Company != "Google" {
		t.Errorf("asn: %+v", r)
	}
	t.Logf("rules version %s", m.Version())
}

func TestAppleSpecificFirst(t *testing.T) {
	m, _ := Default("")
	for d, want := range map[string]string{"gateway.icloud.com": "iCloud", "p144-fmfmobile.icloud.com": "iCloud"} {
		if r, _ := m.Domain(d); r.Service != want && r.Service != "查找" {
			t.Errorf("%s => %q", d, r.Service)
		}
	}
}
