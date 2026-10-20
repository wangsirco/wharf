package panel

import (
	"net/netip"
	"os"
	"strings"
	"testing"
)

func TestSubtractPrefixes(t *testing.T) {
	allow := []netip.Prefix{netip.MustParsePrefix("1.2.0.0/16")}
	deny := []netip.Prefix{netip.MustParsePrefix("1.2.3.0/24"), netip.MustParsePrefix("1.0.0.0/8")}
	if got := subtractPrefixes(allow, deny); len(got) != 0 {
		t.Fatalf("deny must win over a narrower allow, got %v", got)
	}
	got := subtractPrefixes(allow, deny[:1])
	in := func(s string) bool {
		a := netip.MustParseAddr(s)
		for _, p := range got {
			if p.Contains(a) {
				return true
			}
		}
		return false
	}
	if in("1.2.3.9") || !in("1.2.2.255") || !in("1.2.4.0") || !in("1.2.0.0") || !in("1.2.255.255") {
		t.Fatalf("bad subtraction %v", got)
	}
}

func TestFwdComment(t *testing.T) {
	c := fwdComment(12, "张三|长名字长名字长名字长名字长名字长名字长名字", "NAS", "192.168.1.88", "80", "", "443", "tcp", strings.Repeat("备注", 80))
	if !strings.HasPrefix(c, "OWP|uid=12|user=张三/长名字") || !strings.Contains(c, "|dev=NAS|192.168.1.88:80>wan:443/tcp|note=") {
		t.Fatalf("unexpected comment %q", c)
	}
	if len(c) > 200 {
		t.Fatalf("comment too long: %d bytes", len(c))
	}
	if strings.Count(c, "|") != 5 {
		t.Fatalf("user input must not inject separators: %q", c)
	}
}

func TestCheckAccessWAN(t *testing.T) {
	dir := os.Getenv("OWP_GEO_DIR")
	if dir == "" {
		t.Skip("OWP_GEO_DIR not set")
	}
	a := &App{geo: NewGeo(dir), cfg: Config{Agent: AgentConfig{URL: "http://127.0.0.1:7071"}}}
	deny, _ := parsePrefixes([]string{"121.98.1.0/24"})
	allow, _ := parsePrefixes([]string{"8.8.8.8"})
	p := accessPolicy{LanMode: "all", WanMode: "restrict", Regions: []string{"NZ", "AU/New South Wales"}, DenyIPs: deny, AllowIPs: allow}
	for ip, want := range map[string]bool{
		"121.98.1.10":  false, // NZ but blacklisted
		"121.98.0.1":   true,  // NZ
		"1.1.1.1":      true,  // AU / New South Wales
		"8.8.8.8":      true,  // explicit allow
		"223.5.5.5":    false, // CN
		"192.168.1.50": true,  // LAN, mode all
		"127.0.0.1":    true,
	} {
		if got := a.checkAccessWith(p, ip); got.ok != want {
			t.Errorf("%s: got %v (%s), want %v", ip, got.ok, got.reason, want)
		}
	}
}

func TestUsefulTitle(t *testing.T) {
	for title, want := range map[string]bool{
		"403 Forbidden": false, "404 Not Found": false, "Welcome to nginx!": false, "Just a moment...": false,
		"Attention Required! | Cloudflare": false, "Index of /": false, "nginx": false, "Access Denied": false,
		"Speedtest by Ookla": true, "小红书 - 你的生活指南": true, "Plex": true, "GitHub": true,
	} {
		if got := usefulTitle(title); got != want {
			t.Errorf("%q: got %v want %v", title, got, want)
		}
	}
}

func TestMaskURL(t *testing.T) {
	for in, want := range map[string]string{
		"telegram://123456:ABCDEFGHIJ/999": "telegram://123••••/••••",
		"serverchan://SCT123456789abcdef":  "serverchan://SCT••••/••••",
	} {
		if got := maskURL(in); got != want {
			t.Errorf("%s => %s, want %s", in, got, want)
		}
	}
}

func TestCleanKeepsQuotesAndCase(t *testing.T) {
	if got := clean("  Chloe's   iPhone\t17 \"Pro\"\n", 40); got != `Chloe's iPhone 17 "Pro"` {
		t.Fatalf("clean = %q", got)
	}
	c := fwdComment(3, "Hans|X", "Chloe's iPhone", "192.168.1.9", "22", "", "2222", "tcp", "a|b")
	if !strings.Contains(c, "dev=Chloe's iPhone|") || strings.Contains(c, "Hans|X") || !strings.HasSuffix(c, "note=a/b") {
		t.Fatalf("comment = %q", c)
	}
}

func TestNewerVersion(t *testing.T) {
	for _, c := range []struct {
		l, c string
		want bool
	}{{"v0.12.1", "0.12.0", true}, {"0.12.0", "0.12.0", false}, {"v0.11.9", "0.12.0", false}, {"v1.0.0-beta", "0.12.0", true}, {"v0.12.10", "0.12.9", true}} {
		if newerVersion(c.l, c.c) != c.want {
			t.Errorf("newerVersion(%s, %s) want %v", c.l, c.c, c.want)
		}
	}
}
