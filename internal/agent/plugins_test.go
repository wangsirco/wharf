package agent

import (
	"slices"
	"testing"
)

func TestLuaListAndEntries(t *testing.T) {
	vars := map[string]string{"appname": "passwall"}
	if got := luaList(`"admin", "services", appname, "settings"`, vars); !slices.Equal(got, []string{"admin", "services", "passwall", "settings"}) {
		t.Fatalf("path: %v", got)
	}
	if got := luaList(`appname .. "/client/global"`, vars); !slices.Equal(got, []string{"passwall/client/global"}) {
		t.Fatalf("concat: %v", got)
	}
	src := `entry({"admin", "services", "openclash", "settings"},cbi("openclash/settings"),_("Plugin Settings"), 30).leaf = true`
	m := entryRe.FindStringSubmatch(src)
	if m == nil || m[2] != "cbi" || m[4] != "Plugin Settings" || m[5] != "30" {
		t.Fatalf("entry: %q", m)
	}
}

func TestOwnedDirs(t *testing.T) {
	cases := map[string]string{
		"/etc/openclash/core":      "/etc/openclash/",
		"/usr/share/passwall/rule": "/usr/share/passwall/",
		"/etc/init.d":              "",
		"/usr/bin":                 "",
		"/usr/lib/lua/luci/model":  "",
		"/usr":                     "",
	}
	for in, want := range cases {
		if got := topOwnedDir(in); got != want {
			t.Errorf("topOwnedDir(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestHexAddrAndSecrets(t *testing.T) {
	if hexAddr("0100007F") != "127.0.0.1" || hexAddr("00000000") != "0.0.0.0" || hexAddr("00000000000000000000000000000000") != "::" {
		t.Fatal("hexAddr")
	}
	s := redactSection(Section{"proto": "pppoe", "password": "x", "private_key": "k", "username": "u"})
	if s["password"] != "\x00set" || s["private_key"] != "\x00set" || s["username"] != "u" {
		t.Fatalf("redact: %v", s)
	}
	for _, c := range []string{"owp", "rpcd", "dropbear", "../x", "a b"} {
		if configWritable(c) == nil {
			t.Fatalf("%s must not be writable", c)
		}
	}
}
