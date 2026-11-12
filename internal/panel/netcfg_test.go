package panel

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"slices"
	"testing"
)

func netReq(t *testing.T, a *App, u *User, h http.HandlerFunc, method, path string, body any, pv ...string) (int, map[string]any) {
	t.Helper()
	b, _ := json.Marshal(body)
	r := asUser(httptest.NewRequest(method, path, bytes.NewReader(b)), u)
	for i := 0; i+1 < len(pv); i += 2 {
		r.SetPathValue(pv[i], pv[i+1])
	}
	w := httptest.NewRecorder()
	h(w, r)
	var out map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &out)
	return w.Code, out
}

func seedNet(fa *fakeAgent) {
	fa.uci["network"] = map[string]Section{
		"lan":  {".type": "interface", "proto": "static", "device": "br-lan", "ipaddr": "192.168.1.1", "netmask": "255.255.255.0"},
		"wan":  {".type": "interface", "proto": "static", "device": "eth0", "ipaddr": "203.0.113.9", "netmask": "255.255.255.0", "gateway": "203.0.113.1"},
		"wan6": {".type": "interface", "proto": "dhcpv6", "device": "@wan"},
	}
	fa.uci["firewall"] = map[string]Section{
		"d":         {".type": "defaults", "input": "ACCEPT", "output": "ACCEPT", "forward": "REJECT"},
		"zlan":      {".type": "zone", "name": "lan", "network": []any{"lan"}, "input": "ACCEPT", "output": "ACCEPT", "forward": "ACCEPT"},
		"zwan":      {".type": "zone", "name": "wan", "network": []any{"wan", "wan6", "wan2"}, "input": "REJECT", "output": "ACCEPT", "forward": "REJECT", "masq": "1"},
		"r1":        {".type": "rule", "name": "Allow-Ping", "src": "wan", "proto": "icmp", "target": "ACCEPT"},
		"owp_panel": {".type": "rule", "name": "OWP|panel", "src": "wan", "dest_port": "7080", "target": "ACCEPT"},
	}
}

func TestIfaceEditSwitchesProtoAndZone(t *testing.T) {
	a, fa, su := berthApp(t)
	seedNet(fa)
	zone := "wan"
	code, out := netReq(t, a, su, a.handleNetIfaceSave, "PUT", "/api/net/interfaces/wan",
		ifaceReq{Values: map[string]any{"proto": "pppoe", "username": "user@isp", "password": "s3cret", "device": "eth0"}, Zone: &zone}, "name", "wan")
	if code != 200 || out["pending"] == nil {
		t.Fatalf("save: %d %v", code, out)
	}
	w := fa.uci["network"]["wan"]
	if w["proto"] != "pppoe" || w["username"] != "user@isp" || w["password"] != "s3cret" {
		t.Fatalf("wan not switched: %v", w)
	}
	for _, o := range []string{"ipaddr", "netmask", "gateway"} {
		if w[o] != nil {
			t.Fatalf("static option %s kept after switching to pppoe: %v", o, w)
		}
	}
	if fa.guarded != 1 {
		t.Fatalf("interface change must go through the guarded path")
	}
	// unchanged secret marker keeps the password
	netReq(t, a, su, a.handleNetIfaceSave, "PUT", "/", ifaceReq{Values: map[string]any{"proto": "pppoe", "password": secretMarker, "username": "u2"}}, "name", "wan")
	if fa.uci["network"]["wan"]["password"] != "s3cret" || fa.uci["network"]["wan"]["username"] != "u2" {
		t.Fatalf("password marker must leave the secret alone: %v", fa.uci["network"]["wan"])
	}
	// bad values are refused
	if code, _ := netReq(t, a, su, a.handleNetIfaceSave, "PUT", "/", ifaceReq{Values: map[string]any{"proto": "static", "ipaddr": "192.168.1.1", "netmask": "255.0.255.0"}}, "name", "lan"); code != 400 {
		t.Fatalf("bad netmask accepted: %d", code)
	}
	if code, _ := netReq(t, a, su, a.handleNetIfaceSave, "PUT", "/", ifaceReq{Values: map[string]any{"proto": "static", "ipaddr": ""}}, "name", "lan"); code != 400 {
		t.Fatalf("static without address accepted: %d", code)
	}
}

func TestIfaceAddDelete(t *testing.T) {
	a, fa, su := berthApp(t)
	seedNet(fa)
	delete(fa.uci["firewall"]["zwan"], "network")
	fa.uci["firewall"]["zwan"]["network"] = []any{"wan"}
	zone := "wan"
	code, out := netReq(t, a, su, a.handleNetIfaceAdd, "POST", "/", ifaceReq{Name: "wan2", Values: map[string]any{"proto": "dhcp", "device": "eth2"}, Zone: &zone})
	if code != 200 {
		t.Fatalf("add: %d %v", code, out)
	}
	if fa.uci["network"]["wan2"]["proto"] != "dhcp" || !slices.Contains(strList(fa.uci["firewall"]["zwan"]["network"]), "wan2") {
		t.Fatalf("wan2 not added to network and wan zone: %v %v", fa.uci["network"]["wan2"], fa.uci["firewall"]["zwan"])
	}
	if code, _ := netReq(t, a, su, a.handleNetIfaceAdd, "POST", "/", ifaceReq{Name: "Bad-Name", Values: map[string]any{"proto": "dhcp"}}); code != 400 {
		t.Fatalf("bad name accepted")
	}
	if code, _ := netReq(t, a, su, a.handleNetIfaceDelete, "DELETE", "/", nil, "name", "lan"); code != 400 {
		t.Fatalf("deleting lan must be refused")
	}
	if code, _ := netReq(t, a, su, a.handleNetIfaceDelete, "DELETE", "/", nil, "name", "wan2"); code != 200 {
		t.Fatalf("delete wan2: %d", code)
	}
	if fa.uci["network"]["wan2"] != nil || slices.Contains(strList(fa.uci["firewall"]["zwan"]["network"]), "wan2") {
		t.Fatalf("wan2 left behind")
	}
	var n int
	_ = a.db.QueryRow(`SELECT COUNT(*) FROM audit WHERE action LIKE 'net.iface.%'`).Scan(&n)
	if n == 0 {
		t.Fatalf("interface changes not audited")
	}
}

func TestFirewallRulesAndTidy(t *testing.T) {
	a, fa, su := berthApp(t)
	seedNet(fa)
	// orphan wan2 is reported and tidied
	if o := orphanNetworks(fa.uci["firewall"], fa.uci["network"]); !slices.Equal(o["wan"], []string{"wan2"}) {
		t.Fatalf("orphans: %v", o)
	}
	if code, _ := netReq(t, a, su, a.handleFwTidy, "POST", "/", nil); code != 200 {
		t.Fatal("tidy failed")
	}
	if slices.Contains(strList(fa.uci["firewall"]["zwan"]["network"]), "wan2") {
		t.Fatalf("tidy kept wan2")
	}
	// Wharf's own rules are read-only here
	if code, _ := netReq(t, a, su, a.handleFwRule, "DELETE", "/", nil, "section", "owp_panel"); code != 400 {
		t.Fatalf("managed rule deletable: %d", code)
	}
	code, out := netReq(t, a, su, a.handleFwRule, "POST", "/", fwRuleReq{Name: "WireGuard", Src: "wan", Proto: []string{"udp"}, DestPort: "51820", Target: "ACCEPT"})
	if code != 200 {
		t.Fatalf("add rule: %d %v", code, out)
	}
	var sec string
	for n, s := range fa.uci["firewall"] {
		if s["name"] == "WireGuard" {
			sec = n
		}
	}
	if sec == "" || fa.uci["firewall"][sec]["dest_port"] != "51820" {
		t.Fatalf("rule not written: %v", fa.uci["firewall"])
	}
	for _, bad := range []fwRuleReq{
		{Name: "x", Src: "nowhere", Target: "ACCEPT"},
		{Name: "x", Src: "wan", DestPort: "80;rm", Target: "ACCEPT"},
		{Name: "OWP|fake", Src: "wan", Target: "ACCEPT"},
		{Name: "x", Src: "wan", SrcIP: []string{"not-an-ip"}, Target: "ACCEPT"},
	} {
		if code, _ := netReq(t, a, su, a.handleFwRule, "POST", "/", bad); code != 400 {
			t.Fatalf("bad rule accepted: %+v", bad)
		}
	}
	r := asUser(httptest.NewRequest("POST", "/api/net/firewall/rule/"+sec+"/toggle", bytes.NewReader([]byte(`{"enabled":false}`))), su)
	r.SetPathValue("section", sec)
	w := httptest.NewRecorder()
	a.handleFwRule(w, r)
	if w.Code != 200 || fa.uci["firewall"][sec]["enabled"] != "0" {
		t.Fatalf("toggle: %d %v", w.Code, fa.uci["firewall"][sec])
	}
}

func TestDHCPHostConflicts(t *testing.T) {
	a, fa, su := berthApp(t)
	fa.uci["dhcp"] = map[string]Section{"h1": {".type": "host", "name": "nas", "mac": []any{"AA:BB:CC:00:00:30"}, "ip": "192.168.1.30"}}
	body := map[string]any{"name": "tv", "mac": []string{"aa:bb:cc:00:00:40"}, "ip": "192.168.1.30"}
	if code, _ := netReq(t, a, su, a.handleNetDHCPHost, "PUT", "/", body); code != 409 {
		t.Fatalf("duplicate IP accepted")
	}
	body["ip"], body["mac"] = "192.168.1.40", []string{"AA:BB:CC:00:00:30"}
	if code, _ := netReq(t, a, su, a.handleNetDHCPHost, "PUT", "/", body); code != 409 {
		t.Fatalf("duplicate MAC accepted")
	}
	body["mac"] = []string{"aa:bb:cc:00:00:40"}
	if code, out := netReq(t, a, su, a.handleNetDHCPHost, "PUT", "/", body); code != 200 {
		t.Fatalf("host add: %d %v", code, out)
	}
	if code, _ := netReq(t, a, su, a.handleNetDNS, "PUT", "/", map[string]any{"server": []string{"8.8.8.8; reboot"}}); code != 400 && code != 404 {
		t.Fatalf("bad upstream accepted: %d", code)
	}
}

func TestPluginSaveScope(t *testing.T) {
	a, fa, su := berthApp(t)
	fa.plugins = []map[string]any{{"pkg": "luci-app-demo", "title": "Demo", "configs": []string{"demo"}, "pages": []map[string]any{{"path": "admin/services/demo", "kind": "cbi", "target": "demo/main", "title": "Demo"}}}}
	fa.uci["demo"] = map[string]Section{"main": {".type": "demo", "enabled": "0", "password": "old"}}
	fa.uci["dropbear"] = map[string]Section{"d": {".type": "dropbear", "Port": "22"}}
	if code, _ := netReq(t, a, su, a.handlePluginSave, "PUT", "/", map[string]any{"pkg": "luci-app-demo", "changes": []UciChange{{Op: "set", Config: "dropbear", Section: "d", Values: map[string]any{"Port": "2222"}}}}); code != 400 {
		t.Fatalf("plugin wrote a config it does not own")
	}
	code, out := netReq(t, a, su, a.handlePluginSave, "PUT", "/", map[string]any{"pkg": "luci-app-demo", "changes": []UciChange{{Op: "set", Config: "demo", Section: "main", Values: map[string]any{"enabled": "1", "password": "••••••"}}}})
	if code != 200 {
		t.Fatalf("save: %d %v", code, out)
	}
	if fa.uci["demo"]["main"]["enabled"] != "1" || fa.uci["demo"]["main"]["password"] != "old" {
		t.Fatalf("masked secret overwrote the real one: %v", fa.uci["demo"]["main"])
	}
	if !a.modelOfPlugin(&pluginInfo{Pages: []struct {
		Path   string `json:"path"`
		Title  string `json:"title"`
		Order  int    `json:"order"`
		Kind   string `json:"kind"`
		Target string `json:"target"`
	}{{Target: "demo/main"}}}, "demo/edit") || a.modelOfPlugin(&pluginInfo{}, "other/x") {
		t.Fatalf("model scope")
	}
}

func TestMaskFormSecretsAndWanPorts(t *testing.T) {
	raw := json.RawMessage(`{"maps":[{"children":[{"children":[{"option":"password","password":true,"values":{"s":"hunter2"}},{"option":"port","values":{"s":"8080"}}]}]}]}`)
	got := string(maskFormSecrets(raw))
	if bytes.Contains([]byte(got), []byte("hunter2")) || !bytes.Contains([]byte(got), []byte("8080")) {
		t.Fatalf("mask: %s", got)
	}
	fw := map[string]Section{
		"a": {".type": "rule", "src": "wan", "target": "ACCEPT", "proto": "tcp", "dest_port": "8080 9000-9001"},
		"b": {".type": "rule", "src": "wan", "dest": "lan", "target": "ACCEPT", "dest_port": "22"},
		"c": {".type": "rule", "src": "wan", "target": "ACCEPT", "dest_port": "51820", "enabled": "0"},
	}
	open := wanOpenPorts(fw)
	if open["8080/tcp"] != "a" || open["9001/tcp"] != "a" || open["8080/udp"] != "" || open["22/tcp"] != "" || open["51820/udp"] != "" {
		t.Fatalf("wan ports: %v", open)
	}
}
