package panel

import "testing"

func TestForwardGrants(t *testing.T) {
	g := ForwardGrants{Ports: []PortGrant{{From: 8000, To: 8010}, {WAN: "wan2", From: 9000, To: 9000}},
		LAN: []string{"192.168.1.64/28", "192.168.1.100-192.168.1.120", "192.168.1.159"}}
	if err := g.validate(); err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		wan  string
		port int
		ok   bool
	}{{"", 8005, true}, {"wan2", 8010, true}, {"", 8011, false}, {"wan2", 9000, true}, {"", 9000, false}, {"wan", 9000, false}} {
		if g.portAllowed(c.wan, c.port) != c.ok {
			t.Errorf("portAllowed(%q,%d) want %v", c.wan, c.port, c.ok)
		}
	}
	for ip, ok := range map[string]bool{"192.168.1.64": true, "192.168.1.79": true, "192.168.1.80": false, "192.168.1.110": true, "192.168.1.159": true, "192.168.1.160": false} {
		if g.lanAllowed(ip) != ok {
			t.Errorf("lanAllowed(%s) want %v", ip, ok)
		}
	}
	if (ForwardGrants{}).portAllowed("", 1) != true || (ForwardGrants{}).lanAllowed("192.168.1.9") != true {
		t.Error("empty grants must be unrestricted")
	}
	bad := []ForwardGrants{
		{Ports: []PortGrant{{From: 10, To: 5}}},
		{Ports: []PortGrant{{From: 8000, To: 8010}, {From: 8005, To: 8020}}},
		{Ports: []PortGrant{{From: 8000, To: 8010}, {WAN: "wan2", From: 8010, To: 8020}}}, // "" covers wan2 too
		{LAN: []string{"8.8.8.8"}},
		{LAN: []string{"192.168.1.9-192.168.1.1"}},
	}
	for i, b := range bad {
		if b.validate() == nil {
			t.Errorf("case %d should be rejected", i)
		}
	}
	if !grantsOverlap(PortGrant{WAN: "wan", From: 1, To: 5}, PortGrant{From: 5, To: 9}) || grantsOverlap(PortGrant{WAN: "wan", From: 1, To: 5}, PortGrant{WAN: "wan2", From: 1, To: 5}) {
		t.Error("grantsOverlap")
	}
}
