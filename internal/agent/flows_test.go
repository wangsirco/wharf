package agent

import (
	"net/netip"
	"testing"
	"time"
)

func TestParseAndClassify(t *testing.T) {
	c := &Collector{tr: &Traffic{lan: netip.MustParsePrefix("192.168.1.0/24"), router: netip.MustParseAddr("192.168.1.1")}}
	out := "ipv4     2 tcp      6 7386 ESTABLISHED src=192.168.1.230 dst=107.151.183.66 sport=51492 dport=8016 packets=8 bytes=421 src=107.151.183.66 dst=203.0.113.10 sport=8016 dport=51492 packets=13 bytes=682 [ASSURED] mark=15872 zone=0 use=2 id=3311"
	l, ok := parseCT(out)
	if !ok {
		t.Fatal("parse failed")
	}
	k, up, down, ok := c.classify(l)
	if !ok || k.LAN != "192.168.1.230" || k.Remote != "107.151.183.66" || k.Port != 8016 || k.Proto != "tcp" || up != 421 || down != 682 || k.Inbound {
		t.Fatalf("outbound: %+v up=%d down=%d", k, up, down)
	}
	in := "[DESTROY] ipv4     2 udp      17 src=31.217.176.227 dst=203.0.113.10 sport=49809 dport=63219 packets=1 bytes=132 src=192.168.1.159 dst=31.217.176.227 sport=63219 dport=49809 packets=1 bytes=338 mark=16128 id=99"
	l, ok = parseCT(in)
	k, up, down, ok2 := c.classify(l)
	if !ok || !ok2 || k.LAN != "192.168.1.159" || k.Remote != "31.217.176.227" || !k.Inbound || k.Port != 63219 || up != 338 || down != 132 {
		t.Fatalf("inbound: %+v up=%d down=%d", k, up, down)
	}
	lanOnly := "ipv4 2 udp 17 29 src=192.168.1.114 dst=192.168.1.1 sport=5353 dport=53 packets=1 bytes=70 src=192.168.1.1 dst=192.168.1.114 sport=53 dport=5353 packets=1 bytes=86 id=7"
	l, _ = parseCT(lanOnly)
	if _, _, _, ok := c.classify(l); ok {
		t.Fatal("LAN-internal flow must be skipped")
	}
}

func TestDNSLogParse(t *testing.T) {
	var got []string
	d := NewDNSLog("", nil)
	d.onQuery = func(client, name string, blocked bool) { got = append(got, client+" "+name) }
	for _, l := range []string{
		"Oct  5 16:00:01 dnsmasq[1234]: 1592 192.168.1.114/53321 query[A] www.YouTube.com from 192.168.1.114",
		"Oct  5 16:00:01 dnsmasq[1234]: 1592 192.168.1.114/53321 forwarded www.youtube.com to 127.0.0.1#5342",
		"Oct  5 16:00:01 dnsmasq[1234]: 1592 192.168.1.114/53321 reply www.youtube.com is youtube-ui.l.google.com",
		"Oct  5 16:00:01 dnsmasq[1234]: 1592 192.168.1.114/53321 reply youtube-ui.l.google.com is 142.250.66.206",
	} {
		d.handle(l)
	}
	if n := d.Lookup("192.168.1.114", "142.250.66.206"); n != "www.youtube.com" {
		t.Fatalf("lookup = %q", n)
	}
	if n := d.Lookup("192.168.1.99", "142.250.66.206"); n != "www.youtube.com" {
		t.Fatalf("global lookup = %q", n)
	}
}

// A flow already finished by its DESTROY event must not be counted again when an
// older snapshot line for it is processed afterwards.
func TestNoDoubleCountAfterDestroy(t *testing.T) {
	c := &Collector{tr: &Traffic{lan: netip.MustParsePrefix("192.168.1.0/24"), router: netip.MustParseAddr("192.168.1.1")},
		flows: map[string]*flowState{}, ended: map[string]time.Time{}, curFlows: map[flowKey]*FlowRec{}, primed: true,
		dns: NewDNSLog("", nil)}
	line := "ipv4 2 tcp 6 300 ESTABLISHED src=192.168.1.50 dst=1.1.1.1 sport=5000 dport=443 packets=10 bytes=1000 src=1.1.1.1 dst=203.0.113.10 sport=443 dport=5000 packets=10 bytes=9000 id=42"
	l, _ := parseCT(line)
	c.account(l, true)  // DESTROY first
	c.account(l, false) // stale snapshot line
	var up, down uint64
	for _, r := range c.curFlows {
		up, down = up+r.Up, down+r.Down
	}
	if up != 1000 || down != 9000 {
		t.Fatalf("counted up=%d down=%d, want 1000/9000", up, down)
	}
}
