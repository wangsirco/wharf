package agent

import (
	"strings"
	"testing"
)

func TestNftIntercept(t *testing.T) {
	ic := &ProxyIntercept{Port: 443, To: 20443, Skip: []string{"173.245.48.0/20", "10.1.2.3/32", "2400:cb00::/32"}, Devs: []string{"pppoe-wan"}, Back: "192.168.1.10:443"}
	got := nftIntercept(ic, map[string][]string{"pppoe-wan": {"203.0.113.7"}}, 65534)
	for _, want := range []string{
		"table ip wharf_pxy\ndelete table ip wharf_pxy\ntable ip wharf_pxy {\n",
		"elements = { 173.245.48.0/20, 10.1.2.3/32 }",
		"type nat hook prerouting priority dstnat - 10; policy accept;",
		`iifname "pppoe-wan" tcp dport 443 ip saddr != @skip redirect to :20443`,
		`iifname != "pppoe-wan" ip daddr 203.0.113.7 tcp dport 443 redirect to :20443`,
		"ip daddr 192.168.1.10 tcp dport 443 meta skuid 65534 ct mark set ct mark | 0x1000000",
		"ip saddr 192.168.1.10 tcp sport 443 ct mark and 0x1000000 == 0x1000000 meta mark set meta mark | 0x1000000",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %q in\n%s", want, got)
		}
	}
	if strings.Contains(got, "2400:cb00") {
		t.Error("IPv6 source in an ip table")
	}
	if strings.Count(got, "{") != strings.Count(got, "}") {
		t.Errorf("unbalanced braces\n%s", got)
	}

	// no server behind the port (takeover-less split without a transparent back end), no skip list
	got = nftIntercept(&ProxyIntercept{Port: 8443, To: 20443, Devs: []string{"eth1"}}, nil, 65534)
	if strings.Contains(got, "elements") || strings.Contains(got, "mark_out") || !strings.Contains(got, "tcp dport 8443") {
		t.Errorf("unexpected\n%s", got)
	}
}
