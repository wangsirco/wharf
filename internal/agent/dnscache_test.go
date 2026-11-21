package agent

import "testing"

func lay(id string, status string, addrs ...string) DNSLayer {
	l := DNSLayer{ID: id, Status: status, Addrs: addrs}
	for _, a := range addrs {
		l.Records = append(l.Records, "A "+a)
	}
	return l
}

func TestDNSVerdict(t *testing.T) {
	pub := "198.51.100.7"
	cases := []struct {
		name    string
		ls      []DNSLayer
		rebind  bool
		verdict string
		stale   string
	}{
		{"ok", []DNSLayer{lay("dnsmasq", "NOERROR", pub), lay("upstream", "NOERROR", pub), lay("public", "NOERROR", pub), lay("auth", "NOERROR", pub)}, true, "ok", ""},
		{"negative cached in nextdns", []DNSLayer{lay("dnsmasq", "NXDOMAIN"), lay("upstream", "NXDOMAIN"), lay("cloud", "NOERROR", pub), lay("public", "NOERROR", pub), lay("auth", "NOERROR", pub)}, true, "stale_missing", "upstream"},
		{"negative cached in dnsmasq only", []DNSLayer{lay("dnsmasq", "NXDOMAIN"), lay("upstream", "NOERROR", "203.0.113.9"), lay("auth", "NOERROR", "203.0.113.9")}, false, "stale_missing", "dnsmasq"},
		{"cloud stale", []DNSLayer{lay("dnsmasq", "NXDOMAIN"), lay("upstream", "NXDOMAIN"), lay("cloud", "NXDOMAIN"), lay("auth", "NOERROR", pub)}, true, "cloud_stale", "cloud"},
		{"old address", []DNSLayer{lay("dnsmasq", "NOERROR", "203.0.113.1"), lay("upstream", "NOERROR", "203.0.113.1"), lay("cloud", "NOERROR", pub), lay("auth", "NOERROR", pub)}, true, "stale_answer", "upstream"},
		{"missing everywhere", []DNSLayer{lay("dnsmasq", "NXDOMAIN"), lay("auth", "NXDOMAIN")}, true, "missing", ""},
		{"rebind", []DNSLayer{lay("dnsmasq", "NOERROR"), lay("upstream", "NOERROR", "192.168.1.20"), lay("auth", "NOERROR", "192.168.1.20")}, true, "rebind", ""},
		{"blocked", []DNSLayer{lay("dnsmasq", "NOERROR", "0.0.0.0"), lay("auth", "NOERROR", pub)}, true, "blocked", ""},
		{"no auth, public used", []DNSLayer{lay("dnsmasq", "NOERROR", pub), lay("public", "NOERROR", pub), {ID: "auth", Error: "超时"}}, true, "ok", ""},
	}
	for _, c := range cases {
		v, s := dnsVerdict(c.ls, c.rebind)
		if v != c.verdict || s != c.stale {
			t.Errorf("%s: got %s/%s want %s/%s", c.name, v, s, c.verdict, c.stale)
		}
	}
}

func TestParseDig(t *testing.T) {
	out := `;; ->>HEADER<<- opcode: QUERY, status: NXDOMAIN, id: 1
;; AUTHORITY SECTION:
example.com.		1800	IN	SOA	a.ns.example.com. dns.example.com. 1 10000 2400 604800 1800
;; Query time: 12 msec
`
	l := parseDig(DNSLayer{}, out, nil, "A")
	if l.Status != "NXDOMAIN" || l.TTL != 1800 || len(l.Records) != 0 || l.MS != 12 {
		t.Fatalf("negative: %+v", l)
	}
	out = `;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 2
;; ANSWER SECTION:
app.example.com.	300	IN	CNAME	edge.example.net.
edge.example.net.	60	IN	A	198.51.100.7
`
	l = parseDig(DNSLayer{}, out, nil, "A")
	if l.TTL != 60 || len(l.Records) != 2 || len(l.Addrs) != 1 || l.Addrs[0] != "198.51.100.7" {
		t.Fatalf("answer: %+v", l)
	}
}
