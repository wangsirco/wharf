package agent

import (
	"crypto/sha1"
	"encoding/hex"
	"fmt"
	"log"
	"net"
	"net/netip"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Per-device access policies from /etc/config/owpdev:
//
//	config device 'owpd_<mac>'
//		option mac 'aa:bb:..'
//		option block '1'              # cut internet now
//		option mode 'blacklist'       # none | blacklist | whitelist
//		list domain 'youtube.com'     # suffixes (expanded from services by the panel)
//		list cidr '1.2.3.0/24'
//		list schedule 'days=1,2,3,4,5;start=22:00;end=07:00'
//		option captive '1'            # keep OS connectivity checks working while blocked
//		option force_dns '1'          # redirect the device's DNS to the router, block DoT
//		list router_port '22'         # deny access to these router ports
//
// They are compiled into dedicated iptables chains (owp_pol in FORWARD, owp_polin
// in INPUT, owp_dns in nat PREROUTING) and per-device ipsets. Domain rules are
// enforced by adding the IPs dnsmasq resolves for those names (seen in the DNS log).

const (
	polChain    = "owp_pol"
	polInChain  = "owp_polin"
	polDNSChain = "owp_dns"
	captiveSet  = "owp_captive"
)

// Connectivity-check hosts of the major OSes. Allowing just these keeps the
// device's "connected to the internet" indicator on while everything else is cut.
var captiveDomains = []string{
	"captive.apple.com", "www.appleiphonecell.com", "www.ibook.info", "www.itools.info", "www.airport.us", "www.thinkdifferent.us",
	"connectivitycheck.gstatic.com", "connectivitycheck.android.com", "clients3.google.com", "clients1.google.com", "play.googleapis.com",
	"www.msftconnecttest.com", "ipv6.msftconnecttest.com", "www.msftncsi.com", "dns.msftncsi.com",
	"detectportal.firefox.com", "nmcheck.gnome.org", "network-test.debian.org", "connectivity-check.ubuntu.com",
	"connect.rom.miui.com", "conn1.oppomobile.com", "conn2.oppomobile.com", "connectivitycheck.platform.hicloud.com",
	"wifi.vivo.com.cn", "connectivitycheck.smartisan.com", "www.qualcomm.cn", "captive.v2ex.co",
}

type Schedule struct {
	Days       []int // 0 = Sunday
	Start, End int   // minutes after midnight; End < Start means overnight
}

func ParseSchedule(s string) (Schedule, error) {
	var sc Schedule
	for _, part := range strings.Split(s, ";") {
		k, v, _ := strings.Cut(part, "=")
		switch k {
		case "days":
			for _, d := range strings.Split(v, ",") {
				n, err := strconv.Atoi(strings.TrimSpace(d))
				if err != nil || n < 0 || n > 6 {
					return sc, fmt.Errorf("bad day %q", d)
				}
				sc.Days = append(sc.Days, n)
			}
		case "start", "end":
			t, err := time.Parse("15:04", v)
			if err != nil {
				return sc, fmt.Errorf("bad time %q", v)
			}
			m := t.Hour()*60 + t.Minute()
			if k == "start" {
				sc.Start = m
			} else {
				sc.End = m
			}
		}
	}
	if len(sc.Days) == 0 || sc.Start == sc.End {
		return sc, fmt.Errorf("incomplete schedule %q", s)
	}
	return sc, nil
}

// Active reports whether t falls inside the schedule (local time).
func (sc Schedule) Active(t time.Time) bool {
	m := t.Hour()*60 + t.Minute()
	has := func(d int) bool {
		for _, x := range sc.Days {
			if x == d {
				return true
			}
		}
		return false
	}
	day := int(t.Weekday())
	if sc.Start < sc.End {
		return has(day) && m >= sc.Start && m < sc.End
	}
	// overnight: from Start on a listed day until End the next morning
	return (has(day) && m >= sc.Start) || (has((day+6)%7) && m < sc.End)
}

type DevicePolicy struct {
	Section    string
	MAC        string
	Block      bool
	Mode       string
	Domains    []string
	CIDRs      []string
	Schedules  []Schedule
	Captive    bool
	ForceDNS   bool
	RouterPort []string
}

type PolicyStatus struct {
	MAC       string `json:"mac"`
	Blocked   bool   `json:"blocked"`
	Reason    string `json:"reason"` // manual | schedule | ""
	Mode      string `json:"mode"`
	SetSize   int    `json:"set_size"`
	ForceDNS  bool   `json:"force_dns"`
	Scheduled bool   `json:"scheduled"`
}

type Policy struct {
	tr *Traffic

	mu       sync.Mutex
	devices  []DevicePolicy
	suffixes map[string][]string // domain suffix -> ipsets that want its IPs
	lastSig  string
	status   map[string]PolicyStatus
}

func NewPolicy(tr *Traffic) *Policy {
	p := &Policy{tr: tr, status: map[string]PolicyStatus{}}
	_, _ = runIn(10*time.Second, "create "+captiveSet+" hash:ip family inet timeout 86400 -exist\n", "ipset", "restore", "-!")
	return p
}

func setFor(mac, kind string) string {
	h := sha1.Sum([]byte(strings.ToLower(mac)))
	return "owp_p" + kind + "_" + hex.EncodeToString(h[:5]) // <= 31 chars
}

func (p *Policy) load() []DevicePolicy {
	all, err := uciGetConfig("owpdev")
	if err != nil {
		return nil
	}
	var out []DevicePolicy
	for id, s := range all {
		if s[".type"] != "device" {
			continue
		}
		mac := strings.ToLower(secStr(s, "mac"))
		if _, err := net.ParseMAC(mac); err != nil {
			continue
		}
		d := DevicePolicy{Section: id, MAC: mac, Block: secStr(s, "block") == "1", Mode: secStr(s, "mode"),
			Domains: secList(s, "domain"), CIDRs: secList(s, "cidr"), Captive: secStr(s, "captive") != "0",
			ForceDNS: secStr(s, "force_dns") != "0", RouterPort: secList(s, "router_port")}
		for _, sc := range secList(s, "schedule") {
			if v, err := ParseSchedule(sc); err == nil {
				d.Schedules = append(d.Schedules, v)
			}
		}
		out = append(out, d)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].MAC < out[j].MAC })
	return out
}

func secStr(s Section, k string) string {
	if v, ok := s[k].(string); ok {
		return v
	}
	return ""
}

func secList(s Section, k string) []string {
	switch v := s[k].(type) {
	case string:
		return strings.Fields(v)
	case []any:
		var out []string
		for _, x := range v {
			out = append(out, fmt.Sprint(x))
		}
		return out
	}
	return nil
}

// Reload re-reads the config and rebuilds sets and chains.
func (p *Policy) Reload(dns *DNSLog) {
	devs := p.load()
	suffixes := map[string][]string{}
	for _, d := range devs {
		var set string
		switch d.Mode {
		case "blacklist":
			set = setFor(d.MAC, "b")
		case "whitelist":
			set = setFor(d.MAC, "w")
		default:
			continue
		}
		var b strings.Builder
		fmt.Fprintf(&b, "create %s hash:net family inet timeout 86400 maxelem 262144 -exist\nflush %s\n", set, set)
		for _, c := range d.CIDRs {
			if pr, err := netip.ParsePrefix(c); err == nil && pr.Addr().Is4() {
				fmt.Fprintf(&b, "add %s %s timeout 0 -exist\n", set, pr.Masked())
			} else if a, err := netip.ParseAddr(c); err == nil && a.Is4() {
				fmt.Fprintf(&b, "add %s %s timeout 0 -exist\n", set, a)
			}
		}
		for _, dom := range d.Domains {
			suffixes[strings.ToLower(dom)] = append(suffixes[strings.ToLower(dom)], set)
		}
		// IPs already resolved recently for these domains
		if dns != nil {
			for ip, name := range dns.Known() {
				if matchSuffix(name, d.Domains) {
					fmt.Fprintf(&b, "add %s %s -exist\n", set, ip)
				}
			}
		}
		if _, err := runIn(30*time.Second, b.String(), "ipset", "restore", "-!"); err != nil {
			log.Printf("policy: set %s: %v", set, err)
		}
	}
	for _, c := range captiveDomains {
		suffixes[c] = append(suffixes[c], captiveSet)
	}
	p.mu.Lock()
	p.devices, p.suffixes, p.lastSig = devs, suffixes, ""
	p.mu.Unlock()
	go p.resolve(devs)
	p.apply(time.Now())
	// drop sets of devices that no longer have a list (no longer referenced after apply)
	want := map[string]bool{}
	for _, d := range devs {
		want[setFor(d.MAC, "b")], want[setFor(d.MAC, "w")] = d.Mode == "blacklist", d.Mode == "whitelist"
	}
	if out, err := run(10*time.Second, "ipset", "list", "-n"); err == nil {
		for _, n := range strings.Fields(string(out)) {
			if (strings.HasPrefix(n, "owp_pb_") || strings.HasPrefix(n, "owp_pw_")) && !want[n] {
				_, _ = run(5*time.Second, "ipset", "destroy", n)
			}
		}
	}
}

// resolve pre-populates sets by resolving domains through the local resolver.
func (p *Policy) resolve(devs []DevicePolicy) {
	names := append([]string{}, captiveDomains...)
	for _, d := range devs {
		if d.Mode != "" && d.Mode != "none" {
			for _, dom := range d.Domains {
				names = append(names, dom, "www."+dom)
			}
		}
	}
	for _, n := range names {
		addrs, err := net.LookupHost(n)
		if err != nil {
			continue
		}
		for _, a := range addrs {
			p.OnResolve(n, a)
		}
	}
}

func matchSuffix(name string, list []string) bool {
	for _, s := range list {
		if name == s || strings.HasSuffix(name, "."+s) {
			return true
		}
	}
	return false
}

// OnResolve is called for every A record seen in the DNS log.
func (p *Policy) OnResolve(name, ip string) {
	a, err := netip.ParseAddr(ip)
	if err != nil || !a.Is4() || a.IsPrivate() || a.IsUnspecified() {
		return
	}
	p.mu.Lock()
	var sets []string
	for s := name; ; {
		sets = append(sets, p.suffixes[s]...)
		_, rest, ok := strings.Cut(s, ".")
		if !ok {
			break
		}
		s = rest
	}
	p.mu.Unlock()
	if len(sets) == 0 {
		return
	}
	go func() {
		for _, set := range sets {
			_, _ = run(5*time.Second, "ipset", "add", set, ip, "-exist")
		}
	}()
}

func (p *Policy) wanDev() string {
	if d := uciGetOption("network", "wan", "device"); d != "" {
		return d
	}
	return ""
}

// apply (re)builds the chains when the effective state changed.
func (p *Policy) apply(now time.Time) {
	p.mu.Lock()
	devs := p.devices
	p.mu.Unlock()

	var fwd, in, nat []string
	status := map[string]PolicyStatus{}
	router := p.tr.router.String()
	for _, d := range devs {
		st := PolicyStatus{MAC: d.MAC, Mode: d.Mode, ForceDNS: d.ForceDNS, Scheduled: len(d.Schedules) > 0}
		if d.Block {
			st.Blocked, st.Reason = true, "manual"
		}
		for _, sc := range d.Schedules {
			if !st.Blocked && sc.Active(now) {
				st.Blocked, st.Reason = true, "schedule"
			}
		}
		m := "-m mac --mac-source " + d.MAC
		reject := func(extra string) {
			fwd = append(fwd, m+" "+extra+" -p tcp -j REJECT --reject-with tcp-reset", m+" "+extra+" -j REJECT")
		}
		switch {
		case st.Blocked:
			if d.Captive {
				fwd = append(fwd, m+" -m set --match-set "+captiveSet+" dst -j RETURN")
			}
			reject("")
		case d.Mode == "blacklist":
			reject("-m set --match-set " + setFor(d.MAC, "b") + " dst")
		case d.Mode == "whitelist":
			fwd = append(fwd, m+" -m set --match-set "+setFor(d.MAC, "w")+" dst -j RETURN",
				m+" -m set --match-set "+captiveSet+" dst -j RETURN")
			reject("")
		}
		if d.ForceDNS && (st.Blocked || d.Mode == "blacklist" || d.Mode == "whitelist" || st.Scheduled) {
			for _, proto := range []string{"udp", "tcp"} {
				nat = append(nat, m+" -p "+proto+" --dport 53 -j DNAT --to-destination "+router+":53")
				fwd = append(fwd, m+" -p "+proto+" --dport 853 -j REJECT") // DNS over TLS / QUIC
			}
		}
		if len(d.RouterPort) > 0 {
			in = append(in, m+" -p tcp -m multiport --dports "+strings.Join(d.RouterPort, ",")+" -j REJECT --reject-with tcp-reset")
		}
		status[d.MAC] = st
	}

	sig := strings.Join(fwd, "|") + "#" + strings.Join(in, "|") + "#" + strings.Join(nat, "|")
	p.mu.Lock()
	p.status = status
	changed := sig != p.lastSig
	p.lastSig = sig
	p.mu.Unlock()
	if changed {
		restore("filter", polChain, fwd)
		restore("filter", polInChain, in)
		restore("nat", polDNSChain, nat)
		log.Printf("policy: %d devices, %d forward rules", len(devs), len(fwd))
	}
	p.hook()
}

// restore replaces one chain's rules atomically with iptables-restore --noflush.
func restore(table, chain string, rules []string) {
	var b strings.Builder
	fmt.Fprintf(&b, "*%s\n:%s - [0:0]\n", table, chain)
	for _, r := range rules {
		fmt.Fprintf(&b, "-A %s %s\n", chain, r)
	}
	b.WriteString("COMMIT\n")
	if _, err := runIn(20*time.Second, b.String(), "iptables-restore", "-w", "--noflush"); err != nil {
		log.Printf("policy: %s/%s: %v", table, chain, err)
	}
}

// hook keeps the jumps in place (fw3 reloads drop them): accounting first, then policy.
func (p *Policy) hook() {
	ensure := func(table, parent, chain string, pos string) {
		if _, err := run(5*time.Second, "iptables", "-w", "-t", table, "-C", parent, "-j", chain); err != nil {
			_, _ = run(5*time.Second, "iptables", "-w", "-t", table, "-N", chain)
			if _, err := run(5*time.Second, "iptables", "-w", "-t", table, "-I", parent, pos, "-j", chain); err != nil {
				log.Printf("policy: hook %s %s: %v", parent, chain, err)
			}
		}
	}
	ensure("filter", "FORWARD", polChain, "2") // after owp_acct so blocked bytes are still counted
	ensure("filter", "INPUT", polInChain, "1")
	ensure("nat", "PREROUTING", polDNSChain, "1")
}

func (p *Policy) Status() map[string]PolicyStatus {
	p.mu.Lock()
	defer p.mu.Unlock()
	out := make(map[string]PolicyStatus, len(p.status))
	for k, v := range p.status {
		out[k] = v
	}
	return out
}

// Run re-evaluates schedules every 20 s and re-hooks the chains.
func (p *Policy) Run(dns *DNSLog) {
	p.Reload(dns)
	for range time.Tick(20 * time.Second) {
		p.apply(time.Now())
	}
}
