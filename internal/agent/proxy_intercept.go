package agent

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

// Shared 443 without touching an existing port forward: WAN connections to 443 from
// sources outside a list (Cloudflare, when the website behind the forward is proxied by
// it) are redirected to the proxy front before the firewall's own DNAT sees them; the
// listed sources still reach the forward exactly as before, real addresses included.
//
//	nat    PREROUTING -> owp_pxy:   -i <wan> -p tcp --dport 443 -m set ! --match-set owp_pxy_skip src -j REDIRECT --to-ports <front>
//	filter INPUT      -> owp_pxyin: -p tcp --dport <front> -m conntrack --ctstate DNAT -j ACCEPT
//
// What the front passes on to the forward's server it sends from the visitor's own
// address (IP_TRANSPARENT), so that server still sees real visitors. Its replies are
// addressed to the visitor and would be forwarded to the WAN; they are marked and routed
// to the local socket instead:
//
//	mangle PREROUTING -> owp_pxyt: -p tcp -s <server> --sport <port> -m socket --transparent -j MARK --set-xmark <mark>
//	ip rule fwmark <mark> lookup <table>; ip route local 0.0.0.0/0 dev lo table <table>
//
// fw4 (nftables) gets the same in a table of its own (ip wharf_pxy, see nftIntercept),
// which fw4 reloads leave alone. Its redirect runs just before fw4's dstnat, and the
// replies are recognised by a connection mark the front's own connections get on the way
// out (no socket match module needed).

const (
	pxyChain   = "owp_pxy"
	pxyInChain = "owp_pxyin"
	pxySkipSet = "owp_pxy_skip"
	pxyTChain  = "owp_pxyt"
	pxyMark    = "0x1000000/0x1000000" // clear of fw3, mwan3 (0x3f00) and OpenClash
	pxyTable   = "207"
	nftTable   = "wharf_pxy" // fw4: table ip wharf_pxy
)

type ProxyIntercept struct {
	Port int      `json:"port"` // public port, 443
	To   int      `json:"to"`   // the front's port
	Skip []string `json:"skip"` // source CIDRs left to the existing forward
	Devs []string `json:"devs"` // WAN devices
	Back string   `json:"back"` // the forward's server (ip:port) the front connects to transparently
}

var devRe = regexp.MustCompile(`^[a-zA-Z0-9_.@-]{1,15}$`)

func interceptFile() string { return filepath.Join(proxyDir, "run", "intercept.json") }

func (ic *ProxyIntercept) validate() error {
	if ic.Port < 1 || ic.Port > 65535 || ic.To < 1 || ic.To > 65535 {
		return errors.New("intercept: bad port")
	}
	if len(ic.Devs) == 0 {
		return errors.New("找不到 WAN 网卡")
	}
	for _, d := range ic.Devs {
		if !devRe.MatchString(d) {
			return fmt.Errorf("intercept: bad device %q", d)
		}
	}
	for _, c := range ic.Skip {
		if _, err := netip.ParsePrefix(c); err != nil {
			return fmt.Errorf("intercept: bad CIDR %q", c)
		}
	}
	if ic.Back != "" {
		if ap, err := netip.ParseAddrPort(ic.Back); err != nil || !ap.Addr().Is4() {
			return fmt.Errorf("intercept: bad server %q", ic.Back)
		}
	}
	return nil
}

// setIntercept installs (ic != nil) or removes the redirect, and remembers it so the
// rules come back after an agent restart.
func setIntercept(ic *ProxyIntercept) error {
	if ic == nil {
		clearIntercept()
		_ = os.Remove(interceptFile())
		return nil
	}
	if err := ic.validate(); err != nil {
		return err
	}
	if FirewallFlavor() == "fw4" {
		return setInterceptNft(ic)
	}
	var b strings.Builder
	tmp := pxySkipSet + "_n"
	fmt.Fprintf(&b, "create %s hash:net family inet -exist\ncreate %s hash:net family inet -exist\nflush %s\n", pxySkipSet, tmp, tmp)
	for _, c := range ic.Skip {
		if p, _ := netip.ParsePrefix(c); p.Addr().Is4() {
			fmt.Fprintf(&b, "add %s %s -exist\n", tmp, c)
		}
	}
	fmt.Fprintf(&b, "swap %s %s\ndestroy %s\n", tmp, pxySkipSet, tmp)
	if _, err := runIn(20*time.Second, b.String(), "ipset", "restore"); err != nil {
		return fmt.Errorf("ipset：%v", err)
	}
	nat := interceptRules(ic)
	restore("nat", pxyChain, nat)
	lastInterceptSig = strings.Join(nat, "|")
	restore("filter", pxyInChain, []string{fmt.Sprintf("-p tcp --dport %d -m conntrack --ctstate DNAT -j ACCEPT", ic.To)})
	var mangle []string
	if ap, err := netip.ParseAddrPort(ic.Back); err == nil {
		mangle = append(mangle, fmt.Sprintf("-p tcp -s %s --sport %d -m socket --transparent -j MARK --set-xmark %s", ap.Addr(), ap.Port(), pxyMark))
	}
	restore("mangle", pxyTChain, mangle)
	transparentRoute(len(mangle) > 0)
	hookIntercept()
	b2, _ := json.Marshal(ic)
	return os.WriteFile(interceptFile(), b2, 0o600)
}

var lastInterceptSig string

// interceptRules: from the WAN, and from the LAN to the WAN address (so a phone at home
// using the node's domain also reaches the front; the router's own LAN address keeps
// its web interface).
func interceptRules(ic *ProxyIntercept) []string {
	var nat []string
	for _, d := range ic.Devs {
		nat = append(nat, fmt.Sprintf("-i %s -p tcp --dport %d -m set ! --match-set %s src -j REDIRECT --to-ports %d", d, ic.Port, pxySkipSet, ic.To))
		if ifc, err := net.InterfaceByName(d); err == nil {
			addrs, _ := ifc.Addrs()
			for _, a := range addrs {
				if ipn, ok := a.(*net.IPNet); ok && ipn.IP.To4() != nil {
					nat = append(nat, fmt.Sprintf("! -i %s -d %s/32 -p tcp --dport %d -j REDIRECT --to-ports %d", d, ipn.IP, ic.Port, ic.To))
				}
			}
		}
	}
	return nat
}

// hookIntercept keeps the jumps first in line (a firewall reload drops them).
func hookIntercept() {
	ensure := func(table, parent, chain string) {
		if _, err := run(5*time.Second, "iptables", "-w", "-t", table, "-C", parent, "-j", chain); err != nil {
			if _, err := run(5*time.Second, "iptables", "-w", "-t", table, "-I", parent, "1", "-j", chain); err != nil {
				log.Printf("proxy: hook %s %s: %v", parent, chain, err)
			}
		}
	}
	ensure("nat", "PREROUTING", pxyChain)
	ensure("filter", "INPUT", pxyInChain)
	ensure("mangle", "PREROUTING", pxyTChain)
}

// transparentRoute delivers the marked replies locally (the "local" route makes the
// kernel hand them to the front's socket).
func transparentRoute(on bool) {
	_, _ = run(5*time.Second, "ip", "rule", "del", "fwmark", pxyMark, "lookup", pxyTable)
	if !on {
		_, _ = run(5*time.Second, "ip", "route", "flush", "table", pxyTable)
		return
	}
	if _, err := run(5*time.Second, "ip", "rule", "add", "pref", pxyTable, "fwmark", pxyMark, "lookup", pxyTable); err != nil {
		log.Printf("proxy: ip rule: %v", err)
	}
	if _, err := run(5*time.Second, "ip", "route", "replace", "local", "0.0.0.0/0", "dev", "lo", "table", pxyTable); err != nil {
		log.Printf("proxy: ip route: %v", err)
	}
}

// setInterceptNft loads the whole table in one nft transaction (all or nothing).
func setInterceptNft(ic *ProxyIntercept) error {
	uid, _ := nobody()
	rules := nftIntercept(ic, wanAddrs(ic.Devs), uid)
	if _, err := runIn(20*time.Second, rules, "nft", "-f", "-"); err != nil {
		return fmt.Errorf("nftables：%v", err)
	}
	lastInterceptSig = rules
	transparentRoute(ic.Back != "")
	b, _ := json.Marshal(ic)
	return os.WriteFile(interceptFile(), b, 0o600)
}

// wanAddrs are the IPv4 addresses on the WAN devices (for the LAN-to-WAN-address rule).
func wanAddrs(devs []string) map[string][]string {
	out := map[string][]string{}
	for _, d := range devs {
		if ifc, err := net.InterfaceByName(d); err == nil {
			addrs, _ := ifc.Addrs()
			for _, a := range addrs {
				if ipn, ok := a.(*net.IPNet); ok && ipn.IP.To4() != nil {
					out[d] = append(out[d], ipn.IP.String())
				}
			}
		}
	}
	return out
}

// nftIntercept is the fw4 ruleset: the source split, and the transparent replies.
func nftIntercept(ic *ProxyIntercept, addrs map[string][]string, uid int) string {
	var b strings.Builder
	fmt.Fprintf(&b, "table ip %s\ndelete table ip %s\ntable ip %s {\n", nftTable, nftTable, nftTable)
	b.WriteString("\tset skip {\n\t\ttype ipv4_addr\n\t\tflags interval\n\t\tauto-merge\n")
	var skip []string
	for _, c := range ic.Skip {
		if p, err := netip.ParsePrefix(c); err == nil && p.Addr().Is4() {
			skip = append(skip, p.Masked().String())
		}
	}
	if len(skip) > 0 {
		fmt.Fprintf(&b, "\t\telements = { %s }\n", strings.Join(skip, ", "))
	}
	b.WriteString("\t}\n")
	b.WriteString("\tchain dstnat {\n\t\ttype nat hook prerouting priority dstnat - 10; policy accept;\n")
	for _, d := range ic.Devs {
		fmt.Fprintf(&b, "\t\tiifname %q tcp dport %d ip saddr != @skip redirect to :%d\n", d, ic.Port, ic.To)
		for _, a := range addrs[d] {
			fmt.Fprintf(&b, "\t\tiifname != %q ip daddr %s tcp dport %d redirect to :%d\n", d, a, ic.Port, ic.To)
		}
	}
	b.WriteString("\t}\n")
	if ap, err := netip.ParseAddrPort(ic.Back); err == nil {
		mark := strings.SplitN(pxyMark, "/", 2)[0]
		fmt.Fprintf(&b, "\tchain mark_out {\n\t\ttype route hook output priority mangle; policy accept;\n"+
			"\t\tip daddr %s tcp dport %d meta skuid %d ct mark set ct mark | %s\n\t}\n", ap.Addr(), ap.Port(), uid, mark)
		fmt.Fprintf(&b, "\tchain mark_in {\n\t\ttype filter hook prerouting priority mangle; policy accept;\n"+
			"\t\tip saddr %s tcp sport %d ct mark and %s == %s meta mark set meta mark | %s\n\t}\n", ap.Addr(), ap.Port(), mark, mark, mark)
	}
	b.WriteString("}\n")
	return b.String()
}

func clearIntercept() {
	if FirewallFlavor() == "fw4" {
		_, _ = run(5*time.Second, "nft", "delete", "table", "ip", nftTable)
	}
	transparentRoute(false)
	for _, c := range [][3]string{{"nat", "PREROUTING", pxyChain}, {"filter", "INPUT", pxyInChain}, {"mangle", "PREROUTING", pxyTChain}} {
		for i := 0; i < 4; i++ { // in case it was hooked more than once
			if _, err := run(5*time.Second, "iptables", "-w", "-t", c[0], "-D", c[1], "-j", c[2]); err != nil {
				break
			}
		}
		_, _ = run(5*time.Second, "iptables", "-w", "-t", c[0], "-F", c[2])
		_, _ = run(5*time.Second, "iptables", "-w", "-t", c[0], "-X", c[2])
	}
	_, _ = run(5*time.Second, "ipset", "destroy", pxySkipSet)
}

// keepIntercept re-installs a remembered redirect (agent start, firewall reload).
func keepIntercept(full bool) {
	b, err := os.ReadFile(interceptFile())
	if err != nil {
		return
	}
	var ic ProxyIntercept
	if json.Unmarshal(b, &ic) != nil {
		return
	}
	if FirewallFlavor() == "fw4" {
		uid, _ := nobody()
		if !full && nftIntercept(&ic, wanAddrs(ic.Devs), uid) == lastInterceptSig {
			if _, err := run(5*time.Second, "nft", "list", "table", "ip", nftTable); err == nil {
				return
			}
		}
	} else if !full && strings.Join(interceptRules(&ic), "|") == lastInterceptSig { // the WAN address did not change
		hookIntercept()
		return
	}
	if err := setIntercept(&ic); err != nil {
		log.Printf("proxy: intercept: %v", err)
	}
}
