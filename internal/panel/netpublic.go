package panel

import (
	"net/http"
	"net/netip"
	"sort"
	"strings"
	"sync"
	"time"
)

// Public address check: the WAN interface's own address is only half the story.
// Ask several outside services what address the home really leaves with (bound to
// the WAN device), compare, and when the router sits behind a modem look at the
// next hop to tell "modem holds the public address" from "operator's big NAT".
// Ends with what the user can do about it: DDNS when reachable, the ways out
// (bridge / DMZ / ask the ISP / IPv6 / tunnel) when not.

type pubSeen struct {
	Source string `json:"source"`
	IP     string `json:"ip,omitempty"`
	Error  string `json:"error,omitempty"`
}

type pubDDNS struct {
	ID         int64  `json:"id"`
	Domain     string `json:"domain"`
	RType      string `json:"rtype"`
	Enabled    bool   `json:"enabled"`
	LastIP     string `json:"last_ip"`
	LastErr    string `json:"last_err,omitempty"`
	PointsHere bool   `json:"points_here"`
}

type pubCheck struct {
	Iface   string    `json:"iface"`
	Proto   string    `json:"proto"`
	Dynamic bool      `json:"dynamic"`
	WANIP   string    `json:"wan_ip"`
	Seen    []pubSeen `json:"seen"`
	// External: the address most services agree on
	External string `json:"external"`
	// public      WAN address is public and the outside sees the same one
	// public_unverified  WAN address looks public, no service answered
	// mismatch    WAN address is public but the outside sees another one (proxy plugin or a second NAT)
	// cgnat       WAN address is in 100.64.0.0/10, or the hop after the modem is
	// modem       router behind a modem / upstream router; NextHop says what is beyond it
	// none        no IPv4 on the WAN
	Verdict  string    `json:"verdict"`
	NextHop  string    `json:"next_hop,omitempty"`      // first hop beyond the WAN gateway
	NextKind string    `json:"next_hop_kind,omitempty"` // public | cgnat | private | unknown
	Hops     []string  `json:"hops,omitempty"`
	IPv6     string    `json:"ipv6,omitempty"` // a global IPv6 address on any WAN, if there is one
	IPv6Ext  string    `json:"ipv6_external,omitempty"`
	DDNS     []pubDDNS `json:"ddns"`
	DDNSOK   bool      `json:"ddns_visible"` // false: the caller can't see DDNS (not a super admin)
	Checked  int64     `json:"checked"`
}

var pubChecks = struct {
	sync.Mutex
	m map[string]*pubCheck
}{m: map[string]*pubCheck{}}

// GET /api/net/public?iface=wan[&refresh=1]
func (a *App) handleNetPublic(w http.ResponseWriter, r *http.Request) {
	iface := r.URL.Query().Get("iface")
	if iface == "" {
		iface = "wan"
	}
	if !ifNameRe.MatchString(iface) {
		jsonErr(w, 400, "接口名不对")
		return
	}
	refresh := r.URL.Query().Get("refresh") == "1"
	pubChecks.Lock()
	c := pubChecks.m[iface]
	pubChecks.Unlock()
	age := time.Duration(0)
	if c != nil {
		age = time.Since(time.Unix(c.Checked, 0))
	}
	if c == nil || age > 10*time.Minute || (refresh && age > 15*time.Second) {
		c = a.checkPublic(iface)
		pubChecks.Lock()
		pubChecks.m[iface] = c
		pubChecks.Unlock()
	}
	out := *c
	u := currentUser(r)
	out.DDNS = nil
	if u != nil && u.Role == RoleSuper {
		out.DDNSOK = true
		out.DDNS = a.ddnsFor(&out)
	}
	writeJSON(w, 200, out)
}

func (a *App) ddnsFor(c *pubCheck) []pubDDNS {
	list, err := a.ddnsList()
	out := []pubDDNS{}
	if err != nil {
		return out
	}
	for _, d := range list {
		if d.RType == "CNAME" {
			continue
		}
		p := pubDDNS{ID: d.ID, Domain: d.Domain, RType: d.RType, Enabled: d.Enabled, LastIP: d.LastIP, LastErr: d.LastErr}
		switch d.RType {
		case "A":
			p.PointsHere = d.LastIP != "" && (d.LastIP == c.External || d.LastIP == c.WANIP)
		case "AAAA":
			p.PointsHere = d.LastIP != "" && (d.LastIP == c.IPv6 || d.LastIP == c.IPv6Ext)
		}
		out = append(out, p)
	}
	return out
}

func (a *App) checkPublic(iface string) *pubCheck {
	c := &pubCheck{Iface: iface, Checked: time.Now().Unix(), Seen: []pubSeen{}}
	if net, err := a.agent.UciConfig("network"); err == nil {
		if s, ok := net[iface]; ok {
			c.Proto = sectionStr(s, "proto")
		}
	}
	c.Dynamic = c.Proto != "static"
	var st struct {
		Up     bool     `json:"up"`
		Device string   `json:"device"`
		IPv4   string   `json:"ipv4"`
		IPv6   []string `json:"ipv6"`
	}
	_ = a.agent.Do("GET", "/v1/iface?name="+iface, nil, &st)
	c.WANIP = addrOnly(st.IPv4)
	for _, s := range st.IPv6 {
		if s = addrOnly(s); publicIP(s) {
			c.IPv6 = s
			break
		}
	}
	if c.IPv6 == "" { // IPv6 usually lives on wan6
		for _, n := range []string{iface + "6", "wan6"} {
			if ip, err := a.ifaceIP(n, true); err == nil {
				c.IPv6 = ip
				break
			}
		}
	}

	// ask the outside, leaving through the WAN device
	ids := []string{"ddnspod", "ipsb", "ipify", "icanhazip", "cloudflare"}
	seen := make([]pubSeen, len(ids))
	var wg sync.WaitGroup
	for i, id := range ids {
		wg.Add(1)
		go func(i int, id string) {
			defer wg.Done()
			ip, err := a.apiIP(id, false, st.Device)
			seen[i] = pubSeen{Source: id, IP: ip}
			if err != nil {
				seen[i].Error = err.Error()
			}
		}(i, id)
	}
	if c.IPv6 != "" {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for _, id := range []string{"ddnspod6", "ipify6"} {
				if ip, err := a.apiIP(id, true, ""); err == nil {
					c.IPv6Ext = ip
					return
				}
			}
		}()
	}
	wg.Wait()
	c.Seen = seen
	c.External = majorityIP(seen)

	wanPublic := publicIP(c.WANIP)
	switch {
	case c.WANIP == "":
		c.Verdict = "none"
	case wanPublic:
		switch {
		case c.External == "":
			c.Verdict = "public_unverified"
		case seenIncludes(seen, c.WANIP):
			// at least one service sees the interface address: the others went through a proxy
			c.Verdict = "public"
			c.External = c.WANIP
		default:
			c.Verdict = "mismatch"
		}
	case inCGNAT(c.WANIP):
		c.Verdict = "cgnat"
	default:
		c.Verdict = "modem"
		c.Hops = a.firstHops()
		c.NextHop, c.NextKind = nextHopBeyond(c.Hops, c.WANIP)
		if c.NextKind == "cgnat" {
			c.Verdict = "cgnat"
		}
	}
	return c
}

func majorityIP(seen []pubSeen) string {
	n := map[string]int{}
	for _, s := range seen {
		if s.IP != "" {
			n[s.IP]++
		}
	}
	best, bc := "", 0
	keys := make([]string, 0, len(n))
	for k := range n {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		if n[k] > bc {
			best, bc = k, n[k]
		}
	}
	return best
}

func seenIncludes(seen []pubSeen, ip string) bool {
	for _, s := range seen {
		if s.IP == ip {
			return true
		}
	}
	return false
}

func inCGNAT(s string) bool {
	ip, err := netip.ParseAddr(s)
	return err == nil && netip.MustParsePrefix("100.64.0.0/10").Contains(ip)
}

// firstHops traces towards a well-known resolver and returns the first few hop addresses ("" = no answer).
func (a *App) firstHops() []string {
	var res struct {
		Hops []struct {
			Hop int    `json:"hop"`
			IP  string `json:"ip"`
		} `json:"hops"`
	}
	if err := a.agent.Do("POST", "/v1/diag", map[string]any{"tool": "trace", "target": "223.5.5.5", "count": 1}, &res); err != nil {
		return nil
	}
	var out []string
	for _, h := range res.Hops {
		if len(out) >= 5 {
			break
		}
		out = append(out, h.IP)
	}
	return out
}

// nextHopBeyond skips the private hops of the home (router's own LAN-side upstream,
// the modem) and classifies the first hop after them.
func nextHopBeyond(hops []string, wanIP string) (string, string) {
	if len(hops) < 2 {
		return "", "unknown"
	}
	// hop 1 is the modem / upstream router; the next answering hop tells what is beyond it
	for _, h := range hops[1:] {
		if h == "" {
			continue
		}
		switch {
		case inCGNAT(h):
			return h, "cgnat"
		case publicIP(h):
			return h, "public"
		default:
			if sameSlash16(h, wanIP) { // another box of the same home network
				continue
			}
			return h, "private"
		}
	}
	return "", "unknown"
}

func sameSlash16(a, b string) bool {
	pa, pb := strings.Split(a, "."), strings.Split(b, ".")
	return len(pa) == 4 && len(pb) == 4 && pa[0] == pb[0] && pa[1] == pb[1]
}
