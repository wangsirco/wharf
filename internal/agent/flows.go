package agent

import (
	"bufio"
	"log"
	"net/netip"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/wangsirco/wharf/internal/sign"
)

// Flow accounting from conntrack: a snapshot every 10 s gives byte deltas for live
// connections, and DESTROY events give the final bytes of connections that end in
// between. Everything is aggregated into one-minute buckets the panel collects.

type flowKey struct {
	LAN     string
	Remote  string
	Proto   string
	Port    int
	Inbound bool
}

type flowState struct {
	key      flowKey
	up, down uint64
	domain   string
	seen     bool
	start    int64 // first observed (inbound connections only)
	rport    int   // remote source port (inbound)
}

// ConnRec is one finished inbound connection through a port forward.
type ConnRec struct {
	Start  int64  `json:"start"`
	End    int64  `json:"end"`
	IP     string `json:"ip"`
	MAC    string `json:"mac"`
	Port   int    `json:"port"` // LAN service port
	Proto  string `json:"proto"`
	Remote string `json:"remote"`
	RPort  int    `json:"rport"`
	Up     uint64 `json:"up"`              // LAN service -> remote
	Down   uint64 `json:"down"`            // remote -> LAN service
	Early  bool   `json:"early,omitempty"` // started before the agent did: start is approximate
}

const maxConnsPerMinute = 2000

type FlowRec struct {
	IP      string `json:"ip"`
	MAC     string `json:"mac"`
	Remote  string `json:"remote"`
	Proto   string `json:"proto"`
	Port    int    `json:"port"`
	Inbound bool   `json:"inbound,omitempty"`
	Domain  string `json:"domain,omitempty"`
	Up      uint64 `json:"up"`
	Down    uint64 `json:"down"`
	Conns   int    `json:"conns"`
}

type HostRec struct {
	IP   string `json:"ip"`
	MAC  string `json:"mac"`
	Up   uint64 `json:"up"`
	Down uint64 `json:"down"`
}

type DNSRec struct {
	IP      string `json:"ip"`
	MAC     string `json:"mac"`
	Domain  string `json:"domain"`
	Count   int    `json:"count"`
	Blocked int    `json:"blocked"`
}

type MinuteRec struct {
	Seq          int64             `json:"seq"`
	Minute       int64             `json:"minute"` // unix seconds, start of minute
	Hosts        []HostRec         `json:"hosts"`
	Flows        []FlowRec         `json:"flows"`
	DNS          []DNSRec          `json:"dns"`
	Names        map[string]string `json:"names,omitempty"` // mac -> hostname (for offline history)
	Net          []PingStat        `json:"net,omitempty"`
	Conns        []ConnRec         `json:"conns,omitempty"` // finished inbound (port forward) connections
	ConnsDropped int               `json:"conns_dropped,omitempty"`
	Events       []WanEvent        `json:"events,omitempty"`
}

type dnsKey struct{ client, name string }

type Collector struct {
	tr   *Traffic
	dns  *DNSLog
	Net  *NetMon
	boot string

	mu        sync.Mutex
	flows     map[string]*flowState // conntrack id -> state
	ended     map[string]time.Time  // ids whose DESTROY we already accounted (stale snapshots must not revive them)
	curFlows  map[flowKey]*FlowRec
	curDNS    map[dnsKey]*DNSRec
	curConns  []ConnRec
	connsDrop int
	lastTotal map[string][2]uint64
	primed    bool // first snapshot only records state; bytes before agent start are not ours
	seq       int64
	ring      []MinuteRec
}

func NewCollector(tr *Traffic) *Collector {
	c := &Collector{tr: tr, boot: sign.RandomHex(6), flows: map[string]*flowState{}, ended: map[string]time.Time{}, curFlows: map[flowKey]*FlowRec{},
		curDNS: map[dnsKey]*DNSRec{}, lastTotal: tr.Totals()}
	c.dns = NewDNSLog(EnsureDNSLogging(), c.onQuery)
	return c
}

func (c *Collector) onQuery(client, name string, blocked bool) {
	a, err := netip.ParseAddr(client)
	if err != nil || !c.tr.inLAN(a) || a == c.tr.router {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	k := dnsKey{client, name}
	r := c.curDNS[k]
	if r == nil {
		r = &DNSRec{IP: client, Domain: name}
		c.curDNS[k] = r
	}
	if blocked {
		r.Blocked++
	} else {
		r.Count++
	}
}

// ctLine parses one conntrack -o extended,id line (listing or event).
type ctLine struct {
	proto      string
	id         string
	osrc, odst netip.Addr
	osp, odp   int
	obytes     uint64
	rsrc       netip.Addr
	rsp        int
	rbytes     uint64
}

func parseCT(line string) (ctLine, bool) {
	var l ctLine
	f := strings.Fields(line)
	n := 0 // tuple counter: 0 = original, 1 = reply
	for i, tok := range f {
		if i > 0 && (f[i-1] == "ipv4" || f[i-1] == "ipv6") {
			continue
		}
		if l.proto == "" && (tok == "tcp" || tok == "udp" || tok == "icmp" || tok == "sctp" || tok == "gre" || tok == "udplite") {
			l.proto = tok
			continue
		}
		k, v, ok := strings.Cut(tok, "=")
		if !ok {
			continue
		}
		switch k {
		case "src":
			a, _ := netip.ParseAddr(v)
			if n == 0 && !l.osrc.IsValid() {
				l.osrc = a
			} else {
				n = 1
				l.rsrc = a
			}
		case "dst":
			if n == 0 && !l.odst.IsValid() {
				l.odst, _ = netip.ParseAddr(v)
			}
		case "sport":
			p, _ := strconv.Atoi(v)
			if n == 0 && l.osp == 0 {
				l.osp = p
			} else {
				l.rsp = p
			}
		case "dport":
			if n == 0 && l.odp == 0 {
				l.odp, _ = strconv.Atoi(v)
			}
		case "bytes":
			b, _ := strconv.ParseUint(v, 10, 64)
			if n == 0 {
				l.obytes = b
			} else {
				l.rbytes = b
			}
		case "id":
			l.id = v
		}
	}
	return l, l.id != "" && l.osrc.IsValid() && l.odst.IsValid() && l.proto != ""
}

// classify decides which side is the LAN device. ok=false for flows we don't account.
func (c *Collector) classify(l ctLine) (k flowKey, up, down uint64, ok bool) {
	in := c.tr.inLAN
	switch {
	case in(l.osrc) && !in(l.odst) && l.odst.IsGlobalUnicast() && l.osrc != c.tr.router:
		return flowKey{l.osrc.String(), l.odst.String(), l.proto, l.odp, false}, l.obytes, l.rbytes, true
	case l.rsrc.IsValid() && in(l.rsrc) && !in(l.osrc) && l.osrc.IsGlobalUnicast() && l.rsrc != c.tr.router:
		// inbound through a port forward: remote client -> LAN service port
		return flowKey{l.rsrc.String(), l.osrc.String(), l.proto, l.rsp, true}, l.rbytes, l.obytes, true
	}
	return k, 0, 0, false
}

// account adds bytes of a flow since its last observation. Caller holds c.mu.
func (c *Collector) account(l ctLine, final bool) {
	if _, gone := c.ended[l.id]; gone {
		return // a snapshot taken before this flow's DESTROY was processed
	}
	st := c.flows[l.id]
	k, up, down, ok := c.classify(l)
	if !ok {
		return
	}
	isNew := st == nil
	if isNew {
		st = &flowState{key: k, domain: c.dns.Lookup(k.LAN, k.Remote), start: time.Now().Unix()}
		if k.Inbound {
			st.rport = l.osp
		}
		c.flows[l.id] = st
		if !c.primed && !final {
			st.up, st.down, st.seen = up, down, true
			st.start = -st.start // existed before we started: mark as approximate
			return
		}
	}
	if final && k.Inbound {
		start, early := st.start, false
		if start < 0 {
			start, early = -start, true
		}
		if len(c.curConns) < maxConnsPerMinute {
			c.curConns = append(c.curConns, ConnRec{Start: start, End: time.Now().Unix(), IP: k.LAN, Port: k.Port, Proto: k.Proto,
				Remote: k.Remote, RPort: st.rport, Up: up, Down: down, Early: early})
		} else {
			c.connsDrop++
		}
	}
	st.seen = true
	du, dd := sub(up, st.up), sub(down, st.down)
	st.up, st.down = up, down
	r := c.curFlows[k]
	if r == nil {
		r = &FlowRec{IP: k.LAN, Remote: k.Remote, Proto: k.Proto, Port: k.Port, Inbound: k.Inbound}
		c.curFlows[k] = r
	}
	if r.Domain == "" {
		r.Domain = st.domain
	}
	r.Up += du
	r.Down += dd
	if isNew {
		r.Conns++
	}
	if final {
		delete(c.flows, l.id)
		c.ended[l.id] = time.Now()
	}
}

func sub(a, b uint64) uint64 {
	if a >= b {
		return a - b
	}
	return 0
}

func (c *Collector) snapshot() {
	out, err := run(20*time.Second, "conntrack", "-L", "-o", "extended,id")
	if err != nil && len(out) == 0 {
		log.Printf("conntrack -L: %v", err)
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, st := range c.flows {
		st.seen = false
	}
	sc := bufio.NewScanner(strings.NewReader(string(out)))
	sc.Buffer(make([]byte, 64<<10), 1<<20)
	for sc.Scan() {
		if l, ok := parseCT(sc.Text()); ok {
			c.account(l, false)
		}
	}
	for id, st := range c.flows {
		if !st.seen {
			delete(c.flows, id) // ended without us seeing the DESTROY event
		}
	}
	c.primed = true
	for id, t := range c.ended {
		if time.Since(t) > time.Minute {
			delete(c.ended, id)
		}
	}
}

func (c *Collector) events() {
	for {
		cmd := exec.Command("conntrack", "-E", "-e", "DESTROY", "-o", "extended,id")
		stdout, err := cmd.StdoutPipe()
		if err == nil {
			err = cmd.Start()
		}
		if err != nil {
			log.Printf("conntrack -E: %v", err)
			time.Sleep(10 * time.Second)
			continue
		}
		sc := bufio.NewScanner(stdout)
		sc.Buffer(make([]byte, 64<<10), 1<<20)
		for sc.Scan() {
			if l, ok := parseCT(sc.Text()); ok {
				c.mu.Lock()
				c.account(l, true)
				c.mu.Unlock()
			}
		}
		_ = cmd.Wait()
		time.Sleep(2 * time.Second)
	}
}

// closeMinute moves the current buckets into the ring.
func (c *Collector) closeMinute(minute time.Time) {
	neigh := Neighbours()
	names := map[string]string{}
	for _, d := range GetDevices() {
		n := d.StaticName
		if n == "" {
			n = d.Hostname
		}
		if n != "" {
			names[d.MAC] = n
		}
	}
	totals := c.tr.Totals()

	c.mu.Lock()
	defer c.mu.Unlock()
	rec := MinuteRec{Minute: minute.Unix(), Names: names}
	for ip, t := range totals {
		p := c.lastTotal[ip]
		up, down := sub(t[0], p[0]), sub(t[1], p[1])
		if up+down > 0 {
			rec.Hosts = append(rec.Hosts, HostRec{IP: ip, MAC: neigh[ip], Up: up, Down: down})
		}
	}
	c.lastTotal = totals
	for _, r := range c.curFlows {
		if r.Up+r.Down == 0 && r.Conns == 0 {
			continue
		}
		r.MAC = neigh[r.IP]
		rec.Flows = append(rec.Flows, *r)
	}
	for _, r := range c.curDNS {
		r.MAC = neigh[r.IP]
		rec.DNS = append(rec.DNS, *r)
	}
	for _, cr := range c.curConns {
		cr.MAC = neigh[cr.IP]
		rec.Conns = append(rec.Conns, cr)
	}
	rec.ConnsDropped = c.connsDrop
	c.curConns, c.connsDrop = nil, 0
	c.curFlows = map[flowKey]*FlowRec{}
	c.curDNS = map[dnsKey]*DNSRec{}
	if c.Net != nil {
		rec.Net, rec.Events = c.Net.Flush()
	}
	c.seq++
	rec.Seq = c.seq
	c.ring = append(c.ring, rec)
	if len(c.ring) > 720 { // keep 12 h for a panel that was offline
		c.ring = c.ring[len(c.ring)-720:]
	}
}

// Since returns closed minutes after seq (max 120 per call).
func (c *Collector) Since(seq int64) (string, []MinuteRec) {
	c.mu.Lock()
	defer c.mu.Unlock()
	var out []MinuteRec
	for _, r := range c.ring {
		if r.Seq > seq {
			out = append(out, r)
			if len(out) >= 120 {
				break
			}
		}
	}
	return c.boot, out
}

func (c *Collector) Run() {
	go c.dns.Run()
	go c.events()
	snap := time.NewTicker(10 * time.Second)
	cur := time.Now().Truncate(time.Minute)
	for range snap.C {
		c.snapshot()
		if now := time.Now().Truncate(time.Minute); now.After(cur) {
			c.closeMinute(cur)
			cur = now
		}
	}
}

func (c *Collector) DNS() *DNSLog { return c.dns }

func (c *Collector) SetResolveHook(f func(name, ip string)) { c.dns.OnResolve = f }

// LiveConn is an inbound connection that is still open.
type LiveConn struct {
	Start  int64  `json:"start"`
	IP     string `json:"ip"`
	Port   int    `json:"port"`
	Proto  string `json:"proto"`
	Remote string `json:"remote"`
	RPort  int    `json:"rport"`
	Up     uint64 `json:"up"`
	Down   uint64 `json:"down"`
	Early  bool   `json:"early,omitempty"`
}

// LiveInbound lists open connections that came in through port forwards.
func (c *Collector) LiveInbound() []LiveConn {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := []LiveConn{}
	for _, st := range c.flows {
		if !st.key.Inbound {
			continue
		}
		lc := LiveConn{Start: st.start, IP: st.key.LAN, Port: st.key.Port, Proto: st.key.Proto, Remote: st.key.Remote, RPort: st.rport, Up: st.up, Down: st.down}
		if lc.Start < 0 {
			lc.Start, lc.Early = -lc.Start, true
		}
		out = append(out, lc)
	}
	return out
}
