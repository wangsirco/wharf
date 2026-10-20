package agent

import (
	"bufio"
	"log"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Per-device byte counters: two ipsets with counters (owp_up matched on source,
// owp_dn on destination) referenced from an owp_acct chain jumped to first in FORWARD.
// fw3 flushes FORWARD on reload, so the jump is re-checked periodically.

const (
	setUp     = "owp_up"
	setDown   = "owp_dn"
	acctChain = "owp_acct"
)

type HostRate struct {
	Up       float64 `json:"up"`   // bytes/s (device -> internet)
	Down     float64 `json:"down"` // bytes/s
	UpTotal  uint64  `json:"up_total"`
	DownTot  uint64  `json:"down_total"`
	LastSeen int64   `json:"last_seen"`
}

type Traffic struct {
	mu     sync.Mutex
	lan    netip.Prefix
	router netip.Addr
	last   map[string][2]uint64 // raw set counters at last sample
	total  map[string][2]uint64 // monotonically increasing totals since agent start
	rates  map[string]*HostRate
	lastTS time.Time
}

func lanPrefix() (netip.Prefix, netip.Addr) {
	var st struct {
		V4 []struct {
			Address string `json:"address"`
			Mask    int    `json:"mask"`
		} `json:"ipv4-address"`
	}
	if ubusCall("network.interface.lan", "status", nil, &st) == nil && len(st.V4) > 0 {
		if a, err := netip.ParseAddr(st.V4[0].Address); err == nil {
			return netip.PrefixFrom(a, st.V4[0].Mask).Masked(), a
		}
	}
	return netip.MustParsePrefix("192.168.1.0/24"), netip.MustParseAddr("192.168.1.1")
}

func NewTraffic() *Traffic {
	lan, router := lanPrefix()
	t := &Traffic{lan: lan, router: router, last: map[string][2]uint64{}, total: map[string][2]uint64{}, rates: map[string]*HostRate{}}
	t.ensure()
	return t
}

// ensure creates the sets (all hosts of the LAN prefix, up to /20) and the iptables hook.
func (t *Traffic) ensure() {
	for _, s := range []string{setUp, setDown} {
		if _, err := run(5*time.Second, "ipset", "list", "-n", s); err == nil {
			continue
		}
		var b strings.Builder
		b.WriteString("create " + s + " hash:ip family inet counters maxelem 65536 -exist\n")
		if t.lan.Bits() >= 20 {
			for a := t.lan.Addr(); t.lan.Contains(a); a = a.Next() {
				b.WriteString("add " + s + " " + a.String() + " -exist\n")
			}
		}
		if err := runStdin(b.String(), "ipset", "restore", "-!"); err != nil {
			log.Printf("traffic: create %s: %v", s, err)
		}
	}
	_, _ = run(5*time.Second, "iptables", "-w", "-N", acctChain)
	if out, _ := run(5*time.Second, "iptables", "-w", "-S", acctChain); strings.Count(string(out), "match-set") < 2 {
		_, _ = run(5*time.Second, "iptables", "-w", "-F", acctChain)
		_, _ = run(5*time.Second, "iptables", "-w", "-A", acctChain, "-m", "set", "--match-set", setUp, "src")
		_, _ = run(5*time.Second, "iptables", "-w", "-A", acctChain, "-m", "set", "--match-set", setDown, "dst")
	}
	if _, err := run(5*time.Second, "iptables", "-w", "-C", "FORWARD", "-j", acctChain); err != nil {
		if _, err := run(5*time.Second, "iptables", "-w", "-I", "FORWARD", "1", "-j", acctChain); err != nil {
			log.Printf("traffic: hook FORWARD: %v", err)
		}
	}
}

// readSet parses "ipset list" members: "192.168.1.5 packets 12 bytes 3456".
func readSet(name string) map[string]uint64 {
	out, err := run(10*time.Second, "ipset", "list", name)
	if err != nil {
		return nil
	}
	m := map[string]uint64{}
	sc := bufio.NewScanner(strings.NewReader(string(out)))
	members := false
	for sc.Scan() {
		line := sc.Text()
		if line == "Members:" {
			members = true
			continue
		}
		if !members {
			continue
		}
		f := strings.Fields(line)
		if len(f) >= 5 && f[3] == "bytes" {
			n, _ := strconv.ParseUint(f[4], 10, 64)
			if n > 0 {
				m[f[0]] = n
			}
		}
	}
	return m
}

func (t *Traffic) sample() {
	up, down := readSet(setUp), readSet(setDown)
	if up == nil || down == nil {
		t.ensure()
		return
	}
	now := time.Now()
	t.mu.Lock()
	defer t.mu.Unlock()
	dt := now.Sub(t.lastTS).Seconds()
	seen := map[string]bool{}
	for ip := range up {
		seen[ip] = true
	}
	for ip := range down {
		seen[ip] = true
	}
	for ip := range seen {
		cur := [2]uint64{up[ip], down[ip]}
		prev, had := t.last[ip]
		var d [2]uint64
		for i := 0; i < 2; i++ {
			if cur[i] >= prev[i] {
				d[i] = cur[i] - prev[i]
			} else { // set was recreated
				d[i] = cur[i]
			}
		}
		if !had {
			d = cur // first bytes of an address seen after the first sample
		}
		if t.lastTS.IsZero() {
			d = [2]uint64{} // counters from before this agent started are not ours to report
		}
		t.last[ip] = cur
		tot := t.total[ip]
		tot[0] += d[0]
		tot[1] += d[1]
		t.total[ip] = tot
		r := t.rates[ip]
		if r == nil {
			r = &HostRate{}
			t.rates[ip] = r
		}
		if dt > 0 && !t.lastTS.IsZero() {
			r.Up, r.Down = float64(d[0])/dt, float64(d[1])/dt
		}
		r.UpTotal, r.DownTot = tot[0], tot[1]
		if d[0]+d[1] > 0 {
			r.LastSeen = now.Unix()
		}
	}
	for ip, r := range t.rates {
		if !seen[ip] {
			r.Up, r.Down = 0, 0
		}
	}
	t.lastTS = now
}

func (t *Traffic) Live() map[string]HostRate {
	t.mu.Lock()
	defer t.mu.Unlock()
	out := make(map[string]HostRate, len(t.rates))
	for ip, r := range t.rates {
		out[ip] = *r
	}
	return out
}

// Totals returns cumulative per-IP [up, down] since agent start.
func (t *Traffic) Totals() map[string][2]uint64 {
	t.mu.Lock()
	defer t.mu.Unlock()
	out := make(map[string][2]uint64, len(t.total))
	for k, v := range t.total {
		out[k] = v
	}
	return out
}

func (t *Traffic) Run() {
	tick := time.NewTicker(2 * time.Second)
	n := 0
	for range tick.C {
		t.sample()
		if n++; n%5 == 0 {
			t.ensure() // re-hook after firewall reloads
		}
	}
}

func (t *Traffic) inLAN(a netip.Addr) bool { return t.lan.Contains(a) }

func runStdin(in string, name string, args ...string) error {
	_, err := runIn(30*time.Second, in, name, args...)
	return err
}
