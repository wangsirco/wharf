package agent

import (
	"context"
	"net"
	"strings"
	"sync"
	"time"
)

// Presence tracks when each LAN device was last confirmed on the network.
//
// The kernel keeps a departed device's neighbour entry in STALE for a long time,
// so STALE alone cannot tell "idle" from "gone". Every 30 s each STALE / FAILED
// entry gets one ping: whether or not the device answers ICMP, the kernel then
// re-ARPs it (DELAY ~5 s → PROBE → REACHABLE or FAILED, measured ~8 s), so only
// REACHABLE counts as present — DELAY/PROBE would make a departed device look online.
type Presence struct {
	mu    sync.RWMutex
	last  map[string]int64 // mac -> unix time last confirmed reachable
	ready bool             // first round finished
}

// Ready reports whether presence data can be trusted (tracking on, one full round done).
func (p *Presence) Ready() bool {
	if p == nil {
		return false
	}
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.ready
}

var presence *Presence

// presentFor is how long after the last confirmation a device still counts as online.
// A present device is re-confirmed every ~30 s round, so 90 s tolerates two misses.
const presentFor = 90

func NewPresence() *Presence {
	presence = &Presence{last: map[string]int64{}}
	return presence
}

type neighEntry struct{ ip, mac, state string }

func lanNeighbours() []neighEntry {
	lan := uciGetOption("network", "lan", "device")
	out, err := run(5*time.Second, "ip", "-4", "neigh", "show")
	if err != nil {
		return nil
	}
	var list []neighEntry
	for _, line := range strings.Split(string(out), "\n") {
		fs := strings.Fields(line)
		if len(fs) < 6 || fs[3] != "lladdr" || net.ParseIP(fs[0]).To4() == nil || (lan != "" && fs[2] != lan) {
			continue
		}
		list = append(list, neighEntry{fs[0], strings.ToLower(fs[4]), fs[len(fs)-1]})
	}
	return list
}

func (p *Presence) mark(list []neighEntry, now int64) {
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, n := range list {
		switch n.state {
		case "REACHABLE", "PERMANENT":
			p.last[n.mac] = now
		}
	}
}

func (p *Presence) round() {
	list := lanNeighbours()
	p.mark(list, time.Now().Unix())
	var wg sync.WaitGroup
	sem := make(chan struct{}, 16)
	for _, n := range list {
		if n.state != "STALE" && n.state != "FAILED" {
			continue
		}
		wg.Add(1)
		sem <- struct{}{}
		go func(ip string) {
			defer func() { <-sem; wg.Done() }()
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			_, _ = runCtx(ctx, "ping", "-c", "1", "-W", "1", ip)
		}(n.ip)
	}
	wg.Wait()
	time.Sleep(9 * time.Second) // let the kernel finish ARP probing
	p.mark(lanNeighbours(), time.Now().Unix())
	p.mu.Lock()
	p.ready = true
	p.mu.Unlock()
}

func (p *Presence) Run() {
	for {
		start := time.Now()
		p.round()
		if d := 30*time.Second - time.Since(start); d > 0 {
			time.Sleep(d)
		}
	}
}

// LastSeen returns when mac was last confirmed present (0 = never, or tracking off).
func (p *Presence) LastSeen(mac string) int64 {
	if p == nil {
		return 0
	}
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.last[strings.ToLower(mac)]
}
