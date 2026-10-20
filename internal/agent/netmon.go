package agent

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"math"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/showwin/speedtest-go/speedtest"
)

// Network quality: every 10 s, 3 pings to each target (WAN gateway + public
// resolvers). Results are folded into per-minute stats the panel collects, plus
// WAN events (reconnects, link down) detected from the interface uptime.

type PingStat struct {
	Target string  `json:"target"`
	Sent   int     `json:"sent"`
	Lost   int     `json:"lost"`
	Min    float64 `json:"min"`
	Avg    float64 `json:"avg"`
	Max    float64 `json:"max"`
	Jitter float64 `json:"jitter"` // mean absolute difference between consecutive samples
}

type WanEvent struct {
	TS     int64  `json:"ts"`
	Kind   string `json:"kind"` // reconnect | down | up
	Detail string `json:"detail"`
}

type WanStatus struct {
	Up        bool     `json:"up"`
	Proto     string   `json:"proto"`
	Device    string   `json:"device"`
	Uptime    int64    `json:"uptime"`
	IPv4      string   `json:"ipv4"`
	Gateway   string   `json:"gateway"`
	DNS       []string `json:"dns"`
	IPv6      []string `json:"ipv6"`
	Public    string   `json:"public_ip,omitempty"`
	Interface string   `json:"interface"`
}

type NetMon struct {
	mu      sync.Mutex
	samples map[string][]float64 // current minute: rtts (ms), NaN = lost
	events  []WanEvent
	lastUp  int64
	wasUp   bool
	inited  bool
}

var pingRe = regexp.MustCompile(`time=([\d.]+) ms`)

func NewNetMon() *NetMon { return &NetMon{samples: map[string][]float64{}} }

func WANStatus(iface string) WanStatus {
	var st struct {
		Up     bool   `json:"up"`
		Uptime int64  `json:"uptime"`
		Proto  string `json:"proto"`
		L3     string `json:"l3_device"`
		V4     []struct {
			Address string `json:"address"`
		} `json:"ipv4-address"`
		V6 []struct {
			Address string `json:"address"`
		} `json:"ipv6-address"`
		Route []struct {
			Target, Nexthop string
		} `json:"route"`
		DNS []string `json:"dns-server"`
	}
	_ = ubusCall("network.interface."+iface, "status", nil, &st)
	w := WanStatus{Up: st.Up, Proto: st.Proto, Device: st.L3, Uptime: st.Uptime, DNS: st.DNS, Interface: iface}
	if len(st.V4) > 0 {
		w.IPv4 = st.V4[0].Address
	}
	for _, a := range st.V6 {
		w.IPv6 = append(w.IPv6, a.Address)
	}
	for _, r := range st.Route {
		if r.Target == "0.0.0.0" {
			w.Gateway = r.Nexthop
		}
	}
	return w
}

func (n *NetMon) targets() []string {
	t := []string{}
	if gw := WANStatus("wan").Gateway; gw != "" {
		t = append(t, gw)
	}
	return append(t, "1.1.1.1", "223.5.5.5", "8.8.8.8")
}

func ping(target string) []float64 {
	ctx, cancel := context.WithTimeout(context.Background(), 6*time.Second)
	defer cancel()
	out, _ := runCtx(ctx, "ping", "-c", "3", "-W", "1", target)
	var rtts []float64
	for _, m := range pingRe.FindAllStringSubmatch(string(out), -1) {
		v, _ := strconv.ParseFloat(m[1], 64)
		rtts = append(rtts, v)
	}
	for len(rtts) < 3 {
		rtts = append(rtts, math.NaN())
	}
	return rtts
}

func (n *NetMon) round() {
	var wg sync.WaitGroup
	for _, t := range n.targets() {
		wg.Add(1)
		go func(t string) {
			defer wg.Done()
			r := ping(t)
			n.mu.Lock()
			n.samples[t] = append(n.samples[t], r...)
			n.mu.Unlock()
		}(t)
	}
	wg.Wait()

	w := WANStatus("wan")
	n.mu.Lock()
	defer n.mu.Unlock()
	now := time.Now().Unix()
	if n.inited {
		switch {
		case n.wasUp && !w.Up:
			n.events = append(n.events, WanEvent{now, "down", "WAN 接口断开"})
		case !n.wasUp && w.Up:
			n.events = append(n.events, WanEvent{now, "up", "WAN 接口恢复，IP " + w.IPv4})
		case w.Up && w.Uptime < n.lastUp:
			n.events = append(n.events, WanEvent{now, "reconnect", "WAN 重新连接，IP " + w.IPv4})
		}
	}
	n.inited, n.wasUp, n.lastUp = true, w.Up, w.Uptime
}

// Flush returns this minute's stats and events and resets them.
func (n *NetMon) Flush() ([]PingStat, []WanEvent) {
	n.mu.Lock()
	defer n.mu.Unlock()
	var out []PingStat
	for t, rs := range n.samples {
		s := PingStat{Target: t, Sent: len(rs), Min: math.MaxFloat64}
		var sum, jit float64
		var prev float64
		ok := 0
		for _, v := range rs {
			if math.IsNaN(v) {
				s.Lost++
				continue
			}
			if ok > 0 {
				jit += math.Abs(v - prev)
			}
			prev = v
			ok++
			sum += v
			s.Min = math.Min(s.Min, v)
			s.Max = math.Max(s.Max, v)
		}
		if ok > 0 {
			s.Avg = round1(sum / float64(ok))
			s.Min, s.Max = round1(s.Min), round1(s.Max)
			if ok > 1 {
				s.Jitter = round1(jit / float64(ok-1))
			}
		} else {
			s.Min = 0
		}
		out = append(out, s)
	}
	ev := n.events
	n.samples, n.events = map[string][]float64{}, nil
	return out, ev
}

func round1(v float64) float64 { return math.Round(v*10) / 10 }

func (n *NetMon) Run() {
	for {
		start := time.Now()
		n.round()
		if d := 10*time.Second - time.Since(start); d > 0 {
			time.Sleep(d)
		}
	}
}

// ---- speed test against Cloudflare's public speed test endpoints ----

type SpeedResult struct {
	TS        int64   `json:"ts"`
	DownMbps  float64 `json:"down_mbps"`
	UpMbps    float64 `json:"up_mbps"`
	LatencyMs float64 `json:"latency_ms"`
	Server    string  `json:"server"`
	Error     string  `json:"error,omitempty"`
}

var speedMu sync.Mutex

func SpeedTest() SpeedResult {
	if !speedMu.TryLock() {
		return SpeedResult{Error: "已有测速在进行中"}
	}
	defer speedMu.Unlock()
	res := SpeedResult{TS: time.Now().Unix()}
	cl := &http.Client{Timeout: 30 * time.Second}

	// latency + colo from the trace endpoint
	var lat []float64
	for i := 0; i < 5; i++ {
		t0 := time.Now()
		resp, err := cl.Get("https://speed.cloudflare.com/cdn-cgi/trace")
		if err != nil {
			continue
		}
		b, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		lat = append(lat, float64(time.Since(t0).Microseconds())/1000)
		for _, line := range strings.Split(string(b), "\n") {
			if strings.HasPrefix(line, "colo=") {
				res.Server = "Cloudflare " + strings.TrimPrefix(line, "colo=")
			}
		}
	}
	if len(lat) == 0 {
		res.Error = "无法连接测速服务器"
		return res
	}
	minLat := lat[0]
	for _, v := range lat {
		minLat = math.Min(minLat, v)
	}
	res.LatencyMs = round1(minLat)

	// download: 4 parallel streams for ~8 s; Cloudflare rejects single requests over ~25 MB
	res.DownMbps = parallelTransfer(8*time.Second, 4, func(ctx context.Context) int64 {
		var got int64
		for ctx.Err() == nil {
			req, _ := http.NewRequestWithContext(ctx, "GET", "https://speed.cloudflare.com/__down?bytes=25000000", nil)
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				break
			}
			if resp.StatusCode != 200 {
				resp.Body.Close()
				break
			}
			n, _ := io.Copy(io.Discard, resp.Body) // partial count when the deadline hits
			resp.Body.Close()
			got += n
		}
		return got
	})
	// upload: 4 parallel streams for ~8 s; only completed uploads count
	payload := bytes.Repeat([]byte{0}, 2<<20)
	res.UpMbps = parallelTransfer(8*time.Second, 4, func(ctx context.Context) int64 {
		var sent int64
		for ctx.Err() == nil {
			req, _ := http.NewRequestWithContext(ctx, "POST", "https://speed.cloudflare.com/__up", bytes.NewReader(payload))
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				break
			}
			_, _ = io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
			if resp.StatusCode != 200 {
				break
			}
			sent += int64(len(payload))
		}
		return sent
	})
	if res.DownMbps == 0 && res.UpMbps == 0 {
		res.Error = "测速失败：Cloudflare 测速节点拒绝了请求"
	}
	return res
}

func parallelTransfer(d time.Duration, streams int, f func(ctx context.Context) int64) float64 {
	ctx, cancel := context.WithTimeout(context.Background(), d)
	defer cancel()
	var total int64
	var mu sync.Mutex
	var wg sync.WaitGroup
	start := time.Now()
	for i := 0; i < streams; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			n := f(ctx)
			mu.Lock()
			total += n
			mu.Unlock()
		}()
	}
	wg.Wait()
	secs := time.Since(start).Seconds()
	if secs <= 0 {
		return 0
	}
	return round1(float64(total) * 8 / secs / 1e6)
}

// SpeedTestOokla runs a test against the nearest speedtest.net (Ookla) server using
// the open-source speedtest-go client.
func SpeedTestOokla() SpeedResult {
	if !speedMu.TryLock() {
		return SpeedResult{Error: "已有测速在进行中"}
	}
	defer speedMu.Unlock()
	res := SpeedResult{TS: time.Now().Unix()}
	st := speedtest.New()
	servers, err := st.FetchServers()
	if err != nil {
		res.Error = "无法获取 Speedtest 服务器列表"
		return res
	}
	targets, err := servers.FindServer(nil)
	if err != nil || len(targets) == 0 {
		res.Error = "没有可用的 Speedtest 服务器"
		return res
	}
	s := targets[0]
	if err := s.PingTest(nil); err != nil {
		res.Error = "无法连接 " + s.Sponsor
		return res
	}
	_ = s.DownloadTest()
	_ = s.UploadTest()
	res.Server = fmt.Sprintf("Speedtest.net · %s（%s）", s.Sponsor, s.Name)
	res.LatencyMs = round1(float64(s.Latency.Microseconds()) / 1000)
	res.DownMbps = round1(float64(s.DLSpeed) * 8 / 1e6)
	res.UpMbps = round1(float64(s.ULSpeed) * 8 / 1e6)
	s.Context.Reset()
	return res
}

// WANList returns every IPv4 interface in the firewall's WAN zone(s) (a zone named
// "wan" or with masquerading) that exists in /etc/config/network.
func WANList() []WanStatus {
	fw, err := uciGetConfig("firewall")
	if err != nil {
		return nil
	}
	seen := map[string]bool{}
	var out []WanStatus
	names := make([]string, 0, len(fw))
	for n := range fw {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		z := fw[n]
		if z[".type"] != "zone" || (fmt.Sprint(z["name"]) != "wan" && fmt.Sprint(z["masq"]) != "1") {
			continue
		}
		var nets []string
		switch v := z["network"].(type) {
		case string:
			nets = strings.Fields(v)
		case []any:
			for _, x := range v {
				nets = append(nets, fmt.Sprint(x))
			}
		}
		for _, iface := range nets {
			if seen[iface] {
				continue
			}
			seen[iface] = true
			var probe map[string]any
			if ubusCall("network.interface."+iface, "status", nil, &probe) != nil {
				continue // listed in the zone but not configured
			}
			w := WANStatus(iface)
			if strings.HasPrefix(w.Proto, "dhcpv6") || w.Proto == "6in4" || w.Proto == "6to4" || w.Proto == "6rd" || w.Proto == "dslite" {
				continue // IPv6-only; port forwards are IPv4
			}
			if w.Device == "" {
				w.Device = uciValue("network." + iface + ".device")
			}
			out = append(out, w)
		}
	}
	return out
}

// Listener is a port the router itself listens on.
type Listener struct {
	Port  int    `json:"port"`
	Proto string `json:"proto"`
	Proc  string `json:"proc"`
	Local bool   `json:"local"` // bound to loopback only (not reachable from WAN)
}

// Listeners parses /proc/net/{tcp,udp}{,6} and maps socket inodes to process names.
func Listeners() []Listener {
	procOf := map[string]string{}
	pids, _ := filepath.Glob("/proc/[0-9]*/fd")
	for _, fdDir := range pids {
		ents, err := os.ReadDir(fdDir)
		if err != nil {
			continue
		}
		comm := readTrim(filepath.Join(filepath.Dir(fdDir), "comm"))
		for _, e := range ents {
			if l, err := os.Readlink(filepath.Join(fdDir, e.Name())); err == nil && strings.HasPrefix(l, "socket:[") {
				procOf[strings.TrimSuffix(strings.TrimPrefix(l, "socket:["), "]")] = comm
			}
		}
	}
	type key struct {
		port  int
		proto string
	}
	seen := map[key]int{}
	var out []Listener
	for _, f := range []string{"tcp", "tcp6", "udp", "udp6"} {
		b, err := os.ReadFile("/proc/net/" + f)
		if err != nil {
			continue
		}
		proto := strings.TrimSuffix(f, "6")
		for i, line := range strings.Split(string(b), "\n") {
			fs := strings.Fields(line)
			if i == 0 || len(fs) < 10 {
				continue
			}
			if proto == "tcp" && fs[3] != "0A" { // LISTEN
				continue
			}
			if proto == "udp" && fs[2] != "00000000:0000" && !strings.HasPrefix(fs[2], "00000000000000000000000000000000:") {
				continue // connected UDP sockets are clients
			}
			addr, portHex, ok := strings.Cut(fs[1], ":")
			if !ok {
				continue
			}
			port, _ := strconv.ParseInt(portHex, 16, 32)
			local := addr == "0100007F" || addr == "00000000000000000000000001000000"
			k := key{int(port), proto}
			if j, dup := seen[k]; dup {
				out[j].Local = out[j].Local && local
				continue
			}
			seen[k] = len(out)
			out = append(out, Listener{Port: int(port), Proto: proto, Proc: procOf[fs[9]], Local: local})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Port < out[j].Port })
	return out
}
