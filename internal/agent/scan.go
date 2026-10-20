package agent

import (
	"context"
	"errors"
	"math"
	"net"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// LAN scan: wake every address in the LAN subnet with one ping (which also makes the
// kernel ARP for it, so devices that ignore ICMP still show up in the neighbour table),
// then optionally probe common service ports on whatever answered.

type ScanHost struct {
	IP    string     `json:"ip"`
	MAC   string     `json:"mac"`
	Ping  bool       `json:"ping"`   // answered ICMP
	RTT   float64    `json:"rtt_ms"` // ping RTT
	Ports []ScanPort `json:"ports"`
}

type ScanPort struct {
	Port    int    `json:"port"`
	Service string `json:"service"`
}

type ScanResult struct {
	Subnet string     `json:"subnet"`
	Hosts  []ScanHost `json:"hosts"`
	Secs   float64    `json:"secs"`
	Ports  bool       `json:"ports"`
}

var scanPorts = []struct {
	port int
	name string
}{
	{21, "FTP"}, {22, "SSH"}, {23, "Telnet"}, {53, "DNS"}, {80, "Web"}, {139, "SMB"}, {443, "HTTPS"}, {445, "SMB 共享"},
	{515, "打印机 LPD"}, {548, "AFP（Mac 共享）"}, {554, "RTSP 摄像头"}, {631, "打印机 IPP"}, {1883, "MQTT"}, {3000, "Web 应用"},
	{3389, "远程桌面"}, {5000, "群晖 / Web"}, {5001, "群晖 HTTPS"}, {5900, "VNC"}, {6443, "Kubernetes"}, {7080, "Wharf"},
	{8006, "PVE"}, {8080, "Web 备用"}, {8123, "Home Assistant"}, {8443, "HTTPS 备用"}, {8888, "Web 备用"}, {9000, "Portainer / Web"},
	{9100, "打印机 RAW"}, {32400, "Plex"}, {62078, "iPhone 同步"}, {10000, "Webmin"}, {2049, "NFS"}, {111, "RPC"},
}

var pingRTTRe = regexp.MustCompile(`time=([\d.]+) ?ms`)

func lanSubnet() (*net.IPNet, net.IP, error) {
	dev := uciGetOption("network", "lan", "device")
	if dev == "" {
		dev = "br-lan"
	}
	ifc, err := net.InterfaceByName(dev)
	if err != nil {
		return nil, nil, errors.New("找不到局域网接口 " + dev)
	}
	addrs, _ := ifc.Addrs()
	for _, a := range addrs {
		if n, ok := a.(*net.IPNet); ok && n.IP.To4() != nil {
			ones, _ := n.Mask.Size()
			if ones < 22 { // keep it polite: a /16 would be 65k pings
				n = &net.IPNet{IP: n.IP.Mask(net.CIDRMask(24, 32)), Mask: net.CIDRMask(24, 32)}
			}
			return &net.IPNet{IP: n.IP.Mask(n.Mask), Mask: n.Mask}, n.IP.To4(), nil
		}
	}
	return nil, nil, errors.New("局域网接口没有 IPv4 地址")
}

func ScanLAN(withPorts bool) (*ScanResult, error) {
	subnet, self, err := lanSubnet()
	if err != nil {
		return nil, err
	}
	start := time.Now()
	base := ipToU32(subnet.IP)
	ones, bits := subnet.Mask.Size()
	size := uint32(1) << (bits - ones)
	type pr struct {
		ok  bool
		rtt float64
	}
	pings := map[string]pr{}
	var mu sync.Mutex
	var wg sync.WaitGroup
	sem := make(chan struct{}, 64)
	for i := uint32(1); i < size-1; i++ {
		ip := u32ToIP(base + i)
		if ip.Equal(self) {
			continue
		}
		wg.Add(1)
		sem <- struct{}{}
		go func(ip string) {
			defer func() { <-sem; wg.Done() }()
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			out, err := runCtx(ctx, "ping", "-c", "1", "-W", "1", ip)
			if err == nil {
				r := pr{ok: true}
				if m := pingRTTRe.FindSubmatch(out); m != nil {
					r.rtt, _ = strconv.ParseFloat(string(m[1]), 64)
				}
				mu.Lock()
				pings[ip] = r
				mu.Unlock()
			}
		}(ip.String())
	}
	wg.Wait()
	time.Sleep(1500 * time.Millisecond) // ARP answers for ICMP-silent devices

	res := &ScanResult{Subnet: subnet.String(), Ports: withPorts}
	seen := map[string]bool{}
	for _, n := range lanNeighbours() {
		ip := net.ParseIP(n.ip)
		if ip == nil || !subnet.Contains(ip) || n.state == "FAILED" || n.state == "INCOMPLETE" || seen[n.ip] {
			continue
		}
		seen[n.ip] = true
		p := pings[n.ip]
		res.Hosts = append(res.Hosts, ScanHost{IP: n.ip, MAC: n.mac, Ping: p.ok, RTT: p.rtt})
	}
	for ip, p := range pings { // answered ping but no neighbour entry (unlikely)
		if !seen[ip] {
			res.Hosts = append(res.Hosts, ScanHost{IP: ip, Ping: true, RTT: p.rtt})
		}
	}
	sort.Slice(res.Hosts, func(i, j int) bool {
		return ipToU32(net.ParseIP(res.Hosts[i].IP)) < ipToU32(net.ParseIP(res.Hosts[j].IP))
	})

	if withPorts && len(res.Hosts) > 0 {
		sem := make(chan struct{}, 200)
		for hi := range res.Hosts {
			for _, sp := range scanPorts {
				wg.Add(1)
				sem <- struct{}{}
				go func(h *ScanHost, port int, name string) {
					defer func() { <-sem; wg.Done() }()
					c, err := net.DialTimeout("tcp", net.JoinHostPort(h.IP, strconv.Itoa(port)), 800*time.Millisecond)
					if err != nil {
						return
					}
					c.Close()
					mu.Lock()
					h.Ports = append(h.Ports, ScanPort{port, name})
					mu.Unlock()
				}(&res.Hosts[hi], sp.port, sp.name)
			}
		}
		wg.Wait()
		for i := range res.Hosts {
			sort.Slice(res.Hosts[i].Ports, func(a, b int) bool { return res.Hosts[i].Ports[a].Port < res.Hosts[i].Ports[b].Port })
		}
	}
	res.Secs = math.Round(time.Since(start).Seconds()*10) / 10
	return res, nil
}

func ipToU32(ip net.IP) uint32 {
	v := ip.To4()
	if v == nil {
		return 0
	}
	return uint32(v[0])<<24 | uint32(v[1])<<16 | uint32(v[2])<<8 | uint32(v[3])
}

func u32ToIP(v uint32) net.IP { return net.IPv4(byte(v>>24), byte(v>>16), byte(v>>8), byte(v)) }

// ---- monitor probe ----

// ProbeResult is one round of a monitor: ICMP pings, or TCP connects from fresh source
// ports (so a load-balanced path with one broken member shows up as partial failure).
type ProbeResult struct {
	Sent   int       `json:"sent"`
	Recv   int       `json:"recv"`
	Min    float64   `json:"min"`
	Avg    float64   `json:"avg"`
	Max    float64   `json:"max"`
	Jitter float64   `json:"jitter"`
	RTTs   []float64 `json:"rtts"`
	IP     string    `json:"ip"`
	Error  string    `json:"error,omitempty"`
}

var pingSeqRe = regexp.MustCompile(`seq=\d+ ttl=\d+ time=([\d.]+) ?ms`)

func Probe(req DiagReq) (*ProbeResult, error) {
	host, err := validHost(req.Target)
	if err != nil {
		return nil, err
	}
	ip, err := resolveOne(host, req.IPv)
	if err != nil {
		return &ProbeResult{Error: err.Error()}, nil
	}
	n := clamp(req.Count, 1, 30, 10)
	res := &ProbeResult{IP: ip, Sent: n}
	if req.Mode == "tcp" {
		if req.Port < 1 || req.Port > 65535 {
			return nil, errors.New("端口应为 1–65535")
		}
		addr := net.JoinHostPort(ip, strconv.Itoa(req.Port))
		for i := 0; i < n; i++ {
			if i > 0 {
				time.Sleep(300 * time.Millisecond)
			}
			t := time.Now()
			c, err := net.DialTimeout("tcp", addr, 3*time.Second)
			if err != nil {
				if strings.Contains(err.Error(), "refused") && res.Error == "" {
					res.Error = "端口未开放（连接被拒绝）"
				}
				continue
			}
			res.RTTs = append(res.RTTs, float64(time.Since(t).Microseconds())/1000)
			c.Close()
		}
	} else {
		out, _ := run(time.Duration(n)*time.Second+10*time.Second, "ping", "-c", strconv.Itoa(n), "-W", "2", ip)
		for _, m := range pingSeqRe.FindAllSubmatch(out, -1) {
			v, _ := strconv.ParseFloat(string(m[1]), 64)
			res.RTTs = append(res.RTTs, v)
		}
	}
	res.Recv = len(res.RTTs)
	if res.Recv > 0 {
		res.Min, res.Max = res.RTTs[0], res.RTTs[0]
		var sum, jit float64
		for i, v := range res.RTTs {
			sum += v
			res.Min, res.Max = math.Min(res.Min, v), math.Max(res.Max, v)
			if i > 0 {
				jit += math.Abs(v - res.RTTs[i-1])
			}
		}
		res.Avg = round1(sum / float64(res.Recv))
		if res.Recv > 1 {
			res.Jitter = round1(jit / float64(res.Recv-1))
		}
		res.Min, res.Max = round1(res.Min), round1(res.Max)
	}
	return res, nil
}
