package agent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Network diagnostics run from the router: route trace (mtr), TCP ping, DNS lookups
// against several resolvers, HTTP timing (curl) and iperf3 (client and a temporary server).
// Every target is validated and passed as a single argv entry — never through a shell.

var (
	diagSem  = make(chan struct{}, 2) // the router is not a benchmark box: two tools at a time
	hostRe   = regexp.MustCompile(`^[A-Za-z0-9]([A-Za-z0-9-]{0,62}[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]{0,62}[A-Za-z0-9])?)*\.?$`)
	errBusy  = errors.New("路由器上已有两个诊断任务在运行，请稍后再试")
	errHost  = errors.New("目标应为域名或 IP 地址")
	dnsTypes = map[string]bool{"A": true, "AAAA": true, "CNAME": true, "MX": true, "TXT": true, "NS": true, "SOA": true, "PTR": true, "HTTPS": true}
)

func diagSlot() (func(), error) {
	select {
	case diagSem <- struct{}{}:
		return func() { <-diagSem }, nil
	default:
		return nil, errBusy
	}
}

func validHost(h string) (string, error) {
	h = strings.TrimSpace(h)
	if ip := net.ParseIP(h); ip != nil {
		return ip.String(), nil
	}
	if len(h) > 253 || !hostRe.MatchString(h) {
		return "", errHost
	}
	return strings.TrimSuffix(h, "."), nil
}

// DiagReq is the panel's request; which fields apply depends on Tool.
type DiagReq struct {
	Tool    string   `json:"tool"`
	Target  string   `json:"target"`
	Mode    string   `json:"mode"`    // trace: icmp | tcp | udp ; iperf: tcp | udp
	Port    int      `json:"port"`    // trace tcp/udp, tcping, iperf
	Count   int      `json:"count"`   // trace cycles, tcping attempts
	IPv     int      `json:"ipv"`     // 0 auto, 4, 6
	Type    string   `json:"type"`    // dns record type
	Servers []string `json:"servers"` // dns resolvers ("" = the router's own dnsmasq)
	Reverse bool     `json:"reverse"` // iperf: device → router instead of router → device
	Secs    int      `json:"secs"`    // iperf duration, iperf server lifetime (minutes)
	Streams int      `json:"streams"` // iperf parallel streams
	Rate    string   `json:"rate"`    // iperf udp bandwidth, e.g. 100M
	Ports   bool     `json:"ports"`   // scan: also probe common service ports
}

var probeSem = make(chan struct{}, 4) // monitors have their own budget so manual tools can't starve them

func clamp(v, lo, hi, def int) int {
	if v == 0 {
		return def
	}
	return max(lo, min(hi, v))
}

func Diag(req DiagReq) (any, error) {
	switch req.Tool {
	case "iperf-server":
		return IperfServerStart(req.Port, clamp(req.Secs, 1, 60, 10))
	case "iperf-server-stop":
		IperfServerStop()
		return IperfServerStatus(), nil
	case "fingerprint":
		probeSem <- struct{}{}
		defer func() { <-probeSem }()
		return fingerprintReq(req)
	case "probe":
		probeSem <- struct{}{}
		defer func() { <-probeSem }()
		return Probe(req)
	}
	done, err := diagSlot()
	if err != nil {
		return nil, err
	}
	defer done()
	switch req.Tool {
	case "trace":
		return Trace(req)
	case "tcping":
		return TCPing(req)
	case "dns":
		return DNSQuery(req)
	case "http":
		return HTTPCheck(req.Target)
	case "iperf":
		return IperfClient(req)
	case "scan":
		return ScanLAN(req.Ports)
	}
	return nil, errors.New("unknown tool")
}

// ---- route trace ----

type TraceHop struct {
	Hop   int     `json:"hop"`
	IP    string  `json:"ip,omitempty"` // empty = no reply
	Host  string  `json:"host,omitempty"`
	Loss  float64 `json:"loss"`
	Sent  int     `json:"sent"`
	Last  float64 `json:"last"`
	Avg   float64 `json:"avg"`
	Best  float64 `json:"best"`
	Worst float64 `json:"worst"`
	StDev float64 `json:"stdev"`
}

type TraceResult struct {
	Target string     `json:"target"`
	IP     string     `json:"ip"`
	Mode   string     `json:"mode"`
	Hops   []TraceHop `json:"hops"`
	Secs   float64    `json:"secs"`
}

func Trace(req DiagReq) (*TraceResult, error) {
	host, err := validHost(req.Target)
	if err != nil {
		return nil, err
	}
	ip, err := resolveOne(host, req.IPv)
	if err != nil {
		return nil, err
	}
	cycles := clamp(req.Count, 1, 20, 5)
	args := []string{"--json", "-n", "-c", strconv.Itoa(cycles), "-i", "0.5", "-G", "1", "-m", "30", "-Z", "1", "-U", "6"}
	mode := "icmp"
	switch req.Mode {
	case "tcp":
		mode = "tcp"
		args = append(args, "-T", "-P", strconv.Itoa(clamp(req.Port, 1, 65535, 443)))
	case "udp":
		mode = "udp"
		args = append(args, "-u")
		if req.Port > 0 {
			args = append(args, "-P", strconv.Itoa(clamp(req.Port, 1, 65535, 33434)))
		}
	}
	args = append(args, ip)
	start := time.Now()
	out, err := run(time.Duration(cycles)*time.Second+40*time.Second, "mtr", args...)
	if err != nil && len(out) == 0 {
		return nil, fmt.Errorf("mtr: %v", err)
	}
	var rep struct {
		Report struct {
			Hubs []struct {
				Count int     `json:"count"`
				Host  string  `json:"host"`
				Loss  float64 `json:"Loss%"`
				Snt   int     `json:"Snt"`
				Last  float64 `json:"Last"`
				Avg   float64 `json:"Avg"`
				Best  float64 `json:"Best"`
				Wrst  float64 `json:"Wrst"`
				StDev float64 `json:"StDev"`
			} `json:"hubs"`
		} `json:"report"`
	}
	if err := json.Unmarshal(out, &rep); err != nil {
		return nil, fmt.Errorf("mtr 输出无法解析：%v", err)
	}
	res := &TraceResult{Target: host, IP: ip, Mode: mode}
	for _, h := range rep.Report.Hubs {
		hop := TraceHop{Hop: h.Count, Loss: h.Loss, Sent: h.Snt, Last: h.Last, Avg: h.Avg, Best: h.Best, Worst: h.Wrst, StDev: h.StDev}
		if net.ParseIP(h.Host) != nil {
			hop.IP = h.Host
		}
		res.Hops = append(res.Hops, hop)
	}
	reverseNames(res.Hops)
	res.Secs = time.Since(start).Seconds()
	return res, nil
}

func reverseNames(hops []TraceHop) {
	var wg sync.WaitGroup
	r := &net.Resolver{}
	for i := range hops {
		if hops[i].IP == "" {
			continue
		}
		wg.Add(1)
		go func(h *TraceHop) {
			defer wg.Done()
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			if names, err := r.LookupAddr(ctx, h.IP); err == nil && len(names) > 0 {
				h.Host = strings.TrimSuffix(names[0], ".")
			}
		}(&hops[i])
	}
	wg.Wait()
}

func resolveOne(host string, ipv int) (string, error) {
	if ip := net.ParseIP(host); ip != nil {
		return ip.String(), nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	network := "ip4"
	if ipv == 6 {
		network = "ip6"
	}
	ips, err := net.DefaultResolver.LookupIP(ctx, network, host)
	if err != nil || len(ips) == 0 {
		return "", fmt.Errorf("无法解析 %s", host)
	}
	return ips[0].String(), nil
}

// ---- TCP ping ----

type TCPingResult struct {
	Target string    `json:"target"`
	IP     string    `json:"ip"`
	Port   int       `json:"port"`
	RTTs   []float64 `json:"rtts"` // ms; -1 = failed
	Errors []string  `json:"errors,omitempty"`
}

func TCPing(req DiagReq) (*TCPingResult, error) {
	host, err := validHost(req.Target)
	if err != nil {
		return nil, err
	}
	if req.Port < 1 || req.Port > 65535 {
		return nil, errors.New("端口应为 1–65535")
	}
	ip, err := resolveOne(host, req.IPv)
	if err != nil {
		return nil, err
	}
	res := &TCPingResult{Target: host, IP: ip, Port: req.Port}
	addr := net.JoinHostPort(ip, strconv.Itoa(req.Port))
	n := clamp(req.Count, 1, 20, 5)
	for i := 0; i < n; i++ {
		if i > 0 {
			time.Sleep(300 * time.Millisecond)
		}
		t := time.Now()
		c, err := net.DialTimeout("tcp", addr, 3*time.Second)
		if err != nil {
			res.RTTs = append(res.RTTs, -1)
			msg := err.Error()
			switch {
			case strings.Contains(msg, "refused"):
				msg = "连接被拒绝（端口未开放）"
			case strings.Contains(msg, "timeout"):
				msg = "超时（可能被防火墙丢弃）"
			}
			if !contains(res.Errors, msg) {
				res.Errors = append(res.Errors, msg)
			}
			continue
		}
		res.RTTs = append(res.RTTs, float64(time.Since(t).Microseconds())/1000)
		c.Close()
	}
	return res, nil
}

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

// ---- DNS ----

type DNSAnswer struct {
	Server  string   `json:"server"`
	Records []string `json:"records"`
	Status  string   `json:"status"`
	MS      int      `json:"ms"`
	Error   string   `json:"error,omitempty"`
}

var dnsStatusRe = regexp.MustCompile(`status: ([A-Z]+)`)
var dnsTimeRe = regexp.MustCompile(`Query time: (\d+) msec`)

func DNSQuery(req DiagReq) ([]DNSAnswer, error) {
	name, err := validHost(req.Target)
	if err != nil {
		return nil, err
	}
	typ := strings.ToUpper(req.Type)
	if typ == "" {
		typ = "A"
	}
	if !dnsTypes[typ] {
		return nil, errors.New("不支持的记录类型")
	}
	if typ == "PTR" {
		if ip := net.ParseIP(name); ip != nil {
			name = reverseArpa(ip)
		}
	}
	servers := req.Servers
	if len(servers) == 0 {
		servers = []string{""}
	}
	if len(servers) > 6 {
		servers = servers[:6]
	}
	out := make([]DNSAnswer, len(servers))
	var wg sync.WaitGroup
	for i, s := range servers {
		s = strings.TrimSpace(s)
		label := s
		if s == "" {
			s, label = "127.0.0.1", "路由器（dnsmasq）"
		} else if net.ParseIP(s) == nil {
			out[i] = DNSAnswer{Server: s, Error: "DNS 服务器应为 IP 地址"}
			continue
		}
		wg.Add(1)
		go func(i int, server, label string) {
			defer wg.Done()
			a := DNSAnswer{Server: label}
			b, err := run(8*time.Second, "dig", "@"+server, "+time=3", "+tries=1", "+noall", "+answer", "+comments", "+stats", "-t", typ, "-q", name) // dig has no "--"; validHost already rules out a leading "-"
			text := string(b)
			if m := dnsTimeRe.FindStringSubmatch(text); m != nil {
				a.MS, _ = strconv.Atoi(m[1])
			}
			if m := dnsStatusRe.FindStringSubmatch(text); m != nil {
				a.Status = m[1]
			}
			for _, line := range strings.Split(text, "\n") {
				f := strings.Fields(line)
				if len(f) >= 5 && !strings.HasPrefix(line, ";") {
					a.Records = append(a.Records, f[3]+" "+strings.Join(f[4:], " "))
				}
			}
			if err != nil && a.Status == "" {
				a.Error = "无响应"
				if strings.Contains(text, "timed out") || strings.Contains(err.Error(), "timed out") {
					a.Error = "超时"
				}
			}
			out[i] = a
		}(i, s, label)
	}
	wg.Wait()
	return out, nil
}

func reverseArpa(ip net.IP) string {
	if v4 := ip.To4(); v4 != nil {
		return fmt.Sprintf("%d.%d.%d.%d.in-addr.arpa", v4[3], v4[2], v4[1], v4[0])
	}
	const hex = "0123456789abcdef"
	var b strings.Builder
	for i := len(ip) - 1; i >= 0; i-- {
		b.WriteByte(hex[ip[i]&0xf])
		b.WriteByte('.')
		b.WriteByte(hex[ip[i]>>4])
		b.WriteByte('.')
	}
	return b.String() + "ip6.arpa"
}

// ---- HTTP timing ----

type HTTPResult struct {
	URL      string  `json:"url"`
	Code     int     `json:"code"`
	RemoteIP string  `json:"remote_ip"`
	DNS      float64 `json:"dns"`      // ms, cumulative like curl
	Connect  float64 `json:"connect"`  //
	TLS      float64 `json:"tls"`      //
	TTFB     float64 `json:"ttfb"`     //
	Total    float64 `json:"total"`    //
	Size     int64   `json:"size"`     // bytes downloaded (capped)
	Speed    float64 `json:"speed"`    // bytes/s
	Redirect string  `json:"redirect"` // Location when 3xx
	HTTPVer  string  `json:"http_version"`
	Error    string  `json:"error,omitempty"`
}

func HTTPCheck(raw string) (*HTTPResult, error) {
	raw = strings.TrimSpace(raw)
	if !strings.Contains(raw, "://") {
		raw = "https://" + raw
	}
	u, err := url.Parse(raw)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.User != nil {
		return nil, errors.New("网址应以 http:// 或 https:// 开头")
	}
	if _, err := validHost(u.Hostname()); err != nil {
		return nil, err
	}
	out, err := run(25*time.Second, "curl", "-sS", "-o", "/dev/null", "--max-time", "20", "--max-filesize", "52428800",
		"-A", "Mozilla/5.0 (Wharf diagnostics)", "-w", "%{json}", "--proto", "=http,https", "--", u.String())
	var w struct {
		Code     int     `json:"http_code"`
		RemoteIP string  `json:"remote_ip"`
		DNS      float64 `json:"time_namelookup"`
		Connect  float64 `json:"time_connect"`
		TLS      float64 `json:"time_appconnect"`
		TTFB     float64 `json:"time_starttransfer"`
		Total    float64 `json:"time_total"`
		Size     float64 `json:"size_download"`
		Speed    float64 `json:"speed_download"`
		Redirect string  `json:"redirect_url"`
		HTTPVer  string  `json:"http_version"`
		ErrMsg   string  `json:"errormsg"`
	}
	if jerr := json.Unmarshal(out, &w); jerr != nil {
		if err != nil {
			return nil, fmt.Errorf("curl: %v", err)
		}
		return nil, jerr
	}
	ms := func(s float64) float64 { return float64(int(s*10000)) / 10 }
	return &HTTPResult{URL: u.String(), Code: w.Code, RemoteIP: w.RemoteIP, DNS: ms(w.DNS), Connect: ms(w.Connect), TLS: ms(w.TLS),
		TTFB: ms(w.TTFB), Total: ms(w.Total), Size: int64(w.Size), Speed: w.Speed, Redirect: w.Redirect, HTTPVer: w.HTTPVer, Error: w.ErrMsg}, nil
}
