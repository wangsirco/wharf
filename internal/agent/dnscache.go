package agent

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

// DNS caches along the home's resolver chain: devices → dnsmasq → a local
// resolver plugin (NextDNS, ...) → its cloud → the domain's own name servers.
// A name that did not exist a minute ago is remembered as "does not exist" by
// every cache on that path for the zone's negative TTL (30 min on Cloudflare),
// so a freshly created record stays invisible at home. DNSTrace asks every layer
// and says which one is stale; DNSFlush empties the ones that can be emptied.

type DNSUpstream struct {
	Addr  string `json:"addr"`            // as written in dnsmasq: 127.0.0.1#5342, 223.5.5.5, /lan/...
	Port  int    `json:"port,omitempty"`  // local upstreams
	Proc  string `json:"proc,omitempty"`  // process listening there
	Kind  string `json:"kind"`            // nextdns | smartdns | adguardhome | mosdns | openclash | local | remote
	Flush bool   `json:"flush,omitempty"` // Wharf can empty its cache
}

type NextDNSInfo struct {
	Running     bool   `json:"running"`
	Profile     string `json:"profile"`
	CacheSize   string `json:"cache_size"`
	CacheMaxAge string `json:"cache_max_age"`
	MaxTTL      string `json:"max_ttl"`
	Hit         int64  `json:"hit"`
	Miss        int64  `json:"miss"`
	Entries     int    `json:"entries"`
	Since       int64  `json:"since"` // process start (unix), i.e. when the cache was last emptied
}

type DNSCacheInfo struct {
	DnsmasqCache int           `json:"dnsmasq_cache"`
	DnsmasqSince int64         `json:"dnsmasq_since"`
	Rebind       bool          `json:"rebind_protection"`
	Upstreams    []DNSUpstream `json:"upstreams"`
	NextDNS      *NextDNSInfo  `json:"nextdns,omitempty"`
}

func dnsmasqConf() (servers []string, cache int, rebind bool) {
	cache = 150
	files, _ := filepath.Glob("/var/etc/dnsmasq.conf.*")
	for _, f := range files {
		b, err := os.ReadFile(f)
		if err != nil {
			continue
		}
		for _, l := range strings.Split(string(b), "\n") {
			l = strings.TrimSpace(l)
			switch {
			case strings.HasPrefix(l, "server="):
				servers = append(servers, strings.TrimPrefix(l, "server="))
			case strings.HasPrefix(l, "cache-size="):
				cache, _ = strconv.Atoi(strings.TrimPrefix(l, "cache-size="))
			case l == "stop-dns-rebind":
				rebind = true
			}
		}
	}
	return
}

func kindOfProc(p string) string {
	p = strings.ToLower(p)
	for _, k := range []string{"nextdns", "smartdns", "adguardhome", "mosdns", "clash"} {
		if strings.Contains(p, k) {
			if k == "clash" {
				return "openclash"
			}
			return k
		}
	}
	return "local"
}

func dnsUpstreams() []DNSUpstream {
	servers, _, _ := dnsmasqConf()
	procs := map[int]string{}
	for _, l := range Listeners() {
		if l.Proto == "udp" {
			procs[l.Port] = l.Proc
		}
	}
	var out []DNSUpstream
	for _, s := range servers {
		u := DNSUpstream{Addr: s, Kind: "remote"}
		if !strings.HasPrefix(s, "/") { // per-domain servers (/lan/...) are not the general upstream
			host, port, _ := strings.Cut(s, "#")
			if ip, err := netip.ParseAddr(host); err == nil && ip.IsLoopback() {
				u.Port = 53
				if port != "" {
					u.Port, _ = strconv.Atoi(port)
				}
				u.Proc = procs[u.Port]
				u.Kind = kindOfProc(u.Proc)
				u.Flush = u.Kind == "nextdns"
			}
		}
		out = append(out, u)
	}
	return out
}

func procStart(exe string) int64 {
	var btime int64
	if b, err := os.ReadFile("/proc/stat"); err == nil {
		for _, l := range strings.Split(string(b), "\n") {
			if strings.HasPrefix(l, "btime ") {
				btime, _ = strconv.ParseInt(strings.TrimSpace(l[6:]), 10, 64)
			}
		}
	}
	for _, pid := range pidsOf(exe) {
		b, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/stat")
		if err != nil || btime == 0 {
			continue
		}
		// fields after the ")" of comm; starttime is field 22 overall, i.e. index 19 here (USER_HZ = 100)
		_, rest, ok := strings.Cut(string(b), ") ")
		f := strings.Fields(rest)
		if !ok || len(f) < 20 {
			continue
		}
		if j, err := strconv.ParseInt(f[19], 10, 64); err == nil {
			return btime + j/100
		}
	}
	return 0
}

// pidsOf finds processes by executable path (not by name: ujail wrappers carry the same name).
func pidsOf(exe string) []int {
	var out []int
	dirs, _ := filepath.Glob("/proc/[0-9]*")
	for _, d := range dirs {
		if l, err := os.Readlink(d + "/exe"); err == nil && (l == exe || strings.TrimSuffix(l, " (deleted)") == exe) {
			if pid, err := strconv.Atoi(filepath.Base(d)); err == nil {
				out = append(out, pid)
			}
		}
	}
	return out
}

func nextDNSInfo() *NextDNSInfo {
	if !fileExists("/etc/config/nextdns") {
		return nil
	}
	n := &NextDNSInfo{
		Profile: uciValue("nextdns.main.profile"), CacheSize: uciValue("nextdns.main.cache_size"),
		CacheMaxAge: uciValue("nextdns.main.cache_max_age"), MaxTTL: uciValue("nextdns.main.max_ttl"),
	}
	n.Since = procStart("/usr/sbin/nextdns")
	n.Running = n.Since > 0
	if !n.Running {
		return n
	}
	if b, err := run(5*time.Second, "nextdns", "cache-stats"); err == nil {
		var st struct{ Hit, Miss int64 }
		if json.Unmarshal(b, &st) == nil {
			n.Hit, n.Miss = st.Hit, st.Miss
		}
	}
	if b, err := run(8*time.Second, "nextdns", "cache-keys"); err == nil {
		var keys []string
		if json.Unmarshal(b, &keys) == nil {
			n.Entries = len(keys)
		}
	}
	return n
}

func GetDNSCache() DNSCacheInfo {
	_, cache, rebind := dnsmasqConf()
	return DNSCacheInfo{DnsmasqCache: cache, DnsmasqSince: procStart("/usr/sbin/dnsmasq"), Rebind: rebind, Upstreams: dnsUpstreams(), NextDNS: nextDNSInfo()}
}

// ---- tracing one name through every layer ----

type DNSLayer struct {
	ID      string   `json:"id"` // dnsmasq | upstream | cloud | public | auth
	Label   string   `json:"label"`
	Server  string   `json:"server"`
	Status  string   `json:"status,omitempty"` // NOERROR | NXDOMAIN | SERVFAIL ...
	Records []string `json:"records"`          // "A 1.2.3.4", "CNAME x."
	Addrs   []string `json:"addrs"`            // final A / AAAA data
	TTL     int      `json:"ttl"`              // smallest answer TTL, or the SOA TTL for an empty answer
	MS      int      `json:"ms"`
	Cached  *bool    `json:"cached,omitempty"` // NextDNS: the name is in its local cache
	Error   string   `json:"error,omitempty"`
}

type DNSTrace struct {
	Name    string     `json:"name"`
	Type    string     `json:"type"`
	Zone    string     `json:"zone,omitempty"`
	NS      string     `json:"ns,omitempty"`
	NegTTL  int        `json:"neg_ttl,omitempty"` // how long "does not exist" may be cached
	Layers  []DNSLayer `json:"layers"`
	Verdict string     `json:"verdict"`         // ok | stale_missing | stale_answer | cloud_stale | missing | rebind | blocked | unknown
	Stale   string     `json:"stale,omitempty"` // first layer that is behind
	Rebind  bool       `json:"rebind_protection"`
}

var (
	digStatusRe = regexp.MustCompile(`status: ([A-Z]+)`)
	digTimeRe   = regexp.MustCompile(`Query time: (\d+) msec`)
)

func digLayer(l DNSLayer, server string, port int, name, typ string, norec bool) DNSLayer {
	args := []string{"@" + server, "+time=3", "+tries=1", "+noall", "+answer", "+authority", "+comments", "+stats"}
	if port != 0 && port != 53 {
		args = append(args, "-p", strconv.Itoa(port))
	}
	if norec {
		args = append(args, "+norecurse")
	}
	args = append(args, "-t", typ, "-q", name)
	b, err := run(8*time.Second, "dig", args...)
	return parseDig(l, string(b), err, typ)
}

func parseDig(l DNSLayer, text string, err error, typ string) DNSLayer {
	l.Records, l.Addrs = []string{}, []string{}
	if m := digTimeRe.FindStringSubmatch(text); m != nil {
		l.MS, _ = strconv.Atoi(m[1])
	}
	if m := digStatusRe.FindStringSubmatch(text); m != nil {
		l.Status = m[1]
	}
	section := ""
	soaTTL := -1
	for _, line := range strings.Split(text, "\n") {
		switch {
		case strings.HasPrefix(line, ";; ANSWER SECTION"):
			section = "answer"
			continue
		case strings.HasPrefix(line, ";; AUTHORITY SECTION"):
			section = "authority"
			continue
		case strings.HasPrefix(line, ";"), strings.TrimSpace(line) == "":
			continue
		}
		f := strings.Fields(line)
		if len(f) < 5 || f[2] != "IN" {
			continue
		}
		ttl, _ := strconv.Atoi(f[1])
		rt, data := f[3], strings.Join(f[4:], " ")
		if rt == "SOA" && section != "answer" {
			soaTTL = ttl
			continue
		}
		if section == "authority" {
			continue
		}
		l.Records = append(l.Records, rt+" "+data)
		if rt == typ && (rt == "A" || rt == "AAAA") {
			l.Addrs = append(l.Addrs, data)
		}
		if l.TTL == 0 || ttl < l.TTL {
			l.TTL = ttl
		}
	}
	if len(l.Records) == 0 && soaTTL >= 0 {
		l.TTL = soaTTL
	}
	if err != nil && l.Status == "" {
		l.Error = "无响应"
		if strings.Contains(text, "timed out") {
			l.Error = "超时"
		}
	}
	return l
}

func dohJSON(l DNSLayer, profile, name, typ string) DNSLayer {
	l.Records, l.Addrs = []string{}, []string{}
	q := url.Values{"name": {name}, "type": {typ}}
	req, _ := http.NewRequest("GET", "https://dns.nextdns.io/"+url.PathEscape(profile)+"?"+q.Encode(), nil)
	req.Header.Set("Accept", "application/dns-json")
	t0 := time.Now()
	resp, err := (&http.Client{Timeout: 6 * time.Second}).Do(req)
	l.MS = int(time.Since(t0) / time.Millisecond)
	if err != nil {
		l.Error = "连不上"
		return l
	}
	defer resp.Body.Close()
	var r struct {
		Status int
		Answer []struct {
			Type int
			TTL  int
			Data string `json:"data"`
		}
		Authority []struct {
			Type int
			TTL  int
		}
	}
	if err := json.NewDecoder(resp.Body).Decode(&r); err != nil {
		l.Error = "回复看不懂"
		return l
	}
	l.Status = map[int]string{0: "NOERROR", 2: "SERVFAIL", 3: "NXDOMAIN", 5: "REFUSED"}[r.Status]
	if l.Status == "" {
		l.Status = "RCODE" + strconv.Itoa(r.Status)
	}
	names := map[int]string{1: "A", 5: "CNAME", 28: "AAAA", 15: "MX", 16: "TXT", 2: "NS", 65: "HTTPS"}
	for _, a := range r.Answer {
		rt := names[a.Type]
		if rt == "" {
			rt = "TYPE" + strconv.Itoa(a.Type)
		}
		l.Records = append(l.Records, rt+" "+a.Data)
		if rt == typ && (rt == "A" || rt == "AAAA") {
			l.Addrs = append(l.Addrs, a.Data)
		}
		if l.TTL == 0 || a.TTL < l.TTL {
			l.TTL = a.TTL
		}
	}
	if len(r.Answer) == 0 {
		for _, a := range r.Authority {
			if a.Type == 6 {
				l.TTL = a.TTL
			}
		}
	}
	return l
}

// zoneOf finds the zone a name lives in and one of its name servers, plus the zone's negative TTL.
func zoneOf(name string) (zone, ns string, negTTL int) {
	b, _ := run(8*time.Second, "dig", "@1.1.1.1", "+time=3", "+tries=1", "+noall", "+answer", "+authority", "-t", "SOA", "-q", name)
	for _, line := range strings.Split(string(b), "\n") {
		f := strings.Fields(line)
		if len(f) >= 11 && f[3] == "SOA" {
			zone = f[0]
			ttl, _ := strconv.Atoi(f[1])
			min, _ := strconv.Atoi(f[10])
			negTTL = min
			if ttl < min {
				negTTL = ttl
			}
			break
		}
	}
	if zone == "" {
		return
	}
	b, _ = run(8*time.Second, "dig", "@1.1.1.1", "+time=3", "+tries=1", "+short", "-t", "NS", "-q", zone)
	var nss []string
	for _, s := range strings.Fields(string(b)) {
		if strings.HasSuffix(s, ".") {
			nss = append(nss, s)
		}
	}
	sort.Strings(nss)
	if len(nss) > 0 {
		ns = nss[0]
	}
	return
}

func nextDNSCached(name, typ string) *bool {
	b, err := run(8*time.Second, "nextdns", "cache-keys")
	if err != nil {
		return nil
	}
	var keys []string
	if json.Unmarshal(b, &keys) != nil {
		return nil
	}
	want := " " + typ + " " + strings.ToLower(strings.TrimSuffix(name, ".")) + "."
	hit := false
	for _, k := range keys {
		if strings.HasSuffix(strings.ToLower(k), want) {
			hit = true
			break
		}
	}
	return &hit
}

func DNSTraceName(name, typ string) (*DNSTrace, error) {
	name, err := validHost(name)
	if err != nil || net.ParseIP(name) != nil || !strings.Contains(name, ".") {
		return nil, errors.New("请输入域名，例如 app.example.com")
	}
	typ = strings.ToUpper(typ)
	if typ == "" {
		typ = "A"
	}
	if typ != "A" && typ != "AAAA" && typ != "CNAME" && typ != "TXT" && typ != "MX" {
		return nil, errors.New("不支持的记录类型")
	}
	_, _, rebind := dnsmasqConf()
	t := &DNSTrace{Name: name, Type: typ, Rebind: rebind}

	// the outside first: authoritative and public answers don't touch the home caches
	var zwg sync.WaitGroup
	var auth, public DNSLayer
	zwg.Add(2)
	go func() {
		defer zwg.Done()
		t.Zone, t.NS, t.NegTTL = zoneOf(name)
		auth = DNSLayer{ID: "auth", Label: "域名的权威服务器", Records: []string{}, Addrs: []string{}}
		if t.NS == "" {
			auth.Error = "找不到这个域名的权威服务器"
			return
		}
		auth.Server = strings.TrimSuffix(t.NS, ".")
		auth = digLayer(auth, auth.Server, 53, name, typ, true)
	}()
	go func() {
		defer zwg.Done()
		public = digLayer(DNSLayer{ID: "public", Label: "Cloudflare 1.1.1.1", Server: "1.1.1.1"}, "1.1.1.1", 53, name, typ, false)
	}()
	zwg.Wait()

	var cached *bool
	ups := dnsUpstreams()
	var local *DNSUpstream
	for i := range ups {
		if ups[i].Port != 0 {
			local = &ups[i]
			break
		}
	}
	if local != nil && local.Kind == "nextdns" {
		cached = nextDNSCached(name, typ) // before our own queries put it there
	}
	layers := []DNSLayer{digLayer(DNSLayer{ID: "dnsmasq", Label: "路由器 dnsmasq（家里设备问的）", Server: "127.0.0.1"}, "127.0.0.1", 53, name, typ, false)}
	if local != nil {
		label := map[string]string{"nextdns": "NextDNS 本地程序", "smartdns": "SmartDNS", "adguardhome": "AdGuard Home", "mosdns": "MosDNS", "openclash": "OpenClash DNS"}[local.Kind]
		if label == "" {
			label = "本地上游 " + local.Addr
		}
		l := digLayer(DNSLayer{ID: "upstream", Label: label, Server: local.Addr}, "127.0.0.1", local.Port, name, typ, false)
		l.Cached = cached
		layers = append(layers, l)
		if local.Kind == "nextdns" {
			if p := uciValue("nextdns.main.profile"); p != "" {
				layers = append(layers, dohJSON(DNSLayer{ID: "cloud", Label: "NextDNS 云端", Server: "dns.nextdns.io"}, p, name, typ))
			}
		}
	}
	t.Layers = append(append(layers, public), auth)
	t.Verdict, t.Stale = dnsVerdict(t.Layers, rebind)
	return t, nil
}

func answered(l DNSLayer) bool {
	return l.Error == "" && l.Status != "" && l.Status != "SERVFAIL" && l.Status != "REFUSED"
}
func hasData(l DNSLayer) bool { return len(l.Records) > 0 }

func blockedAddr(a string) bool { return a == "0.0.0.0" || a == "::" }

func privateAddr(a string) bool {
	ip, err := netip.ParseAddr(a)
	return err == nil && (ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast())
}

func sameAddrs(a, b []string) bool {
	if len(a) == 0 || len(b) == 0 {
		return true // CNAME-only answers etc.: nothing to compare
	}
	in := map[string]bool{}
	for _, x := range a {
		in[x] = true
	}
	for _, x := range b {
		if in[x] {
			return true // CDNs rotate addresses; any overlap counts
		}
	}
	return false
}

// dnsVerdict compares the home's answer with the outside's and names the first stale layer.
func dnsVerdict(ls []DNSLayer, rebind bool) (string, string) {
	by := map[string]DNSLayer{}
	var home []DNSLayer // dnsmasq, upstream, cloud — in order
	for _, l := range ls {
		by[l.ID] = l
		if l.ID == "dnsmasq" || l.ID == "upstream" || l.ID == "cloud" {
			home = append(home, l)
		}
	}
	truth, ok := by["auth"]
	if !ok || !answered(truth) {
		truth = by["public"]
		if !answered(truth) {
			return "unknown", ""
		}
	}
	dm := by["dnsmasq"]
	for _, a := range dm.Addrs {
		if blockedAddr(a) {
			return "blocked", ""
		}
	}
	disagree := func(l DNSLayer) bool {
		if hasData(truth) {
			return !hasData(l) || !sameAddrs(l.Addrs, truth.Addrs)
		}
		return hasData(l)
	}
	if !disagree(dm) {
		if !hasData(truth) {
			return "missing", ""
		}
		return "ok", ""
	}
	// dnsmasq drops public names that resolve to private addresses (rebind protection)
	if up, ok := by["upstream"]; ok && rebind && hasData(truth) && !hasData(dm) && !disagree(up) {
		for _, a := range up.Addrs {
			if privateAddr(a) {
				return "rebind", ""
			}
		}
	}
	// the outermost home layer that disagrees is where the stale answer comes from
	stale := "dnsmasq"
	for i := len(home) - 1; i >= 0; i-- {
		if answered(home[i]) && disagree(home[i]) {
			stale = home[i].ID
			break
		}
	}
	if stale == "cloud" {
		return "cloud_stale", "cloud"
	}
	if hasData(dm) {
		return "stale_answer", stale
	}
	return "stale_missing", stale
}

// ---- emptying caches ----

type FlushResult struct {
	Target string `json:"target"`
	OK     bool   `json:"ok"`
	MS     int    `json:"ms"`
	Error  string `json:"error,omitempty"`
}

var flushMu sync.Mutex

// waitDNS waits until a local resolver answers again.
func waitDNS(port int, max time.Duration) bool {
	deadline := time.Now().Add(max)
	for time.Now().Before(deadline) {
		if _, err := run(3*time.Second, "dig", "@127.0.0.1", "-p", strconv.Itoa(port), "+time=1", "+tries=1", "+short", "-q", "dns.nextdns.io"); err == nil {
			return true
		}
		time.Sleep(300 * time.Millisecond)
	}
	return false
}

func DNSFlush(targets []string) ([]FlushResult, error) {
	if !flushMu.TryLock() {
		return nil, errors.New("正在刷新，稍等")
	}
	defer flushMu.Unlock()
	if len(targets) == 0 {
		targets = []string{"upstream", "dnsmasq"}
	}
	var out []FlushResult
	for _, tg := range targets {
		t0 := time.Now()
		r := FlushResult{Target: tg}
		switch tg {
		case "dnsmasq":
			pids := pidsOf("/usr/sbin/dnsmasq")
			if len(pids) == 0 {
				r.Error = "dnsmasq 没在运行"
				break
			}
			for _, pid := range pids {
				// SIGHUP: dnsmasq empties its cache and re-reads hosts files; it keeps serving
				if err := syscall.Kill(pid, syscall.SIGHUP); err != nil {
					r.Error = err.Error()
				}
			}
			r.OK = r.Error == ""
		case "upstream":
			var up *DNSUpstream
			for _, u := range dnsUpstreams() {
				if u.Flush {
					up = &u
					break
				}
			}
			if up == nil {
				r.Error = "上游不是 Wharf 能清缓存的程序"
				break
			}
			r.Target = up.Kind
			// NextDNS has no "flush" command; a restart is the only way to empty its cache (about a second)
			if _, err := run(30*time.Second, "/etc/init.d/nextdns", "restart"); err != nil {
				r.Error = "重启 NextDNS 失败：" + err.Error()
				break
			}
			if !waitDNS(up.Port, 15*time.Second) {
				r.Error = "NextDNS 重启后 15 秒内没有恢复应答"
				break
			}
			r.OK = true
		default:
			r.Error = "未知的缓存"
		}
		r.MS = int(time.Since(t0) / time.Millisecond)
		out = append(out, r)
	}
	return out, nil
}

// SetNextDNSMaxAge sets how long NextDNS may keep any cached answer, then restarts it.
func SetNextDNSMaxAge(v string) error {
	ok := map[string]bool{"0s": true, "1m": true, "5m": true, "10m": true, "15m": true, "30m": true, "1h": true}
	if !ok[v] {
		return fmt.Errorf("不支持的时长 %q", v)
	}
	if !fileExists("/etc/config/nextdns") {
		return errors.New("没有安装 NextDNS")
	}
	if _, err := run(5*time.Second, "uci", "set", "nextdns.main.cache_max_age="+v); err != nil {
		return err
	}
	if _, err := run(5*time.Second, "uci", "commit", "nextdns"); err != nil {
		return err
	}
	_, err := DNSFlush([]string{"upstream"})
	return err
}
