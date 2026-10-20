package agent

import (
	"bufio"
	"io"
	"log"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

// DNS query log (dnsmasq --log-queries=extra --log-facility=<file>) gives us
// "client X asked for name N" and "N resolved to IP". That lets flows to an IP be
// labelled with the name the device actually looked up.
//
//	1592 192.168.1.114/53321 query[A] www.youtube.com from 192.168.1.114
//	1592 192.168.1.114/53321 reply www.youtube.com is youtube-ui.l.google.com
//	1592 192.168.1.114/53321 reply youtube-ui.l.google.com is 142.250.66.206

const defaultDNSLog = "/var/log/owp-dns.log"

type dnsEntry struct {
	name string
	at   time.Time
}

type DNSLog struct {
	path string

	mu       sync.Mutex
	serials  map[string]serialInfo          // dnsmasq serial -> query
	byClient map[string]map[string]dnsEntry // client ip -> resolved ip -> name
	global   map[string]dnsEntry            // resolved ip -> name (any client)

	onQuery   func(client, name string, blocked bool)
	OnResolve func(name, ip string) // every A/AAAA answer (used by device policies)
}

type serialInfo struct {
	client, name string
	at           time.Time
}

// EnsureDNSLogging turns on dnsmasq query logging via uci (once) and returns the log path.
func EnsureDNSLogging() string {
	sec := "@dnsmasq[0]"
	all, err := uciGetConfig("dhcp")
	if err == nil {
		for id, s := range all {
			if s[".type"] == "dnsmasq" {
				sec = id
				break
			}
		}
	}
	path := uciGetOption("dhcp", sec, "logfacility")
	if !strings.HasPrefix(path, "/") {
		path = defaultDNSLog
	}
	if uciGetOption("dhcp", sec, "logqueries") == "1" && uciGetOption("dhcp", sec, "logfacility") == path {
		return path
	}
	log.Printf("dns: enabling dnsmasq query log -> %s", path)
	if _, err := Apply([]Change{{Op: "set", Config: "dhcp", Section: sec, Values: map[string]any{"logqueries": "1", "logfacility": path}}}); err != nil {
		log.Printf("dns: %v", err)
	}
	return path
}

func NewDNSLog(path string, onQuery func(client, name string, blocked bool)) *DNSLog {
	return &DNSLog{path: path, serials: map[string]serialInfo{}, byClient: map[string]map[string]dnsEntry{},
		global: map[string]dnsEntry{}, onQuery: onQuery}
}

// Known returns resolved IP -> name for the last few hours.
func (d *DNSLog) Known() map[string]string {
	d.mu.Lock()
	defer d.mu.Unlock()
	out := make(map[string]string, len(d.global))
	for ip, e := range d.global {
		out[ip] = e.name
	}
	return out
}

// Lookup returns the name a client (or anyone) resolved to reach ip.
func (d *DNSLog) Lookup(client, ip string) string {
	d.mu.Lock()
	defer d.mu.Unlock()
	if m := d.byClient[client]; m != nil {
		if e, ok := m[ip]; ok {
			return e.name
		}
	}
	return d.global[ip].name
}

func (d *DNSLog) handle(line string) {
	_, rest, ok := strings.Cut(line, "]: ")
	if !ok {
		return
	}
	f := strings.Fields(rest)
	// serial client/port verb name ...
	if len(f) < 4 {
		return
	}
	serial, verb, name := f[0], f[2], strings.TrimSuffix(strings.ToLower(f[3]), ".")
	client, _, _ := strings.Cut(f[1], "/")
	if _, err := strconv.Atoi(serial); err != nil {
		return
	}
	now := time.Now()
	d.mu.Lock()
	defer d.mu.Unlock()
	switch {
	case strings.HasPrefix(verb, "query["):
		qtype := strings.TrimSuffix(strings.TrimPrefix(verb, "query["), "]")
		if _, seen := d.serials[serial]; !seen {
			d.serials[serial] = serialInfo{client, name, now}
		}
		if qtype == "A" || qtype == "AAAA" || qtype == "HTTPS" {
			if d.onQuery != nil && qtype != "AAAA" { // count each lookup once (A is always asked)
				go d.onQuery(client, name, false)
			}
		}
	case verb == "reply" || verb == "cached" || verb == "config":
		if len(f) < 6 || f[4] != "is" {
			return
		}
		val := f[5]
		q, ok := d.serials[serial]
		if !ok {
			q = serialInfo{client, name, now}
		}
		a, err := netip.ParseAddr(val)
		if err != nil {
			return // CNAME, NXDOMAIN, NODATA ...
		}
		if a.IsUnspecified() { // NextDNS / adblock answer: blocked
			if d.onQuery != nil {
				go d.onQuery(q.client, q.name, true)
			}
			return
		}
		if d.OnResolve != nil {
			d.OnResolve(q.name, a.String())
			if name != q.name {
				d.OnResolve(name, a.String()) // CNAME target
			}
		}
		e := dnsEntry{q.name, now}
		m := d.byClient[q.client]
		if m == nil {
			m = map[string]dnsEntry{}
			d.byClient[q.client] = m
		}
		m[a.String()] = e
		d.global[a.String()] = e
	}
}

func (d *DNSLog) gc() {
	d.mu.Lock()
	defer d.mu.Unlock()
	now := time.Now()
	for k, v := range d.serials {
		if now.Sub(v.at) > time.Minute {
			delete(d.serials, k)
		}
	}
	for c, m := range d.byClient {
		for ip, e := range m {
			if now.Sub(e.at) > 6*time.Hour {
				delete(m, ip)
			}
		}
		if len(m) == 0 {
			delete(d.byClient, c)
		}
	}
	for ip, e := range d.global {
		if now.Sub(e.at) > 6*time.Hour {
			delete(d.global, ip)
		}
	}
}

// Run tails the log file, truncating it when it grows past 16 MB.
func (d *DNSLog) Run() {
	const maxSize = 16 << 20
	var f *os.File
	var rd *bufio.Reader
	var off int64
	var partial string
	lastGC := time.Now()
	for {
		if f == nil {
			var err error
			if f, err = os.Open(d.path); err != nil {
				time.Sleep(5 * time.Second)
				continue
			}
			off, _ = f.Seek(0, io.SeekEnd)
			rd = bufio.NewReaderSize(f, 64<<10)
		}
		line, err := rd.ReadString('\n')
		off += int64(len(line))
		if err == nil {
			d.handle(strings.TrimRight(partial+line, "\n"))
			partial = ""
			continue
		}
		partial += line // incomplete last line; finish it on the next read
		// EOF: wait, handle truncation / rotation
		time.Sleep(500 * time.Millisecond)
		if st, err := os.Stat(d.path); err != nil {
			f.Close()
			f = nil
		} else if st.Size() < off {
			_, _ = f.Seek(0, io.SeekStart)
			off, partial = 0, ""
			rd.Reset(f)
		} else if st.Size() > maxSize && st.Size() == off {
			_ = os.Truncate(d.path, 0) // dnsmasq opens O_APPEND, so this is safe
			_, _ = f.Seek(0, io.SeekStart)
			off, partial = 0, ""
			rd.Reset(f)
		}
		if time.Since(lastGC) > time.Minute {
			d.gc()
			lastGC = time.Now()
		}
	}
}
