package panel

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"io"
	"net"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Probing identifies targets the rules cannot: connect like a client would and
// look at reverse DNS, the TLS certificate and the HTTP page title. Results are
// cached; a target that answers nothing useful is stored as "failed" (测试失败).

type Probe struct {
	Target  string `json:"target"`
	Domain  string `json:"domain"`
	Status  string `json:"status"`  // ok | failed
	Summary string `json:"summary"` // best guess, human readable
	Detail  string `json:"detail"`  // JSON: rdns, cert, title, service
	TS      int64  `json:"ts"`
}

type probeDetail struct {
	RDNS     []string `json:"rdns,omitempty"`
	CertCN   string   `json:"cert_cn,omitempty"`
	CertSANs []string `json:"cert_sans,omitempty"`
	CertOrg  string   `json:"cert_org,omitempty"`
	Issuer   string   `json:"issuer,omitempty"`
	Title    string   `json:"title,omitempty"`
	Server   string   `json:"server,omitempty"`
	Service  string   `json:"service,omitempty"`
	Category string   `json:"category,omitempty"`
	Errors   []string `json:"errors,omitempty"`
}

func (a *App) cachedProbe(ip string, port int) *Probe {
	var p Probe
	if a.db.QueryRow(`SELECT target, domain, status, summary, detail, ts FROM probes WHERE target=?`, probeTarget(ip, port)).
		Scan(&p.Target, &p.Domain, &p.Status, &p.Summary, &p.Detail, &p.TS) != nil {
		return nil
	}
	return &p
}

// probeIndex keeps the best probe per IP in memory. identify() runs inside loops
// over open query results; if it queried the database itself, a few concurrent page
// loads could hold every pooled connection while each waits for one more — the
// panel would hang until restarted. So identify() must never touch the database.
type probeIndex struct {
	mu   sync.RWMutex
	byIP map[string]*Probe
}

func betterProbe(p, q *Probe) bool { // is p more useful than q?
	if q == nil {
		return true
	}
	if (p.Status == "ok") != (q.Status == "ok") {
		return p.Status == "ok"
	}
	return p.TS > q.TS
}

func (a *App) loadProbeIndex() {
	if a.db == nil {
		return
	}
	rows, err := a.db.Query(`SELECT target, domain, status, summary, detail, ts FROM probes`)
	if err != nil {
		return
	}
	m := map[string]*Probe{}
	for rows.Next() {
		var p Probe
		if rows.Scan(&p.Target, &p.Domain, &p.Status, &p.Summary, &p.Detail, &p.TS) != nil {
			continue
		}
		if ip, _, err := net.SplitHostPort(p.Target); err == nil && betterProbe(&p, m[ip]) {
			m[ip] = &p
		}
	}
	rows.Close()
	a.probes.mu.Lock()
	a.probes.byIP = m
	a.probes.mu.Unlock()
}

func (a *App) indexProbe(p *Probe) {
	ip, _, err := net.SplitHostPort(p.Target)
	if err != nil {
		return
	}
	a.probes.mu.Lock()
	defer a.probes.mu.Unlock()
	if a.probes.byIP == nil {
		a.probes.byIP = map[string]*Probe{}
	}
	if betterProbe(p, a.probes.byIP[ip]) {
		a.probes.byIP[ip] = p
	}
}

// bestProbe returns the most useful probe for an IP on any port (memory only).
func (a *App) bestProbe(ip string) *Probe {
	a.probes.mu.RLock()
	defer a.probes.mu.RUnlock()
	return a.probes.byIP[ip]
}

func probeTarget(ip string, port int) string { return net.JoinHostPort(ip, strconv.Itoa(port)) }

var titleRe = regexp.MustCompile(`(?is)<title[^>]*>(.*?)</title>`)

// Error pages and server defaults say nothing about what the site is.
var junkTitleRe = regexp.MustCompile(`(?i)^\s*(\d{3}\b|(http )?error|bad request|unauthori[sz]ed|forbidden|not found|access denied|request rejected|` +
	`service unavailable|bad gateway|gateway time-?out|internal server error|moved|redirect|object moved|found|` +
	`welcome to (nginx|openresty|tengine|caddy)|it works|apache2? .*default page|iis windows server|test page|default (web )?(site|page)|` +
	`index of|just a moment|attention required|ddos-guard|blocked|invalid (url|host)|domain .*not (configured|found)|` +
	`(nginx|openresty|tengine|cloudflare|varnish|awselb|server)\s*$|loading|untitled|document|home|login|sign in)`)

func usefulTitle(t string) bool {
	t = strings.TrimSpace(t)
	return len([]rune(t)) >= 2 && !junkTitleRe.MatchString(t)
}

func (a *App) probe(ip string, port int, domain string) *Probe {
	d := probeDetail{}
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	if names, err := net.DefaultResolver.LookupAddr(ctx, ip); err == nil {
		for _, n := range names {
			d.RDNS = append(d.RDNS, strings.TrimSuffix(n, "."))
		}
	}
	cancel()

	tlsPort := port
	if port == 80 {
		tlsPort = 443
	}
	dialer := &net.Dialer{Timeout: 4 * time.Second}
	conf := &tls.Config{InsecureSkipVerify: true, ServerName: domain} // we only read the certificate
	if c, err := tls.DialWithDialer(dialer, "tcp", probeTarget(ip, tlsPort), conf); err == nil {
		st := c.ConnectionState()
		if len(st.PeerCertificates) > 0 {
			cert := st.PeerCertificates[0]
			d.CertCN = cert.Subject.CommonName
			if len(cert.DNSNames) > 8 {
				d.CertSANs = cert.DNSNames[:8]
			} else {
				d.CertSANs = cert.DNSNames
			}
			if len(cert.Subject.Organization) > 0 {
				d.CertOrg = cert.Subject.Organization[0]
			}
			if len(cert.Issuer.Organization) > 0 {
				d.Issuer = cert.Issuer.Organization[0]
			}
		}
		c.Close()
	} else {
		d.Errors = append(d.Errors, "TLS: "+shortErr(err))
	}

	scheme, hport := "https", tlsPort
	if port == 80 || d.CertCN == "" && len(d.CertSANs) == 0 {
		scheme, hport = "http", port
	}
	host := domain
	if host == "" {
		host = ip
	}
	cl := &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true, ServerName: domain},
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return dialer.DialContext(ctx, network, probeTarget(ip, hport))
		},
	}, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	if req, err := http.NewRequest("GET", fmt.Sprintf("%s://%s/", scheme, host), nil); err == nil {
		req.Header.Set("User-Agent", "Mozilla/5.0 (OWP probe)")
		if resp, err := cl.Do(req); err == nil {
			d.Server = resp.Header.Get("Server")
			b, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
			resp.Body.Close()
			if m := titleRe.FindSubmatch(b); m != nil && resp.StatusCode < 400 {
				if t := truncate(strings.Join(strings.Fields(html.UnescapeString(string(m[1]))), " "), 120); usefulTitle(t) {
					d.Title = t
				}
			}
		} else {
			d.Errors = append(d.Errors, "HTTP: "+shortErr(err))
		}
	}

	// try to name it with the rules, using any hostname we learned
	for _, n := range append(append([]string{d.CertCN}, d.CertSANs...), d.RDNS...) {
		n = strings.TrimPrefix(n, "*.")
		if a.rules == nil || n == "" {
			continue
		}
		if r, ok := a.rules.Domain(n); ok {
			d.Service, d.Category = r.Service, r.Category
			break
		}
	}

	p := &Probe{Target: probeTarget(ip, port), Domain: domain, TS: time.Now().Unix()}
	var parts []string
	if d.Service != "" {
		parts = append(parts, d.Service+"（"+d.Category+"）")
	}
	if d.CertCN != "" {
		parts = append(parts, "证书 "+d.CertCN)
	} else if len(d.CertSANs) > 0 {
		parts = append(parts, "证书 "+d.CertSANs[0])
	}
	if d.CertOrg != "" {
		parts = append(parts, d.CertOrg)
	}
	if d.Title != "" {
		parts = append(parts, "「"+d.Title+"」")
	}
	if len(d.RDNS) > 0 {
		parts = append(parts, "rDNS "+d.RDNS[0])
	}
	if len(parts) == 0 {
		p.Status, p.Summary = "failed", "测试失败"
	} else {
		p.Status, p.Summary = "ok", strings.Join(parts, " · ")
	}
	b, _ := json.Marshal(d)
	p.Detail = string(b)
	defer a.idc.reset() // names derived from probes may change
	a.indexProbe(p)
	_, _ = a.db.Exec(`INSERT INTO probes(target, domain, status, summary, detail, ts) VALUES(?,?,?,?,?,?)
		ON CONFLICT(target) DO UPDATE SET domain=excluded.domain, status=excluded.status, summary=excluded.summary, detail=excluded.detail, ts=excluded.ts`,
		p.Target, p.Domain, p.Status, p.Summary, p.Detail, p.TS)
	return p
}

func shortErr(err error) string {
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		return "超时"
	}
	s := err.Error()
	if i := strings.LastIndex(s, ": "); i >= 0 {
		s = s[i+2:]
	}
	return truncate(s, 60)
}

// POST /api/probe {ip, port, domain}
func (a *App) handleProbe(w http.ResponseWriter, r *http.Request) {
	var req struct {
		IP     string `json:"ip"`
		Port   int    `json:"port"`
		Domain string `json:"domain"`
	}
	if readJSON(r, &req) != nil || net.ParseIP(req.IP) == nil || req.Port < 1 || req.Port > 65535 {
		jsonErr(w, 400, "请求格式错误")
		return
	}
	if ip := net.ParseIP(req.IP); ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsUnspecified() {
		jsonErr(w, 400, "只能探测公网地址")
		return
	}
	if a.beacons.blocked("probe:" + currentUser(r).Username) {
		jsonErr(w, 429, "探测太频繁，请稍后再试")
		return
	}
	a.beacons.record("probe:" + currentUser(r).Username)
	writeJSON(w, 200, a.probe(req.IP, req.Port, strings.TrimSpace(req.Domain)))
}

// autoProbe periodically probes the busiest targets the rules could not identify.
func (a *App) autoProbe() {
	time.Sleep(2 * time.Minute)
	for {
		rows, err := a.db.Query(`SELECT remote, port, MAX(domain), SUM(up+down) b FROM flow_hour
			WHERE hour >= ? AND inbound=0 GROUP BY remote, port ORDER BY b DESC LIMIT 200`, time.Now().Unix()-86400)
		var todo [][3]string
		if err == nil {
			for rows.Next() {
				var remote, domain string
				var port, b int64
				_ = rows.Scan(&remote, &port, &domain, &b)
				id := a.identify(domain, remote)
				if id.By == "" && !id.Guess && a.cachedProbe(remote, int(port)) == nil {
					todo = append(todo, [3]string{remote, strconv.FormatInt(port, 10), domain})
				}
			}
			rows.Close()
		}
		for i, t := range todo {
			if i >= 20 {
				break
			}
			port, _ := strconv.Atoi(t[1])
			if port == 443 || port == 80 || port == 8443 || port == 8080 {
				a.probe(t[0], port, t[2])
			}
		}
		time.Sleep(time.Hour)
	}
}
