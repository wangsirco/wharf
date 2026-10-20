package rules

import (
	"bufio"
	"bytes"
	"compress/gzip"
	_ "embed"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

const Source = "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Clash/%s/%s.list"

type Service struct {
	Name     string `json:"n"`
	Category string `json:"c"`
	Sub      string `json:"s,omitempty"`
	Company  string `json:"o"`
}

type Compiled struct {
	Version  string         `json:"version"`
	Services []Service      `json:"services"`
	Suffix   map[string]int `json:"suffix"`
	Exact    map[string]int `json:"exact"`
	Keywords [][2]string    `json:"keywords"` // [keyword, service index]
	CIDRs    [][2]string    `json:"cidrs"`    // [prefix, service index]
	ASN      map[string]int `json:"asn"`
	Missing  []string       `json:"missing,omitempty"`
	Counts   map[string]int `json:"counts,omitempty"`
}

// Build downloads every list in Catalog and compiles them.
func Build(client *http.Client) (*Compiled, error) {
	c := &Compiled{Version: time.Now().UTC().Format("2006-01-02"), Suffix: map[string]int{}, Exact: map[string]int{},
		ASN: map[string]int{}, Counts: map[string]int{}}
	bodies := make([][]byte, len(Catalog))
	var wg sync.WaitGroup
	sem := make(chan struct{}, 8)
	for i, e := range Catalog {
		wg.Add(1)
		go func(i int, e Entry) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			resp, err := client.Get(fmt.Sprintf(Source, e.List, e.List))
			if err != nil {
				return
			}
			defer resp.Body.Close()
			if resp.StatusCode == 200 {
				bodies[i], _ = io.ReadAll(io.LimitReader(resp.Body, 32<<20))
			}
		}(i, e)
	}
	wg.Wait()
	// hand-maintained services first so they win over broader upstream lists
	for _, x := range Extras {
		idx := len(c.Services)
		c.Services = append(c.Services, Service{x.Name, x.Category, x.Sub, x.Company})
		for _, d := range x.Domains {
			if _, ok := c.Suffix[d]; !ok {
				c.Suffix[d] = idx
			}
		}
	}
	got := 0
	for i, e := range Catalog {
		idx := len(c.Services)
		sub := Subs[e.List]
		if sub == "" {
			sub = e.Category
		}
		c.Services = append(c.Services, Service{e.Name, e.Category, sub, e.Company})
		if bodies[i] == nil {
			c.Missing = append(c.Missing, e.List)
			continue
		}
		got++
		c.Counts[e.List] = c.add(idx, bodies[i])
	}
	if got == 0 {
		return nil, fmt.Errorf("could not download any rule list")
	}
	return c, nil
}

// add parses one list; earlier services keep rules they already own.
func (c *Compiled) add(svc int, body []byte) int {
	n := 0
	sc := bufio.NewScanner(bytes.NewReader(body))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		f := strings.Split(line, ",")
		if len(f) < 2 {
			continue
		}
		v := strings.ToLower(strings.TrimSpace(f[1]))
		switch f[0] {
		case "DOMAIN-SUFFIX":
			if _, ok := c.Suffix[v]; !ok {
				c.Suffix[v] = svc
				n++
			}
		case "DOMAIN":
			if _, ok := c.Exact[v]; !ok {
				c.Exact[v] = svc
				n++
			}
		case "DOMAIN-KEYWORD":
			if len(v) >= 4 { // very short keywords match too much
				c.Keywords = append(c.Keywords, [2]string{v, strconv.Itoa(svc)})
				n++
			}
		case "IP-CIDR":
			if p, err := netip.ParsePrefix(v); err == nil && p.Addr().Is4() {
				c.CIDRs = append(c.CIDRs, [2]string{p.Masked().String(), strconv.Itoa(svc)})
				n++
			}
		case "IP-ASN":
			if _, ok := c.ASN[v]; !ok {
				c.ASN[v] = svc
				n++
			}
		}
	}
	return n
}

func (c *Compiled) Write(path string) error {
	var buf bytes.Buffer
	zw, _ := gzip.NewWriterLevel(&buf, gzip.BestCompression)
	if err := json.NewEncoder(zw).Encode(c); err != nil {
		return err
	}
	zw.Close()
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, buf.Bytes(), 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func Load(gz []byte) (*Compiled, error) {
	zr, err := gzip.NewReader(bytes.NewReader(gz))
	if err != nil {
		return nil, err
	}
	var c Compiled
	if err := json.NewDecoder(zr).Decode(&c); err != nil {
		return nil, err
	}
	return &c, nil
}

//go:embed data/rules.json.gz
var embedded []byte

// ---- matcher ----

type Result struct {
	Service  string `json:"service"`
	Category string `json:"category"`
	Sub      string `json:"sub"`
	Company  string `json:"company"`
	By       string `json:"by"` // domain | keyword | ip | asn | org | probe | ""
}

type ipRange struct {
	lo, hi uint32
	svc    int
}

type Matcher struct {
	c      *Compiled
	ranges []ipRange
	kw     []struct {
		k   string
		svc int
	}
}

func NewMatcher(c *Compiled) *Matcher {
	m := &Matcher{c: c}
	for _, x := range c.CIDRs {
		p, err := netip.ParsePrefix(x[0])
		if err != nil {
			continue
		}
		svc, _ := strconv.Atoi(x[1])
		a := p.Addr().As4()
		lo := binary.BigEndian.Uint32(a[:])
		hi := lo | (uint32(1)<<(32-p.Bits()) - 1)
		if p.Bits() == 0 {
			hi = ^uint32(0)
		}
		m.ranges = append(m.ranges, ipRange{lo, hi, svc})
	}
	// narrowest range first among equals so lookups prefer the most specific rule
	sort.Slice(m.ranges, func(i, j int) bool {
		if m.ranges[i].lo != m.ranges[j].lo {
			return m.ranges[i].lo < m.ranges[j].lo
		}
		return m.ranges[i].hi < m.ranges[j].hi
	})
	for _, k := range c.Keywords {
		svc, _ := strconv.Atoi(k[1])
		m.kw = append(m.kw, struct {
			k   string
			svc int
		}{k[0], svc})
	}
	return m
}

// Default returns a matcher over the rules compiled into the binary, or over a newer
// file at override (written by an online update) when present.
func Default(override string) (*Matcher, error) {
	data := embedded
	if override != "" {
		if b, err := os.ReadFile(override); err == nil {
			data = b
		}
	}
	c, err := Load(data)
	if err != nil {
		return nil, err
	}
	return NewMatcher(c), nil
}

func (m *Matcher) Version() string { return m.c.Version }

func (m *Matcher) svc(i int, by string) Result {
	if i < 0 || i >= len(m.c.Services) {
		return Result{}
	}
	s := m.c.Services[i]
	sub := s.Sub
	if sub == "" {
		sub = s.Category
	}
	return Result{s.Name, s.Category, sub, s.Company, by}
}

func (m *Matcher) Domain(d string) (Result, bool) {
	d = strings.TrimSuffix(strings.ToLower(d), ".")
	if d == "" {
		return Result{}, false
	}
	if i, ok := m.c.Exact[d]; ok {
		return m.svc(i, "domain"), true
	}
	for s := d; ; {
		if i, ok := m.c.Suffix[s]; ok {
			return m.svc(i, "domain"), true
		}
		_, rest, found := strings.Cut(s, ".")
		if !found {
			break
		}
		s = rest
	}
	for _, k := range m.kw {
		if strings.Contains(d, k.k) {
			return m.svc(k.svc, "keyword"), true
		}
	}
	return Result{}, false
}

func (m *Matcher) IP(a netip.Addr) (Result, bool) {
	if !a.Is4() {
		return Result{}, false
	}
	b := a.As4()
	v := binary.BigEndian.Uint32(b[:])
	// last range starting at or before v; walk back over overlapping candidates
	i := sort.Search(len(m.ranges), func(i int) bool { return m.ranges[i].lo > v }) - 1
	for j := i; j >= 0 && j > i-64; j-- {
		if r := m.ranges[j]; v >= r.lo && v <= r.hi {
			return m.svc(r.svc, "ip"), true
		}
	}
	return Result{}, false
}

func (m *Matcher) ASN(asn uint) (Result, bool) {
	if i, ok := m.c.ASN[strconv.FormatUint(uint64(asn), 10)]; ok {
		return m.svc(i, "asn"), true
	}
	if a, ok := ASNs[asn]; ok {
		return Result{a.Name, a.Category, a.Category, a.Company, "asn"}, true
	}
	return Result{}, false
}

// Identify combines all signals: DNS name first, then IP rules, then ASN, then the
// AS organisation from the offline geo database.
func (m *Matcher) Identify(domain string, ip netip.Addr, asn uint, asOrg string) Result {
	if r, ok := m.Domain(domain); ok {
		return r
	}
	if r, ok := m.IP(ip); ok {
		return r
	}
	if r, ok := m.ASN(asn); ok {
		return r
	}
	if asOrg != "" {
		return Result{Service: asOrg, Category: "其他", Sub: "其他", Company: asOrg, By: "org"}
	}
	return Result{Category: "其他", Sub: "其他"}
}

// ServiceInfo lists services (deduplicated by name) for pickers.
func (m *Matcher) Services() []Service {
	seen := map[string]bool{}
	var out []Service
	for _, s := range m.c.Services {
		if !seen[s.Name] {
			seen[s.Name] = true
			out = append(out, s)
		}
	}
	return out
}

// Targets returns the domain suffixes / exact domains and IPv4 CIDRs belonging to a
// service name (used to turn "block YouTube" into firewall/DNS rules).
func (m *Matcher) Targets(name string) (domains, cidrs []string) {
	idx := map[int]bool{}
	for i, s := range m.c.Services {
		if s.Name == name {
			idx[i] = true
		}
	}
	for d, i := range m.c.Suffix {
		if idx[i] {
			domains = append(domains, d)
		}
	}
	for d, i := range m.c.Exact {
		if idx[i] {
			domains = append(domains, d)
		}
	}
	for _, x := range m.c.CIDRs {
		if i, _ := strconv.Atoi(x[1]); idx[i] {
			cidrs = append(cidrs, x[0])
		}
	}
	sort.Strings(domains)
	return domains, cidrs
}
