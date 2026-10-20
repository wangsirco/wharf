package panel

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"

	"github.com/oschwald/maxminddb-golang/v2"
)

// Region keys: "NZ" (country) or "NZ/Auckland" (country/subdivision, English name).

type RegionInfo struct {
	Code    string   `json:"code"`
	Name    string   `json:"name"` // zh-CN when available
	NameEn  string   `json:"name_en"`
	Regions []string `json:"regions"`
}

type geoRec struct {
	Country struct {
		ISO   string            `maxminddb:"iso_code"`
		Names map[string]string `maxminddb:"names"`
	} `maxminddb:"country"`
	Subdivisions []struct {
		Names map[string]string `maxminddb:"names"`
	} `maxminddb:"subdivisions"`
}

var regionMu sync.Mutex

func (g *Geo) cityPath() string { return filepath.Join(g.dir, "dbip-city-lite.mmdb") }

// Regions lists countries and their subdivisions, cached on disk next to the database.
func (g *Geo) Regions() ([]RegionInfo, error) {
	regionMu.Lock()
	defer regionMu.Unlock()
	st, err := os.Stat(g.cityPath())
	if err != nil {
		return nil, errors.New("IP 离线库尚未下载")
	}
	cache := filepath.Join(g.dir, "regions.json")
	if cs, err := os.Stat(cache); err == nil && cs.ModTime().After(st.ModTime()) {
		var out []RegionInfo
		if b, err := os.ReadFile(cache); err == nil && json.Unmarshal(b, &out) == nil {
			return out, nil
		}
	}
	r, err := maxminddb.Open(g.cityPath())
	if err != nil {
		return nil, err
	}
	defer r.Close()
	byCode := map[string]*RegionInfo{}
	subs := map[string]map[string]bool{}
	var rec geoRec
	for res := range r.Networks() {
		if !res.Prefix().Addr().Is4() {
			continue
		}
		rec = geoRec{}
		if res.Decode(&rec) != nil || rec.Country.ISO == "" {
			continue
		}
		c := rec.Country.ISO
		if byCode[c] == nil {
			name := rec.Country.Names["zh-CN"]
			if name == "" {
				name = rec.Country.Names["en"]
			}
			byCode[c] = &RegionInfo{Code: c, Name: name, NameEn: rec.Country.Names["en"]}
			subs[c] = map[string]bool{}
		}
		if len(rec.Subdivisions) > 0 {
			if s := rec.Subdivisions[0].Names["en"]; s != "" {
				subs[c][s] = true
			}
		}
	}
	out := make([]RegionInfo, 0, len(byCode))
	for c, ri := range byCode {
		for s := range subs[c] {
			ri.Regions = append(ri.Regions, s)
		}
		sort.Strings(ri.Regions)
		out = append(out, *ri)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Code < out[j].Code })
	b, _ := json.Marshal(out)
	_ = os.WriteFile(cache, b, 0o644)
	return out, nil
}

func validRegionKey(k string) bool {
	c, s, _ := strings.Cut(k, "/")
	if len(c) != 2 || strings.ToUpper(c) != c {
		return false
	}
	return len(s) <= 80 && !strings.ContainsAny(s, "\n\r\"")
}

// RegionCIDRs returns merged IPv4 prefixes for each requested region key in one pass.
func (g *Geo) RegionCIDRs(keys []string) (map[string][]netip.Prefix, error) {
	want := map[string]bool{}
	for _, k := range keys {
		want[k] = true
	}
	r, err := maxminddb.Open(g.cityPath())
	if err != nil {
		return nil, errors.New("IP 离线库尚未下载")
	}
	defer r.Close()
	raw := map[string][]netip.Prefix{}
	var rec geoRec
	for res := range r.Networks() {
		p := res.Prefix()
		if !p.Addr().Is4() {
			continue
		}
		rec = geoRec{}
		if res.Decode(&rec) != nil {
			continue
		}
		c := rec.Country.ISO
		if want[c] {
			raw[c] = append(raw[c], p)
		}
		if len(rec.Subdivisions) > 0 {
			if k := c + "/" + rec.Subdivisions[0].Names["en"]; want[k] {
				raw[k] = append(raw[k], p)
			}
		}
	}
	out := map[string][]netip.Prefix{}
	for k := range want {
		out[k] = mergePrefixes(raw[k])
	}
	return out, nil
}

// mergePrefixes collapses overlapping/adjacent IPv4 prefixes into the minimal CIDR set.
func mergePrefixes(ps []netip.Prefix) []netip.Prefix {
	type rng struct{ lo, hi uint64 }
	rs := make([]rng, 0, len(ps))
	for _, p := range ps {
		p = p.Masked()
		a := p.Addr().As4()
		lo := uint64(binary.BigEndian.Uint32(a[:]))
		rs = append(rs, rng{lo, lo + (1 << (32 - p.Bits())) - 1})
	}
	sort.Slice(rs, func(i, j int) bool { return rs[i].lo < rs[j].lo })
	var merged []rng
	for _, r := range rs {
		if n := len(merged); n > 0 && r.lo <= merged[n-1].hi+1 {
			if r.hi > merged[n-1].hi {
				merged[n-1].hi = r.hi
			}
			continue
		}
		merged = append(merged, r)
	}
	var out []netip.Prefix
	for _, r := range merged {
		out = append(out, rangeToPrefixes(r.lo, r.hi)...)
	}
	return out
}

// RegionOf returns the region keys ("NZ", "NZ/Auckland") of an IP.
func (g *Geo) RegionOf(ip string) (country, region string) {
	info := g.Lookup(ip)
	if info.Country == "" {
		return "", ""
	}
	if info.Region != "" {
		return info.Country, info.Country + "/" + info.Region
	}
	return info.Country, ""
}

// RegionSets returns CIDR strings per region key, using an on-disk cache that is
// rebuilt when the database is updated. Missing keys are computed in one pass.
func (g *Geo) RegionSets(keys []string) (map[string][]string, error) {
	regionMu.Lock()
	defer regionMu.Unlock()
	st, err := os.Stat(g.cityPath())
	if err != nil {
		return nil, errors.New("IP 离线库尚未下载")
	}
	dir := filepath.Join(g.dir, "sets")
	_ = os.MkdirAll(dir, 0o755)
	file := func(k string) string { return filepath.Join(dir, url.PathEscape(k)+".txt") }

	out := map[string][]string{}
	var missing []string
	for _, k := range keys {
		if fs, err := os.Stat(file(k)); err == nil && fs.ModTime().After(st.ModTime()) {
			if b, err := os.ReadFile(file(k)); err == nil {
				out[k] = strings.Fields(string(b))
				continue
			}
		}
		missing = append(missing, k)
	}
	if len(missing) == 0 {
		return out, nil
	}
	computed, err := g.RegionCIDRs(missing)
	if err != nil {
		return nil, err
	}
	for k, ps := range computed {
		ss := make([]string, len(ps))
		for i, p := range ps {
			ss[i] = p.String()
		}
		out[k] = ss
		_ = os.WriteFile(file(k), []byte(strings.Join(ss, "\n")+"\n"), 0o644)
	}
	return out, nil
}
