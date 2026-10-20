package panel

import (
	"encoding/json"
	"net/http"
	"net/netip"
	"net/url"
	"sort"
	"sync"
	"time"
)

// Anycast CDNs announce the same IPs everywhere; a geo database can only return
// where the block is registered (e.g. Cloudflare in Toronto). Traffic actually goes
// to the nearest edge, so it is counted at home instead.
var anycastASN = map[uint]string{13335: "Cloudflare", 209242: "Cloudflare", 54113: "Fastly", 20940: "Akamai", 16625: "Akamai",
	15133: "Edgecast", 60068: "CDN77", 22822: "Edgio", 30675: "Fastly", 63949: "Akamai"}

// GET /api/geo/flows?range=1h|24h|7d|30d — where the household's traffic goes,
// by country and city, for the world map. Origin is the WAN IP's location.
func (a *App) handleGeoFlows(w http.ResponseWriter, r *http.Request) {
	body, err := a.geoFlows(r.URL.Query().Get("range"), false)
	if err != nil {
		jsonErr(w, 500, err.Error())
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(body)
}

// geoWarmLoop keeps the longer ranges pre-computed so the map opens instantly.
func (a *App) geoWarmLoop() {
	time.Sleep(2 * time.Minute)
	for {
		for _, rng := range []string{"24h", "7d", "30d"} {
			_, _ = a.geoFlows(rng, true)
		}
		time.Sleep(4 * time.Minute)
	}
}

// geoFlows returns the JSON for one range: cached, or computed once even when
// several viewers ask at the same time. refresh recomputes regardless of age.
func (a *App) geoFlows(rng string, refresh bool) ([]byte, error) {
	// aggregating 30 days of flows takes seconds on the router; the picture barely
	// changes minute to minute
	ttl := map[string]time.Duration{"1h": time.Minute, "24h": 5 * time.Minute}[rng]
	if ttl == 0 {
		ttl = 15 * time.Minute
	}
	geoFlowMu.Lock()
	c, ok := geoFlowCache[rng]
	geoFlowMu.Unlock()
	if ok && time.Since(c.at) < ttl && !refresh {
		return c.body, nil
	}
	// one computation at a time per range; concurrent viewers wait for it
	l := geoFlowLock(rng)
	l.Lock()
	defer l.Unlock()
	geoFlowMu.Lock()
	c, ok = geoFlowCache[rng]
	geoFlowMu.Unlock()
	if ok && time.Since(c.at) < ttl && (!refresh || time.Since(c.at) < time.Minute) {
		return c.body, nil
	}
	r, _ := http.NewRequest("GET", "/?range="+url.QueryEscape(rng), nil)
	from, to := timeRange(r)
	type place struct {
		Code    string   `json:"code"`
		Name    string   `json:"name"`
		City    string   `json:"city,omitempty"`
		Lat     float64  `json:"lat"`
		Lon     float64  `json:"lon"`
		Bytes   int64    `json:"bytes"`
		Up      int64    `json:"up"`
		Down    int64    `json:"down"`
		Conns   int64    `json:"conns"`
		Remotes int      `json:"remotes"`
		Top     []string `json:"top,omitempty"`
		wlat    float64
		wlon    float64
		svc     map[string]int64
	}
	countries, cities := map[string]*place{}, map[string]*place{}
	var home GeoInfo
	var wanRaw json.RawMessage
	var wan struct {
		Wan struct {
			IPv4 string `json:"ipv4"`
		} `json:"wan"`
	}
	if a.agent.Do("GET", "/v1/wan", nil, &wanRaw) == nil && json.Unmarshal(wanRaw, &wan) == nil && wan.Wan.IPv4 != "" {
		home = a.geo.LookupFast(wan.Wan.IPv4)
	}
	var anycastBytes int64
	geoOf := map[string]GeoInfo{}
	rows, err := a.db.Query(`SELECT remote, domain, SUM(up), SUM(down), SUM(conns) FROM flow_hour
		WHERE hour>=? AND hour<? GROUP BY remote, domain`, from-from%3600, to)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var remote, domain string
		var up, down, conns int64
		if rows.Scan(&remote, &domain, &up, &down, &conns) != nil {
			continue
		}
		if ip, err := netip.ParseAddr(remote); err != nil || !ip.IsGlobalUnicast() || ip.IsPrivate() {
			continue
		}
		g, seen := geoOf[remote]
		if !seen {
			g = a.geo.LookupFast(remote)
			geoOf[remote] = g
		}
		b := up + down
		if _, cdn := anycastASN[g.ASN]; cdn && home.Country != "" {
			anycastBytes += b
			g.Country, g.City, g.Lat, g.Lon = home.Country, home.City, home.Lat, home.Lon
		}
		if g.Country == "" || (g.Lat == 0 && g.Lon == 0) {
			continue
		}
		c := countries[g.Country]
		if c == nil {
			c = &place{Code: g.Country, svc: map[string]int64{}}
			countries[g.Country] = c
		}
		c.Bytes, c.Up, c.Down, c.Conns, c.Remotes = c.Bytes+b, c.Up+up, c.Down+down, c.Conns+conns, c.Remotes+1
		w := float64(b) + 1
		c.wlat, c.wlon = c.wlat+g.Lat*w, c.wlon+g.Lon*w
		if id := a.identify(domain, remote); !id.Uncertain {
			c.svc[svcName(id)] += b
		}
		key := g.Country + "/" + g.City
		ct := cities[key]
		if ct == nil {
			ct = &place{Code: g.Country, City: g.City, Lat: g.Lat, Lon: g.Lon}
			cities[key] = ct
		}
		ct.Bytes += b
		ct.Conns += conns
	}
	rows.Close()

	names := map[string]string{}
	if rs, err := a.geo.Regions(); err == nil {
		for _, x := range rs {
			names[x.Code] = x.Name
		}
	}
	var cl []*place
	for _, c := range countries {
		w := float64(c.Bytes) + float64(c.Remotes)
		c.Lat, c.Lon = c.wlat/w, c.wlon/w
		c.Name = firstNonEmpty(names[c.Code], c.Code)
		type kv struct {
			k string
			v int64
		}
		var top []kv
		for k, v := range c.svc {
			top = append(top, kv{k, v})
		}
		sort.Slice(top, func(i, j int) bool { return top[i].v > top[j].v })
		for i := 0; i < len(top) && i < 3; i++ {
			c.Top = append(c.Top, top[i].k)
		}
		cl = append(cl, c)
	}
	sort.Slice(cl, func(i, j int) bool { return cl[i].Bytes > cl[j].Bytes })
	var ci []*place
	for _, c := range cities {
		c.Name = firstNonEmpty(names[c.Code], c.Code)
		ci = append(ci, c)
	}
	sort.Slice(ci, func(i, j int) bool { return ci[i].Bytes > ci[j].Bytes })
	if len(ci) > 40 {
		ci = ci[:40]
	}

	origin := map[string]any{}
	if home.Country != "" {
		origin = map[string]any{"lat": home.Lat, "lon": home.Lon, "city": home.City, "country": home.Country, "name": firstNonEmpty(names[home.Country], home.Country)}
	}
	body, _ := json.Marshal(map[string]any{"from": from, "to": to, "origin": origin, "countries": cl, "cities": ci,
		"anycast_bytes": anycastBytes, "generated": time.Now().Unix()})
	geoFlowMu.Lock()
	geoFlowCache[rng] = geoFlowEntry{time.Now(), body}
	geoFlowMu.Unlock()
	return body, nil
}

var (
	countryMu    sync.Mutex
	countryNames map[string]string
	countryAt    time.Time
)

// countryName turns an ISO code into the localized name from the region list
// (cached for an hour; the list itself lives on disk next to the IP database).
func (a *App) countryName(code string) string {
	countryMu.Lock()
	defer countryMu.Unlock()
	if countryNames == nil || time.Since(countryAt) > time.Hour {
		if rs, err := a.geo.Regions(); err == nil {
			countryNames = map[string]string{}
			for _, r := range rs {
				countryNames[r.Code] = r.Name
			}
		}
		countryAt = time.Now()
	}
	return firstNonEmpty(countryNames[code], code)
}

type geoFlowEntry struct {
	at   time.Time
	body []byte
}

var (
	geoFlowMu    sync.Mutex
	geoFlowCache = map[string]geoFlowEntry{}
	geoFlowLocks = map[string]*sync.Mutex{}
)

func geoFlowLock(rng string) *sync.Mutex {
	geoFlowMu.Lock()
	defer geoFlowMu.Unlock()
	if geoFlowLocks[rng] == nil {
		geoFlowLocks[rng] = &sync.Mutex{}
	}
	return geoFlowLocks[rng]
}
