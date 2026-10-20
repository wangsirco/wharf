package panel

import (
	"compress/gzip"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/oschwald/maxminddb-golang/v2"
	"github.com/ringsaturn/tzf"
)

// Geo resolves IPs using offline DB-IP Lite databases (CC BY 4.0, https://db-ip.com)
// and derives the IP's timezone from its coordinates with tzf. No online IP API is used.
type Geo struct {
	dir string

	mu   sync.RWMutex
	city *maxminddb.Reader
	asn  *maxminddb.Reader

	tzOnce sync.Once
	tz     tzf.F
}

type GeoInfo struct {
	ASN     uint    `json:"asn"`
	ASOrg   string  `json:"as_org"`
	Country string  `json:"country"`
	Region  string  `json:"region"`
	City    string  `json:"city"`
	TZ      string  `json:"tz"`
	Lat     float64 `json:"lat"`
	Lon     float64 `json:"lon"`
}

func NewGeo(dir string) *Geo {
	g := &Geo{dir: dir}
	g.reload()
	return g
}

func (g *Geo) reload() {
	open := func(name string) *maxminddb.Reader {
		r, err := maxminddb.Open(filepath.Join(g.dir, name))
		if err != nil {
			return nil
		}
		return r
	}
	c, a := open("dbip-city-lite.mmdb"), open("dbip-asn-lite.mmdb")
	g.mu.Lock()
	old := []*maxminddb.Reader{g.city, g.asn}
	g.city, g.asn = c, a
	g.mu.Unlock()
	for _, r := range old {
		if r != nil {
			_ = r.Close()
		}
	}
}

func (g *Geo) Ready() bool {
	g.mu.RLock()
	defer g.mu.RUnlock()
	return g.city != nil && g.asn != nil
}

func (g *Geo) Lookup(ipStr string) GeoInfo { return g.lookup(ipStr, true) }

// LookupFast skips the timezone polygon search (for bulk aggregation).
func (g *Geo) LookupFast(ipStr string) GeoInfo { return g.lookup(ipStr, false) }

func (g *Geo) lookup(ipStr string, withTZ bool) GeoInfo {
	var info GeoInfo
	ip, err := netip.ParseAddr(ipStr)
	if err != nil {
		return info
	}
	g.mu.RLock()
	city, asn := g.city, g.asn
	g.mu.RUnlock()
	if asn != nil {
		var r struct {
			Num uint   `maxminddb:"autonomous_system_number"`
			Org string `maxminddb:"autonomous_system_organization"`
		}
		if asn.Lookup(ip).Decode(&r) == nil {
			info.ASN, info.ASOrg = r.Num, r.Org
		}
	}
	if city != nil {
		var r struct {
			City struct {
				Names map[string]string `maxminddb:"names"`
			} `maxminddb:"city"`
			Country struct {
				ISO string `maxminddb:"iso_code"`
			} `maxminddb:"country"`
			Subdivisions []struct {
				Names map[string]string `maxminddb:"names"`
			} `maxminddb:"subdivisions"`
			Location struct {
				Lat float64 `maxminddb:"latitude"`
				Lon float64 `maxminddb:"longitude"`
			} `maxminddb:"location"`
		}
		if city.Lookup(ip).Decode(&r) == nil {
			info.Country = r.Country.ISO
			info.City = r.City.Names["en"]
			if len(r.Subdivisions) > 0 {
				info.Region = r.Subdivisions[0].Names["en"]
			}
			info.Lat, info.Lon = r.Location.Lat, r.Location.Lon
			if withTZ && (r.Location.Lat != 0 || r.Location.Lon != 0) {
				info.TZ = g.timezone(r.Location.Lon, r.Location.Lat)
			}
		}
	}
	return info
}

func (g *Geo) timezone(lon, lat float64) string {
	g.tzOnce.Do(func() {
		f, err := tzf.NewDefaultFinder()
		if err != nil {
			log.Printf("tzf: %v", err)
			return
		}
		g.tz = f
	})
	if g.tz == nil {
		return ""
	}
	return g.tz.GetTimezoneName(lon, lat)
}

// OffsetMinutes returns the UTC offset of tz at t, in minutes east of UTC.
func OffsetMinutes(tz string, t time.Time) (int, bool) {
	loc, err := time.LoadLocation(tz)
	if err != nil {
		return 0, false
	}
	_, off := t.In(loc).Zone()
	return off / 60, true
}

// ---- database download (monthly) ----

func (g *Geo) download(kind string, month time.Time) error {
	url := fmt.Sprintf("https://download.db-ip.com/free/dbip-%s-lite-%s.mmdb.gz", kind, month.Format("2006-01"))
	resp, err := (&http.Client{Timeout: 10 * time.Minute}).Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return fmt.Errorf("%s: %s", url, resp.Status)
	}
	zr, err := gzip.NewReader(resp.Body)
	if err != nil {
		return err
	}
	_ = os.MkdirAll(g.dir, 0o755)
	dst := filepath.Join(g.dir, "dbip-"+kind+"-lite.mmdb")
	tmp := dst + ".tmp"
	f, err := os.Create(tmp)
	if err != nil {
		return err
	}
	if _, err := io.Copy(f, zr); err != nil {
		f.Close()
		os.Remove(tmp)
		return err
	}
	f.Close()
	if _, err := maxminddb.Open(tmp); err != nil {
		os.Remove(tmp)
		return fmt.Errorf("downloaded db invalid: %w", err)
	}
	return os.Rename(tmp, dst)
}

// Update fetches this month's databases, falling back to last month's.
func (g *Geo) Update() error {
	now := time.Now().UTC()
	for _, kind := range []string{"city", "asn"} {
		err := g.download(kind, now)
		if err != nil {
			err = g.download(kind, now.AddDate(0, -1, 0))
		}
		if err != nil {
			return err
		}
	}
	g.reload()
	return nil
}

// AutoUpdate refreshes the databases when missing or older than 30 days.
func (g *Geo) AutoUpdate() {
	for {
		st, err := os.Stat(filepath.Join(g.dir, "dbip-city-lite.mmdb"))
		if err != nil || time.Since(st.ModTime()) > 30*24*time.Hour {
			if err := g.Update(); err != nil {
				log.Printf("geo update: %v", err)
			} else {
				log.Printf("geo databases updated")
			}
		}
		time.Sleep(12 * time.Hour)
	}
}
