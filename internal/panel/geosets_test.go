package panel

import (
	"net/netip"
	"os"
	"testing"
	"time"
)

func TestMergePrefixes(t *testing.T) {
	in := []netip.Prefix{
		netip.MustParsePrefix("10.0.0.0/25"), netip.MustParsePrefix("10.0.0.128/25"),
		netip.MustParsePrefix("10.0.1.0/24"), netip.MustParsePrefix("10.0.3.0/24"),
		netip.MustParsePrefix("10.0.3.5/32"), netip.MustParsePrefix("0.0.0.0/1"), netip.MustParsePrefix("128.0.0.0/1"),
	}
	got := mergePrefixes(in)
	if len(got) != 1 || got[0].String() != "0.0.0.0/0" {
		t.Fatalf("got %v", got)
	}
	got = mergePrefixes(in[:5])
	want := []string{"10.0.0.0/23", "10.0.3.0/24"}
	if len(got) != len(want) {
		t.Fatalf("got %v", got)
	}
	for i := range want {
		if got[i].String() != want[i] {
			t.Fatalf("got %v", got)
		}
	}
	got = mergePrefixes([]netip.Prefix{netip.MustParsePrefix("10.0.0.1/32"), netip.MustParsePrefix("10.0.0.2/32"), netip.MustParsePrefix("10.0.0.3/32"), netip.MustParsePrefix("10.0.0.4/32")})
	if len(got) != 3 || got[0].String() != "10.0.0.1/32" || got[1].String() != "10.0.0.2/31" || got[2].String() != "10.0.0.4/32" {
		t.Fatalf("got %v", got)
	}
}

func TestRegionCIDRs(t *testing.T) {
	dir := os.Getenv("OWP_GEO_DIR")
	if dir == "" {
		t.Skip("OWP_GEO_DIR not set")
	}
	g := NewGeo(dir)
	start := time.Now()
	m, err := g.RegionCIDRs([]string{"NZ", "NZ/Auckland", "CN"})
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("NZ=%d NZ/Auckland=%d CN=%d in %v", len(m["NZ"]), len(m["NZ/Auckland"]), len(m["CN"]), time.Since(start))
	start = time.Now()
	rs, err := g.Regions()
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range rs {
		if r.Code == "NZ" {
			t.Logf("%s %s %v (%v)", r.Code, r.Name, r.Regions, time.Since(start))
		}
	}
}
