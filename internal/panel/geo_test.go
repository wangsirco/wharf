package panel

import (
	"os"
	"testing"
)

func TestGeoLookup(t *testing.T) {
	dir := os.Getenv("OWP_GEO_DIR")
	if dir == "" {
		t.Skip("OWP_GEO_DIR not set")
	}
	g := NewGeo(dir)
	for _, ip := range []string{"121.98.0.1", "8.8.8.8", "1.1.1.1", "223.5.5.5"} {
		t.Logf("%s => %+v", ip, g.Lookup(ip))
	}
}
