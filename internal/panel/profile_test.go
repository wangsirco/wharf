package panel

import (
	"testing"

	"github.com/wangsirco/wharf/internal/rules"
)

// identify must work on a zero identCache (regression: nil map panic left the lock held).
func TestIdentifyZeroCache(t *testing.T) {
	m, err := rules.Default("")
	if err != nil {
		t.Fatal(err)
	}
	a := &App{geo: NewGeo(t.TempDir()), rules: m}
	for i := 0; i < 2; i++ {
		if got := a.identify("rr1---sn-x.googlevideo.com", "142.250.66.206"); got.Service != "YouTube" || got.Category != "视频" {
			t.Fatalf("got %+v", got)
		}
	}
	if got := a.identify("", "198.51.100.7"); got.Category != "其他" {
		t.Fatalf("unknown target: %+v", got)
	}
	a.idc.reset()
	_ = a.identify("example.com", "")
}
