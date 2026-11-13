package panel

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestNextHopBeyond(t *testing.T) {
	cases := []struct {
		hops       []string
		wan, ip, k string
	}{
		{[]string{"192.168.1.1", "100.72.0.1", "61.0.0.1"}, "192.168.1.5", "100.72.0.1", "cgnat"},
		{[]string{"192.168.1.1", "", "61.0.0.1"}, "192.168.1.5", "61.0.0.1", "public"},
		{[]string{"192.168.1.1", "192.168.0.1", "10.10.0.1"}, "192.168.1.5", "10.10.0.1", "private"},
		{[]string{"192.168.1.1"}, "192.168.1.5", "", "unknown"},
	}
	for _, c := range cases {
		ip, k := nextHopBeyond(c.hops, c.wan)
		if ip != c.ip || k != c.k {
			t.Errorf("%v: got %s %s, want %s %s", c.hops, ip, k, c.ip, c.k)
		}
	}
}

func TestMajorityIP(t *testing.T) {
	s := []pubSeen{{IP: "203.0.113.9"}, {IP: "198.51.100.1"}, {IP: "198.51.100.1"}, {Error: "x"}}
	if got := majorityIP(s); got != "198.51.100.1" {
		t.Fatal(got)
	}
	if !seenIncludes(s, "203.0.113.9") || seenIncludes(s, "1.1.1.1") {
		t.Fatal("seenIncludes")
	}
}

func TestCleanBlocksDropsValues(t *testing.T) {
	in := `[{"type":"map","map":{"config":"x","sections":[{"options":[{"option":"password","values":{"main":"secret"}}]}]}}]`
	out, err := cleanBlocks(json.RawMessage(in))
	if err != nil || strings.Contains(string(out), "secret") || strings.Contains(string(out), "values") {
		t.Fatalf("%s %v", out, err)
	}
	if _, err := cleanBlocks(json.RawMessage(`{"a":1}`)); err == nil {
		t.Fatal("object accepted")
	}
}
