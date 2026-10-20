package panel

import "testing"

func TestMonitorBad(t *testing.T) {
	m := Monitor{LossAlert: 10, RTTAlert: 200}
	cases := []struct {
		r   MonRow
		bad bool
	}{
		{MonRow{Sent: 20, Recv: 20, Avg: 50}, false},
		{MonRow{Sent: 20, Recv: 18, Avg: 50}, true},  // 10% loss hits the threshold
		{MonRow{Sent: 20, Recv: 19, Avg: 50}, false}, // 5%
		{MonRow{Sent: 10, Recv: 10, Avg: 250}, true}, // too slow
		{MonRow{Sent: 10, Recv: 0}, true},
	}
	for i, c := range cases {
		if bad, why := monBad(m, c.r); bad != c.bad {
			t.Errorf("case %d: bad=%v (%s)", i, bad, why)
		}
	}
	m2 := Monitor{Mode: "tcp", Port: 0, Name: "x", Target: "1.1.1.1", Interval: 5}
	if m2.validate() == nil {
		t.Error("tcp without port accepted")
	}
	m3 := Monitor{Mode: "icmp", Name: "x", Target: "1.1.1.1; reboot", Interval: 5}
	if m3.validate() == nil {
		t.Error("bad target accepted")
	}
}
