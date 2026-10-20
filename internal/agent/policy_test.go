package agent

import (
	"testing"
	"time"
)

func TestScheduleActive(t *testing.T) {
	// weekdays 22:00 -> 07:00 next morning
	sc, err := ParseSchedule("days=1,2,3,4,5;start=22:00;end=07:00")
	if err != nil {
		t.Fatal(err)
	}
	loc := time.FixedZone("NZ", 13*3600)
	at := func(day, hh, mm int) time.Time { return time.Date(2026, 10, 4+day, hh, mm, 0, 0, loc) } // 2026-10-04 is a Sunday
	cases := []struct {
		t    time.Time
		want bool
	}{
		{at(1, 22, 0), true},   // Mon 22:00
		{at(2, 6, 59), true},   // Tue 06:59 (Mon night)
		{at(2, 7, 0), false},   // Tue 07:00
		{at(0, 23, 0), false},  // Sun 23:00 (Sunday not listed)
		{at(1, 3, 0), false},   // Mon 03:00 (Sunday night not listed)
		{at(6, 3, 0), true},    // Sat 03:00 (Friday night)
		{at(6, 22, 30), false}, // Sat 22:30
	}
	for _, c := range cases {
		if got := sc.Active(c.t); got != c.want {
			t.Errorf("%s: got %v want %v", c.t.Format("Mon 15:04"), got, c.want)
		}
	}
	day, _ := ParseSchedule("days=0,6;start=09:00;end=12:00")
	if !day.Active(at(0, 10, 0)) || day.Active(at(0, 12, 0)) || day.Active(at(1, 10, 0)) {
		t.Error("daytime schedule")
	}
	if _, err := ParseSchedule("days=8;start=09:00;end=10:00"); err == nil {
		t.Error("bad day accepted")
	}
}

func TestSetName(t *testing.T) {
	if n := setFor("AA:bb:cc:dd:ee:ff", "b"); len(n) > 31 || n != setFor("aa:bb:cc:dd:ee:ff", "b") {
		t.Fatalf("bad set name %q", n)
	}
}
