package panel

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync"
	"testing"
)

func TestPresenceEvents(t *testing.T) {
	var mu sync.Mutex
	devs := []Device{{MAC: "aa:bb:cc:00:00:01", IP: "192.168.1.50", LastSeen: 1000}}
	agent := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		_ = json.NewEncoder(w).Encode(devs)
	}))
	defer agent.Close()
	db, err := OpenDB(filepath.Join(t.TempDir(), "p.db")) // also runs the new migrations
	if err != nil {
		t.Fatal(err)
	}
	a := &App{db: db, agent: NewAgentClient(AgentConfig{URL: agent.URL, KeyID: "t", Secret: "x"})}
	set := func(seen int64) { mu.Lock(); devs[0].LastSeen = seen; mu.Unlock() }
	count := func(kind string) (n int) {
		_ = db.QueryRow(`SELECT COUNT(*) FROM device_events WHERE kind=?`, kind).Scan(&n)
		return
	}

	a.presenceTick(1060) // baseline: home, no event
	a.presenceTick(1300) // unseen 5 min: still home (default 10 min)
	if count("left") != 0 {
		t.Fatal("left too early")
	}
	a.presenceTick(1700) // unseen > 10 min
	var ts int64
	_ = db.QueryRow(`SELECT ts FROM device_events WHERE kind='left'`).Scan(&ts)
	if count("left") != 1 || ts != 1000 {
		t.Fatalf("left events=%d ts=%d, want 1 at last-seen time 1000", count("left"), ts)
	}
	a.presenceTick(2000) // still away: no duplicate
	set(4600)
	a.presenceTick(4620) // back after an hour
	var away int64
	_ = db.QueryRow(`SELECT away_secs FROM device_events WHERE kind='back'`).Scan(&away)
	if count("left") != 1 || count("back") != 1 || away != 3600 {
		t.Fatalf("left=%d back=%d away=%d", count("left"), count("back"), away)
	}
	// a device that was already gone when tracking started comes home
	mu.Lock()
	devs = append(devs, Device{MAC: "aa:bb:cc:00:00:02", IP: "192.168.1.51"})
	mu.Unlock()
	a.presenceTick(4700)
	mu.Lock()
	devs[1].LastSeen = 5000
	mu.Unlock()
	a.presenceTick(5010)
	if count("back") != 2 {
		t.Fatalf("returning never-seen device: back=%d", count("back"))
	}
	if awayText(3600) != "1 小时" || awayText(5400) != "1 小时 30 分" || awayText(90) != "1 分钟" {
		t.Fatal("awayText")
	}
}

// An agent restart forgets last-seen times; a device gone for only a minute must not
// be reported as "left" right away.
func TestPresenceAgentRestart(t *testing.T) {
	devs := []Device{{MAC: "aa:bb:cc:00:00:09", IP: "192.168.1.60", LastSeen: 1000}, {MAC: "aa:bb:cc:00:00:0a", IP: "192.168.1.61", LastSeen: 1000}}
	var mu sync.Mutex
	agent := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		_ = json.NewEncoder(w).Encode(devs)
	}))
	defer agent.Close()
	db, _ := OpenDB(filepath.Join(t.TempDir(), "p.db"))
	a := &App{db: db, agent: NewAgentClient(AgentConfig{URL: agent.URL})}
	a.presenceTick(1030)
	mu.Lock()
	devs[0].LastSeen = 0    // restarted agent has not confirmed this one
	devs[1].LastSeen = 1080 // still here
	mu.Unlock()
	a.presenceTick(1090)
	var n int
	_ = db.QueryRow(`SELECT COUNT(*) FROM device_events`).Scan(&n)
	if n != 0 {
		t.Fatalf("restart produced %d events", n)
	}
	a.presenceTick(1700) // 10+ min after its real last sighting
	var ts int64
	_ = db.QueryRow(`SELECT ts FROM device_events WHERE kind='left'`).Scan(&ts)
	if ts != 1000 {
		t.Fatalf("left at %d, want 1000", ts)
	}
}
