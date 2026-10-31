package panel

import (
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestPresenceAlerts(t *testing.T) {
	db, err := OpenDB(filepath.Join(t.TempDir(), "a.db"))
	if err != nil {
		t.Fatal(err)
	}
	a := &App{db: db}
	var sent []string
	sendAlert = func(_, title, body string) error { sent = append(sent, title+"|"+body); return nil }
	defer func() { sendAlert = sendTo }()
	_, _ = db.Exec(`INSERT INTO alert_channels(name, url, enabled) VALUES('t', 'telegram://x/1', 1)`)

	// rules saved by 0.18 (one "offline" watch list) carry over to both directions
	_ = a.setSetting("alerts.rules", `{"new_device":true,"offline_watch":["aa:00:00:00:00:01"],"offline_minutes":5}`)
	r := a.alertRules()
	if !r.DeviceLeft || !r.DeviceBack || len(r.PresenceWatch) != 1 || r.OfflineWatch != nil {
		t.Fatalf("migration: %+v", r)
	}

	evs := []presenceEv{
		{ts: 1000, mac: "aa:00:00:00:00:01", ip: "192.168.1.5", kind: "left"},
		{ts: 1000, mac: "aa:00:00:00:00:02", ip: "192.168.1.6", kind: "left"}, // not watched
	}
	a.presenceAlerts(evs)
	if len(sent) != 1 || !strings.Contains(sent[0], "设备离开：aa:00:00:00:00:01 192.168.1.5|最后在线") {
		t.Fatalf("watched only: %q", sent)
	}

	// every device, only "back", several at once -> one grouped message
	sent = nil
	_ = a.setSetting("alerts.rules", `{"device_left":false,"device_back":true,"presence_all":true,"presence_watch":[]}`)
	a.presenceAlerts(append(evs,
		presenceEv{ts: 5000, mac: "aa:00:00:00:00:03", ip: "192.168.1.7", kind: "back", away: 3600},
		presenceEv{ts: 5000, mac: "aa:00:00:00:00:04", ip: "192.168.1.8", kind: "back"}))
	if len(sent) != 1 || !strings.Contains(sent[0], "2 台设备回来|") || !strings.Contains(sent[0], "（离开了 1 小时）") {
		t.Fatalf("grouped: %q", sent)
	}
}

func TestSpikeAndRandomMAC(t *testing.T) {
	db, err := OpenDB(filepath.Join(t.TempDir(), "s.db"))
	if err != nil {
		t.Fatal(err)
	}
	a := &App{db: db}
	var sent []string
	sendAlert = func(_, title, body string) error { sent = append(sent, title+"|"+body); return nil }
	defer func() { sendAlert = sendTo }()
	_, _ = db.Exec(`INSERT INTO alert_channels(name, url, enabled) VALUES('t', 'telegram://x/1', 1)`)

	now := time.Now().Unix()
	hour := now - now%3600
	mb := int64(1 << 20)
	for mac, used := range map[string]int64{"aa:00:00:00:00:01": 600, "aa:00:00:00:00:02": 600, "aa:00:00:00:00:03": 600, "aa:00:00:00:00:04": 100} {
		_, _ = db.Exec(`INSERT INTO traffic_hour(hour, mac, up, down) VALUES(?,?,0,?)`, hour, mac, used*mb)
	}
	r := defaultRules
	r.SpikeMBPerHour = 500
	r.SpikeExclude = []string{"aa:00:00:00:00:02"}            // NAS
	r.SpikeCustom = map[string]int{"aa:00:00:00:00:03": 1000} // TV: higher limit
	st := &alertState{spikeSent: map[string]int64{}}
	a.spikeTick(st, r, now)
	a.spikeTick(st, r, now) // once per window
	if len(sent) != 1 || !strings.Contains(sent[0], "aa:00:00:00:00:01") || !strings.Contains(sent[0], "本小时") {
		t.Fatalf("spike: %q", sent)
	}

	// a phone's new private MAC with a name already known is the same phone
	_, _ = db.Exec(`INSERT INTO devices_seen(mac, name, ip, first_seen, last_seen) VALUES('aa:00:00:00:00:10', 'Pixel-8', '192.168.1.20', 1, 1)`)
	if !a.knownByName("da:00:00:00:00:11", "Pixel-8") || a.knownByName("da:00:00:00:00:11", "Other") || a.knownByName("da:00:00:00:00:11", "") {
		t.Fatal("knownByName")
	}
}
