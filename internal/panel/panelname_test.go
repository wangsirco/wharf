package panel

import (
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
)

func TestPanelNames(t *testing.T) {
	cf := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer tok" {
			_, _ = w.Write([]byte(`{"success":false,"errors":[{"message":"Invalid API Token"}]}`))
			return
		}
		if r.URL.Query().Get("name") == "example.com" {
			_, _ = w.Write([]byte(`{"success":true,"result":[{"id":"zone1"}]}`))
			return
		}
		_, _ = w.Write([]byte(`{"success":true,"result":[]}`))
	}))
	defer cf.Close()
	cfAPI = cf.URL
	defer func() { cfAPI = "https://api.cloudflare.com/client/v4" }()

	if z, err := cfZone(cfCall("tok"), "panel.example.com"); err != nil || z != "zone1" {
		t.Fatalf("zone %q %v", z, err)
	}
	if _, err := cfZone(cfCall("bad"), "panel.example.com"); err == nil {
		t.Fatal("bad token accepted")
	}

	db, err := OpenDB(filepath.Join(t.TempDir(), "n.db"))
	if err != nil {
		t.Fatal(err)
	}
	a := &App{db: db}
	// no token anywhere
	if a.cfTokenFor("panel.example.com") != "" {
		t.Fatal("token from nowhere")
	}
	// a Cloudflare DDNS entry for the same zone lends its token
	_, _ = db.Exec(`INSERT INTO ddns(name, provider, creds, domain, created) VALUES('home', 'cloudflare', '{"token":"tok"}', 'home.example.com', 1)`)
	_, _ = db.Exec(`INSERT INTO ddns(name, provider, creds, domain, created) VALUES('other', 'cloudflare', '{"token":"nope"}', 'home.other.org', 1)`)
	if got := a.cfTokenFor("panel.example.com"); got != "tok" {
		t.Fatalf("token from DDNS: %q", got)
	}
	// the panel's own token wins
	_ = a.setSetting("panel.cf_token", "own")
	if a.cfTokenFor("panel.example.com") != "own" {
		t.Fatal("own token")
	}
	if id, ok := userIDFromHandle([]byte("wharf-user-12")); !ok || id != 12 {
		t.Fatal("handle")
	}
	if _, ok := userIDFromHandle([]byte("someone-else")); ok {
		t.Fatal("foreign handle")
	}
}
