package panel

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/wangsirco/wharf/internal/sign"
)

// A v3 Berth: Wharf learns its names, uses only the chosen one, and switches on request.
func TestBerthV3NamesAndMode(t *testing.T) {
	a, _, su := berthApp(t)
	_, out := pair(t, a, su, append(allScopes, "stats"))
	var mu sync.Mutex
	var events []string
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		if _, err := sign.CheckPrefixed(r, "X-Wharf", sign.DeriveKey(out), body); err != nil {
			w.WriteHeader(401)
			return
		}
		switch r.URL.Path {
		case "/api/ext/wharf/v1/ping":
			_, _ = w.Write([]byte(`{"ok":true,"protocol":3}`))
		case "/api/ext/wharf/v1/names":
			_, _ = w.Write([]byte(`{"lan":"` + "https://" + r.Host + `","public":"https://` + strings.Replace(r.Host, "127.0.0.1", "localhost", 1) + `"}`))
		case "/api/ext/wharf/v1/events":
			mu.Lock()
			events = append(events, string(body))
			mu.Unlock()
		case "/api/ext/wharf/v1/sso/ticket":
			_, _ = w.Write([]byte(`{"url":"https://` + r.Host + `/sso?t=1","via":"lan"}`))
		}
	}))
	defer srv.Close()
	h := sha256.Sum256(srv.Certificate().Raw)
	_, _ = a.db.Exec(`UPDATE berth_link SET url=?, urls=?, cert_fp=?`, srv.URL, mustJSON([]string{srv.URL}), hex.EncodeToString(h[:]))
	l := a.berth()
	a.refreshPeer(l, true)
	l = a.berth()
	pub := strings.Replace(srv.URL, "127.0.0.1", "localhost", 1)
	if l.PeerProto != 3 || l.PeerLAN != srv.URL || l.PeerPub != pub || l.Mode != "lan" {
		t.Fatalf("peer %+v", l)
	}
	if c := l.candidates(); len(c) != 1 || c[0] != srv.URL {
		t.Fatalf("candidates %v", c)
	}
	// public needs a public name on Wharf's side too
	b, _ := json.Marshal(map[string]string{"mode": "public"})
	w := httptest.NewRecorder()
	a.handleBerthMode(w, asUser(httptest.NewRequest("POST", "/", strings.NewReader(string(b))), su))
	if w.Code != 400 || !strings.Contains(w.Body.String(), "外网访问") {
		t.Fatalf("public without a Wharf name: %d %s", w.Code, w.Body)
	}
	_ = a.setSetting("panel.public_names", `["wharf.example.com"]`)
	_ = a.setSetting("panel.via_443", "1")
	w = httptest.NewRecorder()
	a.handleBerthMode(w, asUser(httptest.NewRequest("POST", "/", strings.NewReader(string(b))), su))
	if w.Code != 200 {
		t.Fatalf("mode: %d %s", w.Code, w.Body)
	}
	if c := a.berth().candidates(); len(c) != 1 || c[0] != pub {
		t.Fatalf("public candidates %v", c)
	}
	// (link.mode then goes to Berth's public name — unreachable here, as it should be)
	mu.Lock()
	_ = events
	mu.Unlock()
}

func TestBerthV3Inbound(t *testing.T) {
	a, _, su := berthApp(t)
	tok, _ := pair(t, a, su, append(allScopes, "stats"))
	_ = a.setSetting("panel.lan443", "1")
	w := call(a, tok, "", a.handleBerthNames, "GET", "/api/ext/berth/v1/names", nil)
	var n panelNames
	_ = json.Unmarshal(w.Body.Bytes(), &n)
	if w.Code != 200 || n.LAN != "https://wharf.lan" || n.Public != "" {
		t.Fatalf("names %d %s", w.Code, w.Body)
	}
	// SSO to the public name when asked, falling back to the LAN one when there is none
	w = call(a, tok, "sso", a.handleBerthSSOTicket, "POST", "/api/ext/berth/v1/sso/ticket", map[string]string{"berth_user": "x", "via": "public"})
	if w.Code != 403 { // no user mapping yet
		t.Fatalf("sso without mapping: %d", w.Code)
	}
	_, _ = a.db.Exec(`INSERT INTO berth_user_map(berth_user, wharf_user_id) VALUES('x',?)`, su.ID)
	w = call(a, tok, "sso", a.handleBerthSSOTicket, "POST", "/api/ext/berth/v1/sso/ticket", map[string]string{"berth_user": "x", "via": "public"})
	if !strings.Contains(w.Body.String(), `"via":"lan"`) || !strings.Contains(w.Body.String(), "https://wharf.lan/sso/berth?t=") {
		t.Fatalf("sso fallback %s", w.Body)
	}
	// stats: summary needs the scope; forwards only Berth's own
	if w := call(a, tok, "stats", a.handleBerthStatsSummary, "GET", "/api/ext/berth/v1/stats/summary", nil); w.Code != 200 || !strings.Contains(w.Body.String(), `"pages"`) {
		t.Fatalf("summary %d %s", w.Code, w.Body)
	}
	w = call(a, tok, "stats", a.handleBerthForwardStatsOwn, "GET", "/api/ext/berth/v1/stats/forwards/nope", nil, func(r *http.Request) { r.SetPathValue("id", "nope") })
	if w.Code != 404 {
		t.Fatalf("someone else's forward: %d", w.Code)
	}
	_, _ = a.db.Exec(`UPDATE berth_link SET scopes='["sso"]'`)
	if w := call(a, tok, "stats", a.handleBerthStatsSummary, "GET", "/api/ext/berth/v1/stats/summary", nil); w.Code != 403 {
		t.Fatalf("without stats scope: %d", w.Code)
	}
}

func TestStepErr(t *testing.T) {
	_, err := net.Dial("tcp", "127.0.0.1:1")
	if s := stepErr("https://mini.lan", err); !strings.Contains(s, "连不上") {
		t.Fatal(s)
	}
	if s := stepErr("https://mini.lan", &net.DNSError{Err: "no such host", Name: "mini.lan"}); !strings.Contains(s, "解析不到 mini.lan") {
		t.Fatal(s)
	}
	if s := stepErr("https://mini.lan", errors.New("对方证书与配对时记录的指纹不符")); !strings.Contains(s, "证书不对") {
		t.Fatal(s)
	}
}

// Addresses that failed once and never came back don't pile up in the limiter.
func TestLimiterForgets(t *testing.T) {
	l := newLimiter(5, time.Millisecond)
	for i := range 6000 {
		l.record("ip:" + strconv.Itoa(i))
		if i%1000 == 0 {
			time.Sleep(2 * time.Millisecond)
		}
	}
	if n := len(l.fail); n > 2001 {
		t.Fatalf("%d keys kept", n)
	}
}

// Berth's public name behind Cloudflare Access: the switch is refused with the reason.
func TestBerthAccessDetected(t *testing.T) {
	a, _, su := berthApp(t)
	pair(t, a, su, allScopes)
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "https://team.cloudflareaccess.com/cdn-cgi/access/login/x", http.StatusFound)
	}))
	defer srv.Close()
	h := sha256.Sum256(srv.Certificate().Raw)
	_, _ = a.db.Exec(`UPDATE berth_link SET cert_fp=?`, hex.EncodeToString(h[:]))
	err := a.checkPeerURL(a.berth(), srv.URL)
	if err == nil || !strings.Contains(err.Error(), "Cloudflare Access") {
		t.Fatalf("got %v", err)
	}
}

// A passkey-only account whose passkey is on another name is told why, not "wrong password".
func TestPasskeyOnOtherName(t *testing.T) {
	a, _, su := berthApp(t)
	_, _ = a.db.Exec(`UPDATE users SET login_mode='passkey' WHERE id=?`, su.ID)
	_, _ = a.db.Exec(`INSERT INTO passkeys(user_id, name, rp_id, cred_id, cred, created) VALUES(?,?,?,?,?,?)`, su.ID, "mac", a.localPanelName(), "x", "{}", 1)
	body := strings.NewReader(`{"username":"root","password":"correct-horse"}`)
	r := httptest.NewRequest("POST", "https://wharf.example.com/api/login", body)
	r.Host = "wharf.example.com"
	w := httptest.NewRecorder()
	a.handleLogin(w, r)
	if w.Code != 403 || !strings.Contains(w.Body.String(), "跟着名字走") {
		t.Fatalf("%d %s", w.Code, w.Body)
	}
}

// The one-time link opens only the panel's own name, once.
func TestHop(t *testing.T) {
	a, _, su := berthApp(t)
	_ = a.setSetting("panel.public_names", `["wharf.example.com"]`)
	_ = a.setSetting("panel.via_443", "1")
	do := func(to string) *httptest.ResponseRecorder {
		w := httptest.NewRecorder()
		a.handleHop(w, asUser(httptest.NewRequest("POST", "/", strings.NewReader(`{"to":"`+to+`","path":"/account?passkey=add"}`)), su))
		return w
	}
	if w := do("evil.example.net"); w.Code != 400 {
		t.Fatalf("foreign host: %d", w.Code)
	}
	w := do("wharf.example.com")
	var out struct{ URL string }
	_ = json.Unmarshal(w.Body.Bytes(), &out)
	if !strings.HasPrefix(out.URL, "https://wharf.example.com/hop/") {
		t.Fatalf("url %s", out.URL)
	}
	tk := strings.TrimPrefix(out.URL, "https://wharf.example.com/hop/")
	in := func(host string) *httptest.ResponseRecorder {
		r := httptest.NewRequest("GET", "/hop/"+tk, nil)
		r.Host = host
		r.SetPathValue("t", tk)
		w := httptest.NewRecorder()
		a.handleHopIn(w, r)
		return w
	}
	if w := in("wharf.example.com"); w.Code != 200 || !strings.Contains(w.Body.String(), "/account?passkey=add") || len(w.Result().Cookies()) == 0 {
		t.Fatalf("hop in: %d %s", w.Code, w.Body)
	}
	if w := in("wharf.example.com"); w.Code != 401 {
		t.Fatalf("second use: %d", w.Code)
	}
}
