package panel

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/wangsirco/wharf/internal/sign"
)

// ---- a fake agent: uci in memory, a few devices, one WAN ----

type fakeAgent struct {
	mu      sync.Mutex
	uci     map[string]map[string]Section
	sets    map[string][]string
	guarded int
	plugins []map[string]any
}

func newFakeAgent(t *testing.T) (*fakeAgent, *AgentClient) {
	fa := &fakeAgent{uci: map[string]map[string]Section{"firewall": {}, "owpfwd": {}, "dhcp": {}, "network": {}}, sets: map[string][]string{}}
	srv := httptest.NewServer(http.HandlerFunc(fa.serve))
	t.Cleanup(srv.Close)
	return fa, NewAgentClient(AgentConfig{URL: srv.URL, KeyID: "k", Secret: "s"})
}

func (fa *fakeAgent) serve(w http.ResponseWriter, r *http.Request) {
	fa.mu.Lock()
	defer fa.mu.Unlock()
	out := func(v any) { _ = json.NewEncoder(w).Encode(v) }
	switch r.URL.Path {
	case "/v1/uci":
		out(fa.uci[r.URL.Query().Get("config")])
	case "/v1/uci/apply", "/v1/uci/guarded":
		var req struct{ Changes []UciChange }
		_ = json.NewDecoder(r.Body).Decode(&req)
		res := fa.apply(req.Changes)
		if r.URL.Path == "/v1/uci/guarded" {
			fa.guarded++
			out(map[string]any{"results": res, "pending": map[string]any{"token": "tok", "deadline": 99, "configs": []string{"network"}}})
			return
		}
		out(map[string]any{"results": res})
	case "/v1/plugins":
		out(fa.plugins)
	case "/v1/uci/confirm", "/v1/uci/rollback":
		out(map[string]bool{"ok": true})
	default:
		fa.serve2(w, r)
	}
}

func (fa *fakeAgent) apply(changes []UciChange) []UciResult {
	req := struct{ Changes []UciChange }{changes}
	var res []UciResult
	for i, c := range req.Changes {
		cfg := fa.uci[c.Config]
		if cfg == nil {
			cfg = map[string]Section{}
			fa.uci[c.Config] = cfg
		}
		sec := c.Section
		switch c.Op {
		case "add":
			sec = c.Name
			if sec == "" {
				sec = "cfg" + strconv.Itoa(i)
			}
			s := Section{".type": c.Type}
			for k, v := range c.Values {
				s[k] = jsonish(v)
			}
			cfg[sec] = s
		case "set":
			for k, v := range c.Values {
				cfg[sec][k] = jsonish(v)
			}
		case "delete":
			if len(c.Options) > 0 {
				for _, o := range c.Options {
					delete(cfg[sec], o)
				}
			} else {
				delete(cfg, sec)
			}
		}
		res = append(res, UciResult{Config: c.Config, Section: sec, After: cfg[sec]})
	}
	return res
}

func (fa *fakeAgent) serve2(w http.ResponseWriter, r *http.Request) {
	out := func(v any) { _ = json.NewEncoder(w).Encode(v) }
	switch r.URL.Path {
	case "/v1/devices":
		out([]Device{{MAC: "aa:bb:cc:00:00:20", IP: "192.168.1.20", Hostname: "mini", Online: true}, {MAC: "aa:bb:cc:00:00:30", IP: "192.168.1.30", Hostname: "nas", Online: true}})
	case "/v1/wans":
		out([]wanInfo{{Interface: "wan", Device: "eth1", IPv4: "203.0.113.9", Up: true}})
	case "/v1/listen":
		out([]listener{})
	case "/v1/ipset":
		var req SetWriteReq
		_ = json.NewDecoder(r.Body).Decode(&req)
		if req.Remove {
			delete(fa.sets, req.Name)
		} else {
			fa.sets[req.Name] = req.Entries
		}
		out(map[string]string{"path": "/tmp/sets/" + req.Name + ".txt"})
	default:
		w.WriteHeader(404)
		out(map[string]string{"error": "not here"})
	}
}

type SetWriteReq struct {
	Name    string   `json:"name"`
	Entries []string `json:"entries"`
	Remove  bool     `json:"remove"`
}

// jsonish stores values the way they come back from the agent (lists as []any).
func jsonish(v any) any {
	b, _ := json.Marshal(v)
	var x any
	_ = json.Unmarshal(b, &x)
	return x
}

func berthApp(t *testing.T) (*App, *fakeAgent, *User) {
	t.Helper()
	dir := t.TempDir()
	db, err := OpenDB(filepath.Join(dir, "b.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	fa, ag := newFakeAgent(t)
	cfg := DefaultConfig()
	cfg.DataDir = dir
	cfg.Listen = ":7080"
	a := &App{cfg: cfg, db: db, agent: ag, limiter: newLimiter(50, 15*time.Minute), blockedLog: newLimiter(1, time.Minute), geo: NewGeo(dir)}
	su, err := a.createUser("root", "Root", "correct-horse", RoleSuper)
	if err != nil {
		t.Fatal(err)
	}
	return a, fa, su
}

func asUser(r *http.Request, u *User) *http.Request {
	return r.WithContext(context.WithValue(r.Context(), userKey, u))
}

// pair runs the browser half (approve) and the server half (exchange); returns Wharf's token.
func pair(t *testing.T, a *App, su *User, scopes []string) (string, string) {
	t.Helper()
	body := map[string]any{"berth_url": "https://berth.example.net:8443", "berth_fp": strings.Repeat("ab", 32), "code": "berth-state",
		"cb": "https://berth.example.net:8443/integrations/wharf/done", "scopes": scopes, "expires_days": 0,
		"targets": []berthTarget{{IP: "192.168.1.20", MAC: "aa:bb:cc:00:00:20", Name: "mini"}}}
	b, _ := json.Marshal(body)
	r := asUser(httptest.NewRequest("POST", "https://wharf.lan/api/berth/pair/approve", bytes.NewReader(b)), su)
	r.Host = "wharf.lan:7080"
	w := httptest.NewRecorder()
	a.handleBerthPairApprove(w, r)
	if w.Code != 200 {
		t.Fatalf("approve: %d %s", w.Code, w.Body)
	}
	var ap struct{ Redirect string }
	_ = json.Unmarshal(w.Body.Bytes(), &ap)
	u, _ := url.Parse(ap.Redirect)
	if u.Host != "berth.example.net:8443" || u.Query().Get("state") != "berth-state" || u.Query().Get("wharf_url") != "https://wharf.lan:7080" {
		t.Fatalf("redirect %s", ap.Redirect)
	}
	code := u.Query().Get("code")
	outTok := "berth_wrf_" + strings.Repeat("7", 32)
	ex, _ := json.Marshal(map[string]string{"code": code, "token": outTok, "name": "mini"})
	w = httptest.NewRecorder()
	a.handleBerthExchange(w, httptest.NewRequest("POST", "/api/ext/berth/v1/pair/exchange", bytes.NewReader(ex)))
	if w.Code != 200 {
		t.Fatalf("exchange: %d %s", w.Code, w.Body)
	}
	var res struct{ Token string }
	_ = json.Unmarshal(w.Body.Bytes(), &res)
	if !strings.HasPrefix(res.Token, berthTokenPrefix) {
		t.Fatalf("token %q", res.Token)
	}
	// the code works once
	w = httptest.NewRecorder()
	a.handleBerthExchange(w, httptest.NewRequest("POST", "/api/ext/berth/v1/pair/exchange", bytes.NewReader(ex)))
	if w.Code != 401 {
		t.Fatalf("second exchange: %d", w.Code)
	}
	return res.Token, outTok
}

var allScopes = []string{"forwards", "sni", "ddns", "devices.read", "traffic.read", "bans", "alerts", "sso"}

// call sends a request signed as Berth through berthAPI(scope, h).
func call(a *App, token, scope string, h http.HandlerFunc, method, target string, body any, mut ...func(*http.Request)) *httptest.ResponseRecorder {
	var raw []byte
	if body != nil {
		raw, _ = json.Marshal(body)
	}
	r := httptest.NewRequest(method, target, bytes.NewReader(raw))
	r.Header.Set("Authorization", "Bearer "+token)
	sign.SignPrefixed(r, "X-Berth", sign.DeriveKey(token), raw)
	for _, m := range mut {
		m(r)
	}
	w := httptest.NewRecorder()
	a.berthAPI(scope, h)(w, r)
	return w
}

func TestBerthPairingStoresLink(t *testing.T) {
	a, _, su := berthApp(t)
	_, out := pair(t, a, su, allScopes)
	l := a.berth()
	if l == nil || l.Name != "mini" || l.outToken != out || len(l.signKey) != 32 || l.WharfURL != "https://wharf.lan:7080" || l.state() != "active" {
		t.Fatalf("link %+v", l)
	}
	// a second Berth cannot pair while one is paired
	b, _ := json.Marshal(map[string]any{"berth_url": "https://b2.example.net", "berth_fp": strings.Repeat("cd", 32), "code": "x", "cb": "https://b2.example.net/cb", "scopes": []string{"sso"}})
	w := httptest.NewRecorder()
	a.handleBerthPairApprove(w, asUser(httptest.NewRequest("POST", "/", bytes.NewReader(b)), su))
	if w.Code != 409 {
		t.Fatalf("second pairing: %d", w.Code)
	}
}

func TestBerthPairingRejectsForeignCallback(t *testing.T) {
	if checkBerthCallback("https://berth.example.net", "https://evil.example.com/cb") == nil {
		t.Fatal("callback to another host accepted")
	}
	if checkBerthCallback("https://berth.example.net", "https://berth.example.net/cb") != nil {
		t.Fatal("own callback refused")
	}
}

func TestBerthSignature(t *testing.T) {
	a, _, su := berthApp(t)
	tok, _ := pair(t, a, su, []string{"sso", "devices.read"})
	if w := call(a, tok, "", a.handleBerthPing, "GET", "/api/ext/berth/v1/ping", nil); w.Code != 200 {
		t.Fatalf("ping %d %s", w.Code, w.Body)
	}
	// replay: same nonce twice
	var saved http.Header
	w := call(a, tok, "", a.handleBerthPing, "GET", "/api/ext/berth/v1/ping", nil, func(r *http.Request) { saved = r.Header.Clone() })
	if w.Code != 200 {
		t.Fatal(w.Code)
	}
	w = call(a, tok, "", a.handleBerthPing, "GET", "/api/ext/berth/v1/ping", nil, func(r *http.Request) { r.Header = saved })
	if w.Code != 401 || !strings.Contains(w.Body.String(), "nonce") {
		t.Fatalf("replay: %d %s", w.Code, w.Body)
	}
	// out of the time window
	w = call(a, tok, "", a.handleBerthPing, "GET", "/api/ext/berth/v1/ping", nil, func(r *http.Request) {
		ts := strconv.FormatInt(time.Now().Add(-2*time.Minute).Unix(), 10)
		r.Header.Set("X-Berth-Ts", ts)
	})
	if w.Code != 401 {
		t.Fatalf("skew: %d", w.Code)
	}
	// body changed after signing
	w = call(a, tok, "", a.handleBerthPing, "POST", "/api/ext/berth/v1/ping", map[string]int{"a": 1}, func(r *http.Request) {
		r.Body = io.NopCloser(strings.NewReader(`{"a":2}`))
	})
	if w.Code != 401 {
		t.Fatalf("tampered: %d", w.Code)
	}
	// wrong token
	if w := call(a, berthTokenPrefix+"nope", "", a.handleBerthPing, "GET", "/api/ext/berth/v1/ping", nil); w.Code != 401 {
		t.Fatalf("bad token: %d", w.Code)
	}
	// scope not granted
	if w := call(a, tok, "forwards", a.handleBerthForwards, "GET", "/api/ext/berth/v1/forwards", nil); w.Code != 403 {
		t.Fatalf("scope: %d", w.Code)
	}
	// expired
	_, _ = a.db.Exec(`UPDATE berth_link SET expires_at=?`, time.Now().Add(-time.Hour).Unix())
	if w := call(a, tok, "", a.handleBerthPing, "GET", "/api/ext/berth/v1/ping", nil); w.Code != 401 || !strings.Contains(w.Body.String(), "过期") {
		t.Fatalf("expired: %d %s", w.Code, w.Body)
	}
}

func TestBerthOutboundPinsCertificate(t *testing.T) {
	a, _, su := berthApp(t)
	_, out := pair(t, a, su, allScopes)
	var got struct {
		sync.Mutex
		path, actor string
		ok          bool
	}
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		_, err := sign.CheckPrefixed(r, "X-Wharf", sign.DeriveKey(out), body)
		got.Lock()
		got.path, got.ok = r.URL.Path, err == nil && r.Header.Get("Authorization") == "Bearer "+out
		got.Unlock()
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer srv.Close()
	h := sha256.Sum256(srv.Certificate().Raw)
	_, _ = a.db.Exec(`UPDATE berth_link SET url=?, cert_fp=?`, srv.URL, hex.EncodeToString(h[:]))
	if err := a.berthCall(a.berth(), "GET", "/ping", nil, nil); err != nil {
		t.Fatal(err)
	}
	if got.path != "/api/ext/wharf/v1/ping" || !got.ok {
		t.Fatalf("berth saw %+v", got.path)
	}
	_, _ = a.db.Exec(`UPDATE berth_link SET cert_fp=?`, strings.Repeat("00", 32))
	if err := a.berthCall(a.berth(), "GET", "/ping", nil, nil); err == nil || !strings.Contains(err.Error(), "指纹") {
		t.Fatalf("wrong fingerprint accepted: %v", err)
	}
}

func TestBerthForwardsOnlyItsOwn(t *testing.T) {
	a, fa, su := berthApp(t)
	tok, _ := pair(t, a, su, allScopes)
	create := call(a, tok, "forwards", a.handleBerthForwardCreate, "POST", "/api/ext/berth/v1/forwards", map[string]any{
		"name": "berth: vault.example.net", "proto": "tcp", "wan_port": "8443", "target_ip": "192.168.1.20", "target_port": "443",
		"mode": "all", "berth_ref": "site:vault.example.net", "berth_host": "mini"}, func(r *http.Request) { r.Header.Set("X-Berth-Actor", "王 · 新建站点") })
	if create.Code != 200 {
		t.Fatalf("create %d %s", create.Code, create.Body)
	}
	var res struct{ ID string }
	_ = json.Unmarshal(create.Body.Bytes(), &res)
	st, _ := a.loadFwState()
	f := st.forward(res.ID)
	if f == nil || f.Kind != berthKind || f.BerthRef != "site:vault.example.net" || f.LanIP != "192.168.1.20" || f.WanPort != "8443" {
		t.Fatalf("forward %+v", f)
	}
	var who, summary string
	_ = a.db.QueryRow(`SELECT username, summary FROM audit WHERE action='forward.save'`).Scan(&who, &summary)
	if who != "Berth（mini）" || !strings.Contains(summary, "王 · 新建站点") {
		t.Fatalf("audit %q %q", who, summary)
	}

	// another device is off limits
	w := call(a, tok, "forwards", a.handleBerthForwardCreate, "POST", "/api/ext/berth/v1/forwards", map[string]any{"proto": "tcp", "wan_port": "8444", "target_ip": "192.168.1.30", "target_port": "80"})
	if w.Code != 400 {
		t.Fatalf("other target: %d %s", w.Code, w.Body)
	}
	// the same WAN port is taken
	w = call(a, tok, "forwards", a.handleBerthForwardCreate, "POST", "/api/ext/berth/v1/forwards", map[string]any{"proto": "tcp", "wan_port": "8443", "target_ip": "192.168.1.20", "target_port": "80"})
	if w.Code != 409 {
		t.Fatalf("conflict: %d %s", w.Code, w.Body)
	}
	// plan only previews
	before := len(fa.uci["firewall"])
	w = call(a, tok, "forwards", a.handleBerthForwardCreate, "POST", "/api/ext/berth/v1/forwards?plan=1", map[string]any{"proto": "tcp", "wan_port": "9000", "target_ip": "192.168.1.20", "target_port": "80"})
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"ok":true`) || len(fa.uci["firewall"]) != before {
		t.Fatalf("plan: %d %s", w.Code, w.Body)
	}

	// a forward of Wharf's own may not be touched
	fa.uci["firewall"]["owpr_mine"] = Section{".type": "redirect", "src": "wan", "dest": "lan", "target": "DNAT", "proto": "tcp", "src_dport": "2222", "dest_ip": "192.168.1.20", "dest_port": "22"}
	put := func(id string) *httptest.ResponseRecorder {
		return call(a, tok, "forwards", func(w http.ResponseWriter, r *http.Request) {
			r.SetPathValue("id", id)
			a.handleBerthForwardUpdate(w, r)
		},
			"PUT", "/api/ext/berth/v1/forwards/"+id, map[string]any{"proto": "tcp", "wan_port": "2223", "target_ip": "192.168.1.20", "target_port": "22"})
	}
	if w := put("owpr_mine"); w.Code != 403 {
		t.Fatalf("edit foreign: %d %s", w.Code, w.Body)
	}
	if w := put(res.ID); w.Code != 200 {
		t.Fatalf("edit own: %d %s", w.Code, w.Body)
	}
	st, _ = a.loadFwState()
	if f := st.forward(res.ID); f.WanPort != "2223" || f.BerthRef != "site:vault.example.net" {
		t.Fatalf("after edit %+v", f)
	}
	del := func(id string) *httptest.ResponseRecorder {
		return call(a, tok, "forwards", func(w http.ResponseWriter, r *http.Request) {
			r.SetPathValue("id", id)
			a.handleBerthForwardDelete(w, r)
		},
			"DELETE", "/api/ext/berth/v1/forwards/"+id, nil)
	}
	if w := del("owpr_mine"); w.Code != 403 {
		t.Fatalf("delete foreign: %d", w.Code)
	}
	if w := del(res.ID); w.Code != 200 {
		t.Fatalf("delete own: %d %s", w.Code, w.Body)
	}
	if fa.uci["firewall"][res.ID] != nil || fa.uci["owpfwd"][res.ID] != nil {
		t.Fatal("not deleted")
	}
}

func TestBerthForwardAdminCannotEdit(t *testing.T) {
	a, _, su := berthApp(t)
	tok, _ := pair(t, a, su, allScopes)
	w := call(a, tok, "forwards", a.handleBerthForwardCreate, "POST", "/", map[string]any{"proto": "tcp", "wan_port": "8443", "target_ip": "192.168.1.20", "target_port": "443"})
	var res struct{ ID string }
	_ = json.Unmarshal(w.Body.Bytes(), &res)
	st, _ := a.loadFwState()
	f := st.forward(res.ID)
	admin := &User{ID: 9, Role: RoleAdmin, Perms: []string{"forwards.manage"}}
	raw, _ := json.Marshal(fwdIDReq{ID: res.ID, Rev: f.Rev})
	if _, err := prepareForwardDelete(a, admin, raw); err == nil || !strings.Contains(err.Error(), "Berth") {
		t.Fatalf("admin delete: %v", err)
	}
	if _, err := prepareForwardDelete(a, su, raw); err != nil {
		t.Fatalf("super delete: %v", err)
	}
}

func TestBerthUnpairKeepsMappings(t *testing.T) {
	a, fa, su := berthApp(t)
	tok, _ := pair(t, a, su, allScopes)
	w := call(a, tok, "forwards", a.handleBerthForwardCreate, "POST", "/", map[string]any{"proto": "tcp", "wan_port": "8443", "target_ip": "192.168.1.20", "target_port": "443", "berth_ref": "site:x"})
	var res struct{ ID string }
	_ = json.Unmarshal(w.Body.Bytes(), &res)
	if w := call(a, tok, "", a.handleBerthExtUnpair, "POST", "/", map[string]bool{"keep": true}); w.Code != 200 {
		t.Fatalf("unpair %d %s", w.Code, w.Body)
	}
	if a.berth() != nil {
		t.Fatal("link still there")
	}
	st, _ := a.loadFwState()
	f := st.forward(res.ID)
	if f == nil || f.Kind != "" || optStr(fa.uci["owpfwd"][res.ID], "uid") != strconv.FormatInt(su.ID, 10) {
		t.Fatalf("kept forward %+v %v", f, fa.uci["owpfwd"][res.ID])
	}
	// the old token is dead
	if w := call(a, tok, "", a.handleBerthPing, "GET", "/", nil); w.Code != 401 {
		t.Fatalf("after unpair: %d", w.Code)
	}
}

func TestBerthBanSafety(t *testing.T) {
	a, fa, su := berthApp(t)
	_, _ = a.db.Exec(`INSERT INTO sessions(token_hash, user_id, csrf, ip, user_agent, created_at, seen_at) VALUES('h',?,'c','198.51.100.7','ua',?,?)`, su.ID, time.Now().Unix(), time.Now().Unix())
	for _, bad := range []string{"192.168.1.5", "10.0.0.0/8", "203.0.0.0/8", "203.0.113.9", "198.51.100.0/24", "2001:db8::1", "nope"} {
		if _, err := a.checkBan(bad, ""); err == nil {
			t.Errorf("%s accepted", bad)
		}
	}
	if c, err := a.checkBan("192.0.2.77", ""); err != nil || c != "192.0.2.77/32" {
		t.Fatalf("%q %v", c, err)
	}
	tok, _ := pair(t, a, su, allScopes)
	w := call(a, tok, "bans", a.handleBerthBanAdd, "POST", "/", map[string]any{"cidr": "192.0.2.77", "reason": "SSH 爆破", "source": "berth:mini:fail2ban",
		"expires_at": time.Now().Add(24 * time.Hour).UTC().Format(time.RFC3339), "id": 41})
	if w.Code != 200 {
		t.Fatalf("ban %d %s", w.Code, w.Body)
	}
	if fa.uci["firewall"][banRuleIn] == nil || fa.uci["firewall"][banRuleFwd] == nil || len(fa.sets[banSet]) != 1 {
		t.Fatalf("firewall %v %v", fa.uci["firewall"], fa.sets)
	}
	if optStr(fa.uci["firewall"][banRuleFwd], "target") != "DROP" || optStr(fa.uci["firewall"][banRuleFwd], "src") != "wan" {
		t.Fatal("rule")
	}
	// Berth takes it back by its own id
	w = call(a, tok, "bans", func(w http.ResponseWriter, r *http.Request) {
		r.SetPathValue("id", "remote:41")
		a.handleBerthBanDelete(w, r)
	}, "DELETE", "/", nil)
	if w.Code != 200 {
		t.Fatalf("unban %d %s", w.Code, w.Body)
	}
	if fa.uci["firewall"][banRuleIn] != nil || fa.uci["firewall"][banSection] != nil {
		t.Fatal("firewall not cleaned up")
	}
	// expired bans fall off
	_, _ = a.db.Exec(`INSERT INTO berth_bans(cidr, created_at, expires_at, origin) VALUES('192.0.2.0/24', 1, 2, 'berth')`)
	if n, _ := a.expireBerthBans(); n != 1 {
		t.Fatalf("expired %d", n)
	}
}

func TestBerthSSOTicket(t *testing.T) {
	a, _, su := berthApp(t)
	tok, _ := pair(t, a, su, allScopes)
	ask := func(user, ret string) *httptest.ResponseRecorder {
		return call(a, tok, "sso", a.handleBerthSSOTicket, "POST", "/", map[string]string{"berth_user": user, "return_to": ret})
	}
	if w := ask("wang", "/forwards"); w.Code != 403 {
		t.Fatalf("no mapping: %d", w.Code)
	}
	// mapping onto a super admin needs the password again
	b, _ := json.Marshal(map[string]any{"berth_user": "wang", "wharf_user_id": su.ID})
	w := httptest.NewRecorder()
	a.handleBerthUserMap(w, asUser(httptest.NewRequest("PUT", "/", bytes.NewReader(b)), su))
	if w.Code != 403 {
		t.Fatalf("super mapping without password: %d", w.Code)
	}
	b, _ = json.Marshal(map[string]any{"berth_user": "wang", "wharf_user_id": su.ID, "password": "correct-horse"})
	w = httptest.NewRecorder()
	a.handleBerthUserMap(w, asUser(httptest.NewRequest("PUT", "/", bytes.NewReader(b)), su))
	if w.Code != 200 {
		t.Fatalf("mapping: %d %s", w.Code, w.Body)
	}
	w = ask("wang", "//evil.example.com")
	var tk struct{ URL string }
	_ = json.Unmarshal(w.Body.Bytes(), &tk)
	if !strings.HasPrefix(tk.URL, "https://wharf.lan:7080/sso/berth?t=") {
		t.Fatalf("ticket %d %s", w.Code, w.Body)
	}
	use := func(u, host string) *httptest.ResponseRecorder {
		r := httptest.NewRequest("GET", u, nil)
		r.Host = host
		w := httptest.NewRecorder()
		a.handleBerthSSO(w, r)
		return w
	}
	// wrong audience: the ticket is spent and refused
	if w := use(tk.URL, "other.example.net"); w.Code != 403 {
		t.Fatalf("audience: %d", w.Code)
	}
	_ = json.Unmarshal(ask("wang", "//evil.example.com").Body.Bytes(), &tk)
	w = use(tk.URL, "wharf.lan:7080")
	if w.Code != 200 || !strings.Contains(w.Header().Get("Set-Cookie"), sessionCookie) || !strings.Contains(w.Body.String(), `url=/"`) {
		t.Fatalf("sso: %d %s", w.Code, w.Body)
	}
	if w := use(tk.URL, "wharf.lan:7080"); w.Code != 401 {
		t.Fatalf("replay: %d", w.Code)
	}
	var reason string
	_ = a.db.QueryRow(`SELECT reason FROM visitors WHERE path='/sso/berth'`).Scan(&reason)
	if !strings.Contains(reason, "经 Berth 跳转") {
		t.Fatalf("visitor %q", reason)
	}
	// expired tickets
	_ = json.Unmarshal(ask("wang", "/").Body.Bytes(), &tk)
	berthTickets.Lock()
	for _, v := range berthTickets.m {
		v.until = time.Now().Add(-time.Second)
	}
	berthTickets.Unlock()
	if w := use(tk.URL, "wharf.lan:7080"); w.Code != 401 {
		t.Fatalf("expired: %d", w.Code)
	}
}

func TestBerthDDNSClaim(t *testing.T) {
	a, _, su := berthApp(t)
	tok, _ := pair(t, a, su, allScopes)
	claim := func(d, o string) *httptest.ResponseRecorder {
		return call(a, tok, "ddns", a.handleBerthDDNSClaim, "POST", "/", map[string]string{"domain": d, "owner": o})
	}
	if w := claim("vault.example.net", "wharf"); w.Code != 409 {
		t.Fatalf("no zone account: %d %s", w.Code, w.Body)
	}
	if _, err := a.createDDNS(&DDNS{Name: "home", Enabled: true, Provider: "cloudflare", Creds: map[string]string{"token": "t"}, Domain: "home.example.net", RType: "A",
		Source: DDNSSource{Mode: "iface", Iface: "wan"}, Interval: 5, TTL: 300}); err != nil {
		t.Fatal(err)
	}
	w := claim("vault.example.net", "wharf")
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"ddns_id":2`) {
		t.Fatalf("claim: %d %s", w.Code, w.Body)
	}
	list, _ := a.ddnsList()
	if len(list) != 2 || list[1].Domain != "vault.example.net" || list[1].Creds["token"] != "t" {
		t.Fatalf("list %+v", list[1])
	}
	if w := claim("home.example.net", "berth"); w.Code != 200 || !a.ddnsOwnedByBerth("home.example.net") {
		t.Fatalf("berth owner: %d", w.Code)
	}
	if w := call(a, tok, "ddns", func(w http.ResponseWriter, r *http.Request) { r.SetPathValue("id", "1"); a.handleBerthDDNSRun(w, r) }, "POST", "/", nil); w.Code != 409 {
		t.Fatalf("run a Berth-owned name: %d", w.Code)
	}
}

func TestBerthAlertDedupe(t *testing.T) {
	a, _, su := berthApp(t)
	tok, _ := pair(t, a, su, allScopes)
	send := func() *httptest.ResponseRecorder {
		return call(a, tok, "alerts", a.handleBerthAlert, "POST", "/", map[string]string{"level": "warn", "title": "磁盘快满了", "body": "/ 92%", "dedupe_key": "disk:/"})
	}
	if w := send(); w.Code != 200 || strings.Contains(w.Body.String(), "deduped") {
		t.Fatalf("first: %s", w.Body)
	}
	if w := send(); !strings.Contains(w.Body.String(), "deduped") {
		t.Fatalf("second: %s", w.Body)
	}
	_ = a.setSetting("alerts.primary", "berth")
	if w := call(a, tok, "alerts", a.handleBerthAlert, "POST", "/", map[string]string{"title": "x", "dedupe_key": "y"}); w.Code != 409 {
		t.Fatalf("not primary: %d", w.Code)
	}
}

func TestSNIPriority(t *testing.T) {
	if !sniMatch("*.home.example.net", "a.home.example.net") || sniMatch("*.home.example.net", "a.b.home.example.net") || sniMatch("*.home.example.net", "home.example.net") {
		t.Fatal("wildcard")
	}
	nodes := []*ProxyNode{{Name: "n", Enabled: true, Entry: "sni", Security: "tls", Domain: "a.home.example.net", Port: 443}}
	out, on := buildFront(nodes, frontSite{Mode: "builtin"}, "", nil, true, nil, &berthSNIReg{Target: "192.168.1.20:443", Domains: []string{"*.home.example.net", "vault.example.net"}, ProxyProtocol: true})
	if !on {
		t.Fatal("front off")
	}
	var cfg struct {
		Routes []struct {
			SNI     []string `json:"sni"`
			Backend string   `json:"backend"`
			Proxy   bool     `json:"proxy"`
		} `json:"routes"`
		ACME []string `json:"acme"`
	}
	_ = json.Unmarshal([]byte(out), &cfg)
	last := cfg.Routes[len(cfg.Routes)-1]
	// the wildcard overlaps the node's name, so only vault goes to Berth; no certificate for it
	if last.Backend != "192.168.1.20:443" || len(last.SNI) != 1 || last.SNI[0] != "vault.example.net" || !last.Proxy {
		t.Fatalf("routes %+v", cfg.Routes)
	}
	for _, d := range cfg.ACME {
		if d == "vault.example.net" {
			t.Fatal("ACME for a Berth name")
		}
	}
}
