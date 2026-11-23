package panel

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/wangsirco/wharf/internal/sign"
	"github.com/wangsirco/wharf/internal/tlsutil"
)

func TestBerthURLsOrderAndKinds(t *testing.T) {
	got, err := cleanBerthURLs("https://mini.example.com", []string{"https://mini.lan:7090", "https://192.168.1.20:7090", "https://mini.example.com"})
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"https://192.168.1.20:7090", "https://mini.lan:7090", "https://mini.example.com"}
	if strings.Join(got, " ") != strings.Join(want, " ") {
		t.Fatalf("order %v", got)
	}
	if _, err := cleanBerthURLs("", []string{"http://192.168.1.20"}); err == nil {
		t.Fatal("http accepted")
	}
	for ip, k := range map[string]string{"192.168.1.20": "lan", "fe80::1": "lan", "100.101.1.2": "tailscale", "fd7a:115c:a1e0::5": "tailscale",
		"fd00::1": "lan", "203.0.113.5": "public", "::ffff:10.0.0.1": "lan"} {
		if got := connKind(netip.MustParseAddr(ip)); got != k {
			t.Errorf("%s: %s, want %s", ip, got, k)
		}
	}
	h := http.Header{}
	h.Set("Cf-Ray", "x")
	if viaOf(false, h) != "cloudflare" || viaOf(true, h) != "direct" || viaOf(false, http.Header{}) != "proxy" {
		t.Fatal("via")
	}
}

func TestPairSAS(t *testing.T) {
	s := pairSAS("c", "b", "w")
	if !regexp.MustCompile(`^\d{3} \d{3}$`).MatchString(s) || s != pairSAS("c", "b", "w") || s == pairSAS("c2", "b", "w") {
		t.Fatalf("sas %q", s)
	}
}

// Berth signing with X-Berth-Key (v2) works, and from then on Wharf never sends its token.
func TestBerthKeyAuth(t *testing.T) {
	a, _, su := berthApp(t)
	tok, out := pair(t, a, su, allScopes)
	signKey := func(r *http.Request, raw []byte) {
		r.Header.Del("Authorization")
		r.Header.Set("X-Berth-Key", keyID(tok))
		sign.SignPrefixed(r, "X-Berth", sign.DeriveKey(tok), raw)
	}
	w := call(a, tok, "", a.handleBerthPing, "GET", "/api/ext/berth/v1/ping", nil, func(r *http.Request) { signKey(r, nil) })
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"protocol":2`) {
		t.Fatalf("key ping %d %s", w.Code, w.Body)
	}
	if !a.berth().KeyAuth {
		t.Fatal("key_auth not switched on")
	}
	// a wrong key id
	if w := call(a, tok, "", a.handleBerthPing, "GET", "/api/ext/berth/v1/ping", nil, func(r *http.Request) {
		r.Header.Del("Authorization")
		r.Header.Set("X-Berth-Key", strings.Repeat("0", 16))
	}); w.Code != 401 {
		t.Fatalf("bad key id: %d", w.Code)
	}
	var mu sync.Mutex
	var auth, key string
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		_, err := sign.CheckPrefixed(r, "X-Wharf", sign.DeriveKey(out), body)
		mu.Lock()
		auth, key = r.Header.Get("Authorization"), r.Header.Get("X-Wharf-Key")
		mu.Unlock()
		if err != nil {
			w.WriteHeader(401)
		}
	}))
	defer srv.Close()
	h := sha256.Sum256(srv.Certificate().Raw)
	_, _ = a.db.Exec(`UPDATE berth_link SET url=?, urls=?, cert_fp=?`, srv.URL, mustJSON([]string{srv.URL}), hex.EncodeToString(h[:]))
	if err := a.berthCall(a.berth(), "GET", "/ping", nil, nil); err != nil {
		t.Fatal(err)
	}
	if auth != "" || key != keyID(out) {
		t.Fatalf("Wharf sent Authorization=%q key=%q", auth, key)
	}
}

// An address that does not answer is skipped, and the one that does is remembered.
func TestBerthFailover(t *testing.T) {
	a, _, su := berthApp(t)
	pair(t, a, su, allScopes)
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte(`{"ok":true}`)) }))
	defer srv.Close()
	h := sha256.Sum256(srv.Certificate().Raw)
	dead := "https://127.0.0.1:1"
	_, _ = a.db.Exec(`UPDATE berth_link SET url=?, urls=?, cert_fp=?`, dead, mustJSON([]string{dead, srv.URL}), hex.EncodeToString(h[:]))
	if err := a.berthCall(a.berth(), "GET", "/ping", nil, nil); err != nil {
		t.Fatal(err)
	}
	if l := a.berth(); l.URL != srv.URL {
		t.Fatalf("now using %s", l.URL)
	}
	c := a.measureBerth(a.berth())
	if c.Error != "" || c.Kind != "lan" || c.IP != "127.0.0.1" || c.URL != srv.URL {
		t.Fatalf("conn %+v", c)
	}
}

func discReq(a *App, path, remote string, body any, h http.HandlerFunc) *httptest.ResponseRecorder {
	b, _ := json.Marshal(body)
	r := httptest.NewRequest("POST", path, bytes.NewReader(b))
	r.RemoteAddr = remote + ":5555"
	r.Host = "192.168.1.1:7080"
	w := httptest.NewRecorder()
	h(w, r)
	return w
}

func TestBerthDiscovery(t *testing.T) {
	a, _, su := berthApp(t)
	ca, err := tlsutil.OpenLocalCA(t.TempDir(), "Wharf")
	if err != nil {
		t.Fatal(err)
	}
	a.CA = ca
	self := a.selfFingerprint()
	berthDisc.Lock()
	berthDisc.until, berthDisc.asks, berthDisc.hits = time.Time{}, map[string]*berthAsk{}, map[string][]time.Time{}
	berthDisc.Unlock()
	code := strings.Repeat("q", 24)
	ask := map[string]any{"code": code, "berth_name": "mini", "berth_urls": []string{"https://192.168.1.20:7090"}, "berth_fp": strings.Repeat("ab", 32), "wharf_fp": self}

	// window closed → 404
	if w := discReq(a, "/r", "192.168.1.20", ask, a.handleBerthPairRequest); w.Code != 404 {
		t.Fatalf("closed window: %d", w.Code)
	}
	b, _ := json.Marshal(map[string]bool{"open": true})
	w := httptest.NewRecorder()
	a.handleBerthDiscoverSet(w, asUser(httptest.NewRequest("POST", "/", bytes.NewReader(b)), su))
	if w.Code != 200 {
		t.Fatal(w.Code, w.Body)
	}
	// from the internet → 404
	if w := discReq(a, "/r", "203.0.113.7", ask, a.handleBerthPairRequest); w.Code != 404 {
		t.Fatalf("public source: %d", w.Code)
	}
	// someone swapped the certificate → refused
	bad := map[string]any{}
	for k, v := range ask {
		bad[k] = v
	}
	bad["wharf_fp"], bad["code"] = strings.Repeat("cd", 32), strings.Repeat("z", 24)
	if w := discReq(a, "/r", "192.168.1.20", bad, a.handleBerthPairRequest); w.Code != 400 {
		t.Fatalf("wrong wharf_fp: %d", w.Code)
	}
	w = discReq(a, "/r", "192.168.1.20", ask, a.handleBerthPairRequest)
	if w.Code != 200 {
		t.Fatalf("request: %d %s", w.Code, w.Body)
	}
	var rr struct{ ID, SAS string }
	_ = json.Unmarshal(w.Body.Bytes(), &rr)
	if rr.SAS != pairSAS(code, strings.Repeat("ab", 32), self) {
		t.Fatalf("sas %s", rr.SAS)
	}
	st := func() map[string]string {
		w := discReq(a, "/s", "192.168.1.20", map[string]string{"code": code}, a.handleBerthPairRequestStatus)
		var m map[string]string
		_ = json.Unmarshal(w.Body.Bytes(), &m)
		return m
	}
	if st()["state"] != "waiting" {
		t.Fatal("not waiting")
	}
	// allowing needs a fresh proof of identity
	grant, _ := json.Marshal(berthGrant{Scopes: []string{"sso", "dns"}, Targets: []berthTarget{{IP: "192.168.1.20"}}})
	allow := func() *httptest.ResponseRecorder {
		r := asUser(httptest.NewRequest("POST", "/", bytes.NewReader(grant)), su)
		r.SetPathValue("id", rr.ID)
		r.AddCookie(&http.Cookie{Name: sessionCookie, Value: "sess"})
		w := httptest.NewRecorder()
		a.handleBerthAskAllow(w, r)
		return w
	}
	if w := allow(); w.Code != 403 {
		t.Fatalf("allow without reauth: %d", w.Code)
	}
	reauthDone.Lock()
	if reauthDone.m == nil {
		reauthDone.m = map[string]time.Time{}
	}
	reauthDone.m[tokenHash("sess")] = time.Now().Add(time.Minute)
	reauthDone.Unlock()
	if w := allow(); w.Code != 200 {
		t.Fatalf("allow: %d %s", w.Code, w.Body)
	}
	s := st()
	if s["state"] != "allowed" || s["code"] == "" || s["wharf_url"] != "https://192.168.1.1:7080" {
		t.Fatalf("status %v", s)
	}
	ex, _ := json.Marshal(map[string]string{"code": s["code"], "token": "berth_wrf_" + strings.Repeat("8", 32), "name": "mini"})
	w = httptest.NewRecorder()
	a.handleBerthExchange(w, httptest.NewRequest("POST", "/", bytes.NewReader(ex)))
	if w.Code != 200 {
		t.Fatalf("exchange: %d %s", w.Code, w.Body)
	}
	if l := a.berth(); l == nil || l.URL != "https://192.168.1.20:7090" || !l.has("dns") {
		t.Fatalf("link %+v", l)
	}
}

func TestBerthLocalNames(t *testing.T) {
	a, fa, su := berthApp(t)
	fa.uci["dhcp"]["cfg01"] = Section{".type": "dnsmasq", "domain": "home"}
	fa.uci["dhcp"]["other"] = Section{".type": "domain", "name": "nas.lan", "ip": "192.168.1.30"}
	tok, _ := pair(t, a, su, append(allScopes, "dns"))
	put := func(name, ip string) *httptest.ResponseRecorder {
		return call(a, tok, "dns", a.handleBerthDNSPut, "PUT", "/api/ext/berth/v1/dns/names/"+name, map[string]string{"ip": ip}, func(r *http.Request) { r.SetPathValue("name", name) })
	}
	if w := put("mini.lan", "192.168.1.20"); w.Code != 200 {
		t.Fatalf("put: %d %s", w.Code, w.Body)
	}
	if w := put("mini.home", "192.168.1.20"); w.Code != 200 {
		t.Fatalf("configured suffix: %d %s", w.Code, w.Body)
	}
	for name, ip := range map[string]string{"evil.lan": "192.168.1.30", "mini.example.com": "192.168.1.20", "nas.lan": "192.168.1.20", "a_b.lan": "192.168.1.20"} {
		if w := put(name, ip); w.Code == 200 {
			t.Errorf("%s → %s accepted", name, ip)
		}
	}
	w := call(a, tok, "dns", a.handleBerthDNSNames, "GET", "/api/ext/berth/v1/dns/names", nil)
	if !strings.Contains(w.Body.String(), `"mini.lan"`) || strings.Contains(w.Body.String(), "nas.lan") {
		t.Fatalf("list %s", w.Body)
	}
	for i := range 3 {
		put("m"+string(rune('a'+i))+".lan", "192.168.1.20")
	}
	if w := put("full.lan", "192.168.1.20"); w.Code != 409 {
		t.Fatalf("sixth name: %d", w.Code)
	}
	if _, err := a.berthUnpair(actor{user: su}, a.berth(), true); err != nil {
		t.Fatal(err)
	}
	for _, s := range fa.uci["dhcp"] {
		if s[".type"] == "domain" && s["name"] != "nas.lan" {
			t.Fatalf("left behind: %v", s)
		}
	}
}

func TestTocAnchorMatchesWeb(t *testing.T) {
	// encodeURIComponent('DNS 缓存与排查').replace(/%/g,'').slice(0,40) in the browser
	if got := tocAnchor("DNS 缓存与排查"); got != "sec-DNS20E7BC93E5AD98E4B88EE68E92E69FA5" {
		t.Fatal(got)
	}
}
