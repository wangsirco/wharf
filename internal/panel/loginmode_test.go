package panel

import (
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

func loginModeApp(t *testing.T) (*App, *User) {
	t.Helper()
	db, err := OpenDB(filepath.Join(t.TempDir(), "l.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	a := &App{db: db, limiter: newLimiter(50, 15*time.Minute), agent: NewAgentClient(AgentConfig{URL: "http://127.0.0.1:1"})}
	u, err := a.createUser("alex", "Alex", "correct-horse", RoleAdmin)
	if err != nil {
		t.Fatal(err)
	}
	if u.LoginMode != LoginPassword {
		t.Fatalf("default mode %q", u.LoginMode)
	}
	return a, u
}

func tryLogin(a *App, password string) *httptest.ResponseRecorder {
	r := httptest.NewRequest("POST", "https://wharf.lan/api/login", strings.NewReader(`{"username":"alex","password":"`+password+`"}`))
	r.Host = "wharf.lan"
	w := httptest.NewRecorder()
	a.handleLogin(w, r)
	return w
}

func addCred(t *testing.T, a *App, uid int64, rp string) {
	t.Helper()
	if _, err := a.db.Exec(`INSERT INTO passkeys(user_id, rp_id, cred_id, cred, name, created) VALUES(?,?,?,?,?,1)`, uid, rp, rp+"-id", `{"id":"AAAA"}`, "k"); err != nil {
		t.Fatal(err)
	}
}

func setMode(t *testing.T, a *App, uid int64, m string) {
	t.Helper()
	if _, err := a.db.Exec(`UPDATE users SET login_mode=? WHERE id=?`, m, uid); err != nil {
		t.Fatal(err)
	}
}

func TestPasswordModeSignsIn(t *testing.T) {
	a, _ := loginModeApp(t)
	w := tryLogin(a, "correct-horse")
	if w.Code != 200 || !strings.Contains(w.Header().Get("Set-Cookie"), sessionCookie) {
		t.Fatalf("%d %s", w.Code, w.Body)
	}
}

func TestPasskeyOnlyAnswersLikeAWrongPassword(t *testing.T) {
	a, u := loginModeApp(t)
	host := a.localPanelName()
	addCred(t, a, u.ID, host)
	setMode(t, a, u.ID, LoginPasskey)
	right, wrong := tryLogin(a, "correct-horse"), tryLogin(a, "nope")
	if right.Code != 401 || right.Code != wrong.Code || right.Body.String() != wrong.Body.String() {
		t.Fatalf("right password %d %s; wrong %d %s", right.Code, right.Body, wrong.Code, wrong.Body)
	}
	if right.Header().Get("Set-Cookie") != "" {
		t.Fatal("session handed out")
	}
}

func TestTwoStepOpensNoSessionOnThePassword(t *testing.T) {
	a, u := loginModeApp(t)
	host := a.localPanelName()
	addCred(t, a, u.ID, host)
	setMode(t, a, u.ID, LoginTwoStep)

	r := httptest.NewRequest("POST", "/api/login", strings.NewReader(`{"username":"alex","password":"correct-horse"}`))
	r.Host = host
	r.Header.Set("Origin", "https://"+host)
	w := httptest.NewRecorder()
	a.handleLogin(w, r)
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"second_step":true`) {
		t.Fatalf("%d %s", w.Code, w.Body)
	}
	if w.Header().Get("Set-Cookie") != "" || strings.Contains(w.Body.String(), "csrf") {
		t.Fatal("a session before the passkey")
	}
	// at an address without the passkey: told where to go, still no session
	r = httptest.NewRequest("POST", "/api/login", strings.NewReader(`{"username":"alex","password":"correct-horse"}`))
	r.Host = "10.0.0.1:7080"
	w = httptest.NewRecorder()
	a.handleLogin(w, r)
	if w.Code != 403 || !strings.Contains(w.Body.String(), host) || w.Header().Get("Set-Cookie") != "" {
		t.Fatalf("%d %s", w.Code, w.Body)
	}
}

func TestStrictModeWithoutUsablePasskeyFallsBack(t *testing.T) {
	a, u := loginModeApp(t)
	addCred(t, a, u.ID, "gone.example.com") // its public name was removed
	setMode(t, a, u.ID, LoginPasskey)
	u, _ = a.getUser(u.ID)
	if m := a.effectiveLoginMode(u); m != LoginPassword {
		t.Fatalf("effective %q", m)
	}
	if w := tryLogin(a, "correct-horse"); w.Code != 200 {
		t.Fatalf("%d %s", w.Code, w.Body)
	}
}

func modeRequest(a *App, u *User, mode, cookie string) *httptest.ResponseRecorder {
	r := httptest.NewRequest("PUT", "/api/me/login-mode", strings.NewReader(`{"mode":"`+mode+`"}`))
	r.AddCookie(&http.Cookie{Name: sessionCookie, Value: cookie})
	r = r.WithContext(withUser(r, u))
	w := httptest.NewRecorder()
	a.handleLoginMode(w, r)
	return w
}

func TestChangingLoginMode(t *testing.T) {
	a, u := loginModeApp(t)
	if w := modeRequest(a, u, LoginPasskey, "s1"); w.Code != 400 {
		t.Fatalf("strict mode without a passkey: %d %s", w.Code, w.Body)
	}
	if w := modeRequest(a, u, "whatever", "s1"); w.Code != 400 {
		t.Fatalf("unknown mode: %d", w.Code)
	}
	addCred(t, a, u.ID, a.localPanelName())
	for _, tok := range []string{"s1", "other"} {
		if _, err := a.db.Exec(`INSERT INTO sessions(token_hash, user_id, csrf, ip, user_agent, created_at, seen_at) VALUES(?,?,'c','','',1,1)`, tokenHash(tok), u.ID); err != nil {
			t.Fatal(err)
		}
	}
	if w := modeRequest(a, u, LoginPasskey, "s1"); w.Code != 200 {
		t.Fatalf("%d %s", w.Code, w.Body)
	}
	var n int
	_ = a.db.QueryRow(`SELECT COUNT(*) FROM sessions WHERE user_id=?`, u.ID).Scan(&n)
	if n != 1 {
		t.Fatalf("%d sessions left, want only this one", n)
	}
	// weakening it needs a fresh proof, tied to this session
	u, _ = a.getUser(u.ID)
	if w := modeRequest(a, u, LoginPassword, "s1"); w.Code != 403 {
		t.Fatalf("no proof: %d %s", w.Code, w.Body)
	}
	proof := httptest.NewRequest("POST", "/", nil)
	proof.AddCookie(&http.Cookie{Name: sessionCookie, Value: "s1"})
	markReauth(proof)
	if w := modeRequest(a, u, LoginPassword, "someone-else"); w.Code != 403 {
		t.Fatalf("proof from another session: %d", w.Code)
	}
	if w := modeRequest(a, u, LoginPassword, "s1"); w.Code != 200 {
		t.Fatalf("%d %s", w.Code, w.Body)
	}
}

func TestLastPasskeyStays(t *testing.T) {
	a, u := loginModeApp(t)
	addCred(t, a, u.ID, a.localPanelName())
	setMode(t, a, u.ID, LoginPasskey)
	u, _ = a.getUser(u.ID)
	var id int64
	_ = a.db.QueryRow(`SELECT id FROM passkeys WHERE user_id=?`, u.ID).Scan(&id)
	r := httptest.NewRequest("DELETE", "/api/me/passkeys/x", nil)
	r.SetPathValue("id", itoa64(id))
	r.AddCookie(&http.Cookie{Name: sessionCookie, Value: "s9"})
	markReauth(r)
	r = r.WithContext(withUser(r, u))
	w := httptest.NewRecorder()
	a.handlePasskeyDelete(w, r)
	if w.Code != 400 {
		t.Fatalf("%d %s", w.Code, w.Body)
	}
}

func withUser(r *http.Request, u *User) context.Context {
	return context.WithValue(r.Context(), userKey, u)
}

func itoa64(n int64) string { return strconv.FormatInt(n, 10) }

func TestResetSuperRestoresThePassword(t *testing.T) {
	a, _ := loginModeApp(t)
	su, err := a.createUser("root1", "Root", "correct-horse", RoleSuper)
	if err != nil {
		t.Fatal(err)
	}
	setMode(t, a, su.ID, LoginPasskey)
	if _, err := ResetSuper(a.db, Config{DataDir: t.TempDir()}); err != nil {
		t.Fatal(err)
	}
	su, _ = a.getUser(su.ID)
	if su.LoginMode != LoginPassword {
		t.Fatalf("mode %q", su.LoginMode)
	}
}
