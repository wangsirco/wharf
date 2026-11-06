package panel

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/go-webauthn/webauthn/webauthn"
)

// How a user signs in. Each user chooses, in "账号安全" or the welcome wizard:
//
//	password  the password or a passkey, whichever they like (the default)
//	two_step  the password, then a passkey; a passkey alone is not enough
//	passkey   a passkey only; the password opens nothing
//
// A strict mode needs a passkey on a name the panel still answers to. If the last such
// name goes away (a public name removed), the user falls back to the password rather than
// being locked out for good. Other ways back in: a super admin resets the password, and
// `owp-panel reset-super` does it for the super admin; both restore the password mode.
const (
	LoginPassword = "password"
	LoginTwoStep  = "two_step"
	LoginPasskey  = "passkey"
)

const errBadLogin = "用户名或密码错误"

// usablePasskeyHosts: the panel's names on which this user has a passkey.
func (a *App) usablePasskeyHosts(uid int64) []string {
	hosts := []string{}
	for _, h := range a.passkeyHosts() {
		var n int
		if a.db.QueryRow(`SELECT COUNT(*) FROM passkeys WHERE user_id=? AND rp_id=?`, uid, h).Scan(&n) == nil && n > 0 {
			hosts = append(hosts, h)
		}
	}
	return hosts
}

// usablePasskeyCount: how many of this user's passkeys work on a name the panel answers to.
func (a *App) usablePasskeyCount(uid int64) int {
	n := 0
	for _, h := range a.usablePasskeyHosts(uid) {
		n += len(a.passkeyCreds(uid, h))
	}
	return n
}

func (a *App) effectiveLoginMode(u *User) string {
	if u.LoginMode == LoginPassword || len(a.usablePasskeyHosts(u.ID)) == 0 {
		return LoginPassword
	}
	return u.LoginMode
}

// beginSecondStep answers a correct password in the two-step mode: the browser now has to
// prove the passkey. No session exists until it does.
func (a *App) beginSecondStep(w http.ResponseWriter, r *http.Request, u *User) {
	wa, rp, err := a.rpFor(r)
	var creds []webauthn.Credential
	if err == nil {
		creds = a.passkeyCreds(u.ID, rp)
	}
	if len(creds) == 0 {
		jsonErr(w, 403, "这个账号还要验证 Passkey，但这个地址上没有它的 Passkey；请从 "+strings.Join(a.usablePasskeyHosts(u.ID), " 或 ")+" 打开面板")
		return
	}
	assertion, data, err := wa.BeginLogin(&pkUser{u: u, creds: creds})
	if err != nil {
		jsonErr(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"second_step": true, "flow": pkPut(pkFlow{data: *data, uid: u.ID, kind: pkSecond, rp: rp}), "options": assertion.Response})
}

// PUT /api/me/login-mode {mode}
func (a *App) handleLoginMode(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Mode string `json:"mode"`
	}
	if readJSON(r, &req) != nil || !slices.Contains([]string{LoginPassword, LoginTwoStep, LoginPasskey}, req.Mode) {
		jsonErr(w, 400, "请选择登录方式")
		return
	}
	u := currentUser(r)
	if req.Mode == u.LoginMode {
		writeJSON(w, 200, map[string]string{"login_mode": u.LoginMode})
		return
	}
	if !a.reauthed(w, r, u) {
		return
	}
	if req.Mode != LoginPassword && len(a.usablePasskeyHosts(u.ID)) == 0 {
		jsonErr(w, 400, "请先添加一个 Passkey，否则改完就登录不了了")
		return
	}
	if _, err := a.db.Exec(`UPDATE users SET login_mode=?, updated_at=? WHERE id=?`, req.Mode, time.Now().Unix(), u.ID); err != nil {
		jsonErr(w, 500, err.Error())
		return
	}
	// getting stricter: sessions opened under the old rule end, except this one
	if u.LoginMode == LoginPassword {
		if c, err := r.Cookie(sessionCookie); err == nil {
			_, _ = a.db.Exec(`DELETE FROM sessions WHERE user_id=? AND token_hash<>?`, u.ID, tokenHash(c.Value))
		}
	}
	a.audit(actor{user: u, ip: a.clientIP(r)}, "user.login_mode", "user", strconv.FormatInt(u.ID, 10), "登录方式改为「"+loginModeName(req.Mode)+"」", nil, nil, false)
	writeJSON(w, 200, map[string]string{"login_mode": req.Mode})
}

func loginModeName(m string) string {
	switch m {
	case LoginTwoStep:
		return "密码 + Passkey"
	case LoginPasskey:
		return "只用 Passkey"
	}
	return "密码或 Passkey"
}

// ---- proving it's really you ----

// Someone in a strict mode has to prove themselves again before weakening it: changing the
// mode, adding or removing a passkey. Otherwise a session left open on a borrowed computer
// would undo the whole point. The proof lasts five minutes, for this session only.
const reauthFor = 5 * time.Minute

var reauthDone struct {
	sync.Mutex
	m map[string]time.Time
}

func markReauth(r *http.Request) {
	c, err := r.Cookie(sessionCookie)
	if err != nil {
		return
	}
	reauthDone.Lock()
	defer reauthDone.Unlock()
	if reauthDone.m == nil {
		reauthDone.m = map[string]time.Time{}
	}
	for k, t := range reauthDone.m {
		if time.Now().After(t) {
			delete(reauthDone.m, k)
		}
	}
	reauthDone.m[tokenHash(c.Value)] = time.Now().Add(reauthFor)
}

// reauthed reports whether u may go ahead, answering the request if not.
func (a *App) reauthed(w http.ResponseWriter, r *http.Request, u *User) bool {
	if u.LoginMode == LoginPassword {
		return true
	}
	if c, err := r.Cookie(sessionCookie); err == nil {
		reauthDone.Lock()
		t, ok := reauthDone.m[tokenHash(c.Value)]
		reauthDone.Unlock()
		if ok && time.Now().Before(t) {
			return true
		}
	}
	jsonErr(w, 403, "请先验证身份")
	return false
}

// POST /api/me/reauth {password}
func (a *App) handleReauthPassword(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Password string `json:"password"`
	}
	if readJSON(r, &req) != nil {
		jsonErr(w, 400, "请求格式错误")
		return
	}
	u := currentUser(r)
	keys := []string{"ip:" + a.clientIP(r), "user:" + strings.ToLower(u.Username)}
	if a.limiter.blocked(keys...) {
		jsonErr(w, 429, "失败次数过多，请 15 分钟后再试")
		return
	}
	if _, err := a.checkPassword(u.Username, req.Password); err != nil {
		a.limiter.record(keys...)
		jsonErr(w, 400, "密码错误")
		return
	}
	markReauth(r)
	writeJSON(w, 200, map[string]bool{"ok": true})
}

// POST /api/me/reauth/begin — a passkey of this user, on this name
func (a *App) handleReauthBegin(w http.ResponseWriter, r *http.Request) {
	wa, rp, err := a.rpFor(r)
	if err != nil {
		jsonErr(w, 400, err.Error())
		return
	}
	u := currentUser(r)
	creds := a.passkeyCreds(u.ID, rp)
	if len(creds) == 0 {
		jsonErr(w, 400, "这个地址上没有你的 Passkey")
		return
	}
	assertion, data, err := wa.BeginLogin(&pkUser{u: u, creds: creds})
	if err != nil {
		jsonErr(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"flow": pkPut(pkFlow{data: *data, uid: u.ID, kind: pkReauth, rp: rp}), "options": assertion.Response})
}

// POST /api/me/reauth/finish?flow= (body: the browser's assertion)
func (a *App) handleReauthFinish(w http.ResponseWriter, r *http.Request) {
	u := currentUser(r)
	f, ok := pkTake(r.URL.Query().Get("flow"))
	if !ok || f.uid != u.ID || f.kind != pkReauth {
		jsonErr(w, 400, "操作超时，请重试")
		return
	}
	wa, rp, err := a.rpFor(r)
	if err != nil || rp != f.rp {
		jsonErr(w, 400, errPasskeyHost.Error())
		return
	}
	keys := []string{"ip:" + a.clientIP(r), "user:" + strings.ToLower(u.Username)}
	if a.limiter.blocked(keys...) {
		jsonErr(w, 429, "失败次数过多，请 15 分钟后再试")
		return
	}
	cred, err := wa.FinishLogin(&pkUser{u: u, creds: a.passkeyCreds(u.ID, rp)}, f.data, r)
	if err == nil && cred.Authenticator.CloneWarning {
		err = errors.New("这个 Passkey 的签名计数异常（可能被复制）")
	}
	if err != nil {
		a.limiter.record(keys...)
		jsonErr(w, 400, "Passkey 验证失败："+pkErr(err))
		return
	}
	raw, _ := json.Marshal(cred)
	_, _ = a.db.Exec(`UPDATE passkeys SET cred=?, last_used=? WHERE user_id=? AND cred_id=?`, string(raw), time.Now().Unix(), u.ID, base64.RawURLEncoding.EncodeToString(cred.ID))
	markReauth(r)
	writeJSON(w, 200, map[string]bool{"ok": true})
}
