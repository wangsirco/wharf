package panel

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"net/http"
	"sync"
	"time"

	"github.com/wangsirco/wharf/internal/sign"
)

const (
	sessionCookie = "owp_sid"
	sessionIdle   = 12 * time.Hour
	sessionMax    = 7 * 24 * time.Hour
)

type ctxKey int

const userKey ctxKey = 1

type sessionInfo struct {
	user *User
	csrf string
}

func tokenHash(t string) string {
	h := sha256.Sum256([]byte(t))
	return hex.EncodeToString(h[:])
}

func (a *App) createSession(w http.ResponseWriter, r *http.Request, u *User) (string, error) {
	token, csrf := sign.RandomHex(32), sign.RandomHex(16)
	now := time.Now().Unix()
	if _, err := a.db.Exec(`INSERT INTO sessions(token_hash, user_id, csrf, ip, user_agent, created_at, seen_at) VALUES(?,?,?,?,?,?,?)`,
		tokenHash(token), u.ID, csrf, a.clientIP(r), truncate(r.UserAgent(), 300), now, now); err != nil {
		return "", err
	}
	_, _ = a.db.Exec(`UPDATE users SET last_login_at=? WHERE id=?`, now, u.ID)
	http.SetCookie(w, &http.Cookie{Name: sessionCookie, Value: token, Path: "/", HttpOnly: true, Secure: a.secure, SameSite: http.SameSiteStrictMode, MaxAge: int(sessionMax.Seconds())})
	return csrf, nil
}

func (a *App) destroySession(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie(sessionCookie); err == nil {
		_, _ = a.db.Exec(`DELETE FROM sessions WHERE token_hash=?`, tokenHash(c.Value))
	}
	http.SetCookie(w, &http.Cookie{Name: sessionCookie, Value: "", Path: "/", HttpOnly: true, Secure: a.secure, SameSite: http.SameSiteStrictMode, MaxAge: -1})
}

func (a *App) loadSession(r *http.Request) *sessionInfo {
	c, err := r.Cookie(sessionCookie)
	if err != nil || c.Value == "" {
		return nil
	}
	th := tokenHash(c.Value)
	var uid, created, seen int64
	var csrf string
	if a.db.QueryRow(`SELECT user_id, csrf, created_at, seen_at FROM sessions WHERE token_hash=?`, th).Scan(&uid, &csrf, &created, &seen) != nil {
		return nil
	}
	now := time.Now()
	if now.Sub(time.Unix(seen, 0)) > sessionIdle || now.Sub(time.Unix(created, 0)) > sessionMax {
		_, _ = a.db.Exec(`DELETE FROM sessions WHERE token_hash=?`, th)
		return nil
	}
	u, err := a.getUser(uid)
	if err != nil || u.Disabled {
		return nil
	}
	if now.Unix()-seen > 60 {
		_, _ = a.db.Exec(`UPDATE sessions SET seen_at=? WHERE token_hash=?`, now.Unix(), th)
	}
	return &sessionInfo{user: u, csrf: csrf}
}

func currentUser(r *http.Request) *User {
	u, _ := r.Context().Value(userKey).(*User)
	return u
}

// auth wraps a handler requiring a logged-in user, a valid CSRF header on
// state-changing requests, and (optionally) a permission.
func (a *App) auth(perm string, h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		s := a.loadSession(r)
		if s == nil {
			jsonErr(w, http.StatusUnauthorized, "未登录或会话已过期")
			return
		}
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			if subtle.ConstantTimeCompare([]byte(r.Header.Get("X-OWP-CSRF")), []byte(s.csrf)) != 1 {
				jsonErr(w, http.StatusForbidden, "CSRF 校验失败，请刷新页面")
				return
			}
		}
		if perm != "" && !s.user.Can(perm) {
			jsonErr(w, http.StatusForbidden, "没有权限")
			return
		}
		h(w, r.WithContext(context.WithValue(r.Context(), userKey, s.user)))
	}
}

// super requires the super-admin role.
func (a *App) super(h http.HandlerFunc) http.HandlerFunc {
	return a.auth("", func(w http.ResponseWriter, r *http.Request) {
		if currentUser(r).Role != RoleSuper {
			jsonErr(w, http.StatusForbidden, "仅超级管理员可操作")
			return
		}
		h(w, r)
	})
}

// loginLimiter counts events per key in a sliding window (login failures per
// IP/username, beacons per IP).
type loginLimiter struct {
	mu     sync.Mutex
	max    int
	window time.Duration
	fail   map[string][]time.Time
}

func newLimiter(max int, window time.Duration) *loginLimiter {
	return &loginLimiter{max: max, window: window, fail: map[string][]time.Time{}}
}

func (l *loginLimiter) blocked(keys ...string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	for _, k := range keys {
		if len(l.recent(k)) >= l.max {
			return true
		}
	}
	return false
}

func (l *loginLimiter) recent(k string) []time.Time {
	var keep []time.Time
	for _, t := range l.fail[k] {
		if time.Since(t) < l.window {
			keep = append(keep, t)
		}
	}
	l.fail[k] = keep
	return keep
}

func (l *loginLimiter) record(keys ...string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	for _, k := range keys {
		l.fail[k] = append(l.recent(k), time.Now())
	}
}

func (l *loginLimiter) reset(keys ...string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	for _, k := range keys {
		delete(l.fail, k)
	}
}
