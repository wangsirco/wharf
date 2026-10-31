package panel

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"

	"github.com/wangsirco/wharf/internal/sign"
)

// Passkeys (WebAuthn): sign in with Face ID, a fingerprint or a security key instead of
// the password (both keep working). A passkey belongs to the name it was made on (its
// RP ID); browsers only offer passkeys on a domain name with a trusted certificate, so
// they work at the panel's names from panelname.go and never at an IP address. The
// credentials are discoverable: signing in needs no username.

type pkUser struct {
	u     *User
	creds []webauthn.Credential
}

func (p *pkUser) WebAuthnID() []byte                         { return []byte("wharf-user-" + strconv.FormatInt(p.u.ID, 10)) }
func (p *pkUser) WebAuthnName() string                       { return p.u.Username }
func (p *pkUser) WebAuthnDisplayName() string                { return firstNonEmpty(p.u.DisplayName, p.u.Username) }
func (p *pkUser) WebAuthnCredentials() []webauthn.Credential { return p.creds }

func userIDFromHandle(h []byte) (int64, bool) {
	s, ok := strings.CutPrefix(string(h), "wharf-user-")
	if !ok {
		return 0, false
	}
	id, err := strconv.ParseInt(s, 10, 64)
	return id, err == nil
}

// pending ceremonies (begin -> finish), by a random flow id; five minutes to finish
var pkFlows struct {
	sync.Mutex
	m map[string]pkFlow
}

type pkFlow struct {
	data webauthn.SessionData
	uid  int64
	rp   string
	name string
	exp  time.Time
}

func pkPut(f pkFlow) string {
	pkFlows.Lock()
	defer pkFlows.Unlock()
	if pkFlows.m == nil {
		pkFlows.m = map[string]pkFlow{}
	}
	for k, v := range pkFlows.m {
		if time.Now().After(v.exp) {
			delete(pkFlows.m, k)
		}
	}
	id := sign.RandomHex(16)
	f.exp = time.Now().Add(5 * time.Minute)
	pkFlows.m[id] = f
	return id
}

func pkTake(id string) (pkFlow, bool) {
	pkFlows.Lock()
	defer pkFlows.Unlock()
	f, ok := pkFlows.m[id]
	delete(pkFlows.m, id)
	return f, ok && time.Now().Before(f.exp)
}

var errPasskeyHost = errors.New("Passkey 只能在面板的域名上使用（不能用 IP 地址打开）")

// rpFor builds the relying party for the name this request came in on.
func (a *App) rpFor(r *http.Request) (*webauthn.WebAuthn, string, error) {
	host := strings.ToLower(r.Host)
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	if !slices.Contains(a.passkeyHosts(), host) {
		return nil, "", errPasskeyHost
	}
	wa, err := webauthn.New(&webauthn.Config{RPID: host, RPDisplayName: firstNonEmpty(a.setting("ui.name"), "Wharf"), RPOrigins: []string{"https://" + r.Host}})
	return wa, host, err
}

type passkeyRow struct {
	ID       int64  `json:"id"`
	Name     string `json:"name"`
	RPID     string `json:"rp_id"`
	Created  int64  `json:"created"`
	LastUsed int64  `json:"last_used"`
}

func (a *App) passkeyCreds(uid int64, rp string) []webauthn.Credential {
	var out []webauthn.Credential
	rows, err := a.db.Query(`SELECT cred FROM passkeys WHERE user_id=? AND rp_id=?`, uid, rp)
	if err != nil {
		return nil
	}
	defer rows.Close()
	for rows.Next() {
		var raw string
		var c webauthn.Credential
		if rows.Scan(&raw) == nil && json.Unmarshal([]byte(raw), &c) == nil {
			out = append(out, c)
		}
	}
	return out
}

// GET /api/me/passkeys
func (a *App) handlePasskeys(w http.ResponseWriter, r *http.Request) {
	u := currentUser(r)
	list := []passkeyRow{}
	if rows, err := a.db.Query(`SELECT id, name, rp_id, created, last_used FROM passkeys WHERE user_id=? ORDER BY id`, u.ID); err == nil {
		for rows.Next() {
			var p passkeyRow
			if rows.Scan(&p.ID, &p.Name, &p.RPID, &p.Created, &p.LastUsed) == nil {
				list = append(list, p)
			}
		}
		rows.Close()
	}
	_, here, err := a.rpFor(r)
	_, port, _ := net.SplitHostPort(a.cfg.Listen)
	writeJSON(w, 200, map[string]any{"passkeys": list, "here": here, "usable": err == nil, "hosts": a.passkeyHosts(), "port": port})
}

// POST /api/me/passkeys/begin {name}
func (a *App) handlePasskeyBegin(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name string `json:"name"`
	}
	_ = readJSON(r, &req)
	wa, rp, err := a.rpFor(r)
	if err != nil {
		jsonErr(w, 400, err.Error())
		return
	}
	u := currentUser(r)
	pu := &pkUser{u: u, creds: a.passkeyCreds(u.ID, rp)}
	creation, data, err := wa.BeginRegistration(pu,
		webauthn.WithResidentKeyRequirement(protocol.ResidentKeyRequirementRequired),
		webauthn.WithExclusions(webauthn.Credentials(pu.creds).CredentialDescriptors()))
	if err != nil {
		jsonErr(w, 500, err.Error())
		return
	}
	flow := pkPut(pkFlow{data: *data, uid: u.ID, rp: rp, name: firstNonEmpty(clean(req.Name, 40), "Passkey")})
	writeJSON(w, 200, map[string]any{"flow": flow, "options": creation.Response})
}

// POST /api/me/passkeys/finish?flow= (body: the browser's credential)
func (a *App) handlePasskeyFinish(w http.ResponseWriter, r *http.Request) {
	f, ok := pkTake(r.URL.Query().Get("flow"))
	u := currentUser(r)
	if !ok || f.uid != u.ID {
		jsonErr(w, 400, "操作超时，请重新添加")
		return
	}
	wa, rp, err := a.rpFor(r)
	if err != nil || rp != f.rp {
		jsonErr(w, 400, errPasskeyHost.Error())
		return
	}
	cred, err := wa.FinishRegistration(&pkUser{u: u, creds: a.passkeyCreds(u.ID, rp)}, f.data, r)
	if err != nil {
		jsonErr(w, 400, "Passkey 创建失败："+pkErr(err))
		return
	}
	raw, _ := json.Marshal(cred)
	now := time.Now().Unix()
	if _, err := a.db.Exec(`INSERT INTO passkeys(user_id, rp_id, cred_id, cred, name, created, last_used) VALUES(?,?,?,?,?,?,0)`,
		u.ID, rp, base64.RawURLEncoding.EncodeToString(cred.ID), string(raw), f.name, now); err != nil {
		jsonErr(w, 500, err.Error())
		return
	}
	a.audit(actor{user: u, ip: a.clientIP(r)}, "passkey.add", "user", strconv.FormatInt(u.ID, 10), "添加 Passkey「"+f.name+"」（"+rp+"）", nil, nil, false)
	a.handlePasskeys(w, r)
}

// DELETE /api/me/passkeys/{id}
func (a *App) handlePasskeyDelete(w http.ResponseWriter, r *http.Request) {
	u := currentUser(r)
	var name string
	if a.db.QueryRow(`SELECT name FROM passkeys WHERE id=? AND user_id=?`, pathID(r), u.ID).Scan(&name) != nil {
		jsonErr(w, 404, "没有这个 Passkey")
		return
	}
	_, _ = a.db.Exec(`DELETE FROM passkeys WHERE id=? AND user_id=?`, pathID(r), u.ID)
	a.audit(actor{user: u, ip: a.clientIP(r)}, "passkey.delete", "user", strconv.FormatInt(u.ID, 10), "删除 Passkey「"+name+"」", nil, nil, false)
	a.handlePasskeys(w, r)
}

// POST /api/login/passkey/begin (public)
func (a *App) handlePasskeyLoginBegin(w http.ResponseWriter, r *http.Request) {
	wa, rp, err := a.rpFor(r)
	if err != nil {
		jsonErr(w, 400, err.Error())
		return
	}
	if a.limiter.blocked("ip:" + a.clientIP(r)) {
		jsonErr(w, 429, "失败次数过多，请 15 分钟后再试")
		return
	}
	assertion, data, err := wa.BeginDiscoverableLogin()
	if err != nil {
		jsonErr(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"flow": pkPut(pkFlow{data: *data, rp: rp}), "options": assertion.Response})
}

// POST /api/login/passkey/finish?flow=&tz= (public; body: the browser's assertion)
func (a *App) handlePasskeyLoginFinish(w http.ResponseWriter, r *http.Request) {
	ip := a.clientIP(r)
	if a.limiter.blocked("ip:" + ip) {
		jsonErr(w, 429, "失败次数过多，请 15 分钟后再试")
		return
	}
	f, ok := pkTake(r.URL.Query().Get("flow"))
	if !ok {
		jsonErr(w, 400, "操作超时，请重试")
		return
	}
	wa, rp, err := a.rpFor(r)
	if err != nil || rp != f.rp {
		jsonErr(w, 400, errPasskeyHost.Error())
		return
	}
	if !a.timezoneAllowed(ip, r.URL.Query().Get("tz")) {
		jsonErr(w, 403, "拒绝访问：当前时区不在允许范围")
		return
	}
	var who *User
	user, cred, err := wa.FinishPasskeyLogin(func(rawID, handle []byte) (webauthn.User, error) {
		uid, ok := userIDFromHandle(handle)
		if !ok {
			return nil, errors.New("unknown user")
		}
		u, err := a.getUser(uid)
		if err != nil || u.Disabled {
			return nil, errors.New("账号不存在或已停用")
		}
		who = u
		return &pkUser{u: u, creds: a.passkeyCreds(uid, rp)}, nil
	}, f.data, r)
	if err != nil || who == nil || user == nil {
		a.limiter.record("ip:" + ip)
		jsonErr(w, 401, "Passkey 验证失败："+pkErr(err))
		return
	}
	if cred.Authenticator.CloneWarning {
		a.limiter.record("ip:" + ip)
		jsonErr(w, 401, "这个 Passkey 的签名计数异常（可能被复制），已拒绝；请删除它后重新添加")
		return
	}
	raw, _ := json.Marshal(cred)
	_, _ = a.db.Exec(`UPDATE passkeys SET cred=?, last_used=? WHERE user_id=? AND cred_id=?`, string(raw), time.Now().Unix(), who.ID, base64.RawURLEncoding.EncodeToString(cred.ID))
	csrf, err := a.createSession(w, r, who)
	if err != nil {
		jsonErr(w, 500, err.Error())
		return
	}
	a.limiter.reset("ip:"+ip, "user:"+strings.ToLower(who.Username))
	a.audit(actor{user: who, ip: ip}, "session.login", "session", strconv.FormatInt(who.ID, 10), "登录（Passkey）", nil, nil, false)
	writeJSON(w, 200, map[string]any{"user": who, "csrf": csrf})
}

func pkErr(err error) string {
	if err == nil {
		return "未知错误"
	}
	var pe *protocol.Error
	if errors.As(err, &pe) && pe.DevInfo != "" {
		return pe.Details + "（" + pe.DevInfo + "）"
	}
	return err.Error()
}
