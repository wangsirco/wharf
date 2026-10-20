package panel

import (
	"database/sql"
	"encoding/json"
	"errors"
	"regexp"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/bcrypt"
)

const (
	RoleSuper = "super"
	RoleAdmin = "admin"
)

type User struct {
	ID          int64          `json:"id"`
	Username    string         `json:"username"`
	DisplayName string         `json:"display_name"`
	Role        string         `json:"role"`
	Perms       []string       `json:"perms"`
	Quotas      map[string]int `json:"quotas"`
	Grants      ForwardGrants  `json:"grants"`
	Disabled    bool           `json:"disabled"`
	CreatedAt   int64          `json:"created_at"`
	UpdatedAt   int64          `json:"updated_at"`
	LastLoginAt int64          `json:"last_login_at"`
}

// auditView is what gets stored in audit before/after (never the password hash).
func (u *User) auditView() map[string]any {
	return map[string]any{"username": u.Username, "display_name": u.DisplayName, "perms": u.Perms, "quotas": u.Quotas, "grants": u.Grants, "disabled": u.Disabled}
}

var (
	dummyOnce sync.Once
	dummyHash []byte
)

var usernameRe = regexp.MustCompile(`^[a-zA-Z0-9_.-]{3,32}$`)

func validPassword(p string) error {
	if len(p) < 8 {
		return errors.New("密码至少 8 位")
	}
	if len(p) > 72 {
		return errors.New("密码最多 72 位")
	}
	return nil
}

func hashPassword(p string) (string, error) {
	h, err := bcrypt.GenerateFromPassword([]byte(p), 12)
	return string(h), err
}

const userCols = `id, username, display_name, role, perms, quotas, grants, disabled, created_at, updated_at, last_login_at`

func scanUser(row interface{ Scan(...any) error }) (*User, error) {
	var u User
	var perms, quotas, grants string
	if err := row.Scan(&u.ID, &u.Username, &u.DisplayName, &u.Role, &perms, &quotas, &grants, &u.Disabled, &u.CreatedAt, &u.UpdatedAt, &u.LastLoginAt); err != nil {
		return nil, err
	}
	_ = json.Unmarshal([]byte(perms), &u.Perms)
	_ = json.Unmarshal([]byte(quotas), &u.Quotas)
	_ = json.Unmarshal([]byte(grants), &u.Grants)
	u.Grants.normalize()
	if u.Perms == nil {
		u.Perms = []string{}
	}
	if u.Quotas == nil {
		u.Quotas = map[string]int{}
	}
	return &u, nil
}

func (a *App) getUser(id int64) (*User, error) {
	return scanUser(a.db.QueryRow(`SELECT `+userCols+` FROM users WHERE id=?`, id))
}

func (a *App) listUsers() ([]*User, error) {
	rows, err := a.db.Query(`SELECT ` + userCols + ` FROM users ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*User
	for rows.Next() {
		u, err := scanUser(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, u)
	}
	return out, rows.Err()
}

func (a *App) saveUser(u *User) error {
	perms, _ := json.Marshal(u.Perms)
	quotas, _ := json.Marshal(u.Quotas)
	u.Grants.normalize()
	grants, _ := json.Marshal(u.Grants)
	u.UpdatedAt = time.Now().Unix()
	_, err := a.db.Exec(`UPDATE users SET display_name=?, perms=?, quotas=?, grants=?, disabled=?, updated_at=? WHERE id=?`,
		u.DisplayName, string(perms), string(quotas), string(grants), u.Disabled, u.UpdatedAt, u.ID)
	return err
}

func (a *App) createUser(username, display, password, role string) (*User, error) {
	if !usernameRe.MatchString(username) {
		return nil, errors.New("用户名需为 3-32 位字母、数字、_ . -")
	}
	if err := validPassword(password); err != nil {
		return nil, err
	}
	display = strings.TrimSpace(display)
	if display == "" {
		display = username
	}
	h, err := hashPassword(password)
	if err != nil {
		return nil, err
	}
	now := time.Now().Unix()
	res, err := a.db.Exec(`INSERT INTO users(username, display_name, password_hash, role, created_at, updated_at) VALUES(?,?,?,?,?,?)`,
		username, display, h, role, now, now)
	if err != nil {
		if strings.Contains(err.Error(), "UNIQUE") {
			return nil, errors.New("用户名已存在")
		}
		return nil, err
	}
	id, _ := res.LastInsertId()
	return a.getUser(id)
}

func (a *App) setPassword(id int64, password string) error {
	if err := validPassword(password); err != nil {
		return err
	}
	h, err := hashPassword(password)
	if err != nil {
		return err
	}
	if _, err := a.db.Exec(`UPDATE users SET password_hash=?, updated_at=? WHERE id=?`, h, time.Now().Unix(), id); err != nil {
		return err
	}
	// force re-login everywhere
	_, err = a.db.Exec(`DELETE FROM sessions WHERE user_id=?`, id)
	return err
}

func (a *App) checkPassword(username, password string) (*User, error) {
	var id int64
	var hash string
	err := a.db.QueryRow(`SELECT id, password_hash FROM users WHERE username=?`, username).Scan(&id, &hash)
	if errors.Is(err, sql.ErrNoRows) {
		// still run bcrypt so unknown usernames take as long as wrong passwords
		dummyOnce.Do(func() { dummyHash, _ = bcrypt.GenerateFromPassword([]byte("owp-dummy"), 12) })
		_ = bcrypt.CompareHashAndPassword(dummyHash, []byte(password))
		return nil, errors.New("用户名或密码错误")
	}
	if err != nil {
		return nil, err
	}
	if bcrypt.CompareHashAndPassword([]byte(hash), []byte(password)) != nil {
		return nil, errors.New("用户名或密码错误")
	}
	u, err := a.getUser(id)
	if err != nil {
		return nil, err
	}
	if u.Disabled {
		return nil, errors.New("账号已停用")
	}
	return u, nil
}
