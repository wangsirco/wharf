package panel

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"

	"github.com/wangsirco/wharf/internal/sign"
)

// EnsureSuper creates the single super admin on first start and writes its
// initial password to <data>/initial_password (shown by the LuCI plugin).
func EnsureSuper(db *sql.DB, cfg Config) error {
	var n int
	if err := db.QueryRow(`SELECT COUNT(*) FROM users WHERE role=?`, RoleSuper).Scan(&n); err != nil {
		return err
	}
	if n > 0 {
		return nil
	}
	_, err := ResetSuper(db, cfg)
	return err
}

// ResetSuper sets a new random password for the super admin (creating it if needed).
func ResetSuper(db *sql.DB, cfg Config) (string, error) {
	a := &App{db: db}
	pw := sign.RandomHex(8)
	var id int64
	username := "admin"
	err := db.QueryRow(`SELECT id, username FROM users WHERE role=? ORDER BY id LIMIT 1`, RoleSuper).Scan(&id, &username)
	if err == sql.ErrNoRows {
		if _, err := a.createUser(username, "超级管理员", pw, RoleSuper); err != nil {
			return "", err
		}
	} else if err != nil {
		return "", err
	} else if err := a.setPassword(id, pw); err != nil {
		return "", err
	} else {
		_, _ = db.Exec(`UPDATE users SET disabled=0 WHERE id=?`, id)
	}
	f := filepath.Join(cfg.DataDir, "initial_password")
	if err := os.WriteFile(f, []byte(fmt.Sprintf("%s\n%s\n", username, pw)), 0o600); err != nil {
		return "", err
	}
	return pw, nil
}
