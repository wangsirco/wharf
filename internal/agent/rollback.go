package agent

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"log"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"sync"
	"time"
)

// Guarded apply: changes that can cut the panel off (interfaces, firewall) are
// committed with a snapshot of the touched config files. Unless the panel
// confirms within the window — proving it can still reach the router — the
// snapshot is put back and the services reloaded. The snapshot lives on flash so
// an agent restart or a reboot inside the window also rolls back.

const rollbackDir = "/etc/wharf-rollback"

type PendingApply struct {
	Token    string   `json:"token"`
	Configs  []string `json:"configs"`
	Deadline int64    `json:"deadline"`
	Started  int64    `json:"started"`
	Summary  string   `json:"summary,omitempty"`
}

var pend struct {
	sync.Mutex
	cur   *PendingApply
	timer *time.Timer
}

func CurrentPending() *PendingApply {
	pend.Lock()
	defer pend.Unlock()
	if pend.cur == nil {
		return nil
	}
	p := *pend.cur
	return &p
}

// ApplyGuarded commits changes and arms the rollback timer.
func ApplyGuarded(changes []Change, seconds int, summary string) ([]ChangeResult, *PendingApply, error) {
	if seconds < 30 || seconds > 600 {
		seconds = 90
	}
	applyMu.Lock()
	defer applyMu.Unlock()
	pend.Lock()
	busy := pend.cur != nil
	pend.Unlock()
	if busy {
		return nil, nil, errors.New("还有一项改动在等待确认，请先确认或撤销")
	}
	var cfgs []string
	for _, c := range changes {
		if err := configWritable(c.Config); err != nil {
			return nil, nil, err
		}
		if !slices.Contains(cfgs, c.Config) {
			cfgs = append(cfgs, c.Config)
		}
	}
	sort.Strings(cfgs)
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	p := &PendingApply{Token: hex.EncodeToString(b), Configs: cfgs, Started: time.Now().Unix(), Deadline: time.Now().Unix() + int64(seconds), Summary: summary}
	dir := filepath.Join(rollbackDir, p.Token)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, nil, err
	}
	for _, c := range cfgs {
		data, err := os.ReadFile("/etc/config/" + c)
		if err != nil {
			_ = os.RemoveAll(dir)
			return nil, nil, err
		}
		if err := os.WriteFile(filepath.Join(dir, c), data, 0o600); err != nil {
			_ = os.RemoveAll(dir)
			return nil, nil, err
		}
	}
	mj, _ := json.Marshal(p)
	_ = os.WriteFile(filepath.Join(dir, ".pending.json"), mj, 0o600)
	res, err := applyLocked(changes)
	if err != nil {
		_ = os.RemoveAll(dir)
		return nil, nil, err
	}
	pend.Lock()
	pend.cur = p
	pend.timer = time.AfterFunc(time.Duration(seconds)*time.Second, func() { _ = rollback(p.Token, "timeout") })
	pend.Unlock()
	cp := *p
	return res, &cp, nil
}

// ConfirmApply keeps the changes.
func ConfirmApply(token string) error {
	pend.Lock()
	defer pend.Unlock()
	if pend.cur == nil || pend.cur.Token != token {
		return errors.New("没有等待确认的改动（可能已经超时撤销）")
	}
	pend.timer.Stop()
	_ = os.RemoveAll(filepath.Join(rollbackDir, token))
	pend.cur, pend.timer = nil, nil
	return nil
}

// RollbackApply undoes the pending change now.
func RollbackApply(token string) error { return rollback(token, "manual") }

func rollback(token, why string) error {
	pend.Lock()
	if pend.cur == nil || pend.cur.Token != token {
		pend.Unlock()
		return errors.New("没有等待确认的改动")
	}
	p := pend.cur
	if pend.timer != nil {
		pend.timer.Stop()
	}
	pend.cur, pend.timer = nil, nil
	pend.Unlock()
	applyMu.Lock()
	defer applyMu.Unlock()
	restoreSnapshot(filepath.Join(rollbackDir, token), p.Configs)
	log.Printf("rollback %s (%s): %v", token, why, p.Configs)
	lastRollback.Lock()
	lastRollback.at, lastRollback.why, lastRollback.configs = time.Now().Unix(), why, p.Configs
	lastRollback.Unlock()
	return nil
}

var lastRollback struct {
	sync.Mutex
	at      int64
	why     string
	configs []string
}

// LastRollback tells the panel that a change was undone (and why).
func LastRollback() map[string]any {
	lastRollback.Lock()
	defer lastRollback.Unlock()
	if lastRollback.at == 0 {
		return nil
	}
	return map[string]any{"at": lastRollback.at, "why": lastRollback.why, "configs": lastRollback.configs}
}

func restoreSnapshot(dir string, cfgs []string) {
	for _, c := range cfgs {
		data, err := os.ReadFile(filepath.Join(dir, c))
		if err != nil {
			continue
		}
		_ = ubusCall("uci", "revert", map[string]any{"config": c}, nil)
		tmp := "/etc/config/." + c + ".wharf-rb"
		if os.WriteFile(tmp, data, 0o644) == nil {
			_ = os.Rename(tmp, "/etc/config/"+c)
		}
	}
	for _, c := range cfgs {
		reloadConfig(c)
	}
	_ = os.RemoveAll(dir)
}

// RecoverPending runs at agent start: a snapshot left behind means the change was
// never confirmed (agent restart or reboot inside the window) — put it back.
func RecoverPending() {
	ents, _ := os.ReadDir(rollbackDir)
	for _, e := range ents {
		dir := filepath.Join(rollbackDir, e.Name())
		var p PendingApply
		b, err := os.ReadFile(filepath.Join(dir, ".pending.json"))
		if err != nil || json.Unmarshal(b, &p) != nil {
			_ = os.RemoveAll(dir)
			continue
		}
		log.Printf("unconfirmed change %s found at start: rolling back %v", p.Token, p.Configs)
		restoreSnapshot(dir, p.Configs)
		lastRollback.Lock()
		lastRollback.at, lastRollback.why, lastRollback.configs = time.Now().Unix(), "restart", p.Configs
		lastRollback.Unlock()
	}
}
