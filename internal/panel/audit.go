package panel

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"reflect"
	"strconv"
	"strings"
	"time"
)

type AuditEntry struct {
	ID         int64           `json:"id"`
	TS         int64           `json:"ts"`
	UserID     int64           `json:"user_id"`
	Username   string          `json:"username"`
	IP         string          `json:"ip"`
	Action     string          `json:"action"`
	TargetType string          `json:"target_type"`
	TargetID   string          `json:"target_id"`
	Summary    string          `json:"summary"`
	Before     json.RawMessage `json:"before"`
	After      json.RawMessage `json:"after"`
	ApprovalID *int64          `json:"approval_id"`
	Restorable bool            `json:"restorable"`
	RestoredBy *int64          `json:"restored_by"`
	RestoredAt *int64          `json:"restored_at"`
	RestoreOf  *int64          `json:"restore_of"`
}

// actor identifies who performed an action and from where.
type actor struct {
	user       *User
	ip         string
	approvalID int64 // >0 if executed after super-admin approval
	restoreOf  int64 // >0 if this is a restore of another audit entry
}

func (a *App) audit(ac actor, action, targetType, targetID, summary string, before, after any, restorable bool) int64 {
	var approval, restoreOf any
	if ac.approvalID > 0 {
		approval = ac.approvalID
	}
	if ac.restoreOf > 0 {
		restoreOf = ac.restoreOf
	}
	nullable := func(v any) any {
		if v == nil || (reflect.ValueOf(v).Kind() == reflect.Map && reflect.ValueOf(v).IsNil()) {
			return nil
		}
		return mustJSON(v)
	}
	res, err := a.db.Exec(`INSERT INTO audit(ts, user_id, username, ip, action, target_type, target_id, summary, before, after, approval_id, restorable, restore_of)
		VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		time.Now().Unix(), ac.user.ID, ac.user.Username, ac.ip, action, targetType, targetID, summary,
		nullable(before), nullable(after), approval, restorable, restoreOf)
	if err != nil {
		return 0
	}
	id, _ := res.LastInsertId()
	return id
}

func (a *App) getAudit(id int64) (*AuditEntry, error) {
	rows, err := a.queryAudit(`WHERE id=?`, id)
	if err != nil {
		return nil, err
	}
	if len(rows) == 0 {
		return nil, errors.New("记录不存在")
	}
	return rows[0], nil
}

func (a *App) queryAudit(where string, args ...any) ([]*AuditEntry, error) {
	rows, err := a.db.Query(`SELECT id, ts, user_id, username, ip, action, target_type, target_id, summary,
		COALESCE(before,'null'), COALESCE(after,'null'), approval_id, restorable, restored_by, restored_at, restore_of FROM audit `+where, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []*AuditEntry{}
	for rows.Next() {
		var e AuditEntry
		var before, after string
		if err := rows.Scan(&e.ID, &e.TS, &e.UserID, &e.Username, &e.IP, &e.Action, &e.TargetType, &e.TargetID, &e.Summary,
			&before, &after, &e.ApprovalID, &e.Restorable, &e.RestoredBy, &e.RestoredAt, &e.RestoreOf); err != nil {
			return nil, err
		}
		e.Before, e.After = json.RawMessage(before), json.RawMessage(after)
		out = append(out, &e)
	}
	return out, rows.Err()
}

// GET /api/audit?user_id=&action=&q=&before_id=&limit=
func (a *App) handleAuditList(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	var conds []string
	var args []any
	if v := q.Get("user_id"); v != "" {
		conds = append(conds, "user_id=?")
		args = append(args, v)
	}
	if v := q.Get("action"); v != "" {
		conds = append(conds, "action LIKE ?")
		args = append(args, v+"%")
	}
	if v := q.Get("q"); v != "" {
		conds = append(conds, "(summary LIKE ? OR target_id LIKE ? OR username LIKE ?)")
		args = append(args, "%"+v+"%", "%"+v+"%", "%"+v+"%")
	}
	if v := q.Get("before_id"); v != "" {
		conds = append(conds, "id < ?")
		args = append(args, v)
	}
	limit, _ := strconv.Atoi(q.Get("limit"))
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	where := ""
	if len(conds) > 0 {
		where = "WHERE " + strings.Join(conds, " AND ")
	}
	list, err := a.queryAudit(where+" ORDER BY id DESC LIMIT "+strconv.Itoa(limit), args...)
	if err != nil {
		jsonErr(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, list)
}

// POST /api/audit/{id}/restore {force}
func (a *App) handleAuditRestore(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Force bool `json:"force"`
	}
	_ = readJSON(r, &req)
	e, err := a.getAudit(pathID(r))
	if err != nil {
		jsonErr(w, 404, err.Error())
		return
	}
	if !e.Restorable {
		jsonErr(w, 400, "该记录不支持还原")
		return
	}
	ac := actor{user: currentUser(r), ip: a.clientIP(r), restoreOf: e.ID}
	var conflict string
	switch e.TargetType {
	case "user":
		conflict, err = a.restoreUser(ac, e, req.Force)
	case "setting":
		conflict, err = a.restoreSetting(ac, e, req.Force)
	case "uci":
		conflict, err = a.restoreUci(ac, e, req.Force)
	case "forward":
		conflict, err = a.restoreForward(ac, e, req.Force)
	case "device_meta":
		conflict, err = a.restoreDeviceMeta(ac, e, req.Force)
	default:
		err = fmt.Errorf("unknown target type %s", e.TargetType)
	}
	if conflict != "" {
		writeJSON(w, 409, map[string]string{"error": "当前值已被再次修改，确认要覆盖吗？", "conflict": conflict})
		return
	}
	if err != nil {
		jsonErr(w, 500, err.Error())
		return
	}
	_, _ = a.db.Exec(`UPDATE audit SET restored_by=?, restored_at=? WHERE id=?`, ac.user.ID, time.Now().Unix(), e.ID)
	writeJSON(w, 200, map[string]bool{"ok": true})
}

func (a *App) restoreUser(ac actor, e *AuditEntry, force bool) (string, error) {
	id, _ := strconv.ParseInt(e.TargetID, 10, 64)
	u, err := a.getUser(id)
	if err != nil {
		return "", errors.New("用户已不存在")
	}
	var before, after map[string]any
	_ = json.Unmarshal(e.Before, &before)
	_ = json.Unmarshal(e.After, &after)
	if before == nil {
		return "", errors.New("没有可还原的原值")
	}
	cur := u.auditView()
	if !force && after != nil && !sameJSON(cur, after) {
		return "当前值与该记录修改后的值不一致", nil
	}
	old := u.auditView()
	var bv struct {
		DisplayName string         `json:"display_name"`
		Perms       []string       `json:"perms"`
		Quotas      map[string]int `json:"quotas"`
		Grants      ForwardGrants  `json:"grants"`
		Disabled    bool           `json:"disabled"`
	}
	_ = json.Unmarshal(e.Before, &bv)
	if u.Role == RoleSuper && bv.Disabled {
		return "", errors.New("不能停用超级管理员")
	}
	u.DisplayName, u.Perms, u.Quotas, u.Grants, u.Disabled = bv.DisplayName, bv.Perms, bv.Quotas, bv.Grants, bv.Disabled
	if err := a.saveUser(u); err != nil {
		return "", err
	}
	if u.Disabled {
		_, _ = a.db.Exec(`DELETE FROM sessions WHERE user_id=?`, u.ID)
	}
	a.audit(ac, "user.restore", "user", e.TargetID, fmt.Sprintf("还原用户 %s（审计 #%d）", u.Username, e.ID), old, u.auditView(), true)
	return "", nil
}

func (a *App) restoreSetting(ac actor, e *AuditEntry, force bool) (string, error) {
	var before, after string
	_ = json.Unmarshal(e.Before, &before)
	_ = json.Unmarshal(e.After, &after)
	cur := a.setting(e.TargetID)
	if !force && cur != after {
		return "当前值：" + cur, nil
	}
	if err := a.setSetting(e.TargetID, before); err != nil {
		return "", err
	}
	a.audit(ac, "setting.restore", "setting", e.TargetID, fmt.Sprintf("还原设置 %s（审计 #%d）", e.TargetID, e.ID), cur, before, true)
	return "", nil
}

// uci audit entries store full section snapshots; target_id is "config.section".
func (a *App) restoreUci(ac actor, e *AuditEntry, force bool) (string, error) {
	config, section, _ := strings.Cut(e.TargetID, ".")
	var before, after Section
	_ = json.Unmarshal(e.Before, &before)
	_ = json.Unmarshal(e.After, &after)

	all, err := a.agent.UciConfig(config)
	if err != nil {
		return "", err
	}
	cur := all[section]
	if !force && !sameSection(cur, after) {
		return "路由器上的当前配置与该记录修改后的值不一致", nil
	}

	var change UciChange
	switch {
	case before == nil && cur != nil: // was created -> delete
		change = UciChange{Op: "delete", Config: config, Section: section}
	case before == nil:
		return "", errors.New("该配置已不存在，无需还原")
	case cur == nil: // was deleted -> re-create
		change = UciChange{Op: "add", Config: config, Type: fmt.Sprint(before[".type"]), Values: optionsOf(before)}
		if strings.HasPrefix(section, "owp") { // named sections keep their name
			change.Name = section
		}
	default: // modified -> set old values, drop options that did not exist
		change = UciChange{Op: "set", Config: config, Section: section, Values: optionsOf(before)}
	}
	res, err := a.agent.Apply(change)
	if err != nil {
		return "", err
	}
	if change.Op == "set" {
		var extra []string
		for k := range optionsOf(cur) {
			if _, ok := before[k]; !ok {
				extra = append(extra, k)
			}
		}
		if len(extra) > 0 {
			if r2, err := a.agent.Apply(UciChange{Op: "delete", Config: config, Section: section, Options: extra}); err == nil {
				res[0].After = r2[0].After
			}
		}
	}
	newSection := res[0].Section
	if change.Op == "add" {
		// owned rows outlive deletions, so ownership follows the re-created section
		_, _ = a.db.Exec(`UPDATE owned SET section=? WHERE config=? AND section=?`, newSection, config, section)
	}
	a.audit(ac, "uci.restore", "uci", config+"."+newSection, fmt.Sprintf("还原 %s.%s（审计 #%d）", config, section, e.ID), cur, res[0].After, true)
	return "", nil
}

func optionsOf(s Section) map[string]any {
	out := map[string]any{}
	for k, v := range s {
		if !strings.HasPrefix(k, ".") {
			out[k] = v
		}
	}
	return out
}

func sameSection(a, b Section) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	return sameJSON(optionsOf(a), optionsOf(b))
}

func sameJSON(a, b any) bool {
	return mustJSON(a) == mustJSON(b)
}
