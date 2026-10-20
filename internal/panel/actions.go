package panel

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strconv"
	"time"
)

// Action is a router-changing operation. Every action goes through dispatch,
// which enforces permission, validation, optional super-admin approval and audit.
type Action struct {
	Key   string `json:"key"`
	Label string `json:"label"`
	Perm  string `json:"perm"`
	// Prepare validates the payload for the given user and returns a human summary.
	// It runs both when the request is made and again right before execution.
	Prepare func(a *App, u *User, payload json.RawMessage) (summary string, err error) `json:"-"`
	// Run executes the action and writes its own audit entries.
	Run func(a *App, ac actor, payload json.RawMessage) (any, error) `json:"-"`
	// NeedsApproval optionally forces approval for specific payloads (e.g. opening a port to everyone).
	NeedsApproval func(a *App, payload json.RawMessage) bool `json:"-"`
	// Check optionally validates against the request itself (e.g. who is asking from where).
	Check func(a *App, r *http.Request, payload json.RawMessage) error `json:"-"`
}

var actions = map[string]*Action{}

func registerAction(act *Action) { actions[act.Key] = act }

func (a *App) approvalRequired(key string) bool {
	var list []string
	_ = json.Unmarshal([]byte(a.setting("approval.required")), &list)
	return slices.Contains(list, key)
}

// POST /api/actions/{key}
func (a *App) handleAction(w http.ResponseWriter, r *http.Request) {
	act := actions[r.PathValue("key")]
	if act == nil {
		jsonErr(w, 404, "未知操作")
		return
	}
	u := currentUser(r)
	if !u.Can(act.Perm) {
		jsonErr(w, 403, "没有权限")
		return
	}
	var payload json.RawMessage
	if err := readJSON(r, &payload); err != nil {
		jsonErr(w, 400, "请求格式错误")
		return
	}
	summary, err := act.Prepare(a, u, payload)
	if err == nil && act.Check != nil {
		err = act.Check(a, r, payload)
	}
	if err != nil {
		jsonErr(w, 400, err.Error())
		return
	}
	ip := a.clientIP(r)
	if u.Role != RoleSuper && (a.approvalRequired(act.Key) || (act.NeedsApproval != nil && act.NeedsApproval(a, payload))) {
		res, err := a.db.Exec(`INSERT INTO approvals(ts, user_id, username, ip, action, summary, payload, status) VALUES(?,?,?,?,?,?,?,'pending')`,
			time.Now().Unix(), u.ID, u.Username, ip, act.Key, summary, string(payload))
		if err != nil {
			jsonErr(w, 500, err.Error())
			return
		}
		id, _ := res.LastInsertId()
		writeJSON(w, 202, map[string]any{"pending": true, "approval_id": id, "message": "该操作需要超级管理员确认，已提交审批"})
		return
	}
	out, err := act.Run(a, actor{user: u, ip: ip}, payload)
	if err != nil {
		jsonErr(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true, "result": out})
}

type Approval struct {
	ID        int64  `json:"id"`
	TS        int64  `json:"ts"`
	UserID    int64  `json:"user_id"`
	Username  string `json:"username"`
	IP        string `json:"ip"`
	Action    string `json:"action"`
	Summary   string `json:"summary"`
	Status    string `json:"status"`
	DecidedBy *int64 `json:"decided_by"`
	DecidedAt *int64 `json:"decided_at"`
	Note      string `json:"note"`
	Result    string `json:"result"`
	payload   string
}

func (a *App) listApprovals(where string, args ...any) ([]*Approval, error) {
	rows, err := a.db.Query(`SELECT id, ts, user_id, username, ip, action, summary, status, decided_by, decided_at, note, result, payload FROM approvals `+where, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []*Approval{}
	for rows.Next() {
		var p Approval
		if err := rows.Scan(&p.ID, &p.TS, &p.UserID, &p.Username, &p.IP, &p.Action, &p.Summary, &p.Status, &p.DecidedBy, &p.DecidedAt, &p.Note, &p.Result, &p.payload); err != nil {
			return nil, err
		}
		out = append(out, &p)
	}
	return out, rows.Err()
}

// GET /api/approvals?status=  (super)
func (a *App) handleApprovals(w http.ResponseWriter, r *http.Request) {
	status := r.URL.Query().Get("status")
	var list []*Approval
	var err error
	if status != "" {
		list, err = a.listApprovals(`WHERE status=? ORDER BY id DESC LIMIT 200`, status)
	} else {
		list, err = a.listApprovals(`ORDER BY id DESC LIMIT 200`)
	}
	if err != nil {
		jsonErr(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, list)
}

// GET /api/my/approvals
func (a *App) handleMyApprovals(w http.ResponseWriter, r *http.Request) {
	list, err := a.listApprovals(`WHERE user_id=? ORDER BY id DESC LIMIT 100`, currentUser(r).ID)
	if err != nil {
		jsonErr(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, list)
}

// POST /api/approvals/{id}/{decision}  decision = approve | reject
func (a *App) handleApprovalDecide(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Note string `json:"note"`
	}
	_ = readJSON(r, &req)
	id := pathID(r)
	decision := r.PathValue("decision")
	super := currentUser(r)

	var p Approval
	err := a.db.QueryRow(`SELECT id, user_id, action, payload, status, summary FROM approvals WHERE id=?`, id).
		Scan(&p.ID, &p.UserID, &p.Action, &p.payload, &p.Status, &p.Summary)
	if err != nil {
		jsonErr(w, 404, "审批不存在")
		return
	}
	// claim atomically so two super-admin tabs cannot both execute
	now := time.Now().Unix()
	newStatus := map[string]string{"approve": "approved", "reject": "rejected"}[decision]
	if newStatus == "" {
		jsonErr(w, 400, "无效操作")
		return
	}
	res, _ := a.db.Exec(`UPDATE approvals SET status=?, decided_by=?, decided_at=?, note=? WHERE id=? AND status='pending'`,
		newStatus, super.ID, now, truncate(req.Note, 500), id)
	if n, _ := res.RowsAffected(); n == 0 {
		jsonErr(w, 409, "该审批已处理或已过期")
		return
	}
	ac := actor{user: super, ip: a.clientIP(r), approvalID: id}
	if decision == "reject" {
		a.audit(ac, "approval.reject", "approval", strconv.FormatInt(id, 10), "驳回审批 #"+strconv.FormatInt(id, 10)+"："+p.Summary, nil, nil, false)
		writeJSON(w, 200, map[string]bool{"ok": true})
		return
	}

	out, err := a.executeApproval(&p, ac)
	if err != nil {
		_, _ = a.db.Exec(`UPDATE approvals SET status='failed', result=? WHERE id=?`, truncate(err.Error(), 1000), id)
		jsonErr(w, 500, "执行失败："+err.Error())
		return
	}
	_, _ = a.db.Exec(`UPDATE approvals SET result=? WHERE id=?`, truncate(mustJSON(out), 1000), id)
	writeJSON(w, 200, map[string]any{"ok": true, "result": out})
}

// executeApproval runs the action as the requesting admin (their permissions and
// ownership still apply), recording the approving super admin's approval id.
func (a *App) executeApproval(p *Approval, approver actor) (any, error) {
	act := actions[p.Action]
	if act == nil {
		return nil, errors.New("操作已不存在")
	}
	requester, err := a.getUser(p.UserID)
	if err != nil || requester.Disabled {
		return nil, errors.New("申请人已不存在或被停用")
	}
	if !requester.Can(act.Perm) {
		return nil, errors.New("申请人已没有该权限")
	}
	payload := json.RawMessage(p.payload)
	if _, err := act.Prepare(a, requester, payload); err != nil {
		return nil, fmt.Errorf("校验失败：%w", err)
	}
	return act.Run(a, actor{user: requester, ip: approver.ip, approvalID: p.ID}, payload)
}
