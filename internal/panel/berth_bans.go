package panel

import (
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

// External bans: addresses dropped at the WAN, for the router itself and for everything it
// forwards; the LAN is never affected. They come from Berth (origin berth) or are made here
// (origin wharf), optionally also sent to Berth (sync).
//
//	firewall.owps_berth_ban  ipset  owp_berth_ban (hash:net, contents in the agent's sets dir)
//	firewall.owpb_in         rule   src wan, ipset owp_berth_ban → DROP (to the router)
//	firewall.owpb_fwd        rule   src wan, dest *, ipset owp_berth_ban → DROP (forwarded)
//
// Expiry is handled by the panel (housekeeping rewrites the set), so the set itself
// needs no kernel timeouts. With no bans left, all three sections go away.

const (
	banSet     = "owp_berth_ban"
	banSection = "owps_berth_ban"
	banRuleIn  = "owpb_in"
	banRuleFwd = "owpb_fwd"
)

var banMu sync.Mutex

func (a *App) expireBerthBans() (int64, error) {
	res, err := a.db.Exec(`DELETE FROM berth_bans WHERE expires_at IS NOT NULL AND expires_at > 0 AND expires_at < ?`, time.Now().Unix())
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

// syncBerthBans makes the firewall match the berth_bans table.
func (a *App) syncBerthBans() error {
	banMu.Lock()
	defer banMu.Unlock()
	_, _ = a.expireBerthBans()
	entries := []string{}
	for _, b := range a.listBans("") {
		entries = append(entries, b.CIDR)
	}
	fw, err := a.agent.UciConfig("firewall")
	if err != nil {
		return err
	}
	var changes []UciChange
	put := func(section, typ string, want map[string]any) {
		have := fw[section]
		switch {
		case want == nil && have != nil:
			changes = append(changes, UciChange{Op: "delete", Config: "firewall", Section: section})
		case want != nil && have == nil:
			changes = append(changes, UciChange{Op: "add", Config: "firewall", Type: typ, Name: section, Values: want})
		case want != nil && !sameJSON(optionsOf(have), want):
			changes = append(changes, UciChange{Op: "set", Config: "firewall", Section: section, Values: want})
		}
	}
	if len(entries) == 0 {
		put(banRuleIn, "rule", nil)
		put(banRuleFwd, "rule", nil)
		put(banSection, "ipset", nil)
		if len(changes) > 0 {
			if _, err := a.agent.Apply(changes...); err != nil {
				return err
			}
		}
		_ = a.agent.Do("POST", "/v1/ipset", map[string]any{"name": banSet, "remove": true}, nil)
		return nil
	}
	var r struct {
		Path string `json:"path"`
	}
	if err := a.agent.Do("POST", "/v1/ipset", map[string]any{"name": banSet, "entries": entries}, &r); err != nil {
		return err
	}
	put(banSection, "ipset", map[string]any{"name": banSet, "match": "src_net", "storage": "hash", "family": "ipv4", "maxelem": "65536", "loadfile": r.Path})
	put(banRuleIn, "rule", map[string]any{"name": "Wharf 外部封禁（到路由器）", "src": "wan", "proto": "all", "ipset": banSet, "target": "DROP"})
	put(banRuleFwd, "rule", map[string]any{"name": "Wharf 外部封禁（转发）", "src": "wan", "dest": "*", "proto": "all", "ipset": banSet, "target": "DROP"})
	if len(changes) > 0 {
		if _, err := a.agent.Apply(changes...); err != nil {
			return err
		}
	}
	return nil
}

// ---- the panel's own view (super admin) ----

// GET /api/bans
func (a *App) handleBans(w http.ResponseWriter, r *http.Request) {
	l := a.berth()
	writeJSON(w, 200, map[string]any{"items": a.listBans(""), "berth": l != nil && l.state() == "active" && l.has("bans"),
		"default_sync": a.setting("bans.default_sync_to_berth") == "1"})
}

// POST /api/bans {cidr, reason, days, sync}
func (a *App) handleBanAdd(w http.ResponseWriter, r *http.Request) {
	var req struct {
		CIDR   string `json:"cidr"`
		Reason string `json:"reason"`
		Days   int    `json:"days"` // 0 = until revoked
		Sync   bool   `json:"sync"`
	}
	if readJSON(r, &req) != nil {
		jsonErr(w, 400, "请求格式错误")
		return
	}
	cidr, err := a.checkBan(req.CIDR, a.clientIP(r))
	if err != nil {
		jsonErr(w, 400, err.Error())
		return
	}
	if req.Days < 0 || req.Days > 3650 {
		jsonErr(w, 400, "天数超出范围")
		return
	}
	var exp int64
	if req.Days > 0 {
		exp = time.Now().Add(time.Duration(req.Days) * 24 * time.Hour).Unix()
	}
	u := currentUser(r)
	var dup int64
	if a.db.QueryRow(`SELECT id FROM berth_bans WHERE cidr=?`, cidr).Scan(&dup) == nil {
		jsonErr(w, 409, cidr+" 已经在封禁列表里")
		return
	}
	res, err := a.db.Exec(`INSERT INTO berth_bans(cidr, reason, source, expires_at, created_at, origin, sync, remote_id, created_by) VALUES(?,?,?,?,?,'wharf',0,'',?)`,
		cidr, clean(req.Reason, 120), "wharf:"+u.DisplayName, nullInt(exp), time.Now().Unix(), u.DisplayName)
	if err != nil {
		jsonErr(w, 500, err.Error())
		return
	}
	id, _ := res.LastInsertId()
	if err := a.syncBerthBans(); err != nil {
		_, _ = a.db.Exec(`DELETE FROM berth_bans WHERE id=?`, id)
		jsonErr(w, 502, "防火墙没有更新："+err.Error())
		return
	}
	a.audit(actor{user: u, ip: a.clientIP(r)}, "ban.add", "ban", strconv.FormatInt(id, 10), fmt.Sprintf("封禁 %s（%s）", cidr, firstNonEmpty(req.Reason, "未填写原因")), nil, map[string]any{"cidr": cidr}, false)
	msg := ""
	if req.Sync {
		if err := a.pushBan(id); err != nil {
			msg = "已在 Wharf 生效，同步到 Berth 失败：" + err.Error()
		}
	}
	writeJSON(w, 200, map[string]any{"id": id, "warning": msg})
}

// pushBan sends a Wharf ban to Berth and remembers Berth's id for it.
func (a *App) pushBan(id int64) error {
	l := a.berth()
	if l == nil || l.state() != "active" || !l.has("bans") {
		return errors.New("Berth 对接不可用，或没有授予「封禁同步」")
	}
	bs := a.listBans(`WHERE id=? AND origin='wharf'`, id)
	if len(bs) == 0 {
		return errors.New("封禁不存在")
	}
	b := bs[0]
	body := map[string]any{"cidr": b.CIDR, "reason": b.Reason, "source": "wharf:" + a.setting("ui.name") + ":" + b.CreatedBy, "id": b.ID}
	if b.ExpiresAt > 0 {
		body["expires_at"] = time.Unix(b.ExpiresAt, 0).UTC().Format(time.RFC3339)
	}
	var out struct {
		ID any `json:"id"`
	}
	if err := a.berthCall(l, "POST", "/bans", body, &out); err != nil {
		return err
	}
	_, _ = a.db.Exec(`UPDATE berth_bans SET sync=1, remote_id=? WHERE id=?`, truncate(fmt.Sprint(firstNonNil(out.ID, b.ID)), 64), id)
	return nil
}

func firstNonNil(v ...any) any {
	for _, x := range v {
		if x != nil {
			return x
		}
	}
	return nil
}

// PUT /api/bans/{id}/sync {sync} — add a Wharf ban to Berth, or take it back.
func (a *App) handleBanSync(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Sync bool `json:"sync"`
	}
	_ = readJSON(r, &req)
	id := pathID(r)
	bs := a.listBans(`WHERE id=? AND origin='wharf'`, id)
	if len(bs) == 0 {
		jsonErr(w, 404, "只能同步 Wharf 自己的封禁")
		return
	}
	b := bs[0]
	if req.Sync == b.Sync {
		writeJSON(w, 200, map[string]bool{"ok": true})
		return
	}
	if req.Sync {
		if err := a.pushBan(id); err != nil {
			jsonErr(w, 502, err.Error())
			return
		}
	} else {
		if err := a.berthCall(a.berth(), "DELETE", "/bans/"+urlPart(b.RemoteID), nil, nil); err != nil {
			var he *berthHTTPError
			if !errors.As(err, &he) || he.Code != 404 {
				jsonErr(w, 502, err.Error())
				return
			}
		}
		_, _ = a.db.Exec(`UPDATE berth_bans SET sync=0, remote_id='' WHERE id=?`, id)
	}
	a.audit(actor{user: currentUser(r), ip: a.clientIP(r)}, "ban.sync", "ban", strconv.FormatInt(id, 10),
		map[bool]string{true: "封禁 " + b.CIDR + " 同步到 Berth", false: "封禁 " + b.CIDR + " 撤回 Berth 上的同步"}[req.Sync], nil, nil, false)
	writeJSON(w, 200, map[string]bool{"ok": true})
}

func urlPart(s string) string {
	return strings.NewReplacer("/", "%2F", "?", "%3F", "#", "%23").Replace(s)
}

// DELETE /api/bans/{id}
func (a *App) handleBanDelete(w http.ResponseWriter, r *http.Request) {
	id := pathID(r)
	bs := a.listBans(`WHERE id=?`, id)
	if len(bs) == 0 {
		jsonErr(w, 404, "封禁不存在")
		return
	}
	b := bs[0]
	_, _ = a.db.Exec(`DELETE FROM berth_bans WHERE id=?`, id)
	if err := a.syncBerthBans(); err != nil {
		jsonErr(w, 502, "防火墙没有更新："+err.Error())
		return
	}
	warning := ""
	switch {
	case b.Origin == "berth":
		// Berth unticks "synced to Wharf" for it
		a.berthNotify("ban.revoked", map[string]any{"id": b.RemoteID, "cidr": b.CIDR, "by": currentUser(r).DisplayName})
	case b.Sync:
		if err := a.berthCall(a.berth(), "DELETE", "/bans/"+urlPart(b.RemoteID), nil, nil); err != nil {
			warning = "Berth 上的同步没有撤回：" + err.Error()
		}
	}
	a.audit(actor{user: currentUser(r), ip: a.clientIP(r)}, "ban.delete", "ban", strconv.FormatInt(id, 10), "撤销封禁 "+b.CIDR, b, nil, false)
	writeJSON(w, 200, map[string]any{"ok": true, "warning": warning})
}
