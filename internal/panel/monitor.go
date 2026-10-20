package panel

import (
	"database/sql"
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"math"
	"net"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Scheduled monitors: ping (ICMP) or TCP connect probes run by the router every few
// minutes, kept for 30 days, with alerts when a target goes down or degrades. TCP probes
// open each connection from a fresh source port, so a load-balanced path with one broken
// member (the 2026-10 Telegram Singapore case) shows up as partial loss even when ping is clean.

type Monitor struct {
	ID        int64   `json:"id"`
	Name      string  `json:"name"`
	Target    string  `json:"target"`
	Mode      string  `json:"mode"` // icmp | tcp
	Port      int     `json:"port"`
	Count     int     `json:"count"`
	Interval  int     `json:"interval_min"`
	LossAlert int     `json:"loss_alert"` // %, 0 = only when unreachable
	RTTAlert  int     `json:"rtt_alert"`  // ms, 0 = off
	Enabled   bool    `json:"enabled"`
	State     string  `json:"state"` // ok | bad | unknown
	Since     int64   `json:"state_since"`
	Last      *MonRow `json:"last,omitempty"`
	Day       *MonAgg `json:"day,omitempty"`
}

type MonRow struct {
	TS     int64   `json:"ts"`
	Sent   int     `json:"sent"`
	Recv   int     `json:"recv"`
	Min    float64 `json:"min"`
	Avg    float64 `json:"avg"`
	Max    float64 `json:"max"`
	Jitter float64 `json:"jitter"`
	IP     string  `json:"ip,omitempty"`
	Error  string  `json:"error,omitempty"`
}

type MonAgg struct {
	T      int64   `json:"t"`
	Sent   int     `json:"sent"`
	Recv   int     `json:"recv"`
	Loss   float64 `json:"loss"` // %
	Avg    float64 `json:"avg"`
	Min    float64 `json:"min"`
	Max    float64 `json:"max"`
	Jitter float64 `json:"jitter"`
	Rounds int     `json:"rounds"`
}

var (
	monNameRe = regexp.MustCompile(`^[^\x00-\x1f]{1,40}$`)
	monMu     sync.Mutex
	monLast   = map[int64]int64{} // id -> last run (unix)
	monStreak = map[int64]int{}   // + good rounds / - bad rounds in a row
)

func (m *Monitor) validate() error {
	m.Name, m.Target = strings.TrimSpace(m.Name), strings.TrimSpace(m.Target)
	if !monNameRe.MatchString(m.Name) {
		return errors.New("名称为 1–40 个字")
	}
	if net.ParseIP(m.Target) == nil && !monHostRe.MatchString(m.Target) {
		return errors.New("目标应为域名或 IP")
	}
	switch m.Mode {
	case "icmp":
		m.Port = 0
	case "tcp":
		if m.Port < 1 || m.Port > 65535 {
			return errors.New("TCP 监控需要端口 1–65535")
		}
	default:
		return errors.New("类型应为 icmp 或 tcp")
	}
	m.Count = max(3, min(m.Count, 30))
	switch m.Interval {
	case 1, 2, 5, 10, 15, 30, 60:
	default:
		return errors.New("间隔应为 1 / 2 / 5 / 10 / 15 / 30 / 60 分钟")
	}
	m.LossAlert = max(0, min(m.LossAlert, 100))
	m.RTTAlert = max(0, min(m.RTTAlert, 10000))
	return nil
}

var monHostRe = regexp.MustCompile(`^[A-Za-z0-9]([A-Za-z0-9-]{0,62}[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]{0,62}[A-Za-z0-9])?)+\.?$`)

func (a *App) loadMonitors(onlyEnabled bool) []Monitor {
	q := `SELECT id, name, target, mode, port, count, interval_min, loss_alert, rtt_alert, enabled, state, state_since FROM monitors`
	if onlyEnabled {
		q += ` WHERE enabled=1`
	}
	rows, err := a.db.Query(q + ` ORDER BY id`)
	if err != nil {
		return nil
	}
	defer rows.Close()
	var out []Monitor
	for rows.Next() {
		var m Monitor
		if rows.Scan(&m.ID, &m.Name, &m.Target, &m.Mode, &m.Port, &m.Count, &m.Interval, &m.LossAlert, &m.RTTAlert, &m.Enabled, &m.State, &m.Since) == nil {
			out = append(out, m)
		}
	}
	return out
}

func (a *App) monitorLoop() {
	time.Sleep(40 * time.Second)
	for {
		now := time.Now().Unix()
		for _, m := range a.loadMonitors(true) {
			monMu.Lock()
			due := now-monLast[m.ID] >= int64(m.Interval)*60-5
			if due {
				monLast[m.ID] = now
			}
			monMu.Unlock()
			if due {
				go a.runMonitor(m)
			}
		}
		if time.Now().Minute() == 7 && time.Now().Second() < 30 {
			_, _ = a.db.Exec(`DELETE FROM monitor_results WHERE ts < ?`, now-30*86400)
		}
		time.Sleep(30 * time.Second)
	}
}

func (a *App) runMonitor(m Monitor) MonRow {
	defer func() {
		if r := recover(); r != nil {
			log.Printf("monitor %d: %v", m.ID, r)
		}
	}()
	row := MonRow{TS: time.Now().Unix(), Sent: m.Count}
	req := map[string]any{"tool": "probe", "target": m.Target, "mode": m.Mode, "port": m.Port, "count": m.Count}
	if err := a.agent.Do("POST", "/v1/diag", req, &row); err != nil {
		row.Error, row.Recv = agentMsg(err), 0
	}
	if row.Sent == 0 {
		row.Sent = m.Count
	}
	row.TS = time.Now().Unix()
	_, _ = a.db.Exec(`INSERT INTO monitor_results(monitor_id, ts, sent, recv, min, avg, max, jitter, ip, error) VALUES(?,?,?,?,?,?,?,?,?,?)`,
		m.ID, row.TS, row.Sent, row.Recv, row.Min, row.Avg, row.Max, row.Jitter, row.IP, row.Error)
	a.monitorAlert(m, row)
	return row
}

func monBad(m Monitor, r MonRow) (bool, string) {
	loss := 100 * float64(r.Sent-r.Recv) / math.Max(1, float64(r.Sent))
	switch {
	case r.Recv == 0:
		if r.Error != "" {
			return true, "完全不通（" + r.Error + "）"
		}
		return true, "完全不通"
	case m.LossAlert > 0 && loss >= float64(m.LossAlert):
		return true, fmt.Sprintf("丢包 %.0f%%（阈值 %d%%）", loss, m.LossAlert)
	case m.RTTAlert > 0 && r.Avg >= float64(m.RTTAlert):
		return true, fmt.Sprintf("延迟 %.0f ms（阈值 %d ms）", r.Avg, m.RTTAlert)
	}
	return false, fmt.Sprintf("丢包 %.0f%% · 延迟 %.0f ms", loss, r.Avg)
}

// monitorAlert flips state after two rounds in a row, so one lost burst doesn't page anyone.
func (a *App) monitorAlert(m Monitor, r MonRow) {
	bad, why := monBad(m, r)
	monMu.Lock()
	s := monStreak[m.ID]
	if bad {
		s = min(s, 0) - 1
	} else {
		s = max(s, 0) + 1
	}
	monStreak[m.ID] = s
	monMu.Unlock()
	target := m.Target
	if m.Mode == "tcp" {
		target += ":" + strconv.Itoa(m.Port)
	}
	switch {
	case s <= -2 && m.State != "bad":
		_, _ = a.db.Exec(`UPDATE monitors SET state='bad', state_since=? WHERE id=?`, r.TS, m.ID)
		a.notify("monitor", "监控异常："+m.Name, fmt.Sprintf("%s（%s）连续两次检测异常：%s", m.Name, target, why), false)
	case s >= 2 && m.State == "bad":
		_, _ = a.db.Exec(`UPDATE monitors SET state='ok', state_since=? WHERE id=?`, r.TS, m.ID)
		a.notify("monitor", "监控恢复："+m.Name, fmt.Sprintf("%s（%s）已恢复：%s，异常持续 %s", m.Name, target, why, awayText(r.TS-m.Since)), false)
	case m.State == "unknown" && (s >= 2 || s <= -2):
		st := "ok"
		if s < 0 {
			st = "bad"
		}
		_, _ = a.db.Exec(`UPDATE monitors SET state=?, state_since=? WHERE id=?`, st, r.TS, m.ID)
	}
}

func (a *App) monitorAgg(id, from, to, bucket int64) []MonAgg {
	rows, err := a.db.Query(`SELECT (ts-?)/? AS b, SUM(sent), SUM(recv), SUM(avg*recv), MIN(CASE WHEN recv>0 THEN min END), MAX(max), SUM(jitter*recv), COUNT(*)
		FROM monitor_results WHERE monitor_id=? AND ts>=? AND ts<? GROUP BY b ORDER BY b`, from, bucket, id, from, to)
	if err != nil {
		return nil
	}
	defer rows.Close()
	var out []MonAgg
	for rows.Next() {
		var b int64
		var g MonAgg
		var sumAvg, sumJit float64
		var mn sql.NullFloat64
		if rows.Scan(&b, &g.Sent, &g.Recv, &sumAvg, &mn, &g.Max, &sumJit, &g.Rounds) != nil {
			continue
		}
		g.T = from + b*bucket
		g.Min = mn.Float64
		if g.Recv > 0 {
			g.Avg, g.Jitter = round1(sumAvg/float64(g.Recv)), round1(sumJit/float64(g.Recv))
		}
		if g.Sent > 0 {
			g.Loss = round1(100 * float64(g.Sent-g.Recv) / float64(g.Sent))
		}
		out = append(out, g)
	}
	return out
}

// GET /api/monitors
func (a *App) handleMonitors(w http.ResponseWriter, r *http.Request) {
	list := a.loadMonitors(false)
	now := time.Now().Unix()
	for i := range list {
		m := &list[i]
		var row MonRow
		if a.db.QueryRow(`SELECT ts, sent, recv, min, avg, max, jitter, ip, error FROM monitor_results WHERE monitor_id=? ORDER BY ts DESC LIMIT 1`, m.ID).
			Scan(&row.TS, &row.Sent, &row.Recv, &row.Min, &row.Avg, &row.Max, &row.Jitter, &row.IP, &row.Error) == nil {
			m.Last = &row
		}
		if g := a.monitorAgg(m.ID, now-86400, now+1, 86401); len(g) > 0 {
			m.Day = &g[0]
		}
	}
	if list == nil {
		list = []Monitor{}
	}
	writeJSON(w, 200, list)
}

// GET /api/monitors/{id}/history?range=6h|24h|7d|30d
func (a *App) handleMonitorHistory(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
	secs := map[string]int64{"6h": 6 * 3600, "24h": 86400, "7d": 7 * 86400, "30d": 30 * 86400}[r.URL.Query().Get("range")]
	if secs == 0 {
		secs = 86400
	}
	now := time.Now().Unix()
	from := now - secs
	bucket := max(60, secs/288)
	writeJSON(w, 200, map[string]any{"from": from, "to": now, "bucket": bucket, "points": a.monitorAgg(id, from, now+1, bucket)})
}

// GET /api/monitors/{id}/export — raw rounds as CSV (for the ISP).
func (a *App) handleMonitorExport(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
	var name, target, mode string
	var port int
	if a.db.QueryRow(`SELECT name, target, mode, port FROM monitors WHERE id=?`, id).Scan(&name, &target, &mode, &port) != nil {
		jsonErr(w, 404, "监控不存在")
		return
	}
	rows, err := a.db.Query(`SELECT ts, ip, sent, recv, min, avg, max, jitter, error FROM monitor_results WHERE monitor_id=? ORDER BY ts`, id)
	if err != nil {
		jsonErr(w, 500, err.Error())
		return
	}
	defer rows.Close()
	w.Header().Set("Content-Type", "text/csv; charset=utf-8")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="monitor-%d-%s.csv"`, id, time.Now().Format("20060102")))
	_, _ = io.WriteString(w, "\uFEFF") // BOM so Excel reads UTF-8
	cw := csv.NewWriter(w)
	_ = cw.Write([]string{"time", "target", "probe", "resolved_ip", "sent", "received", "loss_percent", "min_ms", "avg_ms", "max_ms", "jitter_ms", "error"})
	probe := "ICMP ping"
	if mode == "tcp" {
		probe = "TCP connect :" + strconv.Itoa(port)
	}
	for rows.Next() {
		var row MonRow
		if rows.Scan(&row.TS, &row.IP, &row.Sent, &row.Recv, &row.Min, &row.Avg, &row.Max, &row.Jitter, &row.Error) != nil {
			continue
		}
		loss := 0.0
		if row.Sent > 0 {
			loss = 100 * float64(row.Sent-row.Recv) / float64(row.Sent)
		}
		f := func(v float64) string { return strconv.FormatFloat(v, 'f', 1, 64) }
		_ = cw.Write([]string{time.Unix(row.TS, 0).Format("2006-01-02 15:04:05 MST"), target, probe, row.IP, strconv.Itoa(row.Sent), strconv.Itoa(row.Recv),
			f(loss), f(row.Min), f(row.Avg), f(row.Max), f(row.Jitter), row.Error})
	}
	cw.Flush()
}

// POST /api/monitors — create or update ({id} present).
func (a *App) handleMonitorSave(w http.ResponseWriter, r *http.Request) {
	var m Monitor
	if err := json.NewDecoder(io.LimitReader(r.Body, 4096)).Decode(&m); err != nil {
		jsonErr(w, 400, "请求格式错误")
		return
	}
	if err := m.validate(); err != nil {
		jsonErr(w, 400, err.Error())
		return
	}
	ac := actor{user: currentUser(r), ip: a.clientIP(r)}
	if m.ID > 0 {
		res, err := a.db.Exec(`UPDATE monitors SET name=?, target=?, mode=?, port=?, count=?, interval_min=?, loss_alert=?, rtt_alert=?, enabled=? WHERE id=?`,
			m.Name, m.Target, m.Mode, m.Port, m.Count, m.Interval, m.LossAlert, m.RTTAlert, m.Enabled, m.ID)
		if n, _ := res.RowsAffected(); err != nil || n == 0 {
			jsonErr(w, 404, "监控不存在")
			return
		}
		a.audit(ac, "monitor.update", "monitor", strconv.FormatInt(m.ID, 10), "修改监控 "+m.Name+"（"+m.Target+"）", nil, m, false)
	} else {
		var n int
		_ = a.db.QueryRow(`SELECT COUNT(*) FROM monitors`).Scan(&n)
		if n >= 30 {
			jsonErr(w, 400, "最多 30 个监控")
			return
		}
		res, err := a.db.Exec(`INSERT INTO monitors(name, target, mode, port, count, interval_min, loss_alert, rtt_alert, enabled, state, state_since, created_by, created_at)
			VALUES(?,?,?,?,?,?,?,?,?,'unknown',?,?,?)`, m.Name, m.Target, m.Mode, m.Port, m.Count, m.Interval, m.LossAlert, m.RTTAlert, m.Enabled, time.Now().Unix(), ac.user.ID, time.Now().Unix())
		if err != nil {
			jsonErr(w, 500, err.Error())
			return
		}
		m.ID, _ = res.LastInsertId()
		a.audit(ac, "monitor.create", "monitor", strconv.FormatInt(m.ID, 10), "添加监控 "+m.Name+"（"+m.Target+"）", nil, m, false)
	}
	monMu.Lock()
	delete(monLast, m.ID) // run on the next tick
	delete(monStreak, m.ID)
	monMu.Unlock()
	writeJSON(w, 200, m)
}

func (a *App) handleMonitorDelete(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
	var name string
	if a.db.QueryRow(`SELECT name FROM monitors WHERE id=?`, id).Scan(&name) != nil {
		jsonErr(w, 404, "监控不存在")
		return
	}
	_, _ = a.db.Exec(`DELETE FROM monitor_results WHERE monitor_id=?`, id)
	_, _ = a.db.Exec(`DELETE FROM monitors WHERE id=?`, id)
	a.audit(actor{user: currentUser(r), ip: a.clientIP(r)}, "monitor.delete", "monitor", strconv.FormatInt(id, 10), "删除监控 "+name, nil, nil, false)
	writeJSON(w, 200, map[string]bool{"ok": true})
}

// POST /api/monitors/{id}/run — one round now.
func (a *App) handleMonitorRun(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
	for _, m := range a.loadMonitors(false) {
		if m.ID == id {
			monMu.Lock()
			monLast[m.ID] = time.Now().Unix()
			monMu.Unlock()
			writeJSON(w, 200, a.runMonitor(m))
			return
		}
	}
	jsonErr(w, 404, "监控不存在")
}

// AddMonitorCLI: owp-panel monitor-add <name> <target> <icmp|tcp> <port> <count> <interval_min> <loss_alert%>
// (root on the router; skips duplicates by name).
func AddMonitorCLI(a *App, args []string) error {
	if len(args) != 7 {
		return errors.New("usage: monitor-add <name> <target> <icmp|tcp> <port> <count> <interval_min> <loss_alert%>")
	}
	n := func(s string) int { v, _ := strconv.Atoi(s); return v }
	m := Monitor{Name: args[0], Target: args[1], Mode: args[2], Port: n(args[3]), Count: n(args[4]), Interval: n(args[5]), LossAlert: n(args[6]), Enabled: true}
	if err := m.validate(); err != nil {
		return err
	}
	var exists int
	_ = a.db.QueryRow(`SELECT COUNT(*) FROM monitors WHERE name=?`, m.Name).Scan(&exists)
	if exists > 0 {
		return nil
	}
	now := time.Now().Unix()
	_, err := a.db.Exec(`INSERT INTO monitors(name, target, mode, port, count, interval_min, loss_alert, rtt_alert, enabled, state, state_since, created_by, created_at)
		VALUES(?,?,?,?,?,?,?,0,1,'unknown',?,0,?)`, m.Name, m.Target, m.Mode, m.Port, m.Count, m.Interval, m.LossAlert, now, now)
	return err
}

// ExportMonitorsCLI: owp-panel monitor-export — every round of every monitor as CSV on stdout
// (root on the router; read-only).
func ExportMonitorsCLI(a *App, w io.Writer) error {
	rows, err := a.db.Query(`SELECT m.name, m.target, m.mode, m.port, r.ts, r.ip, r.sent, r.recv, r.min, r.avg, r.max, r.jitter, r.error
		FROM monitor_results r JOIN monitors m ON m.id = r.monitor_id ORDER BY m.id, r.ts`)
	if err != nil {
		return err
	}
	defer rows.Close()
	cw := csv.NewWriter(w)
	_ = cw.Write([]string{"monitor", "target", "probe", "time", "unix", "resolved_ip", "sent", "received", "loss_percent", "min_ms", "avg_ms", "max_ms", "jitter_ms", "error"})
	for rows.Next() {
		var name, target, mode, ip, e string
		var port, sent, recv int
		var ts int64
		var mn, avg, mx, jit float64
		if rows.Scan(&name, &target, &mode, &port, &ts, &ip, &sent, &recv, &mn, &avg, &mx, &jit, &e) != nil {
			continue
		}
		probe := "ICMP ping"
		if mode == "tcp" {
			probe = "TCP connect :" + strconv.Itoa(port)
		}
		loss := 0.0
		if sent > 0 {
			loss = 100 * float64(sent-recv) / float64(sent)
		}
		f := func(v float64) string { return strconv.FormatFloat(v, 'f', 1, 64) }
		_ = cw.Write([]string{name, target, probe, time.Unix(ts, 0).Format("2006-01-02 15:04:05 MST"), strconv.FormatInt(ts, 10), ip,
			strconv.Itoa(sent), strconv.Itoa(recv), f(loss), f(mn), f(avg), f(mx), f(jit), e})
	}
	cw.Flush()
	return cw.Error()
}
