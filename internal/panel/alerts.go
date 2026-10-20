package panel

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Alerts: a minute-by-minute check of things a person wants to be told about,
// delivered through Server 酱 or Telegram.

type AlertRules struct {
	NewDevice       bool     `json:"new_device"`
	WanDown         bool     `json:"wan_down"`
	WanDownMinutes  int      `json:"wan_down_minutes"`
	OfflineWatch    []string `json:"offline_watch"` // MACs to report when offline
	OfflineMinutes  int      `json:"offline_minutes"`
	TrafficSpike    bool     `json:"traffic_spike"`
	SpikeMBPerHour  int      `json:"spike_mb_per_hour"`
	PanelDenied     bool     `json:"panel_denied"`
	ApprovalPending bool     `json:"approval_pending"`
	QuietFrom       string   `json:"quiet_from"` // "23:00"; empty = no quiet hours
	QuietTo         string   `json:"quiet_to"`
}

var defaultRules = AlertRules{NewDevice: true, WanDown: true, WanDownMinutes: 2, OfflineMinutes: 5,
	TrafficSpike: false, SpikeMBPerHour: 2048, PanelDenied: true, ApprovalPending: true, OfflineWatch: []string{}}

type AlertChannel struct {
	ID      int64  `json:"id"`
	Name    string `json:"name"`
	URL     string `json:"url,omitempty"`
	Masked  string `json:"masked"`
	Enabled bool   `json:"enabled"`
}

func (a *App) alertRules() AlertRules {
	r := defaultRules
	_ = json.Unmarshal([]byte(a.setting("alerts.rules")), &r)
	if r.OfflineWatch == nil {
		r.OfflineWatch = []string{}
	}
	return r
}

func (a *App) alertChannels(withURL bool) []AlertChannel {
	var out []AlertChannel
	rows, err := a.db.Query(`SELECT id, name, url, enabled FROM alert_channels ORDER BY id`)
	if err != nil {
		return out
	}
	defer rows.Close()
	for rows.Next() {
		var c AlertChannel
		if rows.Scan(&c.ID, &c.Name, &c.URL, &c.Enabled) == nil {
			c.Masked = maskURL(c.URL)
			if !withURL {
				c.URL = ""
			}
			out = append(out, c)
		}
	}
	return out
}

// maskURL hides tokens: keeps scheme and host-ish part only.
func maskURL(u string) string {
	scheme, rest, ok := strings.Cut(u, "://")
	if !ok {
		return "••••"
	}
	host := rest
	if i := strings.IndexAny(rest, "/?@"); i >= 0 {
		host = rest[:i]
	}
	if strings.Contains(rest, "@") {
		host = rest[strings.LastIndex(rest, "@")+1:]
		if i := strings.IndexAny(host, "/?"); i >= 0 {
			host = host[:i]
		}
	}
	if len(host) > 6 && !strings.Contains(host, ".") && !strings.Contains(rest, "@") { // the "host" is the secret itself
		host = host[:3] + "••••"
	}
	return scheme + "://" + host + "/••••"
}

// ---- delivery ----

// sendTo delivers one message to one channel URL:
//
//	serverchan://<SendKey>          Server 酱
//	telegram://<bot-token>/<chat>   Telegram Bot API
func sendTo(raw, title, body string) error {
	scheme, rest, ok := strings.Cut(raw, "://")
	if !ok {
		return errors.New("地址格式不正确")
	}
	cl := &http.Client{Timeout: 15 * time.Second}
	switch scheme {
	case "serverchan":
		resp, err := cl.PostForm("https://sctapi.ftqq.com/"+url.PathEscape(rest)+".send", url.Values{"title": {title}, "desp": {body}})
		if err != nil {
			return err
		}
		defer resp.Body.Close()
		var r struct {
			Code    int    `json:"code"`
			Message string `json:"message"`
		}
		_ = json.NewDecoder(resp.Body).Decode(&r)
		if resp.StatusCode >= 300 || r.Code != 0 {
			return fmt.Errorf("Server 酱：%d %s", r.Code, r.Message)
		}
		return nil
	case "telegram":
		token, chat, ok := strings.Cut(rest, "/")
		if !ok || token == "" || chat == "" {
			return errors.New("Telegram 需要 Bot Token 和 Chat ID")
		}
		b, _ := json.Marshal(map[string]any{"chat_id": chat, "text": title + "\n" + body, "disable_web_page_preview": true})
		resp, err := cl.Post("https://api.telegram.org/bot"+token+"/sendMessage", "application/json", bytes.NewReader(b))
		if err != nil {
			return errors.New("Telegram 不可达") // never echo the token-bearing URL
		}
		defer resp.Body.Close()
		var r struct {
			OK          bool   `json:"ok"`
			Description string `json:"description"`
		}
		_ = json.NewDecoder(resp.Body).Decode(&r)
		if !r.OK {
			return fmt.Errorf("Telegram：%s", r.Description)
		}
		return nil
	}
	return fmt.Errorf("不支持的推送方式 %s", scheme)
}

func (a *App) inQuiet(r AlertRules, t time.Time) bool {
	if r.QuietFrom == "" || r.QuietTo == "" {
		return false
	}
	f, err1 := time.Parse("15:04", r.QuietFrom)
	e, err2 := time.Parse("15:04", r.QuietTo)
	if err1 != nil || err2 != nil {
		return false
	}
	m, fm, em := t.Hour()*60+t.Minute(), f.Hour()*60+f.Minute(), e.Hour()*60+e.Minute()
	if fm < em {
		return m >= fm && m < em
	}
	return m >= fm || m < em
}

// notify sends to every enabled channel and logs the result. urgent alerts ignore quiet hours.
func (a *App) notify(kind, title, body string, urgent bool) {
	r := a.alertRules()
	quiet := !urgent && a.inQuiet(r, time.Now())
	var results []string
	if !quiet {
		for _, c := range a.alertChannels(true) {
			if !c.Enabled {
				continue
			}
			if err := sendTo(c.URL, "【"+a.setting("ui.name")+"】"+title, body); err != nil {
				results = append(results, c.Name+"：失败 "+truncate(err.Error(), 120))
			} else {
				results = append(results, c.Name+"：已发送")
			}
		}
	} else {
		results = append(results, "免打扰时段，未发送")
	}
	_, _ = a.db.Exec(`INSERT INTO alert_log(ts, kind, title, body, result) VALUES(?,?,?,?,?)`,
		time.Now().Unix(), kind, title, body, strings.Join(results, "；"))
}

// ---- engine ----

type alertState struct {
	mu          sync.Mutex
	lastCheck   int64
	wanDown     bool
	offlineAt   map[string]int64 // mac -> first seen offline
	offlineSent map[string]bool
	spikeSent   map[string]int64 // mac -> hour alerted
}

func (a *App) alertEngine() {
	st := &alertState{lastCheck: time.Now().Unix(), offlineAt: map[string]int64{}, offlineSent: map[string]bool{}, spikeSent: map[string]int64{}}
	time.Sleep(90 * time.Second)
	for {
		func() {
			defer func() {
				if r := recover(); r != nil {
					log.Printf("alerts: %v", r)
				}
			}()
			if len(a.alertChannels(false)) > 0 {
				a.alertTick(st)
			}
		}()
		time.Sleep(time.Minute)
	}
}

func (a *App) deviceLabel(mac string) string {
	var name, ip string
	_ = a.db.QueryRow(`SELECT name, ip FROM devices_seen WHERE mac=?`, mac).Scan(&name, &ip)
	if m, ok := a.deviceMeta(mac); ok && m.Alias != "" {
		name = m.Alias
	}
	return strings.TrimSpace(firstNonEmpty(name, mac) + " " + ip)
}

func (a *App) alertTick(st *alertState) {
	r := a.alertRules()
	now := time.Now().Unix()
	since := st.lastCheck
	st.lastCheck = now

	if r.NewDevice {
		rows, err := a.db.Query(`SELECT mac, name, ip FROM devices_seen WHERE first_seen > ? AND first_seen > ?`, since-120, a.newSince())
		if err == nil {
			type nd struct{ mac, name, ip string }
			var list []nd
			for rows.Next() {
				var d nd
				if rows.Scan(&d.mac, &d.name, &d.ip) == nil {
					list = append(list, d)
				}
			}
			rows.Close()
			for _, d := range list {
				id := a.identifyDevice(d.mac, d.name, "")
				a.notify("new_device", "新设备接入："+firstNonEmpty(displayName("", "", d.name, id), d.mac),
					fmt.Sprintf("IP %s\nMAC %s\n类型 %s %s", d.ip, d.mac, id.Type, id.Vendor), false)
			}
		}
	}

	if r.WanDown {
		n := r.WanDownMinutes
		if n < 1 {
			n = 2
		}
		// every target unreachable for each of the last n minutes
		var down, total int
		_ = a.db.QueryRow(`SELECT COUNT(*), COALESCE(SUM(CASE WHEN all_lost THEN 1 ELSE 0 END),0) FROM (
			SELECT minute, MIN(CASE WHEN sent>0 AND lost=sent THEN 1 ELSE 0 END)=1 AS all_lost FROM netq_min
			WHERE minute >= ? GROUP BY minute)`, now-int64(n)*60-90).Scan(&total, &down)
		isDown := total >= n && down >= n
		if isDown && !st.wanDown {
			a.notify("wan_down", "家里断网了", fmt.Sprintf("所有检测目标已连续 %d 分钟无法访问（%s）", n, time.Now().Format("15:04")), true)
		}
		if !isDown && st.wanDown && total > 0 {
			a.notify("wan_up", "网络已恢复", "公网连接恢复正常（"+time.Now().Format("15:04")+"）", true)
		}
		st.wanDown = isDown
	}

	if len(r.OfflineWatch) > 0 {
		var devs []Device
		if a.agent.Do("GET", "/v1/devices", nil, &devs) == nil {
			online := map[string]bool{}
			for _, d := range devs {
				online[d.MAC] = d.Online
			}
			mins := int64(r.OfflineMinutes)
			if mins < 1 {
				mins = 5
			}
			for _, mac := range r.OfflineWatch {
				if online[mac] {
					if st.offlineSent[mac] {
						a.notify("device_online", "设备恢复在线："+a.deviceLabel(mac), "", false)
					}
					delete(st.offlineAt, mac)
					delete(st.offlineSent, mac)
					continue
				}
				if st.offlineAt[mac] == 0 {
					st.offlineAt[mac] = now
				}
				if !st.offlineSent[mac] && now-st.offlineAt[mac] >= mins*60 {
					st.offlineSent[mac] = true
					a.notify("device_offline", "设备离线："+a.deviceLabel(mac), fmt.Sprintf("已离线超过 %d 分钟", mins), true)
				}
			}
		}
	}

	if r.TrafficSpike && r.SpikeMBPerHour > 0 {
		hour := now - now%3600
		rows, err := a.db.Query(`SELECT mac, up+down FROM traffic_hour WHERE hour=? AND up+down > ?`, hour, int64(r.SpikeMBPerHour)<<20)
		if err == nil {
			type sp struct {
				mac string
				b   int64
			}
			var list []sp
			for rows.Next() {
				var s sp
				if rows.Scan(&s.mac, &s.b) == nil {
					list = append(list, s)
				}
			}
			rows.Close()
			for _, s := range list {
				if st.spikeSent[s.mac] == hour {
					continue
				}
				st.spikeSent[s.mac] = hour
				a.notify("traffic_spike", "流量异常："+a.deviceLabel(s.mac),
					fmt.Sprintf("本小时已使用 %.1f GB，超过阈值 %d MB", float64(s.b)/(1<<30), r.SpikeMBPerHour), false)
			}
		}
	}

	if r.PanelDenied {
		var n int
		var ip, reason string
		_ = a.db.QueryRow(`SELECT COUNT(*), COALESCE(MAX(ip),''), COALESCE(MAX(reason),'') FROM visitors WHERE blocked=1 AND ts > ?`, since).Scan(&n, &ip, &reason)
		if n > 0 {
			a.notify("panel_denied", "有人尝试访问面板被拒绝", fmt.Sprintf("%d 次，例如 %s（%s）", n, ip, reason), false)
		}
	}

	if r.ApprovalPending {
		rows, err := a.db.Query(`SELECT username, summary FROM approvals WHERE status='pending' AND ts > ?`, since)
		if err == nil {
			var msgs []string
			for rows.Next() {
				var u, s string
				if rows.Scan(&u, &s) == nil {
					msgs = append(msgs, u+"："+s)
				}
			}
			rows.Close()
			if len(msgs) > 0 {
				a.notify("approval", fmt.Sprintf("%d 条操作等待你审批", len(msgs)), strings.Join(msgs, "\n"), false)
			}
		}
	}
}

// ---- HTTP (super admin) ----

// GET /api/alerts
func (a *App) handleAlerts(w http.ResponseWriter, r *http.Request) {
	type logRow struct {
		TS     int64  `json:"ts"`
		Kind   string `json:"kind"`
		Title  string `json:"title"`
		Body   string `json:"body"`
		Result string `json:"result"`
	}
	var logs []logRow
	if rows, err := a.db.Query(`SELECT ts, kind, title, body, result FROM alert_log ORDER BY id DESC LIMIT 100`); err == nil {
		for rows.Next() {
			var l logRow
			if rows.Scan(&l.TS, &l.Kind, &l.Title, &l.Body, &l.Result) == nil {
				logs = append(logs, l)
			}
		}
		rows.Close()
	}
	writeJSON(w, 200, map[string]any{"rules": a.alertRules(), "channels": a.alertChannels(false), "log": logs})
}

// PUT /api/alerts/rules
func (a *App) handleAlertRules(w http.ResponseWriter, r *http.Request) {
	var req AlertRules
	if readJSON(r, &req) != nil {
		jsonErr(w, 400, "请求格式错误")
		return
	}
	for _, t := range []string{req.QuietFrom, req.QuietTo} {
		if t != "" {
			if _, err := time.Parse("15:04", t); err != nil {
				jsonErr(w, 400, "免打扰时间格式应为 HH:MM")
				return
			}
		}
	}
	if req.OfflineWatch == nil {
		req.OfflineWatch = []string{}
	}
	old := a.setting("alerts.rules")
	b, _ := json.Marshal(req)
	if err := a.setSetting("alerts.rules", string(b)); err != nil {
		jsonErr(w, 500, err.Error())
		return
	}
	a.audit(actor{user: currentUser(r), ip: a.clientIP(r)}, "setting.update", "setting", "alerts.rules", "修改告警规则", old, string(b), true)
	writeJSON(w, 200, req)
}

// POST /api/alerts/channels {type: serverchan|telegram, name, key | token+chat_id}
func (a *App) handleAlertChannelAdd(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Type, Name, Key, Token, ChatID string
	}
	if readJSON(r, &req) != nil {
		jsonErr(w, 400, "请求格式错误")
		return
	}
	var u string
	switch req.Type {
	case "serverchan":
		if !regexp.MustCompile(`^[A-Za-z0-9]{10,80}$`).MatchString(req.Key) {
			jsonErr(w, 400, "Server 酱 SendKey 格式不正确")
			return
		}
		u, req.Name = "serverchan://"+req.Key, firstNonEmpty(clean(req.Name, 40), "Server 酱")
	case "telegram":
		if !regexp.MustCompile(`^\d+:[A-Za-z0-9_-]{20,}$`).MatchString(req.Token) || !regexp.MustCompile(`^-?\d+$|^@[A-Za-z0-9_]{4,}$`).MatchString(req.ChatID) {
			jsonErr(w, 400, "Telegram Bot Token 或 Chat ID 格式不正确")
			return
		}
		u, req.Name = "telegram://"+req.Token+"/"+req.ChatID, firstNonEmpty(clean(req.Name, 40), "Telegram")
	default:
		jsonErr(w, 400, "只支持 Server 酱和 Telegram")
		return
	}
	if _, err := a.db.Exec(`INSERT INTO alert_channels(name, url, enabled) VALUES(?,?,1)`, req.Name, u); err != nil {
		jsonErr(w, 500, err.Error())
		return
	}
	a.audit(actor{user: currentUser(r), ip: a.clientIP(r)}, "alerts.channel.add", "setting", "alerts.channel", "添加告警渠道 "+req.Name+"（"+maskURL(u)+"）", nil, nil, false)
	writeJSON(w, 200, a.alertChannels(false))
}

func (a *App) handleAlertChannelDelete(w http.ResponseWriter, r *http.Request) {
	id := pathID(r)
	_, _ = a.db.Exec(`DELETE FROM alert_channels WHERE id=?`, id)
	a.audit(actor{user: currentUser(r), ip: a.clientIP(r)}, "alerts.channel.delete", "setting", "alerts.channel", "删除告警渠道 #"+strconv.FormatInt(id, 10), nil, nil, false)
	writeJSON(w, 200, a.alertChannels(false))
}

func (a *App) handleAlertChannelToggle(w http.ResponseWriter, r *http.Request) {
	_, _ = a.db.Exec(`UPDATE alert_channels SET enabled = 1 - enabled WHERE id=?`, pathID(r))
	writeJSON(w, 200, a.alertChannels(false))
}

// POST /api/alerts/test {id?} — sends a test message (to one channel or all).
func (a *App) handleAlertTest(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ID int64 `json:"id"`
	}
	_ = readJSON(r, &req)
	var out []map[string]string
	for _, c := range a.alertChannels(true) {
		if req.ID != 0 && c.ID != req.ID {
			continue
		}
		res := "已发送"
		if err := sendTo(c.URL, "【OWP】测试消息", "如果你收到了这条消息，说明告警渠道配置正确。"); err != nil {
			res = "失败：" + err.Error()
		}
		out = append(out, map[string]string{"name": c.Name, "result": res})
	}
	writeJSON(w, 200, out)
}
