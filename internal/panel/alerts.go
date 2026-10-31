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
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Alerts: a minute-by-minute check of things a person wants to be told about,
// delivered through Server 酱 or Telegram.

type AlertRules struct {
	NewDevice      bool `json:"new_device"`
	WanDown        bool `json:"wan_down"`
	WanDownMinutes int  `json:"wan_down_minutes"`
	// device left / came back (from the presence tracker, see presence.go)
	DeviceLeft    bool     `json:"device_left"`
	DeviceBack    bool     `json:"device_back"`
	PresenceAll   bool     `json:"presence_all"`   // every device, not only PresenceWatch
	PresenceWatch []string `json:"presence_watch"` // MACs
	AwayMinutes   int      `json:"away_minutes"`   // = setting presence.away_minutes (shown here)
	// ≤ 0.18: one watch list for "offline" and "back online"; moved to the fields above
	OfflineWatch   []string `json:"offline_watch,omitempty"`
	OfflineMinutes int      `json:"offline_minutes,omitempty"`
	TrafficSpike   bool     `json:"traffic_spike"`
	SpikeMBPerHour int      `json:"spike_mb_per_hour"` // the threshold, per SpikeWindow despite the name
	// SpikeWindow: "hour" (this clock hour) or "day" (since midnight)
	SpikeWindow  string         `json:"spike_window"`
	SpikeExclude []string       `json:"spike_exclude"` // MACs never reported (backups, NAS …)
	SpikeCustom  map[string]int `json:"spike_custom"`  // MAC -> own threshold in MB
	// new devices with a randomised ("private") MAC: one that matches a known device's
	// hostname is that device with a new address and is never reported; this skips the rest too
	NewDeviceSkipRandom bool   `json:"new_device_skip_random"`
	WanLine             bool   `json:"wan_line"`    // one of several WAN lines down / back
	DDNSFail            bool   `json:"ddns_fail"`   // DDNS update failed
	Monitor             bool   `json:"monitor"`     // scheduled monitors down / recovered
	ProxyUsers          bool   `json:"proxy_users"` // proxy users: quota, expiry, IP limit (and early warnings)
	ProxyCert           bool   `json:"proxy_cert"`  // proxy certificates not renewing
	PanelDenied         bool   `json:"panel_denied"`
	ApprovalPending     bool   `json:"approval_pending"`
	QuietFrom           string `json:"quiet_from"` // "23:00"; empty = no quiet hours
	QuietTo             string `json:"quiet_to"`
}

var defaultRules = AlertRules{NewDevice: true, WanDown: true, WanDownMinutes: 2, DeviceLeft: true, DeviceBack: true,
	TrafficSpike: false, SpikeMBPerHour: 2048, SpikeWindow: "hour", PanelDenied: true, ApprovalPending: true,
	WanLine: true, DDNSFail: true, Monitor: true, ProxyUsers: true, ProxyCert: true}

type AlertChannel struct {
	ID      int64  `json:"id"`
	Name    string `json:"name"`
	URL     string `json:"url,omitempty"`
	Masked  string `json:"masked"`
	Enabled bool   `json:"enabled"`
}

func (a *App) alertRules() AlertRules {
	r := defaultRules
	raw := a.setting("alerts.rules")
	_ = json.Unmarshal([]byte(raw), &r)
	if !strings.Contains(raw, `"presence_watch"`) && len(r.OfflineWatch) > 0 { // saved by ≤ 0.18
		r.PresenceWatch = r.OfflineWatch
	}
	r.OfflineWatch, r.OfflineMinutes = nil, 0
	if r.PresenceWatch == nil {
		r.PresenceWatch = []string{}
	}
	if r.SpikeExclude == nil {
		r.SpikeExclude = []string{}
	}
	if r.SpikeCustom == nil {
		r.SpikeCustom = map[string]int{}
	}
	if r.SpikeWindow != "day" {
		r.SpikeWindow = "hour"
	}
	r.AwayMinutes = a.settingInt("presence.away_minutes")
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

var sendAlert = sendTo // replaced in tests

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
		resp, err := cl.Post(tgAPI+"/bot"+token+"/sendMessage", "application/json", bytes.NewReader(b))
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
	if !slices.ContainsFunc(a.alertChannels(false), func(c AlertChannel) bool { return c.Enabled }) {
		return // nowhere to send: no log entry either
	}
	r := a.alertRules()
	quiet := !urgent && a.inQuiet(r, time.Now())
	var results []string
	if !quiet {
		for _, c := range a.alertChannels(true) {
			if !c.Enabled {
				continue
			}
			if err := sendAlert(c.URL, "【"+a.setting("ui.name")+"】"+title, body); err != nil {
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
	mu        sync.Mutex
	lastCheck int64
	wanDown   bool
	spikeSent map[string]int64 // mac -> window alerted
	lineDown  map[string]int64 // WAN interface -> down since (0 = up)
	lineSent  map[string]bool
	lineSeen  bool
}

func (a *App) alertEngine() {
	st := &alertState{lastCheck: time.Now().Unix(), spikeSent: map[string]int64{}, lineDown: map[string]int64{}, lineSent: map[string]bool{}}
	time.Sleep(90 * time.Second)
	for {
		func() {
			defer func() {
				if r := recover(); r != nil {
					log.Printf("alerts: %v", r)
				}
			}()
			a.alertTick(st) // also without channels: it records the network events
		}()
		time.Sleep(time.Minute)
	}
}

// presenceAlerts reports devices that left or came back in one presence round (the
// tracker's own events, so alerts and the dashboard always agree). Several devices at
// once become one message per direction.
func (a *App) presenceAlerts(evs []presenceEv) {
	if len(a.alertChannels(false)) == 0 {
		return
	}
	r := a.alertRules()
	type item struct{ name, detail string }
	var left, back []item
	for _, e := range evs {
		if !r.PresenceAll && !slices.Contains(r.PresenceWatch, e.mac) {
			continue
		}
		name := a.deviceLabel(e.mac)
		if e.ip != "" && !strings.Contains(name, e.ip) {
			name += " " + e.ip
		}
		switch {
		case e.kind == "left" && r.DeviceLeft:
			left = append(left, item{name, "最后在线 " + time.Unix(e.ts, 0).Format("15:04")})
		case e.kind == "back" && r.DeviceBack:
			it := item{name, ""}
			if e.away > 0 {
				it.detail = "离开了 " + awayText(e.away)
			}
			back = append(back, it)
		}
	}
	send := func(kind, verb string, list []item, note string) {
		switch len(list) {
		case 0:
		case 1:
			a.notify(kind, "设备"+verb+"："+list[0].name, strings.TrimPrefix(list[0].detail+note, "\n"), false)
		default:
			lines := make([]string, len(list))
			for i, it := range list {
				lines[i] = it.name
				if it.detail != "" {
					lines[i] += "（" + it.detail + "）"
				}
			}
			a.notify(kind, fmt.Sprintf("%d 台设备%s", len(list), verb), strings.Join(lines, "\n")+note, false)
		}
	}
	send("device_left", "离开", left, fmt.Sprintf("\n超过 %d 分钟没有在网络里出现", max(r.AwayMinutes, 3)))
	send("device_back", "回来", back, "")
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
				note := ""
				if id.Random {
					if a.knownByName(d.mac, d.name) || r.NewDeviceSkipRandom {
						continue // a known phone / laptop that picked a new private address
					}
					note = "\n随机（私有）MAC：可能是手机或电脑开启了「私有地址」"
				}
				a.notify("new_device", "新设备接入："+firstNonEmpty(displayName("", "", d.name, id), d.mac),
					fmt.Sprintf("IP %s\nMAC %s\n类型 %s %s%s", d.ip, d.mac, id.Type, id.Vendor, note), false)
			}
		}
	}

	{
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
			a.netEvent(now, "wan_down", "家里断网了", fmt.Sprintf("所有检测目标连续 %d 分钟无法访问", n))
			if r.WanDown {
				a.notify("wan_down", "家里断网了", fmt.Sprintf("所有检测目标已连续 %d 分钟无法访问（%s）", n, time.Now().Format("15:04")), true)
			}
		}
		if !isDown && st.wanDown && total > 0 {
			a.netEvent(now, "wan_up", "网络已恢复", "公网连接恢复正常")
			if r.WanDown {
				a.notify("wan_up", "网络已恢复", "公网连接恢复正常（"+time.Now().Format("15:04")+"）", true)
			}
		}
		st.wanDown = isDown
	}
	a.lineTick(st, r, now)

	if r.TrafficSpike && r.SpikeMBPerHour > 0 {
		a.spikeTick(st, r, now)
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

var dailySent sync.Map // key -> day number

// notifyDaily sends a recurring problem at most once a day.
func (a *App) notifyDaily(key, kind, title, body string) {
	day := time.Now().Unix() / 86400
	if v, ok := dailySent.Load(key); ok && v.(int64) == day {
		return
	}
	dailySent.Store(key, day)
	a.notify(kind, title, body, false)
}

// knownByName: another device already seen with this hostname (a phone that switched to
// a new private MAC keeps its name).
func (a *App) knownByName(mac, name string) bool {
	if strings.TrimSpace(name) == "" || name == "*" {
		return false
	}
	var n int
	_ = a.db.QueryRow(`SELECT COUNT(*) FROM devices_seen WHERE name=? AND mac<>?`, name, mac).Scan(&n)
	return n > 0
}

// spikeTick: devices over their threshold in this hour or day (each reported once per window).
func (a *App) spikeTick(st *alertState, r AlertRules, now int64) {
	start, per := now-now%3600, "本小时"
	if r.SpikeWindow == "day" {
		t := time.Unix(now, 0)
		start, per = time.Date(t.Year(), t.Month(), t.Day(), 0, 0, 0, 0, time.Local).Unix(), "今天"
	}
	rows, err := a.db.Query(`SELECT mac, SUM(up+down) FROM traffic_hour WHERE hour >= ? GROUP BY mac`, start)
	if err != nil {
		return
	}
	type sp struct {
		mac string
		b   int64
	}
	var list []sp
	for rows.Next() {
		var x sp
		if rows.Scan(&x.mac, &x.b) == nil {
			list = append(list, x)
		}
	}
	rows.Close()
	for _, x := range list {
		limit := r.SpikeMBPerHour
		if c, ok := r.SpikeCustom[x.mac]; ok && c > 0 {
			limit = c
		}
		if slices.Contains(r.SpikeExclude, x.mac) || x.b <= int64(limit)<<20 || st.spikeSent[x.mac] == start {
			continue
		}
		st.spikeSent[x.mac] = start
		a.notify("traffic_spike", "流量异常："+a.deviceLabel(x.mac),
			fmt.Sprintf("%s已使用 %s，超过阈值 %d MB", per, humanBytes(x.b), limit), false)
	}
}

// lineTick: with several WAN lines, one going down (or back) is worth knowing even while
// the others keep the home online.
func (a *App) lineTick(st *alertState, r AlertRules, now int64) {
	var wans []wanInfo
	for _, w := range a.wans() { // wan6 & co. are the same line as their IPv4 sibling
		if !strings.HasPrefix(w.Proto, "dhcpv6") && !slices.Contains([]string{"6in4", "6to4", "6rd", "dslite"}, w.Proto) {
			wans = append(wans, w)
		}
	}
	if len(wans) == 0 {
		return
	}
	n := int64(max(r.WanDownMinutes, 1))
	for _, w := range wans {
		if w.Up {
			if st.lineSent[w.Interface] && st.lineDown[w.Interface] > 0 {
				out := now - st.lineDown[w.Interface]
				a.netEvent(now, "line_up", "线路恢复："+w.Interface, "中断了 "+awayText(out))
				if r.WanLine && len(wans) > 1 {
					a.notify("line_up", "线路恢复："+w.Interface, fmt.Sprintf("%s 已恢复，中断了 %s", w.Interface, awayText(out)), true)
				}
			}
			delete(st.lineDown, w.Interface)
			delete(st.lineSent, w.Interface)
			continue
		}
		if !st.lineSeen { // already down when the panel started (or unused): no event either way
			st.lineSent[w.Interface] = true
			continue
		}
		if st.lineDown[w.Interface] == 0 {
			st.lineDown[w.Interface] = now
		}
		if !st.lineSent[w.Interface] && now-st.lineDown[w.Interface] >= n*60 {
			st.lineSent[w.Interface] = true
			a.netEvent(st.lineDown[w.Interface], "line_down", "线路掉线："+w.Interface, firstNonEmpty(w.Device, w.Proto))
			if r.WanLine && len(wans) > 1 {
				a.notify("line_down", "线路掉线："+w.Interface, fmt.Sprintf("%s（%s）已断开超过 %d 分钟；其他线路仍在工作", w.Interface, firstNonEmpty(w.Device, w.Proto), n), true)
			}
		}
	}
	st.lineSeen = true
}

// netEvent records an internet / line event for the dashboard.
func (a *App) netEvent(ts int64, kind, title, detail string) {
	_, _ = a.db.Exec(`INSERT INTO net_events(ts, kind, title, detail) VALUES(?,?,?,?)`, ts, kind, title, detail)
	_, _ = a.db.Exec(`DELETE FROM net_events WHERE ts < ?`, ts-90*86400)
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
	if req.PresenceWatch == nil {
		req.PresenceWatch = []string{}
	}
	req.OfflineWatch, req.OfflineMinutes = nil, 0
	if req.SpikeWindow != "day" {
		req.SpikeWindow = "hour"
	}
	for mac, mb := range req.SpikeCustom {
		if mb <= 0 {
			delete(req.SpikeCustom, mac)
		}
	}
	if req.AwayMinutes != 0 && req.AwayMinutes != a.settingInt("presence.away_minutes") {
		v := strconv.Itoa(req.AwayMinutes)
		if err := validSetting("presence.away_minutes", v); err != nil {
			jsonErr(w, 400, err.Error())
			return
		}
		_ = a.setSetting("presence.away_minutes", v)
	}
	req.AwayMinutes = 0 // lives in its own setting
	old := a.setting("alerts.rules")
	b, _ := json.Marshal(req)
	if err := a.setSetting("alerts.rules", string(b)); err != nil {
		jsonErr(w, 500, err.Error())
		return
	}
	a.audit(actor{user: currentUser(r), ip: a.clientIP(r)}, "setting.update", "setting", "alerts.rules", "修改告警规则", old, string(b), true)
	writeJSON(w, 200, a.alertRules())
}

// ---- Telegram helpers ----

var tgAPI = "https://api.telegram.org" // replaced in tests

var tgTokenRe = regexp.MustCompile(`\d{5,}:[A-Za-z0-9_-]{30,}`)

// tgToken pulls the token out of whatever was pasted: the token itself, "bot<token>",
// or a whole https://api.telegram.org/bot<token>/getUpdates address.
func tgToken(s string) string {
	return tgTokenRe.FindString(strings.TrimSpace(s))
}

type tgChat struct {
	ID    int64  `json:"id"`
	Type  string `json:"type"` // private | group | supergroup | channel
	Title string `json:"title"`
	Name  string `json:"name"`
}

// tgCall runs one Bot API method; the token never appears in an error.
func tgCall(token, method string, out any) error {
	cl := &http.Client{Timeout: 12 * time.Second}
	resp, err := cl.Get(tgAPI + "/bot" + token + "/" + method)
	if err != nil {
		return errors.New("连不上 Telegram（api.telegram.org），请检查路由器能否访问 Telegram")
	}
	defer resp.Body.Close()
	var r struct {
		OK          bool            `json:"ok"`
		Description string          `json:"description"`
		Result      json.RawMessage `json:"result"`
	}
	if json.NewDecoder(resp.Body).Decode(&r) != nil {
		return errors.New("Telegram 返回了无法识别的内容")
	}
	if !r.OK {
		if resp.StatusCode == 401 || resp.StatusCode == 404 {
			return errors.New("Bot Token 无效：请从 @BotFather 重新复制（形如 123456789:AAE…）")
		}
		if resp.StatusCode == 409 {
			return errors.New("这个机器人设置了 Webhook，无法自动获取 Chat ID，请手动填写")
		}
		return fmt.Errorf("Telegram：%s", r.Description)
	}
	return json.Unmarshal(r.Result, out)
}

type tgMsg struct {
	Chat struct {
		ID        int64  `json:"id"`
		Type      string `json:"type"`
		Title     string `json:"title"`
		FirstName string `json:"first_name"`
		LastName  string `json:"last_name"`
		Username  string `json:"username"`
	} `json:"chat"`
}

// tgChats: the bot's name and the chats that recently wrote to it (getUpdates keeps
// messages for 24 hours).
func tgChats(token string) (string, []tgChat, error) {
	var me struct {
		Username string `json:"username"`
	}
	if err := tgCall(token, "getMe", &me); err != nil {
		return "", nil, err
	}
	type update struct {
		Message      *tgMsg `json:"message"`
		ChannelPost  *tgMsg `json:"channel_post"`
		MyChatMember *tgMsg `json:"my_chat_member"`
	}
	var ups []update
	if err := tgCall(token, "getUpdates", &ups); err != nil {
		return me.Username, nil, err
	}
	var chats []tgChat
	for i := len(ups) - 1; i >= 0; i-- { // newest first
		for _, m := range []*tgMsg{ups[i].Message, ups[i].ChannelPost, ups[i].MyChatMember} {
			if m == nil || slices.ContainsFunc(chats, func(c tgChat) bool { return c.ID == m.Chat.ID }) {
				continue
			}
			c := m.Chat
			name := strings.TrimSpace(c.FirstName + " " + c.LastName)
			if c.Username != "" {
				name = strings.TrimSpace(name + " @" + c.Username)
			}
			chats = append(chats, tgChat{ID: c.ID, Type: c.Type, Title: c.Title, Name: name})
		}
	}
	return me.Username, chats, nil
}

// POST /api/alerts/telegram/chats {token} — finds the Chat ID so nobody has to.
func (a *App) handleTelegramChats(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Token string `json:"token"`
	}
	_ = readJSON(r, &req)
	token := tgToken(req.Token)
	if token == "" {
		jsonErr(w, 400, "Bot Token 格式不对：应形如 123456789:AAE…（从 @BotFather 复制）")
		return
	}
	bot, chats, err := tgChats(token)
	if err != nil {
		jsonErr(w, 400, err.Error())
		return
	}
	if chats == nil {
		chats = []tgChat{}
	}
	writeJSON(w, 200, map[string]any{"bot": bot, "chats": chats})
}

// POST /api/alerts/channels {type: serverchan|telegram, name, key | token+chat_id}
// An empty chat_id is looked up from the bot's recent messages.
func (a *App) handleAlertChannelAdd(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Type   string `json:"type"`
		Name   string `json:"name"`
		Key    string `json:"key"`
		Token  string `json:"token"`
		ChatID string `json:"chat_id"`
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
		req.Token = tgToken(req.Token)
		if req.Token == "" {
			jsonErr(w, 400, "Bot Token 格式不对：应形如 123456789:AAE…（从 @BotFather 复制）")
			return
		}
		req.ChatID = strings.TrimSpace(req.ChatID)
		bot, chats, err := tgChats(req.Token) // also checks the token
		if err != nil {
			jsonErr(w, 400, err.Error())
			return
		}
		if req.ChatID == "" {
			switch len(chats) {
			case 0:
				jsonErr(w, 400, "还找不到你的 Chat ID：请先在 Telegram 里打开 @"+bot+"，点「开始」或随便发一条消息，再点添加")
				return
			case 1:
				req.ChatID = strconv.FormatInt(chats[0].ID, 10)
			default:
				jsonErr(w, 400, "这个机器人收到过多个聊天的消息，请点「自动获取」选择要推送到哪一个")
				return
			}
		}
		if !regexp.MustCompile(`^-?\d+$|^@[A-Za-z0-9_]{4,}$`).MatchString(req.ChatID) {
			jsonErr(w, 400, "Chat ID 应为数字（群组以 - 开头）或 @频道名")
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
