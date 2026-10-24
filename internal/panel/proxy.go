package panel

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Proxy extension (panel side): nodes and proxy users in SQLite, compiled into an Xray
// and a front configuration that the agent installs; WAN redirects (owpx_*) keep the
// firewall in step, so the usual port checks and the forwards list see every node.

const (
	frontSection = "owpx_front"
	proxyKind    = "proxy"
)

func nodeSection(id int64) string { return "owpx_n" + strconv.FormatInt(id, 10) }

// proxySettings are the extension-wide options (super admin).
type proxySettings struct {
	Address    string    `json:"address"`     // host clients use (domain or IP); "" = WAN IPv4
	Site       frontSite `json:"site"`        // camouflage website
	ACMEEmail  string    `json:"acme_email"`  //
	BlockBT    bool      `json:"block_bt"`    //
	BlockPorts []int     `json:"block_ports"` //
	BlockHosts []string  `json:"block_hosts"` //
	AccessDays int       `json:"access_days"` // keep access records this long
	// Share443: what to do when WAN 443 already belongs to a port forward (a website):
	//   ""           not shared — nodes need their own ports
	//   "cloudflare" the forward stays untouched for Cloudflare's addresses (a proxied site's
	//                only visitors); every other source goes to the front, which passes
	//                what is not for a node on to the same server
	//   "takeover"   the front takes the port from every source (the forward is paused)
	Share443      string   `json:"share_443"`
	ShareSkip     []string `json:"share_skip"`     // more sources left to the forward ("cloudflare" mode)
	Takeover443   bool     `json:"takeover_443"`   // (0.18 previews) = Share443 "takeover"
	TakeoverProxy bool     `json:"takeover_proxy"` // send PROXY protocol v2 to that server (it must expect it)
}

func (s proxySettings) share() string {
	if s.Share443 == "" && s.Takeover443 {
		return "takeover"
	}
	return s.Share443
}

func (a *App) proxySettings() proxySettings {
	s := proxySettings{Site: frontSite{Mode: "builtin"}, BlockBT: true, BlockPorts: []int{25}, AccessDays: 30}
	if v := a.setting("proxy.config"); v != "" {
		_ = json.Unmarshal([]byte(v), &s)
	}
	if s.AccessDays <= 0 {
		s.AccessDays = 30
	}
	return s
}

func (s *proxySettings) normalize() error {
	s.Address = strings.TrimSpace(s.Address)
	if s.Address != "" && net.ParseIP(s.Address) == nil && !hostnameOK(s.Address) {
		return errors.New("对外地址应为域名或 IP")
	}
	switch s.Site.Mode {
	case "builtin", "html":
	case "proxy":
		if !strings.HasPrefix(s.Site.Proxy, "http://") && !strings.HasPrefix(s.Site.Proxy, "https://") {
			return errors.New("反向代理地址应以 http:// 或 https:// 开头")
		}
	default:
		s.Site.Mode = "builtin"
	}
	s.Site.Title = clean(s.Site.Title, 60)
	s.Site.Domain = strings.ToLower(strings.TrimSpace(s.Site.Domain))
	if s.Site.Domain != "" && !hostnameOK(s.Site.Domain) {
		return errors.New("网站域名格式不对")
	}
	s.ACMEEmail = strings.TrimSpace(s.ACMEEmail)
	var hosts []string
	for _, h := range s.BlockHosts {
		if h = strings.ToLower(strings.TrimSpace(h)); h != "" {
			if !hostnameOK(h) {
				return fmt.Errorf("屏蔽域名 %q 格式不对", h)
			}
			hosts = append(hosts, h)
		}
	}
	s.BlockHosts = hosts
	for _, p := range s.BlockPorts {
		if p < 1 || p > 65535 {
			return fmt.Errorf("屏蔽端口 %d 不对", p)
		}
	}
	if s.AccessDays > 365 {
		s.AccessDays = 365
	}
	switch s.Share443 {
	case "", "cloudflare", "takeover":
	default:
		return errors.New("共用 443 的方式不对")
	}
	s.Takeover443 = false
	var skip []string
	for _, c := range s.ShareSkip {
		if c = strings.TrimSpace(c); c == "" {
			continue
		}
		if !strings.Contains(c, "/") {
			c += "/32"
		}
		if p, err := netip.ParsePrefix(c); err != nil || !p.Addr().Is4() {
			return fmt.Errorf("来源 %q 不是 IPv4 地址或网段", c)
		}
		skip = append(skip, c)
	}
	s.ShareSkip = skip
	return nil
}

// ---- storage ----

func scanNode(row interface{ Scan(...any) error }) (*ProxyNode, error) {
	var n ProxyNode
	var params string
	if err := row.Scan(&n.ID, &n.OwnerID, &n.Name, &n.Enabled, &n.Protocol, &n.Transport, &n.Security, &n.Entry, &n.Port, &n.Wan,
		&n.Domain, &params, &n.Note, &n.Created, &n.Updated); err != nil {
		return nil, err
	}
	_ = json.Unmarshal([]byte(params), &n.Params)
	return &n, nil
}

const nodeCols = `id, owner_id, name, enabled, protocol, transport, security, entry, port, wan, domain, params, note, created, updated`
const puserCols = `id, owner_id, name, secret, sub_token, nodes, limit_bytes, reset_day, expire_at, ip_limit, allow_lan, enabled, stopped,
	used_up, used_down, period_at, note, created`

func (a *App) proxyNodes() ([]*ProxyNode, error) {
	rows, err := a.db.Query(`SELECT ` + nodeCols + ` FROM proxy_nodes ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []*ProxyNode{}
	for rows.Next() {
		n, err := scanNode(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, n)
	}
	return out, rows.Err()
}

func scanPUser(row interface{ Scan(...any) error }) (*ProxyUser, error) {
	var u ProxyUser
	var nodes string
	if err := row.Scan(&u.ID, &u.OwnerID, &u.Name, &u.Secret, &u.SubToken, &nodes, &u.LimitBytes, &u.ResetDay, &u.ExpireAt, &u.IPLimit,
		&u.AllowLAN, &u.Enabled, &u.Stopped, &u.UsedUp, &u.UsedDown, &u.PeriodAt, &u.Note, &u.Created); err != nil {
		return nil, err
	}
	_ = json.Unmarshal([]byte(nodes), &u.Nodes)
	if u.Nodes == nil {
		u.Nodes = []int64{}
	}
	return &u, nil
}

func (a *App) proxyUsers() ([]*ProxyUser, error) {
	rows, err := a.db.Query(`SELECT ` + puserCols + ` FROM proxy_users ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []*ProxyUser{}
	for rows.Next() {
		u, err := scanPUser(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, u)
	}
	return out, rows.Err()
}

// execer is *sql.DB or *sql.Tx.
type execer interface {
	Exec(query string, args ...any) (sql.Result, error)
}

// Changes are written first and undone if the router refuses them: applying talks to the
// agent for seconds, too long to hold SQLite's write lock in a transaction.

func saveNode(tx execer, n *ProxyNode) error {
	params := mustJSON(n.Params)
	if n.ID == 0 {
		res, err := tx.Exec(`INSERT INTO proxy_nodes(owner_id, name, enabled, protocol, transport, security, entry, port, wan, domain, params, note, created, updated)
			VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)`, n.OwnerID, n.Name, n.Enabled, n.Protocol, n.Transport, n.Security, n.Entry, n.Port, n.Wan, n.Domain, params, n.Note, n.Created, n.Updated)
		if err != nil {
			return err
		}
		n.ID, _ = res.LastInsertId()
		return nil
	}
	_, err := tx.Exec(`UPDATE proxy_nodes SET name=?, enabled=?, protocol=?, transport=?, security=?, entry=?, port=?, wan=?, domain=?, params=?, note=?, updated=? WHERE id=?`,
		n.Name, n.Enabled, n.Protocol, n.Transport, n.Security, n.Entry, n.Port, n.Wan, n.Domain, params, n.Note, n.Updated, n.ID)
	return err
}

func savePUser(tx execer, u *ProxyUser) error {
	nodes := mustJSON(u.Nodes)
	if u.ID == 0 {
		res, err := tx.Exec(`INSERT INTO proxy_users(owner_id, name, secret, sub_token, nodes, limit_bytes, reset_day, expire_at, ip_limit, allow_lan, enabled, stopped,
			used_up, used_down, period_at, note, created) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
			u.OwnerID, u.Name, u.Secret, u.SubToken, nodes, u.LimitBytes, u.ResetDay, u.ExpireAt, u.IPLimit, u.AllowLAN, u.Enabled, u.Stopped,
			u.UsedUp, u.UsedDown, u.PeriodAt, u.Note, u.Created)
		if err != nil {
			return err
		}
		u.ID, _ = res.LastInsertId()
		return nil
	}
	_, err := tx.Exec(`UPDATE proxy_users SET name=?, secret=?, sub_token=?, nodes=?, limit_bytes=?, reset_day=?, expire_at=?, ip_limit=?, allow_lan=?, enabled=?,
		stopped=?, used_up=?, used_down=?, period_at=?, note=? WHERE id=?`,
		u.Name, u.Secret, u.SubToken, nodes, u.LimitBytes, u.ResetDay, u.ExpireAt, u.IPLimit, u.AllowLAN, u.Enabled, u.Stopped,
		u.UsedUp, u.UsedDown, u.PeriodAt, u.Note, u.ID)
	return err
}

// ---- applying ----

var proxyApplyMu sync.Mutex

// proxyHost is the default address in share links.
func (a *App) proxyHost(ps proxySettings) string {
	if ps.Address != "" {
		return ps.Address
	}
	for _, w := range a.wans() {
		if w.Up && w.IPv4 != "" {
			return w.IPv4
		}
	}
	return ""
}

// proxyApply compiles nodes/users into the agent configuration and the WAN redirects.
// Nothing is stored by the caller unless this succeeds.
func (a *App) proxyApply(nodes []*ProxyNode, users []*ProxyUser, ps proxySettings) error {
	now := time.Now().Unix()
	fw, err := a.agent.UciConfig("firewall")
	if err != nil {
		return err
	}
	owners443 := wan443Forwards(fw, a.adopted443())
	mode := ps.share()
	var fb *frontFallback
	if mode != "" && len(owners443) > 0 {
		r := fw[owners443[0]]
		fb = &frontFallback{Backend: net.JoinHostPort(optStr(r, "dest_ip"), firstNonEmpty(optStr(r, "dest_port"), "443")), Proxy: mode == "takeover" && ps.TakeoverProxy}
		// the front only keeps names it knows; give it the panel's address so the
		// subscriptions stay reachable instead of going to the other server
		if ps.Site.Domain == "" && hostnameOK(ps.Address) && !nodeName(nodes, ps.Address) && anySNI(nodes) {
			ps.Site.Domain = ps.Address
		}
	}
	front, frontOn := buildFront(nodes, ps.Site, ps.ACMEEmail, fb)
	if frontOn && len(owners443) > 0 && mode == "" {
		return fmt.Errorf("WAN 443 已转发给「%s」。要共用 443，请在「扩展设置」里选择共用方式，或者让节点用独立端口", displayRule(fw[owners443[0]], nil))
	}
	var intercept *ProxyInterceptReq
	if frontOn && fb != nil && mode == "cloudflare" {
		intercept = &ProxyInterceptReq{Port: 443, To: proxyFrontPort, Skip: append(a.cloudflareCIDRs(), ps.ShareSkip...)}
		for _, w := range a.wans() {
			if w.Device != "" && !slices.Contains(intercept.Devs, w.Device) {
				intercept.Devs = append(intercept.Devs, w.Device)
			}
		}
	}
	xray, err := buildXray(nodes, users, proxyPolicy{BlockBT: ps.BlockBT, BlockPorts: ps.BlockPorts, BlockHosts: ps.BlockHosts}, frontOn, now)
	if err != nil {
		return err
	}
	host := a.proxyHost(ps)
	site := map[string]string{}
	if ps.Site.Mode == "html" {
		site["index.html"] = a.setting("proxy.site_html")
	}
	pins := a.proxyPins()
	needPins := false
	if frontOn {
		for _, u := range users {
			site["subs/"+u.SubToken] = subscription(nodes, u, host, pins, now)
			site["subs/"+u.SubToken+".info"] = subInfo(u)
		}
		for _, n := range nodes {
			needPins = needPins || (n.Enabled && n.Params.Cert == "self" && pins[n.Domain] == "")
		}
	}
	var certs []map[string]string
	seen := map[string]bool{}
	for _, n := range nodes {
		if n.Enabled && n.Security == "tls" && !seen[n.Domain] {
			seen[n.Domain] = true
			certs = append(certs, map[string]string{"domain": n.Domain})
		}
	}
	proxyApplyMu.Lock()
	defer proxyApplyMu.Unlock()
	if err := a.agent.Do("POST", "/v1/proxy/apply", map[string]any{"xray": xray, "front": front, "site": site, "certs": certs, "intercept": intercept}, nil); err != nil {
		var ae *AgentError
		if errors.As(err, &ae) {
			return errors.New(ae.Msg)
		}
		return err
	}
	if needPins { // new self-signed certificates exist now: put their fingerprints into the subscriptions
		pins = a.proxyPins()
		for _, u := range users {
			site["subs/"+u.SubToken] = subscription(nodes, u, host, pins, now)
		}
		_ = a.agent.Do("POST", "/v1/proxy/apply", map[string]any{"xray": xray, "front": front, "site": site, "certs": certs, "intercept": intercept}, nil)
	}
	// with the source split the agent redirects 443 itself; the forward stays as it is
	return a.syncProxyFirewall(nodes, frontOn && intercept == nil, frontOn && fb != nil && mode == "takeover")
}

type ProxyInterceptReq struct {
	Port int      `json:"port"`
	To   int      `json:"to"`
	Skip []string `json:"skip"`
	Devs []string `json:"devs"`
}

func anySNI(nodes []*ProxyNode) bool {
	for _, n := range nodes {
		if n.Enabled && n.Entry == "sni" {
			return true
		}
	}
	return false
}

func nodeName(nodes []*ProxyNode, name string) bool {
	for _, n := range nodes {
		if n.Enabled && slices.Contains(n.sniNames(), name) {
			return true
		}
	}
	return false
}

// Cloudflare's published IPv4 ranges (cloudflare.com/ips-v4), refreshed daily.
var cloudflareV4 = []string{"173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22", "141.101.64.0/18", "108.162.192.0/18",
	"190.93.240.0/20", "188.114.96.0/20", "197.234.240.0/22", "198.41.128.0/17", "162.158.0.0/15", "104.16.0.0/13", "104.24.0.0/14",
	"172.64.0.0/13", "131.0.72.0/22"}

func (a *App) cloudflareCIDRs() []string {
	var list []string
	if json.Unmarshal([]byte(a.setting("proxy.cf_ips")), &list) == nil && len(list) >= 8 {
		return list
	}
	return append([]string{}, cloudflareV4...)
}

// refreshCloudflare fetches the current list; it returns true when it changed.
func (a *App) refreshCloudflare() bool {
	resp, err := (&http.Client{Timeout: 20 * time.Second}).Get("https://www.cloudflare.com/ips-v4")
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	var list []string
	for _, l := range strings.Fields(string(b)) {
		if p, err := netip.ParsePrefix(l); err == nil && p.Addr().Is4() {
			list = append(list, p.String())
		}
	}
	if resp.StatusCode != 200 || len(list) < 8 {
		return false
	}
	slices.Sort(list)
	old := a.cloudflareCIDRs()
	slices.Sort(old)
	if slices.Equal(old, list) {
		return false
	}
	_ = a.setSetting("proxy.cf_ips", mustJSON(list))
	return true
}

// wan443Forwards lists the WAN port forwards (not ours) covering TCP 443 that are
// enabled, or that the front disabled when it took the port over.
func wan443Forwards(fw map[string]Section, adopted []string) []string {
	var out []string
	for id, s := range fw {
		if strings.HasPrefix(id, "owpx_") || !isWanRedirect(s) {
			continue
		}
		if optStr(s, "enabled") == "0" && !slices.Contains(adopted, id) && optStr(s, "wharf_adopted") != "1" {
			continue
		}
		if lo, hi, ok := portRange(optStr(s, "src_dport")); ok && lo <= 443 && 443 <= hi && protoOverlap("tcp", optStr(s, "proto")) && optStr(s, "dest_ip") != "" {
			out = append(out, id)
		}
	}
	slices.Sort(out)
	return out
}

func (a *App) adopted443() []string {
	var ids []string
	_ = json.Unmarshal([]byte(a.setting("proxy.adopted")), &ids)
	return ids
}

// proxyPins maps certificate domains to their SHA-256 (for pinning in links).
func (a *App) proxyPins() map[string]string {
	var certs []struct {
		Domain string `json:"domain"`
		SHA256 string `json:"sha256"`
	}
	_ = a.agent.Do("GET", "/v1/proxy/certs", nil, &certs)
	out := map[string]string{}
	for _, c := range certs {
		out[c.Domain] = c.SHA256
	}
	return out
}

// syncProxyFirewall makes the owpx_* redirects match the enabled nodes (frontOn: WAN 443
// to the front through the firewall). With takeover,
// the port forward that owned WAN 443 is switched off while the front holds the port and
// switched back on when it lets go.
func (a *App) syncProxyFirewall(nodes []*ProxyNode, frontOn, takeover bool) error {
	fw, err := a.agent.UciConfig("firewall")
	if err != nil {
		return err
	}
	adopted := a.adopted443()
	devOf := map[string]string{}
	for _, w := range a.wans() {
		devOf[w.Interface] = w.Device
	}
	want := map[string]map[string]any{}
	owners := map[string]int64{}
	if frontOn {
		want[frontSection] = map[string]any{"name": "Wharf 代理 · 443 分流", "src": "wan", "proto": "tcp", "src_dport": "443",
			"dest_port": strconv.Itoa(proxyFrontPort), "target": "DNAT"}
	}
	for _, n := range nodes {
		if !n.Enabled || n.Entry != "port" {
			continue
		}
		r := map[string]any{"name": "Wharf 代理 · " + n.Name, "src": "wan", "proto": n.fwProto(), "src_dport": strconv.Itoa(n.Port),
			"dest_port": strconv.Itoa(n.inner()), "target": "DNAT"}
		if dev := devOf[n.Wan]; n.Wan != "" && dev != "" {
			r["extra"] = "-i " + dev
		}
		want[nodeSection(n.ID)] = r
		owners[nodeSection(n.ID)] = n.OwnerID
	}
	var changes []UciChange
	var nowAdopted []string
	for _, id := range wan443Forwards(fw, adopted) {
		r := fw[id]
		if takeover {
			nowAdopted = append(nowAdopted, id)
			// wharf_adopted (ignored by fw3) lets the package's postrm switch it back on
			if optStr(r, "enabled") != "0" || optStr(r, "wharf_adopted") != "1" {
				changes = append(changes, UciChange{Op: "set", Config: "firewall", Section: id, Values: map[string]any{"enabled": "0", "wharf_adopted": "1"}})
			}
		} else if slices.Contains(adopted, id) || optStr(r, "wharf_adopted") == "1" {
			changes = append(changes, UciChange{Op: "delete", Config: "firewall", Section: id, Options: []string{"enabled", "wharf_adopted"}})
		}
	}
	for id, s := range fw {
		if !strings.HasPrefix(id, "owpx_") {
			continue
		}
		w, ok := want[id]
		if !ok {
			changes = append(changes, UciChange{Op: "delete", Config: "firewall", Section: id})
			continue
		}
		cur := optionsOf(s)
		same := len(cur) == len(w)
		for k, v := range w {
			same = same && fmt.Sprint(cur[k]) == fmt.Sprint(v)
		}
		if !same {
			changes = append(changes, UciChange{Op: "delete", Config: "firewall", Section: id},
				UciChange{Op: "add", Config: "firewall", Type: "redirect", Name: id, Values: w})
		}
	}
	for id, w := range want {
		if _, ok := fw[id]; !ok {
			changes = append(changes, UciChange{Op: "add", Config: "firewall", Type: "redirect", Name: id, Values: w})
		}
	}
	if len(changes) > 0 {
		if _, err := a.agent.Apply(changes...); err != nil {
			return fmt.Errorf("防火墙规则更新失败：%w", err)
		}
	}
	if nowAdopted == nil {
		nowAdopted = []string{}
	}
	_ = a.setSetting("proxy.adopted", mustJSON(nowAdopted))
	_, _ = a.db.Exec(`DELETE FROM owned WHERE config='firewall' AND kind=?`, proxyKind)
	for id, uid := range owners {
		_, _ = a.db.Exec(`INSERT OR REPLACE INTO owned(config, section, kind, user_id, created_at) VALUES('firewall',?,?,?,?)`, id, proxyKind, uid, time.Now().Unix())
	}
	return nil
}

// reapplyProxy rebuilds from the database (after automatic changes such as quotas).
func (a *App) reapplyProxy() error {
	nodes, err := a.proxyNodes()
	if err != nil {
		return err
	}
	users, err := a.proxyUsers()
	if err != nil {
		return err
	}
	return a.proxyApply(nodes, users, a.proxySettings())
}

// ---- status / listing ----

type proxyExt struct {
	Installed  bool            `json:"installed"`
	Version    string          `json:"version"`
	Previous   string          `json:"previous"`
	OnDisk     []string        `json:"on_disk"`
	Asset      string          `json:"asset"`
	Dir        string          `json:"dir"`
	FreeMB     int64           `json:"free_mb"`
	Running    map[string]bool `json:"running"`
	Configured bool            `json:"configured"`
	SystemXray string          `json:"system_xray"`
	Job        struct {
		Running bool     `json:"running"`
		Action  string   `json:"action"`
		Tag     string   `json:"tag"`
		Log     []string `json:"log"`
		Error   string   `json:"error"`
		Ended   int64    `json:"ended"`
	} `json:"job"`
}

func (a *App) proxyExt() (*proxyExt, error) {
	var st proxyExt
	if err := a.agent.Do("GET", "/v1/proxy", nil, &st); err != nil {
		return nil, err
	}
	return &st, nil
}

func visibleNodes(u *User, all []*ProxyNode) []*ProxyNode {
	out := []*ProxyNode{}
	for _, n := range all {
		if u.Role == RoleSuper || n.OwnerID == u.ID {
			out = append(out, n)
		}
	}
	return out
}

func visibleUsers(u *User, all []*ProxyUser) []*ProxyUser {
	out := []*ProxyUser{}
	for _, p := range all {
		if u.Role == RoleSuper || p.OwnerID == u.ID {
			out = append(out, p)
		}
	}
	return out
}

// GET /api/proxy
func (a *App) handleProxy(w http.ResponseWriter, r *http.Request) {
	u := currentUser(r)
	ext, err := a.proxyExt()
	if err != nil {
		jsonErr(w, 502, err.Error())
		return
	}
	nodes, err := a.proxyNodes()
	if err != nil {
		jsonErr(w, 500, err.Error())
		return
	}
	users, err := a.proxyUsers()
	if err != nil {
		jsonErr(w, 500, err.Error())
		return
	}
	names := a.userNames()
	nodes, users = visibleNodes(u, nodes), visibleUsers(u, users)
	for _, n := range nodes {
		n.OwnerName = names[n.OwnerID]
		if u.Role != RoleSuper && n.OwnerID != u.ID {
			n.Params.PrivateKey = ""
		}
	}
	for _, p := range users {
		p.OwnerName = names[p.OwnerID]
	}
	ps := a.proxySettings()
	out := map[string]any{
		"ext": ext, "nodes": nodes, "users": users, "host": a.proxyHost(ps),
		"quota": map[string]any{"nodes": u.Quota("max_proxy_nodes"), "users": u.Quota("max_proxy_users")},
		"front": map[string]any{"port": proxyFrontPort, "site_domain": ps.Site.Domain},
	}
	if u.Role == RoleSuper {
		if fw, err := a.agent.UciConfig("firewall"); err == nil {
			if ids := wan443Forwards(fw, a.adopted443()); len(ids) > 0 {
				r := fw[ids[0]]
				out["port443"] = map[string]any{"forward": displayRule(r, nil), "target": net.JoinHostPort(optStr(r, "dest_ip"), firstNonEmpty(optStr(r, "dest_port"), "443")),
					"adopted": slices.Contains(a.adopted443(), ids[0])}
			}
		}
		out["settings"] = ps
		out["site_html"] = a.setting("proxy.site_html")
		var certs []map[string]any
		_ = a.agent.Do("GET", "/v1/proxy/certs", nil, &certs)
		out["certs"] = certs
	}
	writeJSON(w, 200, out)
}

// ---- Xray versions (GitHub) ----

type xrayRelease struct {
	Tag        string `json:"tag"`
	Prerelease bool   `json:"prerelease"`
	Published  string `json:"published"`
	URL        string `json:"url"`
	Supported  bool   `json:"supported"` // new enough for every option the panel generates
}

var xrayRel struct {
	sync.Mutex
	at   time.Time
	list []xrayRelease
}

// Oldest core the generated configs are known to work with (Hysteria inbound,
// REALITY "target", xhttp, statsonlineiplist).
const minXray = "v26.1.23"

func versionLess(a, b string) bool {
	pa, pb := strings.Split(strings.TrimPrefix(a, "v"), "."), strings.Split(strings.TrimPrefix(b, "v"), ".")
	for i := 0; i < 3; i++ {
		var x, y int
		if i < len(pa) {
			x, _ = strconv.Atoi(pa[i])
		}
		if i < len(pb) {
			y, _ = strconv.Atoi(pb[i])
		}
		if x != y {
			return x < y
		}
	}
	return false
}

func (a *App) xrayReleases(force bool) ([]xrayRelease, error) {
	xrayRel.Lock()
	defer xrayRel.Unlock()
	if !force && time.Since(xrayRel.at) < time.Hour && xrayRel.list != nil {
		return xrayRel.list, nil
	}
	req, _ := http.NewRequest("GET", "https://api.github.com/repos/XTLS/Xray-core/releases?per_page=30", nil)
	req.Header.Set("Accept", "application/vnd.github+json")
	resp, err := (&http.Client{Timeout: 20 * time.Second}).Do(req)
	if err != nil {
		return xrayRel.list, errors.New("无法访问 GitHub：" + err.Error())
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return xrayRel.list, fmt.Errorf("GitHub 返回 %s", resp.Status)
	}
	var raw []struct {
		Tag        string `json:"tag_name"`
		Prerelease bool   `json:"prerelease"`
		Draft      bool   `json:"draft"`
		Published  string `json:"published_at"`
		URL        string `json:"html_url"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&raw); err != nil {
		return xrayRel.list, err
	}
	var list []xrayRelease
	for _, r := range raw {
		if r.Draft || !strings.HasPrefix(r.Tag, "v") {
			continue
		}
		list = append(list, xrayRelease{Tag: r.Tag, Prerelease: r.Prerelease, Published: r.Published, URL: r.URL, Supported: !versionLess(r.Tag, minXray)})
	}
	xrayRel.list, xrayRel.at = list, time.Now()
	return list, nil
}

// GET /api/proxy/versions
func (a *App) handleProxyVersions(w http.ResponseWriter, r *http.Request) {
	list, err := a.xrayReleases(r.URL.Query().Get("refresh") == "1")
	if err != nil && list == nil {
		jsonErr(w, 502, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"releases": list, "min": minXray})
}

// POST /api/proxy/ext  {action: install|uninstall, tag}
func (a *App) handleProxyExt(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Action string `json:"action"`
		Tag    string `json:"tag"`
	}
	if err := readJSON(r, &req); err != nil {
		jsonErr(w, 400, "请求格式错误")
		return
	}
	u := currentUser(r)
	ac := actor{user: u, ip: a.clientIP(r)}
	before, _ := a.proxyExt()
	switch req.Action {
	case "install":
		if versionLess(req.Tag, minXray) {
			jsonErr(w, 400, "这个版本太旧，面板生成的配置需要 "+minXray+" 或更新")
			return
		}
		if err := a.agent.Do("POST", "/v1/proxy/install", map[string]string{"tag": req.Tag}, nil); err != nil {
			jsonErr(w, 400, agentMsg(err))
			return
		}
		verb := "安装"
		if before != nil && before.Installed {
			verb = "切换"
		}
		a.audit(ac, "proxy.ext", "proxy", "xray", fmt.Sprintf("%s代理扩展内核 Xray %s", verb, req.Tag), before, nil, false)
	case "uninstall":
		// close the WAN ports first, then remove the core; nodes and users stay in the
		// database so a reinstall picks up where it left off
		if err := a.syncProxyFirewall(nil, false, false); err != nil {
			jsonErr(w, 502, err.Error())
			return
		}
		if err := a.agent.Do("POST", "/v1/proxy/uninstall", nil, nil); err != nil {
			jsonErr(w, 400, agentMsg(err))
			return
		}
		a.audit(ac, "proxy.ext", "proxy", "xray", "卸载代理扩展（节点和用户保留在面板中）", before, nil, false)
	default:
		jsonErr(w, 400, "未知操作")
		return
	}
	st, _ := a.proxyExt()
	writeJSON(w, 200, st)
}

// POST /api/proxy/activate — push the configuration after an install finished
func (a *App) handleProxyActivate(w http.ResponseWriter, r *http.Request) {
	if err := a.reapplyProxy(); err != nil {
		jsonErr(w, 400, err.Error())
		return
	}
	writeJSON(w, 200, map[string]bool{"ok": true})
}

// ---- actions ----

func (a *App) nodeIssues(u *User, n *ProxyNode, nodes []*ProxyNode) error {
	for _, o := range nodes {
		if o.ID == n.ID || !o.Enabled || !n.Enabled {
			continue
		}
		for _, s := range n.sniNames() {
			if slices.Contains(o.sniNames(), s) {
				return fmt.Errorf("SNI %s 已被节点「%s」使用", s, nodeLabel(u, o))
			}
		}
		if n.Entry == "port" && o.Entry == "port" && n.Port == o.Port && wanOverlap(n.Wan, o.Wan) && protoOverlap(n.fwProto(), o.fwProto()) {
			return fmt.Errorf("端口 %d 已被节点「%s」使用", n.Port, nodeLabel(u, o))
		}
	}
	if n.Entry == "port" && n.Enabled {
		st, err := a.loadFwState()
		if err != nil {
			return err
		}
		issues := a.forwardIssues(u, st, a.wans(), a.listeners(), nodeSection(n.ID), n.Wan, n.Port, n.fwProto(), "")
		for _, is := range issues {
			if is.Level == "error" {
				return errors.New(is.Msg)
			}
		}
	}
	if n.Entry == "sni" && n.Enabled && a.proxySettings().share() == "" {
		st, err := a.loadFwState()
		if err != nil {
			return err
		}
		for id, s := range st.fw {
			if id == frontSection || !isWanRedirect(s) || optStr(s, "enabled") == "0" {
				continue
			}
			if lo, hi, ok := portRange(optStr(s, "src_dport")); ok && lo <= 443 && 443 <= hi && protoOverlap("tcp", optStr(s, "proto")) {
				return fmt.Errorf("WAN 443 已转发给「%s」。可以在「扩展设置」里选择共用 443 的方式（网站照常访问，节点按域名分流），或者让这个节点用独立端口", displayRule(s, st.owp[id]))
			}
		}
	}
	return nil
}

func nodeLabel(u *User, n *ProxyNode) string {
	if u.Role == RoleSuper || n.OwnerID == u.ID {
		return n.Name
	}
	return "其他管理员的节点"
}

func (a *App) requireExt() error {
	st, err := a.proxyExt()
	if err != nil {
		return err
	}
	if !st.Installed {
		return errors.New("代理扩展还没有安装")
	}
	return nil
}

func prepareProxyNode(a *App, u *User, raw json.RawMessage) (string, error) {
	var n ProxyNode
	if err := json.Unmarshal(raw, &n); err != nil {
		return "", err
	}
	if err := a.requireExt(); err != nil {
		return "", err
	}
	nodes, err := a.proxyNodes()
	if err != nil {
		return "", err
	}
	if n.ID != 0 {
		var cur *ProxyNode
		for _, o := range nodes {
			if o.ID == n.ID {
				cur = o
			}
		}
		if cur == nil || (u.Role != RoleSuper && cur.OwnerID != u.ID) {
			return "", errors.New("节点不存在")
		}
		if n.Params.PrivateKey == "" && n.Security == "reality" && cur.Security == "reality" { // keep keys unless replaced
			n.Params.PrivateKey, n.Params.PublicKey = cur.Params.PrivateKey, cur.Params.PublicKey
		}
		n.OwnerID = cur.OwnerID
	} else {
		n.OwnerID = u.ID
		if q := u.Quota("max_proxy_nodes"); q >= 0 {
			cnt := 0
			for _, o := range nodes {
				if o.OwnerID == u.ID {
					cnt++
				}
			}
			if cnt >= q {
				return "", fmt.Errorf("已达到节点数量上限（%d）", q)
			}
		}
	}
	if err := n.normalize(); err != nil {
		return "", err
	}
	if err := a.nodeIssues(u, &n, nodes); err != nil {
		return "", err
	}
	verb := "新增"
	if n.ID != 0 {
		verb = "修改"
	}
	return fmt.Sprintf("%s代理节点「%s」（%s）", verb, n.Name, nodeDesc(&n)), nil
}

func nodeDesc(n *ProxyNode) string {
	parts := []string{strings.ToUpper(n.Protocol)}
	if n.Transport != "raw" && n.Transport != "hysteria" {
		parts = append(parts, strings.ToUpper(n.Transport))
	}
	if n.Security != "none" {
		parts = append(parts, strings.ToUpper(n.Security))
	}
	entry := fmt.Sprintf("WAN %d", n.Port)
	if n.Entry == "sni" {
		entry = "443 分流 · " + strings.Join(n.sniNames(), ",")
	}
	return strings.Join(parts, " + ") + " · " + entry
}

func runProxyNode(a *App, ac actor, raw json.RawMessage) (any, error) {
	var n ProxyNode
	_ = json.Unmarshal(raw, &n)
	nodes, err := a.proxyNodes()
	if err != nil {
		return nil, err
	}
	users, err := a.proxyUsers()
	if err != nil {
		return nil, err
	}
	var before *ProxyNode
	for _, o := range nodes {
		if o.ID == n.ID && n.ID != 0 {
			cp := *o
			before = &cp
			n.OwnerID, n.Created = o.OwnerID, o.Created
			if n.Params.PrivateKey == "" && n.Security == "reality" && o.Security == "reality" {
				n.Params.PrivateKey, n.Params.PublicKey = o.Params.PrivateKey, o.Params.PublicKey
			}
		}
	}
	if before == nil {
		n.ID, n.OwnerID, n.Created = 0, ac.user.ID, time.Now().Unix()
	}
	if err := n.normalize(); err != nil {
		return nil, err
	}
	n.Updated = time.Now().Unix()
	if err := saveNode(a.db, &n); err != nil {
		return nil, err
	}
	next := []*ProxyNode{}
	for _, o := range nodes {
		if o.ID != n.ID {
			next = append(next, o)
		}
	}
	next = append(next, &n)
	if err := a.proxyApply(next, users, a.proxySettings()); err != nil {
		if before != nil {
			_ = saveNode(a.db, before)
		} else {
			_, _ = a.db.Exec(`DELETE FROM proxy_nodes WHERE id=?`, n.ID)
		}
		return nil, err
	}
	verb := "新增"
	if before != nil {
		verb = "修改"
	}
	a.audit(ac, "proxy.node.save", "proxy_node", strconv.FormatInt(n.ID, 10), fmt.Sprintf("%s代理节点「%s」（%s）", verb, n.Name, nodeDesc(&n)), redactNode(before), redactNode(&n), false)
	return n, nil
}

func redactNode(n *ProxyNode) any {
	if n == nil {
		return nil
	}
	cp := *n
	if cp.Params.PrivateKey != "" {
		cp.Params.PrivateKey = "(已隐藏)"
	}
	if cp.Params.SSKey != "" {
		cp.Params.SSKey = "(已隐藏)"
	}
	return cp
}

type idReq struct {
	ID      int64 `json:"id"`
	Enabled *bool `json:"enabled,omitempty"`
}

func (a *App) nodeFor(u *User, id int64) (*ProxyNode, error) {
	n, err := scanNode(a.db.QueryRow(`SELECT `+nodeCols+` FROM proxy_nodes WHERE id=?`, id))
	if err != nil || (u.Role != RoleSuper && n.OwnerID != u.ID) {
		return nil, errors.New("节点不存在")
	}
	return n, nil
}

func prepareProxyNodeDelete(a *App, u *User, raw json.RawMessage) (string, error) {
	var req idReq
	_ = json.Unmarshal(raw, &req)
	n, err := a.nodeFor(u, req.ID)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("删除代理节点「%s」（%s）", n.Name, nodeDesc(n)), nil
}

func runProxyNodeDelete(a *App, ac actor, raw json.RawMessage) (any, error) {
	var req idReq
	_ = json.Unmarshal(raw, &req)
	n, err := a.nodeFor(ac.user, req.ID)
	if err != nil {
		return nil, err
	}
	nodes, _ := a.proxyNodes()
	users, _ := a.proxyUsers()
	next := []*ProxyNode{}
	for _, o := range nodes {
		if o.ID != n.ID {
			next = append(next, o)
		}
	}
	if err := a.proxyApply(next, users, a.proxySettings()); err != nil {
		return nil, err
	}
	_, _ = a.db.Exec(`DELETE FROM proxy_nodes WHERE id=?`, n.ID)
	for _, u := range users { // drop the node from users' lists
		if i := slices.Index(u.Nodes, n.ID); i >= 0 {
			u.Nodes = slices.Delete(u.Nodes, i, i+1)
			_ = savePUser(a.db, u)
		}
	}
	a.audit(ac, "proxy.node.delete", "proxy_node", strconv.FormatInt(n.ID, 10), fmt.Sprintf("删除代理节点「%s」", n.Name), redactNode(n), nil, false)
	return map[string]bool{"ok": true}, nil
}

func prepareProxyNodeToggle(a *App, u *User, raw json.RawMessage) (string, error) {
	var req idReq
	_ = json.Unmarshal(raw, &req)
	n, err := a.nodeFor(u, req.ID)
	if err != nil {
		return "", err
	}
	if req.Enabled == nil {
		return "", errors.New("缺少 enabled")
	}
	if *req.Enabled {
		nodes, _ := a.proxyNodes()
		cp := *n
		cp.Enabled = true
		if err := a.nodeIssues(u, &cp, nodes); err != nil {
			return "", err
		}
		return fmt.Sprintf("启用代理节点「%s」", n.Name), nil
	}
	return fmt.Sprintf("停用代理节点「%s」", n.Name), nil
}

func runProxyNodeToggle(a *App, ac actor, raw json.RawMessage) (any, error) {
	var req idReq
	_ = json.Unmarshal(raw, &req)
	n, err := a.nodeFor(ac.user, req.ID)
	if err != nil {
		return nil, err
	}
	nodes, _ := a.proxyNodes()
	users, _ := a.proxyUsers()
	for _, o := range nodes {
		if o.ID == n.ID {
			o.Enabled = *req.Enabled
		}
	}
	if err := a.proxyApply(nodes, users, a.proxySettings()); err != nil {
		return nil, err
	}
	if _, err := a.db.Exec(`UPDATE proxy_nodes SET enabled=?, updated=? WHERE id=?`, *req.Enabled, time.Now().Unix(), n.ID); err != nil {
		return nil, err
	}
	verb := map[bool]string{true: "启用", false: "停用"}[*req.Enabled]
	a.audit(ac, "proxy.node.toggle", "proxy_node", strconv.FormatInt(n.ID, 10), fmt.Sprintf("%s代理节点「%s」", verb, n.Name), nil, nil, false)
	return map[string]bool{"ok": true}, nil
}

// ---- proxy users ----

type puserReq struct {
	ProxyUser
	Regenerate bool `json:"regenerate"` // new secret + subscription token (old links stop working)
	ResetUsage bool `json:"reset_usage"`
}

func (a *App) checkPUser(u *User, req *puserReq, nodes []*ProxyNode, users []*ProxyUser) (*ProxyUser, error) {
	p := req.ProxyUser
	p.Name = clean(p.Name, 40)
	if p.Name == "" {
		return nil, errors.New("请填写用户名称")
	}
	var cur *ProxyUser
	if p.ID != 0 {
		for _, o := range users {
			if o.ID == p.ID {
				cur = o
			}
		}
		if cur == nil || (u.Role != RoleSuper && cur.OwnerID != u.ID) {
			return nil, errors.New("用户不存在")
		}
		p.OwnerID, p.Secret, p.SubToken, p.Created = cur.OwnerID, cur.Secret, cur.SubToken, cur.Created
		p.UsedUp, p.UsedDown, p.PeriodAt, p.Stopped = cur.UsedUp, cur.UsedDown, cur.PeriodAt, cur.Stopped
	} else {
		p.OwnerID, p.Created, p.PeriodAt = u.ID, time.Now().Unix(), time.Now().Unix()
		if q := u.Quota("max_proxy_users"); q >= 0 {
			cnt := 0
			for _, o := range users {
				if o.OwnerID == u.ID {
					cnt++
				}
			}
			if cnt >= q {
				return nil, fmt.Errorf("已达到代理用户数量上限（%d）", q)
			}
		}
	}
	if p.Secret == "" || req.Regenerate {
		p.Secret = newUUID()
	}
	if p.SubToken == "" || req.Regenerate {
		p.SubToken = newSubToken()
	}
	if req.ResetUsage {
		p.UsedUp, p.UsedDown, p.PeriodAt = 0, 0, time.Now().Unix()
	}
	var ids []int64
	for _, id := range p.Nodes {
		ok := false
		for _, n := range nodes {
			// a node belongs to its owner; the super admin may hand out any node
			if n.ID == id && (u.Role == RoleSuper || n.OwnerID == u.ID) {
				ok = true
			}
		}
		if !ok {
			return nil, fmt.Errorf("节点 #%d 不存在或不属于你", id)
		}
		if !slices.Contains(ids, id) {
			ids = append(ids, id)
		}
	}
	if ids == nil {
		ids = []int64{}
	}
	p.Nodes = ids
	if p.LimitBytes < 0 || p.IPLimit < 0 || p.ResetDay < 0 || p.ResetDay > 28 || p.ExpireAt < 0 {
		return nil, errors.New("限额参数不对")
	}
	if p.AllowLAN && u.Role != RoleSuper {
		return nil, errors.New("只有超级管理员能允许代理用户访问家里的局域网")
	}
	// lifting a limit clears the automatic pause it caused
	if p.Stopped == "quota" && (p.LimitBytes == 0 || p.UsedUp+p.UsedDown < p.LimitBytes) {
		p.Stopped = ""
	}
	if p.Stopped == "expired" && (p.ExpireAt == 0 || p.ExpireAt > time.Now().Unix()) {
		p.Stopped = ""
	}
	p.Note = clean(p.Note, 200)
	return &p, nil
}

func prepareProxyUser(a *App, u *User, raw json.RawMessage) (string, error) {
	var req puserReq
	if err := json.Unmarshal(raw, &req); err != nil {
		return "", err
	}
	nodes, _ := a.proxyNodes()
	users, _ := a.proxyUsers()
	p, err := a.checkPUser(u, &req, nodes, users)
	if err != nil {
		return "", err
	}
	verb := "新增"
	if p.ID != 0 {
		verb = "修改"
	}
	return fmt.Sprintf("%s代理用户「%s」（%d 个节点）", verb, p.Name, len(p.Nodes)), nil
}

func runProxyUser(a *App, ac actor, raw json.RawMessage) (any, error) {
	var req puserReq
	_ = json.Unmarshal(raw, &req)
	nodes, _ := a.proxyNodes()
	users, _ := a.proxyUsers()
	p, err := a.checkPUser(ac.user, &req, nodes, users)
	if err != nil {
		return nil, err
	}
	var before *ProxyUser
	next := []*ProxyUser{}
	for _, o := range users {
		if o.ID == p.ID && p.ID != 0 {
			cp := *o
			before = &cp
			continue
		}
		next = append(next, o)
	}
	if err := savePUser(a.db, p); err != nil {
		return nil, err
	}
	next = append(next, p)
	if err := a.proxyApply(nodes, next, a.proxySettings()); err != nil {
		if before != nil {
			_ = savePUser(a.db, before)
		} else {
			_, _ = a.db.Exec(`DELETE FROM proxy_users WHERE id=?`, p.ID)
		}
		return nil, err
	}
	verb := "新增"
	if before != nil {
		verb = "修改"
	}
	extra := ""
	if req.Regenerate {
		extra = "，重新生成了密钥和订阅地址"
	}
	if req.ResetUsage {
		extra += "，清零了用量"
	}
	a.audit(ac, "proxy.user.save", "proxy_user", strconv.FormatInt(p.ID, 10), fmt.Sprintf("%s代理用户「%s」%s", verb, p.Name, extra), redactPUser(before), redactPUser(p), false)
	return p, nil
}

func redactPUser(p *ProxyUser) any {
	if p == nil {
		return nil
	}
	cp := *p
	cp.Secret, cp.SubToken = "(已隐藏)", "(已隐藏)"
	return cp
}

func (a *App) puserFor(u *User, id int64) (*ProxyUser, error) {
	p, err := scanPUser(a.db.QueryRow(`SELECT `+puserCols+` FROM proxy_users WHERE id=?`, id))
	if err != nil || (u.Role != RoleSuper && p.OwnerID != u.ID) {
		return nil, errors.New("用户不存在")
	}
	return p, nil
}

func prepareProxyUserDelete(a *App, u *User, raw json.RawMessage) (string, error) {
	var req idReq
	_ = json.Unmarshal(raw, &req)
	p, err := a.puserFor(u, req.ID)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("删除代理用户「%s」", p.Name), nil
}

func runProxyUserDelete(a *App, ac actor, raw json.RawMessage) (any, error) {
	var req idReq
	_ = json.Unmarshal(raw, &req)
	p, err := a.puserFor(ac.user, req.ID)
	if err != nil {
		return nil, err
	}
	nodes, _ := a.proxyNodes()
	users, _ := a.proxyUsers()
	next := []*ProxyUser{}
	for _, o := range users {
		if o.ID != p.ID {
			next = append(next, o)
		}
	}
	if err := a.proxyApply(nodes, next, a.proxySettings()); err != nil {
		return nil, err
	}
	if _, err := a.db.Exec(`DELETE FROM proxy_users WHERE id=?`, p.ID); err != nil {
		return nil, err
	}
	a.audit(ac, "proxy.user.delete", "proxy_user", strconv.FormatInt(p.ID, 10), fmt.Sprintf("删除代理用户「%s」", p.Name), redactPUser(p), nil, false)
	return map[string]bool{"ok": true}, nil
}

func prepareProxySettings(a *App, u *User, raw json.RawMessage) (string, error) {
	if u.Role != RoleSuper {
		return "", errors.New("只有超级管理员能修改代理扩展设置")
	}
	var req struct {
		Settings proxySettings `json:"settings"`
		SiteHTML *string       `json:"site_html"`
	}
	if err := json.Unmarshal(raw, &req); err != nil {
		return "", err
	}
	if err := req.Settings.normalize(); err != nil {
		return "", err
	}
	if req.SiteHTML != nil && len(*req.SiteHTML) > 512<<10 {
		return "", errors.New("伪装页面不能超过 512 KB")
	}
	return "修改代理扩展设置", nil
}

func runProxySettings(a *App, ac actor, raw json.RawMessage) (any, error) {
	var req struct {
		Settings proxySettings `json:"settings"`
		SiteHTML *string       `json:"site_html"`
	}
	_ = json.Unmarshal(raw, &req)
	if err := req.Settings.normalize(); err != nil {
		return nil, err
	}
	before := a.proxySettings()
	oldHTML := a.setting("proxy.site_html")
	if err := a.setSetting("proxy.config", mustJSON(req.Settings)); err != nil {
		return nil, err
	}
	if req.SiteHTML != nil {
		_ = a.setSetting("proxy.site_html", *req.SiteHTML)
	}
	if st, err := a.proxyExt(); err == nil && st.Installed {
		if err := a.reapplyProxy(); err != nil { // put the old settings back
			_ = a.setSetting("proxy.config", mustJSON(before))
			_ = a.setSetting("proxy.site_html", oldHTML)
			return nil, err
		}
	}
	a.audit(ac, "proxy.settings", "proxy", "settings", "修改代理扩展设置", before, req.Settings, false)
	return map[string]bool{"ok": true}, nil
}

func init() {
	registerAction(&Action{Key: "proxy.node.save", Label: "新增/修改代理节点", Perm: "proxy.manage", Prepare: prepareProxyNode, Run: runProxyNode})
	registerAction(&Action{Key: "proxy.node.delete", Label: "删除代理节点", Perm: "proxy.manage", Prepare: prepareProxyNodeDelete, Run: runProxyNodeDelete})
	registerAction(&Action{Key: "proxy.node.toggle", Label: "启用/停用代理节点", Perm: "proxy.manage", Prepare: prepareProxyNodeToggle, Run: runProxyNodeToggle})
	registerAction(&Action{Key: "proxy.user.save", Label: "新增/修改代理用户", Perm: "proxy.manage", Prepare: prepareProxyUser, Run: runProxyUser})
	registerAction(&Action{Key: "proxy.user.delete", Label: "删除代理用户", Perm: "proxy.manage", Prepare: prepareProxyUserDelete, Run: runProxyUserDelete})
	registerAction(&Action{Key: "proxy.settings", Label: "代理扩展设置", Perm: "proxy.manage", Prepare: prepareProxySettings, Run: runProxySettings})
}

// GET /api/proxy/users/{id}/links
func (a *App) handleProxyLinks(w http.ResponseWriter, r *http.Request) {
	u := currentUser(r)
	id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
	p, err := a.puserFor(u, id)
	if err != nil {
		jsonErr(w, 404, err.Error())
		return
	}
	nodes, _ := a.proxyNodes()
	ps := a.proxySettings()
	host := a.proxyHost(ps)
	pins := a.proxyPins()
	type link struct {
		NodeID int64  `json:"node_id"`
		Node   string `json:"node"`
		Link   string `json:"link"`
		Note   string `json:"note,omitempty"`
	}
	out := []link{}
	for _, n := range nodes {
		if !slices.Contains(p.Nodes, n.ID) {
			continue
		}
		l := link{NodeID: n.ID, Node: n.Name, Link: shareLink(n, p, nodeHost(n, host), pins[n.Domain])}
		if !n.Enabled {
			l.Note = "节点已停用"
		}
		out = append(out, l)
	}
	sub, selfSigned := "", false
	if _, on := buildFront(nodes, ps.Site, ps.ACMEEmail, nil); on {
		subHost := firstNonEmpty(ps.Site.Domain, host)
		sub = "https://" + subHost + "/sub/" + p.SubToken
		selfSigned = net.ParseIP(subHost) != nil // a name gets a public certificate
	}
	writeJSON(w, 200, map[string]any{"links": out, "subscription": sub, "self_signed_sub": selfSigned})
}
