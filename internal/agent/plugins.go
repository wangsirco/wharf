package agent

import (
	"bufio"
	_ "embed"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Plugin compatibility layer: discover installed LuCI apps, what they run and
// which ports they hold, and expose their settings pages in a form the panel can
// redraw (CBI models via LuCI's own parser, JS views via a sandbox in the browser).

//go:embed cbidump.lua
var cbiDumpLua string

const i18nLua = `local i=require "luci.i18n"; pcall(i.setlanguage, arg[1] or "zh_cn")
for l in io.lines() do io.write((i.translate(l):gsub("\n"," ")), "\n") end`

const i18nDumpLua = `local p=require "luci.template.parser"; local i=require "luci.i18n"; pcall(i.setlanguage, arg[1] or "zh_cn")
local t={}; p.get_translations(function(k,v) t[k]=v end); io.write(require("luci.jsonc").stringify(t))`

type PluginPage struct {
	Path   string `json:"path"`
	Title  string `json:"title"`
	Order  int    `json:"order"`
	Kind   string `json:"kind"`   // cbi | form | view | template
	Target string `json:"target"` // model / view / template path
}

type PluginProc struct {
	PID  int    `json:"pid"`
	Name string `json:"name"`
	Exe  string `json:"exe,omitempty"`
}

type PluginPort struct {
	Port  int    `json:"port"`
	Proto string `json:"proto"`
	Bind  string `json:"bind"` // 0.0.0.0 / :: / 127.0.0.1 / specific address
	Proc  string `json:"proc"`
}

type PluginSvc struct {
	Name    string `json:"name"`
	Enabled bool   `json:"enabled"`
	Running bool   `json:"running"`
}

type Plugin struct {
	Pkg         string       `json:"pkg"`
	Version     string       `json:"version"`
	Desc        string       `json:"desc,omitempty"`
	InstalledAt int64        `json:"installed_at"`
	Size        int64        `json:"size"`
	Title       string       `json:"title"`
	Category    string       `json:"category"` // services | network | system | nas | vpn | status | control | other
	Pages       []PluginPage `json:"pages"`
	Services    []PluginSvc  `json:"services"`
	Configs     []string     `json:"configs"`
	Procs       []PluginProc `json:"procs"`
	Ports       []PluginPort `json:"ports"`
	I18n        bool         `json:"i18n"` // Chinese translation installed
	ByWharf     bool         `json:"by_wharf"`
	Depends     []string     `json:"depends,omitempty"`
}

type opkgPkg struct {
	Name, Version, Depends, Status string
	Installed                      int64
	Size                           int64
	Auto                           bool
}

func parseOpkgRecords(r *bufio.Scanner, each func(map[string]string)) {
	rec := map[string]string{}
	last := ""
	flush := func() {
		if rec["Package"] != "" {
			each(rec)
		}
		rec, last = map[string]string{}, ""
	}
	for r.Scan() {
		l := r.Text()
		if l == "" {
			flush()
			continue
		}
		if (l[0] == ' ' || l[0] == '\t') && last != "" {
			rec[last] += "\n" + strings.TrimSpace(l)
			continue
		}
		k, v, ok := strings.Cut(l, ":")
		if !ok {
			continue
		}
		last = k
		rec[k] = strings.TrimSpace(v)
	}
	flush()
}

func opkgStatus() map[string]opkgPkg {
	out := map[string]opkgPkg{}
	f, err := os.Open("/usr/lib/opkg/status")
	if err != nil {
		return out
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	parseOpkgRecords(sc, func(m map[string]string) {
		if !strings.Contains(m["Status"], "installed") || strings.Contains(m["Status"], "not-installed") {
			return
		}
		t, _ := strconv.ParseInt(m["Installed-Time"], 10, 64)
		sz, _ := strconv.ParseInt(m["Installed-Size"], 10, 64)
		out[m["Package"]] = opkgPkg{Name: m["Package"], Version: m["Version"], Depends: m["Depends"], Status: m["Status"], Installed: t, Size: sz, Auto: m["Auto-Installed"] == "yes"}
	})
	return out
}

func pkgFiles(pkg string) []string {
	b, err := os.ReadFile("/usr/lib/opkg/info/" + pkg + ".list")
	if err != nil {
		return nil
	}
	return strings.Fields(string(b))
}

func pkgDescription(pkg string) string {
	f, err := os.Open("/usr/lib/opkg/info/" + pkg + ".control")
	if err != nil {
		return ""
	}
	defer f.Close()
	desc := ""
	parseOpkgRecords(bufio.NewScanner(f), func(m map[string]string) { desc = m["Description"] })
	return desc
}

var entryRe = regexp.MustCompile(`entry\(\s*\{([^}]*)\}\s*,\s*(\w+)\(([^)]*)\)\s*(?:,\s*(?:_|translate)?\(?\s*["']([^"']*)["']\s*\)?)?\s*(?:,\s*(-?\d+))?`)
var localVarRe = regexp.MustCompile(`local\s+(\w+)\s*=\s*["']([^"']*)["']`)
var luaTokRe = regexp.MustCompile(`["']([^"']*)["']|([A-Za-z_]\w*)|(\.\.)|(,)`)

// luaList evaluates a list of string expressions ("a", appname .. "/x") using the
// file's simple local string variables.
func luaList(s string, vars map[string]string) []string {
	var out []string
	cur, have := "", false
	for _, m := range luaTokRe.FindAllStringSubmatch(s, -1) {
		switch {
		case m[4] != "":
			if have {
				out = append(out, cur)
			}
			cur, have = "", false
		case m[3] != "":
		case m[2] != "":
			if v, ok := vars[m[2]]; ok {
				cur += v
				have = true
			}
		default:
			cur += m[1]
			have = true
		}
	}
	if have {
		out = append(out, cur)
	}
	return out
}

type menuEntry struct {
	Title  string          `json:"title"`
	Order  json.RawMessage `json:"order"`
	Action struct {
		Type string `json:"type"`
		Path string `json:"path"`
	} `json:"action"`
}

// pluginMenus reads the pages a package adds (menu.d JSON and legacy controllers).
func pluginMenus(files []string) []PluginPage {
	var pages []PluginPage
	for _, f := range files {
		switch {
		case strings.HasPrefix(f, "/usr/share/luci/menu.d/") && strings.HasSuffix(f, ".json"):
			b, err := os.ReadFile(f)
			if err != nil {
				continue
			}
			var m map[string]menuEntry
			if json.Unmarshal(b, &m) != nil {
				continue
			}
			for path, e := range m {
				o, _ := strconv.Atoi(strings.Trim(string(e.Order), `"`))
				pages = append(pages, PluginPage{Path: path, Title: e.Title, Order: o, Kind: e.Action.Type, Target: e.Action.Path})
			}
		case strings.HasPrefix(f, "/usr/lib/lua/luci/controller/") && strings.HasSuffix(f, ".lua"):
			b, err := os.ReadFile(f)
			if err != nil {
				continue
			}
			vars := map[string]string{}
			for _, v := range localVarRe.FindAllStringSubmatch(string(b), -1) {
				vars[v[1]] = v[2]
			}
			for _, m := range entryRe.FindAllStringSubmatch(string(b), -1) {
				path := luaList(m[1], vars)
				if len(path) == 0 {
					continue
				}
				p := PluginPage{Path: strings.Join(path, "/"), Kind: m[2], Title: m[4]}
				if t := luaList(m[3], vars); len(t) > 0 {
					p.Target = t[0]
				}
				p.Order, _ = strconv.Atoi(m[5])
				pages = append(pages, p)
			}
		}
	}
	return pages
}

func translate(lines []string) []string {
	if len(lines) == 0 {
		return lines
	}
	script, err := luaScript("i18n", i18nLua)
	if err != nil {
		return lines
	}
	out, err := runIn(10*time.Second, strings.Join(lines, "\n")+"\n", "lua", script, "zh_cn")
	if err != nil {
		return lines
	}
	res := strings.Split(strings.TrimRight(string(out), "\n"), "\n")
	if len(res) != len(lines) {
		return lines
	}
	return res
}

type procInfo struct {
	pid, ppid int
	name, exe string
	inodes    []string
}

func procTable() map[int]*procInfo {
	out := map[int]*procInfo{}
	dirs, _ := filepath.Glob("/proc/[0-9]*")
	for _, d := range dirs {
		pid, err := strconv.Atoi(filepath.Base(d))
		if err != nil {
			continue
		}
		p := &procInfo{pid: pid, name: readTrim(d + "/comm")}
		p.exe, _ = os.Readlink(d + "/exe")
		if st, err := os.ReadFile(d + "/stat"); err == nil {
			if i := strings.LastIndexByte(string(st), ')'); i > 0 {
				f := strings.Fields(string(st)[i+1:])
				if len(f) > 2 {
					p.ppid, _ = strconv.Atoi(f[1])
				}
			}
		}
		if ents, err := os.ReadDir(d + "/fd"); err == nil {
			for _, e := range ents {
				if l, err := os.Readlink(d + "/fd/" + e.Name()); err == nil && strings.HasPrefix(l, "socket:[") {
					p.inodes = append(p.inodes, strings.TrimSuffix(strings.TrimPrefix(l, "socket:["), "]"))
				}
			}
		}
		out[pid] = p
	}
	return out
}

type sockListen struct {
	port  int
	proto string
	bind  string
}

// listenSockets maps socket inode -> listening socket.
func listenSockets() map[string]sockListen {
	out := map[string]sockListen{}
	for _, f := range []string{"tcp", "tcp6", "udp", "udp6"} {
		b, err := os.ReadFile("/proc/net/" + f)
		if err != nil {
			continue
		}
		proto := strings.TrimSuffix(f, "6")
		for i, line := range strings.Split(string(b), "\n") {
			fs := strings.Fields(line)
			if i == 0 || len(fs) < 10 {
				continue
			}
			if proto == "tcp" && fs[3] != "0A" { // LISTEN
				continue
			}
			if proto == "udp" && fs[2] != "00000000:0000" && !strings.HasSuffix(fs[2], ":0000") {
				continue
			}
			addr, port, ok := strings.Cut(fs[1], ":")
			if !ok {
				continue
			}
			p, _ := strconv.ParseInt(port, 16, 32)
			out[fs[9]] = sockListen{int(p), proto, hexAddr(addr)}
		}
	}
	return out
}

func hexAddr(h string) string {
	switch {
	case h == "00000000":
		return "0.0.0.0"
	case strings.Trim(h, "0") == "":
		return "::"
	case len(h) == 8:
		b := make([]string, 4)
		for i := 0; i < 4; i++ {
			v, _ := strconv.ParseUint(h[i*2:i*2+2], 16, 8)
			b[3-i] = strconv.Itoa(int(v))
		}
		return strings.Join(b, ".")
	case h == "00000000000000000000000001000000":
		return "::1"
	}
	return "ipv6"
}

// packages whose binaries are shared system daemons: never attributed to a plugin
var commonPkgPrefixes = []string{"lib", "luci-", "kmod-", "lua", "dnsmasq", "odhcpd", "uhttpd", "dropbear", "curl", "wget", "ip-", "ipset", "iptables", "ip6tables", "nftables",
	"coreutils", "busybox", "ca-", "resolveip", "unzip", "bash", "jsonfilter", "uci", "ubus", "rpcd", "procd", "base-files", "openssl", "firewall", "kernel", "block-mount", "dnsmasq-full", "bind-", "tcping", "netifd"}

func commonPkg(p string) bool {
	for _, c := range commonPkgPrefixes {
		if strings.HasPrefix(p, c) {
			return true
		}
	}
	return false
}

var plugCache struct {
	sync.Mutex
	at  time.Time
	out []Plugin
}

// Plugins lists the installed LuCI apps with what they run.
// A full scan takes a few seconds on a router, so callers get the cached list
// right away and a stale one is refreshed in the background.
func Plugins(fresh bool) []Plugin {
	plugCache.Lock()
	out, at := plugCache.out, plugCache.at
	plugCache.Unlock()
	if !fresh && out != nil {
		if time.Since(at) > 15*time.Second {
			go refreshPlugins()
		}
		return out
	}
	return refreshPlugins()
}

var plugScan sync.Mutex

func refreshPlugins() []Plugin {
	plugScan.Lock()
	defer plugScan.Unlock()
	plugCache.Lock()
	if plugCache.out != nil && time.Since(plugCache.at) < 2*time.Second {
		out := plugCache.out
		plugCache.Unlock()
		return out
	}
	plugCache.Unlock()
	out := scanPlugins()
	plugCache.Lock()
	plugCache.out, plugCache.at = out, time.Now()
	plugCache.Unlock()
	return out
}

func scanPlugins() []Plugin {
	st := opkgStatus()
	var rc map[string]struct {
		Enabled bool `json:"enabled"`
		Running bool `json:"running"`
	}
	_ = ubusCall("rc", "list", nil, &rc)
	var svcList map[string]struct {
		Instances map[string]struct {
			Running bool `json:"running"`
			PID     int  `json:"pid"`
		} `json:"instances"`
	}
	_ = ubusCall("service", "list", nil, &svcList)
	procs := procTable()
	socks := listenSockets()
	children := map[int][]int{}
	for _, p := range procs {
		children[p.ppid] = append(children[p.ppid], p.pid)
	}
	mine := readAppsFile()

	var out []Plugin
	var titles []string
	for name, p := range st {
		if !strings.HasPrefix(name, "luci-app-") || name == "luci-app-wharf" || name == "luci-app-owp" {
			continue
		}
		files := pkgFiles(name)
		pl := Plugin{Pkg: name, Version: p.Version, InstalledAt: p.Installed, Size: p.Size, Desc: pkgDescription(name), ByWharf: mine[name]}
		for _, d := range strings.Split(p.Depends, ",") {
			if d = strings.TrimSpace(strings.Fields(d + " ")[0]); d != "" {
				pl.Depends = append(pl.Depends, d)
			}
		}
		_, pl.I18n = st["luci-i18n-"+strings.TrimPrefix(name, "luci-app-")+"-zh-cn"]
		// pages
		for _, pg := range pluginMenus(files) {
			if pg.Kind == "call" || pg.Kind == "post" || pg.Kind == "alias" || pg.Kind == "firstchild" || pg.Kind == "arcombine" || pg.Kind == "" || pg.Kind == "function" {
				if pg.Kind != "call" && pg.Title != "" && (pl.Title == "" || strings.Count(pg.Path, "/") < 3) {
					pl.Title = pg.Title
					pl.Category = pathCategory(pg.Path)
				}
				continue
			}
			pl.Pages = append(pl.Pages, pg)
		}
		sort.SliceStable(pl.Pages, func(a, b int) bool {
			if pl.Pages[a].Order != pl.Pages[b].Order {
				return pl.Pages[a].Order < pl.Pages[b].Order
			}
			return pl.Pages[a].Path < pl.Pages[b].Path
		})
		if pl.Title == "" && len(pl.Pages) > 0 {
			pl.Title = pl.Pages[0].Title
			pl.Category = pathCategory(pl.Pages[0].Path)
		}
		if pl.Title == "" {
			pl.Title = strings.TrimPrefix(name, "luci-app-")
		}
		if pl.Category == "" {
			pl.Category = "other"
		}
		// services, configs, owned dirs
		owned := map[string]bool{}
		pids := map[int]bool{}
		var svcNames []string
		for _, f := range files {
			switch {
			case strings.HasPrefix(f, "/etc/init.d/"):
				svcNames = appendUniq(svcNames, filepath.Base(f))
			case strings.HasPrefix(f, "/etc/config/"):
				pl.Configs = append(pl.Configs, filepath.Base(f))
			}
			if d := topOwnedDir(filepath.Dir(f)); d != "" {
				owned[d] = true
			}
			if strings.HasPrefix(f, "/usr/bin/") || strings.HasPrefix(f, "/usr/sbin/") || strings.HasPrefix(f, "/bin/") || strings.HasPrefix(f, "/sbin/") {
				owned[f] = true
			}
		}
		// binaries of direct backend dependencies (xray for PassWall, dockerd for dockerman …)
		for _, dep := range pl.Depends {
			if commonPkg(dep) {
				continue
			}
			for _, f := range pkgFiles(dep) {
				if strings.HasPrefix(f, "/usr/bin/") || strings.HasPrefix(f, "/usr/sbin/") {
					owned[f] = true
				}
				if strings.HasPrefix(f, "/etc/init.d/") {
					svcNames = appendUniq(svcNames, filepath.Base(f))
				}
				if strings.HasPrefix(f, "/etc/config/") && !slicesContainsStr(pl.Configs, filepath.Base(f)) {
					pl.Configs = append(pl.Configs, filepath.Base(f))
				}
			}
		}
		// init scripts some installers create outside opkg (e.g. "nextdns install")
		for _, n := range append([]string{strings.TrimPrefix(name, "luci-app-")}, pl.Configs...) {
			if fileExists("/etc/init.d/"+n) && !commonPkg(n) && n != "network" && n != "firewall" && n != "dhcp" {
				svcNames = appendUniq(svcNames, n)
			}
		}
		instRunning := map[string]bool{}
		for _, n := range svcNames {
			for _, in := range svcList[n].Instances {
				if in.Running && in.PID > 0 {
					pids[in.PID] = true
					instRunning[n] = true
				}
			}
		}
		for _, pr := range procs {
			if pr.exe == "" {
				continue
			}
			if owned[pr.exe] {
				pids[pr.pid] = true
				continue
			}
			for d := range owned {
				if strings.HasSuffix(d, "/") && strings.HasPrefix(pr.exe, d) {
					pids[pr.pid] = true
					break
				}
			}
		}
		// descendants of what we found
		queue := make([]int, 0, len(pids))
		for p := range pids {
			queue = append(queue, p)
		}
		for len(queue) > 0 {
			p := queue[0]
			queue = queue[1:]
			for _, c := range children[p] {
				if !pids[c] {
					pids[c] = true
					queue = append(queue, c)
				}
			}
		}
		seenPort := map[string]bool{}
		for pid := range pids {
			pr := procs[pid]
			if pr == nil {
				continue
			}
			pl.Procs = append(pl.Procs, PluginProc{PID: pid, Name: pr.name, Exe: pr.exe})
			for _, ino := range pr.inodes {
				if s, ok := socks[ino]; ok {
					k := strconv.Itoa(s.port) + s.proto + s.bind
					if !seenPort[k] {
						seenPort[k] = true
						pl.Ports = append(pl.Ports, PluginPort{Port: s.port, Proto: s.proto, Bind: s.bind, Proc: pr.name})
					}
				}
			}
		}
		// running: a procd instance, or — for old-style init scripts procd knows
		// nothing about — processes of the plugin alive (rc's "running" can't be trusted)
		for _, n := range svcNames {
			st := PluginSvc{Name: n, Enabled: rc[n].Enabled, Running: instRunning[n]}
			if !st.Running && !procdScript(n) {
				st.Running = len(pl.Procs) > 0
			}
			pl.Services = append(pl.Services, st)
		}
		sort.Slice(pl.Procs, func(a, b int) bool { return pl.Procs[a].PID < pl.Procs[b].PID })
		sort.Slice(pl.Ports, func(a, b int) bool {
			if pl.Ports[a].Port != pl.Ports[b].Port {
				return pl.Ports[a].Port < pl.Ports[b].Port
			}
			return pl.Ports[a].Proto < pl.Ports[b].Proto
		})
		out = append(out, pl)
	}
	// translate titles in one lua run
	for _, p := range out {
		titles = append(titles, p.Title)
		for _, pg := range p.Pages {
			titles = append(titles, pg.Title)
		}
	}
	tr := translate(titles)
	i := 0
	for pi := range out {
		out[pi].Title = tr[i]
		i++
		for gi := range out[pi].Pages {
			out[pi].Pages[gi].Title = tr[i]
			i++
		}
	}
	sort.Slice(out, func(a, b int) bool { return out[a].Pkg < out[b].Pkg })
	return out
}

// ownedRoots: a package that puts files in <root><name>/ owns that directory
// (/etc/openclash/, /usr/share/passwall/) — unless <name> is a shared one.
var ownedRoots = []string{"/etc/", "/usr/share/", "/usr/lib/", "/usr/libexec/", "/opt/", "/lib/", "/usr/local/", "/mnt/"}
var sharedNames = map[string]bool{"init.d": true, "config": true, "uci-defaults": true, "hotplug.d": true, "rc.d": true, "luci": true, "rpcd": true, "opkg": true,
	"lua": true, "ucitrack": true, "sysctl.d": true, "crontabs": true, "modules.d": true, "modules-boot.d": true, "profile.d": true, "ssl": true, "nftables.d": true,
	"iproute2": true, "acl.d": true, "menu.d": true, "ucode": true, "firewall.d": true, "dnsmasq.d": true, "netifd": true, "upgrade": true, "preinit": true, "functions": true,
	"apk": true, "doc": true, "licenses": true, "locale": true, "zoneinfo": true, "ca-certificates": true, "libubox": true, "x86_64-linux-gnu": true}

func topOwnedDir(d string) string {
	d = strings.TrimRight(d, "/") + "/"
	for _, r := range ownedRoots {
		if strings.HasPrefix(d, r) {
			rest := strings.TrimPrefix(d, r)
			name, _, _ := strings.Cut(rest, "/")
			if name == "" || sharedNames[name] || strings.HasPrefix(name, "lib") && strings.HasSuffix(name, ".so") {
				return ""
			}
			return r + name + "/"
		}
	}
	return ""
}

func pathCategory(p string) string {
	parts := strings.Split(p, "/")
	if len(parts) >= 2 {
		switch parts[1] {
		case "services", "network", "system", "nas", "vpn", "status", "control", "docker":
			return parts[1]
		}
	}
	return "other"
}

// luaScript writes an embedded helper to /tmp once and returns its path.
func luaScript(name, src string) (string, error) {
	p := "/tmp/wharf-" + name + ".lua"
	if b, _ := os.ReadFile(p); string(b) != src {
		if err := os.WriteFile(p, []byte(src), 0o600); err != nil {
			return "", err
		}
	}
	return p, nil
}

var modelRe = regexp.MustCompile(`^[A-Za-z0-9_./-]{1,120}$`)

// PluginForm loads a CBI model and returns its form tree.
func PluginForm(model string) (json.RawMessage, error) {
	if !modelRe.MatchString(model) || strings.Contains(model, "..") {
		return nil, errors.New("bad model")
	}
	if !fileExists("/usr/lib/lua/luci/model/cbi/" + model + ".lua") {
		return nil, errors.New("这个页面不存在")
	}
	script, err := luaScript("cbidump", cbiDumpLua)
	if err != nil {
		return nil, err
	}
	out, err := run(20*time.Second, "lua", script, model, "zh_cn")
	if err != nil && len(out) == 0 {
		return nil, err
	}
	if !json.Valid(out) {
		return nil, errors.New("插件页面无法解析")
	}
	return out, nil
}

var i18nCache struct {
	sync.Mutex
	at   time.Time
	data []byte
}

// LuciTranslations returns LuCI's Chinese catalog (hash -> text) for JS views.
func LuciTranslations() ([]byte, error) {
	i18nCache.Lock()
	defer i18nCache.Unlock()
	if i18nCache.data != nil && time.Since(i18nCache.at) < 10*time.Minute {
		return i18nCache.data, nil
	}
	script, err := luaScript("i18ndump", i18nDumpLua)
	if err != nil {
		return []byte("{}"), err
	}
	out, err := run(20*time.Second, "lua", script, "zh_cn")
	if err != nil || !json.Valid(out) {
		return []byte("{}"), err
	}
	i18nCache.data, i18nCache.at = out, time.Now()
	return out, nil
}

// LuciFile reads a file of LuCI's JS resources (views and their helpers).
func LuciFile(p string) ([]byte, error) {
	clean := filepath.Clean("/" + p)
	if !strings.HasSuffix(clean, ".js") || strings.Contains(p, "..") {
		return nil, errors.New("bad path")
	}
	full := filepath.Join("/www/luci-static/resources", clean)
	b, err := os.ReadFile(full)
	if err != nil {
		return nil, errors.New("文件不存在")
	}
	return b, nil
}

var readMethodRe = regexp.MustCompile(`^(get|list|status|info|board|dump|stat|read|ports|interfaces|version)`)

// LuciRPC runs a ubus call on behalf of a plugin page: read-only methods only
// (get…, list…, status, info …) and file read/stat/list outside secrets.
func LuciRPC(object, method string, params map[string]any) (any, error) {
	if object == "" || method == "" || strings.ContainsAny(object+method, " ;|&$`") {
		return nil, errors.New("bad call")
	}
	switch object {
	case "file":
		if method != "read" && method != "stat" && method != "list" {
			return nil, errors.New("插件页面在 Wharf 里只能读取，不能修改")
		}
		p, _ := params["path"].(string)
		if p == "" || secretPath(filepath.Clean(p)) {
			return nil, errors.New("不允许读取这个文件")
		}
	case "uci":
		if method != "get" && method != "configs" {
			return nil, errors.New("插件页面在 Wharf 里只能读取，不能修改")
		}
		if c, _ := params["config"].(string); protectedConfigs[c] && c != "luci" {
			return nil, errors.New("不允许读取这个配置")
		}
	case "session", "rpc-sys":
		return nil, errors.New("不支持")
	default:
		if !readMethodRe.MatchString(strings.ToLower(method)) {
			return nil, errors.New("插件页面在 Wharf 里只能读取，不能修改")
		}
	}
	var out any
	if err := ubusCall(object, method, params, &out); err != nil {
		return nil, err
	}
	return out, nil
}

func secretPath(p string) bool {
	for _, s := range []string{"/etc/shadow", "/etc/passwd-", "/etc/dropbear", "/etc/config/owp", "/etc/wharf", "/mnt/data/owp", "/var/etc/owp", "/etc/ssl/private", "/root/.ssh", "/etc/config/rpcd", "/etc/uhttpd.key"} {
		if strings.HasPrefix(p, s) {
			return true
		}
	}
	return false
}

// PluginService starts, stops, restarts, enables or disables an init script
// that belongs to an installed LuCI app (or its backend).
func PluginService(name, action string) error {
	if !cfgNameRe.MatchString(name) || !fileExists("/etc/init.d/"+name) {
		return errors.New("没有这个服务")
	}
	ok := false
	for _, p := range Plugins(false) {
		for _, s := range p.Services {
			if s.Name == name {
				ok = true
			}
		}
	}
	if !ok {
		if _, known := svcDefOf(name); !known {
			return errors.New("这个服务不属于已安装的插件")
		}
	}
	switch action {
	case "start", "stop", "restart", "enable", "disable":
	default:
		return errors.New("未知操作")
	}
	if out, err := run(120*time.Second, "/etc/init.d/"+name, action); err != nil {
		return errors.New(strings.TrimSpace(string(out)) + " " + err.Error())
	}
	plugCache.Lock()
	plugCache.out = nil // next read rescans
	plugCache.Unlock()
	return nil
}

func slicesHasSvc(l []PluginSvc, name string) bool {
	for _, s := range l {
		if s.Name == name {
			return true
		}
	}
	return false
}

func slicesContainsStr(l []string, s string) bool {
	for _, x := range l {
		if x == s {
			return true
		}
	}
	return false
}

func appendUniq(l []string, s string) []string {
	for _, x := range l {
		if x == s {
			return l
		}
	}
	return append(l, s)
}

// procdScript: the init script runs its service under procd (USE_PROCD=1).
func procdScript(name string) bool {
	b, err := os.ReadFile("/etc/init.d/" + name)
	return err == nil && strings.Contains(string(b), "USE_PROCD=1")
}
