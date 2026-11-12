package agent

import (
	"bufio"
	"compress/gzip"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

// App store: LuCI apps from the router's own opkg feeds. Installing goes through
// opkg like LuCI's package page does; what Wharf installed is recorded so removing
// Wharf (or the app) can clean up after it.

const appsFile = "/etc/wharf-apps.list"

func readAppsFile() map[string]bool {
	out := map[string]bool{}
	b, err := os.ReadFile(appsFile)
	if err != nil {
		return out
	}
	for _, l := range strings.Fields(string(b)) {
		out[l] = true
	}
	return out
}

func writeAppsFile(m map[string]bool) {
	var l []string
	for k, v := range m {
		if v {
			l = append(l, k)
		}
	}
	sort.Strings(l)
	if len(l) == 0 {
		_ = os.Remove(appsFile)
		return
	}
	_ = os.WriteFile(appsFile, []byte(strings.Join(l, "\n")+"\n"), 0o644)
}

type StoreApp struct {
	Pkg       string   `json:"pkg"`
	Version   string   `json:"version"`
	Size      int64    `json:"size"` // download size
	Desc      string   `json:"desc"`
	Depends   []string `json:"depends"`
	Feed      string   `json:"feed"`
	Installed string   `json:"installed,omitempty"` // installed version
	I18n      string   `json:"i18n,omitempty"`      // Chinese translation package, if the feed has one
}

type StoreList struct {
	Apps      []StoreApp `json:"apps"`
	ListsAt   int64      `json:"lists_at"` // when the package lists were fetched (0 = never since boot)
	Arch      string     `json:"arch"`
	FreeBytes int64      `json:"free_bytes"` // free space on the overlay
	Job       StoreJob   `json:"job"`
}

func listFeeds() map[string][]map[string]string {
	out := map[string][]map[string]string{}
	ents, _ := os.ReadDir("/var/opkg-lists")
	for _, e := range ents {
		if e.IsDir() || strings.HasSuffix(e.Name(), ".sig") {
			continue
		}
		f, err := os.Open(filepath.Join("/var/opkg-lists", e.Name()))
		if err != nil {
			continue
		}
		var r io.Reader = f
		hdr := make([]byte, 2)
		if n, _ := f.Read(hdr); n == 2 && hdr[0] == 0x1f && hdr[1] == 0x8b {
			_, _ = f.Seek(0, 0)
			if gz, err := gzip.NewReader(f); err == nil {
				r = gz
			}
		} else {
			_, _ = f.Seek(0, 0)
		}
		sc := bufio.NewScanner(r)
		sc.Buffer(make([]byte, 1<<20), 4<<20)
		parseOpkgRecords(sc, func(m map[string]string) { out[e.Name()] = append(out[e.Name()], m) })
		f.Close()
	}
	return out
}

func overlayFree() int64 {
	var st syscall.Statfs_t
	for _, p := range []string{"/overlay", "/"} {
		if syscall.Statfs(p, &st) == nil {
			return int64(st.Bavail) * int64(st.Bsize)
		}
	}
	return 0
}

func GetStore() StoreList {
	feeds := listFeeds()
	inst := opkgStatus()
	all := map[string]map[string]string{}
	for feed, recs := range feeds {
		for _, m := range recs {
			m["_feed"] = feed
			if old, ok := all[m["Package"]]; !ok || old["Version"] < m["Version"] {
				all[m["Package"]] = m
			}
		}
	}
	out := StoreList{Arch: PkgArch(), FreeBytes: overlayFree(), Job: StoreStatus()}
	if fi, err := os.Stat("/var/opkg-lists"); err == nil {
		if ents, _ := os.ReadDir("/var/opkg-lists"); len(ents) > 0 {
			out.ListsAt = fi.ModTime().Unix()
		}
	}
	for name, m := range all {
		if !strings.HasPrefix(name, "luci-app-") || name == "luci-app-wharf" {
			continue
		}
		sz, _ := strconv.ParseInt(m["Size"], 10, 64)
		a := StoreApp{Pkg: name, Version: m["Version"], Size: sz, Desc: pkgFirstLine(m["Description"]), Feed: m["_feed"]}
		for _, d := range strings.Split(m["Depends"], ",") {
			if f := strings.Fields(d); len(f) > 0 {
				a.Depends = append(a.Depends, f[0])
			}
		}
		if p, ok := inst[name]; ok {
			a.Installed = p.Version
		}
		if tr := "luci-i18n-" + strings.TrimPrefix(name, "luci-app-") + "-zh-cn"; all[tr] != nil {
			a.I18n = tr
		}
		out.Apps = append(out.Apps, a)
	}
	// installed apps that no feed knows (iStore, manual ipk) still show up
	for name, p := range inst {
		if strings.HasPrefix(name, "luci-app-") && all[name] == nil && name != "luci-app-wharf" {
			out.Apps = append(out.Apps, StoreApp{Pkg: name, Version: p.Version, Installed: p.Version, Feed: "local", Desc: pkgFirstLine(pkgDescription(name))})
		}
	}
	sort.Slice(out.Apps, func(a, b int) bool { return out.Apps[a].Pkg < out.Apps[b].Pkg })
	return out
}

func pkgFirstLine(s string) string {
	s, _, _ = strings.Cut(strings.TrimSpace(s), "\n")
	return s
}

var pkgNameRe = regexp.MustCompile(`^[a-z0-9][a-z0-9+._-]{0,80}$`)
var installingRe = regexp.MustCompile(`(?m)^Installing (\S+) \(([^)]+)\)`)

type StoreCheck struct {
	Pkg       string   `json:"pkg"`
	Installs  []string `json:"installs"` // packages opkg would add (name version)
	Bytes     int64    `json:"bytes"`    // their download size
	FreeBytes int64    `json:"free_bytes"`
	Errors    []string `json:"errors,omitempty"`
	Output    string   `json:"output,omitempty"`
}

// CheckInstall asks opkg what installing pkg would do without doing it.
func CheckInstall(pkg string) (StoreCheck, error) {
	if !pkgNameRe.MatchString(pkg) {
		return StoreCheck{}, errors.New("bad package")
	}
	if lists, _ := os.ReadDir("/var/opkg-lists"); len(lists) == 0 {
		return StoreCheck{}, errors.New("还没有软件列表，请先刷新")
	}
	args := []string{"install", "--noaction", pkg}
	feeds := listFeeds()
	sizes := map[string]int64{}
	tr := "luci-i18n-" + strings.TrimPrefix(pkg, "luci-app-") + "-zh-cn"
	hasTr := false
	for _, recs := range feeds {
		for _, m := range recs {
			sz, _ := strconv.ParseInt(m["Size"], 10, 64)
			sizes[m["Package"]] = sz
			if m["Package"] == tr {
				hasTr = true
			}
		}
	}
	if hasTr {
		args = append(args, tr)
	}
	out, _ := exec.Command("opkg", args...).CombinedOutput()
	c := StoreCheck{Pkg: pkg, FreeBytes: overlayFree(), Output: strings.TrimSpace(string(out))}
	for _, m := range installingRe.FindAllStringSubmatch(string(out), -1) {
		c.Installs = append(c.Installs, m[1]+" "+m[2])
		c.Bytes += sizes[m[1]]
	}
	for _, l := range strings.Split(string(out), "\n") {
		l = strings.TrimSpace(l)
		if strings.Contains(l, "Cannot satisfy") || strings.Contains(l, "incompatible with the architectures") || strings.Contains(l, "Unknown package") ||
			strings.Contains(l, "conflicts with") || strings.Contains(l, "check_data_file_clashes") || strings.HasPrefix(l, " * ") && strings.Contains(l, "error") {
			c.Errors = append(c.Errors, l)
		}
	}
	return c, nil
}

type StoreJob struct {
	Running bool     `json:"running"`
	Action  string   `json:"action"`
	Pkgs    []string `json:"pkgs"`
	Started int64    `json:"started"`
	Ended   int64    `json:"ended"`
	Log     []string `json:"log"`
	Error   string   `json:"error,omitempty"`
}

var storeJob struct {
	sync.Mutex
	job StoreJob
}

func StoreStatus() StoreJob {
	storeJob.Lock()
	defer storeJob.Unlock()
	j := storeJob.job
	j.Log = append([]string{}, j.Log...)
	return j
}

func storeLog(s string) {
	storeJob.Lock()
	storeJob.job.Log = append(storeJob.job.Log, s)
	if len(storeJob.job.Log) > 400 {
		storeJob.job.Log = storeJob.job.Log[len(storeJob.job.Log)-400:]
	}
	storeJob.Unlock()
}

// StartStore runs update | install | remove in the background.
func StartStore(action string, pkgs []string) error {
	switch action {
	case "update":
		pkgs = nil
	case "install", "remove":
		if len(pkgs) == 0 {
			return errors.New("没有选择软件")
		}
		for _, p := range pkgs {
			if !pkgNameRe.MatchString(p) || !(strings.HasPrefix(p, "luci-app-") || strings.HasPrefix(p, "luci-i18n-")) || strings.HasPrefix(p, "luci-app-wharf") || strings.HasPrefix(p, "luci-app-owp") {
				return errors.New("只能安装 / 卸载 LuCI 插件：" + p)
			}
		}
	default:
		return errors.New("bad action")
	}
	if DepStatus().Running {
		return errors.New("依赖组件正在安装，请稍后")
	}
	storeJob.Lock()
	if storeJob.job.Running {
		storeJob.Unlock()
		return errors.New("已有任务在进行")
	}
	storeJob.job = StoreJob{Running: true, Action: action, Pkgs: pkgs, Started: time.Now().Unix()}
	storeJob.Unlock()
	go runStore(action, pkgs)
	return nil
}

func runStore(action string, pkgs []string) {
	end := func(msg string) {
		storeJob.Lock()
		storeJob.job.Error, storeJob.job.Running, storeJob.job.Ended = msg, false, time.Now().Unix()
		storeJob.Unlock()
	}
	opkg := func(args ...string) error {
		storeLog("$ opkg " + strings.Join(args, " "))
		out, err := exec.Command("opkg", args...).CombinedOutput()
		for _, l := range strings.Split(strings.TrimSpace(string(out)), "\n") {
			if l = strings.TrimSpace(l); l != "" {
				storeLog(l)
			}
		}
		return err
	}
	refreshLuci := func() {
		// LuCI caches its menu; rpcd needs the new ACL files
		if m, _ := filepath.Glob("/tmp/luci-indexcache*"); len(m) > 0 {
			for _, f := range m {
				_ = os.RemoveAll(f)
			}
		}
		_ = os.RemoveAll("/tmp/luci-modulecache")
		_, _ = run(30*time.Second, "/etc/init.d/rpcd", "reload")
		plugCache.Lock()
		plugCache.out = nil // next read rescans
		plugCache.Unlock()
	}
	switch action {
	case "update":
		if err := opkg("update"); err != nil {
			end("刷新软件列表失败：检查路由器能否访问软件源")
			return
		}
	case "install":
		if lists, _ := os.ReadDir("/var/opkg-lists"); len(lists) == 0 {
			if err := opkg("update"); err != nil {
				end("刷新软件列表失败：检查路由器能否访问软件源")
				return
			}
		}
		before := opkgStatus()
		err := opkg(append([]string{"install"}, pkgs...)...)
		after := opkgStatus()
		mine := readAppsFile()
		for name := range after {
			if _, was := before[name]; !was && (strings.HasPrefix(name, "luci-app-") || strings.HasPrefix(name, "luci-i18n-")) {
				mine[name] = true
			}
		}
		writeAppsFile(mine)
		refreshLuci()
		if err != nil {
			end("安装没有完全成功，详见日志")
			return
		}
	case "remove":
		err := opkg(append([]string{"remove", "--autoremove"}, pkgs...)...)
		after := opkgStatus()
		mine := readAppsFile()
		for name := range mine {
			if _, ok := after[name]; !ok {
				delete(mine, name)
			}
		}
		writeAppsFile(mine)
		refreshLuci()
		if err != nil {
			end("卸载没有完全成功（可能有别的软件依赖它），详见日志")
			return
		}
	}
	storeLog("完成")
	end("")
}
