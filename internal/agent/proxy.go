package agent

import (
	"archive/zip"
	"bufio"
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/user"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/wangsirco/wharf/internal/tlsutil"
)

// Proxy extension: an Xray-core server run by the router for its admins and their friends.
//
// Nothing of it ships in the package. When the super admin installs the extension, the agent
// downloads an official Xray-core release (XTLS/Xray-core on GitHub, checked against the
// release's own .dgst digest) into <data_dir>-proxy, writes /etc/init.d/wharf-proxy and runs
// Xray and the SNI front (owp-agent proxy-front) as nobody under procd. The router's own xray
// (PassWall, OpenClash …) is never used or touched. Removing the extension, or the panel,
// removes all of it.
//
//	<dir>/xray/<tag>/xray      downloaded cores; current / previous are symlinks
//	<dir>/run/xray.json        written by apply (owned by nobody, 0600: holds keys)
//	<dir>/run/front.json
//	<dir>/site/                camouflage page, subscriptions (served by the front)
//	<dir>/certs/               certificates for TLS nodes (ACME by the front, or self-signed)
//	<dir>/acme/                ACME account and cache (front)
//	/tmp/wharf-proxy/          access / error logs

const (
	proxyInit   = "/etc/init.d/wharf-proxy"
	proxyLogDir = "/tmp/wharf-proxy"
	xrayRepo    = "https://github.com/XTLS/Xray-core/releases/download/"
	// ProxyDirMarker in configs from the panel is replaced with the extension directory.
	ProxyDirMarker = "@PROXYDIR@"
)

var proxyDir = "/etc/owp-proxy"

// SetProxyDir places the extension next to the agent's data directory (which is 0700).
func SetProxyDir(dataDir string) { proxyDir = strings.TrimRight(dataDir, "/") + "-proxy" }

func ProxyDir() string { return proxyDir }

func xrayBin() string { return filepath.Join(proxyDir, "xray", "current", "xray") }

// XrayAsset is the release file for this router's CPU.
func XrayAsset() string {
	switch runtime.GOARCH {
	case "amd64":
		return "Xray-linux-64.zip"
	case "386":
		return "Xray-linux-32.zip"
	case "arm64":
		return "Xray-linux-arm64-v8a.zip"
	case "arm":
		switch goarm {
		case "5":
			return "Xray-linux-arm32-v5.zip"
		case "6":
			return "Xray-linux-arm32-v6.zip"
		}
		return "Xray-linux-arm32-v7a.zip"
	case "mips", "mipsle", "mips64", "mips64le":
		return "Xray-linux-" + strings.Replace(runtime.GOARCH, "mips", "mips32", 1) + ".zip"
	case "riscv64", "loong64", "ppc64le", "s390x":
		return "Xray-linux-" + runtime.GOARCH + ".zip"
	}
	return ""
}

func nobody() (uid, gid int) {
	uid, gid = 65534, 65534
	if u, err := user.Lookup("nobody"); err == nil {
		uid, _ = strconv.Atoi(u.Uid)
		gid, _ = strconv.Atoi(u.Gid)
	}
	return
}

// ---- status ----

type ProxyJob struct {
	Running bool     `json:"running"`
	Action  string   `json:"action"`
	Tag     string   `json:"tag"`
	Log     []string `json:"log"`
	Error   string   `json:"error,omitempty"`
	Started int64    `json:"started"`
	Ended   int64    `json:"ended,omitempty"`
}

type ProxyStatus struct {
	Installed  bool            `json:"installed"`
	Version    string          `json:"version"`  // tag in use, e.g. v26.10.21
	Previous   string          `json:"previous"` // kept for rollback
	OnDisk     []string        `json:"on_disk"`
	Asset      string          `json:"asset"`
	Dir        string          `json:"dir"`
	FreeMB     int64           `json:"free_mb"`
	Running    map[string]bool `json:"running"` // procd instance -> running
	Configured bool            `json:"configured"`
	SystemXray string          `json:"system_xray,omitempty"` // /usr/bin/xray (other plugins), informational
	Job        ProxyJob        `json:"job"`
}

var proxyJob struct {
	sync.Mutex
	job ProxyJob
}

var proxyMu sync.Mutex // serialises install / apply / uninstall

func jobLog(s string) {
	proxyJob.Lock()
	proxyJob.job.Log = append(proxyJob.job.Log, time.Now().Format("15:04:05 ")+s)
	if len(proxyJob.job.Log) > 200 {
		proxyJob.job.Log = proxyJob.job.Log[len(proxyJob.job.Log)-200:]
	}
	proxyJob.Unlock()
}

func linkTarget(name string) string {
	t, err := os.Readlink(filepath.Join(proxyDir, "xray", name))
	if err != nil {
		return ""
	}
	return filepath.Base(t)
}

func freeMB(path string) int64 {
	var st syscall.Statfs_t
	for p := path; p != "/" && p != "."; p = filepath.Dir(p) {
		if syscall.Statfs(p, &st) == nil {
			return int64(st.Bavail) * int64(st.Bsize) >> 20
		}
	}
	if syscall.Statfs("/", &st) == nil {
		return int64(st.Bavail) * int64(st.Bsize) >> 20
	}
	return -1
}

func proxyInstances() map[string]bool {
	out := map[string]bool{}
	var res map[string]struct {
		Instances map[string]struct {
			Running bool `json:"running"`
		} `json:"instances"`
	}
	if ubusCall("service", "list", map[string]any{"name": "wharf-proxy"}, &res) == nil {
		for name, inst := range res["wharf-proxy"].Instances {
			out[name] = inst.Running
		}
	}
	return out
}

func GetProxyStatus() ProxyStatus {
	st := ProxyStatus{Asset: XrayAsset(), Dir: proxyDir, FreeMB: freeMB(proxyDir), Running: proxyInstances()}
	st.Version, st.Previous = linkTarget("current"), linkTarget("previous")
	if fi, err := os.Stat(xrayBin()); err == nil && fi.Mode()&0o111 != 0 {
		st.Installed = true
	}
	if ents, err := os.ReadDir(filepath.Join(proxyDir, "xray")); err == nil {
		for _, e := range ents {
			if e.IsDir() && strings.HasPrefix(e.Name(), "v") {
				st.OnDisk = append(st.OnDisk, e.Name())
			}
		}
	}
	_, err := os.Stat(filepath.Join(proxyDir, "run", "xray.json"))
	st.Configured = err == nil
	if _, err := os.Stat("/usr/bin/xray"); err == nil {
		if out, err := run(5*time.Second, "/usr/bin/xray", "version"); err == nil {
			st.SystemXray = strings.TrimSpace(strings.SplitN(string(out), "\n", 2)[0])
		}
	}
	proxyJob.Lock()
	st.Job = proxyJob.job
	st.Job.Log = append([]string{}, st.Job.Log...)
	proxyJob.Unlock()
	return st
}

// ---- install / switch version / uninstall ----

var tagRe = regexp.MustCompile(`^v\d+\.\d+\.\d+$`)

// StartProxyInstall downloads and activates an Xray-core release in the background.
// An already downloaded version is switched to without downloading again.
func StartProxyInstall(tag string) error {
	if !tagRe.MatchString(tag) {
		return errors.New("版本号格式不对")
	}
	if XrayAsset() == "" {
		return errors.New("Xray 官方没有这个 CPU 架构（" + runtime.GOARCH + "）的版本")
	}
	return startProxyJob("install", tag, func() error { return installXray(tag) })
}

func StartProxyUninstall() error {
	return startProxyJob("uninstall", "", uninstallProxy)
}

func startProxyJob(action, tag string, fn func() error) error {
	proxyJob.Lock()
	if proxyJob.job.Running {
		proxyJob.Unlock()
		return errors.New("已有任务在进行")
	}
	proxyJob.job = ProxyJob{Running: true, Action: action, Tag: tag, Started: time.Now().Unix()}
	proxyJob.Unlock()
	go func() {
		proxyMu.Lock()
		err := fn()
		proxyMu.Unlock()
		proxyJob.Lock()
		proxyJob.job.Running, proxyJob.job.Ended = false, time.Now().Unix()
		if err != nil {
			proxyJob.job.Error = err.Error()
		}
		proxyJob.Unlock()
		if err != nil {
			jobLog("失败：" + err.Error())
		} else {
			jobLog("完成")
		}
	}()
	return nil
}

func download(url string, max int64) ([]byte, error) {
	resp, err := (&http.Client{Timeout: 5 * time.Minute}).Get(url)
	if err != nil {
		return nil, errors.New("路由器无法访问 GitHub：" + err.Error())
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("下载失败：%s", resp.Status)
	}
	return io.ReadAll(io.LimitReader(resp.Body, max))
}

// digest reads the SHA2-256 line of an Xray .dgst file.
func digest(dgst []byte) string {
	for _, l := range strings.Split(string(dgst), "\n") {
		if k, v, ok := strings.Cut(l, "="); ok && strings.EqualFold(strings.TrimSpace(k), "SHA2-256") {
			return strings.ToLower(strings.TrimSpace(v))
		}
	}
	return ""
}

func installXray(tag string) error {
	dir := filepath.Join(proxyDir, "xray", tag)
	bin := filepath.Join(dir, "xray")
	if err := os.MkdirAll(filepath.Join(proxyDir, "xray"), 0o755); err != nil {
		return err
	}
	_ = os.Chmod(proxyDir, 0o755)
	if _, err := os.Stat(bin); err != nil {
		if mb := freeMB(proxyDir); mb >= 0 && mb < 80 {
			return fmt.Errorf("%s 剩余空间只有 %d MB，至少需要 80 MB", proxyDir, mb)
		}
		asset := XrayAsset()
		jobLog("下载 " + tag + " / " + asset + "（来自 XTLS/Xray-core 官方 Release）")
		dg, err := download(xrayRepo+tag+"/"+asset+".dgst", 1<<16)
		if err != nil {
			return err
		}
		want := digest(dg)
		if len(want) != 64 {
			return errors.New("官方校验文件里没有 SHA2-256")
		}
		zb, err := download(xrayRepo+tag+"/"+asset, 80<<20)
		if err != nil {
			return err
		}
		sum := sha256.Sum256(zb)
		if hex.EncodeToString(sum[:]) != want {
			return errors.New("文件校验失败（下载不完整或被篡改），已放弃")
		}
		jobLog(fmt.Sprintf("校验通过（SHA-256 %s…，%.1f MB）", want[:12], float64(len(zb))/(1<<20)))
		zr, err := zip.NewReader(bytes.NewReader(zb), int64(len(zb)))
		if err != nil {
			return err
		}
		tmp := dir + ".tmp"
		_ = os.RemoveAll(tmp)
		if err := os.MkdirAll(tmp, 0o755); err != nil {
			return err
		}
		found := false
		for _, f := range zr.File {
			if f.Name != "xray" && f.Name != "LICENSE" {
				continue // geo files are not needed: routing uses explicit lists
			}
			rc, err := f.Open()
			if err != nil {
				return err
			}
			mode := os.FileMode(0o644)
			if f.Name == "xray" {
				mode, found = 0o755, true
			}
			out, err := os.OpenFile(filepath.Join(tmp, f.Name), os.O_CREATE|os.O_TRUNC|os.O_WRONLY, mode)
			if err == nil {
				_, err = io.Copy(out, io.LimitReader(rc, 200<<20))
				out.Close()
			}
			rc.Close()
			if err != nil {
				return err
			}
		}
		if !found {
			return errors.New("安装包里没有 xray 程序")
		}
		_ = os.RemoveAll(dir)
		if err := os.Rename(tmp, dir); err != nil {
			return err
		}
	} else {
		jobLog(tag + " 已在本机，直接切换")
	}

	// the core must run here: right CPU, right libc, kernel new enough
	out, err := run(15*time.Second, bin, "version")
	if err != nil || !strings.Contains(string(out), "Xray "+strings.TrimPrefix(tag, "v")) {
		_ = os.RemoveAll(dir)
		return fmt.Errorf("这个版本无法在本机运行：%v", firstLine(string(out)+" "+errString(err)))
	}
	jobLog(firstLine(string(out)))
	if err := testXray(bin, minimalXray); err != nil {
		_ = os.RemoveAll(dir)
		return fmt.Errorf("自检失败：%v", err)
	}
	// an existing configuration must still be accepted by the new core
	cfg := filepath.Join(proxyDir, "run", "xray.json")
	if b, err := os.ReadFile(cfg); err == nil {
		if err := testXray(bin, string(b)); err != nil {
			return fmt.Errorf("现有节点配置在 %s 下无法通过检查，未切换：%v", tag, err)
		}
		jobLog("现有节点配置在新版本下检查通过")
	}

	cur := linkTarget("current")
	if cur != tag {
		if cur != "" {
			_ = relink("previous", cur)
		}
		if err := relink("current", tag); err != nil {
			return err
		}
	}
	if err := writeProxyInit(); err != nil {
		return err
	}
	if err := proxyService("start"); err != nil {
		return err
	}
	if _, err := os.Stat(cfg); err == nil {
		if err := waitRunning("xray", 3*time.Second); err != nil {
			jobLog("新版本启动失败，退回 " + cur)
			if cur != "" && cur != tag {
				_ = relink("current", cur)
				_ = relink("previous", tag)
				_ = proxyService("start")
			}
			return err
		}
		jobLog("Xray " + tag + " 已运行")
	}
	pruneVersions()
	return nil
}

func errString(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

func firstLine(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		s = s[:i]
	}
	if len(s) > 300 {
		s = s[:300]
	}
	return s
}

func relink(name, tag string) error {
	l := filepath.Join(proxyDir, "xray", name)
	tmp := l + ".new"
	_ = os.Remove(tmp)
	if err := os.Symlink(tag, tmp); err != nil {
		return err
	}
	return os.Rename(tmp, l)
}

// pruneVersions keeps only current and previous.
func pruneVersions() {
	keep := map[string]bool{linkTarget("current"): true, linkTarget("previous"): true}
	ents, _ := os.ReadDir(filepath.Join(proxyDir, "xray"))
	for _, e := range ents {
		if e.IsDir() && !keep[e.Name()] {
			_ = os.RemoveAll(filepath.Join(proxyDir, "xray", e.Name()))
		}
	}
}

const minimalXray = `{"log":{"loglevel":"none"},"inbounds":[{"listen":"127.0.0.1","port":1,"protocol":"socks"}],"outbounds":[{"protocol":"freedom"}]}`

// testXray runs `xray run -test` on a config.
func testXray(bin, cfg string) error {
	f, err := os.CreateTemp("", "wharf-xray-*.json")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	// -test opens the log files: point them at a scratch directory so no root-owned
	// file is left where Xray (as nobody) has to write later
	logDir, err := os.MkdirTemp("", "wharf-xray-log-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(logDir)
	cfg = strings.ReplaceAll(cfg, ProxyDirMarker, proxyDir)
	cfg = strings.ReplaceAll(cfg, proxyLogDir+"/", logDir+"/")
	_, _ = f.WriteString(cfg)
	f.Close()
	out, err := run(20*time.Second, bin, "run", "-test", "-c", f.Name())
	if err != nil {
		var lines []string
		for _, l := range strings.Split(string(out)+"\n"+err.Error(), "\n") {
			l = strings.TrimSpace(l)
			if l != "" && !strings.Contains(l, "Reading config") && !strings.HasPrefix(l, "Xray ") && !strings.HasPrefix(l, "A unified platform") && !strings.Contains(l, "[Warning]") {
				lines = append(lines, l)
			}
		}
		if len(lines) > 4 {
			lines = lines[len(lines)-4:]
		}
		return errors.New(strings.Join(lines, " / "))
	}
	return nil
}

const proxyInitScript = `#!/bin/sh /etc/rc.common
# Wharf proxy extension: Xray-core + SNI front, both as nobody.
# Written by owp-agent; removed with the extension (or the panel).

START=99
STOP=10
USE_PROCD=1

DIR=%s

start_service() {
	local x="$DIR/xray/current/xray" c="$DIR/run/xray.json" f="$DIR/run/front.json"
	mkdir -p /tmp/wharf-proxy && chown nobody /tmp/wharf-proxy && chmod 0750 /tmp/wharf-proxy
	if [ -x "$x" ] && [ -s "$c" ]; then
		procd_open_instance xray
		procd_set_param command "$x" run -c "$c"
		procd_set_param env XRAY_LOCATION_ASSET="$DIR/xray/current" WHARF_CFG="$(md5sum < "$c" | cut -c1-32)-$(readlink "$DIR/xray/current")-$(cat "$DIR"/certs/*.crt 2>/dev/null | md5sum | cut -c1-8)"
		procd_set_param user nobody
		procd_set_param limits nofile="65535 65535"
		procd_set_param respawn 3600 5 0
		procd_set_param stdout 1
		procd_set_param stderr 1
		procd_close_instance
	fi
	if [ -x /usr/bin/owp-agent ] && [ -s "$f" ]; then
		procd_open_instance front
		procd_set_param command /usr/bin/owp-agent proxy-front -c "$f"
		procd_set_param env WHARF_CFG="$(md5sum < "$f" | cut -c1-32)"
		procd_set_param user nobody
		procd_set_param limits nofile="65535 65535"
		procd_set_param respawn 3600 5 0
		procd_set_param stdout 1
		procd_set_param stderr 1
		procd_close_instance
	fi
}

# procd restarts only the instances whose command or env (config hash) changed
reload_service() {
	start
}
`

func writeProxyInit() error {
	want := fmt.Sprintf(proxyInitScript, proxyDir)
	if b, err := os.ReadFile(proxyInit); err == nil && string(b) == want {
		return nil
	}
	if err := os.WriteFile(proxyInit, []byte(want), 0o755); err != nil {
		return err
	}
	_, _ = run(10*time.Second, proxyInit, "enable")
	return nil
}

func proxyService(action string) error {
	if _, err := os.Stat(proxyInit); err != nil {
		return nil
	}
	_, err := run(30*time.Second, proxyInit, action)
	return err
}

func waitRunning(inst string, d time.Duration) error {
	time.Sleep(d)
	if proxyInstances()[inst] {
		// procd marks a crash-looping instance running between respawns; look once more
		time.Sleep(1500 * time.Millisecond)
		if proxyInstances()[inst] {
			return nil
		}
	}
	return fmt.Errorf("%s 没有运行起来：%s", inst, lastProxyLog(inst))
}

// lastProxyLog returns the latest syslog lines of an instance.
func lastProxyLog(inst string) string {
	out, _ := run(5*time.Second, "logread", "-l", "200")
	var lines []string
	for _, l := range strings.Split(string(out), "\n") {
		if strings.Contains(l, inst+"[") || strings.Contains(l, "wharf-proxy") {
			if i := strings.Index(l, "]: "); i >= 0 {
				l = l[i+3:]
			}
			lines = append(lines, strings.TrimSpace(l))
		}
	}
	if len(lines) > 3 {
		lines = lines[len(lines)-3:]
	}
	if len(lines) == 0 {
		return "没有日志"
	}
	return strings.Join(lines, " / ")
}

func uninstallProxy() error {
	jobLog("停止并移除服务")
	_ = proxyService("stop")
	_, _ = run(10*time.Second, proxyInit, "disable")
	_ = os.Remove(proxyInit)
	jobLog("删除 " + proxyDir)
	if err := os.RemoveAll(proxyDir); err != nil {
		return err
	}
	_ = os.RemoveAll(proxyLogDir)
	proxyStats.reset()
	return nil
}

// ---- apply configuration ----

type ProxyApply struct {
	Xray  string            `json:"xray"`  // full Xray config; "" = no nodes (Xray stopped)
	Front string            `json:"front"` // front config; "" = front stopped
	Site  map[string]string `json:"site"`  // files under site/ (camouflage page, subs/<token>)
	Certs []ProxyCert       `json:"certs"` // certificates TLS nodes need on disk
}

type ProxyCert struct {
	Domain string `json:"domain"`
}

type ProxyApplyResult struct {
	Changed []string `json:"changed"`
	Warning string   `json:"warning,omitempty"`
}

var siteNameRe = regexp.MustCompile(`^[a-zA-Z0-9_.-]+(/[a-zA-Z0-9_.-]+)?$`)

// ApplyProxy validates and installs a new configuration; on a failed start the previous
// configuration is put back.
func ApplyProxy(req ProxyApply) (ProxyApplyResult, error) {
	proxyMu.Lock()
	defer proxyMu.Unlock()
	var res ProxyApplyResult
	if _, err := os.Stat(xrayBin()); err != nil {
		return res, errors.New("代理扩展还没有安装")
	}
	uid, gid := nobody()
	for _, d := range []string{"run", "site", "site/subs", "certs", "acme"} {
		p := filepath.Join(proxyDir, d)
		_ = os.MkdirAll(p, 0o750)
		_ = os.Chown(p, uid, gid)
	}
	for _, c := range req.Certs { // the test below already opens the certificate files
		if err := ensureCert(c.Domain, uid, gid); err != nil {
			return res, err
		}
	}
	if req.Xray != "" {
		if err := testXray(xrayBin(), req.Xray); err != nil {
			return res, fmt.Errorf("Xray 拒绝了这份配置：%v", err)
		}
	}
	pruneCerts(req)

	runDir := filepath.Join(proxyDir, "run")
	files := map[string]string{"xray.json": strings.ReplaceAll(req.Xray, ProxyDirMarker, proxyDir), "front.json": req.Front}
	old := map[string][]byte{}
	for name, content := range files {
		p := filepath.Join(runDir, name)
		prev, _ := os.ReadFile(p)
		if string(prev) == content {
			continue
		}
		old[name] = prev
		if content == "" {
			_ = os.Remove(p)
		} else if err := writeOwned(p, []byte(content), 0o600, uid, gid); err != nil {
			return res, err
		}
		res.Changed = append(res.Changed, strings.TrimSuffix(name, ".json"))
	}
	syncSite(req.Site, uid, gid)

	if err := writeProxyInit(); err != nil {
		return res, err
	}
	if len(res.Changed) == 0 {
		// nothing new, but make sure what should run does
		run := proxyInstances()
		if (req.Xray == "" || run["xray"]) && (req.Front == "" || run["front"]) {
			return res, nil
		}
	}
	if err := proxyService("reload"); err != nil {
		return res, err
	}
	var failed []string
	for _, inst := range []string{"xray", "front"} {
		if files[inst+".json"] == "" {
			continue
		}
		if err := waitRunning(inst, 2*time.Second); err != nil {
			failed = append(failed, err.Error())
		}
	}
	if len(failed) > 0 {
		for name, prev := range old { // put back what ran before
			p := filepath.Join(runDir, name)
			if len(prev) == 0 {
				_ = os.Remove(p)
			} else {
				_ = writeOwned(p, prev, 0o600, uid, gid)
			}
		}
		_ = proxyService("reload")
		return res, errors.New(strings.Join(failed, "；") + "（已恢复上一份配置）")
	}
	return res, nil
}

func writeOwned(path string, b []byte, mode os.FileMode, uid, gid int) error {
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, b, mode); err != nil {
		return err
	}
	_ = os.Chown(tmp, uid, gid)
	return os.Rename(tmp, path)
}

func syncSite(files map[string]string, uid, gid int) {
	site := filepath.Join(proxyDir, "site")
	keep := map[string]bool{}
	for name, content := range files {
		if !siteNameRe.MatchString(name) || strings.Contains(name, "..") {
			continue
		}
		p := filepath.Join(site, name)
		keep[p] = true
		_ = os.MkdirAll(filepath.Dir(p), 0o750)
		_ = os.Chown(filepath.Dir(p), uid, gid)
		if b, err := os.ReadFile(p); err == nil && string(b) == content {
			continue
		}
		_ = writeOwned(p, []byte(content), 0o640, uid, gid)
	}
	_ = filepath.Walk(site, func(p string, fi os.FileInfo, err error) error {
		if err == nil && !fi.IsDir() && !keep[p] {
			_ = os.Remove(p)
		}
		return nil
	})
}

// ensureCert makes sure certs/<domain>.crt/.key exist; until the front has an ACME
// certificate (or for nodes without a public domain) a self-signed one stands in.
func ensureCert(domain string, uid, gid int) error {
	if !domainRe.MatchString(domain) {
		return fmt.Errorf("域名格式不对：%s", domain)
	}
	crt := filepath.Join(proxyDir, "certs", domain+".crt")
	if _, err := os.Stat(crt); err == nil {
		return nil
	}
	certPEM, keyPEM, err := tlsutil.SelfSigned(domain, "Wharf")
	if err != nil {
		return err
	}
	if err := writeOwned(filepath.Join(proxyDir, "certs", domain+".key"), keyPEM, 0o600, uid, gid); err != nil {
		return err
	}
	return writeOwned(crt, certPEM, 0o644, uid, gid)
}

// pruneCerts removes certificates no node or site domain uses any more.
func pruneCerts(req ProxyApply) {
	keep := map[string]bool{}
	for _, c := range req.Certs {
		keep[c.Domain] = true
	}
	var front struct {
		ACME []string `json:"acme"`
	}
	_ = json.Unmarshal([]byte(req.Front), &front)
	for _, d := range front.ACME {
		keep[d] = true
	}
	dir := filepath.Join(proxyDir, "certs")
	ents, _ := os.ReadDir(dir)
	for _, e := range ents {
		name := e.Name()
		d := strings.TrimSuffix(strings.TrimSuffix(strings.TrimSuffix(name, ".crt"), ".key"), ".status")
		if d != name && !keep[d] {
			_ = os.Remove(filepath.Join(dir, name))
		}
	}
}

var domainRe = regexp.MustCompile(`^[a-zA-Z0-9]([a-zA-Z0-9.-]{0,251}[a-zA-Z0-9])?$`)

// ---- statistics ----

// ProxyMinute is one minute of proxy traffic and access records.
type ProxyMinute struct {
	Minute int64               `json:"minute"`
	Users  map[string][2]int64 `json:"users"` // email -> [up, down]
	Access []ProxyAccess       `json:"access"`
}

type ProxyAccess struct {
	Email  string `json:"email"`
	IP     string `json:"ip"`
	Dest   string `json:"dest"`
	Port   int    `json:"port"`
	Net    string `json:"net"`
	Inbd   string `json:"inbound"`
	Out    string `json:"outbound"`
	Status string `json:"status"` // accepted | rejected | blocked (routing rule)
	Count  int    `json:"count"`
	First  int64  `json:"first"`
	Last   int64  `json:"last"`
}

type ProxyLive struct {
	TS     int64                       `json:"ts"`
	Users  map[string][2]float64       `json:"users"`  // email -> bytes/s [up, down] (Xray counters)
	Online map[string]map[string]int64 `json:"online"` // email -> ip -> last seen
	// From the connection table: Xray's counters only move when a spliced (Vision)
	// connection ends, so live rates come from conntrack byte counts instead.
	Ports map[int][2]float64    `json:"ports"` // Xray inbound port -> bytes/s [up, down]
	IPs   map[string][2]float64 `json:"ips"`   // client address -> bytes/s [up, down]
}

type proxyCollector struct {
	ct      map[string][2]int64 // conntrack entry -> bytes [orig, reply] at the last sample
	mu      sync.Mutex
	boot    int64
	minutes []ProxyMinute // completed
	cur     ProxyMinute
	access  map[string]*ProxyAccess
	live    ProxyLive
	logOff  int64
}

var proxyStats = &proxyCollector{boot: time.Now().Unix()}

func (c *proxyCollector) reset() {
	c.mu.Lock()
	c.minutes, c.cur, c.access, c.live = nil, ProxyMinute{}, nil, ProxyLive{}
	c.mu.Unlock()
}

// ProxySince returns completed minutes after a cursor, plus live rates.
func ProxySince(after int64) (int64, []ProxyMinute, ProxyLive) {
	c := proxyStats
	c.mu.Lock()
	defer c.mu.Unlock()
	var out []ProxyMinute
	for _, m := range c.minutes {
		if m.Minute > after {
			out = append(out, m)
		}
	}
	return c.boot, out, c.live
}

func apiAddr() string {
	b, err := os.ReadFile(filepath.Join(proxyDir, "run", "xray.json"))
	if err != nil {
		return ""
	}
	var cfg struct {
		Inbounds []struct {
			Tag    string `json:"tag"`
			Listen string `json:"listen"`
			Port   int    `json:"port"`
		} `json:"inbounds"`
	}
	if json.Unmarshal(b, &cfg) != nil {
		return ""
	}
	for _, in := range cfg.Inbounds {
		if in.Tag == "api" {
			return fmt.Sprintf("127.0.0.1:%d", in.Port)
		}
	}
	return ""
}

// RunProxyStats samples Xray's counters every 5 s (reading and resetting them, so each
// sample is a delta) and tails its access log.
func RunProxyStats() {
	t := time.NewTicker(5 * time.Second)
	last := time.Now()
	n := 0
	certs := certsStamp()
	for now := range t.C {
		n++
		if n%12 == 0 { // the front renewed a certificate: Xray must load it
			if c := certsStamp(); c != certs {
				certs = c
				proxyMu.Lock()
				_ = proxyService("reload")
				proxyMu.Unlock()
			}
		}
		addr := apiAddr()
		if addr == "" || !proxyInstances()["xray"] {
			last = now
			proxyStats.roll(now)
			continue
		}
		ports, ips := proxyStats.connRates(now.Sub(last).Seconds())
		deltas := queryStats(addr)
		var online map[string]map[string]int64
		if n%3 == 0 {
			online = queryOnline(addr)
		}
		access := tailAccess()
		proxyStats.add(now, now.Sub(last).Seconds(), deltas, online, access)
		proxyStats.mu.Lock()
		proxyStats.live.Ports, proxyStats.live.IPs = ports, ips
		proxyStats.mu.Unlock()
		last = now
	}
}

// connRates reads /proc/net/nf_conntrack for connections to Xray's inbounds (20000–20999)
// and returns per-port and per-client byte rates since the previous call.
//
//	... src=C dst=R sport=x dport=P packets=.. bytes=UP src=R dst=C sport=Q dport=x packets=.. bytes=DOWN ...
//
// Q (the reply's source port) is where Xray listens — for a redirected WAN port too.
// Connections to the front (proxyFrontPort) only count per client; the front's own
// loopback connections to Xray count per port.
func (c *proxyCollector) connRates(secs float64) (map[int][2]float64, map[string][2]float64) {
	ports, ips := map[int][2]float64{}, map[string][2]float64{}
	f, err := os.Open("/proc/net/nf_conntrack")
	if err != nil {
		return ports, ips
	}
	defer f.Close()
	cur := map[string][2]int64{}
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 4096), 4096)
	for sc.Scan() {
		line := sc.Text()
		if !strings.Contains(line, "sport=20") {
			continue
		}
		var src, rsport, osport string
		var up, down int64
		nsrc, nsport, nbytes := 0, 0, 0
		for _, fld := range strings.Fields(line) {
			k, v, ok := strings.Cut(fld, "=")
			if !ok {
				continue
			}
			switch k {
			case "src":
				if nsrc == 0 {
					src = v
				}
				nsrc++
			case "sport":
				if nsport == 0 {
					osport = v
				} else {
					rsport = v
				}
				nsport++
			case "bytes":
				n, _ := strconv.ParseInt(v, 10, 64)
				if nbytes == 0 {
					up = n
				} else {
					down = n
				}
				nbytes++
			}
		}
		port, _ := strconv.Atoi(rsport)
		if port < 20000 || port > 20999 || port == 20085 {
			continue
		}
		key := src + ":" + osport + ">" + rsport
		cur[key] = [2]int64{up, down}
		prev, seen := c.ct[key]
		if !seen || secs <= 0 {
			continue // first sight: no baseline yet
		}
		du, dd := float64(max(0, up-prev[0]))/secs, float64(max(0, down-prev[1]))/secs
		if du == 0 && dd == 0 {
			continue
		}
		if port != 20443 {
			r := ports[port]
			ports[port] = [2]float64{r[0] + du, r[1] + dd}
		}
		if src != "127.0.0.1" && src != "::1" {
			r := ips[src]
			ips[src] = [2]float64{r[0] + du, r[1] + dd}
		}
	}
	c.ct = cur
	return ports, ips
}

func certsStamp() string {
	var b strings.Builder
	ents, _ := os.ReadDir(filepath.Join(proxyDir, "certs"))
	for _, e := range ents {
		if fi, err := e.Info(); err == nil && strings.HasSuffix(e.Name(), ".crt") {
			fmt.Fprintf(&b, "%s:%d:%d;", e.Name(), fi.Size(), fi.ModTime().UnixNano())
		}
	}
	return b.String()
}

func xrayAPI(args ...string) []byte {
	out, err := run(8*time.Second, xrayBin(), append([]string{"api"}, args...)...)
	if err != nil {
		return nil
	}
	return out
}

func queryStats(addr string) map[string][2]int64 {
	out := xrayAPI("statsquery", "-s", addr, "-reset", "-pattern", "user>>>")
	var r struct {
		Stat []struct {
			Name  string          `json:"name"`
			Value json.RawMessage `json:"value"`
		} `json:"stat"`
	}
	res := map[string][2]int64{}
	if json.Unmarshal(out, &r) != nil {
		return res
	}
	for _, s := range r.Stat {
		p := strings.Split(s.Name, ">>>") // user>>>email>>>traffic>>>uplink
		if len(p) != 4 || p[0] != "user" {
			continue
		}
		v, _ := strconv.ParseInt(strings.Trim(string(s.Value), `"`), 10, 64)
		if v <= 0 {
			continue
		}
		cur := res[p[1]]
		if p[3] == "uplink" {
			cur[0] += v
		} else {
			cur[1] += v
		}
		res[p[1]] = cur
	}
	return res
}

func queryOnline(addr string) map[string]map[string]int64 {
	out := xrayAPI("statsonlineiplist", "-s", addr, "-all")
	var r struct {
		Users []struct {
			Email string `json:"email"`
			IPs   []struct {
				IP       string `json:"ip"`
				LastSeen int64  `json:"lastSeen"`
			} `json:"ips"`
		} `json:"users"`
	}
	res := map[string]map[string]int64{}
	if json.Unmarshal(out, &r) != nil {
		return res
	}
	for _, u := range r.Users {
		m := map[string]int64{}
		for _, ip := range u.IPs {
			m[ip.IP] = ip.LastSeen
		}
		res[u.Email] = m
	}
	return res
}

// 2026/10/24 22:35:03.798918 from 1.2.3.4:54358 accepted tcp:www.cloudflare.com:443 [n1 >> direct] email: u1@n1
var accessRe = regexp.MustCompile(`^(\d{4}/\d\d/\d\d \d\d:\d\d:\d\d)(?:\.\d+)? from (?:tcp:|udp:)?(\S+) (accepted|rejected) (tcp|udp):(\S+) \[([^\]]*)\](?: email: (\S+))?`)

func tailAccess() []ProxyAccess {
	p := filepath.Join(proxyLogDir, "access.log")
	f, err := os.Open(p)
	if err != nil {
		return nil
	}
	defer f.Close()
	fi, _ := f.Stat()
	c := proxyStats
	if fi.Size() < c.logOff {
		c.logOff = 0 // rotated / truncated
	}
	_, _ = f.Seek(c.logOff, io.SeekStart)
	var out []ProxyAccess
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64<<10), 64<<10)
	read := c.logOff
	for sc.Scan() {
		line := sc.Text()
		read += int64(len(line)) + 1
		m := accessRe.FindStringSubmatch(line)
		if m == nil || strings.HasPrefix(m[6], "api") {
			continue
		}
		ts, err := time.ParseInLocation("2006/01/02 15:04:05", m[1], time.Local)
		if err != nil {
			continue
		}
		src := m[2]
		if h, _, err := splitHostPortLoose(src); err == nil {
			src = h
		}
		dest, port := m[5], 0
		if i := strings.LastIndexByte(dest, ':'); i > 0 {
			port, _ = strconv.Atoi(dest[i+1:])
			dest = strings.Trim(dest[:i], "[]")
		}
		in, outb := m[6], ""
		for _, sep := range []string{" >> ", " -> "} {
			if a, b, ok := strings.Cut(m[6], sep); ok {
				in, outb = a, b
			}
		}
		status := m[3]
		if status == "accepted" && outb == "blocked" { // refused by a routing rule (LAN, BT, blocked port / site)
			status = "blocked"
		}
		out = append(out, ProxyAccess{Email: m[7], IP: src, Dest: dest, Port: port, Net: m[4], Inbd: in, Out: outb,
			Status: status, Count: 1, First: ts.Unix(), Last: ts.Unix()})
	}
	c.logOff = read
	if read > 8<<20 { // keep the log small; Xray appends, so truncating in place is safe
		_ = os.Truncate(p, 0)
		c.logOff = 0
	}
	return out
}

func splitHostPortLoose(s string) (string, string, error) {
	i := strings.LastIndexByte(s, ':')
	if i < 0 {
		return "", "", errors.New("no port")
	}
	return strings.Trim(s[:i], "[]"), s[i+1:], nil
}

func (c *proxyCollector) roll(now time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	min := now.Unix() / 60 * 60
	if c.cur.Minute != 0 && c.cur.Minute < min {
		for _, a := range c.access {
			c.cur.Access = append(c.cur.Access, *a)
		}
		sort.Slice(c.cur.Access, func(i, j int) bool { return c.cur.Access[i].First < c.cur.Access[j].First })
		if len(c.cur.Users) > 0 || len(c.cur.Access) > 0 {
			c.minutes = append(c.minutes, c.cur)
		}
		cut := min - 6*3600
		i := 0
		for i < len(c.minutes) && c.minutes[i].Minute < cut {
			i++
		}
		c.minutes = c.minutes[i:]
		c.cur, c.access = ProxyMinute{}, nil
	}
	if c.cur.Minute == 0 {
		c.cur = ProxyMinute{Minute: min, Users: map[string][2]int64{}}
		c.access = map[string]*ProxyAccess{}
	}
}

func (c *proxyCollector) add(now time.Time, secs float64, deltas map[string][2]int64, online map[string]map[string]int64, access []ProxyAccess) {
	c.roll(now)
	c.mu.Lock()
	defer c.mu.Unlock()
	live := map[string][2]float64{}
	for e, d := range deltas {
		cur := c.cur.Users[e]
		cur[0] += d[0]
		cur[1] += d[1]
		c.cur.Users[e] = cur
		if secs > 0 {
			live[e] = [2]float64{float64(d[0]) / secs, float64(d[1]) / secs}
		}
	}
	c.live.TS, c.live.Users = now.Unix(), live
	if online != nil {
		c.live.Online = online
	}
	for _, a := range access {
		k := a.Email + "|" + a.IP + "|" + a.Dest + "|" + strconv.Itoa(a.Port) + "|" + a.Net + "|" + a.Status
		if e := c.access[k]; e != nil {
			e.Count++
			e.Last = a.Last
			continue
		}
		if len(c.access) >= 5000 { // a flood of distinct targets: keep the minute bounded
			continue
		}
		a := a
		c.access[k] = &a
	}
}

// ProxyErrorLog returns the tail of Xray's error log.
func ProxyErrorLog(n int) []string {
	b, err := os.ReadFile(filepath.Join(proxyLogDir, "error.log"))
	if err != nil {
		return []string{}
	}
	lines := strings.Split(strings.TrimSpace(string(b)), "\n")
	if n <= 0 || n > 500 {
		n = 200
	}
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	if len(b) > 4<<20 {
		_ = os.Truncate(filepath.Join(proxyLogDir, "error.log"), 0)
	}
	return lines
}

// BlockProxyIP refuses new connections from an address on all nodes until Xray restarts.
func BlockProxyIP(ip string) error {
	addr := apiAddr()
	if addr == "" {
		return errors.New("Xray 没有运行")
	}
	if net := strings.TrimSpace(ip); net == "" || strings.ContainsAny(net, " ;|&") {
		return errors.New("IP 格式不对")
	}
	_, err := run(8*time.Second, xrayBin(), "api", "sib", "-s", addr, "-outbound=blocked", ip)
	return err
}


// ProxyCert describes a certificate on disk for the panel.
type ProxyCertInfo struct {
	Domain   string `json:"domain"`
	Issuer   string `json:"issuer"`
	NotAfter int64  `json:"not_after"`
	Self     bool   `json:"self_signed"`
	SHA256   string `json:"sha256"`           // leaf certificate (what clients pin: pcs / pinSHA256)
	Status   string `json:"status,omitempty"` // last ACME attempt (front)
}

func ProxyCerts() []ProxyCertInfo {
	out := []ProxyCertInfo{}
	dir := filepath.Join(proxyDir, "certs")
	ents, _ := os.ReadDir(dir)
	for _, e := range ents {
		d, ok := strings.CutSuffix(e.Name(), ".crt")
		if !ok {
			continue
		}
		info := ProxyCertInfo{Domain: d}
		if b, err := os.ReadFile(filepath.Join(dir, e.Name())); err == nil {
			if blk, _ := pem.Decode(b); blk != nil {
				sum := sha256.Sum256(blk.Bytes)
				info.SHA256 = hex.EncodeToString(sum[:])
				if c, err := x509.ParseCertificate(blk.Bytes); err == nil {
					info.Issuer, info.NotAfter = c.Issuer.CommonName+" "+strings.Join(c.Issuer.Organization, " "), c.NotAfter.Unix()
					info.Self = c.Issuer.String() == c.Subject.String()
				}
			}
		}
		if b, err := os.ReadFile(filepath.Join(dir, d+".status")); err == nil {
			info.Status = strings.TrimSpace(string(b))
		}
		out = append(out, info)
	}
	return out
}
