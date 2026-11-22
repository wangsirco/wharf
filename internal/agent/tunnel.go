package agent

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"
)

// Cloudflare Tunnel: cloudflared from Cloudflare's own GitHub releases (never the
// router's package feed, which lags years behind), kept in <data_dir>-tunnel and run by
// procd as nobody (/etc/init.d/wharf-tunnel). The panel creates the tunnel and its
// routes through the Cloudflare API ("remotely managed"), so the only thing on the
// router is the tunnel token. Visitors for the panel arrive on a unix socket that only
// nobody (cloudflared) and root can open (panel side: TunnelSocket).

const (
	tunnelInit    = "/etc/init.d/wharf-tunnel"
	TunnelSocket  = "/var/run/wharf-tunnel.sock"
	tunnelMetrics = "127.0.0.1:20092"
)

var tunnelDir = "/etc/owp-tunnel"

func SetTunnelDir(dataDir string) { tunnelDir = strings.TrimRight(dataDir, "/") + "-tunnel" }

func cloudflaredBin() string { return filepath.Join(tunnelDir, "current", "cloudflared") }

// cloudflaredAsset: the release file for this router.
func cloudflaredAsset() string {
	switch runtime.GOARCH {
	case "amd64":
		return "cloudflared-linux-amd64"
	case "arm64":
		return "cloudflared-linux-arm64"
	case "arm":
		return "cloudflared-linux-arm"
	case "386":
		return "cloudflared-linux-386"
	}
	return ""
}

type TunnelStatus struct {
	Installed bool     `json:"installed"`
	Version   string   `json:"version"`
	Asset     string   `json:"asset"`
	Dir       string   `json:"dir"`
	FreeMB    int64    `json:"free_mb"`
	HasToken  bool     `json:"has_token"`
	Running   bool     `json:"running"`
	Ready     int      `json:"ready"` // connections to Cloudflare's edge (healthy: 4)
	Job       ProxyJob `json:"job"`
	Log       []string `json:"log,omitempty"`
}

var tunnelJob struct {
	sync.Mutex
	job ProxyJob
}

var tunnelMu sync.Mutex

func tunnelLog(s string) {
	tunnelJob.Lock()
	tunnelJob.job.Log = append(tunnelJob.job.Log, time.Now().Format("15:04:05")+" "+s)
	if len(tunnelJob.job.Log) > 200 {
		tunnelJob.job.Log = tunnelJob.job.Log[len(tunnelJob.job.Log)-200:]
	}
	tunnelJob.Unlock()
}

func tunnelRunning() bool {
	var st map[string]struct {
		Instances map[string]struct {
			Running bool `json:"running"`
		} `json:"instances"`
	}
	if ubusCall("service", "list", map[string]any{"name": "wharf-tunnel"}, &st) != nil {
		return false
	}
	return st["wharf-tunnel"].Instances["tunnel"].Running
}

func tunnelReady() int {
	resp, err := (&http.Client{Timeout: 2 * time.Second}).Get("http://" + tunnelMetrics + "/ready")
	if err != nil {
		return 0
	}
	defer resp.Body.Close()
	var r struct {
		ReadyConnections int `json:"readyConnections"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&r)
	return r.ReadyConnections
}

func GetTunnelStatus() TunnelStatus {
	st := TunnelStatus{Asset: cloudflaredAsset(), Dir: tunnelDir, FreeMB: freeMB(filepath.Dir(tunnelDir))}
	if v := tunnelCurrent(); v != "" {
		if _, err := os.Stat(cloudflaredBin()); err == nil {
			st.Installed, st.Version = true, v
		}
	}
	if fi, err := os.Stat(filepath.Join(tunnelDir, "token")); err == nil && fi.Size() > 0 {
		st.HasToken = true
	}
	st.Running = tunnelRunning()
	if st.Running {
		st.Ready = tunnelReady()
		if st.Ready == 0 {
			st.Log = lastTunnelLog()
		}
	}
	tunnelJob.Lock()
	st.Job = tunnelJob.job
	st.Job.Log = append([]string(nil), tunnelJob.job.Log...)
	tunnelJob.Unlock()
	return st
}

func lastTunnelLog() []string {
	out, _ := run(5*time.Second, "logread", "-l", "300")
	var lines []string
	for _, l := range strings.Split(string(out), "\n") {
		if strings.Contains(l, "wharf-tunnel") || strings.Contains(l, "cloudflared[") {
			if i := strings.Index(l, "]: "); i >= 0 {
				l = l[i+3:]
			}
			lines = append(lines, strings.TrimSpace(l))
		}
	}
	if len(lines) > 5 {
		lines = lines[len(lines)-5:]
	}
	return lines
}

// ---- install / update / remove ----

func startTunnelJob(action string, fn func() error) error {
	tunnelJob.Lock()
	if tunnelJob.job.Running {
		tunnelJob.Unlock()
		return errors.New("已有任务在进行")
	}
	tunnelJob.job = ProxyJob{Running: true, Action: action, Started: time.Now().Unix()}
	tunnelJob.Unlock()
	go func() {
		tunnelMu.Lock()
		err := fn()
		tunnelMu.Unlock()
		tunnelJob.Lock()
		tunnelJob.job.Running, tunnelJob.job.Ended = false, time.Now().Unix()
		if err != nil {
			tunnelJob.job.Error = err.Error()
		}
		tunnelJob.Unlock()
		if err != nil {
			tunnelLog("失败：" + err.Error())
		} else {
			tunnelLog("完成")
		}
	}()
	return nil
}

var cfdVersionRe = regexp.MustCompile(`^\d{4}\.\d{1,2}\.\d{1,3}$`)

// releaseSHA finds "<asset>: <sha256>" in the release notes (cloudflared lists them there).
func releaseSHA(body, asset string) string {
	re := regexp.MustCompile(`(?m)^\s*` + regexp.QuoteMeta(asset) + `\s*:\s*([0-9a-fA-F]{64})\s*$`)
	if m := re.FindStringSubmatch(body); m != nil {
		return strings.ToLower(m[1])
	}
	return ""
}

func installCloudflared() error {
	asset := cloudflaredAsset()
	if asset == "" {
		return fmt.Errorf("cloudflared 没有 %s 架构的版本", runtime.GOARCH)
	}
	if free := freeMB(filepath.Dir(tunnelDir)); free > 0 && free < 120 {
		return fmt.Errorf("%s 剩余空间只有 %d MB，至少需要 120 MB", filepath.Dir(tunnelDir), free)
	}
	tunnelLog("查询 cloudflared 最新版本…")
	b, err := download("https://api.github.com/repos/cloudflare/cloudflared/releases/latest", 2<<20)
	if err != nil {
		return err
	}
	var rel struct {
		Tag    string `json:"tag_name"`
		Body   string `json:"body"`
		Assets []struct {
			Name string `json:"name"`
			URL  string `json:"browser_download_url"`
			Size int64  `json:"size"`
		} `json:"assets"`
	}
	if err := json.Unmarshal(b, &rel); err != nil || !cfdVersionRe.MatchString(rel.Tag) {
		return errors.New("读不懂 GitHub 返回的版本信息")
	}
	if tunnelCurrent() == rel.Tag {
		tunnelLog("已经是最新版 " + rel.Tag)
		return writeTunnelInit()
	}
	url := ""
	for _, a := range rel.Assets {
		if a.Name == asset {
			url = a.URL
		}
	}
	if url == "" {
		return fmt.Errorf("版本 %s 里没有 %s", rel.Tag, asset)
	}
	want := releaseSHA(rel.Body, asset)
	tunnelLog(fmt.Sprintf("下载 %s %s…", asset, rel.Tag))
	bin, err := download(url, 200<<20)
	if err != nil {
		return err
	}
	sum := sha256.Sum256(bin)
	got := hex.EncodeToString(sum[:])
	if want != "" {
		if got != want {
			return errors.New("校验值不对，可能下载被篡改或不完整，已丢弃")
		}
		tunnelLog("SHA-256 与官方发布说明一致")
	} else {
		tunnelLog("发布说明里没有校验值，仅凭 HTTPS 从 GitHub 下载（SHA-256 " + got[:16] + "…）")
	}
	dir := filepath.Join(tunnelDir, rel.Tag)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(dir, "cloudflared"), bin, 0o755); err != nil {
		return err
	}
	if out, err := run(15*time.Second, filepath.Join(dir, "cloudflared"), "--version"); err != nil {
		_ = os.RemoveAll(dir)
		return errors.New("cloudflared 在这台路由器上运行不了：" + firstLine(string(out)))
	} else {
		tunnelLog(firstLine(string(out)))
	}
	prev := tunnelCurrent()
	tmp := filepath.Join(tunnelDir, "current.new")
	_ = os.Remove(tmp)
	if err := os.Symlink(rel.Tag, tmp); err != nil {
		return err
	}
	if err := os.Rename(tmp, filepath.Join(tunnelDir, "current")); err != nil {
		return err
	}
	// keep only the previous version
	ents, _ := os.ReadDir(tunnelDir)
	var vers []string
	for _, e := range ents {
		if e.IsDir() && cfdVersionRe.MatchString(e.Name()) && e.Name() != rel.Tag && e.Name() != prev {
			vers = append(vers, e.Name())
		}
	}
	sort.Strings(vers)
	for _, v := range vers {
		_ = os.RemoveAll(filepath.Join(tunnelDir, v))
	}
	if err := writeTunnelInit(); err != nil {
		return err
	}
	if fi, err := os.Stat(filepath.Join(tunnelDir, "token")); err == nil && fi.Size() > 0 {
		tunnelLog("重启隧道…")
		_, _ = run(30*time.Second, tunnelInit, "restart")
	}
	return nil
}

const tunnelInitScript = `#!/bin/sh /etc/rc.common
# Wharf: Cloudflare Tunnel (written by owp-agent; removed with the package)
START=99
USE_PROCD=1
DIR=%s

start_service() {
	[ -x "$DIR/current/cloudflared" ] && [ -s "$DIR/token" ] || return 0
	procd_open_instance tunnel
	procd_set_param command "$DIR/current/cloudflared" tunnel --no-autoupdate --metrics %s run
	procd_set_param env TUNNEL_TOKEN="$(cat "$DIR/token")" WHARF_CFG="$(readlink "$DIR/current")"
	procd_set_param user nobody
	procd_set_param respawn 3600 5 0
	procd_set_param stdout 1
	procd_set_param stderr 1
	procd_close_instance
}
`

func writeTunnelInit() error {
	want := fmt.Sprintf(tunnelInitScript, tunnelDir, tunnelMetrics)
	if b, err := os.ReadFile(tunnelInit); err == nil && string(b) == want {
		return nil
	}
	if err := os.WriteFile(tunnelInit, []byte(want), 0o755); err != nil {
		return err
	}
	_, _ = run(10*time.Second, tunnelInit, "enable")
	return nil
}

// SetTunnelToken stores the token (empty: stop the tunnel and forget it) and restarts.
func SetTunnelToken(token string) error {
	tunnelMu.Lock()
	defer tunnelMu.Unlock()
	token = strings.TrimSpace(token)
	path := filepath.Join(tunnelDir, "token")
	if token == "" {
		if _, err := os.Stat(tunnelInit); err == nil {
			_, _ = run(30*time.Second, tunnelInit, "stop")
		}
		_ = os.Remove(path)
		return nil
	}
	if len(token) > 4096 || strings.ContainsAny(token, " \n\r\t\"'$`\\") {
		return errors.New("隧道令牌格式不对")
	}
	if _, err := os.Stat(cloudflaredBin()); err != nil {
		return errors.New("还没有安装 cloudflared")
	}
	if err := os.MkdirAll(tunnelDir, 0o755); err != nil {
		return err
	}
	if err := writeOwned(path, []byte(token), 0o600, 0, 0); err != nil { // read by the init script (root), handed over in the environment
		return err
	}
	if err := writeTunnelInit(); err != nil {
		return err
	}
	_, err := run(30*time.Second, tunnelInit, "restart")
	return err
}

func uninstallCloudflared() error {
	if _, err := os.Stat(tunnelInit); err == nil {
		_, _ = run(30*time.Second, tunnelInit, "stop")
		_, _ = run(10*time.Second, tunnelInit, "disable")
		_ = os.Remove(tunnelInit)
	}
	if strings.HasSuffix(tunnelDir, "-tunnel") {
		_ = os.RemoveAll(tunnelDir)
	}
	tunnelLog("已删除 cloudflared 和隧道令牌")
	return nil
}

func StartTunnelAction(action string) error {
	switch action {
	case "install", "update":
		return startTunnelJob(action, installCloudflared)
	case "uninstall":
		return startTunnelJob(action, uninstallCloudflared)
	case "restart":
		if _, err := os.Stat(tunnelInit); err != nil {
			return errors.New("隧道还没有设置")
		}
		_, err := run(30*time.Second, tunnelInit, "restart")
		return err
	}
	return errors.New("未知操作")
}

// tunnelCurrent: the version the "current" link points at.
func tunnelCurrent() string {
	t, err := os.Readlink(filepath.Join(tunnelDir, "current"))
	if err != nil {
		return ""
	}
	return filepath.Base(t)
}
