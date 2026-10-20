package panel

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/wangsirco/wharf/internal/release"
	"github.com/wangsirco/wharf/internal/version"
)

// Online update from GitHub Releases (update.repo, default wangsirco/wharf).
//
// Each release carries a signed manifest (internal/release) listing per-component
// fingerprints. The panel compares them with what it is running and updates only what
// changed:
//   - web:   the browser UI bundle (~1 MB) is unpacked into the data directory and served
//            immediately, no restart;
//   - core:  agent + panel + LuCI page, one ipk for this router's architecture, installed by
//            the agent through opkg (services restart for a few seconds, the network does not).
// The IP database and the content rules have always updated themselves separately.
// Nothing is applied without a valid signature, and only the super admin can apply.

const defaultRepo = "wangsirco/wharf"

type compStatus struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Desc    string `json:"desc"`
	Current string `json:"current"`          // short fingerprint / version running now
	Latest  string `json:"latest,omitempty"` // in the release
	Update  bool   `json:"update"`
	Size    int64  `json:"size,omitempty"` // download size
	Auto    bool   `json:"auto,omitempty"` // updates by itself (rules, geo)
	Note    string `json:"note,omitempty"`
}

type updateInfo struct {
	Current    string       `json:"current"`
	WebVersion string       `json:"web_version"` // differs from Current after a web-only update
	Repo       string       `json:"repo"`
	Latest     string       `json:"latest,omitempty"`
	Newer      bool         `json:"newer"` // something can be updated
	URL        string       `json:"url,omitempty"`
	Notes      string       `json:"notes,omitempty"`
	Published  int64        `json:"published,omitempty"`
	Checked    int64        `json:"checked,omitempty"`
	Error      string       `json:"error,omitempty"`
	Signed     bool         `json:"signed"`
	Arch       string       `json:"arch,omitempty"`
	Components []compStatus `json:"components"`
	Download   int64        `json:"download"` // bytes needed for the pending updates

	manifest *release.Manifest
	base     string // asset download base URL
}

var (
	updateMu  sync.Mutex
	updateNow updateInfo
	applyMu   sync.Mutex
	repoRe    = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,64}/[A-Za-z0-9_.-]{1,100}$`)
	githubAPI = "https://api.github.com"
	updateKey = version.UpdateKey
)

func validUpdateSetting(key, value string) (bool, error) {
	switch key {
	case "update.repo":
		if value != "" && !repoRe.MatchString(value) {
			return true, errors.New("仓库格式应为 用户名/仓库名，例如 wangsirco/wharf")
		}
		return true, nil
	case "update.check":
		if value != "0" && value != "1" {
			return true, errors.New("update.check 只能是 0 或 1")
		}
		return true, nil
	}
	return false, nil
}

// newerVersion compares "v1.2.3" style versions; non-numeric parts compare as 0.
func newerVersion(latest, current string) bool {
	parse := func(v string) [3]int {
		var out [3]int
		v = strings.TrimPrefix(strings.TrimSpace(v), "v")
		v, _, _ = strings.Cut(v, "-")
		for i, p := range strings.SplitN(v, ".", 3) {
			out[i], _ = strconv.Atoi(p)
		}
		return out
	}
	l, c := parse(latest), parse(current)
	for i := range l {
		if l[i] != c[i] {
			return l[i] > c[i]
		}
	}
	return false
}

func short(h string) string {
	if len(h) > 8 {
		return h[:8]
	}
	return h
}

func (a *App) updateRepo() string {
	if r := a.setting("update.repo"); r != "" {
		return r
	}
	return defaultRepo
}

func ghGet(url string, out any, limit int64) ([]byte, error) {
	req, _ := http.NewRequest("GET", url, nil)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("User-Agent", "wharf-panel/"+version.Version)
	resp, err := (&http.Client{Timeout: 60 * time.Second}).Do(req)
	if err != nil {
		return nil, fmt.Errorf("无法连接 GitHub：%s", shortErr(err))
	}
	defer resp.Body.Close()
	if resp.StatusCode == 404 {
		return nil, errors.New("仓库不存在、未公开，或还没有发布任何 Release")
	}
	if resp.StatusCode != 200 {
		return nil, errors.New("GitHub 返回 " + resp.Status)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, limit))
	if err != nil {
		return nil, err
	}
	if out != nil {
		return b, json.Unmarshal(b, out)
	}
	return b, nil
}

func (a *App) checkUpdate() updateInfo {
	ws := a.webState()
	info := updateInfo{Current: version.Version, WebVersion: ws.version, Repo: a.updateRepo(), Checked: time.Now().Unix()}
	var rel struct {
		Tag       string    `json:"tag_name"`
		URL       string    `json:"html_url"`
		Body      string    `json:"body"`
		Published time.Time `json:"published_at"`
		Assets    []struct {
			Name string `json:"name"`
			URL  string `json:"browser_download_url"`
		} `json:"assets"`
	}
	if _, err := ghGet(fmt.Sprintf("%s/repos/%s/releases/latest", githubAPI, info.Repo), &rel, 4<<20); err != nil {
		info.Error = err.Error()
	} else if rel.Tag == "" {
		info.Error = "无法解析 GitHub 的返回"
	} else {
		info.Latest, info.URL, info.Published = rel.Tag, rel.URL, rel.Published.Unix()
		info.Notes = truncate(rel.Body, 4000)
		var mURL, sURL string
		for _, as := range rel.Assets {
			switch as.Name {
			case release.ManifestName:
				mURL = as.URL
			case release.SigName:
				sURL = as.URL
			}
		}
		if mURL != "" && sURL != "" {
			if m, err := fetchManifest(mURL, sURL); err != nil {
				info.Error = err.Error()
			} else {
				info.manifest, info.Signed = m, true
				info.base = mURL[:strings.LastIndex(mURL, "/")+1]
			}
		} else {
			info.Error = "这个 Release 没有签名清单，只能手动下载安装"
		}
		info.Newer = newerVersion(rel.Tag, version.Version) && info.manifest == nil
	}
	a.fillComponents(&info)
	updateMu.Lock()
	updateNow = info
	updateMu.Unlock()
	return info
}

func fetchManifest(mURL, sURL string) (*release.Manifest, error) {
	mb, err := ghGet(mURL, nil, 1<<20)
	if err != nil {
		return nil, err
	}
	sig, err := ghGet(sURL, nil, 4096)
	if err != nil {
		return nil, err
	}
	if err := release.Verify(mb, sig, updateKey); err != nil {
		return nil, err
	}
	var m release.Manifest
	if err := json.Unmarshal(mb, &m); err != nil {
		return nil, errors.New("更新清单格式错误")
	}
	return &m, nil
}

// fillComponents decides, component by component, what differs from the running version.
func (a *App) fillComponents(info *updateInfo) {
	ws := a.webState()
	var ping struct {
		Version  string `json:"version"`
		CoreHash string `json:"core_hash"`
		Arch     string `json:"arch"`
	}
	_ = a.agent.Do("GET", "/v1/ping", nil, &ping)
	info.Arch = ping.Arch
	core := compStatus{ID: "core", Name: "程序核心", Desc: "路由器代理 + 面板后端 + LuCI 页面（含当时的网页界面）", Current: version.Version + " · " + short(version.CoreHash)}
	web := compStatus{ID: "web", Name: "网页界面", Desc: "浏览器里看到的所有页面，更新后刷新即生效，无需重启", Current: ws.version + " · " + short(ws.hash)}
	if m := info.manifest; m != nil {
		core.Latest = m.Version + " · " + short(m.Core.Hash)
		web.Latest = m.Version + " · " + short(m.Web.Hash)
		coreChanged := m.Core.Hash != version.CoreHash || (ping.CoreHash != "" && ping.CoreHash != m.Core.Hash)
		if version.CoreHash == "dev" { // a local build: compare by version only
			coreChanged = newerVersion(m.Version, version.Version)
		}
		if coreChanged && newerVersion(m.Version, version.Version) {
			core.Update = true
			if p, ok := m.Core.Packages[ping.Arch]; ok {
				core.Size = p.Size
			} else {
				core.Note = "这个版本没有提供 " + ping.Arch + " 架构的安装包，请手动更新"
				core.Update = false
			}
		}
		if m.Web.Hash != ws.hash && newerVersion(m.Version, ws.version) {
			web.Update = true
			web.Size = m.Web.Asset.Size
			if core.Update {
				web.Note = "会随程序核心一起更新"
				web.Size = 0
			}
		}
		info.Newer = core.Update || web.Update
		info.Download = core.Size + web.Size
	}
	info.Components = []compStatus{core, web,
		{ID: "rules", Name: "内容识别规则库", Desc: "识别抖音、YouTube、AI 等服务的规则", Auto: true, Current: a.rulesLabel(), Note: "每 " + a.setting("rules.update_hours") + " 小时自动从 GitHub 更新"},
		{ID: "geo", Name: "IP 地理与运营商库", Desc: "DB-IP Lite（City + ASN）", Auto: true, Current: a.geoVersion(), Note: "每月自动更新"},
	}
}

func (a *App) geoVersion() string {
	if st, err := os.Stat(a.cfg.Path("geo/dbip-city-lite.mmdb")); err == nil {
		return st.ModTime().Format("2006-01-02")
	}
	return "—"
}

func (a *App) updateLoop() {
	time.Sleep(3 * time.Minute)
	for {
		if a.setting("update.check") != "0" {
			if info := a.checkUpdate(); info.Error != "" {
				log.Printf("update check: %s", info.Error)
			}
		}
		time.Sleep(12 * time.Hour)
	}
}

// GET /api/update — last check (super). POST /api/update/check — check now.
func (a *App) handleUpdate(w http.ResponseWriter, r *http.Request) {
	updateMu.Lock()
	info := updateNow
	updateMu.Unlock()
	info.Current, info.Repo, info.WebVersion = version.Version, a.updateRepo(), a.webState().version
	if info.Checked == 0 {
		a.fillComponents(&info)
	}
	writeJSON(w, 200, info)
}

func (a *App) handleUpdateCheck(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, 200, a.checkUpdate())
}

// POST /api/update/apply — update what changed (super, audited).
func (a *App) handleUpdateApply(w http.ResponseWriter, r *http.Request) {
	if !applyMu.TryLock() {
		jsonErr(w, 409, "已有更新在进行")
		return
	}
	defer applyMu.Unlock()
	info := a.checkUpdate() // always re-fetch and re-verify the signed manifest
	if info.manifest == nil {
		jsonErr(w, 400, firstNonEmpty(info.Error, "没有可用的签名更新"))
		return
	}
	m := info.manifest
	ac := actor{user: currentUser(r), ip: a.clientIP(r)}
	var core, web compStatus
	for _, c := range info.Components {
		switch c.ID {
		case "core":
			core = c
		case "web":
			web = c
		}
	}
	switch {
	case core.Update:
		p := m.Core.Packages[info.Arch]
		var st json.RawMessage
		if err := a.agent.Do("POST", "/v1/update/core", map[string]any{"url": info.base + p.Name, "sha256": p.SHA256, "size": p.Size}, &st); err != nil {
			jsonErr(w, 502, agentMsg(err))
			return
		}
		a.audit(ac, "update.core", "system", m.Version, fmt.Sprintf("在线更新程序核心 %s → %s（%s）", version.Version, m.Version, p.Name), nil, nil, false)
		writeJSON(w, 200, map[string]any{"core": true, "status": st})
	case web.Update:
		if err := a.installWeb(info.base, m); err != nil {
			jsonErr(w, 502, err.Error())
			return
		}
		a.audit(ac, "update.web", "system", m.Version, fmt.Sprintf("在线更新网页界面 → %s（%s）", m.Version, short(m.Web.Hash)), nil, nil, false)
		writeJSON(w, 200, map[string]any{"web": true, "version": m.Version})
	default:
		jsonErr(w, 400, "已是最新，没有需要更新的组件")
	}
}

// GET /api/update/status — progress of a program update (survives the restart).
func (a *App) handleUpdateStatus(w http.ResponseWriter, r *http.Request) {
	var st json.RawMessage
	if err := a.agent.Do("GET", "/v1/update/core", nil, &st); err != nil {
		jsonErr(w, 502, agentMsg(err))
		return
	}
	writeJSON(w, 200, map[string]any{"core": st, "current": version.Version, "web_version": a.webState().version})
}

// POST /api/update/rollback-web — go back to the UI built into the program.
func (a *App) handleUpdateRollbackWeb(w http.ResponseWriter, r *http.Request) {
	old := a.webState().version
	a.dropWebOverride()
	a.audit(actor{user: currentUser(r), ip: a.clientIP(r)}, "update.web_rollback", "system", old, "网页界面恢复为程序内置版本 "+version.Version, nil, nil, false)
	writeJSON(w, 200, map[string]any{"ok": true})
}

// ---- web UI overlay ----

type webState struct {
	fs       fs.FS
	hash     string
	version  string
	override bool
}

type webMeta struct {
	Version string `json:"version"`
	Hash    string `json:"hash"`
	Dir     string `json:"dir"`
}

func (a *App) webDir() string { return a.cfg.Path("web") }

func (a *App) webState() *webState {
	if s := a.webCur.Load(); s != nil {
		return s
	}
	h, _ := release.WebHash(a.web)
	s := &webState{fs: a.web, hash: h, version: version.Version}
	a.webCur.Store(s)
	return s
}

// loadWebOverride switches to a downloaded UI if it is newer than the built-in one.
func (a *App) loadWebOverride() {
	b, err := os.ReadFile(filepath.Join(a.webDir(), "current.json"))
	if err != nil {
		return
	}
	var m webMeta
	if json.Unmarshal(b, &m) != nil || !newerVersion(m.Version, version.Version) {
		a.dropWebOverride() // the program caught up (or the file is bad): use the built-in UI
		return
	}
	dir := filepath.Join(a.webDir(), m.Dir)
	fsys := os.DirFS(dir)
	if h, err := release.WebHash(fsys); err != nil || h != m.Hash {
		log.Printf("web override %s is damaged, ignoring", dir)
		a.dropWebOverride()
		return
	}
	a.webCur.Store(&webState{fs: fsys, hash: m.Hash, version: m.Version, override: true})
	log.Printf("serving web UI %s from %s", m.Version, dir)
}

func (a *App) dropWebOverride() {
	_ = os.RemoveAll(a.webDir())
	a.webCur.Store(nil)
	_ = a.webState()
}

func (a *App) installWeb(base string, m *release.Manifest) error {
	body, err := ghGet(base+m.Web.Asset.Name, nil, 64<<20)
	if err != nil {
		return err
	}
	if fmt.Sprintf("%x", sha256Sum(body)) != m.Web.Asset.SHA256 {
		return errors.New("网页包校验失败，已放弃")
	}
	name := m.Version + "-" + short(m.Web.Hash)
	tmp := filepath.Join(a.webDir(), "."+name)
	_ = os.RemoveAll(tmp)
	if err := os.MkdirAll(tmp, 0o755); err != nil {
		return err
	}
	if err := release.ExtractWeb(bytes.NewReader(body), tmp); err != nil {
		_ = os.RemoveAll(tmp)
		return err
	}
	if h, err := release.WebHash(os.DirFS(tmp)); err != nil || h != m.Web.Hash {
		_ = os.RemoveAll(tmp)
		return errors.New("网页包内容与清单不一致，已放弃")
	}
	dst := filepath.Join(a.webDir(), name)
	_ = os.RemoveAll(dst)
	if err := os.Rename(tmp, dst); err != nil {
		return err
	}
	meta, _ := json.Marshal(webMeta{Version: m.Version, Hash: m.Web.Hash, Dir: name})
	if err := os.WriteFile(filepath.Join(a.webDir(), "current.json"), meta, 0o644); err != nil {
		return err
	}
	// keep only the active bundle
	if entries, err := os.ReadDir(a.webDir()); err == nil {
		for _, e := range entries {
			if e.IsDir() && e.Name() != name {
				_ = os.RemoveAll(filepath.Join(a.webDir(), e.Name()))
			}
		}
	}
	a.webCur.Store(&webState{fs: os.DirFS(dst), hash: m.Web.Hash, version: m.Version, override: true})
	return nil
}

func sha256Sum(b []byte) [32]byte { return sha256.Sum256(b) }

func (a *App) rulesLabel() string {
	if v := a.rulesVersion(); v != "" {
		return v
	}
	return "内置"
}
