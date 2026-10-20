package agent

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"net/http"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/wangsirco/wharf/internal/release"
)

// Online program update: download one release ipk, check it against the SHA-256 from the
// signed manifest (verified by the panel), then let opkg install it in a separate session —
// the package's postinst restarts this agent, and the install must outlive it.

const (
	updIPK = "/tmp/wharf-update.ipk"
	updLog = "/tmp/wharf-update.log"
)

var goarm = "" // set with -ldflags for GOARCH=arm builds

// PkgArch is the opkg architecture this binary was built for.
func PkgArch() string { return release.PkgArch(runtime.GOARCH, goarm) }

var updMu sync.Mutex

type CoreUpdate struct {
	Running bool     `json:"running"`
	Done    bool     `json:"done"`
	OK      bool     `json:"ok"`
	Log     []string `json:"log"`
	Started int64    `json:"started"`
}

func CoreUpdateStatus() CoreUpdate {
	var st CoreUpdate
	b, err := os.ReadFile(updLog)
	if err != nil {
		return st
	}
	if fi, err := os.Stat(updLog); err == nil {
		st.Started = fi.ModTime().Unix()
	}
	for _, l := range strings.Split(strings.TrimSpace(string(b)), "\n") {
		if strings.HasPrefix(l, "exit=") {
			st.Done, st.OK = true, l == "exit=0"
			continue
		}
		if l = strings.TrimSpace(l); l != "" {
			st.Log = append(st.Log, l)
		}
	}
	if len(st.Log) > 200 {
		st.Log = st.Log[len(st.Log)-200:]
	}
	st.Running = !st.Done && st.Log != nil
	return st
}

// StartCoreUpdate downloads the ipk and hands it to opkg.
func StartCoreUpdate(url, sum string, size int64) error {
	if !updMu.TryLock() {
		return errors.New("已有更新在进行")
	}
	defer updMu.Unlock()
	if st := CoreUpdateStatus(); st.Running && time.Since(time.Unix(st.Started, 0)) < 10*time.Minute {
		return errors.New("已有更新在进行")
	}
	if !strings.HasPrefix(url, "https://github.com/") || !strings.Contains(url, "/releases/download/") {
		return errors.New("只接受 GitHub Release 的下载地址")
	}
	if len(sum) != 64 {
		return errors.New("缺少校验值")
	}
	log := func(s string) {
		f, err := os.OpenFile(updLog, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
		if err == nil {
			_, _ = f.WriteString(time.Now().Format("15:04:05 ") + s + "\n")
			f.Close()
		}
	}
	_ = os.Remove(updLog)
	log("下载 " + url[strings.LastIndex(url, "/")+1:])
	resp, err := (&http.Client{Timeout: 5 * time.Minute}).Get(url)
	if err != nil {
		log("下载失败：" + err.Error())
		log("exit=1")
		return errors.New("下载失败：路由器无法访问 GitHub")
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		log("下载失败：" + resp.Status)
		log("exit=1")
		return errors.New("下载失败：" + resp.Status)
	}
	f, err := os.OpenFile(updIPK, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	h := sha256.New()
	n, err := io.Copy(io.MultiWriter(f, h), io.LimitReader(resp.Body, 128<<20))
	f.Close()
	if err != nil || (size > 0 && n != size) || hex.EncodeToString(h.Sum(nil)) != sum {
		_ = os.Remove(updIPK)
		log("校验失败：文件不完整或被篡改，已放弃")
		log("exit=1")
		return errors.New("安装包校验失败，已放弃更新")
	}
	log("校验通过，开始安装（服务会自动重启，约 10 秒）")
	// a new session, so the opkg run survives the service restart it triggers
	cmd := exec.Command("/bin/sh", "-c", "sleep 1; opkg install "+updIPK+" >> "+updLog+" 2>&1; echo \"exit=$?\" >> "+updLog+"; rm -f "+updIPK)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	cmd.Stdin, cmd.Stdout, cmd.Stderr = nil, nil, nil
	if err := cmd.Start(); err != nil {
		log("无法启动 opkg：" + err.Error())
		log("exit=1")
		return err
	}
	go func() { _ = cmd.Wait() }()
	return nil
}
