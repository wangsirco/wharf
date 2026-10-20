package agent

import (
	"bufio"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
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

// Packet capture: tcpdump writes a pcap into RAM (/tmp), bounded by time and size; the
// panel shows live progress, an analysis (see pcapan.go) and offers the file for Wireshark.

const (
	capDir      = "/tmp/owp-pcap"
	capKeep     = 12        // captures kept
	capTotalMax = 600 << 20 // bytes across all kept captures
)

type CaptureReq struct {
	Iface     string `json:"iface"`
	Host      string `json:"host"`       // IP of a device / remote
	MAC       string `json:"mac"`        //
	Port      int    `json:"port"`       //
	Proto     string `json:"proto"`      // tcp | udp | icmp | dns | arp | ""
	Filter    string `json:"filter"`     // raw BPF, ANDed with the above
	Snap      int    `json:"snap"`       // 0 = full packets
	Secs      int    `json:"secs"`       // ≤ 1800
	MaxMB     int    `json:"max_mb"`     // ≤ 200
	SkipPanel bool   `json:"skip_panel"` // leave out the panel's / agent's own traffic
	Note      string `json:"note"`
	By        string `json:"by"`
}

type Capture struct {
	ID      string `json:"id"`
	Iface   string `json:"iface"`
	Filter  string `json:"filter"`
	Note    string `json:"note"`
	By      string `json:"by"`
	Snap    int    `json:"snap"`
	Secs    int    `json:"secs"`
	MaxMB   int    `json:"max_mb"`
	Started int64  `json:"started"`
	Ended   int64  `json:"ended,omitempty"`
	Size    int64  `json:"size"`
	Packets int64  `json:"packets"`
	Dropped int64  `json:"dropped"`
	Running bool   `json:"running"`
	Reason  string `json:"reason,omitempty"` // time | size | stopped | error
	Error   string `json:"error,omitempty"`
}

var captures struct {
	sync.Mutex
	list []*Capture
	proc map[string]*exec.Cmd
	stop map[string]chan string
}

var (
	capIDRe  = regexp.MustCompile(`^[0-9a-f]{12}$`)
	bpfBad   = regexp.MustCompile("[;&|`$<>\\\\\n\r]")
	ifaceRe  = regexp.MustCompile(`^[A-Za-z0-9_.@-]{1,15}$`)
	tdStatRe = regexp.MustCompile(`(\d+) packets? (captured|dropped by kernel)`)
)

// CaptureIface is an interface offered for capture, with what it sees.
type CaptureIface struct {
	Name  string `json:"name"`
	Label string `json:"label"`
	Hint  string `json:"hint"`
}

func CaptureIfaces() []CaptureIface {
	lan := uciGetOption("network", "lan", "device")
	wan := uciGetOption("network", "wan", "device")
	var out []CaptureIface
	if lan != "" {
		out = append(out, CaptureIface{lan, "局域网 " + lan, "看得到每台设备自己的 IP（NAT 之前），排查某台设备用这个"})
	}
	if wan != "" {
		out = append(out, CaptureIface{wan, "外网 " + wan, "运营商线路上的真实收发（NAT 之后，源地址都是公网 IP），排查国际线路、运营商问题用这个"})
	}
	out = append(out, CaptureIface{"any", "全部接口", "同时抓所有接口（同一个包可能出现两次：进 LAN、出 WAN）"})
	ifs, _ := net.Interfaces()
	for _, i := range ifs {
		if i.Name == lan || i.Name == wan || i.Name == "lo" || i.Flags&net.FlagUp == 0 {
			continue
		}
		out = append(out, CaptureIface{i.Name, i.Name, ""})
	}
	return out
}

func buildFilter(r CaptureReq) (string, error) {
	var parts []string
	if r.Host != "" {
		ip := net.ParseIP(strings.TrimSpace(r.Host))
		if ip == nil {
			return "", errors.New("IP 地址无效")
		}
		parts = append(parts, "host "+ip.String())
	}
	if r.MAC != "" {
		hw, err := net.ParseMAC(strings.TrimSpace(r.MAC))
		if err != nil {
			return "", errors.New("MAC 地址无效")
		}
		parts = append(parts, "ether host "+hw.String())
	}
	if r.Port > 0 {
		if r.Port > 65535 {
			return "", errors.New("端口无效")
		}
		parts = append(parts, "port "+strconv.Itoa(r.Port))
	}
	switch r.Proto {
	case "":
	case "tcp", "udp", "icmp", "arp":
		parts = append(parts, r.Proto)
	case "dns":
		parts = append(parts, "port 53")
	default:
		return "", errors.New("协议无效")
	}
	if f := strings.TrimSpace(r.Filter); f != "" {
		if len(f) > 300 || bpfBad.MatchString(f) || strings.HasPrefix(f, "-") {
			return "", errors.New("过滤表达式含有不允许的字符")
		}
		parts = append(parts, "("+f+")")
	}
	if r.SkipPanel {
		parts = append(parts, "not (tcp port 7080 or tcp port 7071 or tcp port 22)")
	}
	return strings.Join(parts, " and "), nil
}

func newCapID() string {
	b := make([]byte, 6)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func capPath(id string) string { return filepath.Join(capDir, id+".pcap") }

func StartCapture(r CaptureReq) (*Capture, error) {
	if _, err := exec.LookPath("tcpdump"); err != nil {
		return nil, errors.New("路由器上没有 tcpdump（opkg install tcpdump）")
	}
	if r.Iface == "" || !ifaceRe.MatchString(r.Iface) {
		return nil, errors.New("接口无效")
	}
	if r.Iface != "any" {
		if _, err := net.InterfaceByName(r.Iface); err != nil {
			return nil, errors.New("接口不存在")
		}
	}
	filter, err := buildFilter(r)
	if err != nil {
		return nil, err
	}
	// let tcpdump compile the expression first: a syntax error should be a clear message, not a dead capture
	args := []string{"-i", r.Iface, "-d"}
	if filter != "" {
		args = append(args, filter)
	}
	if out, err := run(5*time.Second, "tcpdump", args...); err != nil {
		msg := strings.TrimSpace(string(out))
		if i := strings.LastIndex(err.Error(), ": "); i > 0 {
			msg = strings.TrimSpace(err.Error()[i+2:])
		}
		return nil, fmt.Errorf("过滤表达式有误：%s", truncateStr(msg, 200))
	}
	captures.Lock()
	defer captures.Unlock()
	if captures.proc == nil {
		captures.proc, captures.stop = map[string]*exec.Cmd{}, map[string]chan string{}
	}
	if len(captures.proc) >= 2 {
		return nil, errors.New("已有两个抓包在进行，请先停止一个")
	}
	_ = os.MkdirAll(capDir, 0o700)
	c := &Capture{ID: newCapID(), Iface: r.Iface, Filter: filter, Note: truncateStr(r.Note, 120), By: r.By,
		Snap: r.Snap, Secs: clamp(r.Secs, 5, 1800, 60), MaxMB: clamp(r.MaxMB, 1, 200, 20), Started: time.Now().Unix(), Running: true}
	snap := "0"
	if r.Snap > 0 {
		snap = strconv.Itoa(max(64, min(r.Snap, 65535)))
	}
	args = []string{"-i", r.Iface, "-n", "-U", "-s", snap, "-w", capPath(c.ID)}
	if filter != "" {
		args = append(args, filter)
	}
	cmd := exec.Command("tcpdump", args...)
	stderr, _ := cmd.StderrPipe()
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	stop := make(chan string, 1)
	captures.proc[c.ID], captures.stop[c.ID] = cmd, stop
	captures.list = append([]*Capture{c}, captures.list...)
	pruneCaptures()
	go watchCapture(c, cmd, stderr, stop)
	cp := *c
	return &cp, nil
}

func watchCapture(c *Capture, cmd *exec.Cmd, stderr interface{ Read([]byte) (int, error) }, stop chan string) {
	var tail []string
	done := make(chan struct{})
	go func() {
		sc := bufio.NewScanner(stderr)
		for sc.Scan() {
			tail = append(tail, sc.Text())
			if len(tail) > 20 {
				tail = tail[1:]
			}
		}
		close(done)
	}()
	exited := make(chan error, 1)
	go func() { <-done; exited <- cmd.Wait() }()
	deadline := time.Now().Add(time.Duration(c.Secs) * time.Second)
	tick := time.NewTicker(time.Second)
	defer tick.Stop()
	reason := ""
loop:
	for {
		select {
		case reason = <-stop:
			break loop
		case err := <-exited:
			reason = "error"
			if err == nil {
				reason = "stopped"
			}
			exited <- err
			break loop
		case <-tick.C:
			if st, err := os.Stat(capPath(c.ID)); err == nil {
				captures.Lock()
				c.Size = st.Size()
				captures.Unlock()
				if st.Size() >= int64(c.MaxMB)<<20 {
					reason = "size"
					break loop
				}
			}
			if time.Now().After(deadline) {
				reason = "time"
				break loop
			}
		}
	}
	_ = cmd.Process.Signal(syscall.SIGINT) // tcpdump flushes and prints its counters
	var err error
	select {
	case err = <-exited:
	case <-time.After(5 * time.Second):
		_ = cmd.Process.Kill()
		err = <-exited
	}
	captures.Lock()
	defer captures.Unlock()
	delete(captures.proc, c.ID)
	delete(captures.stop, c.ID)
	c.Running, c.Ended, c.Reason = false, time.Now().Unix(), reason
	for _, l := range tail {
		if m := tdStatRe.FindStringSubmatch(l); m != nil {
			n, _ := strconv.ParseInt(m[1], 10, 64)
			if m[2] == "captured" {
				c.Packets = n
			} else {
				c.Dropped = n
			}
		}
	}
	if st, e := os.Stat(capPath(c.ID)); e == nil {
		c.Size = st.Size()
	}
	if reason == "error" && err != nil && c.Packets == 0 {
		c.Error = truncateStr(strings.Join(tail, " "), 300)
	}
}

func StopCapture(id string) error {
	captures.Lock()
	ch := captures.stop[id]
	captures.Unlock()
	if ch == nil {
		return errors.New("抓包未在运行")
	}
	select {
	case ch <- "stopped":
	default:
	}
	for i := 0; i < 60; i++ { // wait for tcpdump to finish writing
		time.Sleep(100 * time.Millisecond)
		if c := findCapture(id); c != nil && !c.Running {
			break
		}
	}
	return nil
}

func DeleteCapture(id string) error {
	if !capIDRe.MatchString(id) {
		return errors.New("bad id")
	}
	_ = StopCapture(id)
	captures.Lock()
	defer captures.Unlock()
	for i, c := range captures.list {
		if c.ID == id {
			captures.list = append(captures.list[:i], captures.list[i+1:]...)
			break
		}
	}
	_ = os.Remove(capPath(id))
	analysisCache.Delete(id)
	return nil
}

func findCapture(id string) *Capture {
	captures.Lock()
	defer captures.Unlock()
	for _, c := range captures.list {
		if c.ID == id {
			cp := *c
			return &cp
		}
	}
	return nil
}

func ListCaptures() []Capture {
	captures.Lock()
	defer captures.Unlock()
	out := make([]Capture, 0, len(captures.list))
	for _, c := range captures.list {
		cp := *c
		if cp.Running {
			if st, err := os.Stat(capPath(c.ID)); err == nil {
				cp.Size = st.Size()
			}
		}
		out = append(out, cp)
	}
	return out
}

// pruneCaptures drops the oldest finished captures beyond the count / size budget. Caller holds the lock.
func pruneCaptures() {
	var total int64
	keep := captures.list[:0]
	for i, c := range captures.list {
		total += c.Size
		if !c.Running && (i >= capKeep || total > capTotalMax) {
			_ = os.Remove(capPath(c.ID))
			analysisCache.Delete(c.ID)
			continue
		}
		keep = append(keep, c)
	}
	captures.list = keep
	// stray files from before an agent restart
	files, _ := filepath.Glob(filepath.Join(capDir, "*.pcap"))
	known := map[string]bool{}
	for _, c := range captures.list {
		known[capPath(c.ID)] = true
	}
	sort.Strings(files)
	for _, f := range files {
		if !known[f] {
			_ = os.Remove(f)
		}
	}
}

// CaptureFile opens a finished capture for download.
func CaptureFile(id string) (*os.File, *Capture, error) {
	if !capIDRe.MatchString(id) {
		return nil, nil, errors.New("bad id")
	}
	c := findCapture(id)
	if c == nil {
		return nil, nil, errors.New("抓包不存在或已被清理")
	}
	f, err := os.Open(capPath(id))
	return f, c, err
}

func truncateStr(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}
