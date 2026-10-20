package agent

import (
	"bufio"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

// System maintenance: hardware status, plugin services, logs, reboot, config
// backup / restore, scheduled reboot, UPnP and Wake-on-LAN. Everything that
// changes the router is limited to explicit allowlists.

// ---- hardware status ----

type DiskStat struct {
	Mount string `json:"mount"`
	Dev   string `json:"dev"`
	Total uint64 `json:"total"`
	Used  uint64 `json:"used"`
}

type TempStat struct {
	Name string  `json:"name"`
	C    float64 `json:"c"`
}

type HWStats struct {
	CPUModel string     `json:"cpu_model"`
	Cores    int        `json:"cores"`
	CPU      float64    `json:"cpu"`      // percent busy over the sample window
	PerCore  []float64  `json:"per_core"` // percent per core
	Temps    []TempStat `json:"temps"`
	Disks    []DiskStat `json:"disks"`
}

func cpuTimes() map[string][2]uint64 { // name -> [busy, total]
	out := map[string][2]uint64{}
	f, err := os.Open("/proc/stat")
	if err != nil {
		return out
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		fs := strings.Fields(sc.Text())
		if len(fs) < 5 || !strings.HasPrefix(fs[0], "cpu") {
			continue
		}
		var total, idle uint64
		for i, v := range fs[1:] {
			n, _ := strconv.ParseUint(v, 10, 64)
			total += n
			if i == 3 || i == 4 { // idle, iowait
				idle += n
			}
		}
		out[fs[0]] = [2]uint64{total - idle, total}
	}
	return out
}

func pct(a, b [2]uint64) float64 {
	if b[1] <= a[1] {
		return 0
	}
	return round1(float64(b[0]-a[0]) * 100 / float64(b[1]-a[1]))
}

func GetHW() HWStats {
	var h HWStats
	t0 := cpuTimes()
	time.Sleep(400 * time.Millisecond)
	t1 := cpuTimes()
	h.CPU = pct(t0["cpu"], t1["cpu"])
	for i := 0; ; i++ {
		k := "cpu" + strconv.Itoa(i)
		if _, ok := t1[k]; !ok {
			break
		}
		h.PerCore = append(h.PerCore, pct(t0[k], t1[k]))
	}
	h.Cores = len(h.PerCore)
	for _, line := range strings.Split(readTrim("/proc/cpuinfo"), "\n") {
		if k, v, ok := strings.Cut(line, ":"); ok && strings.TrimSpace(k) == "model name" {
			h.CPUModel = strings.TrimSpace(v)
			break
		}
	}
	// temperatures: thermal zones, then hwmon sensors
	zones, _ := filepath.Glob("/sys/class/thermal/thermal_zone*/temp")
	for _, z := range zones {
		if v := readInt(z); v > 0 {
			h.Temps = append(h.Temps, TempStat{Name: readTrim(filepath.Join(filepath.Dir(z), "type")), C: round1(float64(v) / 1000)})
		}
	}
	mons, _ := filepath.Glob("/sys/class/hwmon/hwmon*/temp*_input")
	for _, m := range mons {
		if v := readInt(m); v > 0 {
			name := readTrim(filepath.Join(filepath.Dir(m), "name"))
			if l := readTrim(strings.TrimSuffix(m, "_input") + "_label"); l != "" {
				name += " " + l
			}
			h.Temps = append(h.Temps, TempStat{Name: name, C: round1(float64(v) / 1000)})
		}
	}
	h.Disks = disks()
	return h
}

func disks() []DiskStat {
	out, _ := run(5*time.Second, "df", "-kP")
	seen := map[string]bool{}
	var res []DiskStat
	for i, line := range strings.Split(string(out), "\n") {
		fs := strings.Fields(line)
		if i == 0 || len(fs) < 6 {
			continue
		}
		dev, mount := fs[0], fs[5]
		if !strings.HasPrefix(dev, "/dev/") || dev == "/dev/root" || seen[dev] { // "/" overlay = /overlay, listed once
			continue
		}
		if strings.HasPrefix(mount, "/overlay/upper") || strings.HasPrefix(mount, "/opt/docker") {
			continue
		}
		seen[dev] = true
		total, _ := strconv.ParseUint(fs[1], 10, 64)
		used, _ := strconv.ParseUint(fs[2], 10, 64)
		res = append(res, DiskStat{Mount: mount, Dev: dev, Total: total * 1024, Used: used * 1024})
	}
	return res
}

// ---- plugin services ----

type svcDef struct {
	Name     string // init script
	Label    string
	Desc     string
	UCI      string // config.section.option holding the plugin's own on/off switch
	Critical bool   // turning it off can break DNS / internet for everyone
}

var services = []svcDef{
	{"nextdns", "NextDNS", "加密 DNS 上游，dnsmasq 通过它解析", "nextdns.main.enabled", true},
	{"openclash", "OpenClash", "代理 / 分流", "openclash.config.enable", true},
	{"passwall", "PassWall", "代理 / 分流", "passwall.@global[0].enabled", true},
	{"passwall2", "PassWall 2", "代理 / 分流", "passwall2.@global[0].enabled", true},
	{"smartdns", "SmartDNS", "DNS 加速", "smartdns.@smartdns[0].enabled", true},
	{"mwan3", "多线负载均衡", "mwan3 多 WAN 分流", "", true},
	{"dockerd", "Docker", "容器引擎", "", false},
	{"miniupnpd", "UPnP / NAT-PMP", "允许局域网设备自动映射端口", "upnpd.config.enabled", false},
	{"ddns", "动态域名 DDNS", "", "", false},
	{"ddnsto", "DDNSTO", "远程穿透", "ddnsto.@ddnsto[0].enabled", false},
	{"appfilter", "应用过滤", "OpenAppFilter", "appfilter.global.enable", false},
	{"naiveproxy", "NaiveProxy", "", "naiveproxy.config.enable", false},
	{"samba4", "Samba 文件共享", "", "", false},
	{"unishare", "统一文件共享", "", "unishare.@global[0].enabled", false},
	{"webdav2", "WebDAV", "", "webdav2.@global[0].enabled", false},
	{"linkease", "易有云", "", "linkease.@linkease[0].enabled", false},
	{"homebox", "内网测速 Homebox", "", "homebox.@homebox[0].enabled", false},
	{"ttyd", "网页终端 ttyd", "", "", false},
	{"nlbwmon", "带宽监控 nlbwmon", "", "", false},
	{"avahi-daemon", "mDNS（Avahi）", "", "", false},
	{"wsdd2", "Windows 网络发现", "", "", false},
}

type SvcStatus struct {
	Name     string `json:"name"`
	Label    string `json:"label"`
	Desc     string `json:"desc,omitempty"`
	Enabled  bool   `json:"enabled"`
	Running  bool   `json:"running"`
	Critical bool   `json:"critical,omitempty"`
}

func svcDefOf(name string) (svcDef, bool) {
	for _, d := range services {
		if d.Name == name {
			return d, true
		}
	}
	return svcDef{}, false
}

func uciValue(path string) string {
	out, _ := run(3*time.Second, "uci", "-q", "get", path)
	return strings.TrimSpace(string(out))
}

func Services() []SvcStatus {
	var rc map[string]struct {
		Enabled bool `json:"enabled"`
		Running bool `json:"running"`
	}
	_ = ubusCall("rc", "list", nil, &rc)
	out := []SvcStatus{}
	for _, d := range services {
		if _, err := os.Stat("/etc/init.d/" + d.Name); err != nil {
			continue
		}
		st := rc[d.Name]
		s := SvcStatus{Name: d.Name, Label: d.Label, Desc: d.Desc, Running: st.Running, Critical: d.Critical, Enabled: st.Enabled}
		if d.UCI != "" {
			s.Enabled = st.Enabled && uciValue(d.UCI) == "1"
		}
		out = append(out, s)
	}
	return out
}

// ServiceAction turns a plugin on/off or restarts it. Plugins with their own
// switch are toggled the way LuCI does it: flip the uci option, then (re)start.
func ServiceAction(name, action string) (SvcStatus, error) {
	d, ok := svcDefOf(name)
	if !ok {
		return SvcStatus{}, errors.New("不支持的服务")
	}
	init := "/etc/init.d/" + d.Name
	if _, err := os.Stat(init); err != nil {
		return SvcStatus{}, errors.New("服务未安装")
	}
	sh := func(args ...string) error {
		if out, err := run(90*time.Second, args[0], args[1:]...); err != nil {
			return fmt.Errorf("%s: %v %s", strings.Join(args, " "), err, strings.TrimSpace(string(out)))
		}
		return nil
	}
	var err error
	switch action {
	case "on":
		if d.UCI != "" {
			if err = sh("uci", "set", d.UCI+"=1"); err == nil {
				err = sh("uci", "commit", strings.SplitN(d.UCI, ".", 2)[0])
			}
		}
		if err == nil {
			_ = sh(init, "enable")
			err = sh(init, "restart")
		}
	case "off":
		if d.UCI != "" {
			if err = sh("uci", "set", d.UCI+"=0"); err == nil {
				err = sh("uci", "commit", strings.SplitN(d.UCI, ".", 2)[0])
			}
		} else {
			_ = sh(init, "disable")
		}
		if err == nil {
			err = sh(init, "stop")
		}
	case "restart":
		err = sh(init, "restart")
	default:
		return SvcStatus{}, errors.New("未知操作")
	}
	time.Sleep(time.Second)
	for _, s := range Services() {
		if s.Name == name {
			return s, err
		}
	}
	return SvcStatus{}, err
}

// ---- logs ----

type LogLine struct {
	TS    string `json:"ts"`
	Level string `json:"level"` // facility.level
	Proc  string `json:"proc"`
	Msg   string `json:"msg"`
}

var logRe = regexp.MustCompile(`^\w{3} (\w{3}\s+\d+ [\d:]+ \d{4}) (\S+) ([^:]+): (.*)$`)

func Logs(source string, lines int, q string) []LogLine {
	if lines <= 0 || lines > 5000 {
		lines = 500
	}
	var raw []byte
	if source == "kernel" {
		raw, _ = run(10*time.Second, "dmesg")
	} else {
		window := lines
		if q != "" { // search further back than what is shown
			window = 20000
		}
		raw, _ = run(10*time.Second, "logread", "-l", strconv.Itoa(window))
	}
	q = strings.ToLower(q)
	out := []LogLine{}
	for _, l := range strings.Split(strings.TrimRight(string(raw), "\n"), "\n") {
		if l == "" || (q != "" && !strings.Contains(strings.ToLower(l), q)) {
			continue
		}
		if m := logRe.FindStringSubmatch(l); m != nil {
			out = append(out, LogLine{TS: m[1], Level: m[2], Proc: m[3], Msg: m[4]})
		} else {
			out = append(out, LogLine{Msg: l})
		}
	}
	if len(out) > lines {
		out = out[len(out)-lines:]
	}
	return out
}

// ---- reboot / backup / restore ----

func Reboot() {
	go func() {
		time.Sleep(2 * time.Second)
		_, _ = run(10*time.Second, "sync")
		_, _ = run(10*time.Second, "reboot")
	}()
}

func Backup() (string, []byte, error) {
	host := readTrim("/proc/sys/kernel/hostname")
	name := fmt.Sprintf("backup-%s-%s.tar.gz", host, time.Now().Format("2006-01-02"))
	tmp := "/tmp/owp-backup.tar.gz"
	defer os.Remove(tmp)
	if out, err := run(60*time.Second, "sysupgrade", "-b", tmp); err != nil {
		return "", nil, fmt.Errorf("sysupgrade -b: %v %s", err, out)
	}
	b, err := os.ReadFile(tmp)
	return name, b, err
}

// RestoreCheck validates an uploaded archive: a gzip'd tar of etc/ files only.
func RestoreCheck(b64 string) (string, []string, error) {
	data, err := base64.StdEncoding.DecodeString(b64)
	if err != nil || len(data) < 100 || len(data) > 40<<20 {
		return "", nil, errors.New("文件无效或超过 40 MB")
	}
	tmp := "/tmp/owp-restore.tar.gz"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return "", nil, err
	}
	out, err := run(20*time.Second, "tar", "-tzf", tmp)
	if err != nil {
		os.Remove(tmp)
		return "", nil, errors.New("不是有效的 tar.gz 备份文件")
	}
	var files []string
	for _, f := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		f = strings.TrimPrefix(f, "./")
		if f == "" {
			continue
		}
		if !strings.HasPrefix(f, "etc/") || strings.Contains(f, "..") {
			os.Remove(tmp)
			return "", nil, fmt.Errorf("备份包含 /etc 以外的文件：%s", f)
		}
		files = append(files, f)
	}
	if len(files) == 0 {
		os.Remove(tmp)
		return "", nil, errors.New("备份是空的")
	}
	sort.Strings(files)
	return tmp, files, nil
}

// Restore applies a checked archive with sysupgrade -r and reboots.
func Restore(b64 string) ([]string, error) {
	tmp, files, err := RestoreCheck(b64)
	if err != nil {
		return nil, err
	}
	if out, err := run(60*time.Second, "sysupgrade", "-r", tmp); err != nil {
		return nil, fmt.Errorf("sysupgrade -r: %v %s", err, out)
	}
	os.Remove(tmp)
	Reboot()
	return files, nil
}

// ---- scheduled reboot (root crontab line tagged "# owp-reboot") ----

type RebootSchedule struct {
	Enabled bool   `json:"enabled"`
	Time    string `json:"time"` // HH:MM
	Days    []int  `json:"days"` // 0=Sunday … 6; empty = every day
}

const crontab = "/etc/crontabs/root"
const cronTag = "# owp-reboot"

var hhmmRe = regexp.MustCompile(`^([01]\d|2[0-3]):([0-5]\d)$`)

func GetRebootSchedule() RebootSchedule {
	b, _ := os.ReadFile(crontab)
	for _, l := range strings.Split(string(b), "\n") {
		if !strings.HasSuffix(l, cronTag) {
			continue
		}
		fs := strings.Fields(l)
		if len(fs) < 5 {
			break
		}
		s := RebootSchedule{Enabled: true}
		m, _ := strconv.Atoi(fs[0])
		h, _ := strconv.Atoi(fs[1])
		s.Time = fmt.Sprintf("%02d:%02d", h, m)
		if fs[4] != "*" {
			for _, d := range strings.Split(fs[4], ",") {
				n, _ := strconv.Atoi(d)
				s.Days = append(s.Days, n)
			}
		}
		return s
	}
	return RebootSchedule{Time: "04:30"}
}

func SetRebootSchedule(s RebootSchedule) error {
	m := hhmmRe.FindStringSubmatch(s.Time)
	if s.Enabled && m == nil {
		return errors.New("时间格式应为 HH:MM")
	}
	b, _ := os.ReadFile(crontab)
	var keep []string
	for _, l := range strings.Split(strings.TrimRight(string(b), "\n"), "\n") {
		if l != "" && !strings.HasSuffix(l, cronTag) {
			keep = append(keep, l)
		}
	}
	if s.Enabled {
		dow := "*"
		if len(s.Days) > 0 && len(s.Days) < 7 {
			var ds []string
			for _, d := range s.Days {
				if d < 0 || d > 6 {
					return errors.New("星期无效")
				}
				ds = append(ds, strconv.Itoa(d))
			}
			dow = strings.Join(ds, ",")
		}
		h, _ := strconv.Atoi(m[1])
		mi, _ := strconv.Atoi(m[2])
		// "sleep 70": if the clock is corrected right after boot, the same minute can't match twice
		keep = append(keep, fmt.Sprintf("%d %d * * %s sleep 70 && touch /etc/banner && reboot %s", mi, h, dow, cronTag))
	}
	tmp := crontab + ".owp"
	if err := os.WriteFile(tmp, []byte(strings.Join(keep, "\n")+"\n"), 0o600); err != nil {
		return err
	}
	if err := os.Rename(tmp, crontab); err != nil {
		return err
	}
	_, err := run(10*time.Second, "/etc/init.d/cron", "restart")
	return err
}

// ---- UPnP ----

type UPnPRule struct {
	Num      string `json:"num"`
	Proto    string `json:"proto"`
	ExtPort  int    `json:"extport"`
	IntAddr  string `json:"intaddr"`
	IntPort  int    `json:"intport"`
	HostHint string `json:"host_hint"`
	Descr    string `json:"descr"`
	Expires  int    `json:"expires"`
}

func UPnP() (bool, bool, []UPnPRule) {
	var st struct {
		Rules []UPnPRule `json:"rules"`
	}
	_ = ubusCall("luci.upnp", "get_status", nil, &st)
	running := false
	var rc map[string]struct {
		Running bool `json:"running"`
	}
	if ubusCall("rc", "list", nil, &rc) == nil {
		running = rc["miniupnpd"].Running
	}
	return uciValue("upnpd.config.enabled") == "1", running, st.Rules
}

func UPnPDelete(num string) error {
	if _, err := strconv.Atoi(num); err != nil {
		return errors.New("bad token")
	}
	return ubusCall("luci.upnp", "delete_rule", map[string]any{"token": num}, nil)
}

// ---- Wake-on-LAN ----

var macRe = regexp.MustCompile(`^[0-9a-fA-F]{2}(:[0-9a-fA-F]{2}){5}$`)

func WakeOnLAN(mac string) error {
	if !macRe.MatchString(mac) {
		return errors.New("MAC 无效")
	}
	iface := GetSystem().LanIfname
	if iface == "" {
		iface = "br-lan"
	}
	if out, err := run(5*time.Second, "etherwake", "-b", "-i", iface, mac); err != nil {
		return fmt.Errorf("etherwake: %v %s", err, out)
	}
	return nil
}
