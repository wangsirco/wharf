package agent

import (
	"bufio"
	"errors"
	"os"
	"os/exec"
	"slices"
	"strings"
	"sync"
	"time"
)

// Optional system components the panel builds on (conntrack, tcpdump, mtr …).
//
// Nothing here is a hard opkg dependency: the panel works without them and each page
// says what is missing. When the super admin installs a component from the panel, its
// package name is recorded in depsFile; uninstalling the panel removes exactly those
// packages again (postrm), unless something else on the router has come to depend on them.
// Components that were already on the router are never touched.

const depsFile = "/etc/wharf-deps.list"

type Dep struct {
	ID        string   `json:"id"`
	Name      string   `json:"name"`
	Pkg       string   `json:"pkg"`   // opkg package that provides it
	Level     string   `json:"level"` // core | recommended | optional
	Purpose   string   `json:"purpose"`
	Features  []string `json:"features"`
	Installed bool     `json:"installed"`
	ByPanel   bool     `json:"by_panel"` // installed through the panel (removed with it)
	Note      string   `json:"note,omitempty"`
	Kind      string   `json:"kind,omitempty"` // "" = package, "sysctl" = kernel switch
}

type depDef struct {
	Dep
	check func() bool
}

func have(bin string) func() bool {
	return func() bool { _, err := exec.LookPath(bin); return err == nil }
}

func fileHas(path, s string) func() bool {
	return func() bool { b, err := os.ReadFile(path); return err == nil && strings.Contains(string(b), s) }
}

func depDefs() []depDef {
	fw4 := GetSystem().Firewall == "fw4"
	upnp := "miniupnpd-iptables"
	if fw4 {
		upnp = "miniupnpd-nftables"
	}
	return []depDef{
		{Dep{ID: "conntrack", Name: "conntrack 连接跟踪工具", Pkg: "conntrack", Level: "core",
			Purpose: "读取路由器的连接表", Features: []string{"流量统计与设备画像", "全球流量地图", "端口转发用量与连接记录", "设备在线判断"}}, have("conntrack")},
		{Dep{ID: "conntrack_acct", Name: "连接字节统计（内核开关）", Pkg: "", Level: "core", Kind: "sysctl",
			Purpose: "让连接表记录每个连接的字节数", Features: []string{"每个连接 / 目标的流量大小", "端口转发用量"},
			Note: "开启 net.netfilter.nf_conntrack_acct，写入 /etc/sysctl.d/90-wharf.conf，卸载面板时删除"},
			fileHas("/proc/sys/net/netfilter/nf_conntrack_acct", "1")},
		{Dep{ID: "ipset", Name: "ipset", Pkg: "ipset", Level: "core",
			Purpose: "按 IP 集合匹配防火墙规则", Features: []string{"端口转发按地区 / IP 限制来源", "设备断网与黑白名单", "设备实时网速"}}, have("ipset")},
		{Dep{ID: "ip-full", Name: "ip（完整版 iproute2）", Pkg: "ip-full", Level: "recommended",
			Purpose: "读取邻居表、接口状态", Features: []string{"设备在线 / 离开判断更准确"}, Note: "精简版 busybox ip 也能用，但信息较少"},
			func() bool {
				out, _ := exec.Command("ip", "-V").CombinedOutput()
				return strings.Contains(string(out), "iproute2")
			}},
		{Dep{ID: "tcpdump", Name: "tcpdump", Pkg: "tcpdump", Level: "recommended",
			Purpose: "抓包", Features: []string{"网络工具 → 抓包与分析"}}, have("tcpdump")},
		{Dep{ID: "mtr", Name: "mtr（JSON 版）", Pkg: "mtr-json", Level: "recommended",
			Purpose: "逐跳路由追踪", Features: []string{"网络工具 → 路由追踪"}},
			func() bool {
				out, _ := exec.Command("mtr", "--help").CombinedOutput()
				return strings.Contains(string(out), "--json")
			}},
		{Dep{ID: "iperf3", Name: "iperf3", Pkg: "iperf3", Level: "recommended",
			Purpose: "专业内网测速", Features: []string{"网络工具 → 内网测速（iperf3 服务端 / 客户端）"}, Note: "浏览器测速不需要它"}, have("iperf3")},
		{Dep{ID: "dig", Name: "dig", Pkg: "bind-dig", Level: "recommended",
			Purpose: "向指定 DNS 服务器查询", Features: []string{"网络工具 → DNS 查询对比"}}, have("dig")},
		{Dep{ID: "curl", Name: "curl", Pkg: "curl", Level: "recommended",
			Purpose: "HTTP 请求与分段计时", Features: []string{"网络工具 → 网站访问测试", "检测公网 IP"}}, have("curl")},
		{Dep{ID: "etherwake", Name: "etherwake", Pkg: "etherwake", Level: "optional",
			Purpose: "发送网络唤醒包", Features: []string{"网络工具 → 网络唤醒（WOL）"}}, have("etherwake")},
		{Dep{ID: "upnp", Name: "UPnP 服务（miniupnpd）", Pkg: upnp, Level: "optional",
			Purpose: "让游戏机 / 下载软件自动开端口", Features: []string{"网络工具 → UPnP 管理"},
			Note: "UPnP 有安全风险，不需要就不要装；装了也默认关闭"}, have("miniupnpd")},
	}
}

func readDepsFile() []string {
	f, err := os.Open(depsFile)
	if err != nil {
		return nil
	}
	defer f.Close()
	var out []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		if l := strings.TrimSpace(sc.Text()); l != "" && !strings.HasPrefix(l, "#") {
			out = append(out, l)
		}
	}
	return out
}

func writeDepsFile(list []string) error {
	slices.Sort(list)
	list = slices.Compact(list)
	body := "# Installed by the Wharf panel; removed again when luci-app-wharf is uninstalled.\n" + strings.Join(list, "\n") + "\n"
	return os.WriteFile(depsFile, []byte(body), 0o644)
}

func opkgInstalled() map[string]bool {
	out := map[string]bool{}
	f, err := os.Open("/usr/lib/opkg/status")
	if err != nil {
		return out
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64<<10), 1<<20)
	pkg := ""
	for sc.Scan() {
		l := sc.Text()
		if p, ok := strings.CutPrefix(l, "Package: "); ok {
			pkg = p
		} else if strings.HasPrefix(l, "Status: ") && strings.HasSuffix(l, " installed") && pkg != "" {
			out[pkg] = true
		}
	}
	return out
}

func Deps() []Dep {
	mine := readDepsFile()
	var out []Dep
	for _, d := range depDefs() {
		d.Installed = d.check()
		if d.Kind == "sysctl" {
			d.ByPanel = fileHas("/etc/sysctl.d/90-wharf.conf", "nf_conntrack_acct")()
		} else {
			d.ByPanel = slices.Contains(mine, d.Pkg)
		}
		out = append(out, d.Dep)
	}
	return out
}

// ---- install job ----

type DepJob struct {
	Running bool     `json:"running"`
	Started int64    `json:"started"`
	Ended   int64    `json:"ended,omitempty"`
	IDs     []string `json:"ids"`
	Log     []string `json:"log"`
	Error   string   `json:"error,omitempty"`
	Action  string   `json:"action"` // install | remove
}

var depJob struct {
	sync.Mutex
	job DepJob
}

func DepStatus() DepJob {
	depJob.Lock()
	defer depJob.Unlock()
	j := depJob.job
	j.Log = append([]string{}, j.Log...)
	return j
}

func depLog(s string) {
	depJob.Lock()
	depJob.job.Log = append(depJob.job.Log, s)
	if len(depJob.job.Log) > 300 {
		depJob.job.Log = depJob.job.Log[len(depJob.job.Log)-300:]
	}
	depJob.Unlock()
}

// StartDeps installs (or removes) the given components in the background.
func StartDeps(action string, ids []string) error {
	if action != "install" && action != "remove" {
		return errors.New("bad action")
	}
	defs := map[string]depDef{}
	for _, d := range depDefs() {
		defs[d.ID] = d
	}
	for _, id := range ids {
		if _, ok := defs[id]; !ok {
			return errors.New("未知组件：" + id)
		}
	}
	if len(ids) == 0 {
		return errors.New("没有选择组件")
	}
	depJob.Lock()
	if depJob.job.Running {
		depJob.Unlock()
		return errors.New("已有安装任务在进行")
	}
	depJob.job = DepJob{Running: true, Started: time.Now().Unix(), IDs: ids, Action: action}
	depJob.Unlock()
	go runDeps(action, ids, defs)
	return nil
}

func runDeps(action string, ids []string, defs map[string]depDef) {
	fail := func(msg string) {
		depJob.Lock()
		depJob.job.Error, depJob.job.Running, depJob.job.Ended = msg, false, time.Now().Unix()
		depJob.Unlock()
	}
	opkg := func(args ...string) error {
		depLog("$ opkg " + strings.Join(args, " "))
		cmd := exec.Command("opkg", args...)
		out, err := cmd.CombinedOutput()
		for _, l := range strings.Split(strings.TrimSpace(string(out)), "\n") {
			if l = strings.TrimSpace(l); l != "" {
				depLog(l)
			}
		}
		return err
	}
	mine := readDepsFile()
	before := opkgInstalled()
	var pkgs []string
	for _, id := range ids {
		d := defs[id]
		if d.Kind == "sysctl" {
			if action == "install" {
				_ = os.WriteFile("/proc/sys/net/netfilter/nf_conntrack_acct", []byte("1"), 0o644)
				_ = os.WriteFile("/etc/sysctl.d/90-wharf.conf", []byte("# Wharf: per-connection byte counters\nnet.netfilter.nf_conntrack_acct=1\n"), 0o644)
				depLog("已开启 net.netfilter.nf_conntrack_acct")
			} else {
				_ = os.Remove("/etc/sysctl.d/90-wharf.conf")
				depLog("已移除 /etc/sysctl.d/90-wharf.conf（当前运行中的设置保持不变，重启后恢复系统默认）")
			}
			continue
		}
		if action == "install" && d.check() {
			depLog(d.Name + " 已经可用，跳过")
			continue
		}
		if action == "remove" && !slices.Contains(mine, d.Pkg) {
			depLog(d.Name + " 不是面板安装的，不会移除")
			continue
		}
		pkgs = append(pkgs, d.Pkg)
	}
	if len(pkgs) > 0 {
		if action == "install" {
			// package lists live in RAM (/var/opkg-lists) and are gone after a reboot
			if lists, _ := os.ReadDir("/var/opkg-lists"); len(lists) == 0 {
				if err := opkg("update"); err != nil {
					fail("opkg update 失败：检查路由器能否访问软件源")
					return
				}
			}
			err := opkg(append([]string{"install"}, pkgs...)...)
			after := opkgInstalled()
			for _, p := range pkgs {
				if after[p] && !before[p] {
					mine = append(mine, p) // only what we actually added
				}
			}
			_ = writeDepsFile(mine)
			if err != nil {
				fail("部分组件安装失败，详见日志")
				return
			}
		} else {
			err := opkg(append([]string{"remove", "--autoremove"}, pkgs...)...) // also drops libraries pulled in only for them
			after := opkgInstalled()
			mine = slices.DeleteFunc(mine, func(p string) bool { return !after[p] })
			_ = writeDepsFile(mine)
			if err != nil {
				fail("部分组件移除失败（可能有其他软件依赖它），详见日志")
				return
			}
		}
	}
	depLog("完成")
	depJob.Lock()
	depJob.job.Running, depJob.job.Ended = false, time.Now().Unix()
	depJob.Unlock()
}
