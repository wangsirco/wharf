package agent

import (
	"bufio"
	"os"
	"strconv"
	"strings"
	"time"
)

type IfStat struct {
	Name    string `json:"name"`
	RxBytes uint64 `json:"rx_bytes"`
	TxBytes uint64 `json:"tx_bytes"`
	RxPkts  uint64 `json:"rx_packets"`
	TxPkts  uint64 `json:"tx_packets"`
}

type SystemInfo struct {
	Hostname   string    `json:"hostname"`
	Release    string    `json:"release"`
	Kernel     string    `json:"kernel"`
	Model      string    `json:"model"`
	Firewall   string    `json:"firewall"` // fw3 | fw4
	Uptime     float64   `json:"uptime"`
	Load       []float64 `json:"load"`
	MemTotal   uint64    `json:"mem_total"`
	MemAvail   uint64    `json:"mem_available"`
	Conntrack  int       `json:"conntrack"`
	ConntrackM int       `json:"conntrack_max"`
	WanIfname  string    `json:"wan_ifname"`
	LanIfname  string    `json:"lan_ifname"`
	Ifaces     []IfStat  `json:"ifaces"`
	Time       int64     `json:"time"`
}

func readTrim(p string) string {
	b, _ := os.ReadFile(p)
	return strings.TrimSpace(string(b))
}

func readInt(p string) int {
	n, _ := strconv.Atoi(readTrim(p))
	return n
}

func FirewallFlavor() string {
	if _, err := os.Stat("/sbin/fw4"); err == nil {
		return "fw4"
	}
	return "fw3"
}

func osRelease() string {
	for _, line := range strings.Split(readTrim("/etc/openwrt_release"), "\n") {
		if strings.HasPrefix(line, "DISTRIB_DESCRIPTION=") {
			return strings.Trim(strings.TrimPrefix(line, "DISTRIB_DESCRIPTION="), "'\"")
		}
	}
	return ""
}

func ifStats() []IfStat {
	f, err := os.Open("/proc/net/dev")
	if err != nil {
		return nil
	}
	defer f.Close()
	var out []IfStat
	sc := bufio.NewScanner(f)
	for i := 0; sc.Scan(); i++ {
		if i < 2 {
			continue
		}
		name, rest, ok := strings.Cut(sc.Text(), ":")
		if !ok {
			continue
		}
		fs := strings.Fields(rest)
		if len(fs) < 10 {
			continue
		}
		p := func(s string) uint64 { n, _ := strconv.ParseUint(s, 10, 64); return n }
		out = append(out, IfStat{Name: strings.TrimSpace(name), RxBytes: p(fs[0]), RxPkts: p(fs[1]), TxBytes: p(fs[8]), TxPkts: p(fs[9])})
	}
	return out
}

func GetSystem() SystemInfo {
	s := SystemInfo{
		Hostname:   readTrim("/proc/sys/kernel/hostname"),
		Release:    osRelease(),
		Kernel:     readTrim("/proc/sys/kernel/osrelease"),
		Model:      readTrim("/tmp/sysinfo/model"),
		Firewall:   FirewallFlavor(),
		Conntrack:  readInt("/proc/sys/net/netfilter/nf_conntrack_count"),
		ConntrackM: readInt("/proc/sys/net/netfilter/nf_conntrack_max"),
		WanIfname:  uciGetOption("network", "wan", "device"),
		LanIfname:  uciGetOption("network", "lan", "device"),
		Ifaces:     ifStats(),
		Time:       time.Now().Unix(),
	}
	if fs := strings.Fields(readTrim("/proc/uptime")); len(fs) > 0 {
		s.Uptime, _ = strconv.ParseFloat(fs[0], 64)
	}
	if fs := strings.Fields(readTrim("/proc/loadavg")); len(fs) >= 3 {
		for _, f := range fs[:3] {
			v, _ := strconv.ParseFloat(f, 64)
			s.Load = append(s.Load, v)
		}
	}
	for _, line := range strings.Split(readTrim("/proc/meminfo"), "\n") {
		fs := strings.Fields(line)
		if len(fs) < 2 {
			continue
		}
		v, _ := strconv.ParseUint(fs[1], 10, 64)
		switch fs[0] {
		case "MemTotal:":
			s.MemTotal = v * 1024
		case "MemAvailable:":
			s.MemAvail = v * 1024
		}
	}
	return s
}
