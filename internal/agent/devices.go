package agent

import (
	"net"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Device merges DHCP leases, static hosts and the neighbour table.
type Device struct {
	MAC         string `json:"mac"`
	IP          string `json:"ip"`
	Hostname    string `json:"hostname"`     // from DHCP request
	StaticName  string `json:"static_name"`  // from uci dhcp host
	LeaseExpiry int64  `json:"lease_expiry"` // unix, 0 = static/none
	NeighState  string `json:"neigh_state"`  // REACHABLE / STALE / ...
	Online      bool   `json:"online"`
	LastSeen    int64  `json:"last_seen,omitempty"` // last confirmed present (presence tracking)
	Static      bool   `json:"static"`
	StaticID    string `json:"static_id,omitempty"` // uci section of the static host
}

func leaseFile() string {
	if v := uciGetOption("dhcp", "@dnsmasq[0]", "leasefile"); v != "" {
		return v
	}
	return "/tmp/dhcp.leases"
}

func normMAC(s string) string {
	hw, err := net.ParseMAC(s)
	if err != nil {
		return strings.ToLower(s)
	}
	return hw.String()
}

func GetDevices() []Device {
	byMAC := map[string]*Device{}
	get := func(mac string) *Device {
		mac = normMAC(mac)
		d := byMAC[mac]
		if d == nil {
			d = &Device{MAC: mac}
			byMAC[mac] = d
		}
		return d
	}

	if b, err := os.ReadFile(leaseFile()); err == nil {
		for _, line := range strings.Split(string(b), "\n") {
			fs := strings.Fields(line)
			if len(fs) < 4 || net.ParseIP(fs[2]).To4() == nil {
				continue
			}
			d := get(fs[1])
			d.IP = fs[2]
			if fs[3] != "*" {
				d.Hostname = fs[3]
			}
			d.LeaseExpiry, _ = strconv.ParseInt(fs[0], 10, 64)
		}
	}

	if hosts, err := uciGetConfig("dhcp"); err == nil {
		for id, s := range hosts {
			if s[".type"] != "host" {
				continue
			}
			macs := s["mac"]
			var list []string
			switch v := macs.(type) {
			case string:
				list = strings.Fields(v)
			case []any:
				for _, m := range v {
					if ms, ok := m.(string); ok {
						list = append(list, ms)
					}
				}
			}
			for _, m := range list {
				d := get(m)
				d.Static, d.StaticID = true, id
				if n, ok := s["name"].(string); ok {
					d.StaticName = n
				}
				if ip, ok := s["ip"].(string); ok && d.IP == "" {
					d.IP = ip
				}
			}
		}
	}

	lan := uciGetOption("network", "lan", "device")
	if out, err := run(5*time.Second, "ip", "neigh", "show"); err == nil {
		for _, line := range strings.Split(string(out), "\n") {
			// 192.168.1.102 dev br-lan lladdr 2c:0d:a7:78:dd:45 STALE
			fs := strings.Fields(line)
			if len(fs) < 6 || fs[3] != "lladdr" || net.ParseIP(fs[0]).To4() == nil {
				continue
			}
			if lan != "" && fs[2] != lan {
				continue
			}
			d := get(fs[4])
			if d.IP == "" {
				d.IP = fs[0]
			}
			if d.IP == fs[0] {
				d.NeighState = fs[len(fs)-1]
				switch d.NeighState {
				// STALE just means "not confirmed recently"; gone devices end up FAILED
				case "REACHABLE", "DELAY", "PROBE", "PERMANENT", "STALE":
					d.Online = true
				}
			}
		}
	}

	out := make([]Device, 0, len(byMAC))
	now := time.Now().Unix()
	for _, d := range byMAC {
		// with presence tracking, "online" means confirmed reachable in the last few minutes
		if presence.Ready() {
			d.LastSeen = presence.LastSeen(d.MAC)
			d.Online = d.LastSeen > 0 && now-d.LastSeen <= presentFor
		}
		out = append(out, *d)
	}
	sort.Slice(out, func(i, j int) bool {
		a, b := net.ParseIP(out[i].IP).To4(), net.ParseIP(out[j].IP).To4()
		if a == nil || b == nil {
			return a != nil
		}
		return string(a) < string(b)
	})
	return out
}

// Neighbours returns the IPv4 -> MAC map of the LAN neighbour table plus DHCP leases.
func Neighbours() map[string]string {
	m := map[string]string{}
	for _, d := range GetDevices() {
		if d.IP != "" && d.NeighState != "FAILED" && d.NeighState != "INCOMPLETE" {
			m[d.IP] = d.MAC
		}
	}
	return m
}
