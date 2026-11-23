package agent

import (
	"net"
	"os"
	"strings"
	"time"
)

// Tailscale on the router: whether it is installed and up, and its addresses (shown on
// the panel's remote-access page; Wharf does not manage Tailscale itself).
type TailscaleStatus struct {
	Installed bool     `json:"installed"`
	Running   bool     `json:"running"`
	IPs       []string `json:"ips"`
	Version   string   `json:"version,omitempty"`
}

func GetTailscale() TailscaleStatus {
	st := TailscaleStatus{IPs: []string{}}
	for _, p := range []string{"/usr/sbin/tailscale", "/usr/bin/tailscale"} {
		if _, err := os.Stat(p); err == nil {
			st.Installed = true
			if out, err := run(5*time.Second, p, "version"); err == nil {
				st.Version = strings.TrimSpace(strings.SplitN(string(out), "\n", 2)[0])
			}
			break
		}
	}
	st.Running = len(pidsOf("/usr/sbin/tailscaled")) > 0 || len(pidsOf("/usr/bin/tailscaled")) > 0
	if ifc, err := net.InterfaceByName("tailscale0"); err == nil {
		if addrs, err := ifc.Addrs(); err == nil {
			for _, a := range addrs {
				ip, _, _ := strings.Cut(a.String(), "/")
				st.IPs = append(st.IPs, ip)
			}
		}
	}
	return st
}
