package agent

import (
	"errors"
	"log"
	"net"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/wangsirco/wharf/internal/proxyfront"
)

// The panel without a port at home: https://wharf.lan. LuCI's uhttpd keeps port 443; a
// firewall redirect (owp_lan443: LAN → router address, tcp 443 → lan443Port) sends home
// connections to a splitter that passes the panel's names to the panel and everything
// else (LuCI by IP, other names) on to uhttpd. Turning it off removes the redirect and
// 443 is uhttpd's alone again. State: uci owp.lan443 (enabled, list name).

const (
	lan443Port    = "20445"
	lan443Section = "owp_lan443"
)

var lan443 = struct {
	sync.Mutex
	split     *proxyfront.Split
	listening bool
	err       string
}{split: &proxyfront.Split{Panel: "127.0.0.1:20090", Other: "127.0.0.1:443"}}

type LAN443Status struct {
	Enabled   bool     `json:"enabled"`
	Names     []string `json:"names"`
	Listening bool     `json:"listening"`
	Redirect  bool     `json:"redirect"` // the firewall rule is in place
	Other     bool     `json:"other"`    // something (LuCI) answers on 127.0.0.1:443
	Error     string   `json:"error,omitempty"`
}

// StartLAN443 listens (always, so it can be checked before the redirect is on) and loads
// the names saved last time.
func StartLAN443() {
	lan443.split.SetNames(uciGetList("owp", "lan443", "name"))
	lan443.Lock()
	defer lan443.Unlock()
	if lan443.listening {
		return
	}
	ln, err := net.Listen("tcp", ":"+lan443Port)
	if err != nil {
		lan443.err = err.Error()
		log.Printf("lan443: %v", err)
		return
	}
	lan443.listening = true
	go func() {
		err := lan443.split.Serve(ln)
		lan443.Lock()
		lan443.listening, lan443.err = false, errString(err)
		lan443.Unlock()
	}()
}

func uciGetList(config, section, option string) []string {
	all, err := uciGetConfig(config)
	if err != nil {
		return nil
	}
	s, ok := all[section]
	if !ok {
		return nil
	}
	switch v := s[option].(type) {
	case []any:
		var out []string
		for _, x := range v {
			if str, ok := x.(string); ok {
				out = append(out, str)
			}
		}
		return out
	case string:
		return strings.Fields(v)
	}
	return nil
}

// WatchLAN443 keeps the splitter up while the redirect sends LAN 443 to it. If it cannot
// listen, the redirect goes (443 back to uhttpd alone) rather than leaving names dead.
func WatchLAN443() {
	for {
		time.Sleep(30 * time.Second)
		lan443.Lock()
		up := lan443.listening
		lan443.Unlock()
		if up || uciGetOption("owp", "lan443", "enabled") != "1" {
			continue
		}
		StartLAN443()
		lan443.Lock()
		up = lan443.listening
		lan443.Unlock()
		if !up {
			if fw, err := uciGetConfig("firewall"); err == nil {
				if _, ok := fw[lan443Section]; ok {
					log.Printf("lan443: splitter not listening (%s); removing the redirect", lan443.err)
					_, _ = Apply([]Change{{Op: "delete", Config: "firewall", Section: lan443Section}})
				}
			}
		}
	}
}

func GetLAN443() LAN443Status {
	lan443.Lock()
	st := LAN443Status{Enabled: uciGetOption("owp", "lan443", "enabled") == "1", Names: lan443.split.Names(), Listening: lan443.listening, Error: lan443.err}
	lan443.Unlock()
	slices.Sort(st.Names)
	if fw, err := uciGetConfig("firewall"); err == nil {
		_, st.Redirect = fw[lan443Section]
	}
	if c, err := net.DialTimeout("tcp", "127.0.0.1:443", time.Second); err == nil {
		st.Other = true
		c.Close()
	}
	return st
}

// SetLAN443 saves the names, and adds or removes the redirect for the router's LAN address.
func SetLAN443(enabled bool, names []string, lanIP string) (LAN443Status, error) {
	var clean []string
	for _, n := range names {
		n = strings.ToLower(strings.TrimSpace(n))
		if n != "" && len(n) < 254 && !strings.ContainsAny(n, " /'\"") && !slices.Contains(clean, n) {
			clean = append(clean, n)
		}
	}
	ip, err := netip.ParseAddr(lanIP)
	if enabled && (err != nil || !ip.Is4()) {
		return GetLAN443(), errors.New("路由器的局域网地址不对")
	}
	// owp is not changed through Apply (protected); plain uci like the panel's own options
	args := [][]string{{"set", "owp.lan443=lan443"}, {"set", "owp.lan443.enabled=" + map[bool]string{true: "1", false: "0"}[enabled]}, {"-q", "delete", "owp.lan443.name"}}
	for _, n := range clean {
		args = append(args, []string{"add_list", "owp.lan443.name=" + n})
	}
	args = append(args, []string{"commit", "owp"})
	for _, a := range args {
		if _, err := run(10*time.Second, "uci", a...); err != nil && a[0] != "-q" {
			return GetLAN443(), err
		}
	}
	lan443.split.SetNames(clean)
	StartLAN443()

	fw, err := uciGetConfig("firewall")
	if err != nil {
		return GetLAN443(), err
	}
	cur, ok := fw[lan443Section]
	want := map[string]any{"name": "Wharf: https://" + firstOr(clean, "wharf.lan"), "src": "lan", "proto": "tcp", "src_dip": ip.String(),
		"src_dport": "443", "dest_port": lan443Port, "target": "DNAT"}
	switch {
	case !enabled && ok:
		_, err = Apply([]Change{{Op: "delete", Config: "firewall", Section: lan443Section}})
	case enabled && (!ok || secStr(cur, "src_dip") != ip.String() || secStr(cur, "dest_port") != lan443Port):
		c := []Change{{Op: "add", Config: "firewall", Type: "redirect", Name: lan443Section, Values: want}}
		if ok {
			c = append([]Change{{Op: "delete", Config: "firewall", Section: lan443Section}}, c...)
		}
		_, err = Apply(c)
	}
	return GetLAN443(), err
}

func firstOr(s []string, d string) string {
	if len(s) > 0 {
		return s[0]
	}
	return d
}
