package agent

import (
	"errors"
	"fmt"
	"log"
	"os"
	"regexp"
	"slices"
	"sort"
	"sync"
	"time"
)

// Configs the agent is willing to modify with a known reload. Other configs in
// /etc/config (plugins) are writable too, except the protected ones below, and
// are reloaded the way LuCI does it.
var writableConfigs = map[string]string{
	"firewall": "firewall", // config -> init.d service reloaded after commit
	"dhcp":     "dnsmasq",
	"network":  "network",
	"owpfwd":   "", // port-forward metadata written by the panel
	"owpdev":   "", // per-device policies (compiled by Policy, not by a service)
}

// protectedConfigs are never written through the generic path: the agent's own
// settings (a change restarts the agent), remote access and the RPC daemon.
var protectedConfigs = map[string]bool{"owp": true, "rpcd": true, "uhttpd": true, "dropbear": true, "ucitrack": true, "luci": true}

var cfgNameRe = regexp.MustCompile(`^[a-zA-Z0-9_-]{1,40}$`)

func configWritable(cfg string) error {
	if _, ok := writableConfigs[cfg]; ok {
		return nil
	}
	if protectedConfigs[cfg] || !cfgNameRe.MatchString(cfg) {
		return fmt.Errorf("config %q is not writable", cfg)
	}
	if _, err := os.Stat("/etc/config/" + cfg); err != nil {
		return fmt.Errorf("config %q does not exist", cfg)
	}
	return nil
}

// reloadConfig applies a committed config: known services are reloaded (never
// restarted), plugins the way LuCI does it — the legacy ucitrack init script is
// restarted, otherwise procd gets a config.change event for the package.
func reloadConfig(cfg string) {
	if svc, ok := writableConfigs[cfg]; ok {
		if svc == "" {
			return
		}
		if _, err := run(60*time.Second, "/etc/init.d/"+svc, "reload"); err != nil {
			log.Printf("reload %s: %v", svc, err)
		}
		if cfg == "dhcp" && fileExists("/etc/init.d/odhcpd") {
			_, _ = run(30*time.Second, "/etc/init.d/odhcpd", "reload")
		}
		return
	}
	if init := uciValue("ucitrack.@" + cfg + "[0].init"); init != "" && cfgNameRe.MatchString(init) && fileExists("/etc/init.d/"+init) {
		if _, err := run(90*time.Second, "/etc/init.d/"+init, "restart"); err != nil {
			log.Printf("restart %s: %v", init, err)
		}
		return
	}
	_ = ubusCall("service", "event", map[string]any{"type": "config.change", "data": map[string]any{"package": cfg}}, nil)
}

// Change is one uci mutation.
//
//	set:    Config, Section, Values (merged into section)
//	add:    Config, Type, Values (optional Name for a named section)
//	delete: Config, Section, Options (empty Options = delete whole section)
type Change struct {
	Op      string         `json:"op"`
	Config  string         `json:"config"`
	Section string         `json:"section,omitempty"`
	Type    string         `json:"type,omitempty"`
	Name    string         `json:"name,omitempty"`
	Values  map[string]any `json:"values,omitempty"`
	Options []string       `json:"options,omitempty"`
}

// ChangeResult carries full section snapshots so the panel can audit and later restore.
type ChangeResult struct {
	Config  string  `json:"config"`
	Section string  `json:"section"`
	Before  Section `json:"before"` // nil when the section did not exist
	After   Section `json:"after"`  // nil when the section was deleted
}

var applyMu sync.Mutex

func Apply(changes []Change) ([]ChangeResult, error) {
	applyMu.Lock()
	defer applyMu.Unlock()
	if p := CurrentPending(); p != nil {
		for _, c := range changes {
			if slices.Contains(p.Configs, c.Config) {
				return nil, errors.New("还有一项改动在等待确认，请先确认或撤销")
			}
		}
	}
	return applyLocked(changes)
}

func applyLocked(changes []Change) ([]ChangeResult, error) {

	touched := map[string]bool{}
	for _, c := range changes {
		if err := configWritable(c.Config); err != nil {
			return nil, err
		}
		touched[c.Config] = true
	}
	revert := func() {
		for cfg := range touched {
			_ = ubusCall("uci", "revert", map[string]any{"config": cfg}, nil)
		}
	}
	// discard any stray uncommitted changes so we only commit our own
	revert()

	var results []ChangeResult
	for _, c := range changes {
		res := ChangeResult{Config: c.Config, Section: c.Section}
		if c.Section != "" {
			res.Before, _ = uciGetSection(c.Config, c.Section)
		}
		var err error
		switch c.Op {
		case "set":
			if c.Section == "" || res.Before == nil {
				err = fmt.Errorf("set: section %s.%s not found", c.Config, c.Section)
				break
			}
			err = ubusCall("uci", "set", map[string]any{"config": c.Config, "section": c.Section, "values": c.Values}, nil)
		case "add":
			p := map[string]any{"config": c.Config, "type": c.Type, "values": c.Values}
			if c.Name != "" {
				p["name"] = c.Name
			}
			var r struct {
				Section string `json:"section"`
			}
			err = ubusCall("uci", "add", p, &r)
			res.Section = r.Section
		case "delete":
			if res.Before == nil {
				err = fmt.Errorf("delete: section %s.%s not found", c.Config, c.Section)
				break
			}
			p := map[string]any{"config": c.Config, "section": c.Section}
			if len(c.Options) > 0 {
				p["options"] = c.Options
			}
			err = ubusCall("uci", "delete", p, nil)
		default:
			err = fmt.Errorf("unknown op %q", c.Op)
		}
		if err != nil {
			revert()
			return nil, err
		}
		results = append(results, res)
	}

	var cfgs []string
	for cfg := range touched {
		cfgs = append(cfgs, cfg)
	}
	sort.Strings(cfgs)
	for _, cfg := range cfgs {
		if err := ubusCall("uci", "commit", map[string]any{"config": cfg}, nil); err != nil {
			revert()
			return nil, err
		}
	}
	for i := range results {
		results[i].After, _ = uciGetSection(results[i].Config, results[i].Section)
	}
	for _, cfg := range cfgs {
		reloadConfig(cfg)
	}
	return results, nil
}
