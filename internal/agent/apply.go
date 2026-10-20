package agent

import (
	"fmt"
	"log"
	"sort"
	"sync"
	"time"
)

// Configs the agent is willing to modify. Everything else is read-only.
var writableConfigs = map[string]string{
	"firewall": "firewall", // config -> init.d service reloaded after commit
	"dhcp":     "dnsmasq",
	"owpfwd":   "", // port-forward metadata written by the panel
	"owpdev":   "", // per-device policies (compiled by Policy, not by a service)
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

	touched := map[string]bool{}
	for _, c := range changes {
		if _, ok := writableConfigs[c.Config]; !ok {
			return nil, fmt.Errorf("config %q is not writable", c.Config)
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
		if svc := writableConfigs[cfg]; svc != "" {
			// reload, never restart: keeps existing connections and the WAN up
			if _, err := run(60*time.Second, "/etc/init.d/"+svc, "reload"); err != nil {
				log.Printf("reload %s: %v", svc, err)
			}
		}
	}
	return results, nil
}
