package panel

import (
	"fmt"
	"net/http"
	"slices"
	"strings"
	"time"
)

// The verdict line at the top of the overview: "一切正常", or what is wrong and where to go.
// Each item is something a person would want to act on, worst first.

type todoItem struct {
	Level string `json:"level"` // bad | warn | info
	Text  string `json:"text"`
	To    string `json:"to,omitempty"`
}

// GET /api/overview/todo
func (a *App) handleOverviewTodo(w http.ResponseWriter, r *http.Request) {
	u := currentUser(r)
	items := []todoItem{}
	add := func(level, to, f string, args ...any) {
		items = append(items, todoItem{level, fmt.Sprintf(f, args...), to})
	}

	h, err := a.netHealth()
	if err != nil {
		add("bad", "/settings?tab=update", "面板连不上路由器上的 Agent，大部分数据暂时看不到")
	} else {
		if h.Health != nil && h.Health.Checked && !h.Health.Internet {
			since := ""
			if h.Health.DownSince > 0 {
				since = "（" + time.Unix(h.Health.DownSince, 0).Format("15:04") + " 起）"
			}
			add("bad", "/network", "外网断了%s", since)
		}
		if h.Pending != nil && (u.Can("network.manage") || u.Can("firewall.manage")) {
			add("bad", "/interfaces", "有一处网络改动在等确认，不确认会自动恢复")
		}
	}

	// DNS: when dnsmasq forwards to a local NextDNS that is not running, nothing resolves
	var dc struct {
		Upstreams []struct {
			Kind string `json:"kind"`
		} `json:"upstreams"`
		NextDNS *struct {
			Running bool `json:"running"`
		} `json:"nextdns"`
	}
	if err == nil && a.agent.Do("GET", "/v1/dns/cache", nil, &dc) == nil && dc.NextDNS != nil && !dc.NextDNS.Running {
		usesIt := false
		for _, up := range dc.Upstreams {
			if up.Kind == "nextdns" {
				usesIt = true
			}
		}
		if usesIt {
			add("bad", "/dhcp#"+tocAnchor("DNS 缓存与排查"), "NextDNS 没在运行，家里设备可能解析不了域名")
		} else {
			add("warn", "/system", "NextDNS 装了但没在运行")
		}
	}

	if u.Role == RoleSuper {
		var pending int
		_ = a.db.QueryRow(`SELECT COUNT(*) FROM approvals WHERE status='pending'`).Scan(&pending)
		if pending > 0 {
			add("warn", "/approvals", "%d 个操作在等你审批", pending)
		}
		if list, err := a.ddnsList(); err == nil {
			var bad []string
			for _, d := range list {
				if d.Enabled && d.LastErr != "" && d.LastRun > d.LastOK {
					bad = append(bad, d.Domain)
				}
			}
			if len(bad) > 0 {
				add("warn", "/ddns", "DDNS 更新失败：%s", strings.Join(firstN(bad, 3), "、"))
			}
		}
		pubCert.RLock()
		exp := pubCert.exp
		hasCert := pubCert.cert != nil
		pubCert.RUnlock()
		if hasCert {
			if d := time.Until(exp); d < 0 {
				add("bad", "/remote#panel-names", "面板的公网证书已经过期")
			} else if d < 14*24*time.Hour {
				add("warn", "/remote#panel-names", "面板的公网证书 %d 天后到期，自动续期好像没成功", int(d.Hours()/24))
			}
		}
		if !a.lan443() && a.CA != nil {
			add("info", "/settings?tab=link#"+tocAnchor("访问地址"), "还没开启「用 %s 打开，不带端口」：Passkey 只认名字，开启后更好记", "https://"+a.localPanelName())
		}
		if l := a.berth(); l != nil && l.state() != "active" {
			add("warn", "/berth", "和 Berth「%s」的对接已失效，需要重新配对", l.Name)
		}
		if stale := a.staleImports(); len(stale) > 0 {
			add("info", "/plugins", "%s 升级了，界面需要重新导入一次", strings.Join(firstN(stale, 3), "、"))
		}
	}
	writeJSON(w, 200, map[string]any{"items": items})
}

func firstN(s []string, n int) []string {
	if len(s) > n {
		return append(slices.Clone(s[:n]), fmt.Sprintf("等 %d 个", len(s)))
	}
	return s
}

// tocAnchor mirrors the web's tocId(): the anchor a <Section title> gets.
func tocAnchor(title string) string {
	var b strings.Builder
	for _, c := range []byte(title) {
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9', strings.IndexByte("-_.!~*'()", c) >= 0:
			b.WriteByte(c)
		default:
			fmt.Fprintf(&b, "%02X", c)
		}
	}
	s := b.String()
	if len(s) > 40 {
		s = s[:40]
	}
	return "sec-" + s
}

// staleImports: plugins whose pages Wharf converted for an older version.
func (a *App) staleImports() []string {
	rows, err := a.db.Query(`SELECT pkg, version FROM plugin_imports`)
	if err != nil {
		return nil
	}
	imported := map[string]string{}
	for rows.Next() {
		var p, v string
		if rows.Scan(&p, &v) == nil {
			imported[p] = v
		}
	}
	rows.Close()
	if len(imported) == 0 {
		return nil
	}
	var list []struct {
		Pkg     string `json:"pkg"`
		Version string `json:"version"`
		Title   string `json:"title"`
	}
	if a.agent.Do("GET", "/v1/plugins", nil, &list) != nil {
		return nil
	}
	var out []string
	for _, p := range list {
		if v, ok := imported[p.Pkg]; ok && v != "" && p.Version != "" && v != p.Version {
			out = append(out, firstNonEmpty(knownApps[appKey(p.Pkg)].Name, p.Title, p.Pkg))
		}
	}
	return out
}
