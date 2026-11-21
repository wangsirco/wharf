package panel

import (
	"encoding/json"
	"net/http"
	"strings"
)

// DNS caches: see internal/agent/dnscache.go. Looking a name up through every
// layer is read-only; emptying caches restarts the local resolver plugin for a
// second, so it needs network.manage and is audited.

// GET /api/net/dns/cache
func (a *App) handleDNSCache(w http.ResponseWriter, r *http.Request) {
	var out json.RawMessage
	if err := a.agent.Do("GET", "/v1/dns/cache", nil, &out); err != nil {
		jsonErr(w, 502, err.Error())
		return
	}
	writeJSON(w, 200, out)
}

// POST /api/net/dns/trace {name, type}
func (a *App) handleDNSTrace(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name string `json:"name"`
		Type string `json:"type"`
	}
	if readJSON(r, &req) != nil {
		jsonErr(w, 400, "请求格式错误")
		return
	}
	req.Name = strings.TrimSpace(strings.ToLower(req.Name))
	// accept a pasted URL: https://app.example.com/path
	if i := strings.Index(req.Name, "://"); i >= 0 {
		req.Name = req.Name[i+3:]
	}
	if i := strings.IndexAny(req.Name, "/:?#"); i >= 0 {
		req.Name = req.Name[:i]
	}
	var out json.RawMessage
	if err := a.agent.Do("POST", "/v1/dns/trace", req, &out); err != nil {
		jsonErr(w, 400, err.Error())
		return
	}
	writeJSON(w, 200, out)
}

// POST /api/net/dns/flush {targets, name}
func (a *App) handleDNSFlush(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Targets []string `json:"targets"`
		Name    string   `json:"name"` // the name that prompted it, for the audit log
	}
	if readJSON(r, &req) != nil {
		jsonErr(w, 400, "请求格式错误")
		return
	}
	var out struct {
		Results []struct {
			Target string `json:"target"`
			OK     bool   `json:"ok"`
			MS     int    `json:"ms"`
			Error  string `json:"error"`
		} `json:"results"`
	}
	if err := a.agent.Do("POST", "/v1/dns/flush", map[string]any{"targets": req.Targets}, &out); err != nil {
		jsonErr(w, 409, err.Error())
		return
	}
	var done []string
	for _, x := range out.Results {
		if x.OK {
			done = append(done, x.Target)
		}
	}
	msg := "刷新 DNS 缓存（" + strings.Join(done, "、") + "）"
	if n := truncate(strings.TrimSpace(req.Name), 120); n != "" {
		msg += "：" + n
	}
	a.audit(actor{user: currentUser(r), ip: a.clientIP(r)}, "dns.flush", "dns", "cache", msg, nil, nil, false)
	writeJSON(w, 200, out)
}

// PUT /api/net/dns/nextdns {cache_max_age}
func (a *App) handleDNSNextDNS(w http.ResponseWriter, r *http.Request) {
	var req struct {
		MaxAge string `json:"cache_max_age"`
	}
	if readJSON(r, &req) != nil {
		jsonErr(w, 400, "请求格式错误")
		return
	}
	var before struct {
		NextDNS *struct {
			CacheMaxAge string `json:"cache_max_age"`
		} `json:"nextdns"`
	}
	_ = a.agent.Do("GET", "/v1/dns/cache", nil, &before)
	if err := a.agent.Do("POST", "/v1/dns/nextdns", req, nil); err != nil {
		jsonErr(w, 400, err.Error())
		return
	}
	old := ""
	if before.NextDNS != nil {
		old = before.NextDNS.CacheMaxAge
	}
	a.audit(actor{user: currentUser(r), ip: a.clientIP(r)}, "dns.nextdns", "dns", "nextdns", "NextDNS 缓存最长保留："+req.MaxAge,
		map[string]string{"cache_max_age": old}, map[string]string{"cache_max_age": req.MaxAge}, false)
	writeJSON(w, 200, map[string]bool{"ok": true})
}
