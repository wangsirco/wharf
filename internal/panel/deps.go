package panel

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"
)

// Optional components (see agent/deps.go): status for everyone who can see the system
// page; installing / removing is super-admin only and audited.

func (a *App) handleDeps(w http.ResponseWriter, r *http.Request) {
	var res json.RawMessage
	if err := a.agent.Do("GET", "/v1/deps", nil, &res); err != nil {
		jsonErr(w, 502, agentMsg(err))
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(res)
}

func (a *App) handleDepsAction(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Action string   `json:"action"`
		IDs    []string `json:"ids"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 4096)).Decode(&req); err != nil {
		jsonErr(w, 400, "请求格式错误")
		return
	}
	var res json.RawMessage
	if err := a.agent.Do("POST", "/v1/deps", req, &res); err != nil {
		jsonErr(w, 400, agentMsg(err))
		return
	}
	verb := map[string]string{"install": "安装", "remove": "移除"}[req.Action]
	a.audit(actor{user: currentUser(r), ip: a.clientIP(r)}, "deps."+req.Action, "system", "deps", verb+"组件："+strings.Join(req.IDs, "、"), nil, nil, false)
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(res)
}
