package panel

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/wangsirco/wharf/internal/oui"
	"github.com/wangsirco/wharf/internal/sign"
)

// Packet capture (tools.capture): the router records, analyses and keeps the files; the
// panel audits who captured what and streams the pcap to the browser for Wireshark.

var capIDRe = regexp.MustCompile(`^[0-9a-f]{12}$`)

// Stream performs a signed GET and returns the raw response (caller closes the body).
func (c *AgentClient) Stream(path string) (*http.Response, error) {
	req, err := http.NewRequest("GET", strings.TrimRight(c.cfg.URL, "/")+path, bytes.NewReader(nil))
	if err != nil {
		return nil, err
	}
	sign.Sign(req, c.cfg.KeyID, []byte(c.cfg.Secret), nil)
	// downloads can be large and slow: no overall client timeout here
	resp, err := (&http.Client{Transport: c.http.Transport}).Do(req)
	if err != nil {
		return nil, fmt.Errorf("agent unreachable: %w", err)
	}
	if resp.StatusCode != 200 {
		defer resp.Body.Close()
		var e struct {
			Error string `json:"error"`
		}
		_ = json.NewDecoder(io.LimitReader(resp.Body, 4096)).Decode(&e)
		return nil, &AgentError{resp.StatusCode, e.Error}
	}
	return resp, nil
}

func (a *App) handleCaptures(w http.ResponseWriter, r *http.Request) {
	var res json.RawMessage
	if err := a.agent.Do("GET", "/v1/capture", nil, &res); err != nil {
		jsonErr(w, 502, agentMsg(err))
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(res)
}

func (a *App) handleCaptureStart(w http.ResponseWriter, r *http.Request) {
	u := currentUser(r)
	var req map[string]any
	if err := json.NewDecoder(io.LimitReader(r.Body, 8192)).Decode(&req); err != nil {
		jsonErr(w, 400, "请求格式错误")
		return
	}
	req["by"] = u.DisplayName
	var c struct {
		ID     string `json:"id"`
		Iface  string `json:"iface"`
		Filter string `json:"filter"`
		Secs   int    `json:"secs"`
		MaxMB  int    `json:"max_mb"`
	}
	if err := a.agent.Do("POST", "/v1/capture", req, &c); err != nil {
		jsonErr(w, 400, agentMsg(err))
		return
	}
	filter := c.Filter
	if filter == "" {
		filter = "全部流量"
	}
	a.audit(actor{user: u, ip: a.clientIP(r)}, "capture.start", "capture", c.ID,
		fmt.Sprintf("开始抓包：%s · %s · 最长 %d 秒 / %d MB", c.Iface, truncate(filter, 160), c.Secs, c.MaxMB), nil, nil, false)
	writeJSON(w, 200, c)
}

func (a *App) handleCaptureOp(w http.ResponseWriter, r *http.Request) {
	id, op := r.PathValue("id"), r.PathValue("op")
	if !capIDRe.MatchString(id) || (op != "stop" && op != "delete") {
		jsonErr(w, 400, "参数错误")
		return
	}
	var res json.RawMessage
	if err := a.agent.Do("POST", "/v1/capture/"+op, map[string]string{"id": id}, &res); err != nil {
		jsonErr(w, 400, agentMsg(err))
		return
	}
	if op == "delete" {
		a.audit(actor{user: currentUser(r), ip: a.clientIP(r)}, "capture.delete", "capture", id, "删除抓包文件 "+id, nil, nil, false)
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(res)
}

func (a *App) handleCaptureAnalysis(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if !capIDRe.MatchString(id) {
		jsonErr(w, 400, "参数错误")
		return
	}
	var res json.RawMessage
	if err := a.agent.Do("GET", "/v1/capture/analysis?id="+id, nil, &res); err != nil {
		jsonErr(w, 400, agentMsg(err))
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(res)
}

func (a *App) handleCaptureDownload(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if !capIDRe.MatchString(id) {
		jsonErr(w, 400, "参数错误")
		return
	}
	resp, err := a.agent.Stream("/v1/capture/file?id=" + id)
	if err != nil {
		jsonErr(w, 404, agentMsg(err))
		return
	}
	defer resp.Body.Close()
	name := fmt.Sprintf("wharf-%s-%s-%s.pcap", strings.ReplaceAll(resp.Header.Get("X-Capture-Iface"), "/", "_"), time.Now().Format("20060102-1504"), id[:6])
	w.Header().Set("Content-Type", "application/vnd.tcpdump.pcap")
	w.Header().Set("Content-Disposition", `attachment; filename="`+name+`"`)
	if l := resp.Header.Get("Content-Length"); l != "" {
		w.Header().Set("Content-Length", l)
	}
	_ = http.NewResponseController(w).SetWriteDeadline(time.Now().Add(10 * time.Minute))
	a.audit(actor{user: currentUser(r), ip: a.clientIP(r)}, "capture.download", "capture", id, "下载抓包文件 "+name, nil, nil, false)
	_, _ = io.Copy(w, resp.Body)
}

// scanVendors adds the OUI vendor to LAN scan results (devices without a DHCP lease included).
func scanVendors(raw json.RawMessage) json.RawMessage {
	var res map[string]any
	if json.Unmarshal(raw, &res) != nil {
		return raw
	}
	hosts, _ := res["hosts"].([]any)
	for _, h := range hosts {
		if m, ok := h.(map[string]any); ok {
			if mac, _ := m["mac"].(string); mac != "" {
				m["vendor"], m["random_mac"] = oui.Vendor(mac), oui.Random(mac)
			}
		}
	}
	b, _ := json.Marshal(res)
	return b
}
