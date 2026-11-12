package agent

import (
	"encoding/json"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/wangsirco/wharf/internal/sign"
	"github.com/wangsirco/wharf/internal/version"
)

// Version is the shared release version.
const Version = version.Version

type Config struct {
	Listen    string
	KeyID     string
	Secret    string
	AllowFrom []string // CIDRs/IPs allowed to connect; empty = any
	DataDir   string
}

type Server struct {
	cfg   Config
	ver   *sign.Verifier
	allow []*net.IPNet

	Traffic   *Traffic   // nil when collection is disabled
	Collector *Collector //
	Policy    *Policy    // nil when collection is disabled
}

func NewServer(cfg Config) *Server {
	s := &Server{cfg: cfg, ver: sign.NewVerifier(map[string][]byte{cfg.KeyID: []byte(cfg.Secret)})}
	for _, a := range cfg.AllowFrom {
		if !strings.Contains(a, "/") {
			if strings.Contains(a, ":") {
				a += "/128"
			} else {
				a += "/32"
			}
		}
		if _, n, err := net.ParseCIDR(a); err == nil {
			s.allow = append(s.allow, n)
		}
	}
	return s
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func (s *Server) allowed(r *http.Request) bool {
	if len(s.allow) == 0 {
		return true
	}
	host, _, _ := net.SplitHostPort(r.RemoteAddr)
	ip := net.ParseIP(host)
	for _, n := range s.allow {
		if ip != nil && n.Contains(ip) {
			return true
		}
	}
	return false
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if !s.allowed(r) {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "source not allowed"})
		return
	}
	body, err := s.ver.Verify(r)
	if err != nil {
		log.Printf("reject %s %s from %s: %v", r.Method, r.URL.Path, r.RemoteAddr, err)
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": err.Error()})
		return
	}
	switch {
	case r.Method == "GET" && r.URL.Path == "/v1/ping":
		sys := GetSystem()
		writeJSON(w, 200, map[string]any{"version": Version, "core_hash": version.CoreHash, "arch": PkgArch(), "hostname": sys.Hostname, "firewall": sys.Firewall, "time": sys.Time})
	case r.Method == "GET" && r.URL.Path == "/v1/system":
		writeJSON(w, 200, GetSystem())
	case r.Method == "GET" && r.URL.Path == "/v1/devices":
		writeJSON(w, 200, GetDevices())
	case r.Method == "GET" && r.URL.Path == "/v1/identity":
		writeJSON(w, 200, Fingerprints())
	case r.Method == "POST" && r.URL.Path == "/v1/identity/probe":
		go ProbeNetwork()
		writeJSON(w, 202, map[string]bool{"ok": true})
	case r.Method == "POST" && r.URL.Path == "/v1/panel/wan":
		var req struct {
			On bool     `json:"on"`
			CF []string `json:"cf"` // Cloudflare ranges allowed in when only they may reach the panel
		}
		_ = json.NewDecoder(io.LimitReader(r.Body, 64<<10)).Decode(&req)
		err := SetPanelWAN(req.On)
		if err == nil {
			err = SetPanelCF(req.CF)
		}
		if err != nil {
			writeJSON(w, 500, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, 200, map[string]bool{"ok": true})
	case r.Method == "POST" && r.URL.Path == "/v1/identity/dhcplog":
		var req struct {
			On bool `json:"on"`
		}
		_ = json.NewDecoder(io.LimitReader(r.Body, 1<<10)).Decode(&req)
		if err := SetDHCPLogging(req.On); err != nil {
			writeJSON(w, 500, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, 200, map[string]bool{"ok": true})
	case r.Method == "GET" && r.URL.Path == "/v1/uci":
		cfg := r.URL.Query().Get("config")
		if cfg == "" || strings.ContainsAny(cfg, "/. ") {
			writeJSON(w, 400, map[string]string{"error": "bad config"})
			return
		}
		v, err := uciGetConfig(cfg)
		if err != nil {
			writeJSON(w, 500, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, 200, v)
	case r.Method == "POST" && r.URL.Path == "/v1/uci/apply":
		var req struct {
			Changes []Change `json:"changes"`
		}
		if err := json.Unmarshal(body, &req); err != nil || len(req.Changes) == 0 {
			writeJSON(w, 400, map[string]string{"error": "bad request"})
			return
		}
		res, err := Apply(req.Changes)
		if err != nil {
			writeJSON(w, 500, map[string]string{"error": err.Error()})
			return
		}
		for _, c := range req.Changes {
			if c.Config == "owpdev" && s.Policy != nil {
				s.Policy.Reload(s.Collector.dns)
				break
			}
		}
		writeJSON(w, 200, map[string]any{"results": res})
	case r.Method == "POST" && r.URL.Path == "/v1/ipset":
		var req SetWrite
		if err := json.Unmarshal(body, &req); err != nil {
			writeJSON(w, 400, map[string]string{"error": "bad request"})
			return
		}
		path, err := s.WriteSet(req)
		if err != nil {
			writeJSON(w, 400, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, 200, map[string]string{"path": path})
	case r.Method == "GET" && r.URL.Path == "/v1/traffic/live":
		if s.Traffic == nil {
			writeJSON(w, 503, map[string]string{"error": "traffic collection disabled"})
			return
		}
		writeJSON(w, 200, map[string]any{"ts": time.Now().Unix(), "hosts": s.Traffic.Live()})
	case r.Method == "GET" && r.URL.Path == "/v1/collect":
		if s.Collector == nil {
			writeJSON(w, 503, map[string]string{"error": "traffic collection disabled"})
			return
		}
		after, _ := strconv.ParseInt(r.URL.Query().Get("after"), 10, 64)
		boot, recs := s.Collector.Since(after)
		writeJSON(w, 200, map[string]any{"boot": boot, "minutes": recs})
	case r.Method == "GET" && r.URL.Path == "/v1/wan":
		out := map[string]any{"wan": WANStatus("wan")}
		if w6 := WANStatus("wan6"); w6.Up {
			out["wan6"] = w6
		}
		var mw any
		if ubusCall("mwan3", "status", map[string]any{"section": "interfaces"}, &mw) == nil {
			out["mwan3"] = mw
		}
		writeJSON(w, 200, out)
	case r.Method == "POST" && r.URL.Path == "/v1/speedtest":
		if r.URL.Query().Get("engine") == "ookla" {
			writeJSON(w, 200, SpeedTestOokla())
		} else {
			writeJSON(w, 200, SpeedTest())
		}
	case r.Method == "GET" && r.URL.Path == "/v1/policy/status":
		if s.Policy == nil {
			writeJSON(w, 503, map[string]string{"error": "policies disabled"})
			return
		}
		writeJSON(w, 200, s.Policy.Status())
	case strings.HasPrefix(r.URL.Path, "/v1/sys/") || strings.HasPrefix(r.URL.Path, "/v1/upnp") || r.URL.Path == "/v1/wol":
		s.maint(w, r, body)
	case r.Method == "POST" && r.URL.Path == "/v1/diag":
		var req DiagReq
		if err := json.Unmarshal(body, &req); err != nil {
			writeJSON(w, 400, map[string]string{"error": "bad request"})
			return
		}
		res, err := Diag(req)
		if err != nil {
			writeJSON(w, 400, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, 200, res)
	case strings.HasPrefix(r.URL.Path, "/v1/capture"):
		s.capture(w, r, body)
	case r.Method == "GET" && r.URL.Path == "/v1/update/core":
		writeJSON(w, 200, CoreUpdateStatus())
	case r.Method == "POST" && r.URL.Path == "/v1/update/core":
		var req struct {
			URL    string `json:"url"`
			SHA256 string `json:"sha256"`
			Size   int64  `json:"size"`
		}
		if err := json.Unmarshal(body, &req); err != nil {
			writeJSON(w, 400, map[string]string{"error": "bad request"})
			return
		}
		if err := StartCoreUpdate(req.URL, req.SHA256, req.Size); err != nil {
			writeJSON(w, 400, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, 200, CoreUpdateStatus())
	case r.Method == "GET" && r.URL.Path == "/v1/deps":
		writeJSON(w, 200, map[string]any{"deps": Deps(), "job": DepStatus()})
	case r.Method == "POST" && r.URL.Path == "/v1/deps":
		var req struct {
			Action string   `json:"action"`
			IDs    []string `json:"ids"`
		}
		if err := json.Unmarshal(body, &req); err != nil {
			writeJSON(w, 400, map[string]string{"error": "bad request"})
			return
		}
		if err := StartDeps(req.Action, req.IDs); err != nil {
			writeJSON(w, 400, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, 200, DepStatus())
	case strings.HasPrefix(r.URL.Path, "/v1/proxy"):
		s.proxy(w, r, body)
	case r.Method == "GET" && r.URL.Path == "/v1/forward-live":
		if s.Collector == nil {
			writeJSON(w, 503, map[string]string{"error": "traffic collection disabled"})
			return
		}
		writeJSON(w, 200, s.Collector.LiveInbound())
	case r.Method == "GET" && r.URL.Path == "/v1/diag/iperf-server":
		writeJSON(w, 200, IperfServerStatus())
	case r.Method == "GET" && r.URL.Path == "/v1/iface":
		name := r.URL.Query().Get("name")
		if name == "" || strings.ContainsAny(name, "/. ") {
			writeJSON(w, 400, map[string]string{"error": "bad interface"})
			return
		}
		writeJSON(w, 200, WANStatus(name))
	case r.Method == "GET" && r.URL.Path == "/v1/wans":
		writeJSON(w, 200, WANList())
	case r.Method == "GET" && r.URL.Path == "/v1/listen":
		writeJSON(w, 200, Listeners())
	case strings.HasPrefix(r.URL.Path, "/v1/net") || strings.HasPrefix(r.URL.Path, "/v1/plugins") || strings.HasPrefix(r.URL.Path, "/v1/luci/") ||
		strings.HasPrefix(r.URL.Path, "/v1/store") || r.URL.Path == "/v1/uci/guarded" || r.URL.Path == "/v1/uci/confirm" || r.URL.Path == "/v1/uci/rollback":
		s.netAPI(w, r, body)
	case r.Method == "GET" && r.URL.Path == "/v1/neigh":
		// ip -> mac for LAN clients (used by the panel's LAN access control)
		writeJSON(w, 200, Neighbours())
	default:
		writeJSON(w, 404, map[string]string{"error": "not found"})
	}
}

func (s *Server) maint(w http.ResponseWriter, r *http.Request, body []byte) {
	fail := func(err error) { writeJSON(w, 400, map[string]string{"error": err.Error()}) }
	var req struct {
		Name   string         `json:"name"`
		Action string         `json:"action"`
		MAC    string         `json:"mac"`
		Num    string         `json:"num"`
		Data   string         `json:"data"`
		Sched  RebootSchedule `json:"schedule"`
	}
	if r.Method == "POST" {
		if err := json.Unmarshal(body, &req); err != nil {
			fail(err)
			return
		}
	}
	q := r.URL.Query()
	switch r.Method + " " + r.URL.Path {
	case "GET /v1/sys/hw":
		writeJSON(w, 200, GetHW())
	case "GET /v1/sys/services":
		writeJSON(w, 200, Services())
	case "POST /v1/sys/service":
		st, err := ServiceAction(req.Name, req.Action)
		if err != nil {
			fail(err)
			return
		}
		writeJSON(w, 200, st)
	case "GET /v1/sys/log":
		n, _ := strconv.Atoi(q.Get("lines"))
		writeJSON(w, 200, Logs(q.Get("source"), n, q.Get("q")))
	case "POST /v1/sys/reboot":
		log.Printf("reboot requested")
		Reboot()
		writeJSON(w, 200, map[string]bool{"ok": true})
	case "GET /v1/sys/backup":
		name, b, err := Backup()
		if err != nil {
			fail(err)
			return
		}
		writeJSON(w, 200, map[string]any{"name": name, "data": b})
	case "POST /v1/sys/restore":
		var files []string
		var err error
		if req.Action == "check" {
			var tmp string
			tmp, files, err = RestoreCheck(req.Data)
			_ = os.Remove(tmp)
		} else {
			files, err = Restore(req.Data)
		}
		if err != nil {
			fail(err)
			return
		}
		writeJSON(w, 200, map[string]any{"files": files})
	case "GET /v1/sys/reboot-schedule":
		writeJSON(w, 200, GetRebootSchedule())
	case "POST /v1/sys/reboot-schedule":
		if err := SetRebootSchedule(req.Sched); err != nil {
			fail(err)
			return
		}
		writeJSON(w, 200, GetRebootSchedule())
	case "GET /v1/upnp":
		en, running, rules := UPnP()
		writeJSON(w, 200, map[string]any{"enabled": en, "running": running, "rules": rules})
	case "POST /v1/upnp/delete":
		if err := UPnPDelete(req.Num); err != nil {
			fail(err)
			return
		}
		writeJSON(w, 200, map[string]bool{"ok": true})
	case "POST /v1/wol":
		if err := WakeOnLAN(req.MAC); err != nil {
			fail(err)
			return
		}
		writeJSON(w, 200, map[string]bool{"ok": true})
	default:
		writeJSON(w, 404, map[string]string{"error": "not found"})
	}
}

func (s *Server) capture(w http.ResponseWriter, r *http.Request, body []byte) {
	fail := func(code int, err error) { writeJSON(w, code, map[string]string{"error": err.Error()}) }
	var req struct {
		CaptureReq
		ID string `json:"id"`
	}
	if r.Method == "POST" {
		if err := json.Unmarshal(body, &req); err != nil {
			fail(400, err)
			return
		}
	}
	id := r.URL.Query().Get("id")
	switch r.Method + " " + r.URL.Path {
	case "GET /v1/capture":
		writeJSON(w, 200, map[string]any{"ifaces": CaptureIfaces(), "captures": ListCaptures()})
	case "POST /v1/capture":
		c, err := StartCapture(req.CaptureReq)
		if err != nil {
			fail(400, err)
			return
		}
		writeJSON(w, 200, c)
	case "POST /v1/capture/stop":
		if err := StopCapture(req.ID); err != nil {
			fail(400, err)
			return
		}
		writeJSON(w, 200, findCapture(req.ID))
	case "POST /v1/capture/delete":
		if err := DeleteCapture(req.ID); err != nil {
			fail(400, err)
			return
		}
		writeJSON(w, 200, map[string]bool{"ok": true})
	case "GET /v1/capture/analysis":
		a, err := AnalyseCapture(id)
		if err != nil {
			fail(400, err)
			return
		}
		writeJSON(w, 200, a)
	case "GET /v1/capture/file":
		f, c, err := CaptureFile(id)
		if err != nil {
			fail(404, err)
			return
		}
		defer f.Close()
		w.Header().Set("Content-Type", "application/vnd.tcpdump.pcap")
		w.Header().Set("X-Capture-Iface", c.Iface)
		if st, err := f.Stat(); err == nil {
			w.Header().Set("Content-Length", strconv.FormatInt(st.Size(), 10))
		}
		_, _ = io.Copy(w, f)
	default:
		writeJSON(w, 404, map[string]string{"error": "not found"})
	}
}

func (s *Server) proxy(w http.ResponseWriter, r *http.Request, body []byte) {
	fail := func(err error) { writeJSON(w, 400, map[string]string{"error": err.Error()}) }
	switch r.Method + " " + r.URL.Path {
	case "GET /v1/proxy":
		writeJSON(w, 200, GetProxyStatus())
	case "POST /v1/proxy/install":
		var req struct {
			Tag string `json:"tag"`
		}
		if err := json.Unmarshal(body, &req); err != nil {
			fail(err)
			return
		}
		if err := StartProxyInstall(req.Tag); err != nil {
			fail(err)
			return
		}
		writeJSON(w, 200, GetProxyStatus())
	case "POST /v1/proxy/uninstall":
		if err := StartProxyUninstall(); err != nil {
			fail(err)
			return
		}
		writeJSON(w, 200, GetProxyStatus())
	case "POST /v1/proxy/apply":
		var req ProxyApply
		if err := json.Unmarshal(body, &req); err != nil {
			fail(err)
			return
		}
		res, err := ApplyProxy(req)
		if err != nil {
			fail(err)
			return
		}
		writeJSON(w, 200, res)
	case "GET /v1/proxy/stats":
		after, _ := strconv.ParseInt(r.URL.Query().Get("after"), 10, 64)
		boot, mins, live := ProxySince(after)
		writeJSON(w, 200, map[string]any{"boot": boot, "minutes": mins, "live": live})
	case "GET /v1/proxy/log":
		n, _ := strconv.Atoi(r.URL.Query().Get("lines"))
		writeJSON(w, 200, map[string]any{"error": ProxyErrorLog(n)})
	case "GET /v1/proxy/certs":
		writeJSON(w, 200, ProxyCerts())
	case "POST /v1/proxy/block":
		var req struct {
			IP string `json:"ip"`
		}
		if err := json.Unmarshal(body, &req); err != nil {
			fail(err)
			return
		}
		if err := BlockProxyIP(req.IP); err != nil {
			fail(err)
			return
		}
		writeJSON(w, 200, map[string]bool{"ok": true})
	default:
		writeJSON(w, 404, map[string]string{"error": "not found"})
	}
}

// netAPI: interfaces, guarded changes, plugins and the app store.
func (s *Server) netAPI(w http.ResponseWriter, r *http.Request, body []byte) {
	fail := func(code int, err error) { writeJSON(w, code, map[string]string{"error": err.Error()}) }
	var req struct {
		Name    string         `json:"name"`
		Action  string         `json:"action"`
		Iface   string         `json:"iface"`
		Changes []Change       `json:"changes"`
		Seconds int            `json:"seconds"`
		Summary string         `json:"summary"`
		Token   string         `json:"token"`
		Pkgs    []string       `json:"pkgs"`
		Object  string         `json:"object"`
		Method  string         `json:"method"`
		Params  map[string]any `json:"params"`
	}
	if r.Method == "POST" && len(body) > 0 {
		if err := json.Unmarshal(body, &req); err != nil {
			fail(400, err)
			return
		}
	}
	q := r.URL.Query()
	switch r.Method + " " + r.URL.Path {
	case "GET /v1/net":
		writeJSON(w, 200, GetNetOverview())
	case "GET /v1/net/health":
		out := map[string]any{"wans": WANList(), "pending": CurrentPending(), "rollback": LastRollback()}
		if s.Collector != nil && s.Collector.Net != nil {
			out["health"] = s.Collector.Net.Health()
		}
		writeJSON(w, 200, out)
	case "POST /v1/net/iface":
		if err := IfaceAction(req.Name, req.Action); err != nil {
			fail(400, err)
			return
		}
		writeJSON(w, 200, map[string]bool{"ok": true})
	case "POST /v1/net/diagnose":
		writeJSON(w, 200, DiagnoseWAN(req.Iface))
	case "POST /v1/uci/guarded":
		if len(req.Changes) == 0 {
			fail(400, errors.New("no changes"))
			return
		}
		res, p, err := ApplyGuarded(req.Changes, req.Seconds, req.Summary)
		if err != nil {
			fail(409, err)
			return
		}
		writeJSON(w, 200, map[string]any{"results": res, "pending": p})
	case "POST /v1/uci/confirm":
		if err := ConfirmApply(req.Token); err != nil {
			fail(409, err)
			return
		}
		writeJSON(w, 200, map[string]bool{"ok": true})
	case "POST /v1/uci/rollback":
		if err := RollbackApply(req.Token); err != nil {
			fail(409, err)
			return
		}
		writeJSON(w, 200, map[string]bool{"ok": true})
	case "GET /v1/plugins":
		writeJSON(w, 200, Plugins(q.Get("fresh") == "1"))
	case "GET /v1/plugins/form":
		out, err := PluginForm(q.Get("model"))
		if err != nil {
			fail(400, err)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(out)
	case "POST /v1/plugins/service":
		if err := PluginService(req.Name, req.Action); err != nil {
			fail(400, err)
			return
		}
		writeJSON(w, 200, map[string]bool{"ok": true})
	case "GET /v1/luci/i18n":
		out, _ := LuciTranslations()
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(out)
	case "GET /v1/luci/file":
		b, err := LuciFile(q.Get("path"))
		if err != nil {
			fail(404, err)
			return
		}
		writeJSON(w, 200, map[string]string{"source": string(b)})
	case "POST /v1/luci/rpc":
		out, err := LuciRPC(req.Object, req.Method, req.Params)
		if err != nil {
			fail(400, err)
			return
		}
		writeJSON(w, 200, map[string]any{"result": out})
	case "GET /v1/store":
		writeJSON(w, 200, GetStore())
	case "GET /v1/store/check":
		c, err := CheckInstall(q.Get("pkg"))
		if err != nil {
			fail(400, err)
			return
		}
		writeJSON(w, 200, c)
	case "GET /v1/store/job":
		writeJSON(w, 200, StoreStatus())
	case "POST /v1/store":
		if err := StartStore(req.Action, req.Pkgs); err != nil {
			fail(409, err)
			return
		}
		writeJSON(w, 202, map[string]bool{"ok": true})
	default:
		writeJSON(w, 404, map[string]string{"error": "not found"})
	}
}
