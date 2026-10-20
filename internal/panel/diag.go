package panel

import (
	"crypto/rand"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"strconv"
	"time"

	"github.com/wangsirco/wharf/internal/tlsutil"
)

// Network diagnostics (tools.diag): the router runs the tool, the panel adds
// geography / ASN to every hop so the route can be drawn on the map, and a
// browser speed test measures the link between the viewer's device and the router.

type traceHop struct {
	Hop     int     `json:"hop"`
	IP      string  `json:"ip,omitempty"`
	Host    string  `json:"host,omitempty"`
	Loss    float64 `json:"loss"`
	Sent    int     `json:"sent"`
	Last    float64 `json:"last"`
	Avg     float64 `json:"avg"`
	Best    float64 `json:"best"`
	Worst   float64 `json:"worst"`
	StDev   float64 `json:"stdev"`
	Private bool    `json:"private,omitempty"`
	ASN     uint    `json:"asn,omitempty"`
	ASOrg   string  `json:"as_org,omitempty"`
	Country string  `json:"country,omitempty"`
	CName   string  `json:"country_name,omitempty"`
	Region  string  `json:"region,omitempty"`
	City    string  `json:"city,omitempty"`
	Lat     float64 `json:"lat,omitempty"`
	Lon     float64 `json:"lon,omitempty"`
}

func (a *App) handleDiag(w http.ResponseWriter, r *http.Request) {
	u := currentUser(r)
	key := "diag:" + u.Username
	if a.beacons.blocked(key) {
		jsonErr(w, 429, "操作太频繁，请稍后再试")
		return
	}
	for i := 0; i < 4; i++ { // ~15 runs a minute per user
		a.beacons.record(key)
	}
	var req map[string]any
	if err := json.NewDecoder(io.LimitReader(r.Body, 8192)).Decode(&req); err != nil {
		jsonErr(w, 400, "请求格式错误")
		return
	}
	tool, _ := req["tool"].(string)
	if tool == "trace" {
		var res struct {
			Target string     `json:"target"`
			IP     string     `json:"ip"`
			Mode   string     `json:"mode"`
			Secs   float64    `json:"secs"`
			Hops   []traceHop `json:"hops"`
		}
		if err := a.agent.Do("POST", "/v1/diag", req, &res); err != nil {
			jsonErr(w, 400, agentMsg(err))
			return
		}
		for i := range res.Hops {
			a.placeHop(&res.Hops[i])
		}
		writeJSON(w, 200, map[string]any{"target": res.Target, "ip": res.IP, "mode": res.Mode, "secs": res.Secs, "hops": res.Hops, "origin": a.homePlace()})
		return
	}
	var res json.RawMessage
	if err := a.agent.Do("POST", "/v1/diag", req, &res); err != nil {
		jsonErr(w, 400, agentMsg(err))
		return
	}
	if tool == "scan" {
		res = scanVendors(res)
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(res)
}

func agentMsg(err error) string {
	var ae *AgentError
	if errors.As(err, &ae) && ae.Msg != "" {
		return ae.Msg
	}
	return err.Error()
}

func (a *App) placeHop(h *traceHop) {
	ip := net.ParseIP(h.IP)
	if ip == nil {
		return
	}
	if tlsutil.PrivateIP(ip) || ip.IsLinkLocalUnicast() {
		h.Private = true
		return
	}
	g := a.geo.LookupFast(h.IP)
	h.ASN, h.ASOrg, h.Country, h.Region, h.City, h.Lat, h.Lon = g.ASN, g.ASOrg, g.Country, g.Region, g.City, g.Lat, g.Lon
	if g.Country != "" {
		h.CName = a.countryName(g.Country)
	}
}

func (a *App) homePlace() map[string]any {
	var wan struct {
		Wan struct {
			IPv4 string `json:"ipv4"`
		} `json:"wan"`
	}
	if a.agent.Do("GET", "/v1/wan", nil, &wan) != nil || wan.Wan.IPv4 == "" {
		return nil
	}
	g := a.geo.LookupFast(wan.Wan.IPv4)
	if g.Country == "" {
		return nil
	}
	return map[string]any{"lat": g.Lat, "lon": g.Lon, "city": g.City, "country": g.Country, "name": a.countryName(g.Country)}
}

func (a *App) handleIperfServer(w http.ResponseWriter, r *http.Request) {
	var res json.RawMessage
	if err := a.agent.Do("GET", "/v1/diag/iperf-server", nil, &res); err != nil {
		jsonErr(w, 502, agentMsg(err))
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(res)
}

// ---- browser ↔ router speed test ----

var speedBlock = func() []byte {
	b := make([]byte, 1<<20)
	_, _ = rand.Read(b) // incompressible
	return b
}()

// GET /api/tools/speed/down?mb=N — N MiB of random bytes (max 256).
func (a *App) handleSpeedDown(w http.ResponseWriter, r *http.Request) {
	mb, _ := strconv.Atoi(r.URL.Query().Get("mb"))
	mb = max(1, min(256, mb))
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Length", strconv.Itoa(mb<<20))
	w.Header().Set("Cache-Control", "no-store")
	rc := http.NewResponseController(w)
	_ = rc.SetWriteDeadline(time.Now().Add(60 * time.Second))
	for i := 0; i < mb; i++ {
		if _, err := w.Write(speedBlock); err != nil {
			return
		}
	}
}

// POST /api/tools/speed/up — reads and discards up to 256 MiB, reports what arrived.
func (a *App) handleSpeedUp(w http.ResponseWriter, r *http.Request) {
	rc := http.NewResponseController(w)
	_ = rc.SetReadDeadline(time.Now().Add(60 * time.Second))
	start := time.Now()
	n, _ := io.Copy(io.Discard, io.LimitReader(r.Body, 256<<20))
	writeJSON(w, 200, map[string]any{"bytes": n, "ms": time.Since(start).Milliseconds()})
}
