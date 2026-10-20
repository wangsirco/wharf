package panel

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"
)

// Optional Proxmox VE integration: with a read-only API token (PVEAuditor role) the
// panel maps every guest NIC's MAC address to the VM / container name, so guests
// that send no DHCP hostname still get their real name, tagged "PVE 虚拟机".
// PVE uses a self-signed certificate; the panel pins its SHA-256 fingerprint.

type pveGuest struct {
	VMID   int    `json:"vmid"`
	Name   string `json:"name"`
	Node   string `json:"node"`
	Kind   string `json:"kind"` // qemu | lxc
	Status string `json:"status"`
}

type pveCache struct {
	mu    sync.RWMutex
	byMAC map[string]pveGuest
	at    time.Time
	err   string
	kick  chan struct{}
}

var (
	pveTokenRe = regexp.MustCompile(`^[A-Za-z0-9._-]+@[A-Za-z0-9._-]+![A-Za-z0-9._-]+=[0-9a-fA-F-]{36}$`)
	pveMACRe   = regexp.MustCompile(`(?i)\b([0-9a-f]{2}(?::[0-9a-f]{2}){5})\b`)
	pveFPRe    = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

func validPVESetting(key, value string) (bool, error) {
	switch key {
	case "pve.url":
		if value == "" {
			return true, nil
		}
		u, err := url.Parse(value)
		if err != nil || u.Scheme != "https" || u.Host == "" || (u.Path != "" && u.Path != "/") {
			return true, errors.New("PVE 地址格式应为 https://主机:8006")
		}
		return true, nil
	case "pve.token":
		if value != "" && !pveTokenRe.MatchString(value) {
			return true, errors.New("API Token 格式应为 用户@域!令牌名=UUID")
		}
		return true, nil
	case "pve.fingerprint":
		if value != "" && !pveFPRe.MatchString(value) {
			return true, errors.New("证书指纹格式不正确")
		}
		return true, nil
	}
	return false, nil
}

// pveClient returns an HTTP client that only trusts a certificate with the given
// fingerprint; an empty pin records the presented fingerprint into *seen instead.
func pveClient(pin string, seen *string) *http.Client {
	tr := &http.Transport{TLSClientConfig: &tls.Config{
		InsecureSkipVerify: true, // replaced by the pin check below
		VerifyConnection: func(cs tls.ConnectionState) error {
			if len(cs.PeerCertificates) == 0 {
				return errors.New("no certificate")
			}
			fp := certFP(cs.PeerCertificates[0])
			if seen != nil {
				*seen = fp
			}
			if pin != "" && fp != pin {
				return errors.New("PVE 证书指纹与保存的不一致")
			}
			return nil
		},
	}}
	return &http.Client{Timeout: 10 * time.Second, Transport: tr}
}

func certFP(c *x509.Certificate) string {
	s := sha256.Sum256(c.Raw)
	return hex.EncodeToString(s[:])
}

func pveGet(cl *http.Client, base, token, path string, out any) error {
	req, _ := http.NewRequest("GET", strings.TrimRight(base, "/")+"/api2/json"+path, nil)
	req.Header.Set("Authorization", "PVEAPIToken="+token)
	resp, err := cl.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	switch resp.StatusCode {
	case 200:
	case 401:
		return errors.New("API Token 无效")
	case 403:
		return errors.New("权限不足：请给 Token 授予 PVEAuditor 角色")
	default:
		return fmt.Errorf("PVE 返回 %s", resp.Status)
	}
	return json.NewDecoder(resp.Body).Decode(&struct {
		Data any `json:"data"`
	}{out})
}

// pveFetch lists all guests and their NIC MAC addresses.
func pveFetch(cl *http.Client, base, token string) (map[string]pveGuest, int, error) {
	var res []struct {
		VMID   int    `json:"vmid"`
		Name   string `json:"name"`
		Node   string `json:"node"`
		Type   string `json:"type"`
		Status string `json:"status"`
	}
	if err := pveGet(cl, base, token, "/cluster/resources?type=vm", &res); err != nil {
		return nil, 0, err
	}
	out := map[string]pveGuest{}
	for _, g := range res {
		if g.Type != "qemu" && g.Type != "lxc" {
			continue
		}
		var cfg map[string]any
		if err := pveGet(cl, base, token, fmt.Sprintf("/nodes/%s/%s/%d/config", url.PathEscape(g.Node), g.Type, g.VMID), &cfg); err != nil {
			continue
		}
		name := g.Name
		if h, ok := cfg["hostname"].(string); ok && h != "" {
			name = h
		}
		for k, v := range cfg {
			s, ok := v.(string)
			if !ok || !strings.HasPrefix(k, "net") {
				continue
			}
			if m := pveMACRe.FindString(s); m != "" {
				out[strings.ToLower(m)] = pveGuest{VMID: g.VMID, Name: name, Node: g.Node, Kind: g.Type, Status: g.Status}
			}
		}
	}
	return out, len(res), nil
}

func (a *App) pveGuest(mac string) (pveGuest, bool) {
	a.pve.mu.RLock()
	defer a.pve.mu.RUnlock()
	g, ok := a.pve.byMAC[mac]
	return g, ok
}

func (a *App) pveRefresh() {
	base, token, pin := a.setting("pve.url"), a.setting("pve.token"), a.setting("pve.fingerprint")
	var m map[string]pveGuest
	var err error
	if base != "" && token != "" {
		m, _, err = pveFetch(pveClient(pin, nil), base, token)
	}
	a.pve.mu.Lock()
	defer a.pve.mu.Unlock()
	switch {
	case base == "" || token == "":
		a.pve.byMAC, a.pve.err = nil, ""
	case err != nil:
		a.pve.err = err.Error() // keep the last good map
		log.Printf("pve: %v", err)
	default:
		a.pve.byMAC, a.pve.err = m, ""
	}
	a.pve.at = time.Now()
}

func (a *App) pveLoop() {
	for {
		a.pveRefresh()
		select {
		case <-time.After(10 * time.Minute):
		case <-a.pve.kick:
		}
	}
}

func (a *App) pveKick() {
	select {
	case a.pve.kick <- struct{}{}:
	default:
	}
}

// POST /api/pve/test {url, token} — checks the token and returns the certificate
// fingerprint to pin plus the guests found. Empty fields fall back to saved ones.
func (a *App) handlePVETest(w http.ResponseWriter, r *http.Request) {
	var req struct {
		URL   string `json:"url"`
		Token string `json:"token"`
	}
	_ = readJSON(r, &req)
	if req.URL == "" {
		req.URL = a.setting("pve.url")
	}
	if req.Token == "" {
		req.Token = a.setting("pve.token")
	}
	for k, v := range map[string]string{"pve.url": req.URL, "pve.token": req.Token} {
		if _, err := validPVESetting(k, v); err != nil || v == "" {
			jsonErr(w, 400, firstNonEmpty(errString(err), "请填写 PVE 地址和 API Token"))
			return
		}
	}
	var fp string
	m, n, err := pveFetch(pveClient("", &fp), req.URL, req.Token)
	if err != nil {
		jsonErr(w, 400, "连接失败："+err.Error())
		return
	}
	var guests []pveGuest
	seen := map[int]bool{}
	for _, g := range m {
		if !seen[g.VMID] {
			seen[g.VMID] = true
			guests = append(guests, g)
		}
	}
	writeJSON(w, 200, map[string]any{"ok": true, "fingerprint": fp, "total": n, "guests": guests, "macs": len(m)})
}

// GET /api/pve/status
func (a *App) handlePVEStatus(w http.ResponseWriter, r *http.Request) {
	a.pve.mu.RLock()
	defer a.pve.mu.RUnlock()
	writeJSON(w, 200, map[string]any{"configured": a.setting("pve.token") != "", "macs": len(a.pve.byMAC),
		"updated": a.pve.at.Unix(), "error": a.pve.err})
}

func errString(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}
