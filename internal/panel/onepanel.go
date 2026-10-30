package panel

import (
	"bytes"
	"crypto/md5"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/netip"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"
)

// 1Panel integration (optional, super admin). When the server behind the WAN 443 port
// forward is a 1Panel host, its API tells which websites live there: the proxy page
// lists them as "still served by 1Panel" and node domains may not collide with them.
// Nothing is ever changed on the 1Panel side; the API key only needs to read.
//
// Auth (1Panel v1 and v2): 1Panel-Token = md5("1panel" + key + timestamp), 1Panel-Timestamp.

type onePanelSite struct {
	ID       int      `json:"id"`
	Domain   string   `json:"domain"` // primary domain
	Domains  []string `json:"domains"`
	Alias    string   `json:"alias"`
	Type     string   `json:"type"`
	Status   string   `json:"status"`
	Protocol string   `json:"protocol"` // HTTP | HTTPS
	Remark   string   `json:"remark"`
}

var onePanel struct {
	sync.Mutex
	sites []onePanelSite
	at    time.Time
	err   string
	ver   string
}

func onePanelClient(base string) *http.Client {
	c := &http.Client{Timeout: 15 * time.Second}
	// a LAN 1Panel usually has a self-signed certificate; only private addresses skip the check
	if u, err := url.Parse(base); err == nil {
		if ip, err := netip.ParseAddr(u.Hostname()); err == nil && ip.IsPrivate() {
			c.Transport = &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}
		}
	}
	return c
}

func onePanelCall(c *http.Client, base, key, ver, method, path string, body any, out any) error {
	var rd io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequest(method, strings.TrimRight(base, "/")+"/api/"+ver+path, rd)
	if err != nil {
		return err
	}
	ts := strconv.FormatInt(time.Now().Unix(), 10)
	sum := md5.Sum([]byte("1panel" + key + ts))
	req.Header.Set("1Panel-Token", hex.EncodeToString(sum[:]))
	req.Header.Set("1Panel-Timestamp", ts)
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.Do(req)
	if err != nil {
		return errors.New(shortErr(err))
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	var env struct {
		Code    int             `json:"code"`
		Message string          `json:"message"`
		Data    json.RawMessage `json:"data"`
	}
	if json.Unmarshal(b, &env) != nil {
		return errNotOnePanelAPI
	}
	if env.Code != 200 {
		msg := env.Message
		if strings.Contains(msg, "禁止") || strings.Contains(strings.ToLower(msg), "api") || env.Code == 401 {
			msg += "（在 1Panel「面板设置 → API 接口」开启，并把路由器的局域网地址加入 IP 白名单）"
		}
		return fmt.Errorf("1Panel：%s", firstNonEmpty(msg, "HTTP "+strconv.Itoa(resp.StatusCode)))
	}
	if out != nil {
		return json.Unmarshal(env.Data, out)
	}
	return nil
}

var errNotOnePanelAPI = errors.New("这个地址没有 1Panel 接口（地址和端口对吗？安全入口不用填）")

// fetchOnePanelSites reads every website and its domains.
func fetchOnePanelSites(base, key string) ([]onePanelSite, string, error) {
	c := onePanelClient(base)
	type item struct {
		ID            int    `json:"id"`
		PrimaryDomain string `json:"primaryDomain"`
		Alias         string `json:"alias"`
		Type          string `json:"type"`
		Status        string `json:"status"`
		Protocol      string `json:"protocol"`
		Remark        string `json:"remark"`
	}
	var page struct {
		Total int    `json:"total"`
		Items []item `json:"items"`
	}
	search := map[string]any{"page": 1, "pageSize": 500, "orderBy": "created_at", "order": "null", "name": "", "websiteGroupId": 0}
	ver := ""
	var err error
	for _, v := range []string{"v1", "v2"} {
		if err = onePanelCall(c, base, key, v, "POST", "/websites/search", search, &page); !errors.Is(err, errNotOnePanelAPI) {
			ver = v
			break
		}
	}
	if err != nil {
		return nil, "", err
	}
	var out []onePanelSite
	for _, it := range page.Items {
		s := onePanelSite{ID: it.ID, Domain: strings.ToLower(it.PrimaryDomain), Alias: it.Alias, Type: it.Type, Status: it.Status, Protocol: it.Protocol, Remark: it.Remark}
		var doms []struct {
			Domain string `json:"domain"`
		}
		if err := onePanelCall(c, base, key, ver, "GET", "/websites/domains/"+strconv.Itoa(it.ID), nil, &doms); err == nil {
			for _, d := range doms {
				if d := strings.ToLower(strings.TrimSpace(d.Domain)); d != "" && !slices.Contains(s.Domains, d) {
					s.Domains = append(s.Domains, d)
				}
			}
		}
		if s.Domain != "" && !slices.Contains(s.Domains, s.Domain) {
			s.Domains = append([]string{s.Domain}, s.Domains...)
		}
		out = append(out, s)
	}
	return out, ver, nil
}

func (a *App) refreshOnePanel() error {
	base, key := a.setting("onepanel.url"), a.setting("onepanel.key")
	if base == "" || key == "" {
		onePanel.Lock()
		onePanel.sites, onePanel.err, onePanel.ver = nil, "", ""
		onePanel.Unlock()
		return nil
	}
	sites, ver, err := fetchOnePanelSites(base, key)
	onePanel.Lock()
	defer onePanel.Unlock()
	onePanel.at = time.Now()
	if err != nil {
		onePanel.err = err.Error()
		return err
	}
	onePanel.sites, onePanel.err, onePanel.ver = sites, "", ver
	return nil
}

// onePanelOwner returns the 1Panel website that serves a domain (wildcards included).
func onePanelOwner(domain string) *onePanelSite {
	onePanel.Lock()
	defer onePanel.Unlock()
	for i, s := range onePanel.sites {
		for _, d := range s.Domains {
			if d == domain || (strings.HasPrefix(d, "*.") && strings.HasSuffix(domain, d[1:]) && !strings.Contains(strings.TrimSuffix(domain, d[1:]), ".")) {
				return &onePanel.sites[i]
			}
		}
	}
	return nil
}

func (a *App) onePanelLoop() {
	time.Sleep(15 * time.Second)
	for {
		if err := a.refreshOnePanel(); err != nil {
			log.Printf("1panel: %v", err)
		}
		time.Sleep(10 * time.Minute)
	}
}

func (a *App) onePanelState() map[string]any {
	onePanel.Lock()
	defer onePanel.Unlock()
	key := a.setting("onepanel.key")
	sites := onePanel.sites
	if sites == nil {
		sites = []onePanelSite{}
	}
	out := map[string]any{"url": a.setting("onepanel.url"), "key": maskSecret(key), "sites": sites, "error": onePanel.err, "api": onePanel.ver}
	if !onePanel.at.IsZero() {
		out["fetched"] = onePanel.at.Unix()
	}
	return out
}

// GET /api/proxy/onepanel
func (a *App) handleOnePanel(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, 200, a.onePanelState())
}

// POST /api/proxy/onepanel {url, key}  (masked key = keep; empty url = disconnect)
func (a *App) handleOnePanelSave(w http.ResponseWriter, r *http.Request) {
	var req struct {
		URL string `json:"url"`
		Key string `json:"key"`
	}
	if err := readJSON(r, &req); err != nil {
		jsonErr(w, 400, "请求格式错误")
		return
	}
	req.URL = strings.TrimRight(strings.TrimSpace(req.URL), "/")
	if req.URL != "" {
		u, err := url.Parse(req.URL)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
			jsonErr(w, 400, "1Panel 地址应为 http(s)://IP:端口，例如 http://192.168.1.10:8888")
			return
		}
		req.URL = u.Scheme + "://" + u.Host // the security entrance path is not needed for the API
	}
	oldURL, oldKey := a.setting("onepanel.url"), a.setting("onepanel.key")
	key := strings.TrimSpace(req.Key)
	if strings.HasPrefix(key, "••") {
		key = oldKey
	}
	if req.URL == "" {
		key = ""
	}
	if req.URL != "" {
		if key == "" {
			jsonErr(w, 400, "请填写 1Panel 的 API 密钥")
			return
		}
		if _, _, err := fetchOnePanelSites(req.URL, key); err != nil {
			jsonErr(w, 400, err.Error())
			return
		}
	}
	_ = a.setSetting("onepanel.url", req.URL)
	_ = a.setSetting("onepanel.key", key)
	_ = a.refreshOnePanel()
	what := "连接 1Panel " + req.URL
	if req.URL == "" {
		what = "断开 1Panel"
	}
	a.audit(actor{user: currentUser(r), ip: a.clientIP(r)}, "proxy.onepanel", "proxy", "onepanel", what,
		map[string]any{"url": oldURL, "key": oldKey != ""}, map[string]any{"url": req.URL, "key": key != ""}, false)
	writeJSON(w, 200, a.onePanelState())
}

// parentDomain: "blog.example.com" -> "example.com" (for suggestions only).
func parentDomain(d string) string {
	if i := strings.Index(d, "."); i > 0 && strings.Count(d, ".") > 1 {
		return d[i+1:]
	}
	return d
}
