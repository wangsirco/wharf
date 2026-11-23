package panel

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"
)

// cfErr is a Cloudflare API error with its codes, so callers can tell "no permission"
// (10000, 9109) and "Zero Trust not set up" from other failures.
type cfErr struct {
	Status int
	Codes  []int
	Msg    string
}

func (e *cfErr) Error() string { return "Cloudflare：" + e.Msg }

func (e *cfErr) denied() bool {
	if e.Status == 403 {
		return true
	}
	for _, c := range e.Codes {
		if c == 10000 || c == 9109 || c == 10001 {
			return true
		}
	}
	return false
}

func isDenied(err error) bool {
	var ce *cfErr
	return errors.As(err, &ce) && ce.denied()
}

var cfHTTP = &http.Client{Timeout: 20 * time.Second}

// cfDo calls the API and reads the envelope whatever the HTTP status.
func cfDo(token, method, path string, body any, out any) error {
	var rd io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	}
	req, _ := http.NewRequest(method, cfAPI+path, rd)
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := cfHTTP.Do(req)
	if err != nil {
		return errors.New("连不上 Cloudflare：" + shortErr(err))
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	var env struct {
		Success bool `json:"success"`
		Errors  []struct {
			Code    int    `json:"code"`
			Message string `json:"message"`
		} `json:"errors"`
		Result json.RawMessage `json:"result"`
	}
	if err := json.Unmarshal(b, &env); err != nil {
		return &cfErr{Status: resp.StatusCode, Msg: fmt.Sprintf("HTTP %d", resp.StatusCode)}
	}
	if !env.Success || resp.StatusCode/100 != 2 {
		e := &cfErr{Status: resp.StatusCode}
		var msgs []string
		for _, x := range env.Errors {
			e.Codes = append(e.Codes, x.Code)
			msgs = append(msgs, x.Message)
		}
		e.Msg = strings.Join(msgs, "；")
		if e.Msg == "" {
			e.Msg = fmt.Sprintf("HTTP %d", resp.StatusCode)
		}
		return e
	}
	if out != nil && len(env.Result) > 0 && string(env.Result) != "null" {
		return json.Unmarshal(env.Result, out)
	}
	return nil
}

// cfGraphQL runs an analytics query.
func cfGraphQL(token, query string, vars map[string]any, out any) error {
	b, _ := json.Marshal(map[string]any{"query": query, "variables": vars})
	req, _ := http.NewRequest("POST", cfAPI+"/graphql", bytes.NewReader(b))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := cfHTTP.Do(req)
	if err != nil {
		return errors.New("连不上 Cloudflare：" + shortErr(err))
	}
	defer resp.Body.Close()
	var env struct {
		Data   json.RawMessage `json:"data"`
		Errors []struct {
			Message string `json:"message"`
		} `json:"errors"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 4<<20)).Decode(&env); err != nil {
		return &cfErr{Status: resp.StatusCode, Msg: fmt.Sprintf("HTTP %d", resp.StatusCode)}
	}
	if len(env.Errors) > 0 {
		e := &cfErr{Status: resp.StatusCode, Msg: env.Errors[0].Message}
		if m := strings.ToLower(e.Msg); strings.Contains(m, "not authorized") || strings.Contains(m, "authentication") || strings.Contains(m, "does not have permission") {
			e.Status = 403
		}
		return e
	}
	return json.Unmarshal(env.Data, out)
}

// ---- the account behind the token ----

type cfAccountInfo struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

var cfAccountCache struct {
	sync.Mutex
	token string
	acc   *cfAccountInfo
	at    time.Time
}

// cfAccountOf: the (first) account the token reaches; tunnels and Access live there.
func cfAccountOf(token string) (*cfAccountInfo, error) {
	cfAccountCache.Lock()
	defer cfAccountCache.Unlock()
	if cfAccountCache.token == token && cfAccountCache.acc != nil && time.Since(cfAccountCache.at) < 10*time.Minute {
		return cfAccountCache.acc, nil
	}
	var accs []cfAccountInfo
	if err := cfDo(token, "GET", "/accounts?per_page=5", nil, &accs); err != nil {
		return nil, err
	}
	if len(accs) == 0 {
		// tokens scoped to zones only can't list accounts; the zone tells
		var zs []struct {
			Account cfAccountInfo `json:"account"`
		}
		if err := cfDo(token, "GET", "/zones?per_page=1", nil, &zs); err == nil && len(zs) > 0 && zs[0].Account.ID != "" {
			accs = append(accs, zs[0].Account)
		}
	}
	if len(accs) == 0 {
		return nil, errors.New("这个令牌看不到任何 Cloudflare 账户：创建令牌时「账户资源」要选你的账户")
	}
	cfAccountCache.token, cfAccountCache.acc, cfAccountCache.at = token, &accs[0], time.Now()
	return &accs[0], nil
}

// ---- what the token can do ----

type cfCaps struct {
	Account   *cfAccountInfo    `json:"account,omitempty"`
	Zones     bool              `json:"zones"`
	DNS       bool              `json:"dns"`
	Tunnel    bool              `json:"tunnel"`
	Access    string            `json:"access"` // ok | denied | not_enabled (Zero Trust not set up)
	Settings  bool              `json:"settings"`
	Analytics bool              `json:"analytics"`
	Errors    map[string]string `json:"errors,omitempty"`
	Checked   int64             `json:"checked"`
}

var cfCapsCache struct {
	sync.Mutex
	token string
	caps  *cfCaps
}

func cfCapabilities(token string, fresh bool) *cfCaps {
	cfCapsCache.Lock()
	if !fresh && cfCapsCache.token == token && cfCapsCache.caps != nil && time.Since(time.Unix(cfCapsCache.caps.Checked, 0)) < 10*time.Minute {
		c := cfCapsCache.caps
		cfCapsCache.Unlock()
		return c
	}
	cfCapsCache.Unlock()
	c := &cfCaps{Errors: map[string]string{}, Checked: time.Now().Unix(), Access: "denied"}
	var mu sync.Mutex
	note := func(k string, err error) {
		if err != nil && !isDenied(err) {
			mu.Lock()
			c.Errors[k] = err.Error()
			mu.Unlock()
		}
	}
	zs, err := cfZones(token, fresh)
	c.Zones = err == nil && len(zs) > 0
	note("zones", err)
	var wg sync.WaitGroup
	if c.Zones {
		z := zs[0].ID
		wg.Add(3)
		go func() {
			defer wg.Done()
			err := cfDo(token, "GET", "/zones/"+z+"/dns_records?per_page=1", nil, nil)
			c.DNS = err == nil
			note("dns", err)
		}()
		go func() {
			defer wg.Done()
			err := cfDo(token, "GET", "/zones/"+z+"/settings/security_level", nil, nil)
			c.Settings = err == nil
			note("settings", err)
		}()
		go func() {
			defer wg.Done()
			var out any
			err := cfGraphQL(token, `query($z:String!){viewer{zones(filter:{zoneTag:$z}){httpRequests1dGroups(limit:1,filter:{date_geq:"2020-01-01"}){sum{requests}}}}}`, map[string]any{"z": z}, &out)
			c.Analytics = err == nil
			note("analytics", err)
		}()
	}
	if acc, err := cfAccountOf(token); err == nil {
		c.Account = acc
		wg.Add(2)
		go func() {
			defer wg.Done()
			err := cfDo(token, "GET", "/accounts/"+acc.ID+"/cfd_tunnel?per_page=1&is_deleted=false", nil, nil)
			c.Tunnel = err == nil
			note("tunnel", err)
		}()
		go func() {
			defer wg.Done()
			err := cfDo(token, "GET", "/accounts/"+acc.ID+"/access/apps?per_page=1", nil, nil)
			switch {
			case err == nil:
				c.Access = "ok"
			case isDenied(err):
				c.Access = "denied"
			default:
				var ce *cfErr
				if errors.As(err, &ce) && (strings.Contains(strings.ToLower(ce.Msg), "not enabled") || strings.Contains(strings.ToLower(ce.Msg), "organization")) {
					c.Access = "not_enabled"
				} else {
					note("access", err)
				}
			}
		}()
	} else {
		note("account", err)
	}
	wg.Wait()
	cfCapsCache.Lock()
	cfCapsCache.token, cfCapsCache.caps = token, c
	cfCapsCache.Unlock()
	return c
}
