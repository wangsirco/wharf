package panel

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/wangsirco/wharf/internal/sign"
	"github.com/wangsirco/wharf/internal/tlsutil"
)

// AgentClient talks to owp-agent with signed requests.
type AgentClient struct {
	cfg  AgentConfig
	http *http.Client
}

func NewAgentClient(cfg AgentConfig) *AgentClient {
	tr := &http.Transport{MaxIdleConns: 4, IdleConnTimeout: 60 * time.Second}
	if strings.HasPrefix(cfg.URL, "https://") {
		tr.TLSClientConfig = tlsutil.PinnedConfig(cfg.Fingerprint)
	}
	return &AgentClient{cfg: cfg, http: &http.Client{Transport: tr, Timeout: 90 * time.Second}}
}

type AgentError struct {
	Status int
	Msg    string
}

func (e *AgentError) Error() string { return fmt.Sprintf("agent %d: %s", e.Status, e.Msg) }

func (c *AgentClient) Do(method, path string, in, out any) error {
	var body []byte
	if in != nil {
		body, _ = json.Marshal(in)
	}
	req, err := http.NewRequest(method, strings.TrimRight(c.cfg.URL, "/")+path, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	sign.Sign(req, c.cfg.KeyID, []byte(c.cfg.Secret), body)
	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("agent unreachable: %w", err)
	}
	defer resp.Body.Close()
	rb, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<20))
	if resp.StatusCode != 200 {
		var e struct {
			Error string `json:"error"`
		}
		_ = json.Unmarshal(rb, &e)
		return &AgentError{resp.StatusCode, e.Error}
	}
	if out != nil {
		return json.Unmarshal(rb, out)
	}
	return nil
}

// Section mirrors agent.Section.
type Section map[string]any

type UciChange struct {
	Op      string         `json:"op"`
	Config  string         `json:"config"`
	Section string         `json:"section,omitempty"`
	Type    string         `json:"type,omitempty"`
	Name    string         `json:"name,omitempty"` // named section for "add"
	Values  map[string]any `json:"values,omitempty"`
	Options []string       `json:"options,omitempty"`
}

type UciResult struct {
	Config  string  `json:"config"`
	Section string  `json:"section"`
	Before  Section `json:"before"`
	After   Section `json:"after"`
}

func (c *AgentClient) Apply(changes ...UciChange) ([]UciResult, error) {
	var r struct {
		Results []UciResult `json:"results"`
	}
	err := c.Do("POST", "/v1/uci/apply", map[string]any{"changes": changes}, &r)
	return r.Results, err
}

func (c *AgentClient) UciConfig(config string) (map[string]Section, error) {
	var r map[string]Section
	err := c.Do("GET", "/v1/uci?config="+config, nil, &r)
	return r, err
}
