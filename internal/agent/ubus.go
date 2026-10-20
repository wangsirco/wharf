package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"
	"time"
)

// run executes a command without a shell; args are passed verbatim.
func run(timeout time.Duration, name string, args ...string) ([]byte, error) {
	return runIn(timeout, "", name, args...)
}

// runIn is run with stdin.
func runIn(timeout time.Duration, stdin string, name string, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	var out, errb bytes.Buffer
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Stdout, cmd.Stderr = &out, &errb
	if stdin != "" {
		cmd.Stdin = strings.NewReader(stdin)
	}
	if err := cmd.Run(); err != nil {
		return out.Bytes(), fmt.Errorf("%s %v: %v: %s", name, args, err, errb.String())
	}
	return out.Bytes(), nil
}

func ubusCall(obj, method string, params any, result any) error {
	p, _ := json.Marshal(params)
	if params == nil {
		p = []byte("{}")
	}
	out, err := run(15*time.Second, "ubus", "call", obj, method, string(p))
	if err != nil {
		return err
	}
	if result == nil || len(bytes.TrimSpace(out)) == 0 {
		return nil
	}
	return json.Unmarshal(out, result)
}

// Section is one uci section as returned by ubus: ".name", ".type", ".anonymous", options...
type Section map[string]any

func uciGetConfig(config string) (map[string]Section, error) {
	var r struct {
		Values map[string]Section `json:"values"`
	}
	if err := ubusCall("uci", "get", map[string]any{"config": config}, &r); err != nil {
		return nil, err
	}
	return r.Values, nil
}

func uciGetSection(config, section string) (Section, error) {
	var r struct {
		Values Section `json:"values"`
	}
	err := ubusCall("uci", "get", map[string]any{"config": config, "section": section}, &r)
	if err != nil {
		return nil, err
	}
	return r.Values, nil
}

func uciGetOption(config, section, option string) string {
	var r struct {
		Value any `json:"value"`
	}
	if ubusCall("uci", "get", map[string]any{"config": config, "section": section, "option": option}, &r) != nil {
		return ""
	}
	if s, ok := r.Value.(string); ok {
		return s
	}
	return ""
}

// runCtx runs a command bound to ctx (output is returned even on failure).
func runCtx(ctx context.Context, name string, args ...string) ([]byte, error) {
	return exec.CommandContext(ctx, name, args...).Output()
}
