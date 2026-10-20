package agent

import (
	"bytes"
	"fmt"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

// Sets created by the panel live in <data>/sets/<name>.txt and are referenced by
// uci firewall ipset sections (option loadfile). fw3 only reads loadfile when it
// creates a set, so existing kernel sets are refreshed in place here.

var setNameRe = regexp.MustCompile(`^owp_[a-z0-9_]{1,27}$`)

func (s *Server) setsDir() string { return filepath.Join(s.cfg.DataDir, "sets") }

// SetPath is the loadfile path the panel must put into the uci ipset section.
func (s *Server) SetPath(name string) string { return filepath.Join(s.setsDir(), name+".txt") }

// validEntry accepts "a.b.c.d[/n]" optionally followed by " nomatch".
func validEntry(e string) (string, bool) {
	addr, flag, _ := strings.Cut(strings.TrimSpace(e), " ")
	if flag != "" && flag != "nomatch" {
		return "", false
	}
	var p netip.Prefix
	var err error
	if strings.Contains(addr, "/") {
		p, err = netip.ParsePrefix(addr)
	} else {
		var a netip.Addr
		a, err = netip.ParseAddr(addr)
		p = netip.PrefixFrom(a, 32)
	}
	if err != nil || !p.Addr().Is4() {
		return "", false
	}
	out := p.Masked().String()
	if flag != "" {
		out += " nomatch"
	}
	return out, true
}

type SetWrite struct {
	Name    string   `json:"name"`
	Entries []string `json:"entries"`
	Remove  bool     `json:"remove"`
}

func (s *Server) WriteSet(req SetWrite) (string, error) {
	if !setNameRe.MatchString(req.Name) {
		return "", fmt.Errorf("bad set name %q", req.Name)
	}
	path := s.SetPath(req.Name)
	if req.Remove {
		_ = os.Remove(path)
		// fails harmlessly while still referenced; firewall reload drops the reference first
		_, _ = run(10*time.Second, "ipset", "destroy", req.Name)
		return path, nil
	}
	var lines []string
	for _, e := range req.Entries {
		v, ok := validEntry(e)
		if !ok {
			return "", fmt.Errorf("bad entry %q", e)
		}
		lines = append(lines, v)
	}
	if err := os.MkdirAll(s.setsDir(), 0o755); err != nil {
		return "", err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, []byte(strings.Join(lines, "\n")+"\n"), 0o644); err != nil {
		return "", err
	}
	if err := os.Rename(tmp, path); err != nil {
		return "", err
	}
	if _, err := run(5*time.Second, "ipset", "list", "-n", req.Name); err == nil {
		// fill a scratch set and swap it in, so the live set is never half-empty
		applyMu.Lock()
		defer applyMu.Unlock()
		const tmpSet = "owp__swap"
		var b bytes.Buffer
		fmt.Fprintf(&b, "create %s hash:net family inet maxelem 1048576 -exist\nflush %s\n", tmpSet, tmpSet)
		for _, l := range lines {
			fmt.Fprintf(&b, "add %s %s\n", tmpSet, l)
		}
		fmt.Fprintf(&b, "swap %s %s\ndestroy %s\n", tmpSet, req.Name, tmpSet)
		cmd := exec.Command("ipset", "restore", "-!")
		cmd.Stdin = &b
		if out, err := cmd.CombinedOutput(); err != nil {
			return "", fmt.Errorf("ipset restore: %v: %s", err, out)
		}
	}
	return path, nil
}
