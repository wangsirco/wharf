package proxyfront

import (
	"bufio"
	"bytes"
	"io"
	"log"
	"net"
	"strings"
	"sync"
	"time"
)

// Split shares the router's LAN port 443 between Wharf and the router's own web page
// (LuCI's uhttpd keeps listening on 443 untouched). LAN connections to the router's
// address on 443 are redirected here by a firewall rule; the ClientHello is read without
// terminating TLS, and the panel's names (wharf.lan, the public names) go to the panel's
// loopback listener with a PROXY protocol header, everything else — LuCI by IP, other
// names, plain HTTP — goes on to Other unchanged.
type Split struct {
	Panel string // the panel's PROXY-protocol listener, e.g. 127.0.0.1:20090
	Other string // where everything else goes, e.g. 127.0.0.1:443

	mu    sync.RWMutex
	names map[string]bool
}

func (s *Split) SetNames(ns []string) {
	m := map[string]bool{}
	for _, n := range ns {
		if n = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(n), ".")); n != "" {
			m[n] = true
		}
	}
	s.mu.Lock()
	s.names = m
	s.mu.Unlock()
}

func (s *Split) Names() []string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]string, 0, len(s.names))
	for n := range s.names {
		out = append(out, n)
	}
	return out
}

// Route says where a connection for this server name goes (for tests and status).
func (s *Split) Route(name string) string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.names[strings.ToLower(name)] {
		return s.Panel
	}
	return s.Other
}

func (s *Split) Serve(ln net.Listener) error {
	var tempDelay time.Duration
	for {
		c, err := ln.Accept()
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				tempDelay = max(5*time.Millisecond, min(2*tempDelay, time.Second))
				time.Sleep(tempDelay)
				continue
			}
			return err
		}
		tempDelay = 0
		go s.handle(c)
	}
}

func (s *Split) handle(c net.Conn) {
	defer func() {
		if r := recover(); r != nil {
			log.Printf("lan443: %v", r)
			c.Close()
		}
	}()
	f := &front{}
	_ = c.SetReadDeadline(time.Now().Add(10 * time.Second))
	br := bufio.NewReader(c)
	first, err := br.Peek(1)
	if err != nil {
		c.Close()
		return
	}
	in := &peekConn{Conn: c, r: br}
	if first[0] != 0x16 { // plain HTTP on 443: the router's own page decides
		_ = c.SetReadDeadline(time.Time{})
		f.pipe(in, c, Route{Backend: s.Other})
		return
	}
	hello, raw, _ := peekHello(in)
	_ = c.SetReadDeadline(time.Time{})
	replay := &peekConn{Conn: c, r: io.MultiReader(bytes.NewReader(raw), br)}
	name := ""
	if hello != nil {
		name = strings.TrimSuffix(hello.ServerName, ".")
	}
	if to := s.Route(name); to == s.Panel && name != "" {
		f.pipe(replay, c, Route{Backend: s.Panel, Proxy: true})
		return
	}
	f.pipe(replay, c, Route{Backend: s.Other})
}
