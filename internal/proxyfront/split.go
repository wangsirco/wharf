package proxyfront

import (
	"bufio"
	"bytes"
	"errors"
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

// MaxConns bounds the connections in flight; more wait in the kernel's queue. A home
// network needs a few dozen; the bound keeps a misbehaving client from using up the
// process's file handles (each connection holds two sockets and a splice pipe pair).
const MaxConns = 512

// IdleTimeout closes a connection that moved no data either way for this long.
var IdleTimeout = 10 * time.Minute

// Serve accepts until the listener is closed. Any other accept error (out of file
// handles, …) is waited out — the firewall keeps sending LAN 443 here, so this must not stop.
func (s *Split) Serve(ln net.Listener) error {
	sem := make(chan struct{}, MaxConns)
	var tempDelay time.Duration
	for {
		sem <- struct{}{}
		c, err := ln.Accept()
		if err != nil {
			<-sem
			if errors.Is(err, net.ErrClosed) {
				return err
			}
			tempDelay = max(5*time.Millisecond, min(2*tempDelay, time.Second))
			log.Printf("lan443: accept: %v (retrying)", err)
			time.Sleep(tempDelay)
			continue
		}
		tempDelay = 0
		go func() {
			defer func() { <-sem }()
			s.handle(&idleConn{Conn: c, idle: IdleTimeout})
		}()
	}
}

// idleConn pushes its deadline forward on every read or write, so only a connection that
// moves nothing either way for idle is closed. A read deadline set by the code using it
// (10 s for the ClientHello) holds until that code clears it.
type idleConn struct {
	net.Conn
	idle  time.Duration
	fixed bool // a caller's read deadline is in force
}

func (c *idleConn) Read(p []byte) (int, error) {
	if !c.fixed {
		_ = c.Conn.SetReadDeadline(time.Now().Add(c.idle))
	}
	return c.Conn.Read(p)
}

func (c *idleConn) Write(p []byte) (int, error) {
	_ = c.Conn.SetWriteDeadline(time.Now().Add(c.idle))
	if !c.fixed {
		_ = c.Conn.SetReadDeadline(time.Now().Add(c.idle))
	}
	return c.Conn.Write(p)
}

func (c *idleConn) SetReadDeadline(t time.Time) error {
	c.fixed = !t.IsZero()
	if t.IsZero() {
		t = time.Now().Add(c.idle)
	}
	return c.Conn.SetReadDeadline(t)
}

// CloseWrite lets pipe half-close the client side like a plain TCP connection.
func (c *idleConn) CloseWrite() error {
	if tc, ok := c.Conn.(*net.TCPConn); ok {
		return tc.CloseWrite()
	}
	return nil
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
