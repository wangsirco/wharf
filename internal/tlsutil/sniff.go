package tlsutil

import (
	"bufio"
	"errors"
	"net"
	"sync"
	"time"
)

// SplitListener separates TLS connections from plain-HTTP ones arriving on the same
// port, so someone typing http://router:7080 gets redirected instead of a 400 page.
// The first byte decides: 0x16 starts a TLS handshake.
func SplitListener(ln net.Listener) (tlsLn, plainLn net.Listener) {
	s := &splitter{Listener: ln, tls: make(chan net.Conn), plain: make(chan net.Conn), done: make(chan struct{})}
	go s.loop()
	return &chanListener{s, s.tls}, &chanListener{s, s.plain}
}

type splitter struct {
	net.Listener
	tls, plain chan net.Conn
	done       chan struct{}
	once       sync.Once
	err        error
}

func (s *splitter) loop() {
	for {
		c, err := s.Listener.Accept()
		if err != nil {
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				time.Sleep(50 * time.Millisecond)
				continue
			}
			s.err = err
			s.close()
			return
		}
		go s.route(c)
	}
}

func (s *splitter) route(c net.Conn) {
	_ = c.SetReadDeadline(time.Now().Add(10 * time.Second))
	br := bufio.NewReader(c)
	b, err := br.Peek(1)
	_ = c.SetReadDeadline(time.Time{})
	if err != nil {
		c.Close()
		return
	}
	ch := s.plain
	if b[0] == 0x16 {
		ch = s.tls
	}
	select {
	case ch <- &peekedConn{Conn: c, r: br}:
	case <-s.done:
		c.Close()
	}
}

func (s *splitter) close() { s.once.Do(func() { close(s.done); s.Listener.Close() }) }

type chanListener struct {
	s  *splitter
	ch chan net.Conn
}

func (l *chanListener) Accept() (net.Conn, error) {
	select {
	case c := <-l.ch:
		return c, nil
	case <-l.s.done:
		if l.s.err != nil {
			return nil, l.s.err
		}
		return nil, net.ErrClosed
	}
}

func (l *chanListener) Close() error   { l.s.close(); return nil }
func (l *chanListener) Addr() net.Addr { return l.s.Addr() }

type peekedConn struct {
	net.Conn
	r *bufio.Reader
}

func (c *peekedConn) Read(p []byte) (int, error) { return c.r.Read(p) }
