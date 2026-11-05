package tlsutil

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"time"
)

// ProxyListener accepts connections that start with a PROXY protocol v2 header (sent by
// Wharf's 443 front) and reports the address in it as the connection's remote address,
// so the panel sees the real visitor. It must only listen where nothing but the front
// can connect (loopback).
type ProxyListener struct{ net.Listener }

var v2sig = []byte("\r\n\r\n\x00\r\nQUIT\n")

type proxyConn struct {
	net.Conn
	rd     *bufio.Reader
	remote net.Addr
}

func (c *proxyConn) Read(b []byte) (int, error) { return c.rd.Read(b) }
func (c *proxyConn) RemoteAddr() net.Addr       { return c.remote }

func (l ProxyListener) Accept() (net.Conn, error) {
	for {
		c, err := l.Listener.Accept()
		if err != nil {
			return nil, err
		}
		pc, err := readProxyHeader(c)
		if err != nil {
			c.Close() // not from the front: drop it and wait for the next one
			continue
		}
		return pc, nil
	}
}

func readProxyHeader(c net.Conn) (net.Conn, error) {
	_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
	defer c.SetReadDeadline(time.Time{})
	rd := bufio.NewReader(c)
	head := make([]byte, 16)
	if _, err := io.ReadFull(rd, head); err != nil {
		return nil, err
	}
	if !bytes.Equal(head[:12], v2sig) || head[12]>>4 != 2 {
		return nil, errors.New("no PROXY v2 header")
	}
	body := make([]byte, binary.BigEndian.Uint16(head[14:16]))
	if _, err := io.ReadFull(rd, body); err != nil {
		return nil, err
	}
	pc := &proxyConn{Conn: c, rd: rd, remote: c.RemoteAddr()}
	if head[12]&0x0f != 1 { // LOCAL: keep the real peer
		return pc, nil
	}
	switch head[13] {
	case 0x11: // TCP over IPv4
		if len(body) >= 12 {
			pc.remote = &net.TCPAddr{IP: net.IP(body[0:4]), Port: int(binary.BigEndian.Uint16(body[8:10]))}
		}
	case 0x21: // TCP over IPv6
		if len(body) >= 36 {
			pc.remote = &net.TCPAddr{IP: net.IP(body[0:16]), Port: int(binary.BigEndian.Uint16(body[32:34]))}
		}
	}
	return pc, nil
}
