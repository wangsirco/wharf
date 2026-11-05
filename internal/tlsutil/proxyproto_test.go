package tlsutil

import (
	"encoding/binary"
	"io"
	"net"
	"testing"
)

func TestProxyListener(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	pl := ProxyListener{ln}
	defer pl.Close()
	go func() {
		// a stray connection without a header is dropped, the next one is served
		c0, _ := net.Dial("tcp", ln.Addr().String())
		_, _ = c0.Write([]byte("GET / HTTP/1.1\r\n\r\n.."))
		c0.Close()
		c, _ := net.Dial("tcp", ln.Addr().String())
		h := append([]byte{}, v2sig...)
		h = append(h, 0x21, 0x11, 0, 12)
		h = append(h, 203, 0, 113, 7, 127, 0, 0, 1)
		h = binary.BigEndian.AppendUint16(h, 51234)
		h = binary.BigEndian.AppendUint16(h, 20090)
		_, _ = c.Write(append(h, []byte("hello")...))
		c.Close()
	}()
	c, err := pl.Accept()
	if err != nil {
		t.Fatal(err)
	}
	if a := c.RemoteAddr().(*net.TCPAddr); a.IP.String() != "203.0.113.7" || a.Port != 51234 {
		t.Fatalf("remote %v", c.RemoteAddr())
	}
	b, _ := io.ReadAll(c)
	if string(b) != "hello" {
		t.Fatalf("payload %q", b)
	}
}
