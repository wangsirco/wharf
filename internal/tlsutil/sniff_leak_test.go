package tlsutil

import (
	"errors"
	"net"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

// flaky fails its first Accepts the way a process out of file handles does.
type flaky struct {
	net.Listener
	n atomic.Int32
}

func (f *flaky) Accept() (net.Conn, error) {
	if f.n.Add(1) <= 3 {
		return nil, &net.OpError{Op: "accept", Net: "tcp", Err: syscall.EMFILE}
	}
	return f.Listener.Accept()
}

// The panel's port keeps accepting after "too many open files".
func TestSplitListenerSurvivesAcceptErrors(t *testing.T) {
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	defer ln.Close()
	_, plain := SplitListener(&flaky{Listener: ln})
	go func() {
		c, err := net.Dial("tcp", ln.Addr().String())
		if err == nil {
			_, _ = c.Write([]byte("GET / HTTP/1.1\r\n\r\n"))
			time.Sleep(time.Second)
			c.Close()
		}
	}()
	got := make(chan error, 1)
	go func() { _, err := plain.Accept(); got <- err }()
	select {
	case err := <-got:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("listener stopped after accept errors")
	}
	_ = errors.New
}
