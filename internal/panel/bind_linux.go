package panel

import "syscall"

// bindToDevice makes outgoing connections leave through one interface (multi-WAN DDNS).
func bindToDevice(dev string) func(network, address string, c syscall.RawConn) error {
	if dev == "" {
		return nil
	}
	return func(network, address string, c syscall.RawConn) error {
		var serr error
		if err := c.Control(func(fd uintptr) { serr = syscall.SetsockoptString(int(fd), syscall.SOL_SOCKET, syscall.SO_BINDTODEVICE, dev) }); err != nil {
			return err
		}
		return serr
	}
}
