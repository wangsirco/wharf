//go:build !linux

package proxyfront

import (
	"errors"
	"net"
	"net/netip"
	"syscall"
)

func dropPrivileges(string) error { return errors.New("only on Linux") }

func transparentDialer(netip.Addr) *net.Dialer {
	return &net.Dialer{Control: func(string, string, syscall.RawConn) error { return syscall.EPERM }}
}
