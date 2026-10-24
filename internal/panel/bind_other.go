//go:build !linux

package panel

import "syscall"

func bindToDevice(dev string) func(network, address string, c syscall.RawConn) error { return nil }
