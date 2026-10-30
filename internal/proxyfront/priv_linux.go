package proxyfront

import (
	"net"
	"net/netip"
	"os/user"
	"strconv"
	"syscall"
	"time"
	"unsafe"
)

const (
	capNetAdmin   = 12
	prSetKeepCaps = 8
	capVersion3   = 0x20080522
)

// dropPrivileges switches every thread to the given user while keeping CAP_NET_ADMIN
// (and nothing else). procd on OpenWrt 22.03 cannot grant capabilities to a non-root
// service without ujail, so the front does it itself.
func dropPrivileges(name string) error {
	u, err := user.Lookup(name)
	if err != nil {
		return err
	}
	uid, _ := strconv.Atoi(u.Uid)
	gid, _ := strconv.Atoi(u.Gid)
	if _, _, e := syscall.AllThreadsSyscall(syscall.SYS_PRCTL, prSetKeepCaps, 1, 0); e != 0 {
		return e
	}
	if err := syscall.Setgroups(nil); err != nil {
		return err
	}
	if err := syscall.Setgid(gid); err != nil {
		return err
	}
	if err := syscall.Setuid(uid); err != nil {
		return err
	}
	hdr := struct{ version, pid uint32 }{capVersion3, 0}
	var data [2]struct{ effective, permitted, inheritable uint32 }
	data[0].effective, data[0].permitted = 1<<capNetAdmin, 1<<capNetAdmin
	if _, _, e := syscall.AllThreadsSyscall(syscall.SYS_CAPSET, uintptr(unsafe.Pointer(&hdr)), uintptr(unsafe.Pointer(&data[0])), 0); e != 0 {
		return e
	}
	return nil
}

func transparentDialer(src netip.Addr) *net.Dialer {
	return &net.Dialer{
		Timeout:   5 * time.Second,
		LocalAddr: &net.TCPAddr{IP: src.AsSlice()},
		Control: func(_, _ string, c syscall.RawConn) error {
			var serr error
			if err := c.Control(func(fd uintptr) {
				serr = syscall.SetsockoptInt(int(fd), syscall.SOL_IP, syscall.IP_TRANSPARENT, 1)
			}); err != nil {
				return err
			}
			return serr
		},
	}
}
