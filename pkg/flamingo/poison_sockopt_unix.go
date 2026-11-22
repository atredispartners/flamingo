//go:build !windows

package flamingo

import (
	"syscall"

	"golang.org/x/sys/unix"
)

// poisonListenControl sets SO_REUSEADDR and SO_REUSEPORT on the socket before
// bind so a poisoner can share a multicast port with the host's own responders
// (e.g. mDNSResponder on 5353). Errors are non-fatal; the caller still binds.
func poisonListenControl(network, address string, c syscall.RawConn) error {
	var cerr error
	err := c.Control(func(fd uintptr) {
		if e := unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_REUSEADDR, 1); e != nil {
			cerr = e
		}
		// SO_REUSEPORT is required on BSD/darwin to coexist with a running
		// mDNSResponder; it is harmless elsewhere.
		_ = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_REUSEPORT, 1)
	})
	if err != nil {
		return err
	}
	return cerr
}
