//go:build windows

package flamingo

import (
	"syscall"
)

// poisonListenControl sets SO_REUSEADDR on the socket before bind. Windows has
// no SO_REUSEPORT; SO_REUSEADDR already grants the shared-port semantics the
// poisoners need there. Errors are non-fatal; the caller still binds.
func poisonListenControl(network, address string, c syscall.RawConn) error {
	var cerr error
	err := c.Control(func(fd uintptr) {
		if e := syscall.SetsockoptInt(syscall.Handle(fd), syscall.SOL_SOCKET, syscall.SO_REUSEADDR, 1); e != nil {
			cerr = e
		}
	})
	if err != nil {
		return err
	}
	return cerr
}
