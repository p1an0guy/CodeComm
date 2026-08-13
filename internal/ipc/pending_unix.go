//go:build linux || darwin

package ipc

import (
	"errors"
	"fmt"
	"net"

	"golang.org/x/sys/unix"
)

func pendingNativeBytes(connection net.Conn) (bool, error) {
	connection = nativeConnection(connection)
	unixConnection, ok := connection.(*net.UnixConn)
	if !ok {
		return false, fmt.Errorf("ipc: pipeline probe requires a Unix socket")
	}
	raw, err := unixConnection.SyscallConn()
	if err != nil {
		return false, err
	}
	var (
		pending   bool
		socketErr error
	)
	if err := raw.Control(func(fileDescriptor uintptr) {
		var buffer [1]byte
		count, _, err := unix.Recvfrom(
			int(fileDescriptor),
			buffer[:],
			unix.MSG_PEEK|unix.MSG_DONTWAIT,
		)
		switch {
		case err == nil:
			pending = count > 0
		case errors.Is(err, unix.EAGAIN), errors.Is(err, unix.EWOULDBLOCK):
		default:
			socketErr = err
		}
	}); err != nil {
		return false, fmt.Errorf("ipc: access Unix socket for pipeline probe: %w", err)
	}
	if socketErr != nil {
		return false, fmt.Errorf("ipc: probe Unix socket pipeline: %w", socketErr)
	}
	return pending, nil
}
