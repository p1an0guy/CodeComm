//go:build linux

package ipc

import (
	"fmt"
	"net"

	"golang.org/x/sys/unix"
)

func kernelPeerIdentity(connection *net.UnixConn) (int, uint32, error) {
	raw, err := connection.SyscallConn()
	if err != nil {
		return 0, 0, err
	}
	var (
		processID int
		userID    uint32
		socketErr error
	)
	if err := raw.Control(func(fileDescriptor uintptr) {
		credentials, err := unix.GetsockoptUcred(
			int(fileDescriptor),
			unix.SOL_SOCKET,
			unix.SO_PEERCRED,
		)
		if err != nil {
			socketErr = err
			return
		}
		processID = int(credentials.Pid)
		userID = credentials.Uid
	}); err != nil {
		return 0, 0, fmt.Errorf("access Unix socket descriptor: %w", err)
	}
	if socketErr != nil {
		return 0, 0, fmt.Errorf("read SO_PEERCRED: %w", socketErr)
	}
	return processID, userID, nil
}
