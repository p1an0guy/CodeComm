//go:build darwin

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
		credentials, err := unix.GetsockoptXucred(
			int(fileDescriptor),
			unix.SOL_LOCAL,
			unix.LOCAL_PEERCRED,
		)
		if err != nil {
			socketErr = err
			return
		}
		pid, err := unix.GetsockoptInt(
			int(fileDescriptor),
			unix.SOL_LOCAL,
			unix.LOCAL_PEERPID,
		)
		if err != nil {
			socketErr = err
			return
		}
		processID = pid
		userID = credentials.Uid
	}); err != nil {
		return 0, 0, fmt.Errorf("access Unix socket descriptor: %w", err)
	}
	if socketErr != nil {
		return 0, 0, fmt.Errorf(
			"read LOCAL_PEERCRED/LOCAL_PEERPID: %w",
			socketErr,
		)
	}
	return processID, userID, nil
}
