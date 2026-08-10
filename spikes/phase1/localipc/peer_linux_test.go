//go:build linux

package localipc

import (
	"fmt"
	"net"

	"golang.org/x/sys/unix"
)

func kernelPeerIdentity(connection *net.UnixConn) (peerIdentity, error) {
	raw, err := connection.SyscallConn()
	if err != nil {
		return peerIdentity{}, err
	}
	var (
		identity  peerIdentity
		socketErr error
	)
	if err := raw.Control(func(fd uintptr) {
		credentials, err := unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
		if err != nil {
			socketErr = err
			return
		}
		identity = peerIdentity{
			pid: int(credentials.Pid),
			uid: credentials.Uid,
			gid: credentials.Gid,
		}
	}); err != nil {
		return peerIdentity{}, fmt.Errorf("access Unix socket descriptor: %w", err)
	}
	if socketErr != nil {
		return peerIdentity{}, fmt.Errorf("read SO_PEERCRED: %w", socketErr)
	}
	return identity, nil
}
