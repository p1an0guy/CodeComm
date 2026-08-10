//go:build darwin

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
		credentials, err := unix.GetsockoptXucred(int(fd), unix.SOL_LOCAL, unix.LOCAL_PEERCRED)
		if err != nil {
			socketErr = err
			return
		}
		pid, err := unix.GetsockoptInt(int(fd), unix.SOL_LOCAL, unix.LOCAL_PEERPID)
		if err != nil {
			socketErr = err
			return
		}
		identity.pid = pid
		identity.uid = credentials.Uid
		if credentials.Ngroups > 0 {
			identity.gid = credentials.Groups[0]
		}
	}); err != nil {
		return peerIdentity{}, fmt.Errorf("access Unix socket descriptor: %w", err)
	}
	if socketErr != nil {
		return peerIdentity{}, fmt.Errorf("read LOCAL_PEERCRED/LOCAL_PEERPID: %w", socketErr)
	}
	return identity, nil
}
