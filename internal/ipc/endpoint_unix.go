//go:build linux || darwin

package ipc

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
)

func validateEndpointAddress(address string) error {
	if address == "" ||
		len(address) > 103 ||
		strings.IndexByte(address, 0) >= 0 ||
		!filepath.IsAbs(address) ||
		filepath.Clean(address) != address ||
		filepath.Base(address) == "." ||
		filepath.Base(address) == string(filepath.Separator) {
		return errors.New("unix socket path must be a clean absolute path of at most 103 bytes")
	}
	return nil
}

func listenNative(
	endpoint Endpoint,
) (net.Listener, string, func() error, error) {
	ownerUID := uint32(os.Geteuid())
	ownerID := strconv.FormatUint(uint64(ownerUID), 10)
	directory := filepath.Dir(endpoint.address)
	if err := prepareSocketDirectory(directory, ownerUID); err != nil {
		return nil, "", nil, err
	}
	if err := clearStaleSocket(endpoint.address, ownerUID); err != nil {
		return nil, "", nil, err
	}

	listener, err := net.ListenUnix(
		"unix",
		&net.UnixAddr{Name: endpoint.address, Net: "unix"},
	)
	if err != nil {
		return nil, "", nil, fmt.Errorf("ipc: listen on Unix socket: %w", err)
	}
	listener.SetUnlinkOnClose(false)
	cleanupOnError := true
	defer func() {
		if cleanupOnError {
			_ = listener.Close()
			_ = os.Remove(endpoint.address)
		}
	}()
	if err := os.Chmod(endpoint.address, 0o600); err != nil {
		return nil, "", nil, fmt.Errorf("ipc: restrict Unix socket: %w", err)
	}
	created, err := secureSocketInfo(endpoint.address, ownerUID)
	if err != nil {
		return nil, "", nil, err
	}

	cleanup := func() error {
		current, err := os.Lstat(endpoint.address)
		switch {
		case errors.Is(err, os.ErrNotExist):
			return nil
		case err != nil:
			return fmt.Errorf("ipc: inspect Unix socket during cleanup: %w", err)
		case !os.SameFile(created, current):
			return fmt.Errorf(
				"%w: Unix socket changed before cleanup",
				ErrEndpointInsecure,
			)
		case current.Mode()&os.ModeSocket == 0:
			return fmt.Errorf(
				"%w: endpoint is no longer a Unix socket",
				ErrEndpointInsecure,
			)
		default:
			if err := os.Remove(endpoint.address); err != nil &&
				!errors.Is(err, os.ErrNotExist) {
				return fmt.Errorf("ipc: remove Unix socket: %w", err)
			}
			return nil
		}
	}
	cleanupOnError = false
	return listener, ownerID, cleanup, nil
}

func dialNative(
	ctx context.Context,
	endpoint Endpoint,
) (net.Conn, VerifiedPeer, error) {
	ownerUID := uint32(os.Geteuid())
	before, err := secureSocketInfo(endpoint.address, ownerUID)
	if err != nil {
		return nil, VerifiedPeer{}, err
	}
	var dialer net.Dialer
	connection, err := dialer.DialContext(ctx, "unix", endpoint.address)
	if err != nil {
		return nil, VerifiedPeer{}, fmt.Errorf("ipc: dial Unix socket: %w", err)
	}
	peer, err := authenticateUnixPeer(connection, ownerUID)
	if err != nil {
		_ = connection.Close()
		if peerGoneUnixError(err) {
			return nil, VerifiedPeer{}, fmt.Errorf(
				"%w: server closed before peer verification",
				ErrEndpointUnavailable,
			)
		}
		return nil, VerifiedPeer{}, err
	}
	after, err := secureSocketInfo(endpoint.address, ownerUID)
	if err != nil || !os.SameFile(before, after) {
		_ = connection.Close()
		if err != nil {
			return nil, VerifiedPeer{}, err
		}
		return nil, VerifiedPeer{}, fmt.Errorf(
			"%w: Unix socket changed while dialing",
			ErrEndpointInsecure,
		)
	}
	return connection, peer, nil
}

func authenticateAcceptedPeer(
	connection net.Conn,
	ownerID string,
) (VerifiedPeer, error) {
	uid, err := strconv.ParseUint(ownerID, 10, 32)
	if err != nil {
		return VerifiedPeer{}, fmt.Errorf(
			"%w: invalid listener owner",
			ErrTransportIntegrity,
		)
	}
	return authenticateUnixPeer(connection, uint32(uid))
}

func authenticateUnixPeer(
	connection net.Conn,
	ownerUID uint32,
) (VerifiedPeer, error) {
	unixConnection, ok := connection.(*net.UnixConn)
	if !ok {
		return VerifiedPeer{}, fmt.Errorf(
			"%w: connection is not a Unix socket",
			ErrPeerAuthentication,
		)
	}
	processID, userID, err := kernelPeerIdentity(unixConnection)
	if err != nil {
		return VerifiedPeer{}, fmt.Errorf(
			"%w: %w",
			ErrPeerAuthentication,
			err,
		)
	}
	if processID <= 0 || userID != ownerUID {
		return VerifiedPeer{}, fmt.Errorf(
			"%w: peer UID %d does not match owner UID %d",
			ErrPeerAuthentication,
			userID,
			ownerUID,
		)
	}
	return VerifiedPeer{
		processID: uint32(processID),
		userID:    strconv.FormatUint(uint64(userID), 10),
	}, nil
}

func peerGoneUnixError(err error) bool {
	return errors.Is(err, syscall.ENOTCONN) ||
		errors.Is(err, syscall.ECONNRESET) ||
		errors.Is(err, syscall.EPIPE) ||
		errors.Is(err, syscall.EBADF)
}

func prepareSocketDirectory(path string, ownerUID uint32) error {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		if err := os.MkdirAll(path, 0o700); err != nil {
			return fmt.Errorf("ipc: create Unix socket directory: %w", err)
		}
		if err := os.Chmod(path, 0o700); err != nil {
			return fmt.Errorf("ipc: restrict Unix socket directory: %w", err)
		}
		info, err = os.Lstat(path)
	}
	if err != nil {
		return fmt.Errorf("ipc: inspect Unix socket directory: %w", err)
	}
	if !info.IsDir() ||
		info.Mode()&os.ModeSymlink != 0 ||
		info.Mode().Perm() != 0o700 {
		return fmt.Errorf(
			"%w: Unix socket directory must be a real mode-0700 directory",
			ErrEndpointInsecure,
		)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != ownerUID {
		return fmt.Errorf(
			"%w: Unix socket directory is not owned by effective UID %d",
			ErrEndpointInsecure,
			ownerUID,
		)
	}
	return nil
}

func clearStaleSocket(path string, ownerUID uint32) error {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("ipc: inspect existing Unix socket: %w", err)
	}
	if _, err := validateSocketInfo(info, ownerUID); err != nil {
		return err
	}

	connection, dialErr := net.DialTimeout("unix", path, 100*time.Millisecond)
	if dialErr == nil {
		_ = connection.Close()
		return ErrEndpointInUse
	}
	if !errors.Is(dialErr, syscall.ECONNREFUSED) &&
		!errors.Is(dialErr, syscall.ENOENT) {
		return fmt.Errorf(
			"%w: cannot prove existing Unix socket is stale: %v",
			ErrEndpointInsecure,
			dialErr,
		)
	}
	current, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("ipc: recheck stale Unix socket: %w", err)
	}
	if !os.SameFile(info, current) {
		return fmt.Errorf(
			"%w: Unix socket changed during stale check",
			ErrEndpointInsecure,
		)
	}
	if err := os.Remove(path); err != nil {
		return fmt.Errorf("ipc: remove stale Unix socket: %w", err)
	}
	return nil
}

func secureSocketInfo(path string, ownerUID uint32) (os.FileInfo, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, fmt.Errorf("ipc: inspect Unix socket: %w", err)
	}
	return validateSocketInfo(info, ownerUID)
}

func validateSocketInfo(info os.FileInfo, ownerUID uint32) (os.FileInfo, error) {
	if info.Mode()&os.ModeSocket == 0 ||
		info.Mode()&os.ModeSymlink != 0 ||
		info.Mode().Perm() != 0o600 {
		return nil, fmt.Errorf(
			"%w: endpoint must be a real mode-0600 Unix socket",
			ErrEndpointInsecure,
		)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != ownerUID {
		return nil, fmt.Errorf(
			"%w: Unix socket is not owned by effective UID %d",
			ErrEndpointInsecure,
			ownerUID,
		)
	}
	return info, nil
}

func normalizeListenerCloseError(err error) error {
	if errors.Is(err, net.ErrClosed) {
		return nil
	}
	return err
}
