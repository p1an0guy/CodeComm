//go:build linux || darwin

package localipc

import (
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

type peerIdentity struct {
	pid int
	uid uint32
	gid uint32
}

type acceptedPeer struct {
	identity peerIdentity
	err      error
}

func TestUnixSocketIsOwnerOnlyAndKernelIdentifiesPeer(t *testing.T) {
	root, err := os.MkdirTemp("/tmp", "cc-ipc-")
	if err != nil {
		t.Fatalf("create short runtime directory: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(root) })
	if err := os.Chmod(root, 0o700); err != nil {
		t.Fatalf("chmod socket directory: %v", err)
	}
	rootInfo, err := os.Stat(root)
	if err != nil {
		t.Fatal(err)
	}
	if got := rootInfo.Mode().Perm(); got != 0o700 {
		t.Fatalf("socket directory mode = %#o, want 0700", got)
	}

	socketPath := filepath.Join(root, "codecomm.sock")
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: socketPath, Net: "unix"})
	if err != nil {
		t.Fatalf("listen on Unix socket: %v", err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	if err := os.Chmod(socketPath, 0o600); err != nil {
		t.Fatalf("chmod Unix socket: %v", err)
	}

	socketInfo, err := os.Lstat(socketPath)
	if err != nil {
		t.Fatal(err)
	}
	if socketInfo.Mode()&os.ModeSocket == 0 {
		t.Fatalf("%s is not a socket: %v", socketPath, socketInfo.Mode())
	}
	if got := socketInfo.Mode().Perm(); got != 0o600 {
		t.Fatalf("socket mode = %#o, want 0600", got)
	}
	address, ok := listener.Addr().(*net.UnixAddr)
	if !ok || address.Network() != "unix" || address.Name != socketPath {
		t.Fatalf("listener address = %#v, want host-local Unix path %q", listener.Addr(), socketPath)
	}

	if err := listener.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	accepted := make(chan acceptedPeer, 1)
	go func() {
		connection, acceptErr := listener.AcceptUnix()
		if acceptErr != nil {
			accepted <- acceptedPeer{err: acceptErr}
			return
		}
		defer connection.Close()
		identity, identityErr := kernelPeerIdentity(connection)
		if identityErr == nil {
			var request [1]byte
			_, identityErr = connection.Read(request[:])
			if identityErr == nil {
				_, identityErr = connection.Write([]byte{request[0] + 1})
			}
		}
		accepted <- acceptedPeer{identity: identity, err: identityErr}
	}()

	client, err := net.DialUnix("unix", nil, address)
	if err != nil {
		t.Fatalf("dial Unix socket: %v", err)
	}
	defer client.Close()
	if err := client.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := client.Write([]byte{41}); err != nil {
		t.Fatalf("write local request: %v", err)
	}
	var response [1]byte
	if _, err := client.Read(response[:]); err != nil {
		t.Fatalf("read local response: %v", err)
	}
	if response[0] != 42 {
		t.Fatalf("response = %d, want 42", response[0])
	}

	result := <-accepted
	if result.err != nil {
		t.Fatalf("accept/authenticate peer: %v", result.err)
	}
	if result.identity.uid != uint32(os.Getuid()) {
		t.Fatalf("peer uid = %d, want %d", result.identity.uid, os.Getuid())
	}
	if result.identity.pid != os.Getpid() {
		t.Fatalf("peer pid = %d, want %d", result.identity.pid, os.Getpid())
	}
}
