//go:build linux || darwin

package ipc

import (
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestUnixListenerIsOwnerOnlyAndAuthenticatesBothPeers(t *testing.T) {
	t.Parallel()

	directory := testRuntimeDirectory(t)
	endpoint, err := ParseEndpoint(filepath.Join(directory, "codecomm.sock"))
	if err != nil {
		t.Fatal(err)
	}
	listener, err := Listen(endpoint)
	if err != nil {
		t.Fatalf("Listen() error = %v", err)
	}
	t.Cleanup(func() {
		_ = listener.Close()
	})
	directoryInfo, err := os.Lstat(directory)
	if err != nil {
		t.Fatal(err)
	}
	socketInfo, err := os.Lstat(endpoint.String())
	if err != nil {
		t.Fatal(err)
	}
	if directoryInfo.Mode().Perm() != 0o700 ||
		socketInfo.Mode().Perm() != 0o600 ||
		socketInfo.Mode()&os.ModeSocket == 0 {
		t.Fatalf(
			"directory/socket modes = %v/%v",
			directoryInfo.Mode(),
			socketInfo.Mode(),
		)
	}

	accepted := make(chan *Conn, 1)
	acceptError := make(chan error, 1)
	go func() {
		connection, err := listener.Accept()
		if err != nil {
			acceptError <- err
			return
		}
		accepted <- connection
	}()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	client, err := Dial(ctx, endpoint)
	if err != nil {
		t.Fatalf("Dial() error = %v", err)
	}
	defer client.Close()
	var server *Conn
	select {
	case server = <-accepted:
		defer server.Close()
	case err := <-acceptError:
		t.Fatalf("Accept() error = %v", err)
	case <-ctx.Done():
		t.Fatal("Accept() timed out")
	}
	wantUser := strconv.Itoa(os.Geteuid())
	for label, peer := range map[string]VerifiedPeer{
		"server sees client": server.Peer(),
		"client sees server": client.Peer(),
	} {
		if peer.PID() != uint32(os.Getpid()) || peer.UserID() != wantUser {
			t.Errorf(
				"%s peer = PID %d, user %q; want PID %d, user %q",
				label,
				peer.PID(),
				peer.UserID(),
				os.Getpid(),
				wantUser,
			)
		}
	}

	if err := listener.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	if _, err := os.Lstat(endpoint.String()); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("socket remains after close: %v", err)
	}
}

func TestUnixListenerRejectsInsecurePathsAndLiveCollision(t *testing.T) {
	t.Parallel()

	t.Run("world-readable directory", func(t *testing.T) {
		directory := testRuntimeDirectory(t)
		if err := os.Chmod(directory, 0o755); err != nil {
			t.Fatal(err)
		}
		endpoint, err := ParseEndpoint(filepath.Join(directory, "codecomm.sock"))
		if err != nil {
			t.Fatal(err)
		}
		listener, err := Listen(endpoint)
		if listener != nil || !errors.Is(err, ErrEndpointInsecure) {
			t.Fatalf("Listen() = %#v, %v; want ErrEndpointInsecure", listener, err)
		}
	})

	t.Run("symlink directory", func(t *testing.T) {
		root := testRuntimeDirectory(t)
		target := filepath.Join(root, "target")
		if err := os.Mkdir(target, 0o700); err != nil {
			t.Fatal(err)
		}
		link := filepath.Join(root, "link")
		if err := os.Symlink(target, link); err != nil {
			t.Fatal(err)
		}
		endpoint, err := ParseEndpoint(filepath.Join(link, "codecomm.sock"))
		if err != nil {
			t.Fatal(err)
		}
		listener, err := Listen(endpoint)
		if listener != nil || !errors.Is(err, ErrEndpointInsecure) {
			t.Fatalf("Listen() = %#v, %v; want ErrEndpointInsecure", listener, err)
		}
	})

	t.Run("regular file collision", func(t *testing.T) {
		directory := testRuntimeDirectory(t)
		path := filepath.Join(directory, "codecomm.sock")
		if err := os.WriteFile(path, []byte("not a socket"), 0o600); err != nil {
			t.Fatal(err)
		}
		endpoint, err := ParseEndpoint(path)
		if err != nil {
			t.Fatal(err)
		}
		listener, err := Listen(endpoint)
		if listener != nil || !errors.Is(err, ErrEndpointInsecure) {
			t.Fatalf("Listen() = %#v, %v; want ErrEndpointInsecure", listener, err)
		}
	})

	t.Run("live socket collision", func(t *testing.T) {
		directory := testRuntimeDirectory(t)
		endpoint, err := ParseEndpoint(filepath.Join(directory, "codecomm.sock"))
		if err != nil {
			t.Fatal(err)
		}
		first, err := Listen(endpoint)
		if err != nil {
			t.Fatal(err)
		}
		defer first.Close()
		second, err := Listen(endpoint)
		if second != nil || !errors.Is(err, ErrEndpointInUse) {
			t.Fatalf("second Listen() = %#v, %v; want ErrEndpointInUse", second, err)
		}
	})
}

func TestUnixListenerRecoversStaleSocketAndNeverDeletesReplacement(t *testing.T) {
	t.Parallel()

	directory := testRuntimeDirectory(t)
	path := filepath.Join(directory, "codecomm.sock")
	stale, err := net.ListenUnix(
		"unix",
		&net.UnixAddr{Name: path, Net: "unix"},
	)
	if err != nil {
		t.Fatal(err)
	}
	stale.SetUnlinkOnClose(false)
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := stale.Close(); err != nil {
		t.Fatal(err)
	}

	endpoint, err := ParseEndpoint(path)
	if err != nil {
		t.Fatal(err)
	}
	listener, err := Listen(endpoint)
	if err != nil {
		t.Fatalf("Listen() did not recover stale socket: %v", err)
	}
	if err := listener.native.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("replacement"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := listener.Close(); !errors.Is(err, ErrEndpointInsecure) {
		t.Fatalf("Close() error = %v, want ErrEndpointInsecure", err)
	}
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("replacement was removed: %v", err)
	}
	if string(content) != "replacement" {
		t.Fatalf("replacement content = %q", content)
	}
}

func TestUnixEndpointValidationRejectsRelativeAndUncleanPaths(t *testing.T) {
	t.Parallel()

	for _, path := range []string{
		"",
		"relative.sock",
		"/tmp/../tmp/codecomm.sock",
		"/tmp/" + strings.Repeat("x", 104),
		string([]byte{'/', 't', 'm', 'p', '/', 0, 'x'}),
	} {
		if endpoint, err := ParseEndpoint(path); endpoint != (Endpoint{}) ||
			!errors.Is(err, ErrInvalidEndpoint) {
			t.Errorf("ParseEndpoint(%q) = %#v, %v", path, endpoint, err)
		}
	}
}

func TestUnixPeerUIDMismatchFailsClosed(t *testing.T) {
	t.Parallel()

	directory := testRuntimeDirectory(t)
	path := filepath.Join(directory, "peer.sock")
	listener, err := net.ListenUnix(
		"unix",
		&net.UnixAddr{Name: path, Net: "unix"},
	)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	accepted := make(chan *net.UnixConn, 1)
	go func() {
		connection, _ := listener.AcceptUnix()
		accepted <- connection
	}()
	client, err := net.DialUnix(
		"unix",
		nil,
		&net.UnixAddr{Name: path, Net: "unix"},
	)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	server := <-accepted
	defer server.Close()
	_, err = authenticateUnixPeer(server, uint32(os.Geteuid()+1))
	if !errors.Is(err, ErrPeerAuthentication) {
		t.Fatalf("authenticateUnixPeer() error = %v, want ErrPeerAuthentication", err)
	}
}
