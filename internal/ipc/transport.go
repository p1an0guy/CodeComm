package ipc

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"
)

var (
	ErrPeerAuthentication = errors.New("ipc: local peer authentication failed")
	ErrTransportIntegrity = errors.New("ipc: local transport integrity failure")
)

// Conn is a byte-stream connection whose peer account was verified through
// kernel credentials.
type Conn struct {
	connection net.Conn
	peer       VerifiedPeer
}

func nativeConnection(connection net.Conn) net.Conn {
	if authenticated, ok := connection.(*Conn); ok {
		return authenticated.connection
	}
	return connection
}

func (connection *Conn) Read(buffer []byte) (int, error) {
	return connection.connection.Read(buffer)
}

func (connection *Conn) Write(buffer []byte) (int, error) {
	return connection.connection.Write(buffer)
}

func (connection *Conn) Close() error {
	return connection.connection.Close()
}

func (connection *Conn) LocalAddr() net.Addr {
	return connection.connection.LocalAddr()
}

func (connection *Conn) RemoteAddr() net.Addr {
	return connection.connection.RemoteAddr()
}

func (connection *Conn) SetDeadline(deadline time.Time) error {
	return connection.connection.SetDeadline(deadline)
}

func (connection *Conn) SetReadDeadline(deadline time.Time) error {
	return connection.connection.SetReadDeadline(deadline)
}

func (connection *Conn) SetWriteDeadline(deadline time.Time) error {
	return connection.connection.SetWriteDeadline(deadline)
}

// Peer returns the immutable kernel-authenticated peer.
func (connection *Conn) Peer() VerifiedPeer {
	return connection.peer
}

// Listener accepts only authenticated host-local connections.
type Listener struct {
	endpoint Endpoint
	native   net.Listener
	ownerID  string
	cleanup  func() error

	closeOnce sync.Once
	closeErr  error

	stateMu        sync.Mutex
	closed         bool
	authenticating sync.WaitGroup
}

// Listen creates one owner-restricted local endpoint.
func Listen(endpoint Endpoint) (*Listener, error) {
	if !endpoint.valid() {
		return nil, ErrInvalidEndpoint
	}
	native, ownerID, cleanup, err := listenNative(endpoint)
	if err != nil {
		return nil, err
	}
	return &Listener{
		endpoint: endpoint,
		native:   native,
		ownerID:  ownerID,
		cleanup:  cleanup,
	}, nil
}

// Accept waits for and authenticates a connection. Rejected peers are closed
// and never become visible to callers.
func (listener *Listener) Accept() (*Conn, error) {
	for {
		connection, err := listener.native.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return nil, ErrListenerClosed
			}
			return nil, fmt.Errorf("ipc: accept local connection: %w", err)
		}
		if !listener.trackAuthentication(connection) {
			_ = connection.Close()
			return nil, ErrListenerClosed
		}
		peer, err := authenticateAcceptedPeer(connection, listener.ownerID)
		closed := listener.finishAuthentication(connection)
		if err != nil {
			_ = connection.Close()
			if errors.Is(err, ErrEndpointInsecure) ||
				errors.Is(err, ErrTransportIntegrity) {
				return nil, err
			}
			continue
		}
		if closed || !peer.valid() {
			_ = connection.Close()
			if closed {
				return nil, ErrListenerClosed
			}
			continue
		}
		return &Conn{connection: connection, peer: peer}, nil
	}
}

// Close unblocks Accept and safely removes the endpoint where the platform
// uses a filesystem object.
func (listener *Listener) Close() error {
	listener.closeOnce.Do(func() {
		listener.stateMu.Lock()
		listener.closed = true
		listener.stateMu.Unlock()

		closeErr := listener.native.Close()
		listener.authenticating.Wait()
		cleanupErr := listener.cleanup()
		listener.closeErr = errors.Join(
			normalizeListenerCloseError(closeErr),
			cleanupErr,
		)
	})
	return listener.closeErr
}

func (listener *Listener) trackAuthentication(connection net.Conn) bool {
	listener.stateMu.Lock()
	defer listener.stateMu.Unlock()
	if listener.closed {
		return false
	}
	listener.authenticating.Add(1)
	return true
}

func (listener *Listener) finishAuthentication(connection net.Conn) bool {
	listener.stateMu.Lock()
	closed := listener.closed
	listener.stateMu.Unlock()
	listener.authenticating.Done()
	return closed
}

// Endpoint returns the address reserved by this listener.
func (listener *Listener) Endpoint() Endpoint {
	return listener.endpoint
}

// Dial connects to a local endpoint and verifies the server account.
func Dial(ctx context.Context, endpoint Endpoint) (*Conn, error) {
	if ctx == nil {
		return nil, fmt.Errorf("%w: nil context", ErrInvalidEndpoint)
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if !endpoint.valid() {
		return nil, ErrInvalidEndpoint
	}
	connection, peer, err := dialNative(ctx, endpoint)
	if err != nil {
		return nil, err
	}
	if !peer.valid() {
		_ = connection.Close()
		return nil, ErrPeerAuthentication
	}
	return &Conn{connection: connection, peer: peer}, nil
}
