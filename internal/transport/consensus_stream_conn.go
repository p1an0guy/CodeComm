package transport

import (
	"errors"
	"net"
	"sync"
	"time"

	"github.com/ijonahch/codecomm/internal/domain"
)

type consensusDeviceAddr struct {
	deviceID domain.DeviceID
}

func (address consensusDeviceAddr) Network() string {
	return "codecomm-consensus"
}

func (address consensusDeviceAddr) String() string {
	return string(address.deviceID)
}

// consensusStreamConn combines two independent in-memory pipes. Separating
// directions preserves request half-close semantics and keeps Raft deadlines
// off the shared HTTP/2 TLS connection.
type consensusStreamConn struct {
	read  net.Conn
	write net.Conn

	local  consensusDeviceAddr
	remote consensusDeviceAddr

	closeOnce sync.Once
	done      chan struct{}

	hookMu sync.Mutex
	closed bool
	hooks  []func()

	progressMu      sync.Mutex
	progressTimer   *time.Timer
	progressTimeout time.Duration
	progressClosed  bool
}

type consensusStreamBridges struct {
	read  net.Conn
	write net.Conn
}

func newConsensusStreamConn(
	localDeviceID domain.DeviceID,
	remoteDeviceID domain.DeviceID,
	closeHook func(),
) (*consensusStreamConn, consensusStreamBridges) {
	readApplication, readBridge := net.Pipe()
	writeApplication, writeBridge := net.Pipe()
	connection := &consensusStreamConn{
		read: readApplication, write: writeApplication,
		local: consensusDeviceAddr{deviceID: localDeviceID},
		remote: consensusDeviceAddr{
			deviceID: remoteDeviceID,
		},
		done: make(chan struct{}),
	}
	if closeHook != nil {
		connection.hooks = append(connection.hooks, closeHook)
	}
	connection.armProgressTimeout(consensusStreamProgress)
	return connection, consensusStreamBridges{
		read:  readBridge,
		write: writeBridge,
	}
}

func (connection *consensusStreamConn) Read(buffer []byte) (int, error) {
	if connection == nil || connection.read == nil {
		return 0, net.ErrClosed
	}
	count, err := connection.read.Read(buffer)
	if count > 0 {
		connection.markProgress()
	}
	return count, err
}

func (connection *consensusStreamConn) Write(buffer []byte) (int, error) {
	if connection == nil || connection.write == nil {
		return 0, net.ErrClosed
	}
	count, err := connection.write.Write(buffer)
	if count > 0 {
		connection.markProgress()
	}
	return count, err
}

func (connection *consensusStreamConn) Close() error {
	if connection == nil {
		return net.ErrClosed
	}
	var closeErr error
	connection.closeOnce.Do(func() {
		connection.stopProgressTimer()
		connection.hookMu.Lock()
		connection.closed = true
		hooks := append([]func(){}, connection.hooks...)
		clear(connection.hooks)
		connection.hooks = nil
		connection.hookMu.Unlock()
		closeErr = errors.Join(
			connection.read.Close(),
			connection.write.Close(),
		)
		for _, hook := range hooks {
			hook()
		}
		close(connection.done)
	})
	return closeErr
}

func (connection *consensusStreamConn) armProgressTimeout(
	timeout time.Duration,
) {
	if connection == nil || timeout <= 0 {
		return
	}
	connection.progressMu.Lock()
	defer connection.progressMu.Unlock()
	if connection.progressClosed {
		return
	}
	connection.progressTimeout = timeout
	if connection.progressTimer == nil {
		connection.progressTimer = time.AfterFunc(timeout, func() {
			_ = connection.Close()
		})
		return
	}
	connection.progressTimer.Stop()
	connection.progressTimer.Reset(timeout)
}

func (connection *consensusStreamConn) markProgress() {
	if connection == nil {
		return
	}
	connection.progressMu.Lock()
	defer connection.progressMu.Unlock()
	if connection.progressClosed ||
		connection.progressTimer == nil ||
		connection.progressTimeout <= 0 {
		return
	}
	connection.progressTimer.Stop()
	connection.progressTimer.Reset(connection.progressTimeout)
}

func (connection *consensusStreamConn) stopProgressTimer() {
	connection.progressMu.Lock()
	connection.progressClosed = true
	if connection.progressTimer != nil {
		connection.progressTimer.Stop()
	}
	connection.progressMu.Unlock()
}

// addCloseHook transfers lifecycle ownership to the stream when it is still
// open. If Close already won, it runs hook synchronously and reports false.
func (connection *consensusStreamConn) addCloseHook(hook func()) bool {
	if connection == nil || hook == nil {
		return false
	}
	connection.hookMu.Lock()
	if !connection.closed {
		connection.hooks = append(connection.hooks, hook)
		connection.hookMu.Unlock()
		return true
	}
	connection.hookMu.Unlock()
	hook()
	return false
}

func (connection *consensusStreamConn) LocalAddr() net.Addr {
	if connection == nil {
		return consensusDeviceAddr{}
	}
	return connection.local
}

func (connection *consensusStreamConn) RemoteAddr() net.Addr {
	if connection == nil {
		return consensusDeviceAddr{}
	}
	return connection.remote
}

func (connection *consensusStreamConn) SetDeadline(deadline time.Time) error {
	if connection == nil || connection.read == nil || connection.write == nil {
		return net.ErrClosed
	}
	return errors.Join(
		connection.read.SetReadDeadline(deadline),
		connection.write.SetWriteDeadline(deadline),
	)
}

func (connection *consensusStreamConn) SetReadDeadline(
	deadline time.Time,
) error {
	if connection == nil || connection.read == nil {
		return net.ErrClosed
	}
	return connection.read.SetReadDeadline(deadline)
}

func (connection *consensusStreamConn) SetWriteDeadline(
	deadline time.Time,
) error {
	if connection == nil || connection.write == nil {
		return net.ErrClosed
	}
	return connection.write.SetWriteDeadline(deadline)
}

var _ net.Conn = (*consensusStreamConn)(nil)
