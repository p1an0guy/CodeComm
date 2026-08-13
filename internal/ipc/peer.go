package ipc

// VerifiedPeer is an immutable kernel-authenticated local peer. UserID is a
// decimal effective UID on Unix and a canonical SID on Windows. PID is
// diagnostic only and never grants authority.
type VerifiedPeer struct {
	processID uint32
	userID    string
}

// PID returns the peer process identifier observed by the kernel.
func (peer VerifiedPeer) PID() uint32 {
	return peer.processID
}

// UserID returns the peer's kernel-authenticated account identifier.
func (peer VerifiedPeer) UserID() string {
	return peer.userID
}

func (peer VerifiedPeer) valid() bool {
	return peer.processID != 0 && peer.userID != ""
}
