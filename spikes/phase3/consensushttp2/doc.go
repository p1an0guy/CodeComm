// Package consensushttp2 contains executable dependency proofs for carrying
// HashiCorp Raft's maintained byte framing over RFC 8441 extended CONNECT.
//
// golang.org/x/net/http2 v0.55.0 supports the required client and server
// semantics only when the process starts with GODEBUG=http2xconnect=1. The
// package snapshots that setting during initialization; setting it from Go
// after startup is too late. Production composition must therefore treat the
// setting as a supervisor-owned startup invariant and fail fast when absent.
//
// The selected API supports a client request-body half-close while the server
// continues writing its response. It does not expose a server response
// half-close that keeps the handler reading. HashiCorp Raft v1.7.3 does not use
// net.Conn.CloseWrite, so the supported direction is sufficient for the V1
// stream adapter and the adapter must not claim a broader CloseWrite contract.
package consensushttp2
