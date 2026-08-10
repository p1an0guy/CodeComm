// Package raftprobe contains executable Phase 1 dependency proofs.
//
// It is intentionally outside internal/consensus: production code must not
// depend on the candidate Raft stack until these probes have passed.
package raftprobe
