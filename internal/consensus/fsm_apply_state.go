package consensus

import (
	"bytes"
	"crypto/ed25519"

	"github.com/hashicorp/raft"
	"github.com/ijonahch/codecomm/internal/domain"
	"github.com/ijonahch/codecomm/internal/peerauth"
	"github.com/ijonahch/codecomm/internal/reducer"
	"github.com/ijonahch/codecomm/internal/store"
)

// fsmApplyState is the reducer input at the last durable FSM command. Raft
// serializes Apply calls, and applyMu also protects direct harness calls and
// snapshot replacement. Full store views remain trust-boundary operations at
// startup, checkpoints, snapshots, scrubs, and restores.
type fsmApplyState struct {
	sessionID               domain.UUIDv7
	workspaceID             domain.UUIDv4
	recoveryGeneration      uint64
	heads                   store.ApplyHeads
	lastRaftAppliedLogIndex uint64
	admissionRevision       uint64
	reducer                 reducer.State
	admission               *peerauth.Snapshot
	identityPublicKeys      map[domain.DeviceID]ed25519.PublicKey
}

func newFSMApplyState(
	view store.StateView,
	decoded decodedState,
) fsmApplyState {
	state := fsmApplyState{
		sessionID:          view.SessionID,
		workspaceID:        view.WorkspaceID,
		recoveryGeneration: view.RecoveryGeneration,
		heads:              view.Heads,
		admissionRevision:  view.AdmissionRevision,
		reducer:            decoded.Reducer,
		admission:          decoded.Admission,
		identityPublicKeys: copyIdentityPublicKeysFromDecoded(decoded),
	}
	if view.LastRaftAppliedLogIndex != nil {
		state.lastRaftAppliedLogIndex = *view.LastRaftAppliedLogIndex
	}
	return state
}

func (state fsmApplyState) identityPublicKey(
	deviceID domain.DeviceID,
) (ed25519.PublicKey, bool) {
	key, exists := state.identityPublicKeys[deviceID]
	if !exists {
		return nil, false
	}
	return ed25519.PublicKey(bytes.Clone(key)), true
}

func (state *fsmApplyState) advance(
	log *raft.Log,
	result store.ApplyResult,
	prospective reducer.State,
	admission *peerauth.Snapshot,
	changes reducer.Changes,
) {
	state.heads = result.Heads
	state.lastRaftAppliedLogIndex = log.Index
	state.admissionRevision = result.AdmissionRevision
	state.reducer = prospective
	state.admission = admission
	for _, member := range changes.Devices {
		state.identityPublicKeys[member.ID] = ed25519.PublicKey(
			bytes.Clone(member.IdentityPublicKey),
		)
	}
}

func (state *fsmApplyState) advanceDuplicate(
	log *raft.Log,
	result store.ApplyResult,
) {
	state.heads = result.Heads
	state.lastRaftAppliedLogIndex = log.Index
	state.admissionRevision = result.AdmissionRevision
}

func copyIdentityPublicKeysFromDecoded(
	decoded decodedState,
) map[domain.DeviceID]ed25519.PublicKey {
	keys := make(
		map[domain.DeviceID]ed25519.PublicKey,
		len(decoded.identityPublicKeys),
	)
	for id, key := range decoded.identityPublicKeys {
		keys[id] = ed25519.PublicKey(bytes.Clone(key))
	}
	return keys
}
