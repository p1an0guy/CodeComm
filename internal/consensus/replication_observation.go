package consensus

import (
	"context"
	"fmt"
	"sort"

	"github.com/ijonahch/codecomm/internal/chain"
	"github.com/ijonahch/codecomm/internal/domain"
	"github.com/ijonahch/codecomm/internal/domain/device"
	"github.com/ijonahch/codecomm/internal/replication"
	"github.com/ijonahch/codecomm/internal/store"
)

type liveReplicationObservation struct {
	RelayPeerID              domain.DeviceID
	SignerDeviceID           domain.DeviceID
	AuthorityVersion         uint64
	VerifiedResultIndex      uint64
	ServerAppliedResultIndex uint64
}

// ObserveReplicationAcknowledgement verifies and durably records one signed
// equal-cursor response. It publishes live freshness only when the
// authenticated relay is the signer.
func (replica *SettledReplica) ObserveReplicationAcknowledgement(
	ctx context.Context,
	relayPeerID domain.DeviceID,
	acknowledgement replication.Acknowledgement,
) error {
	if replica == nil ||
		replica.state == nil ||
		replica.clock == nil ||
		ctx == nil ||
		!relayPeerID.Valid() ||
		len(acknowledgement.CanonicalBytes()) == 0 {
		return ErrInvalidNodeOptions
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := replica.beginOperation(); err != nil {
		return err
	}
	defer replica.endOperation()
	operationContext, cancel, wait := replica.operationContext(ctx)
	defer func() {
		cancel()
		wait()
	}()

	select {
	case replica.importGate <- struct{}{}:
		defer func() { <-replica.importGate }()
	case <-operationContext.Done():
		return operationContext.Err()
	}
	if err := replica.FatalError(); err != nil {
		return err
	}
	if replica.transitionRequired.Load() {
		return ErrSettledReplicaIneligible
	}
	view, err := replica.state.VerifiedSettledNonvoterView(
		operationContext,
	)
	if err != nil {
		if operationContext.Err() != nil {
			return operationContext.Err()
		}
		if fatalSettledImportError(err) {
			return replica.failSettledIntegrity(
				"read acknowledgement state",
				err,
			)
		}
		return err
	}
	decoded, err := decodeStateView(view)
	if err != nil {
		return replica.failSettledIntegrity(
			"decode acknowledgement state",
			err,
		)
	}
	metadata := acknowledgement.Unsigned().Metadata()
	member, exists := decoded.Reducer.Device(metadata.ServerDeviceID)
	authority := decoded.Reducer.CredentialAuthority()
	if metadata.SessionID != view.SessionID ||
		metadata.WorkspaceID != view.WorkspaceID ||
		metadata.RecoveryGeneration != view.RecoveryGeneration ||
		metadata.ResultIndex != view.Heads.ResultIndex ||
		metadata.ResultHash != chain.Digest(view.Heads.ResultHash) ||
		metadata.ChainIndex != view.Heads.ChainIndex ||
		metadata.ChainHash != chain.Digest(view.Heads.ChainHash) ||
		metadata.ProjectionAccumulator !=
			chain.Digest(view.Heads.ProjectionAccumulator) ||
		metadata.ProjectionStateDigest !=
			chain.Digest(view.ProjectionStateDigest) ||
		metadata.ServerAppliedResultIndex != view.Heads.ResultIndex ||
		!exists ||
		member.Status != device.StatusActive ||
		authority.VoterSetVersion !=
			metadata.ServerAuthorityVersion ||
		!authority.Contains(metadata.ServerDeviceID) ||
		replication.VerifyAcknowledgement(
			acknowledgement,
			member.IdentityPublicKey,
		) != nil {
		return fmt.Errorf(
			"%w: invalid equal-cursor acknowledgement",
			ErrInvalidReplicationReplay,
		)
	}
	verifiedAt, _, err := replica.clock()
	if err != nil {
		return fmt.Errorf(
			"consensus: read acknowledgement clock: %w",
			err,
		)
	}
	err = replica.state.RecordSettledReplicationAcknowledgement(
		operationContext,
		store.VerifiedReplicationWatermarkObservation{
			RelayPeerID:     relayPeerID,
			Acknowledgement: acknowledgement,
			VerifiedAt:      verifiedAt,
		},
	)
	if err != nil {
		if fatalSettledImportError(err) {
			return replica.failSettledIntegrity(
				"record replication acknowledgement",
				err,
			)
		}
		return err
	}
	if err := replica.refreshReplicationProgress(operationContext); err != nil {
		return replica.failSettledIntegrity(
			"refresh progress after acknowledgement commit",
			err,
		)
	}
	replica.recordLiveReplicationObservation(
		relayPeerID,
		metadata.ServerDeviceID,
		metadata.ServerAuthorityVersion,
		metadata.ResultIndex,
		metadata.ServerAppliedResultIndex,
	)
	return nil
}

// ForgetReplicationPeer removes all freshness evidence learned through one
// no-longer-reachable authenticated relay.
func (replica *SettledReplica) ForgetReplicationPeer(
	relayPeerID domain.DeviceID,
) {
	if replica == nil || !relayPeerID.Valid() {
		return
	}
	replica.replicationObservationsMu.Lock()
	delete(replica.replicationObservations, relayPeerID)
	replica.replicationObservationsMu.Unlock()
}

func (replica *SettledReplica) recordLiveReplicationObservation(
	relayPeerID domain.DeviceID,
	signerDeviceID domain.DeviceID,
	authorityVersion uint64,
	verifiedResultIndex uint64,
	serverAppliedResultIndex uint64,
) {
	if replica == nil ||
		!relayPeerID.Valid() ||
		!signerDeviceID.Valid() ||
		relayPeerID != signerDeviceID ||
		authorityVersion < 1 {
		return
	}
	replica.replicationObservationsMu.Lock()
	if replica.replicationObservations == nil {
		replica.replicationObservations = make(
			map[domain.DeviceID]liveReplicationObservation,
		)
	}
	current, exists := replica.replicationObservations[relayPeerID]
	if !exists ||
		authorityVersion > current.AuthorityVersion ||
		authorityVersion == current.AuthorityVersion &&
			(serverAppliedResultIndex >
				current.ServerAppliedResultIndex ||
				serverAppliedResultIndex ==
					current.ServerAppliedResultIndex &&
					verifiedResultIndex >
						current.VerifiedResultIndex) {
		replica.replicationObservations[relayPeerID] =
			liveReplicationObservation{
				RelayPeerID:              relayPeerID,
				SignerDeviceID:           signerDeviceID,
				AuthorityVersion:         authorityVersion,
				VerifiedResultIndex:      verifiedResultIndex,
				ServerAppliedResultIndex: serverAppliedResultIndex,
			}
	}
	replica.replicationObservationsMu.Unlock()
}

func (replica *SettledReplica) liveReplicationObservationSnapshot() []liveReplicationObservation {
	replica.replicationObservationsMu.RLock()
	defer replica.replicationObservationsMu.RUnlock()
	result := make(
		[]liveReplicationObservation,
		0,
		len(replica.replicationObservations),
	)
	for _, observation := range replica.replicationObservations {
		result = append(result, observation)
	}
	sort.Slice(result, func(left, right int) bool {
		if result[left].SignerDeviceID != result[right].SignerDeviceID {
			return result[left].SignerDeviceID <
				result[right].SignerDeviceID
		}
		return result[left].RelayPeerID < result[right].RelayPeerID
	})
	return result
}
