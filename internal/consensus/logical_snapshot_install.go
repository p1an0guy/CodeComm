package consensus

import (
	"context"
	"fmt"

	"github.com/ijonahch/codecomm/internal/domain"
	"github.com/ijonahch/codecomm/internal/domain/device"
	"github.com/ijonahch/codecomm/internal/reducer"
	"github.com/ijonahch/codecomm/internal/store"
)

// InstallStandalone atomically installs this verified quarantine into a
// destination store and enters settled-nonvoter mode. A successful install
// consumes the quarantine; Close must still be called to release its database.
func (verified *VerifiedLogicalSnapshotStage) InstallStandalone(
	ctx context.Context,
	destination *store.Store,
	verifiedAt domain.Timestamp,
) (store.StandaloneLogicalSnapshotInstallResult, error) {
	if verified == nil ||
		verified.stage == nil ||
		destination == nil ||
		ctx == nil ||
		!verifiedAt.Valid() ||
		verified.clock == nil {
		return store.StandaloneLogicalSnapshotInstallResult{},
			ErrInvalidLogicalSnapshotImport
	}
	if err := ctx.Err(); err != nil {
		return store.StandaloneLogicalSnapshotInstallResult{}, err
	}
	installedAt, monotonicNow, err := verified.clock()
	if err != nil {
		return store.StandaloneLogicalSnapshotInstallResult{}, err
	}
	return destination.InstallStandaloneLogicalSnapshot(
		ctx,
		verified.stage,
		store.StandaloneLogicalSnapshotInstallOptions{
			VerifiedAt:     verifiedAt,
			OriginBootID:   verified.originBootID,
			InstalledAt:    installedAt,
			MonotonicNowNS: monotonicNow,
		},
	)
}

// InstallLogicalSnapshot atomically replaces a settled replica from a
// verified quarantine and republishes admission only after the durable cut is
// committed. Snapshot replacement and result-batch import share one gate.
func (replica *SettledReplica) InstallLogicalSnapshot(
	ctx context.Context,
	verified *VerifiedLogicalSnapshotStage,
	verifiedAt domain.Timestamp,
) (store.StandaloneLogicalSnapshotInstallResult, error) {
	if replica == nil ||
		replica.state == nil ||
		ctx == nil ||
		verified == nil ||
		!verifiedAt.Valid() {
		return store.StandaloneLogicalSnapshotInstallResult{},
			ErrInvalidNodeOptions
	}
	if err := ctx.Err(); err != nil {
		return store.StandaloneLogicalSnapshotInstallResult{}, err
	}
	if err := replica.beginOperation(); err != nil {
		return store.StandaloneLogicalSnapshotInstallResult{}, err
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
		return store.StandaloneLogicalSnapshotInstallResult{},
			operationContext.Err()
	}
	if err := replica.FatalError(); err != nil {
		return store.StandaloneLogicalSnapshotInstallResult{}, err
	}
	if replica.transitionRequired.Load() {
		return store.StandaloneLogicalSnapshotInstallResult{},
			ErrSettledReplicaIneligible
	}

	current, err := replica.state.VerifiedSettledNonvoterView(
		operationContext,
	)
	if err != nil {
		if fatalSettledImportError(err) {
			return store.StandaloneLogicalSnapshotInstallResult{},
				replica.failSettledIntegrity(
					"preflight snapshot destination",
					err,
				)
		}
		return store.StandaloneLogicalSnapshotInstallResult{}, err
	}
	staged, err := verified.View(operationContext)
	if err != nil {
		return store.StandaloneLogicalSnapshotInstallResult{}, err
	}
	if staged.WorkspaceID != current.WorkspaceID {
		return store.StandaloneLogicalSnapshotInstallResult{},
			fmt.Errorf(
				"%w: snapshot workspace differs from settled replica",
				ErrInvalidLogicalSnapshotImport,
			)
	}
	stagedState, err := decodeStateView(staged)
	if err != nil {
		return store.StandaloneLogicalSnapshotInstallResult{}, err
	}
	transitionRequired, err := logicalSnapshotTransitionRequired(
		stagedState.Reducer,
		replica.localDeviceID,
	)
	if err != nil {
		return store.StandaloneLogicalSnapshotInstallResult{}, err
	}

	replica.admissionMu.Lock()
	result, err := verified.InstallStandalone(
		operationContext,
		replica.state,
		verifiedAt,
	)
	if err == nil && result.Heads != staged.Heads {
		err = fmt.Errorf(
			"%w: installed heads differ from verified snapshot",
			ErrInvalidLogicalSnapshotImport,
		)
	}
	if err != nil {
		if result.AttestationID != "" {
			replica.recordFatalLocked(fmt.Errorf(
				"consensus: settled-replica integrity failure after snapshot install: %w",
				err,
			))
			err = replica.FatalError()
		}
		replica.admissionMu.Unlock()
		return store.StandaloneLogicalSnapshotInstallResult{}, err
	}
	installed, err := replica.state.VerifiedSettledNonvoterView(
		operationContext,
	)
	if err == nil {
		stagedState, err = decodeStateView(installed)
	}
	if err == nil {
		var installedTransition bool
		installedTransition, err = logicalSnapshotTransitionRequired(
			stagedState.Reducer,
			replica.localDeviceID,
		)
		if err == nil && installedTransition != transitionRequired {
			err = fmt.Errorf(
				"%w: installed local eligibility differs from verified snapshot",
				ErrInvalidLogicalSnapshotImport,
			)
		}
	}
	if err == nil && !transitionRequired {
		err = validateSettledReplicaEligibility(
			operationContext,
			replica.state,
			replica.localDeviceID,
			stagedState.Reducer,
		)
	}
	if err == nil {
		err = replica.refreshReplicationProgress(operationContext)
	}
	if err != nil {
		replica.recordFatalLocked(fmt.Errorf(
			"consensus: settled-replica integrity failure after snapshot install: %w",
			err,
		))
		replica.admissionMu.Unlock()
		return store.StandaloneLogicalSnapshotInstallResult{},
			replica.FatalError()
	}
	replica.admission.Store(&peerAdmissionPublication{
		revision: result.AdmissionRevision,
		snapshot: stagedState.Admission,
	})
	replica.transitionRequired.Store(transitionRequired)
	replica.admissionMu.Unlock()

	replica.replicationObservationsMu.Lock()
	clear(replica.replicationObservations)
	replica.replicationObservationsMu.Unlock()
	replica.changes.signal()
	return result, nil
}

func logicalSnapshotTransitionRequired(
	state reducer.State,
	localDeviceID domain.DeviceID,
) (bool, error) {
	member, exists := state.Device(localDeviceID)
	if !exists || member.ID != localDeviceID {
		return false, ErrSettledReplicaIneligible
	}
	return member.Status != device.StatusActive ||
		state.VoterSet().Contains(localDeviceID) ||
		state.CredentialAuthority().Contains(localDeviceID), nil
}
