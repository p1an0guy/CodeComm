package consensus

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"sync"
	"sync/atomic"

	"github.com/hashicorp/raft"
	"github.com/ijonahch/codecomm/internal/domain"
	"github.com/ijonahch/codecomm/internal/domain/device"
	"github.com/ijonahch/codecomm/internal/peerauth"
	"github.com/ijonahch/codecomm/internal/reducer"
	"github.com/ijonahch/codecomm/internal/replication"
	coordstatus "github.com/ijonahch/codecomm/internal/status"
	"github.com/ijonahch/codecomm/internal/store"
)

var ErrSettledReplicaIneligible = errors.New(
	"consensus: local device is not eligible for settled-nonvoter mode",
)

// SettledReplicaOptions configures an application nonvoter that catches up
// from authority-signed result batches and owns no Raft runtime.
type SettledReplicaOptions struct {
	StatePath     string
	OriginBootID  domain.UUIDv7
	LocalDeviceID domain.DeviceID
	Clock         ApplyClock
}

// SettledReplica owns the SQLite and peer-admission state for one application
// nonvoter. Result imports are serialized across scratch replay and commit.
type SettledReplica struct {
	state         *store.Store
	localState    store.LocalState
	originBootID  domain.UUIDv7
	localDeviceID domain.DeviceID
	clock         ApplyClock

	admissionMu             sync.Mutex
	admission               atomic.Pointer[peerAdmissionPublication]
	changes                 *changeFeed
	peerChangesClaimed      atomic.Bool
	consensusChangesClaimed atomic.Bool
	transitionRequired      atomic.Bool
	importGate              chan struct{}

	replicationObservationsMu sync.RWMutex
	replicationObservations   map[domain.DeviceID]liveReplicationObservation

	localStateMu     sync.RWMutex
	localStateClosed atomic.Bool

	lifecycleMu  sync.Mutex
	closing      bool
	closeStarted chan struct{}
	active       sync.WaitGroup

	fatalOnce sync.Once
	fatalMu   sync.RWMutex
	fatalErr  error
	fatalSet  chan struct{}

	closeOnce sync.Once
	closeErr  error
}

// OpenSettledReplica opens a store already carrying the explicit
// settled-nonvoter evidence marker. It never creates or opens Raft state.
func OpenSettledReplica(
	ctx context.Context,
	options SettledReplicaOptions,
) (_ *SettledReplica, err error) {
	if ctx == nil ||
		options.StatePath == "" ||
		!options.OriginBootID.Valid() ||
		!options.LocalDeviceID.Valid() {
		return nil, ErrInvalidNodeOptions
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	database, err := store.Open(ctx, store.Options{Path: options.StatePath})
	if err != nil {
		return nil, err
	}
	defer func() {
		if err != nil {
			_ = database.Close()
		}
	}()
	mode, err := database.ReplicaEvidenceMode(ctx)
	if err != nil {
		return nil, err
	}
	if mode != store.ReplicaEvidenceSettledNonvoter {
		return nil, store.ErrReplicaEvidenceMode
	}
	view, err := database.View(ctx)
	if err != nil {
		return nil, err
	}
	decoded, err := decodeStateView(view)
	if err != nil {
		return nil, err
	}
	if err := validateSettledReplicaEligibility(
		ctx,
		database,
		options.LocalDeviceID,
		decoded.Reducer,
	); err != nil {
		return nil, err
	}
	clock := options.Clock
	if clock == nil {
		clock = NewSystemApplyClock()
	}
	replica := &SettledReplica{
		state:         database,
		originBootID:  options.OriginBootID,
		localDeviceID: options.LocalDeviceID,
		clock:         clock,
		changes:       newChangeFeed(),
		importGate:    make(chan struct{}, 1),
		replicationObservations: make(
			map[domain.DeviceID]liveReplicationObservation,
		),
		closeStarted: make(chan struct{}),
		fatalSet:     make(chan struct{}),
	}
	replica.localState = database.LocalStateWithGuard(
		replica.beginLocalStateOperation,
	)
	replica.admission.Store(&peerAdmissionPublication{
		revision: view.AdmissionRevision,
		snapshot: decoded.Admission,
	})
	return replica, nil
}

// ImportResultBatch verifies and atomically imports one authority-attested
// result batch without assigning Raft provenance.
func (replica *SettledReplica) ImportResultBatch(
	ctx context.Context,
	relayPeerID domain.DeviceID,
	batch replication.Batch,
) (store.ResultBatchImportResult, error) {
	if replica == nil ||
		replica.state == nil ||
		replica.clock == nil ||
		!replica.originBootID.Valid() ||
		ctx == nil ||
		!relayPeerID.Valid() ||
		batch.EncodedLen() == 0 {
		return store.ResultBatchImportResult{}, ErrInvalidNodeOptions
	}
	if err := ctx.Err(); err != nil {
		return store.ResultBatchImportResult{}, err
	}
	if err := replica.beginOperation(); err != nil {
		return store.ResultBatchImportResult{}, err
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
		return store.ResultBatchImportResult{}, operationContext.Err()
	}
	if err := replica.FatalError(); err != nil {
		return store.ResultBatchImportResult{}, err
	}
	if replica.transitionRequired.Load() {
		return store.ResultBatchImportResult{},
			ErrSettledReplicaIneligible
	}

	view, err := replica.state.VerifiedSettledNonvoterView(operationContext)
	if err != nil {
		if operationContext.Err() != nil {
			return store.ResultBatchImportResult{}, operationContext.Err()
		}
		if fatalSettledImportError(err) {
			return store.ResultBatchImportResult{},
				replica.failSettledIntegrity("read durable state", err)
		}
		return store.ResultBatchImportResult{}, err
	}
	replayed, err := replayResultBatch(operationContext, view, batch)
	if err != nil {
		if fatalSettledImportError(err) {
			return store.ResultBatchImportResult{},
				replica.failSettledIntegrity("scratch replay", err)
		}
		return store.ResultBatchImportResult{}, err
	}
	if replayed.admission == nil {
		return store.ResultBatchImportResult{}, fmt.Errorf(
			"%w: replay produced no peer-admission snapshot",
			ErrInvalidReplicationReplay,
		)
	}
	localMember, localExists := replayed.state.Device(replica.localDeviceID)
	if !localExists || localMember.ID != replica.localDeviceID {
		return store.ResultBatchImportResult{}, fmt.Errorf(
			"%w: replay removed the retained local identity",
			ErrInvalidReplicationReplay,
		)
	}
	transitionRequired := localMember.Status != device.StatusActive ||
		replayed.state.VoterSet().Contains(replica.localDeviceID) ||
		replayed.state.CredentialAuthority().Contains(replica.localDeviceID)
	commands, verifiedAt, err := replica.mapResultBatch(view, replayed)
	if err != nil {
		return store.ResultBatchImportResult{}, err
	}

	replica.admissionMu.Lock()
	result, err := replica.state.ImportSettledNonvoterResultBatch(
		operationContext,
		store.VerifiedResultBatchImport{
			RelayPeerID: relayPeerID,
			Batch:       batch,
			Commands:    commands,
			VerifiedAt:  verifiedAt,
			FinalProjectionDigest: store.Digest(
				replayed.projectionStateDigest,
			),
		},
	)
	if err == nil {
		replica.admission.Store(&peerAdmissionPublication{
			revision: result.AdmissionRevision,
			snapshot: replayed.admission,
		})
		if transitionRequired {
			replica.transitionRequired.Store(true)
		}
		if replayed.admissionChanged {
			replica.changes.signal()
		}
	} else if fatalSettledImportError(err) {
		replica.recordFatalLocked(fmt.Errorf(
			"consensus: settled-replica integrity failure: %w",
			err,
		))
	}
	replica.admissionMu.Unlock()
	if err != nil {
		if fatalSettledImportError(err) {
			return store.ResultBatchImportResult{}, replica.FatalError()
		}
		return store.ResultBatchImportResult{}, err
	}
	metadata := batch.Unsigned().Metadata()
	replica.recordLiveReplicationObservation(
		relayPeerID,
		metadata.ServerDeviceID,
		metadata.ServerAuthorityVersion,
		metadata.ToResultIndex,
		metadata.ServerAppliedResultIndex,
	)
	return result, nil
}

func (replica *SettledReplica) mapResultBatch(
	view store.StateView,
	replayed resultBatchReplay,
) ([]store.ResultBatchCommand, domain.Timestamp, error) {
	commands := make([]store.ResultBatchCommand, len(replayed.commands))
	priorHeads := view.Heads
	var verifiedAt domain.Timestamp
	for index, command := range replayed.commands {
		appliedAt, monotonicNow, err := replica.clock()
		if err != nil {
			return nil, "", fmt.Errorf(
				"consensus: read result-batch apply clock: %w",
				err,
			)
		}
		mapped, err := buildApplyRequest(
			command.signed,
			command.outcome,
			localApplyContext{
				RecoveryGeneration: view.RecoveryGeneration,
				AppliedAt:          appliedAt,
				OriginBootID:       replica.originBootID,
				MonotonicNowNS:     monotonicNow,
				PriorHeads:         priorHeads,
			},
		)
		if err != nil {
			return nil, "", fmt.Errorf(
				"%w: map result offset %d: %v",
				ErrInvalidReplicationReplay,
				index,
				err,
			)
		}
		commands[index] = store.ResultBatchCommand{
			Proposal:    mapped.Proposal,
			Outcome:     mapped.Outcome,
			Projections: mapped.Projections,
			Mutations:   command.mutations,
			Heads:       command.heads,
			Local: store.ResultBatchLocalWrites{
				AppliedAt:            mapped.AppliedAt,
				RecordActivity:       mapped.RecordActivity,
				ActivityTaskID:       mapped.ActivityTaskID,
				Audit:                mapped.Audit,
				Checkpoint:           mapped.Checkpoint,
				LeaseDeadlines:       mapped.LeaseDeadlines,
				DeleteLeaseDeadlines: mapped.DeleteLeaseDeadlines,
			},
		}
		priorHeads = command.heads
		verifiedAt = appliedAt
	}
	return commands, verifiedAt, nil
}

// View returns one immutable committed state cut.
func (replica *SettledReplica) View(
	ctx context.Context,
) (store.StateView, error) {
	if replica == nil || replica.state == nil || ctx == nil {
		return store.StateView{}, ErrInvalidNodeOptions
	}
	if err := replica.beginOperation(); err != nil {
		return store.StateView{}, err
	}
	defer replica.endOperation()
	return replica.state.View(ctx)
}

// ReplicationHeads returns one fully reverified durable catch-up cursor.
func (replica *SettledReplica) ReplicationHeads(
	ctx context.Context,
) (store.ApplyHeads, error) {
	if replica == nil || replica.state == nil || ctx == nil {
		return store.ApplyHeads{}, ErrInvalidNodeOptions
	}
	if err := replica.beginOperation(); err != nil {
		return store.ApplyHeads{}, err
	}
	defer replica.endOperation()
	view, err := replica.state.VerifiedSettledNonvoterView(ctx)
	if err != nil && fatalSettledImportError(err) {
		return store.ApplyHeads{},
			replica.failSettledIntegrity(
				"read replication heads",
				err,
			)
	}
	return view.Heads, err
}

// ReplicationProgress returns the fully reverified settled evidence head and
// its retained signed authority observations.
func (replica *SettledReplica) ReplicationProgress(
	ctx context.Context,
) (store.SettledReplicationProgress, error) {
	if replica == nil || replica.state == nil || ctx == nil {
		return store.SettledReplicationProgress{}, ErrInvalidNodeOptions
	}
	if err := replica.beginOperation(); err != nil {
		return store.SettledReplicationProgress{}, err
	}
	defer replica.endOperation()
	progress, err := replica.state.SettledReplicationProgress(ctx)
	if err != nil && fatalSettledImportError(err) {
		return store.SettledReplicationProgress{},
			replica.failSettledIntegrity(
				"read replication progress",
				err,
			)
	}
	return progress, err
}

// Status returns a read-only operator cut for a settled application
// nonvoter. A frozen pre-conversion Raft configuration is historical evidence,
// not a live observation, so topology and reconciliation remain unknown.
func (replica *SettledReplica) Status(
	ctx context.Context,
) (coordstatus.Snapshot, error) {
	if replica == nil || replica.state == nil || ctx == nil {
		return coordstatus.Snapshot{}, ErrInvalidNodeOptions
	}
	if !replica.localDeviceID.Valid() {
		return coordstatus.Snapshot{}, ErrInvalidNodeOptions
	}
	if err := replica.beginOperation(); err != nil {
		return coordstatus.Snapshot{}, err
	}
	defer replica.endOperation()
	select {
	case replica.importGate <- struct{}{}:
		defer func() { <-replica.importGate }()
	case <-ctx.Done():
		return coordstatus.Snapshot{}, ctx.Err()
	}
	durable, err := replica.localState.StatusSnapshot(
		ctx,
		replica.localDeviceID,
		coordstatus.MaxTasks,
	)
	if err != nil {
		return coordstatus.Snapshot{}, err
	}
	progress, err := replica.state.SettledReplicationProgress(ctx)
	if err != nil {
		if fatalSettledImportError(err) {
			return coordstatus.Snapshot{},
				replica.failSettledIntegrity(
					"derive status replication progress",
					err,
				)
		}
		return coordstatus.Snapshot{}, err
	}
	if progress.Heads.ChainIndex != durable.Heads.ChainIndex ||
		progress.Heads.ResultIndex != durable.Heads.ResultIndex ||
		progress.Heads.DigestVersion != durable.Heads.DigestVersion ||
		progress.Heads.ProjectionSchemaVersion !=
			durable.Heads.ProjectionSchemaVersion {
		return coordstatus.Snapshot{},
			replica.failSettledIntegrity(
				"compare status replication heads",
				ErrInvalidStateView,
			)
	}
	currency, observedAuthorityIDs, observedResultIndex :=
		settledReplicaCurrency(
			progress,
			replica.liveReplicationObservationSnapshot(),
			durable.CredentialAuthority.VoterDeviceIDs(),
			durable.CredentialAuthority.VoterSetVersion,
		)
	runtime := coordstatus.RuntimeSnapshot{
		State:                   coordstatus.ConsensusSettled,
		Role:                    coordstatus.RoleNonvoter,
		LocalDeviceID:           durable.Member.ID,
		LiveConfigurationSource: coordstatus.LiveConfigurationUnknown,
		LiveVoterDeviceIDs:      []domain.DeviceID{},
		LiveNonvoterDeviceIDs:   []domain.DeviceID{},
		QuorumRequired:          0,
		StrongWrites:            coordstatus.StrongWritesWaiting,
		ReplicaCurrency:         currency,
		ObservedAuthorityIDs:    observedAuthorityIDs,
		ObservedResultIndex:     observedResultIndex,
		ConfigurationReconciled: false,
		ReconciliationState:     coordstatus.ReconciliationUnknown,
		ReconciliationStep:      coordstatus.ReconciliationStepObserve,
		ReconciliationBlocker:   coordstatus.ReconciliationBlockerNone,
	}
	snapshot := coordstatus.Snapshot{
		Durable: durable,
		Runtime: runtime,
	}
	if err := snapshot.Validate(); err != nil {
		return coordstatus.Snapshot{}, fmt.Errorf(
			"consensus: invalid settled status snapshot: %w",
			err,
		)
	}
	return snapshot, nil
}

func settledReplicaCurrency(
	progress store.SettledReplicationProgress,
	live []liveReplicationObservation,
	authorityIDs []domain.DeviceID,
	authorityVersion uint64,
) (coordstatus.ReplicaCurrencyState, []domain.DeviceID, uint64) {
	authority := make(map[domain.DeviceID]struct{}, len(authorityIDs))
	for _, deviceID := range authorityIDs {
		authority[deviceID] = struct{}{}
	}
	observedSet := make(map[domain.DeviceID]struct{}, len(authorityIDs))
	currentSet := make(map[domain.DeviceID]struct{}, len(authorityIDs))
	observedResultIndex := uint64(0)
	for _, observation := range live {
		if observation.ServerAppliedResultIndex > observedResultIndex {
			observedResultIndex = observation.ServerAppliedResultIndex
		}
		if observation.AuthorityVersion != authorityVersion {
			continue
		}
		if _, current := authority[observation.SignerDeviceID]; current {
			observedSet[observation.SignerDeviceID] = struct{}{}
			if observation.VerifiedResultIndex ==
				progress.Heads.ResultIndex &&
				observation.ServerAppliedResultIndex ==
					progress.Heads.ResultIndex {
				currentSet[observation.SignerDeviceID] = struct{}{}
			}
		}
	}
	observed := make([]domain.DeviceID, 0, len(observedSet))
	for deviceID := range observedSet {
		observed = append(observed, deviceID)
	}
	sort.Slice(observed, func(left, right int) bool {
		return observed[left] < observed[right]
	})
	if progress.Blocker != nil &&
		progress.Blocker.ResultIndex > progress.Heads.ResultIndex {
		return coordstatus.ReplicaCurrencyBehind,
			observed,
			progress.Blocker.ResultIndex
	}
	if observedResultIndex > progress.Heads.ResultIndex {
		return coordstatus.ReplicaCurrencyBehind,
			observed,
			observedResultIndex
	}
	if len(currentSet) == len(authorityIDs) && len(authorityIDs) != 0 {
		return coordstatus.ReplicaCurrencyCurrent,
			observed,
			progress.Heads.ResultIndex
	}
	return coordstatus.ReplicaCurrencyUnknown,
		observed,
		observedResultIndex
}

func validateSettledReplicaEligibility(
	ctx context.Context,
	database *store.Store,
	localDeviceID domain.DeviceID,
	state reducer.State,
) error {
	if ctx == nil || database == nil || !localDeviceID.Valid() {
		return ErrSettledReplicaIneligible
	}
	if err := validateSettledReducerEligibility(
		state,
		localDeviceID,
	); err != nil {
		return err
	}
	voters, nonvoters, err := settledDurableConfiguration(ctx, database)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrSettledReplicaIneligible, err)
	}
	for _, configured := range voters {
		if configured == localDeviceID {
			return ErrSettledReplicaIneligible
		}
	}
	for _, configured := range nonvoters {
		if configured == localDeviceID {
			return ErrSettledReplicaIneligible
		}
	}
	return nil
}

func validateSettledReducerEligibility(
	state reducer.State,
	localDeviceID domain.DeviceID,
) error {
	if !localDeviceID.Valid() {
		return ErrSettledReplicaIneligible
	}
	member, exists := state.Device(localDeviceID)
	if !exists ||
		member.ID != localDeviceID ||
		member.Status != device.StatusActive ||
		state.VoterSet().Contains(localDeviceID) ||
		state.CredentialAuthority().Contains(localDeviceID) {
		return ErrSettledReplicaIneligible
	}
	return nil
}

func settledDurableConfiguration(
	ctx context.Context,
	database *store.Store,
) ([]domain.DeviceID, []domain.DeviceID, error) {
	if ctx == nil || database == nil {
		return nil, nil, ErrSettledReplicaIneligible
	}
	record, found, err := database.CommittedRaftConfiguration(ctx)
	if err != nil {
		return nil, nil, err
	}
	if !found {
		return nil, nil, ErrSettledReplicaIneligible
	}
	configuration, err := decodeRaftConfigurationJSON(
		record.ConfigurationJSON,
	)
	if err != nil {
		return nil, nil, err
	}
	voters := make([]domain.DeviceID, 0, len(configuration.Servers))
	nonvoters := make([]domain.DeviceID, 0, len(configuration.Servers))
	seen := make(map[domain.DeviceID]struct{}, len(configuration.Servers))
	for _, server := range configuration.Servers {
		deviceID := domain.DeviceID(server.ID)
		if !deviceID.Valid() ||
			server.Address != raft.ServerAddress(deviceID) {
			return nil, nil, ErrInvalidRaftTopology
		}
		if _, duplicate := seen[deviceID]; duplicate {
			return nil, nil, ErrInvalidRaftTopology
		}
		seen[deviceID] = struct{}{}
		switch server.Suffrage {
		case raft.Voter:
			voters = append(voters, deviceID)
		case raft.Nonvoter:
			nonvoters = append(nonvoters, deviceID)
		default:
			return nil, nil, ErrInvalidRaftTopology
		}
	}
	if len(voters) == 0 {
		return nil, nil, ErrInvalidRaftTopology
	}
	sort.Slice(voters, func(left, right int) bool {
		return voters[left] < voters[right]
	})
	sort.Slice(nonvoters, func(left, right int) bool {
		return nonvoters[left] < nonvoters[right]
	})
	return voters, nonvoters, nil
}

// Member returns one exact committed member projection.
func (replica *SettledReplica) Member(
	ctx context.Context,
	deviceID domain.DeviceID,
) (coordstatus.MemberSummary, bool, error) {
	if replica == nil ||
		replica.state == nil ||
		ctx == nil ||
		!deviceID.Valid() {
		return coordstatus.MemberSummary{}, false, ErrInvalidNodeOptions
	}
	if err := replica.beginOperation(); err != nil {
		return coordstatus.MemberSummary{}, false, err
	}
	defer replica.endOperation()
	return replica.localState.MemberStatus(ctx, deviceID)
}

// LocalState returns the restricted local-only store capability.
func (replica *SettledReplica) LocalState() (store.LocalState, error) {
	if replica == nil || replica.state == nil {
		return store.LocalState{}, ErrInvalidNodeOptions
	}
	replica.lifecycleMu.Lock()
	closing := replica.closing
	replica.lifecycleMu.Unlock()
	if closing {
		return store.LocalState{}, ErrNodeClosed
	}
	if err := replica.FatalError(); err != nil {
		return store.LocalState{}, err
	}
	return replica.localState, nil
}

// PeerAdmissionSnapshot returns the immutable admission cut published only
// after its matching import transaction commits.
func (replica *SettledReplica) PeerAdmissionSnapshot() (
	*peerauth.Snapshot,
	error,
) {
	if replica == nil || replica.state == nil {
		return nil, ErrInvalidNodeOptions
	}
	if err := replica.beginOperation(); err != nil {
		return nil, err
	}
	defer replica.endOperation()
	replica.admissionMu.Lock()
	defer replica.admissionMu.Unlock()
	if err := replica.FatalError(); err != nil {
		return nil, err
	}
	publication := replica.admission.Load()
	if publication == nil ||
		publication.snapshot == nil ||
		publication.revision == 0 ||
		publication.revision != replica.state.AdmissionRevision() {
		return nil, ErrPeerAdmissionUnavailable
	}
	return publication.snapshot, nil
}

// PeerAdmissionChanges claims the single ingress authorization subscription.
func (replica *SettledReplica) PeerAdmissionChanges() <-chan struct{} {
	if replica == nil || replica.changes == nil ||
		!replica.peerChangesClaimed.CompareAndSwap(false, true) {
		return closedChangeChannel()
	}
	return replica.changes.subscribe()
}

// ConsensusAuthorizationChanges claims the control-only identity stream's
// independent admission-change subscription.
func (replica *SettledReplica) ConsensusAuthorizationChanges() <-chan struct{} {
	if replica == nil || replica.changes == nil ||
		!replica.consensusChangesClaimed.CompareAndSwap(false, true) {
		return closedChangeChannel()
	}
	return replica.changes.subscribe()
}

// FatalError reports a terminal local integrity failure.
func (replica *SettledReplica) FatalError() error {
	if replica == nil {
		return ErrInvalidNodeOptions
	}
	replica.fatalMu.RLock()
	defer replica.fatalMu.RUnlock()
	return replica.fatalErr
}

func (replica *SettledReplica) beginOperation() error {
	replica.lifecycleMu.Lock()
	defer replica.lifecycleMu.Unlock()
	if replica.closing {
		return ErrNodeClosed
	}
	if err := replica.FatalError(); err != nil {
		return err
	}
	replica.active.Add(1)
	return nil
}

func (replica *SettledReplica) endOperation() {
	replica.active.Done()
}

func (replica *SettledReplica) operationContext(
	ctx context.Context,
) (context.Context, context.CancelFunc, func()) {
	operationContext, cancel := context.WithCancel(ctx)
	finished := make(chan struct{})
	watcherDone := make(chan struct{})
	go func() {
		defer close(watcherDone)
		select {
		case <-replica.closeStarted:
			cancel()
		case <-replica.fatalSet:
			cancel()
		case <-finished:
		}
	}()
	var once sync.Once
	wait := func() {
		once.Do(func() {
			close(finished)
			<-watcherDone
		})
	}
	return operationContext, cancel, wait
}

func (replica *SettledReplica) recordFatal(err error) {
	if err == nil {
		return
	}
	replica.admissionMu.Lock()
	defer replica.admissionMu.Unlock()
	replica.recordFatalLocked(err)
}

// recordFatalLocked publishes fatal state while admissionMu excludes any
// authorization read from observing the prior snapshot after detection.
func (replica *SettledReplica) recordFatalLocked(err error) {
	if err == nil {
		return
	}
	replica.localStateMu.Lock()
	defer replica.localStateMu.Unlock()
	replica.fatalOnce.Do(func() {
		replica.fatalMu.Lock()
		replica.fatalErr = err
		replica.fatalMu.Unlock()
		close(replica.fatalSet)
		replica.changes.close()
	})
}

func (replica *SettledReplica) failSettledIntegrity(
	operation string,
	err error,
) error {
	terminal := fmt.Errorf(
		"consensus: settled-replica integrity failure during %s: %w",
		operation,
		err,
	)
	replica.recordFatal(terminal)
	return replica.FatalError()
}

func (replica *SettledReplica) beginLocalStateOperation() (func(), error) {
	replica.localStateMu.RLock()
	if replica.localStateClosed.Load() {
		replica.localStateMu.RUnlock()
		return nil, ErrNodeClosed
	}
	if err := replica.FatalError(); err != nil {
		replica.localStateMu.RUnlock()
		return nil, err
	}
	return replica.localStateMu.RUnlock, nil
}

// Close cancels active imports and closes the owned store.
func (replica *SettledReplica) Close() error {
	if replica == nil {
		return ErrInvalidNodeOptions
	}
	replica.closeOnce.Do(func() {
		replica.lifecycleMu.Lock()
		replica.closing = true
		replica.localStateClosed.Store(true)
		close(replica.closeStarted)
		replica.lifecycleMu.Unlock()
		replica.changes.close()
		replica.active.Wait()
		replica.localStateMu.Lock()
		replica.localStateMu.Unlock()
		replica.closeErr = replica.state.Close()
	})
	return replica.closeErr
}

func fatalSettledImportError(err error) bool {
	return errors.Is(err, store.ErrIntegrityCheck) ||
		errors.Is(err, store.ErrCorrupt) ||
		errors.Is(err, store.ErrCommandResultCorrupt) ||
		errors.Is(err, store.ErrAppliedCheckpointIntegrity) ||
		errors.Is(err, store.ErrRaftCommandBinding) ||
		errors.Is(err, store.ErrReplicaEvidenceMode) ||
		errors.Is(
			err,
			store.ErrInvalidReplicationWatermarkObservation,
		) ||
		errors.Is(err, ErrInvalidStateView) ||
		errors.Is(err, reducer.ErrInvalidCommittedState)
}
