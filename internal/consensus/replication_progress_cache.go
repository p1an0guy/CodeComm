package consensus

import (
	"context"

	"github.com/ijonahch/codecomm/internal/store"
)

func (replica *SettledReplica) refreshReplicationProgress(
	ctx context.Context,
) error {
	if replica == nil || replica.state == nil || ctx == nil {
		return ErrInvalidNodeOptions
	}
	progress, err :=
		replica.state.SettledReplicationProgressAfterVerification(ctx)
	if err != nil {
		return err
	}
	replica.setReplicationProgress(progress)
	return nil
}

func (replica *SettledReplica) setReplicationProgress(
	progress store.SettledReplicationProgress,
) {
	if replica == nil {
		return
	}
	replica.replicationProgressMu.Lock()
	replica.replicationProgress = cloneSettledReplicationProgress(progress)
	replica.replicationProgressSet = true
	replica.replicationProgressMu.Unlock()
}

func (replica *SettledReplica) replicationProgressSnapshot() (
	store.SettledReplicationProgress,
	bool,
) {
	if replica == nil {
		return store.SettledReplicationProgress{}, false
	}
	replica.replicationProgressMu.RLock()
	defer replica.replicationProgressMu.RUnlock()
	if !replica.replicationProgressSet {
		return store.SettledReplicationProgress{}, false
	}
	return cloneSettledReplicationProgress(replica.replicationProgress), true
}

func cloneSettledReplicationProgress(
	progress store.SettledReplicationProgress,
) store.SettledReplicationProgress {
	result := progress
	result.Observations = append(
		[]store.SettledReplicationObservation(nil),
		progress.Observations...,
	)
	if progress.Blocker != nil {
		blocker := *progress.Blocker
		result.Blocker = &blocker
	}
	return result
}
