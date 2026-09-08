package agent

import (
	"bytes"
	"context"
	"fmt"

	"github.com/ijonahch/codecomm/internal/domain"
	"github.com/ijonahch/codecomm/internal/domain/device"
	"github.com/ijonahch/codecomm/internal/event"
	"github.com/ijonahch/codecomm/internal/store"
)

// VersionReportReservation is an opaque durable membership-version command.
// The daemon composition root may await it without gaining signing authority.
type VersionReportReservation struct {
	record store.LocalCommandRecord
}

// ResumePendingVersionReport returns the sole unresolved report from any
// prior boot without starting background forwarding.
func (origin *BootOrigin) ResumePendingVersionReport(
	ctx context.Context,
) (VersionReportReservation, bool, error) {
	if err := origin.available(); err != nil {
		return VersionReportReservation{}, false, err
	}
	if ctx == nil {
		return VersionReportReservation{}, false, ErrInvalidOptions
	}
	operationContext, cancel := origin.operationContext(ctx)
	defer cancel()
	if err := origin.acquireExclusive(operationContext); err != nil {
		return VersionReportReservation{}, false, err
	}
	defer origin.releaseExclusive()
	record, found, err := origin.findPendingVersionReportLocked(
		operationContext,
	)
	if err != nil || !found {
		return VersionReportReservation{}, false, err
	}
	if err := origin.installVersionReportPriorityLocked(
		operationContext,
		record,
	); err != nil {
		return VersionReportReservation{}, false, err
	}
	return VersionReportReservation{record: record}, true, nil
}

// ReserveVersionReport durably queues this binary's changed compatibility
// report under the local daemon binding. It starts no background work.
func (origin *BootOrigin) ReserveVersionReport(
	ctx context.Context,
	daemonVersion string,
	maxApplyLevel uint64,
	expectedEntityVersion uint64,
) (VersionReportReservation, error) {
	if err := origin.available(); err != nil {
		return VersionReportReservation{}, err
	}
	if ctx == nil ||
		!device.ValidDaemonVersion(daemonVersion) ||
		maxApplyLevel < 1 ||
		maxApplyLevel > domain.MaxApplyLevel ||
		expectedEntityVersion < 1 ||
		!domain.ValidUnsignedInteger(expectedEntityVersion) {
		return VersionReportReservation{}, ErrInvalidOptions
	}
	operationContext, cancel := origin.operationContext(ctx)
	defer cancel()
	if err := origin.acquireExclusive(operationContext); err != nil {
		return VersionReportReservation{}, err
	}
	defer origin.releaseExclusive()
	payload, err := canonicalObject(map[string]any{
		"daemon_version":  daemonVersion,
		"max_apply_level": maxApplyLevel,
	})
	if err != nil {
		return VersionReportReservation{}, err
	}
	record, found, err := origin.findPendingVersionReportLocked(
		operationContext,
	)
	if err != nil {
		return VersionReportReservation{}, err
	}
	if !found {
		record, err = origin.reserveDaemonCommandLocked(
			operationContext,
			event.KindMembershipVersionReported,
			event.StringEntityID(string(origin.deviceID)),
			expectedEntityVersion,
			payload,
			map[string]any{
				"daemon_version":  daemonVersion,
				"max_apply_level": maxApplyLevel,
			},
		)
		if err != nil {
			return VersionReportReservation{}, err
		}
	}
	if err := origin.installVersionReportPriorityLocked(
		operationContext,
		record,
	); err != nil {
		return VersionReportReservation{}, err
	}
	return VersionReportReservation{record: record}, nil
}

// AwaitVersionReport waits for the exact durable reservation to resolve.
func (origin *BootOrigin) AwaitVersionReport(
	ctx context.Context,
	reservation VersionReportReservation,
) (store.CommandOutcome, error) {
	if err := origin.available(); err != nil {
		return store.CommandOutcome{}, err
	}
	record := reservation.record
	if ctx == nil ||
		origin.validateVersionReportReservation(record) != nil ||
		!sameVersionReportRecord(origin.versionReportPriority(), record) {
		return store.CommandOutcome{}, ErrInvalidOptions
	}
	origin.wakeWorker()
	operationContext, cancel := origin.operationContext(ctx)
	defer cancel()
	resolved, err := origin.waitResolved(operationContext, record)
	if err != nil {
		return store.CommandOutcome{}, err
	}
	if resolved.Outcome == nil {
		return store.CommandOutcome{}, ErrCommandForwarding
	}
	return *resolved.Outcome, nil
}

// CompleteVersionReport releases the startup mutation barrier only after the
// composition root has verified the report against committed membership.
func (origin *BootOrigin) CompleteVersionReport(
	ctx context.Context,
	reservation VersionReportReservation,
) error {
	if err := origin.available(); err != nil {
		return err
	}
	record := reservation.record
	if ctx == nil || origin.validateVersionReportReservation(record) != nil {
		return ErrInvalidOptions
	}
	operationContext, cancel := origin.operationContext(ctx)
	defer cancel()
	if err := origin.acquireExclusive(operationContext); err != nil {
		return err
	}
	defer origin.releaseExclusive()
	priority := origin.versionReportPriority()
	if !sameVersionReportRecord(priority, record) {
		return ErrInvalidOptions
	}
	current, found, err := origin.local.LookupRequest(
		operationContext,
		record.ClientInstanceID,
		record.RequestID,
	)
	if err != nil {
		return err
	}
	if !found ||
		current.State != store.LocalRequestResolved ||
		current.Outcome == nil {
		return ErrCommandForwarding
	}
	origin.mu.Lock()
	if origin.versionReport == nil ||
		!sameVersionReportRecord(origin.versionReport, record) {
		origin.mu.Unlock()
		return ErrInvalidOptions
	}
	origin.versionReport = nil
	origin.mu.Unlock()
	origin.wakeWorker()
	return nil
}

func (origin *BootOrigin) findPendingVersionReportLocked(
	ctx context.Context,
) (store.LocalCommandRecord, bool, error) {
	records, err := origin.local.OutboxRecords(ctx)
	if err != nil {
		return store.LocalCommandRecord{}, false, err
	}
	var pending *store.LocalCommandRecord
	for _, candidate := range records {
		if candidate.Kind != event.KindMembershipVersionReported {
			continue
		}
		scope := store.OutboxScope{
			OriginDeviceID:  candidate.OriginDeviceID,
			OriginScopeKind: candidate.OriginScopeKind,
			OriginScopeID:   candidate.OriginScopeID,
		}
		signed, err := origin.validateBootOutboxRecord(candidate, scope)
		if err != nil {
			return store.LocalCommandRecord{}, false, err
		}
		for _, predecessor := range records {
			if predecessor.OriginDeviceID == candidate.OriginDeviceID &&
				predecessor.OriginScopeKind == candidate.OriginScopeKind &&
				predecessor.OriginScopeID == candidate.OriginScopeID &&
				predecessor.OriginSequence < candidate.OriginSequence {
				return store.LocalCommandRecord{}, false, fmt.Errorf(
					"%w: pending version report is not its boot-scope head",
					ErrBootOriginIntegrity,
				)
			}
		}
		record, found, err := origin.local.LookupRequest(
			ctx,
			candidate.ClientInstanceID,
			candidate.RequestID,
		)
		if err != nil {
			return store.LocalCommandRecord{}, false, err
		}
		if !found ||
			record.State != store.LocalRequestSigned &&
				record.State != store.LocalRequestPending {
			return store.LocalCommandRecord{}, false, fmt.Errorf(
				"%w: pending version report request is missing",
				ErrBootOriginIntegrity,
			)
		}
		if err := origin.validateVersionReportReservation(record); err != nil {
			return store.LocalCommandRecord{}, false, err
		}
		if !bytes.Equal(signed.CanonicalBytes(), record.SignedProposal) {
			return store.LocalCommandRecord{}, false, fmt.Errorf(
				"%w: pending version report request differs from its outbox record",
				ErrBootOriginIntegrity,
			)
		}
		if pending != nil {
			return store.LocalCommandRecord{}, false, fmt.Errorf(
				"%w: multiple pending version reports",
				ErrBootOriginIntegrity,
			)
		}
		cloned := record
		pending = &cloned
	}
	if pending == nil {
		return store.LocalCommandRecord{}, false, nil
	}
	return *pending, true, nil
}

func (origin *BootOrigin) installVersionReportPriorityLocked(
	ctx context.Context,
	record store.LocalCommandRecord,
) error {
	if err := origin.validateVersionReportReservation(record); err != nil {
		return err
	}
	previous := origin.versionReportPriority()
	if previous != nil && !sameVersionReportRecord(previous, record) {
		current, found, err := origin.local.LookupRequest(
			ctx,
			previous.ClientInstanceID,
			previous.RequestID,
		)
		if err != nil {
			return err
		}
		if !found ||
			current.State != store.LocalRequestResolved ||
			current.Outcome == nil {
			return ErrCommandForwarding
		}
	}
	cloned := record
	cloned.SignedProposal = bytes.Clone(record.SignedProposal)
	if record.Outcome != nil {
		outcome := *record.Outcome
		outcome.JSON = bytes.Clone(record.Outcome.JSON)
		cloned.Outcome = &outcome
	}
	origin.mu.Lock()
	origin.versionReport = &cloned
	origin.mu.Unlock()
	return nil
}

func (origin *BootOrigin) validateVersionReportReservation(
	record store.LocalCommandRecord,
) error {
	if record.ClientInstanceID != record.OriginScopeID ||
		record.SessionID != origin.sessionID ||
		record.WorkspaceID != origin.workspaceID ||
		record.BindingClass != store.LocalBindingDaemon ||
		record.OriginDeviceID != origin.deviceID ||
		record.OriginScopeKind != store.OriginScopeKindBoot ||
		record.RequestKind != event.KindMembershipVersionReported ||
		!record.RequestID.Valid() ||
		!record.EventID.Valid() ||
		len(record.SignedProposal) == 0 {
		return ErrInvalidOptions
	}
	signed, err := event.ParseAndVerify(
		record.SignedProposal,
		event.VerificationContext{
			SessionID:         origin.sessionID,
			WorkspaceID:       origin.workspaceID,
			IdentityPublicKey: origin.publicKey,
		},
	)
	if err != nil ||
		!bytes.Equal(signed.CanonicalBytes(), record.SignedProposal) {
		return fmt.Errorf(
			"%w: version report proposal failed verification",
			ErrBootOriginIntegrity,
		)
	}
	proposal := signed.Proposal()
	entityID, entityPresent := proposal.EntityID.Value()
	if proposal.EventID != record.EventID ||
		proposal.Kind != event.KindMembershipVersionReported ||
		proposal.Origin.DeviceID() != origin.deviceID ||
		proposal.Origin.ActorType() != event.ActorDaemon ||
		proposal.Origin.OriginBootID() != record.OriginScopeID ||
		proposal.Origin.AgentSessionID() != "" ||
		proposal.Origin.Sequence() != record.OriginSequence ||
		!entityPresent ||
		entityID != string(origin.deviceID) ||
		proposal.ExpectedEntityVersion == nil {
		return fmt.Errorf(
			"%w: invalid version report reservation binding",
			ErrBootOriginIntegrity,
		)
	}
	return nil
}

func sameVersionReportRecord(
	left *store.LocalCommandRecord,
	right store.LocalCommandRecord,
) bool {
	return left != nil &&
		left.ClientInstanceID == right.ClientInstanceID &&
		left.RequestID == right.RequestID &&
		left.EventID == right.EventID &&
		left.OriginScopeID == right.OriginScopeID
}
