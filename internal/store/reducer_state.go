package store

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/ijonahch/codecomm/internal/codec"
	"github.com/ijonahch/codecomm/internal/domain"
	"github.com/ijonahch/codecomm/internal/domain/agentsession"
	"github.com/ijonahch/codecomm/internal/domain/auditcounter"
	"github.com/ijonahch/codecomm/internal/domain/conflict"
	"github.com/ijonahch/codecomm/internal/domain/controlfile"
	"github.com/ijonahch/codecomm/internal/domain/credentialauthority"
	"github.com/ijonahch/codecomm/internal/domain/credentialauthorization"
	"github.com/ijonahch/codecomm/internal/domain/device"
	"github.com/ijonahch/codecomm/internal/domain/lease"
	"github.com/ijonahch/codecomm/internal/domain/memory"
	"github.com/ijonahch/codecomm/internal/domain/plan"
	"github.com/ijonahch/codecomm/internal/domain/publication"
	"github.com/ijonahch/codecomm/internal/domain/task"
	"github.com/ijonahch/codecomm/internal/reducer"
)

func reducerStateFromProjectionWrites(
	sessionID domain.UUIDv7,
	workspaceID domain.UUIDv4,
	recoveryGeneration uint64,
	genesisJSON []byte,
	heads ApplyHeads,
	writes ProjectionWrites,
) (reducer.State, error) {
	recoveryPublicKey, err := reducerRecoveryPublicKey(genesisJSON)
	if err != nil {
		return reducer.State{}, err
	}
	if len(writes.VoterSet) != 1 ||
		len(writes.CredentialAuthority) != 1 ||
		len(writes.PlanCurrent) != 1 ||
		len(writes.CanonicalRefs) != 1 ||
		len(writes.SessionPolicy) != 1 {
		return reducer.State{}, errors.New(
			"store: reducer projection snapshot lacks singleton rows",
		)
	}
	snapshot := reducer.Snapshot{
		SessionID:                sessionID,
		WorkspaceID:              workspaceID,
		RecoveryGeneration:       recoveryGeneration,
		RecoveryPublicKey:        recoveryPublicKey,
		CurrentChainIndex:        heads.ChainIndex,
		CurrentResultIndex:       heads.ResultIndex,
		OriginScopes:             make(map[reducer.OriginScopeKey]reducer.OriginScope),
		AuditCounters:            make(map[domain.DeviceID]auditcounter.Counter),
		Devices:                  make(map[domain.DeviceID]device.Device),
		VoterSet:                 writes.VoterSet[0],
		CredentialAuthority:      credentialauthority.Authority(writes.CredentialAuthority[0]),
		CredentialAuthorizations: make(map[credentialauthorization.Key]credentialauthorization.Authorization),
		AgentSessions:            make(map[domain.UUIDv7]agentsession.Session),
		Tasks:                    make(map[domain.UUIDv7]task.Task),
		PlanRevisions:            make(map[domain.UUIDv7]plan.Revision),
		PlanCurrent:              writes.PlanCurrent[0],
		MemoryRecords:            make(map[domain.UUIDv7]memory.Record),
		Leases:                   make(map[domain.UUIDv7]lease.Lease),
		SessionPolicy:            writes.SessionPolicy[0],
		CanonicalRef:             writes.CanonicalRefs[0],
		Publications:             make(map[domain.UUIDv7]publication.Publication),
		ControlFileProposals:     make(map[domain.UUIDv7]controlfile.Proposal),
		MergeConflicts:           make(map[domain.ConflictID]conflict.Conflict),
	}

	for _, row := range writes.OriginScopes {
		key := reducer.OriginScopeKey{
			DeviceID: row.DeviceID,
			Kind:     reducer.ScopeKind(row.ScopeKind),
			ScopeID:  row.ScopeID,
		}
		if _, exists := snapshot.OriginScopes[key]; exists {
			return reducer.State{}, duplicateReducerProjection("origin scope")
		}
		snapshot.OriginScopes[key] = reducer.OriginScope{
			OriginScopeKey: key,
			LastSequence:   row.LastSequence,
		}
	}
	for _, row := range writes.AuditCounters {
		if _, exists := snapshot.AuditCounters[row.DeviceID]; exists {
			return reducer.State{}, duplicateReducerProjection("audit counter")
		}
		snapshot.AuditCounters[row.DeviceID] = row
	}
	for _, row := range writes.Devices {
		if _, exists := snapshot.Devices[row.ID]; exists {
			return reducer.State{}, duplicateReducerProjection("device")
		}
		snapshot.Devices[row.ID] = row
	}
	for _, row := range writes.CredentialAuthorizations {
		authorization := reducerCredentialAuthorization(row)
		key := authorization.PrimaryKey()
		if _, exists := snapshot.CredentialAuthorizations[key]; exists {
			return reducer.State{}, duplicateReducerProjection(
				"credential authorization",
			)
		}
		snapshot.CredentialAuthorizations[key] = authorization
	}
	for _, row := range writes.AgentSessions {
		if _, exists := snapshot.AgentSessions[row.ID]; exists {
			return reducer.State{}, duplicateReducerProjection("agent session")
		}
		snapshot.AgentSessions[row.ID] = row
	}
	for _, row := range writes.Tasks {
		if _, exists := snapshot.Tasks[row.ID]; exists {
			return reducer.State{}, duplicateReducerProjection("task")
		}
		snapshot.Tasks[row.ID] = row
	}
	for _, row := range writes.PlanRevisions {
		if _, exists := snapshot.PlanRevisions[row.ID()]; exists {
			return reducer.State{}, duplicateReducerProjection("plan revision")
		}
		snapshot.PlanRevisions[row.ID()] = row
	}
	for _, row := range writes.MemoryRecords {
		if _, exists := snapshot.MemoryRecords[row.ID()]; exists {
			return reducer.State{}, duplicateReducerProjection("memory record")
		}
		snapshot.MemoryRecords[row.ID()] = row
	}
	for _, row := range writes.Leases {
		if _, exists := snapshot.Leases[row.ID]; exists {
			return reducer.State{}, duplicateReducerProjection("lease")
		}
		snapshot.Leases[row.ID] = row
	}
	for _, row := range writes.Publications {
		id := row.Metadata.PublicationID
		if _, exists := snapshot.Publications[id]; exists {
			return reducer.State{}, duplicateReducerProjection("publication")
		}
		snapshot.Publications[id] = row
	}
	for _, row := range writes.ControlFileProposals {
		proposal := reducerControlFileProposal(row)
		if _, exists := snapshot.ControlFileProposals[proposal.ProposalEventID]; exists {
			return reducer.State{}, duplicateReducerProjection(
				"control-file proposal",
			)
		}
		snapshot.ControlFileProposals[proposal.ProposalEventID] = proposal
	}
	for _, row := range writes.MergeConflicts {
		if _, exists := snapshot.MergeConflicts[row.ID]; exists {
			return reducer.State{}, duplicateReducerProjection("merge conflict")
		}
		snapshot.MergeConflicts[row.ID] = row
	}
	state, err := reducer.NewState(snapshot)
	if err != nil {
		return reducer.State{}, fmt.Errorf(
			"store: construct reducer snapshot: %w",
			err,
		)
	}
	return state, nil
}

func reducerRecoveryPublicKey(genesisJSON []byte) (ed25519.PublicKey, error) {
	canonical, err := codec.CanonicalizeSignedObject(genesisJSON)
	if err != nil || !bytes.Equal(canonical, genesisJSON) {
		return nil, fmt.Errorf(
			"store: reducer genesis is not canonical: %w",
			err,
		)
	}
	var members map[string]json.RawMessage
	if err := json.Unmarshal(genesisJSON, &members); err != nil {
		return nil, fmt.Errorf("store: decode reducer genesis: %w", err)
	}
	raw, exists := members["recovery_public_key"]
	if !exists {
		return nil, errors.New(
			"store: reducer genesis omits recovery_public_key",
		)
	}
	var encoded string
	if err := json.Unmarshal(raw, &encoded); err != nil {
		return nil, fmt.Errorf(
			"store: decode reducer recovery key: %w",
			err,
		)
	}
	decoded, err := codec.DecodeBase64URLExact(
		encoded,
		ed25519.PublicKeySize,
	)
	if err != nil {
		return nil, fmt.Errorf(
			"store: decode reducer recovery key: %w",
			err,
		)
	}
	return ed25519.PublicKey(bytes.Clone(decoded)), nil
}

func reducerCredentialAuthorization(
	row CredentialAuthorizationRow,
) credentialauthorization.Authorization {
	endorsements := make(
		[]credentialauthorization.ClockEndorsement,
		len(row.ClockEndorsements),
	)
	for index, endorsement := range row.ClockEndorsements {
		endorsements[index] = credentialauthorization.ClockEndorsement{
			DeviceID:  endorsement.DeviceID,
			Signature: endorsement.Signature,
		}
	}
	return credentialauthorization.Authorization{
		SessionID:                row.SessionID,
		DeviceID:                 row.DeviceID,
		Epoch:                    row.Epoch,
		EpochPublicKey:           row.EpochPublicKey,
		KeyDigest:                row.KeyDigest,
		Role:                     credentialauthorization.Role(row.Role),
		IssuedAt:                 row.IssuedAt,
		NotBefore:                row.NotBefore,
		ValiditySeconds:          row.ValiditySeconds,
		AuthorityVoterSetVersion: row.AuthorityVoterSetVersion,
		ClockEndorsements:        endorsements,
		BindingSignature:         row.BindingSignature,
		AuthorizationChainIndex:  row.AuthorizationChainIndex,
	}
}

func reducerControlFileProposal(
	row ControlFileProposalRow,
) controlfile.Proposal {
	var digest *controlfile.SHA256Digest
	if row.ContentDigest != nil {
		value := controlfile.SHA256Digest(*row.ContentDigest)
		digest = &value
	}
	return controlfile.Proposal{
		ProposalEventID:    row.ProposalEventID,
		SessionID:          row.SessionID,
		Path:               row.Path,
		Operation:          controlfile.Operation(row.Operation),
		ContentDigest:      digest,
		ContentSize:        row.ContentSize,
		Diff:               row.Diff,
		ProposedByDeviceID: row.ProposedByDeviceID,
		ChainIndex:         row.ChainIndex,
	}
}

func duplicateReducerProjection(kind string) error {
	return fmt.Errorf("store: duplicate reducer %s projection", kind)
}
