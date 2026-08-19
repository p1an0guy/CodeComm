package reducer

import (
	"github.com/ijonahch/codecomm/internal/codec"
	"github.com/ijonahch/codecomm/internal/domain"
	"github.com/ijonahch/codecomm/internal/domain/credentialauthorization"
	"github.com/ijonahch/codecomm/internal/domain/device"
)

func (state *State) loadCredentialSnapshot(
	authorizations map[credentialauthorization.Key]credentialauthorization.Authorization,
) error {
	if state == nil {
		return invalidState("nil reducer state")
	}
	type streamKey struct {
		sessionID domain.UUIDv7
		deviceID  domain.DeviceID
	}
	byStream := make(
		map[streamKey]map[uint64]credentialauthorization.Authorization,
	)
	chainPositions := make(map[uint64]credentialauthorization.Key, len(authorizations))
	for key, value := range authorizations {
		if key != value.PrimaryKey() {
			return invalidState(
				"credential-authorization map key does not match row",
			)
		}
		if err := value.Validate(); err != nil {
			return invalidState(
				"credential authorization %q/%d: %v",
				key.DeviceID,
				key.Epoch,
				err,
			)
		}
		member, exists := state.devices[key.DeviceID]
		if !exists {
			return invalidState(
				"credential authorization references missing device %q",
				key.DeviceID,
			)
		}
		if value.SessionID == state.sessionID &&
			value.AuthorityVoterSetVersion >
				state.credentialAuthority.VoterSetVersion {
			return invalidState(
				"credential authorization %q/%q/%d has a future authority version",
				key.SessionID,
				key.DeviceID,
				key.Epoch,
			)
		}
		if value.AuthorizationChainIndex > state.currentChainIndex {
			return invalidState(
				"credential authorization %q/%q/%d has a future chain index",
				key.SessionID,
				key.DeviceID,
				key.Epoch,
			)
		}
		if prior, duplicate := chainPositions[value.AuthorizationChainIndex]; duplicate {
			return invalidState(
				"credential authorizations %q/%q/%d and %q/%q/%d reuse chain index %d",
				prior.SessionID,
				prior.DeviceID,
				prior.Epoch,
				key.SessionID,
				key.DeviceID,
				key.Epoch,
				value.AuthorizationChainIndex,
			)
		}
		chainPositions[value.AuthorizationChainIndex] = key
		if prior, reused := state.credentialKeys[value.KeyDigest]; reused {
			return invalidState(
				"credential authorizations %q/%q/%d and %q/%q/%d reuse a key",
				prior.SessionID,
				prior.DeviceID,
				prior.Epoch,
				key.SessionID,
				key.DeviceID,
				key.Epoch,
			)
		}
		if !verifyCredentialBinding(value, member.IdentityPublicKey) {
			return invalidState(
				"credential authorization %q/%q/%d has an invalid binding",
				key.SessionID,
				key.DeviceID,
				key.Epoch,
			)
		}
		preimage, err := credentialauthorization.CanonicalEndorsementPreimage(
			value,
		)
		if err != nil {
			return invalidState(
				"credential authorization %q/%q/%d endorsement preimage: %v",
				key.SessionID,
				key.DeviceID,
				key.Epoch,
				err,
			)
		}
		for _, endorsement := range value.ClockEndorsements {
			endorser, exists := state.devices[endorsement.DeviceID]
			if !exists || !verifyLabeledSignature(
				endorser.IdentityPublicKey,
				codec.SignatureCredentialTimeEndorsement,
				preimage,
				endorsement.Signature[:],
			) {
				return invalidState(
					"credential authorization %q/%q/%d has an invalid historical endorsement",
					key.SessionID,
					key.DeviceID,
					key.Epoch,
				)
			}
		}
		stream := streamKey{
			sessionID: value.SessionID,
			deviceID:  value.DeviceID,
		}
		if byStream[stream] == nil {
			byStream[stream] = make(
				map[uint64]credentialauthorization.Authorization,
			)
		}
		byStream[stream][key.Epoch] = value.Clone()
		state.credentialKeys[value.KeyDigest] = key
	}

	// Historical authority membership and quorum are authenticated by replayed
	// event/result chains and the projection accumulator before rows reach
	// NewState. The current authority projection cannot reconstruct authority
	// sets that were active at earlier credential positions. Here we still
	// verify every retained identity signature and each stream's immutable
	// transition structure.
	for stream, rows := range byStream {
		var previous *credentialauthorization.Authorization
		var previousChainIndex uint64
		for epoch := uint64(1); epoch <= uint64(len(rows)); epoch++ {
			value, exists := rows[epoch]
			if !exists {
				return invalidState(
					"credential history %q/%q omits epoch %d",
					stream.sessionID,
					stream.deviceID,
					epoch,
				)
			}
			if previousChainIndex >= value.AuthorizationChainIndex {
				return invalidState(
					"credential history %q/%q chain positions are not increasing",
					stream.sessionID,
					stream.deviceID,
				)
			}
			if err := credentialauthorization.ValidateTransition(
				previous,
				value,
			); err != nil {
				return invalidState(
					"credential history %q/%q epoch %d transition: %v",
					stream.sessionID,
					stream.deviceID,
					epoch,
					err,
				)
			}
			key := value.PrimaryKey()
			state.credentialAuthorizations[key] = value.Clone()
			previousValue := value.Clone()
			previous = &previousValue
			previousChainIndex = value.AuthorizationChainIndex
		}
	}
	for deviceID, counter := range state.auditCounters {
		rows := byStream[streamKey{
			sessionID: state.sessionID,
			deviceID:  deviceID,
		}]
		if uint64(len(rows)) != counter.CredentialEpoch {
			return invalidState(
				"device %q current-session credential history length %d does not match audit-counter epoch %d",
				deviceID,
				len(rows),
				counter.CredentialEpoch,
			)
		}
	}
	return nil
}

func (state State) validateCredentialChanges(
	changes Changes,
	pendingMembership pendingMembershipChanges,
) (map[credentialauthorization.Key]credentialauthorization.Authorization, error) {
	pending := make(
		map[credentialauthorization.Key]credentialauthorization.Authorization,
		len(changes.CredentialAuthorizations),
	)
	if len(changes.CredentialAuthorizations) == 0 {
		for deviceID, next := range pendingMembership.auditCounters {
			current, exists := state.auditCounters[deviceID]
			if exists && next.CredentialEpoch != current.CredentialEpoch {
				return nil, invalidState(
					"audit counter %q advances epoch without a credential authorization",
					deviceID,
				)
			}
		}
		return pending, nil
	}
	if len(changes.CredentialAuthorizations) != 1 {
		return nil, invalidState(
			"credential change set must contain exactly one authorization",
		)
	}
	if len(changes.AuditCounters) != 1 ||
		len(changes.Devices) != 0 ||
		len(changes.VoterSet) != 0 ||
		len(changes.CredentialAuthority) != 0 ||
		hasNonCredentialDomainChanges(changes) {
		return nil, invalidState(
			"credential authorization must be paired only with its audit-counter reset",
		)
	}

	value := changes.CredentialAuthorizations[0].Clone()
	if err := value.Validate(); err != nil {
		return nil, invalidState(
			"credential authorization change: %v",
			err,
		)
	}
	if value.SessionID != state.sessionID {
		return nil, invalidState(
			"credential authorization change has wrong session",
		)
	}
	if value.AuthorizationChainIndex != state.currentChainIndex+1 {
		return nil, invalidState(
			"credential authorization chain index %d does not follow %d",
			value.AuthorizationChainIndex,
			state.currentChainIndex,
		)
	}
	member, exists := state.devices[value.DeviceID]
	if !exists || member.Status != device.StatusActive {
		return nil, invalidState(
			"credential authorization subject %q is not active",
			value.DeviceID,
		)
	}
	if device.Role(value.Role) != member.Role {
		return nil, invalidState(
			"credential authorization subject %q has stale role",
			value.DeviceID,
		)
	}
	if !verifyCredentialBinding(value, member.IdentityPublicKey) {
		return nil, invalidState(
			"credential authorization subject %q has invalid binding",
			value.DeviceID,
		)
	}
	if prior, reused := state.credentialKeys[value.KeyDigest]; reused {
		return nil, invalidState(
			"credential authorization reuses key from %q/%d",
			prior.DeviceID,
			prior.Epoch,
		)
	}
	if value.AuthorityVoterSetVersion !=
		state.credentialAuthority.VoterSetVersion {
		return nil, invalidState(
			"credential authorization has stale authority version",
		)
	}
	if err := validateCredentialEndorsements(state, value); err != nil {
		return nil, invalidState(
			"credential authorization endorsements: %v",
			err,
		)
	}

	currentCounter, exists := state.auditCounters[value.DeviceID]
	if !exists {
		return nil, invalidState(
			"credential authorization subject %q has no audit counter",
			value.DeviceID,
		)
	}
	nextCounter, exists := pendingMembership.auditCounters[value.DeviceID]
	if !exists ||
		nextCounter.CredentialEpoch != value.Epoch ||
		nextCounter.AcceptedCount != 0 {
		return nil, invalidState(
			"credential authorization does not atomically reset its audit counter",
		)
	}
	if currentCounter.CredentialEpoch == domain.MaxSafeInteger ||
		value.Epoch != currentCounter.CredentialEpoch+1 {
		return nil, invalidState(
			"credential authorization epoch does not follow its audit counter",
		)
	}
	var previous *credentialauthorization.Authorization
	if currentCounter.CredentialEpoch != 0 {
		key := credentialauthorization.Key{
			SessionID: state.sessionID,
			DeviceID:  value.DeviceID,
			Epoch:     currentCounter.CredentialEpoch,
		}
		prior, exists := state.credentialAuthorizations[key]
		if !exists {
			return nil, invalidState(
				"credential authorization subject %q lacks prior epoch",
				value.DeviceID,
			)
		}
		prior = prior.Clone()
		previous = &prior
	}
	if err := credentialauthorization.ValidateTransition(previous, value); err != nil {
		return nil, invalidState(
			"credential authorization transition: %v",
			err,
		)
	}
	pending[value.PrimaryKey()] = value
	return pending, nil
}

func hasNonCredentialDomainChanges(changes Changes) bool {
	// Every future Changes projection family, including control-file proposals,
	// must be added here so credential events remain an exact two-row write.
	return len(changes.Tasks) != 0 ||
		len(changes.PlanRevisions) != 0 ||
		len(changes.PlanCurrent) != 0 ||
		len(changes.MemoryRecords) != 0 ||
		len(changes.Leases) != 0 ||
		len(changes.AgentSessions) != 0 ||
		len(changes.CanonicalRefs) != 0 ||
		len(changes.Publications) != 0 ||
		len(changes.ControlFileProposals) != 0 ||
		len(changes.MergeConflicts) != 0 ||
		len(changes.SessionPolicy) != 0
}
