package reducer

import (
	"crypto/sha256"
	"errors"

	"github.com/ijonahch/codecomm/internal/codec"
	"github.com/ijonahch/codecomm/internal/domain"
	"github.com/ijonahch/codecomm/internal/domain/auditcounter"
	"github.com/ijonahch/codecomm/internal/domain/credentialauthorization"
	"github.com/ijonahch/codecomm/internal/domain/device"
)

func reduceCredentialAuthorized(
	context reductionContext,
) (Outcome, error) {
	authorizationChainIndex := context.state.currentChainIndex
	if authorizationChainIndex < domain.MaxSafeInteger {
		authorizationChainIndex++
	}
	authorization, ok := decodeCredentialAuthorization(
		context.proposal.Payload,
		context.state.sessionID,
		authorizationChainIndex,
	)
	if !ok {
		_, code := decodePayload(
			context.proposal.Payload,
			credentialAuthorizationFields,
			nil,
		)
		if code != "" {
			return context.reject(code), nil
		}
		return context.reject(CodeInvalidPayload), nil
	}

	if authorization.DeviceID != context.subjectDeviceID() {
		return context.reject(CodeCredentialSubjectMismatch), nil
	}
	member, exists := context.state.devices[authorization.DeviceID]
	if !exists {
		return context.reject(CodeCredentialSubjectNotFound), nil
	}
	if member.Status != device.StatusActive {
		return context.reject(CodeCredentialSubjectNotActive), nil
	}
	counter, exists := context.state.auditCounters[authorization.DeviceID]
	if !exists || counter.DeviceID != authorization.DeviceID {
		return Outcome{}, invalidState(
			"credential subject %q has no audit counter",
			authorization.DeviceID,
		)
	}
	if counter.CredentialEpoch == domain.MaxSafeInteger {
		return context.reject(CodeCredentialEpochExhausted), nil
	}
	expectedEpoch := counter.CredentialEpoch + 1
	if authorization.Epoch != expectedEpoch {
		return context.reject(CodeCredentialEpochMismatch), nil
	}
	if sha256.Sum256(authorization.EpochPublicKey[:]) != authorization.KeyDigest {
		return context.reject(CodeCredentialKeyDigestMismatch), nil
	}
	if !verifyCredentialBinding(authorization, member.IdentityPublicKey) {
		return context.reject(CodeInvalidCredentialBinding), nil
	}
	if _, reused := context.state.credentialKeys[authorization.KeyDigest]; reused {
		return context.reject(CodeCredentialKeyReused), nil
	}
	if device.Role(authorization.Role) != member.Role {
		return context.reject(CodeCredentialRoleMismatch), nil
	}

	authority := context.state.credentialAuthority
	if authorization.AuthorityVoterSetVersion !=
		authority.VoterSetVersion {
		return context.reject(CodeCredentialAuthorityVersionMismatch), nil
	}
	if err := validateCredentialEndorsements(
		context.state,
		authorization,
	); err != nil {
		if errors.Is(err, errCredentialEndorsementQuorum) {
			return context.reject(
				CodeCredentialEndorsementQuorumNotMet,
			), nil
		}
		return context.reject(CodeInvalidCredentialEndorsements), nil
	}
	if authorization.ValiditySeconds !=
		credentialauthorization.ValiditySeconds {
		return context.reject(CodeCredentialValidityMismatch), nil
	}

	var previous *credentialauthorization.Authorization
	if counter.CredentialEpoch != 0 {
		key := credentialauthorization.Key{
			SessionID: context.state.sessionID,
			DeviceID:  authorization.DeviceID,
			Epoch:     counter.CredentialEpoch,
		}
		value, found := context.state.credentialAuthorizations[key]
		if !found {
			return Outcome{}, invalidState(
				"credential subject %q lacks prior epoch %d",
				authorization.DeviceID,
				counter.CredentialEpoch,
			)
		}
		value = value.Clone()
		previous = &value
	}
	if err := credentialauthorization.ValidateTransition(
		previous,
		authorization,
	); err != nil {
		switch {
		case errors.Is(
			err,
			credentialauthorization.ErrIssuedAtBelowRenewalFloor,
		):
			return context.reject(CodeCredentialRenewalTooEarly), nil
		case errors.Is(
			err,
			credentialauthorization.ErrNotBeforeClampMismatch,
		), errors.Is(
			err,
			credentialauthorization.ErrNotBeforePrecedesIssuedAt,
		):
			return context.reject(CodeCredentialNotBeforeMismatch), nil
		default:
			return context.reject(CodeInvalidPayload), nil
		}
	}

	nextCounter := auditcounter.Counter{
		DeviceID:        authorization.DeviceID,
		CredentialEpoch: authorization.Epoch,
		AcceptedCount:   0,
	}
	return context.acceptCredential(authorization, nextCounter)
}

var errCredentialEndorsementQuorum = errors.New(
	"credential endorsement quorum not met",
)

func validateCredentialEndorsements(
	state State,
	authorization credentialauthorization.Authorization,
) error {
	endorsements := authorization.ClockEndorsements
	if len(endorsements) < 1 ||
		len(endorsements) > credentialauthorization.MaxEndorsements {
		return credentialauthorization.ErrInvalidEndorsementCount
	}
	var previous domain.DeviceID
	preimage, err := credentialauthorization.CanonicalEndorsementPreimage(
		authorization,
	)
	if err != nil {
		return err
	}
	for index, endorsement := range endorsements {
		if !endorsement.DeviceID.Valid() ||
			index > 0 && previous >= endorsement.DeviceID {
			return credentialauthorization.ErrEndorsementsNotSorted
		}
		previous = endorsement.DeviceID
		member, exists := state.devices[endorsement.DeviceID]
		if !exists ||
			member.Status != device.StatusActive ||
			!state.credentialAuthority.Contains(endorsement.DeviceID) {
			return credentialauthorization.ErrInvalidEndorser
		}
		if !verifyLabeledSignature(
			member.IdentityPublicKey,
			codec.SignatureCredentialTimeEndorsement,
			preimage,
			endorsement.Signature[:],
		) {
			return credentialauthorization.ErrInvalidEndorser
		}
	}
	required := len(state.credentialAuthority.VoterDeviceIDs)/2 + 1
	if len(endorsements) < required {
		return errCredentialEndorsementQuorum
	}
	return nil
}

func (context reductionContext) acceptCredential(
	authorization credentialauthorization.Authorization,
	counter auditcounter.Counter,
) (Outcome, error) {
	if err := authorization.Validate(); err != nil {
		return Outcome{}, invalidState(
			"reducer produced invalid credential authorization: %v",
			err,
		)
	}
	if err := counter.Validate(); err != nil {
		return Outcome{}, invalidState(
			"reducer produced invalid audit counter: %v",
			err,
		)
	}
	return Outcome{
		Status: StatusAccepted,
		Code:   CodeAccepted,
		Changes: Changes{
			OriginScopes:  []OriginScope{context.scope},
			AuditCounters: []auditcounter.Counter{counter},
			CredentialAuthorizations: []credentialauthorization.Authorization{
				authorization.Clone(),
			},
		},
	}, nil
}
