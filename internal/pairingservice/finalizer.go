package pairingservice

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"errors"
	"fmt"

	"github.com/ijonahch/codecomm/internal/domain"
	"github.com/ijonahch/codecomm/internal/domain/device"
	"github.com/ijonahch/codecomm/internal/event"
	"github.com/ijonahch/codecomm/internal/pairing"
	"github.com/ijonahch/codecomm/internal/store"
)

var (
	ErrInvalidDurableFinalizer = errors.New(
		"pairing service: invalid durable finalizer",
	)
	ErrFinalizationIntegrity = errors.New(
		"pairing service: finalization integrity failure",
	)
)

// FinalizationCommandState reads the exact local command reserved by the
// operator's final SAS confirmation.
type FinalizationCommandState interface {
	LookupRequest(
		context.Context,
		domain.UUIDv7,
		domain.UUIDv7,
	) (store.LocalCommandRecord, bool, error)
	AbandonCommandCollision(
		context.Context,
		store.LocalCommandCollisionInput,
	) (store.LocalCommandRecord, bool, error)
}

// GenerationCoordinator fences committed proposals and other durable pairing
// side effects to one exact active lineage.
type GenerationCoordinator interface {
	ApplyAtGeneration(
		context.Context,
		domain.UUIDv7,
		uint64,
		event.SignedEvent,
	) (store.ApplyResult, error)
	RunAtGeneration(
		context.Context,
		domain.UUIDv7,
		uint64,
		func(context.Context) error,
	) error
}

// RebootstrapDelegate durably installs the retained member's replacement
// local state. It must be idempotent and must not reenter the generation
// coordinator while called. A deterministic refusal wraps
// ErrFinalizationRejected; availability errors remain retryable.
type RebootstrapDelegate interface {
	FinalizeRebootstrap(context.Context, AttemptDetails) error
}

// DurableFinalizerOptions binds admission and rebootstrap to production
// dependencies. Rebootstrap is mandatory even on a daemon currently serving
// only new-member invites; there is no implicit successful implementation.
type DurableFinalizerOptions struct {
	State             FinalizationCommandState
	Consensus         GenerationCoordinator
	Rebootstrap       RebootstrapDelegate
	IdentityPublicKey []byte
}

// DurableFinalizer executes the exact operation authorized by two-sided SAS.
type DurableFinalizer struct {
	state       FinalizationCommandState
	consensus   GenerationCoordinator
	rebootstrap RebootstrapDelegate
	publicKey   ed25519.PublicKey
	deviceID    domain.DeviceID
}

// NewDurableFinalizer validates the local installation identity and all
// mode-specific production dependencies.
func NewDurableFinalizer(
	options DurableFinalizerOptions,
) (*DurableFinalizer, error) {
	if options.State == nil ||
		options.Consensus == nil ||
		options.Rebootstrap == nil ||
		len(options.IdentityPublicKey) != ed25519.PublicKeySize {
		return nil, ErrInvalidDurableFinalizer
	}
	deviceID, err := device.DeriveID(options.IdentityPublicKey)
	if err != nil {
		return nil, ErrInvalidDurableFinalizer
	}
	return &DurableFinalizer{
		state:       options.State,
		consensus:   options.Consensus,
		rebootstrap: options.Rebootstrap,
		publicKey:   append(ed25519.PublicKey(nil), options.IdentityPublicKey...),
		deviceID:    deviceID,
	}, nil
}

// FinalizePairing commits admission/readmission or delegates generation-fenced
// rebootstrap installation. The operation is safe to repeat after any crash.
func (finalizer *DurableFinalizer) FinalizePairing(
	ctx context.Context,
	details AttemptDetails,
) error {
	if finalizer == nil ||
		finalizer.state == nil ||
		finalizer.consensus == nil ||
		finalizer.rebootstrap == nil ||
		ctx == nil {
		return ErrInvalidDurableFinalizer
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := finalizer.validateDetails(details); err != nil {
		return err
	}
	switch details.Invite.Mode {
	case pairing.ModeRebootstrap:
		return finalizer.consensus.RunAtGeneration(
			ctx,
			details.Invite.SessionID,
			details.Invite.RecoveryGeneration,
			func(ctx context.Context) error {
				return finalizer.rebootstrap.FinalizeRebootstrap(ctx, details)
			},
		)
	case pairing.ModeNew, pairing.ModeReadmission:
		return finalizer.finalizeAdmission(ctx, details)
	default:
		return integrityFinalization("unsupported pairing mode")
	}
}

func (finalizer *DurableFinalizer) finalizeAdmission(
	ctx context.Context,
	details AttemptDetails,
) error {
	var (
		record        store.LocalCommandRecord
		signed        event.SignedEvent
		applyRequired bool
	)
	err := finalizer.consensus.RunAtGeneration(
		ctx,
		details.Invite.SessionID,
		details.Invite.RecoveryGeneration,
		func(operationContext context.Context) error {
			loaded, found, err := finalizer.state.LookupRequest(
				operationContext,
				details.Attempt.AttemptID,
				details.Attempt.AttemptID,
			)
			if err != nil {
				return finalizationStateError(
					"load reserved admission",
					err,
				)
			}
			if !found {
				return integrityFinalization(
					"reserved admission is absent",
				)
			}
			record = loaded
			if err := finalizer.validateCommandRecord(
				record,
				details,
			); err != nil {
				return err
			}
			if record.State == store.LocalRequestResolved {
				return classifyFinalizationOutcome(record.Outcome)
			}
			if record.State == store.LocalRequestAbandoned {
				return integrityFinalization(
					"admission event ID collision poisoned the operator origin",
				)
			}
			if record.State != store.LocalRequestSigned &&
				record.State != store.LocalRequestPending {
				return integrityFinalization(
					"reserved admission is no longer committable",
				)
			}

			parsed, err := event.ParseAndVerify(
				record.SignedProposal,
				event.VerificationContext{
					SessionID:         details.Invite.SessionID,
					WorkspaceID:       details.Invite.WorkspaceID,
					IdentityPublicKey: finalizer.publicKey,
				},
			)
			if err != nil {
				return integrityFinalization(
					"reserved admission signature is invalid",
				)
			}
			if err := finalizer.validateSignedAdmission(
				parsed,
				record,
				details,
			); err != nil {
				return err
			}
			signed = parsed
			applyRequired = true
			return nil
		},
	)
	if err != nil {
		return err
	}
	if !applyRequired {
		return nil
	}
	result, err := finalizer.consensus.ApplyAtGeneration(
		ctx,
		details.Invite.SessionID,
		details.Invite.RecoveryGeneration,
		signed,
	)
	if err != nil {
		if errors.Is(err, store.ErrIdempotencyConflict) {
			collision, _, abandonErr :=
				finalizer.state.AbandonCommandCollision(
					ctx,
					store.LocalCommandCollisionInput{
						ClientInstanceID:   record.ClientInstanceID,
						RequestID:          record.RequestID,
						SessionID:          record.SessionID,
						RecoveryGeneration: record.RecoveryGeneration,
						EventID:            record.EventID,
						ProposalDigest:     record.ProposalDigest,
					},
				)
			if abandonErr != nil {
				return finalizationStateError(
					"abandon colliding admission",
					abandonErr,
				)
			}
			if collision.State == store.LocalRequestResolved {
				return classifyFinalizationOutcome(collision.Outcome)
			}
			if collision.State != store.LocalRequestAbandoned ||
				collision.TerminalCode !=
					store.LocalEventIDCollisionCode {
				return integrityFinalization(
					"colliding admission was not durably abandoned",
				)
			}
			return integrityFinalization(
				"admission event ID collision poisoned the operator origin",
			)
		}
		return err
	}
	return classifyFinalizationOutcome(&result.Outcome)
}

func (finalizer *DurableFinalizer) validateDetails(
	details AttemptDetails,
) error {
	invite := details.Invite
	attempt := details.Attempt
	core := details.Core
	if invite.IssuerDeviceID != finalizer.deviceID ||
		!invite.SessionID.Valid() ||
		!invite.WorkspaceID.Valid() ||
		!domain.ValidUnsignedInteger(invite.RecoveryGeneration) ||
		attempt.State != store.PairingAttemptFinalizing ||
		!attempt.AttemptID.Valid() ||
		attempt.InviteID != invite.InviteID ||
		!attempt.LocalConfirmed ||
		!attempt.RemoteConfirmed ||
		attempt.JoinerDeviceID != core.JoinerDeviceID ||
		core.AttemptID != attempt.AttemptID ||
		core.InitialEpochBinding.SessionID != invite.SessionID ||
		core.InitialEpochBinding.DeviceID != core.JoinerDeviceID ||
		core.InitialEpochBinding.Epoch != invite.InitialCredentialEpoch {
		return integrityFinalization("pairing authorization changed")
	}
	if err := core.InitialEpochBinding.Validate(
		core.JoinerIdentityPublicKey[:],
	); err != nil {
		return integrityFinalization("joiner credential binding changed")
	}
	switch invite.Mode {
	case pairing.ModeNew:
		if invite.SubjectDeviceID != nil ||
			invite.ExpectedEntityVersion != nil {
			return integrityFinalization(
				"new-member authorization changed",
			)
		}
	case pairing.ModeRebootstrap:
		if invite.SubjectDeviceID == nil ||
			*invite.SubjectDeviceID != core.JoinerDeviceID ||
			invite.ExpectedEntityVersion != nil {
			return integrityFinalization(
				"rebootstrap authorization changed",
			)
		}
	case pairing.ModeReadmission:
		if invite.SubjectDeviceID == nil ||
			*invite.SubjectDeviceID != core.JoinerDeviceID ||
			invite.ExpectedEntityVersion == nil {
			return integrityFinalization(
				"readmission authorization changed",
			)
		}
	default:
		return integrityFinalization("unsupported pairing mode")
	}
	return nil
}

func (finalizer *DurableFinalizer) validateCommandRecord(
	record store.LocalCommandRecord,
	details AttemptDetails,
) error {
	request, err := finalizationCanonicalRequest(details)
	if err != nil {
		return integrityFinalization(
			"operator request cannot be reconstructed",
		)
	}
	requestDigest := store.Digest(sha256.Sum256(request))
	if record.ClientInstanceID != details.Attempt.AttemptID ||
		record.RequestID != details.Attempt.AttemptID ||
		record.SessionID != details.Invite.SessionID ||
		record.WorkspaceID != details.Invite.WorkspaceID ||
		record.RecoveryGeneration != details.Invite.RecoveryGeneration ||
		record.BindingClass != store.LocalBindingOperator ||
		record.OriginDeviceID != details.Invite.IssuerDeviceID ||
		record.OriginScopeKind != store.OriginScopeKindBoot ||
		!record.OriginScopeID.Valid() ||
		record.RequestDigest != requestDigest ||
		record.RequestKind != event.KindMembershipDeviceAdmitted ||
		record.CreatedAt != details.Attempt.LocalConfirmedAt {
		return integrityFinalization(
			"reserved admission authority changed",
		)
	}
	switch record.State {
	case store.LocalRequestSigned, store.LocalRequestPending:
		if record.Outcome != nil ||
			len(record.SignedProposal) == 0 ||
			record.OriginSequence < 1 ||
			store.Digest(sha256.Sum256(record.SignedProposal)) !=
				record.ProposalDigest {
			return integrityFinalization(
				"reserved admission command changed",
			)
		}
	case store.LocalRequestResolved:
		if record.Outcome == nil ||
			len(record.SignedProposal) != 0 ||
			record.TerminalCode != record.Outcome.Code {
			return integrityFinalization(
				"resolved admission result changed",
			)
		}
	case store.LocalRequestAbandoned:
		if len(record.SignedProposal) != 0 ||
			record.Outcome != nil ||
			record.TerminalCode != store.LocalEventIDCollisionCode {
			return integrityFinalization(
				"abandoned admission result changed",
			)
		}
	default:
		return integrityFinalization("reserved admission state changed")
	}
	return nil
}

func (finalizer *DurableFinalizer) validateSignedAdmission(
	signed event.SignedEvent,
	record store.LocalCommandRecord,
	details AttemptDetails,
) error {
	proposal := signed.Proposal()
	payload, err := admissionPayload(details)
	if err != nil {
		return integrityFinalization(
			"admission payload cannot be reconstructed",
		)
	}
	if err := proposal.ValidateForEmission(); err != nil ||
		proposal.EventID != record.EventID ||
		proposal.SessionID != record.SessionID ||
		proposal.WorkspaceID != record.WorkspaceID ||
		proposal.CreatedAt != record.CreatedAt ||
		proposal.Kind != record.RequestKind ||
		proposal.Origin.DeviceID() != record.OriginDeviceID ||
		proposal.Origin.ActorType() != event.ActorHuman ||
		proposal.Origin.OriginBootID() != record.OriginScopeID ||
		proposal.Origin.AgentSessionID() != "" ||
		proposal.Origin.Sequence() != record.OriginSequence ||
		proposal.RationaleSummary != "" ||
		len(proposal.Actions) != 0 ||
		!proposalEntityIs(proposal, details.Core.JoinerDeviceID) ||
		!sameVersion(
			proposal.ExpectedEntityVersion,
			details.Invite.ExpectedEntityVersion,
		) ||
		!bytes.Equal(proposal.Payload, payload) ||
		proposal.Redaction.Policy != event.RedactionDefault ||
		proposal.Redaction.FieldsRemoved == nil ||
		len(proposal.Redaction.FieldsRemoved) != 0 {
		return integrityFinalization(
			"reserved admission command changed",
		)
	}
	return nil
}

func proposalEntityIs(
	proposal event.Proposal,
	deviceID domain.DeviceID,
) bool {
	entityID, present := proposal.EntityID.Value()
	return present && entityID == string(deviceID)
}

func sameVersion(left, right *uint64) bool {
	if left == nil || right == nil {
		return left == nil && right == nil
	}
	return *left == *right
}

func classifyFinalizationOutcome(outcome *store.CommandOutcome) error {
	if outcome == nil {
		return integrityFinalization(
			"admission returned no durable outcome",
		)
	}
	switch outcome.Status {
	case store.OutcomeAccepted:
		return nil
	case store.OutcomeRejected:
		return fmt.Errorf(
			"%w: admission rejected with code %s",
			ErrFinalizationRejected,
			outcome.Code,
		)
	default:
		return integrityFinalization(
			fmt.Sprintf(
				"admission returned status %q",
				outcome.Status,
			),
		)
	}
}

func finalizationStateError(operation string, err error) error {
	if errors.Is(err, store.ErrLocalStateIntegrity) ||
		errors.Is(err, store.ErrIntegrityCheck) ||
		errors.Is(err, store.ErrCorrupt) ||
		errors.Is(err, store.ErrCommandResultCorrupt) {
		return fmt.Errorf(
			"%w: %s: %w",
			ErrFinalizationIntegrity,
			operation,
			err,
		)
	}
	return fmt.Errorf("pairing service: %s: %w", operation, err)
}

func integrityFinalization(reason string) error {
	return fmt.Errorf("%w: %s", ErrFinalizationIntegrity, reason)
}
