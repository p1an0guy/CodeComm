package consensus

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"reflect"
	"sort"
	"sync"
	"time"

	"github.com/ijonahch/codecomm/internal/codec"
	"github.com/ijonahch/codecomm/internal/credential"
	codecommcrypto "github.com/ijonahch/codecomm/internal/crypto"
	"github.com/ijonahch/codecomm/internal/domain"
	"github.com/ijonahch/codecomm/internal/domain/credentialauthorization"
	"github.com/ijonahch/codecomm/internal/domain/device"
	"github.com/ijonahch/codecomm/internal/reducer"
	"github.com/ijonahch/codecomm/internal/store"
)

const credentialAuthorizationCollectionTimeout = 5 * time.Second

var (
	ErrCredentialAuthorizationOriginUnavailable = errors.New(
		"consensus: durable credential authorization origin unavailable",
	)
	ErrCredentialAuthorizationUnavailable = errors.New(
		"consensus: credential authorization unavailable",
	)
	ErrCredentialAuthorizationRejected = errors.New(
		"consensus: credential authorization command rejected",
	)
	ErrInvalidCredentialBinding = errors.New(
		"consensus: invalid credential binding",
	)
	ErrCredentialRenewalTooEarly = errors.New(
		"consensus: credential renewal is too early",
	)
)

// CredentialAuthorizationOrigin durably submits one complete authorization.
// It shares the checkpoint origin's boot-scoped identity and outbox.
type CredentialAuthorizationOrigin interface {
	DeviceID() domain.DeviceID
	BootID() domain.UUIDv7
	SubmitCredentialAuthorization(
		context.Context,
		credentialauthorization.Authorization,
	) (store.CommandOutcome, error)
}

type credentialAuthorizationCut struct {
	leadership        raftLeadershipEpoch
	sessionID         domain.UUIDv7
	workspaceID       domain.UUIDv4
	recovery          uint64
	heads             store.ApplyHeads
	projectionDigest  store.Digest
	admissionRevision uint64
	state             decodedState
	subject           device.Device
	previous          *credentialauthorization.Authorization
	authorityIDs      []domain.DeviceID
	authorityKeys     map[domain.DeviceID]ed25519.PublicKey
}

type credentialEndorsementResult struct {
	endorsement credentialauthorization.ClockEndorsement
	err         error
}

// AuthorizeCredential constructs and commits one content-credential epoch.
// Only the applied Raft leader may collect authority clock endorsements.
func (node *SingleNode) AuthorizeCredential(
	ctx context.Context,
	binding credential.Binding,
) (
	credentialauthorization.Authorization,
	store.CommandOutcome,
	error,
) {
	if node == nil || node.raft == nil || node.state == nil || ctx == nil {
		return credentialauthorization.Authorization{},
			store.CommandOutcome{},
			ErrInvalidNodeOptions
	}
	if err := ctx.Err(); err != nil {
		return credentialauthorization.Authorization{},
			store.CommandOutcome{},
			err
	}
	if err := node.beginOperation(); err != nil {
		return credentialauthorization.Authorization{},
			store.CommandOutcome{},
			err
	}
	defer node.endOperation()
	if err := node.FatalError(); err != nil {
		return credentialauthorization.Authorization{},
			store.CommandOutcome{},
			err
	}
	origin := node.credentialAuthorizationOrigin
	if origin == nil {
		return credentialauthorization.Authorization{},
			store.CommandOutcome{},
			ErrCredentialAuthorizationOriginUnavailable
	}

	operationContext, cancel, wait := node.operationContext(ctx)
	defer func() {
		cancel()
		wait()
	}()
	ctx = operationContext

	leadership, err := node.readConfigurationLeadershipEpoch()
	if err != nil {
		return credentialauthorization.Authorization{},
			store.CommandOutcome{},
			err
	}
	cut, err := node.captureCredentialAuthorizationCut(
		ctx,
		leadership,
		binding,
	)
	if err != nil {
		return credentialauthorization.Authorization{},
			store.CommandOutcome{},
			err
	}
	issuedAt, issuedTime, err := node.credentialAuthorizationTime()
	if err != nil {
		return credentialauthorization.Authorization{},
			store.CommandOutcome{},
			err
	}
	authorization, err := buildCredentialAuthorization(
		binding,
		cut,
		issuedAt,
	)
	if err != nil {
		return credentialauthorization.Authorization{},
			store.CommandOutcome{},
			err
	}
	endorsements, err := node.collectCredentialEndorsements(
		ctx,
		leadership,
		cut,
		authorization,
	)
	if err != nil {
		return credentialauthorization.Authorization{},
			store.CommandOutcome{},
			err
	}
	authorization.ClockEndorsements = endorsements
	validationAuthorization := authorization.Clone()
	validationAuthorization.AuthorizationChainIndex = 1
	if err := validationAuthorization.Validate(); err != nil {
		return credentialauthorization.Authorization{},
			store.CommandOutcome{},
			node.haltNode(fmt.Errorf(
				"%w: constructed authorization: %v",
				ErrCredentialAuthorizationRejected,
				err,
			))
	}
	if err := node.requireCredentialAuthorizationCut(
		ctx,
		cut,
		binding,
		issuedTime,
	); err != nil {
		return credentialauthorization.Authorization{},
			store.CommandOutcome{},
			err
	}

	outcome, err := node.submitCredentialAuthorizationAtLeadership(
		ctx,
		leadership,
		origin,
		authorization,
	)
	if err != nil {
		return credentialauthorization.Authorization{},
			store.CommandOutcome{},
			err
	}
	switch outcome.Status {
	case store.OutcomeAccepted:
		if outcome.Code != string(reducer.CodeAccepted) {
			return credentialauthorization.Authorization{},
				store.CommandOutcome{},
				node.haltNode(fmt.Errorf(
					"%w: accepted outcome code %q",
					ErrCredentialAuthorizationRejected,
					outcome.Code,
				))
		}
		return authorization.Clone(), outcome, nil
	case store.OutcomeRejected:
		if cutErr := node.requireCredentialAuthorizationSemanticCut(
			ctx,
			cut,
			binding,
			issuedTime,
		); cutErr != nil {
			return credentialauthorization.Authorization{},
				store.CommandOutcome{},
				cutErr
		}
		return credentialauthorization.Authorization{},
			store.CommandOutcome{},
			node.haltNode(fmt.Errorf(
				"%w: unchanged authorization cut rejected with %s",
				ErrCredentialAuthorizationRejected,
				outcome.Code,
			))
	default:
		return credentialauthorization.Authorization{},
			store.CommandOutcome{},
			node.haltNode(ErrCredentialAuthorizationRejected)
	}
}

func (node *SingleNode) captureCredentialAuthorizationCut(
	ctx context.Context,
	leadership raftLeadershipEpoch,
	binding credential.Binding,
) (credentialAuthorizationCut, error) {
	if err := node.requireConfigurationLeadershipEpoch(leadership); err != nil {
		return credentialAuthorizationCut{}, err
	}
	view, err := node.state.View(ctx)
	if err != nil {
		return credentialAuthorizationCut{}, err
	}
	state, err := decodeStateView(view)
	if err != nil {
		return credentialAuthorizationCut{}, err
	}
	if binding.SessionID != view.SessionID ||
		binding.DeviceID == "" ||
		binding.Epoch == 0 {
		return credentialAuthorizationCut{}, ErrInvalidCredentialBinding
	}
	member, exists := state.Admission.Member(binding.DeviceID)
	identityKey, keyExists := state.IdentityPublicKey(binding.DeviceID)
	if !exists ||
		member.Status != device.StatusActive ||
		!keyExists ||
		!bytes.Equal(member.IdentityPublicKey, identityKey) ||
		binding.Validate(identityKey) != nil {
		return credentialAuthorizationCut{}, ErrInvalidCredentialBinding
	}
	currentEpoch, exists := state.Admission.CurrentCredentialEpoch(
		binding.DeviceID,
	)
	if !exists ||
		currentEpoch == domain.MaxSafeInteger ||
		binding.Epoch != currentEpoch+1 {
		return credentialAuthorizationCut{}, ErrInvalidCredentialBinding
	}
	var previous *credentialauthorization.Authorization
	if currentEpoch != 0 {
		value, found := state.Admission.Authorization(
			credentialauthorization.Key{
				SessionID: view.SessionID,
				DeviceID:  binding.DeviceID,
				Epoch:     currentEpoch,
			},
		)
		if !found {
			return credentialAuthorizationCut{},
				ErrInvalidCredentialBinding
		}
		previous = &value
	}
	authority := state.CredentialAuthority
	if authority.Validate() != nil ||
		authority.SessionID != view.SessionID {
		return credentialAuthorizationCut{},
			ErrCredentialAuthorizationUnavailable
	}
	authorityIDs := authority.VoterIDs()
	authorityKeys := make(
		map[domain.DeviceID]ed25519.PublicKey,
		len(authorityIDs),
	)
	for _, authorityID := range authorityIDs {
		authorityMember, found := state.Admission.Member(authorityID)
		authorityKey, foundKey := state.IdentityPublicKey(authorityID)
		if !found ||
			authorityMember.Status != device.StatusActive ||
			!foundKey ||
			!bytes.Equal(
				authorityMember.IdentityPublicKey,
				authorityKey,
			) {
			return credentialAuthorizationCut{},
				ErrCredentialAuthorizationUnavailable
		}
		authorityKeys[authorityID] = bytes.Clone(authorityKey)
	}
	if err := node.requireConfigurationLeadershipEpoch(leadership); err != nil {
		return credentialAuthorizationCut{}, err
	}
	return credentialAuthorizationCut{
		leadership:        leadership,
		sessionID:         view.SessionID,
		workspaceID:       view.WorkspaceID,
		recovery:          view.RecoveryGeneration,
		heads:             view.Heads,
		projectionDigest:  view.ProjectionStateDigest,
		admissionRevision: view.AdmissionRevision,
		state:             state,
		subject:           member,
		previous:          previous,
		authorityIDs:      authorityIDs,
		authorityKeys:     authorityKeys,
	}, nil
}

func (node *SingleNode) credentialAuthorizationTime() (
	domain.WholeSecondTimestamp,
	time.Time,
	error,
) {
	if node == nil || node.credentialEndorsementNow == nil {
		return "", time.Time{}, ErrCredentialAuthorizationUnavailable
	}
	now := node.credentialEndorsementNow()
	if now.IsZero() {
		return "", time.Time{}, ErrCredentialAuthorizationUnavailable
	}
	whole := now.UTC().Truncate(time.Second)
	issuedAt := domain.WholeSecondTimestamp(whole.Format(time.RFC3339))
	if !issuedAt.Valid() {
		return "", time.Time{}, ErrCredentialAuthorizationUnavailable
	}
	return issuedAt, whole, nil
}

func buildCredentialAuthorization(
	binding credential.Binding,
	cut credentialAuthorizationCut,
	issuedAt domain.WholeSecondTimestamp,
) (credentialauthorization.Authorization, error) {
	issuedTime, err := issuedAt.Time()
	if err != nil {
		return credentialauthorization.Authorization{},
			ErrCredentialAuthorizationUnavailable
	}
	notBefore := issuedTime
	if cut.previous != nil {
		priorNotBefore, priorErr := cut.previous.NotBefore.Time()
		if priorErr != nil {
			return credentialauthorization.Authorization{},
				ErrCredentialAuthorizationUnavailable
		}
		renewalFloor := priorNotBefore.Add(
			time.Duration(
				credentialauthorization.ValiditySeconds-
					credentialauthorization.RenewalLeadSeconds,
			) * time.Second,
		)
		if issuedTime.Before(renewalFloor) {
			return credentialauthorization.Authorization{},
				ErrCredentialRenewalTooEarly
		}
		overlapFloor := priorNotBefore.Add(
			time.Duration(
				credentialauthorization.ValiditySeconds-
					credentialauthorization.OverlapSeconds,
			) * time.Second,
		)
		if overlapFloor.After(notBefore) {
			notBefore = overlapFloor
		}
	}
	authorization := credentialauthorization.Authorization{
		SessionID:      binding.SessionID,
		DeviceID:       binding.DeviceID,
		Epoch:          binding.Epoch,
		EpochPublicKey: binding.EpochPublicKey,
		KeyDigest:      binding.KeyDigest,
		Role:           credentialauthorization.Role(cut.subject.Role),
		IssuedAt:       issuedAt,
		NotBefore: domain.WholeSecondTimestamp(
			notBefore.UTC().Format(time.RFC3339),
		),
		ValiditySeconds: credentialauthorization.ValiditySeconds,
		AuthorityVoterSetVersion: cut.state.CredentialAuthority.
			VoterSetVersion,
		BindingSignature: binding.Signature,
	}
	return authorization, nil
}

func (node *SingleNode) collectCredentialEndorsements(
	ctx context.Context,
	leadership raftLeadershipEpoch,
	cut credentialAuthorizationCut,
	authorization credentialauthorization.Authorization,
) ([]credentialauthorization.ClockEndorsement, error) {
	required := len(cut.authorityIDs)/2 + 1
	if required < 1 || len(cut.authorityIDs) > credentialauthorization.MaxEndorsements {
		return nil, ErrCredentialAuthorizationUnavailable
	}
	requester, _ := node.transport.(credentialEndorsementRequester)
	collectionContext, cancel := context.WithTimeout(
		ctx,
		credentialAuthorizationCollectionTimeout,
	)
	defer cancel()
	results := make(
		chan credentialEndorsementResult,
		len(cut.authorityIDs),
	)
	var workers sync.WaitGroup
	for _, authorityID := range cut.authorityIDs {
		authorityID := authorityID
		publicKey := bytes.Clone(cut.authorityKeys[authorityID])
		workers.Add(1)
		go func() {
			defer workers.Done()
			endorsement, err := node.collectCredentialEndorsement(
				collectionContext,
				leadership,
				requester,
				authorityID,
				publicKey,
				authorization,
			)
			results <- credentialEndorsementResult{
				endorsement: endorsement,
				err:         err,
			}
		}()
	}

	endorsements := make(
		[]credentialauthorization.ClockEndorsement,
		0,
		required,
	)
	remaining := len(cut.authorityIDs)
	for remaining > 0 && len(endorsements) < required {
		select {
		case <-collectionContext.Done():
			remaining = 0
		case result := <-results:
			remaining--
			if result.err == nil {
				endorsements = append(
					endorsements,
					result.endorsement,
				)
			}
			if len(endorsements)+remaining < required {
				remaining = 0
			}
		}
	}
	cancel()
	workers.Wait()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if len(endorsements) < required {
		return nil, ErrCredentialAuthorizationUnavailable
	}
	sort.Slice(endorsements, func(left, right int) bool {
		return endorsements[left].DeviceID <
			endorsements[right].DeviceID
	})
	for index := 1; index < len(endorsements); index++ {
		if endorsements[index-1].DeviceID >= endorsements[index].DeviceID {
			return nil, ErrCredentialAuthorizationUnavailable
		}
	}
	return endorsements, nil
}

func (node *SingleNode) collectCredentialEndorsement(
	ctx context.Context,
	leadership raftLeadershipEpoch,
	requester credentialEndorsementRequester,
	authorityID domain.DeviceID,
	publicKey ed25519.PublicKey,
	authorization credentialauthorization.Authorization,
) (credentialauthorization.ClockEndorsement, error) {
	if authorityID != domain.DeviceID(node.serverID) {
		if requester == nil {
			return credentialauthorization.ClockEndorsement{},
				ErrCredentialAuthorizationUnavailable
		}
		proof, err := requestCredentialEndorsement(
			ctx,
			requester,
			authorityID,
			publicKey,
			authorization,
		)
		if err != nil {
			return credentialauthorization.ClockEndorsement{}, err
		}
		if err := node.requireConfigurationLeadershipEpoch(
			leadership,
		); err != nil {
			return credentialauthorization.ClockEndorsement{}, err
		}
		return credentialauthorization.ClockEndorsement{
			DeviceID:  proof.endorserDeviceID,
			Signature: proof.signature,
		}, nil
	}
	signer := node.credentialEndorsementSigner
	if signer == nil || signer.DeviceID() != authorityID {
		return credentialauthorization.ClockEndorsement{},
			ErrCredentialAuthorizationUnavailable
	}
	signature, err := signer.SignCredentialEndorsement(ctx, authorization)
	if err != nil {
		return credentialauthorization.ClockEndorsement{},
			ErrCredentialAuthorizationUnavailable
	}
	preimage, err := credentialauthorization.
		CanonicalEndorsementPreimage(authorization)
	if err != nil ||
		codecommcrypto.VerifyEd25519(
			publicKey,
			codec.SignatureCredentialTimeEndorsement,
			preimage,
			signature[:],
		) != nil {
		return credentialauthorization.ClockEndorsement{},
			ErrInvalidCredentialEndorsementSigner
	}
	if err := node.requireConfigurationLeadershipEpoch(leadership); err != nil {
		return credentialauthorization.ClockEndorsement{}, err
	}
	return credentialauthorization.ClockEndorsement{
		DeviceID:  authorityID,
		Signature: signature,
	}, nil
}

func (node *SingleNode) requireCredentialAuthorizationCut(
	ctx context.Context,
	expected credentialAuthorizationCut,
	binding credential.Binding,
	issuedAt time.Time,
) error {
	if err := node.requireConfigurationLeadershipEpoch(
		expected.leadership,
	); err != nil {
		return err
	}
	current, err := node.captureCredentialAuthorizationCut(
		ctx,
		expected.leadership,
		binding,
	)
	if err != nil {
		return err
	}
	if !sameCredentialAuthorizationCut(expected, current) {
		return ErrCredentialAuthorizationUnavailable
	}
	return node.requireCredentialAuthorizationClock(issuedAt)
}

func sameCredentialAuthorizationCut(
	left credentialAuthorizationCut,
	right credentialAuthorizationCut,
) bool {
	return left.heads == right.heads &&
		left.projectionDigest == right.projectionDigest &&
		left.admissionRevision == right.admissionRevision &&
		sameCredentialAuthorizationSemanticCut(left, right)
}

func sameCredentialAuthorizationSemanticCut(
	left credentialAuthorizationCut,
	right credentialAuthorizationCut,
) bool {
	if left.leadership != right.leadership ||
		left.sessionID != right.sessionID ||
		left.workspaceID != right.workspaceID ||
		left.recovery != right.recovery ||
		left.subject.ID != right.subject.ID ||
		left.subject.Role != right.subject.Role ||
		left.subject.Status != right.subject.Status ||
		left.subject.EntityVersion != right.subject.EntityVersion ||
		!bytes.Equal(
			left.subject.IdentityPublicKey,
			right.subject.IdentityPublicKey,
		) ||
		len(left.authorityIDs) != len(right.authorityIDs) {
		return false
	}
	for index, id := range left.authorityIDs {
		if id != right.authorityIDs[index] ||
			!bytes.Equal(left.authorityKeys[id], right.authorityKeys[id]) {
			return false
		}
	}
	switch {
	case left.previous == nil && right.previous == nil:
		return true
	case left.previous == nil || right.previous == nil:
		return false
	default:
		return reflect.DeepEqual(*left.previous, *right.previous)
	}
}

func (node *SingleNode) requireCredentialAuthorizationSemanticCut(
	ctx context.Context,
	expected credentialAuthorizationCut,
	binding credential.Binding,
	issuedAt time.Time,
) error {
	if err := node.requireConfigurationLeadershipEpoch(
		expected.leadership,
	); err != nil {
		return err
	}
	current, err := node.captureCredentialAuthorizationCut(
		ctx,
		expected.leadership,
		binding,
	)
	if err != nil {
		return err
	}
	if !sameCredentialAuthorizationSemanticCut(expected, current) {
		return ErrCredentialAuthorizationUnavailable
	}
	return node.requireCredentialAuthorizationClock(issuedAt)
}

func (node *SingleNode) requireCredentialAuthorizationClock(
	issuedAt time.Time,
) error {
	if node == nil || node.credentialEndorsementNow == nil {
		return ErrCredentialAuthorizationUnavailable
	}
	now := node.credentialEndorsementNow()
	if now.IsZero() ||
		issuedAt.Before(now.Add(-credentialEndorsementClockSkew)) ||
		issuedAt.After(now.Add(credentialEndorsementClockSkew)) {
		return ErrCredentialAuthorizationUnavailable
	}
	return nil
}

func (node *SingleNode) submitCredentialAuthorizationAtLeadership(
	ctx context.Context,
	leadership raftLeadershipEpoch,
	origin CredentialAuthorizationOrigin,
	authorization credentialauthorization.Authorization,
) (store.CommandOutcome, error) {
	attemptContext, cancel := context.WithCancelCause(ctx)
	watchDone := make(chan struct{})
	go func() {
		defer close(watchDone)
		ticker := time.NewTicker(25 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-attemptContext.Done():
				return
			case <-node.closeStarted:
				cancel(ErrNodeClosed)
				return
			case <-node.fatalSet:
				cancel(node.FatalError())
				return
			case <-ticker.C:
				if err := node.requireConfigurationLeadershipEpoch(
					leadership,
				); err != nil {
					cancel(err)
					return
				}
			}
		}
	}()
	outcome, err := origin.SubmitCredentialAuthorization(
		attemptContext,
		authorization,
	)
	cancel(context.Canceled)
	<-watchDone
	if err != nil {
		if cause := context.Cause(attemptContext); cause != nil &&
			!errors.Is(cause, context.Canceled) {
			return store.CommandOutcome{}, cause
		}
		return store.CommandOutcome{}, err
	}
	return outcome, nil
}

func normalizedCredentialAuthorizationOrigin(
	origin CheckpointOrigin,
) CredentialAuthorizationOrigin {
	candidate, ok := origin.(CredentialAuthorizationOrigin)
	if !ok || candidate == nil {
		return nil
	}
	value := reflect.ValueOf(candidate)
	switch value.Kind() {
	case reflect.Chan,
		reflect.Func,
		reflect.Interface,
		reflect.Map,
		reflect.Pointer,
		reflect.Slice:
		if value.IsNil() {
			return nil
		}
	}
	return candidate
}

func validateCredentialAuthorizationOrigin(
	deviceID domain.DeviceID,
	bootID domain.UUIDv7,
	origin CredentialAuthorizationOrigin,
) error {
	if origin == nil {
		return nil
	}
	if origin.DeviceID() != deviceID || origin.BootID() != bootID {
		return fmt.Errorf(
			"%w: credential origin belongs to another daemon",
			ErrInvalidNodeOptions,
		)
	}
	return nil
}
