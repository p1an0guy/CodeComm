package peerauth

import (
	"bytes"
	"slices"
	"sync"
	"time"

	"github.com/ijonahch/codecomm/internal/codec"
	"github.com/ijonahch/codecomm/internal/credential"
	codecommcrypto "github.com/ijonahch/codecomm/internal/crypto"
	"github.com/ijonahch/codecomm/internal/domain"
	"github.com/ijonahch/codecomm/internal/domain/credentialauthority"
	"github.com/ijonahch/codecomm/internal/domain/credentialauthorization"
	"github.com/ijonahch/codecomm/internal/domain/device"
	"github.com/ijonahch/codecomm/internal/event"
	"github.com/ijonahch/codecomm/internal/transport"
	"github.com/ijonahch/codecomm/internal/voteractivation"
)

// ProvisionalAuthorizations retains at most one locally-unapplied later
// authorization per active peer.
type ProvisionalAuthorizations struct {
	mu     sync.Mutex
	byPeer map[domain.DeviceID]provisionalAuthorizationEntry
}

type provisionalAuthorizationEntry struct {
	authorization credentialauthorization.Authorization
	workspaceID   domain.UUIDv4
	authority     *credentialauthority.Authority
}

// NewProvisionalAuthorizations creates an empty bounded overlay.
func NewProvisionalAuthorizations() *ProvisionalAuthorizations {
	return &ProvisionalAuthorizations{
		byPeer: make(
			map[domain.DeviceID]provisionalAuthorizationEntry,
		),
	}
}

// InstallProvisionalAuthorization validates one identity-bound later epoch
// against the current applied membership before making it available to
// content-certificate admission.
func (verifiers *Verifiers) InstallProvisionalAuthorization(
	peerID domain.DeviceID,
	authorization credentialauthorization.Authorization,
) error {
	return verifiers.installProvisionalAuthorization(
		peerID,
		authorization,
		"",
		nil,
	)
}

// InstallProvisionalAuthorizationAfterHandoff admits one later peer
// credential only after verifying an immediate authority activation from the
// caller's applied authority. It remains outbound-only and is pruned once the
// local applied state no longer supports that exact bridge.
func (verifiers *Verifiers) InstallProvisionalAuthorizationAfterHandoff(
	peerID domain.DeviceID,
	workspaceID domain.UUIDv4,
	authorization credentialauthorization.Authorization,
	authority credentialauthority.Authority,
) error {
	if !workspaceID.Valid() {
		return ErrInvalidProvisionalAuthorization
	}
	authority = authority.Clone()
	return verifiers.installProvisionalAuthorization(
		peerID,
		authorization,
		workspaceID,
		&authority,
	)
}

func (verifiers *Verifiers) installProvisionalAuthorization(
	peerID domain.DeviceID,
	authorization credentialauthorization.Authorization,
	workspaceID domain.UUIDv4,
	authority *credentialauthority.Authority,
) error {
	if verifiers == nil ||
		verifiers.provisional == nil ||
		!peerID.Valid() {
		return ErrInvalidProvisionalAuthorization
	}
	snapshot, err := verifiers.current()
	if err != nil {
		return err
	}
	now := verifiers.now()
	if now.IsZero() {
		return ErrAdmissionClock
	}
	applied, appliedActive := snapshot.ActiveCredentialAuthorizationAt(
		peerID,
		now,
	)
	if appliedActive &&
		sameProvisionalAuthorization(applied, authorization) {
		verifiers.provisional.prune(snapshot, now)
		return nil
	}
	if !validProvisionalAuthorization(
		snapshot,
		peerID,
		authorization,
		now,
		workspaceID,
		authority,
	) {
		return ErrInvalidProvisionalAuthorization
	}

	verifiers.provisional.mu.Lock()
	defer verifiers.provisional.mu.Unlock()
	verifiers.provisional.pruneLocked(snapshot, now)
	if verifiers.provisional.byPeer == nil {
		verifiers.provisional.byPeer = make(
			map[domain.DeviceID]provisionalAuthorizationEntry,
		)
	}
	if current, exists := verifiers.provisional.byPeer[peerID]; exists &&
		current.authorization.Epoch > authorization.Epoch {
		return ErrInvalidProvisionalAuthorization
	}
	entry := provisionalAuthorizationEntry{
		authorization: authorization.Clone(),
		workspaceID:   workspaceID,
	}
	if authority != nil {
		value := authority.Clone()
		entry.authority = &value
	}
	verifiers.provisional.byPeer[peerID] = entry
	return nil
}

func (provisional *ProvisionalAuthorizations) verify(
	snapshot *Snapshot,
	certificate transport.ContentCertificate,
	now time.Time,
) (transport.ContentPeerAdmission, error) {
	if provisional == nil || snapshot == nil || now.IsZero() {
		return transport.ContentPeerAdmission{}, ErrPeerNotAdmitted
	}
	peerID := certificate.Binding.DeviceID
	provisional.mu.Lock()
	provisional.pruneLocked(snapshot, now)
	entry, exists := provisional.byPeer[peerID]
	provisional.mu.Unlock()
	if !exists ||
		certificate.Binding.Epoch != entry.authorization.Epoch ||
		certificate.VerifyAuthorization(
			entry.authorization,
			now,
		) != nil {
		return transport.ContentPeerAdmission{}, ErrPeerNotAdmitted
	}
	closeAfter, err := certificate.CloseAfter(now)
	if err != nil {
		return transport.ContentPeerAdmission{}, ErrPeerNotAdmitted
	}
	return transport.ContentPeerAdmission{CloseAfter: closeAfter}, nil
}

func (provisional *ProvisionalAuthorizations) prune(
	snapshot *Snapshot,
	now time.Time,
) {
	if provisional == nil {
		return
	}
	provisional.mu.Lock()
	provisional.pruneLocked(snapshot, now)
	provisional.mu.Unlock()
}

func (provisional *ProvisionalAuthorizations) pruneLocked(
	snapshot *Snapshot,
	now time.Time,
) {
	for peerID, entry := range provisional.byPeer {
		if !validProvisionalAuthorization(
			snapshot,
			peerID,
			entry.authorization,
			now,
			entry.workspaceID,
			entry.authority,
		) {
			delete(provisional.byPeer, peerID)
		}
	}
}

func validProvisionalAuthorization(
	snapshot *Snapshot,
	peerID domain.DeviceID,
	authorization credentialauthorization.Authorization,
	now time.Time,
	workspaceID domain.UUIDv4,
	successorAuthority *credentialauthority.Authority,
) bool {
	if snapshot == nil ||
		!snapshot.valid ||
		!peerID.Valid() ||
		authorization.DeviceID != peerID ||
		authorization.Validate() != nil ||
		!authorization.ActiveAt(now) {
		return false
	}
	sessionID, _, valid := snapshot.Lineage()
	member, exists := snapshot.Member(peerID)
	if !valid ||
		authorization.SessionID != sessionID ||
		!exists ||
		member.Status != device.StatusActive {
		return false
	}
	binding := credential.Binding{
		SessionID:      authorization.SessionID,
		DeviceID:       authorization.DeviceID,
		Epoch:          authorization.Epoch,
		EpochPublicKey: authorization.EpochPublicKey,
		KeyDigest:      authorization.KeyDigest,
		Signature:      authorization.BindingSignature,
	}
	if binding.Validate(member.IdentityPublicKey) != nil {
		return false
	}
	appliedAuthority, valid := snapshot.CredentialAuthority()
	if !valid || appliedAuthority.Validate() != nil {
		return false
	}
	authority := appliedAuthority
	if authorization.AuthorityVoterSetVersion !=
		appliedAuthority.VoterSetVersion {
		if successorAuthority == nil ||
			!validProvisionalAuthorityHandoff(
				snapshot,
				workspaceID,
				appliedAuthority,
				*successorAuthority,
			) ||
			authorization.AuthorityVoterSetVersion !=
				successorAuthority.VoterSetVersion {
			return false
		}
		authority = successorAuthority.Clone()
	}
	preimage, err := credentialauthorization.CanonicalEndorsementPreimage(
		authorization,
	)
	if err != nil {
		return false
	}
	for _, endorsement := range authorization.ClockEndorsements {
		endorser, exists := snapshot.Member(endorsement.DeviceID)
		if !exists ||
			endorser.Status != device.StatusActive ||
			!authority.Contains(endorsement.DeviceID) ||
			codecommcrypto.VerifyEd25519(
				endorser.IdentityPublicKey,
				codec.SignatureCredentialTimeEndorsement,
				preimage,
				endorsement.Signature[:],
			) != nil {
			return false
		}
	}
	if len(authorization.ClockEndorsements) <
		len(authority.VoterDeviceIDs)/2+1 {
		return false
	}
	appliedChainIndex, valid := snapshot.AppliedChainIndex()
	currentEpoch, exists := snapshot.CurrentCredentialEpoch(peerID)
	if !valid ||
		!exists ||
		currentEpoch == domain.MaxSafeInteger ||
		authorization.Epoch <= currentEpoch ||
		authorization.AuthorizationChainIndex <= appliedChainIndex ||
		authorization.Epoch-currentEpoch >
			authorization.AuthorizationChainIndex-appliedChainIndex {
		return false
	}
	if authorization.Epoch > currentEpoch+1 {
		return currentEpoch != 0
	}
	var prior *credentialauthorization.Authorization
	if currentEpoch != 0 {
		value, found := snapshot.Authorization(
			credentialauthorization.Key{
				SessionID: sessionID,
				DeviceID:  peerID,
				Epoch:     currentEpoch,
			},
		)
		if !found {
			return false
		}
		prior = &value
	}
	return credentialauthorization.ValidateTransition(
		prior,
		authorization,
	) == nil
}

func validProvisionalAuthorityHandoff(
	snapshot *Snapshot,
	workspaceID domain.UUIDv4,
	before credentialauthority.Authority,
	after credentialauthority.Authority,
) bool {
	if snapshot == nil ||
		!workspaceID.Valid() ||
		credentialauthority.ValidateTransition(
			credentialauthority.OperationActivate,
			before,
			after,
		) != nil {
		return false
	}
	sessionID, generation, valid := snapshot.Lineage()
	if !valid ||
		after.SessionID != sessionID ||
		len(after.ActivationProofs) != len(after.VoterDeviceIDs) ||
		after.PriorAuthorityHandoff == nil {
		return false
	}

	proofs := make(
		[]voteractivation.Proof,
		len(after.ActivationProofs),
	)
	for index, stored := range after.ActivationProofs {
		proof, err := voteractivation.ParseProof(stored.CanonicalJSON)
		if err != nil ||
			!bytes.Equal(
				proof.CanonicalBytes(),
				stored.CanonicalJSON,
			) {
			return false
		}
		input := proof.Unsigned().Input()
		if stored.VoterDeviceID != after.VoterDeviceIDs[index] ||
			proof.VoterDeviceID() != stored.VoterDeviceID ||
			input.SessionID != sessionID ||
			input.WorkspaceID != workspaceID ||
			input.RecoveryGeneration != generation ||
			input.TargetVoterSetVersion !=
				after.VoterSetVersion ||
			input.CurrentAuthorityVoterSetVersion !=
				before.VoterSetVersion ||
			input.CheckpointEventID !=
				after.ActivationCheckpointEventID ||
			!slices.Equal(
				input.VoterSet,
				after.VoterDeviceIDs,
			) {
			return false
		}
		voter, exists := snapshot.Member(stored.VoterDeviceID)
		if !exists ||
			voter.Status != device.StatusActive ||
			voteractivation.VerifyProof(
				proof,
				voter.IdentityPublicKey,
			) != nil {
			return false
		}
		checkpointSigner, exists := snapshot.Member(
			input.Checkpoint.SignerDeviceID,
		)
		checkpointBytes, err := event.EncodeCheckpoint(
			input.Checkpoint,
		)
		if !exists ||
			checkpointSigner.Status != device.StatusActive ||
			!before.Contains(checkpointSigner.ID) ||
			err != nil ||
			codecommcrypto.VerifyEd25519(
				checkpointSigner.IdentityPublicKey,
				codec.SignatureCheckpoint,
				checkpointBytes,
				input.CheckpointSignature[:],
			) != nil {
			return false
		}
		proofs[index] = proof
	}

	handoff, err := voteractivation.NewUnsignedAuthorityHandoff(
		voteractivation.AuthorityHandoffInput{
			SessionID:          sessionID,
			WorkspaceID:        workspaceID,
			RecoveryGeneration: generation,
			TargetVoterSetVersion: after.
				VoterSetVersion,
			ExpectedAuthorityVoterSetVersion: before.
				VoterSetVersion,
			VoterSet: after.VoterIDs(),
			ActivationCheckpointEventID: after.
				ActivationCheckpointEventID,
			ActivationProofs:     proofs,
			PriorAuthoritySigner: after.PriorAuthoritySigner,
		},
	)
	if err != nil {
		return false
	}
	payload, err := voteractivation.NewActivationPayload(
		handoff,
		*after.PriorAuthorityHandoff,
	)
	if err != nil {
		return false
	}
	priorSigner, exists := snapshot.Member(
		after.PriorAuthoritySigner,
	)
	return exists &&
		priorSigner.Status == device.StatusActive &&
		before.Contains(priorSigner.ID) &&
		voteractivation.VerifyAuthorityHandoff(
			payload,
			priorSigner.IdentityPublicKey,
		) == nil
}

func sameProvisionalAuthorization(
	left credentialauthorization.Authorization,
	right credentialauthorization.Authorization,
) bool {
	return left.SessionID == right.SessionID &&
		left.DeviceID == right.DeviceID &&
		left.Epoch == right.Epoch &&
		left.EpochPublicKey == right.EpochPublicKey &&
		left.KeyDigest == right.KeyDigest &&
		left.Role == right.Role &&
		left.IssuedAt == right.IssuedAt &&
		left.NotBefore == right.NotBefore &&
		left.ValiditySeconds == right.ValiditySeconds &&
		left.AuthorityVoterSetVersion ==
			right.AuthorityVoterSetVersion &&
		slices.Equal(
			left.ClockEndorsements,
			right.ClockEndorsements,
		) &&
		left.BindingSignature == right.BindingSignature &&
		left.AuthorizationChainIndex ==
			right.AuthorizationChainIndex
}
