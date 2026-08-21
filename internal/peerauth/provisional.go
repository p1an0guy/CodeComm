package peerauth

import (
	"slices"
	"sync"
	"time"

	"github.com/ijonahch/codecomm/internal/codec"
	"github.com/ijonahch/codecomm/internal/credential"
	codecommcrypto "github.com/ijonahch/codecomm/internal/crypto"
	"github.com/ijonahch/codecomm/internal/domain"
	"github.com/ijonahch/codecomm/internal/domain/credentialauthorization"
	"github.com/ijonahch/codecomm/internal/domain/device"
	"github.com/ijonahch/codecomm/internal/transport"
)

// ProvisionalAuthorizations retains at most one locally-unapplied later
// authorization per active peer.
type ProvisionalAuthorizations struct {
	mu     sync.Mutex
	byPeer map[domain.DeviceID]credentialauthorization.Authorization
}

// NewProvisionalAuthorizations creates an empty bounded overlay.
func NewProvisionalAuthorizations() *ProvisionalAuthorizations {
	return &ProvisionalAuthorizations{
		byPeer: make(
			map[domain.DeviceID]credentialauthorization.Authorization,
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
	) {
		return ErrInvalidProvisionalAuthorization
	}

	verifiers.provisional.mu.Lock()
	defer verifiers.provisional.mu.Unlock()
	verifiers.provisional.pruneLocked(snapshot, now)
	if verifiers.provisional.byPeer == nil {
		verifiers.provisional.byPeer = make(
			map[domain.DeviceID]credentialauthorization.Authorization,
		)
	}
	if current, exists := verifiers.provisional.byPeer[peerID]; exists &&
		current.Epoch > authorization.Epoch {
		return ErrInvalidProvisionalAuthorization
	}
	verifiers.provisional.byPeer[peerID] = authorization.Clone()
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
	authorization, exists := provisional.byPeer[peerID]
	provisional.mu.Unlock()
	if !exists ||
		certificate.Binding.Epoch != authorization.Epoch ||
		certificate.VerifyAuthorization(authorization, now) != nil {
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
	for peerID, authorization := range provisional.byPeer {
		if !validProvisionalAuthorization(
			snapshot,
			peerID,
			authorization,
			now,
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
	authority, valid := snapshot.CredentialAuthority()
	if !valid ||
		authority.Validate() != nil ||
		authorization.AuthorityVoterSetVersion !=
			authority.VoterSetVersion {
		return false
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
