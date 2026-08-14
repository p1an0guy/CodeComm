package peerauth

import (
	"errors"
	"time"

	"github.com/ijonahch/codecomm/internal/domain"
	"github.com/ijonahch/codecomm/internal/domain/credentialauthorization"
	"github.com/ijonahch/codecomm/internal/domain/device"
	"github.com/ijonahch/codecomm/internal/transport"
)

var (
	ErrInvalidVerifier      = errors.New("peer auth: invalid verifier")
	ErrAdmissionUnavailable = errors.New("peer auth: applied admission unavailable")
	ErrPeerNotAdmitted      = errors.New("peer auth: peer not admitted")
	ErrPeerNotAuthorized    = errors.New("peer auth: peer role not authorized")
	ErrAdmissionClock       = errors.New("peer auth: invalid admission clock")
)

// SnapshotProvider returns the latest immutable applied-state cut. It must not
// perform peer-controlled unbounded work.
type SnapshotProvider func() (*Snapshot, error)

// Clock returns local verifier time for content-certificate admission.
type Clock func() time.Time

// Verifiers supplies the three closed TLS-plane policy callbacks.
type Verifiers struct {
	snapshot SnapshotProvider
	now      Clock
}

// NewVerifiers validates a production snapshot and clock provider.
func NewVerifiers(
	snapshot SnapshotProvider,
	now Clock,
) (*Verifiers, error) {
	if snapshot == nil || now == nil {
		return nil, ErrInvalidVerifier
	}
	return &Verifiers{snapshot: snapshot, now: now}, nil
}

// VerifyPairingPeer permits an unknown joiner or a retained readmission key in
// the exact applied lineage, but refuses identities already marked revoked.
// The pairing transcript later pins the joiner identity to its request.
func (verifiers *Verifiers) VerifyPairingPeer(
	certificate transport.IdentityCertificate,
) error {
	snapshot, err := verifiers.current()
	if err != nil {
		return err
	}
	sessionID, generation, _ := snapshot.Lineage()
	if err := certificate.VerifyLineage(sessionID, generation); err != nil {
		return ErrPeerNotAdmitted
	}
	member, exists := snapshot.Member(certificate.Binding.DeviceID)
	if !exists {
		return nil
	}
	if member.Status == device.StatusRevoked {
		return ErrPeerNotAdmitted
	}
	if err := certificate.VerifyIdentity(
		sessionID,
		generation,
		member.ID,
		member.IdentityPublicKey,
	); err != nil {
		return ErrPeerNotAdmitted
	}
	return nil
}

// VerifyConsensusPeer requires active applied membership and the exact
// enrolled long-lived identity key.
func (verifiers *Verifiers) VerifyConsensusPeer(
	certificate transport.IdentityCertificate,
) error {
	snapshot, err := verifiers.current()
	if err != nil {
		return err
	}
	member, exists := snapshot.Member(certificate.Binding.DeviceID)
	if !exists || member.Status != device.StatusActive {
		return ErrPeerNotAdmitted
	}
	sessionID, generation, _ := snapshot.Lineage()
	if err := certificate.VerifyIdentity(
		sessionID,
		generation,
		member.ID,
		member.IdentityPublicKey,
	); err != nil {
		return ErrPeerNotAdmitted
	}
	return nil
}

// VerifyExpectedConsensusPeer additionally pins an outbound consensus
// connection to the device ID carried as its Raft server address.
func (verifiers *Verifiers) VerifyExpectedConsensusPeer(
	expectedDeviceID domain.DeviceID,
	certificate transport.IdentityCertificate,
) error {
	if !expectedDeviceID.Valid() ||
		certificate.Binding.DeviceID != expectedDeviceID {
		return ErrPeerNotAdmitted
	}
	return verifiers.VerifyConsensusPeer(certificate)
}

// VerifyContentPeer requires active applied membership, the current or overlap
// predecessor epoch, and an exact authorization already covered by this cut.
func (verifiers *Verifiers) VerifyContentPeer(
	certificate transport.ContentCertificate,
) (transport.ContentPeerAdmission, error) {
	snapshot, err := verifiers.current()
	if err != nil {
		return transport.ContentPeerAdmission{}, err
	}
	member, exists := snapshot.Member(certificate.Binding.DeviceID)
	if !exists || member.Status != device.StatusActive {
		return transport.ContentPeerAdmission{}, ErrPeerNotAdmitted
	}
	sessionID, _, _ := snapshot.Lineage()
	if certificate.Binding.SessionID != sessionID {
		return transport.ContentPeerAdmission{}, ErrPeerNotAdmitted
	}
	currentEpoch, exists := snapshot.CurrentCredentialEpoch(member.ID)
	if !exists ||
		certificate.Binding.Epoch > currentEpoch ||
		currentEpoch-certificate.Binding.Epoch > 1 {
		return transport.ContentPeerAdmission{}, ErrPeerNotAdmitted
	}
	authorization, exists := snapshot.Authorization(
		credentialauthorization.Key{
			SessionID: sessionID,
			DeviceID:  member.ID,
			Epoch:     certificate.Binding.Epoch,
		},
	)
	appliedChainIndex, valid := snapshot.AppliedChainIndex()
	if !exists || !valid ||
		authorization.AuthorizationChainIndex > appliedChainIndex {
		return transport.ContentPeerAdmission{}, ErrPeerNotAdmitted
	}
	now := verifiers.now()
	if now.IsZero() {
		return transport.ContentPeerAdmission{}, ErrAdmissionClock
	}
	if err := certificate.VerifyAuthorization(
		authorization,
		now,
	); err != nil {
		return transport.ContentPeerAdmission{}, ErrPeerNotAdmitted
	}
	closeAfter, err := certificate.CloseAfter(now)
	if err != nil {
		return transport.ContentPeerAdmission{}, ErrPeerNotAdmitted
	}
	return transport.ContentPeerAdmission{CloseAfter: closeAfter}, nil
}

// CurrentRole resolves an authenticated device against current applied
// membership. Request handlers must use it instead of a credential's
// historical display role.
func (verifiers *Verifiers) CurrentRole(
	deviceID domain.DeviceID,
) (device.Role, error) {
	snapshot, err := verifiers.current()
	if err != nil {
		return "", err
	}
	member, exists := snapshot.Member(deviceID)
	if !exists || member.Status != device.StatusActive {
		return "", ErrPeerNotAdmitted
	}
	return member.Role, nil
}

// RequireOwner authorizes one owner-level request from current membership.
func (verifiers *Verifiers) RequireOwner(deviceID domain.DeviceID) error {
	role, err := verifiers.CurrentRole(deviceID)
	if err != nil {
		return err
	}
	if role != device.RoleOwner {
		return ErrPeerNotAuthorized
	}
	return nil
}

func (verifiers *Verifiers) current() (*Snapshot, error) {
	if verifiers == nil || verifiers.snapshot == nil || verifiers.now == nil {
		return nil, ErrInvalidVerifier
	}
	snapshot, err := verifiers.snapshot()
	if err != nil {
		return nil, ErrAdmissionUnavailable
	}
	if snapshot == nil || !snapshot.valid {
		return nil, ErrAdmissionUnavailable
	}
	return snapshot, nil
}

var (
	_ transport.IdentityPeerVerifier = (&Verifiers{}).VerifyPairingPeer
	_ transport.IdentityPeerVerifier = (&Verifiers{}).VerifyConsensusPeer
	_ transport.ContentPeerVerifier  = (&Verifiers{}).VerifyContentPeer
)
