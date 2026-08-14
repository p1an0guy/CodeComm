package peerauth

import (
	"crypto/ed25519"
	"errors"
	"testing"
	"time"

	"github.com/ijonahch/codecomm/internal/domain"
	"github.com/ijonahch/codecomm/internal/domain/auditcounter"
	"github.com/ijonahch/codecomm/internal/domain/credentialauthorization"
	"github.com/ijonahch/codecomm/internal/domain/device"
	"github.com/ijonahch/codecomm/internal/transport"
)

func TestPairingAndConsensusVerifiersApplyDistinctAdmissionRules(t *testing.T) {
	t.Parallel()

	fixture := newSnapshotFixture(t, 1)
	current, err := NewSnapshot(fixture.input)
	if err != nil {
		t.Fatalf("NewSnapshot() error = %v", err)
	}
	verifiers, err := NewVerifiers(
		func() (*Snapshot, error) { return current, nil },
		snapshotTestNow,
	)
	if err != nil {
		t.Fatalf("NewVerifiers() error = %v", err)
	}

	memberCertificate := parsedIdentityCertificate(
		t,
		snapshotTestSessionID,
		4,
		fixture.identityKey,
	)
	if err := verifiers.VerifyPairingPeer(memberCertificate); err != nil {
		t.Fatalf("VerifyPairingPeer(member) error = %v", err)
	}
	if err := verifiers.VerifyConsensusPeer(memberCertificate); err != nil {
		t.Fatalf("VerifyConsensusPeer(member) error = %v", err)
	}

	joinerCertificate := parsedIdentityCertificate(
		t,
		snapshotTestSessionID,
		4,
		snapshotPrivateKey(71),
	)
	if err := verifiers.VerifyPairingPeer(joinerCertificate); err != nil {
		t.Fatalf("VerifyPairingPeer(unadmitted joiner) error = %v", err)
	}
	if err := verifiers.VerifyConsensusPeer(joinerCertificate); !errors.Is(
		err,
		ErrPeerNotAdmitted,
	) {
		t.Fatalf("VerifyConsensusPeer(unadmitted joiner) error = %v", err)
	}

	wrongGeneration := parsedIdentityCertificate(
		t,
		snapshotTestSessionID,
		5,
		snapshotPrivateKey(72),
	)
	if err := verifiers.VerifyPairingPeer(wrongGeneration); !errors.Is(
		err,
		ErrPeerNotAdmitted,
	) {
		t.Fatalf("VerifyPairingPeer(wrong generation) error = %v", err)
	}

	requiresReadmission := fixture.input.Devices[fixture.deviceID]
	requiresReadmission.Status = device.StatusRequiresReadmission
	requiresReadmission.EntityVersion++
	current, err = current.Advance(Changes{
		AdvancesEventChain: true,
		Devices:            []device.Device{requiresReadmission},
	})
	if err != nil {
		t.Fatalf("Advance(requires readmission) error = %v", err)
	}
	if err := verifiers.VerifyPairingPeer(memberCertificate); err != nil {
		t.Fatalf("VerifyPairingPeer(requires readmission) error = %v", err)
	}
	if err := verifiers.VerifyConsensusPeer(memberCertificate); !errors.Is(
		err,
		ErrPeerNotAdmitted,
	) {
		t.Fatalf("VerifyConsensusPeer(requires readmission) error = %v", err)
	}

	revoked := requiresReadmission
	revoked.Status = device.StatusRevoked
	revoked.EntityVersion++
	current, err = current.Advance(Changes{
		AdvancesEventChain: true,
		Devices:            []device.Device{revoked},
	})
	if err != nil {
		t.Fatalf("Advance(revocation) error = %v", err)
	}
	if err := verifiers.VerifyConsensusPeer(memberCertificate); !errors.Is(
		err,
		ErrPeerNotAdmitted,
	) {
		t.Fatalf("VerifyConsensusPeer(revoked member) error = %v", err)
	}
	if err := verifiers.VerifyPairingPeer(memberCertificate); !errors.Is(
		err,
		ErrPeerNotAdmitted,
	) {
		t.Fatalf("VerifyPairingPeer(revoked member) error = %v", err)
	}
}

func TestVerifyExpectedConsensusPeerPinsRaftDeviceAddress(t *testing.T) {
	t.Parallel()

	fixture := newSnapshotFixture(t, 0)
	otherIdentityKey := snapshotPrivateKey(12)
	otherDeviceID, err := device.DeriveID(
		otherIdentityKey.Public().(ed25519.PublicKey),
	)
	if err != nil {
		t.Fatalf("device.DeriveID(other) error = %v", err)
	}
	fixture.input.Devices[otherDeviceID] = device.Device{
		ID:                otherDeviceID,
		Role:              device.RoleEditor,
		IdentityPublicKey: otherIdentityKey.Public().(ed25519.PublicKey),
		DaemonVersion:     "0.1.0",
		MaxApplyLevel:     1,
		Status:            device.StatusActive,
		EntityVersion:     1,
	}
	fixture.input.AuditCounters[otherDeviceID] = auditcounter.Counter{
		DeviceID: otherDeviceID,
	}
	snapshot, err := NewSnapshot(fixture.input)
	if err != nil {
		t.Fatalf("NewSnapshot() error = %v", err)
	}
	verifiers, err := NewVerifiers(
		func() (*Snapshot, error) { return snapshot, nil },
		snapshotTestNow,
	)
	if err != nil {
		t.Fatalf("NewVerifiers() error = %v", err)
	}
	certificate := parsedIdentityCertificate(
		t,
		snapshotTestSessionID,
		fixture.input.RecoveryGeneration,
		fixture.identityKey,
	)
	if err := verifiers.VerifyExpectedConsensusPeer(
		fixture.deviceID,
		certificate,
	); err != nil {
		t.Fatalf("VerifyExpectedConsensusPeer() error = %v", err)
	}

	otherCertificate := parsedIdentityCertificate(
		t,
		snapshotTestSessionID,
		fixture.input.RecoveryGeneration,
		otherIdentityKey,
	)
	if err := verifiers.VerifyConsensusPeer(otherCertificate); err != nil {
		t.Fatalf("VerifyConsensusPeer(other active member) error = %v", err)
	}
	if err := verifiers.VerifyExpectedConsensusPeer(
		fixture.deviceID,
		otherCertificate,
	); !errors.Is(err, ErrPeerNotAdmitted) {
		t.Fatalf(
			"VerifyExpectedConsensusPeer(other active member) error = %v",
			err,
		)
	}
}

func TestVerifyExpectedConsensusPeerFailsClosed(t *testing.T) {
	t.Parallel()

	fixture := newSnapshotFixture(t, 0)
	snapshot, err := NewSnapshot(fixture.input)
	if err != nil {
		t.Fatalf("NewSnapshot() error = %v", err)
	}
	verifiers, err := NewVerifiers(
		func() (*Snapshot, error) { return snapshot, nil },
		snapshotTestNow,
	)
	if err != nil {
		t.Fatalf("NewVerifiers() error = %v", err)
	}
	valid := parsedIdentityCertificate(
		t,
		snapshotTestSessionID,
		fixture.input.RecoveryGeneration,
		fixture.identityKey,
	)
	malformed := valid
	malformed.Leaf = nil

	tests := []struct {
		name             string
		expectedDeviceID domain.DeviceID
		certificate      transport.IdentityCertificate
	}{
		{
			name:             "empty expected device ID",
			expectedDeviceID: "",
			certificate:      valid,
		},
		{
			name:             "noncanonical expected device ID",
			expectedDeviceID: domain.DeviceID("cc1ABC"),
			certificate:      valid,
		},
		{
			name:             "malformed certificate",
			expectedDeviceID: fixture.deviceID,
			certificate:      malformed,
		},
		{
			name:             "wrong session",
			expectedDeviceID: fixture.deviceID,
			certificate: parsedIdentityCertificate(
				t,
				"01890f47-3e72-7000-8000-000000000199",
				fixture.input.RecoveryGeneration,
				fixture.identityKey,
			),
		},
		{
			name:             "wrong recovery generation",
			expectedDeviceID: fixture.deviceID,
			certificate: parsedIdentityCertificate(
				t,
				snapshotTestSessionID,
				fixture.input.RecoveryGeneration+1,
				fixture.identityKey,
			),
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			if err := verifiers.VerifyExpectedConsensusPeer(
				test.expectedDeviceID,
				test.certificate,
			); !errors.Is(err, ErrPeerNotAdmitted) {
				t.Fatalf(
					"VerifyExpectedConsensusPeer() error = %v, want %v",
					err,
					ErrPeerNotAdmitted,
				)
			}
		})
	}
}

func TestContentVerifierAllowsOnlyCurrentOverlapEpochsAndActiveMember(t *testing.T) {
	t.Parallel()

	fixture := newSnapshotFixture(t, 3)
	snapshot, err := NewSnapshot(fixture.input)
	if err != nil {
		t.Fatalf("NewSnapshot() error = %v", err)
	}
	verifiers, err := NewVerifiers(
		func() (*Snapshot, error) { return snapshot, nil },
		snapshotTestNow,
	)
	if err != nil {
		t.Fatalf("NewVerifiers() error = %v", err)
	}

	for epoch, wantAccepted := range map[uint64]bool{
		1: false,
		2: true,
		3: true,
	} {
		epochKey := snapshotPrivateKey(byte(20 + epoch))
		authorization := snapshotAuthorization(
			fixture.deviceID,
			epoch,
			epoch,
			epochKey,
		)
		certificate := parsedContentCertificate(
			t,
			authorization,
			epochKey,
		)
		_, err := verifiers.VerifyContentPeer(certificate)
		if wantAccepted && err != nil {
			t.Errorf("VerifyContentPeer(epoch %d) error = %v", epoch, err)
		}
		if !wantAccepted && !errors.Is(err, ErrPeerNotAdmitted) {
			t.Errorf(
				"VerifyContentPeer(epoch %d) error = %v, want rejection",
				epoch,
				err,
			)
		}
	}
}

func TestContentVerifierRejectsExpiryRevocationAndChangedAuthorization(t *testing.T) {
	t.Parallel()

	fixture := newSnapshotFixture(t, 1)
	current, err := NewSnapshot(fixture.input)
	if err != nil {
		t.Fatalf("NewSnapshot() error = %v", err)
	}
	now := snapshotTestNow()
	verifiers, err := NewVerifiers(
		func() (*Snapshot, error) { return current, nil },
		func() time.Time { return now },
	)
	if err != nil {
		t.Fatalf("NewVerifiers() error = %v", err)
	}
	epochKey := snapshotPrivateKey(21)
	authorization := fixture.input.CredentialAuthorizations[credentialauthorization.Key{
		SessionID: snapshotTestSessionID,
		DeviceID:  fixture.deviceID,
		Epoch:     1,
	}]
	certificate := parsedContentCertificate(t, authorization, epochKey)
	admission, err := verifiers.VerifyContentPeer(certificate)
	if err != nil {
		t.Fatalf("VerifyContentPeer(current) error = %v", err)
	}
	if admission.CloseAfter != 25*time.Minute {
		t.Fatalf(
			"VerifyContentPeer(current) close after = %s, want 25m",
			admission.CloseAfter,
		)
	}

	now = time.Date(2026, 8, 14, 12, 30, 0, 0, time.UTC)
	if _, err := verifiers.VerifyContentPeer(certificate); !errors.Is(
		err,
		ErrPeerNotAdmitted,
	) {
		t.Fatalf("VerifyContentPeer(expired) error = %v", err)
	}
	now = snapshotTestNow()

	revoked := fixture.input.Devices[fixture.deviceID]
	revoked.Status = device.StatusRevoked
	revoked.EntityVersion++
	current, err = current.Advance(Changes{
		AdvancesEventChain: true,
		Devices:            []device.Device{revoked},
	})
	if err != nil {
		t.Fatalf("Advance(revocation) error = %v", err)
	}
	if _, err := verifiers.VerifyContentPeer(certificate); !errors.Is(
		err,
		ErrPeerNotAdmitted,
	) {
		t.Fatalf("VerifyContentPeer(revoked) error = %v", err)
	}
}

func TestOwnerAuthorizationReadsCurrentMembershipRole(t *testing.T) {
	t.Parallel()

	fixture := newSnapshotFixture(t, 1)
	current, err := NewSnapshot(fixture.input)
	if err != nil {
		t.Fatalf("NewSnapshot() error = %v", err)
	}
	verifiers, err := NewVerifiers(
		func() (*Snapshot, error) { return current, nil },
		snapshotTestNow,
	)
	if err != nil {
		t.Fatalf("NewVerifiers() error = %v", err)
	}
	authorization := fixture.input.CredentialAuthorizations[credentialauthorization.Key{
		SessionID: snapshotTestSessionID,
		DeviceID:  fixture.deviceID,
		Epoch:     1,
	}]
	certificate := parsedContentCertificate(
		t,
		authorization,
		snapshotPrivateKey(21),
	)
	if err := verifiers.RequireOwner(fixture.deviceID); err != nil {
		t.Fatalf("RequireOwner(owner) error = %v", err)
	}

	member := fixture.input.Devices[fixture.deviceID]
	member.Role = device.RoleEditor
	member.EntityVersion++
	current, err = current.Advance(Changes{
		AdvancesEventChain: true,
		Devices:            []device.Device{member},
	})
	if err != nil {
		t.Fatalf("Advance(demotion) error = %v", err)
	}
	if _, err := verifiers.VerifyContentPeer(certificate); err != nil {
		t.Fatalf("credential stopped authenticating after demotion: %v", err)
	}
	if role, err := verifiers.CurrentRole(fixture.deviceID); err != nil ||
		role != device.RoleEditor {
		t.Fatalf("CurrentRole() = (%q, %v), want editor", role, err)
	}
	if err := verifiers.RequireOwner(fixture.deviceID); !errors.Is(
		err,
		ErrPeerNotAuthorized,
	) {
		t.Fatalf("RequireOwner(demoted) error = %v", err)
	}
}

func TestVerifierFailsClosedWhenSnapshotOrClockUnavailable(t *testing.T) {
	t.Parallel()

	if _, err := NewVerifiers(nil, snapshotTestNow); !errors.Is(
		err,
		ErrInvalidVerifier,
	) {
		t.Fatalf("NewVerifiers(nil) error = %v", err)
	}
	unavailable := errors.New("node closing")
	verifiers, err := NewVerifiers(
		func() (*Snapshot, error) { return nil, unavailable },
		snapshotTestNow,
	)
	if err != nil {
		t.Fatalf("NewVerifiers() error = %v", err)
	}
	var identity transport.IdentityCertificate
	if err := verifiers.VerifyPairingPeer(identity); !errors.Is(
		err,
		ErrAdmissionUnavailable,
	) {
		t.Fatalf("VerifyPairingPeer(unavailable) error = %v", err)
	}

	fixture := newSnapshotFixture(t, 1)
	snapshot, err := NewSnapshot(fixture.input)
	if err != nil {
		t.Fatalf("NewSnapshot() error = %v", err)
	}
	zeroClock, err := NewVerifiers(
		func() (*Snapshot, error) { return snapshot, nil },
		func() time.Time { return time.Time{} },
	)
	if err != nil {
		t.Fatalf("NewVerifiers(zero clock) error = %v", err)
	}
	authorization := fixture.input.CredentialAuthorizations[credentialauthorization.Key{
		SessionID: snapshotTestSessionID,
		DeviceID:  fixture.deviceID,
		Epoch:     1,
	}]
	certificate := parsedContentCertificate(
		t,
		authorization,
		snapshotPrivateKey(21),
	)
	if _, err := zeroClock.VerifyContentPeer(certificate); !errors.Is(
		err,
		ErrAdmissionClock,
	) {
		t.Fatalf("VerifyContentPeer(zero clock) error = %v", err)
	}
}

func TestSnapshotRejectsMissingCurrentCredential(t *testing.T) {
	t.Parallel()

	fixture := newSnapshotFixture(t, 1)
	fixture.input.CredentialAuthorizations =
		map[credentialauthorization.Key]credentialauthorization.Authorization{}
	if _, err := NewSnapshot(fixture.input); !errors.Is(err, ErrInvalidSnapshot) {
		t.Fatalf("NewSnapshot(missing current authorization) error = %v", err)
	}

	fixture = newSnapshotFixture(t, 0)
	fixture.input.AuditCounters[fixture.deviceID] = auditcounter.Counter{
		DeviceID: fixture.deviceID,
	}
	if _, err := NewSnapshot(fixture.input); err != nil {
		t.Fatalf("NewSnapshot(epoch zero) error = %v", err)
	}
}

func parsedIdentityCertificate(
	t *testing.T,
	sessionID domain.UUIDv7,
	generation uint64,
	privateKey []byte,
) transport.IdentityCertificate {
	t.Helper()
	certificate, _, err := transport.IssueIdentityCertificate(
		sessionID,
		generation,
		privateKey,
	)
	if err != nil {
		t.Fatalf("IssueIdentityCertificate() error = %v", err)
	}
	parsed, err := transport.ParseIdentityCertificate(certificate.Certificate[0])
	if err != nil {
		t.Fatalf("ParseIdentityCertificate() error = %v", err)
	}
	return parsed
}

func parsedContentCertificate(
	t *testing.T,
	authorization credentialauthorization.Authorization,
	privateKey []byte,
) transport.ContentCertificate {
	t.Helper()
	certificate, _, err := transport.IssueContentCertificate(
		authorization,
		privateKey,
	)
	if err != nil {
		t.Fatalf("IssueContentCertificate() error = %v", err)
	}
	parsed, err := transport.ParseContentCertificate(certificate.Certificate[0])
	if err != nil {
		t.Fatalf("ParseContentCertificate() error = %v", err)
	}
	return parsed
}
