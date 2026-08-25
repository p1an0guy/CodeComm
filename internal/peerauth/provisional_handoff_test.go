package peerauth

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"testing"
	"time"

	"github.com/ijonahch/codecomm/internal/codec"
	"github.com/ijonahch/codecomm/internal/credential"
	codecommcrypto "github.com/ijonahch/codecomm/internal/crypto"
	"github.com/ijonahch/codecomm/internal/domain"
	"github.com/ijonahch/codecomm/internal/domain/auditcounter"
	"github.com/ijonahch/codecomm/internal/domain/credentialauthority"
	"github.com/ijonahch/codecomm/internal/domain/credentialauthorization"
	"github.com/ijonahch/codecomm/internal/domain/device"
	"github.com/ijonahch/codecomm/internal/event"
	"github.com/ijonahch/codecomm/internal/voteractivation"
)

const (
	provisionalHandoffWorkspace      domain.UUIDv4 = "550e8400-e29b-41d4-a716-446655440000"
	provisionalHandoffOtherWorkspace domain.UUIDv4 = "550e8400-e29b-41d4-a716-446655440001"
	provisionalHandoffCheckpointID   domain.UUIDv7 = "018f47de-89ab-7def-8123-1123456789ab"
)

func TestInstallProvisionalAuthorizationAfterHandoffIsOutboundOnly(
	t *testing.T,
) {
	t.Parallel()

	fixture := newProvisionalHandoffFixture(t)
	verifiers := fixture.verifiers(t)
	certificate := parsedContentCertificate(
		t,
		fixture.authorization,
		fixture.epochKey,
	)

	if _, err := verifiers.VerifyExpectedContentPeer(
		fixture.target.id,
		certificate,
	); !errors.Is(err, ErrPeerNotAdmitted) {
		t.Fatalf("VerifyExpectedContentPeer(before install) error = %v", err)
	}
	if err := verifiers.InstallProvisionalAuthorizationAfterHandoff(
		fixture.target.id,
		provisionalHandoffWorkspace,
		fixture.authorization,
		fixture.authority,
	); err != nil {
		t.Fatalf(
			"InstallProvisionalAuthorizationAfterHandoff() error = %v",
			err,
		)
	}

	admission, err := verifiers.VerifyExpectedContentPeer(
		fixture.target.id,
		certificate,
	)
	if err != nil {
		t.Fatalf("VerifyExpectedContentPeer() error = %v", err)
	}
	if admission.CloseAfter != 29*time.Minute+30*time.Second {
		t.Fatalf(
			"VerifyExpectedContentPeer() close after = %s, want 29m30s",
			admission.CloseAfter,
		)
	}
	if _, err := verifiers.VerifyContentPeer(certificate); !errors.Is(
		err,
		ErrPeerNotAdmitted,
	) {
		t.Fatalf("VerifyContentPeer(provisional) error = %v", err)
	}
	if _, err := verifiers.VerifyExpectedContentPeer(
		fixture.prior.id,
		certificate,
	); !errors.Is(err, ErrPeerNotAdmitted) {
		t.Fatalf("VerifyExpectedContentPeer(wrong peer) error = %v", err)
	}
}

func TestInstallProvisionalAuthorizationAfterHandoffRejectsMutations(
	t *testing.T,
) {
	t.Parallel()

	tests := []struct {
		name   string
		mutate func(*testing.T, *provisionalHandoffFixture)
	}{
		{
			name: "bad checkpoint signature",
			mutate: func(t *testing.T, fixture *provisionalHandoffFixture) {
				fixture.authority = provisionalHandoffAuthority(
					t,
					fixture.prior,
					fixture.target,
					provisionalHandoffActivationOptions{
						workspaceID:            provisionalHandoffWorkspace,
						recoveryGeneration:     4,
						badCheckpointSignature: true,
					},
				)
			},
		},
		{
			name: "bad target activation proof",
			mutate: func(t *testing.T, fixture *provisionalHandoffFixture) {
				fixture.authority = provisionalHandoffAuthority(
					t,
					fixture.prior,
					fixture.target,
					provisionalHandoffActivationOptions{
						workspaceID:        provisionalHandoffWorkspace,
						recoveryGeneration: 4,
						badTargetProof:     true,
					},
				)
			},
		},
		{
			name: "bad prior authority handoff",
			mutate: func(t *testing.T, fixture *provisionalHandoffFixture) {
				fixture.authority = provisionalHandoffAuthority(
					t,
					fixture.prior,
					fixture.target,
					provisionalHandoffActivationOptions{
						workspaceID:        provisionalHandoffWorkspace,
						recoveryGeneration: 4,
						badPriorHandoff:    true,
					},
				)
			},
		},
		{
			name: "wrong workspace",
			mutate: func(t *testing.T, fixture *provisionalHandoffFixture) {
				fixture.authority = provisionalHandoffAuthority(
					t,
					fixture.prior,
					fixture.target,
					provisionalHandoffActivationOptions{
						workspaceID:        provisionalHandoffOtherWorkspace,
						recoveryGeneration: 4,
					},
				)
			},
		},
		{
			name: "wrong recovery generation",
			mutate: func(t *testing.T, fixture *provisionalHandoffFixture) {
				fixture.authority = provisionalHandoffAuthority(
					t,
					fixture.prior,
					fixture.target,
					provisionalHandoffActivationOptions{
						workspaceID:        provisionalHandoffWorkspace,
						recoveryGeneration: 5,
					},
				)
			},
		},
		{
			name: "unknown target voter",
			mutate: func(t *testing.T, fixture *provisionalHandoffFixture) {
				unknown := newProvisionalHandoffSigner(t, 103)
				fixture.authority = provisionalHandoffAuthority(
					t,
					fixture.prior,
					unknown,
					provisionalHandoffActivationOptions{
						workspaceID:        provisionalHandoffWorkspace,
						recoveryGeneration: 4,
					},
				)
			},
		},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			fixture := newProvisionalHandoffFixture(t)
			test.mutate(t, &fixture)
			verifiers := fixture.verifiers(t)
			certificate := parsedContentCertificate(
				t,
				fixture.authorization,
				fixture.epochKey,
			)

			if err := verifiers.InstallProvisionalAuthorizationAfterHandoff(
				fixture.target.id,
				provisionalHandoffWorkspace,
				fixture.authorization,
				fixture.authority,
			); !errors.Is(err, ErrInvalidProvisionalAuthorization) {
				t.Fatalf(
					"InstallProvisionalAuthorizationAfterHandoff() error = %v",
					err,
				)
			}
			if _, err := verifiers.VerifyExpectedContentPeer(
				fixture.target.id,
				certificate,
			); !errors.Is(err, ErrPeerNotAdmitted) {
				t.Fatalf(
					"VerifyExpectedContentPeer(after rejected install) error = %v",
					err,
				)
			}
		})
	}
}

type provisionalHandoffSigner struct {
	id      domain.DeviceID
	private ed25519.PrivateKey
	public  ed25519.PublicKey
}

type provisionalHandoffFixture struct {
	snapshot      *Snapshot
	prior         provisionalHandoffSigner
	target        provisionalHandoffSigner
	authority     credentialauthority.Authority
	authorization credentialauthorization.Authorization
	epochKey      ed25519.PrivateKey
}

type provisionalHandoffActivationOptions struct {
	workspaceID            domain.UUIDv4
	recoveryGeneration     uint64
	badCheckpointSignature bool
	badTargetProof         bool
	badPriorHandoff        bool
}

func newProvisionalHandoffFixture(t *testing.T) provisionalHandoffFixture {
	t.Helper()

	prior := newProvisionalHandoffSigner(t, 101)
	target := newProvisionalHandoffSigner(t, 102)
	priorAuthorization := provisionalHandoffAuthorization(
		t,
		prior,
		snapshotPrivateKey(111),
		1,
		1,
		1,
		"2026-08-14T12:00:00Z",
		"2026-08-14T12:00:00Z",
		prior,
		credentialauthorization.RoleOwner,
	)
	targetAuthorization := provisionalHandoffAuthorization(
		t,
		target,
		snapshotPrivateKey(112),
		1,
		1,
		1,
		"2026-08-14T12:00:00Z",
		"2026-08-14T12:00:00Z",
		prior,
		credentialauthorization.RoleEditor,
	)
	snapshot, err := NewSnapshot(SnapshotInput{
		SessionID:          snapshotTestSessionID,
		RecoveryGeneration: 4,
		AppliedChainIndex:  1,
		Devices: map[domain.DeviceID]device.Device{
			prior.id:  provisionalHandoffDevice(prior, device.RoleOwner),
			target.id: provisionalHandoffDevice(target, device.RoleEditor),
		},
		AuditCounters: map[domain.DeviceID]auditcounter.Counter{
			prior.id: {
				DeviceID:        prior.id,
				CredentialEpoch: 1,
			},
			target.id: {
				DeviceID:        target.id,
				CredentialEpoch: 1,
			},
		},
		CredentialAuthority: credentialauthority.Authority{
			SessionID:        snapshotTestSessionID,
			VoterDeviceIDs:   []domain.DeviceID{prior.id},
			VoterSetVersion:  1,
			ActivationSource: credentialauthority.ActivationGenesis,
		},
		CredentialAuthorizations: map[credentialauthorization.Key]credentialauthorization.Authorization{
			priorAuthorization.PrimaryKey():  priorAuthorization,
			targetAuthorization.PrimaryKey(): targetAuthorization,
		},
	})
	if err != nil {
		t.Fatalf("NewSnapshot() error = %v", err)
	}

	epochKey := snapshotPrivateKey(113)
	authorization := provisionalHandoffAuthorization(
		t,
		target,
		epochKey,
		2,
		2,
		2,
		"2026-08-14T12:25:00Z",
		"2026-08-14T12:28:00Z",
		target,
		credentialauthorization.RoleEditor,
	)
	if err := credentialauthorization.ValidateTransition(
		&targetAuthorization,
		authorization,
	); err != nil {
		t.Fatalf("ValidateTransition(v2 credential) error = %v", err)
	}

	return provisionalHandoffFixture{
		snapshot: snapshot,
		prior:    prior,
		target:   target,
		authority: provisionalHandoffAuthority(
			t,
			prior,
			target,
			provisionalHandoffActivationOptions{
				workspaceID:        provisionalHandoffWorkspace,
				recoveryGeneration: 4,
			},
		),
		authorization: authorization,
		epochKey:      epochKey,
	}
}

func (fixture provisionalHandoffFixture) verifiers(t *testing.T) *Verifiers {
	t.Helper()
	verifiers, err := NewVerifiersWithProvisional(
		func() (*Snapshot, error) { return fixture.snapshot, nil },
		func() time.Time {
			return time.Date(2026, 8, 14, 12, 28, 30, 0, time.UTC)
		},
		NewProvisionalAuthorizations(),
	)
	if err != nil {
		t.Fatalf("NewVerifiersWithProvisional() error = %v", err)
	}
	return verifiers
}

func provisionalHandoffAuthority(
	t *testing.T,
	prior provisionalHandoffSigner,
	target provisionalHandoffSigner,
	options provisionalHandoffActivationOptions,
) credentialauthority.Authority {
	t.Helper()

	checkpoint := domain.Checkpoint{
		SessionID:                snapshotTestSessionID,
		WorkspaceID:              options.workspaceID,
		RecoveryGeneration:       options.recoveryGeneration,
		AuthorityVoterSetVersion: 1,
		SignerDeviceID:           prior.id,
		Term:                     3,
		CoveredAppliedLogIndex:   9,
		CoveredChainIndex:        1,
		CoveredChainHash:         [32]byte{0x41},
		CoveredResultIndex:       1,
		CoveredResultHash:        [32]byte{0x42},
		ProjectionAccumulator:    [32]byte{0x43},
		DigestVersion:            1,
		ProjectionSchemaVersion:  1,
	}
	checkpointSignature, err := event.SignCheckpoint(
		checkpoint,
		prior.private,
	)
	if err != nil {
		t.Fatalf("event.SignCheckpoint() error = %v", err)
	}
	if options.badCheckpointSignature {
		checkpointSignature[0] ^= 0xff
	}
	unsignedProof, err := voteractivation.NewUnsignedProof(
		voteractivation.ProofInput{
			SessionID:                       snapshotTestSessionID,
			WorkspaceID:                     options.workspaceID,
			RecoveryGeneration:              options.recoveryGeneration,
			TargetVoterSetVersion:           2,
			CurrentAuthorityVoterSetVersion: 1,
			VoterSet:                        []domain.DeviceID{target.id},
			VoterDeviceID:                   target.id,
			LiveConfigurationIndex:          8,
			CheckpointEventID:               provisionalHandoffCheckpointID,
			Checkpoint:                      checkpoint,
			CheckpointSignature:             checkpointSignature,
		},
	)
	if err != nil {
		t.Fatalf("voteractivation.NewUnsignedProof() error = %v", err)
	}
	proof, err := voteractivation.SignProof(unsignedProof, target.private)
	if err != nil {
		t.Fatalf("voteractivation.SignProof() error = %v", err)
	}
	if options.badTargetProof {
		signature := proof.VoterSignature()
		signature[0] ^= 0xff
		proof, err = voteractivation.NewProof(unsignedProof, signature)
		if err != nil {
			t.Fatalf("voteractivation.NewProof() error = %v", err)
		}
	}
	unsignedHandoff, err := voteractivation.NewUnsignedAuthorityHandoff(
		voteractivation.AuthorityHandoffInput{
			SessionID:                        snapshotTestSessionID,
			WorkspaceID:                      options.workspaceID,
			RecoveryGeneration:               options.recoveryGeneration,
			TargetVoterSetVersion:            2,
			ExpectedAuthorityVoterSetVersion: 1,
			VoterSet:                         []domain.DeviceID{target.id},
			ActivationCheckpointEventID:      provisionalHandoffCheckpointID,
			ActivationProofs:                 []voteractivation.Proof{proof},
			PriorAuthoritySigner:             prior.id,
		},
	)
	if err != nil {
		t.Fatalf(
			"voteractivation.NewUnsignedAuthorityHandoff() error = %v",
			err,
		)
	}
	payload, err := voteractivation.SignAuthorityHandoff(
		unsignedHandoff,
		prior.private,
	)
	if err != nil {
		t.Fatalf("voteractivation.SignAuthorityHandoff() error = %v", err)
	}
	handoffSignature := payload.HandoffSignature()
	if options.badPriorHandoff {
		handoffSignature[0] ^= 0xff
	}
	authority := credentialauthority.Authority{
		SessionID:                   snapshotTestSessionID,
		VoterDeviceIDs:              []domain.DeviceID{target.id},
		VoterSetVersion:             2,
		ActivationSource:            credentialauthority.ActivationHandoff,
		ActivationCheckpointEventID: provisionalHandoffCheckpointID,
		ActivationProofs: []credentialauthority.ActivationProof{{
			VoterDeviceID: target.id,
			CanonicalJSON: proof.CanonicalBytes(),
		}},
		PriorAuthoritySigner:  prior.id,
		PriorAuthorityHandoff: &handoffSignature,
	}
	if err := authority.Validate(); err != nil {
		t.Fatalf("Authority.Validate() error = %v", err)
	}
	return authority
}

func provisionalHandoffAuthorization(
	t *testing.T,
	subject provisionalHandoffSigner,
	epochKey ed25519.PrivateKey,
	epoch uint64,
	authorityVersion uint64,
	chainIndex uint64,
	issuedAt domain.WholeSecondTimestamp,
	notBefore domain.WholeSecondTimestamp,
	endorser provisionalHandoffSigner,
	role credentialauthorization.Role,
) credentialauthorization.Authorization {
	t.Helper()

	binding, err := credential.SignBinding(
		snapshotTestSessionID,
		subject.id,
		epoch,
		epochKey.Public().(ed25519.PublicKey),
		subject.private,
	)
	if err != nil {
		t.Fatalf("credential.SignBinding() error = %v", err)
	}
	authorization := credentialauthorization.Authorization{
		SessionID:                binding.SessionID,
		DeviceID:                 binding.DeviceID,
		Epoch:                    binding.Epoch,
		EpochPublicKey:           binding.EpochPublicKey,
		KeyDigest:                binding.KeyDigest,
		Role:                     role,
		IssuedAt:                 issuedAt,
		NotBefore:                notBefore,
		ValiditySeconds:          credentialauthorization.ValiditySeconds,
		AuthorityVoterSetVersion: authorityVersion,
		ClockEndorsements: []credentialauthorization.ClockEndorsement{{
			DeviceID: endorser.id,
		}},
		BindingSignature:        binding.Signature,
		AuthorizationChainIndex: chainIndex,
	}
	preimage, err := credentialauthorization.CanonicalEndorsementPreimage(
		authorization,
	)
	if err != nil {
		t.Fatalf("CanonicalEndorsementPreimage() error = %v", err)
	}
	signature, err := codecommcrypto.SignEd25519(
		endorser.private,
		codec.SignatureCredentialTimeEndorsement,
		preimage,
	)
	if err != nil {
		t.Fatalf("SignEd25519(endorsement) error = %v", err)
	}
	defer clear(signature)
	copy(authorization.ClockEndorsements[0].Signature[:], signature)
	if err := authorization.Validate(); err != nil {
		t.Fatalf("Authorization.Validate() error = %v", err)
	}
	return authorization
}

func provisionalHandoffDevice(
	signer provisionalHandoffSigner,
	role device.Role,
) device.Device {
	return device.Device{
		ID:                signer.id,
		Role:              role,
		IdentityPublicKey: bytes.Clone(signer.public),
		DaemonVersion:     "0.1.0",
		MaxApplyLevel:     1,
		Status:            device.StatusActive,
		EntityVersion:     1,
	}
}

func newProvisionalHandoffSigner(
	t *testing.T,
	seed byte,
) provisionalHandoffSigner {
	t.Helper()
	private := ed25519.NewKeyFromSeed(
		bytes.Repeat([]byte{seed}, ed25519.SeedSize),
	)
	public := private.Public().(ed25519.PublicKey)
	id, err := device.DeriveID(public)
	if err != nil {
		t.Fatalf("device.DeriveID() error = %v", err)
	}
	return provisionalHandoffSigner{
		id:      id,
		private: private,
		public:  public,
	}
}
