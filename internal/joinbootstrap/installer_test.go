package joinbootstrap

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"testing"

	"github.com/ijonahch/codecomm/internal/codec"
	"github.com/ijonahch/codecomm/internal/domain"
	"github.com/ijonahch/codecomm/internal/domain/device"
	"github.com/ijonahch/codecomm/internal/pairing"
	"github.com/ijonahch/codecomm/internal/platform/credentialstore"
	"github.com/ijonahch/codecomm/internal/store"
)

func TestPrepareJoinUsesRetainedIdentityForTargetedModes(t *testing.T) {
	t.Parallel()

	for _, test := range []struct {
		mode     pairing.Mode
		epoch    uint64
		expected *uint64
	}{
		{
			mode:  pairing.ModeRebootstrap,
			epoch: 4,
		},
		{
			mode:     pairing.ModeReadmission,
			epoch:    1,
			expected: joinUint64Pointer(7),
		},
	} {
		test := test
		t.Run(string(test.mode), func(t *testing.T) {
			t.Parallel()

			invite, localPrivate, localPublic, localID :=
				joinTargetedInvite(t, test.mode, test.epoch, test.expected)
			secrets := &joinTestCredentialStore{
				values: map[credentialstore.Reference][]byte{
					credentialstore.IdentityReference(): bytes.Clone(localPrivate),
				},
			}
			generated := 0
			options := normalizeOptions(Options{
				StatePath:   filepath.Join(t.TempDir(), "join", "state.db"),
				Credentials: secrets,
				Invite:      invite,
				generateKeyPair: func() ([]byte, []byte, error) {
					generated++
					privateKey := ed25519.NewKeyFromSeed(
						bytes.Repeat([]byte{0x74}, ed25519.SeedSize),
					)
					return privateKey.Public().(ed25519.PublicKey),
						privateKey,
						nil
				},
				newUUIDv7: func() (domain.UUIDv7, error) {
					return "018f47de-89ab-7def-8123-7123456789ab", nil
				},
			})

			journal, err := prepareNewJoin(t.Context(), options)
			if err != nil {
				t.Fatalf("prepareNewJoin(): %v", err)
			}
			if generated != 1 ||
				secrets.createCalls != 1 ||
				journal.Mode != test.mode ||
				journal.LocalDeviceID != localID ||
				journal.SubjectDeviceID == nil ||
				*journal.SubjectDeviceID != localID ||
				!equalJournalUint64(
					journal.ExpectedEntityVersion,
					test.expected,
				) ||
				!bytes.Equal(
					journal.LocalIdentityPublicKey[:],
					localPublic,
				) {
				t.Fatalf(
					"prepared journal = %#v, generated %d, creates %d",
					journal,
					generated,
					secrets.createCalls,
				)
			}
			journal.ApprovedRequestDigest = sha256.Sum256(
				[]byte("approved request"),
			)
			if err := journal.validate(); err != nil {
				t.Fatalf("journal validation: %v", err)
			}
		})
	}
}

func TestPrepareTargetedJoinNeverGeneratesMissingOrMismatchedIdentity(
	t *testing.T,
) {
	t.Parallel()

	invite, _, _, _ := joinTargetedInvite(
		t,
		pairing.ModeRebootstrap,
		4,
		nil,
	)
	for _, test := range []struct {
		name   string
		values map[credentialstore.Reference][]byte
	}{
		{
			name:   "missing",
			values: make(map[credentialstore.Reference][]byte),
		},
		{
			name: "mismatched",
			values: map[credentialstore.Reference][]byte{
				credentialstore.IdentityReference(): ed25519.NewKeyFromSeed(
					bytes.Repeat([]byte{0x75}, ed25519.SeedSize),
				),
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			secrets := &joinTestCredentialStore{values: test.values}
			generated := 0
			options := normalizeOptions(Options{
				StatePath:   filepath.Join(t.TempDir(), "join", "state.db"),
				Credentials: secrets,
				Invite:      invite,
				generateKeyPair: func() ([]byte, []byte, error) {
					generated++
					return nil, nil, errors.New("identity generation forbidden")
				},
			})

			if _, err := prepareNewJoin(
				t.Context(),
				options,
			); !errors.Is(err, ErrStateConflict) {
				t.Fatalf("prepareNewJoin() error = %v, want %v", err, ErrStateConflict)
			}
			if generated != 0 || secrets.createCalls != 0 {
				t.Fatalf(
					"targeted identity generated %d keys and created %d secrets",
					generated,
					secrets.createCalls,
				)
			}
		})
	}
}

func TestReadmissionDestinationRequiresExactPredecessorLineage(
	t *testing.T,
) {
	t.Parallel()

	journal, _, _ := joinJournalFixture(t)
	successorSessionID := domain.UUIDv7(
		"018f47de-89ab-7def-8123-4123456789ab",
	)
	statePath := filepath.Join(t.TempDir(), "predecessor", "state.db")
	database, err := store.Open(
		t.Context(),
		store.Options{Path: statePath, RequireNew: true},
	)
	if err != nil {
		t.Fatal(err)
	}
	genesis, err := codec.CanonicalizeSignedObject([]byte(fmt.Sprintf(
		`{"recovery_generation":0,"session_id":%q,"workspace_id":%q}`,
		journal.SessionID,
		journal.WorkspaceID,
	)))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := database.Initialize(t.Context(), store.InitialState{
		SessionID:               journal.SessionID,
		WorkspaceID:             journal.WorkspaceID,
		GenesisJSON:             genesis,
		DigestVersion:           1,
		ProjectionSchemaVersion: 1,
	}); err != nil {
		t.Fatalf("Initialize(predecessor): %v", err)
	}
	if err := database.Close(); err != nil {
		t.Fatal(err)
	}

	if err := requireReadmissionDestination(
		t.Context(),
		statePath,
		successorSessionID,
		journal.WorkspaceID,
		1,
	); err != nil {
		t.Fatalf("exact predecessor rejected: %v", err)
	}
	for name, candidate := range map[string]struct {
		sessionID  domain.UUIDv7
		workspace  domain.UUIDv4
		generation uint64
	}{
		"other workspace": {
			sessionID:  successorSessionID,
			workspace:  "550e8400-e29b-41d4-a716-446655440001",
			generation: 1,
		},
		"same generation": {
			sessionID:  successorSessionID,
			workspace:  journal.WorkspaceID,
			generation: 0,
		},
		"generation gap": {
			sessionID:  successorSessionID,
			workspace:  journal.WorkspaceID,
			generation: 2,
		},
	} {
		t.Run(name, func(t *testing.T) {
			if err := requireReadmissionDestination(
				t.Context(),
				statePath,
				candidate.sessionID,
				candidate.workspace,
				candidate.generation,
			); !errors.Is(err, ErrStateConflict) {
				t.Fatalf("destination error = %v, want %v", err, ErrStateConflict)
			}
		})
	}

	missingPath := filepath.Join(t.TempDir(), "unused", "state.db")
	if err := requireReadmissionDestination(
		t.Context(),
		missingPath,
		successorSessionID,
		journal.WorkspaceID,
		1,
	); err != nil {
		t.Fatalf("unused destination rejected: %v", err)
	}
	if err := os.MkdirAll(filepath.Dir(missingPath), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(missingPath+"-wal", []byte("stale"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := requireReadmissionDestination(
		t.Context(),
		missingPath,
		successorSessionID,
		journal.WorkspaceID,
		1,
	); !errors.Is(err, ErrStateConflict) {
		t.Fatalf("stale sidecar error = %v, want %v", err, ErrStateConflict)
	}
}

func TestJoinCompletionRequiresModeSpecificRebootstrapMarker(
	t *testing.T,
) {
	t.Parallel()

	journal, _, _ := joinJournalFixture(t)
	journal.Mode = pairing.ModeRebootstrap
	subject := journal.LocalDeviceID
	journal.SubjectDeviceID = &subject
	marker := store.RebootstrapInstallMarker{
		SessionID:          journal.SessionID,
		WorkspaceID:        journal.WorkspaceID,
		RecoveryGeneration: journal.RecoveryGeneration,
		DeviceID:           journal.LocalDeviceID,
	}
	if err := validateJoinCompletionMarker(
		journal,
		marker,
		true,
	); err != nil {
		t.Fatalf("exact rebootstrap marker rejected: %v", err)
	}
	if err := validateJoinCompletionMarker(
		journal,
		store.RebootstrapInstallMarker{},
		false,
	); !errors.Is(err, ErrStateConflict) {
		t.Fatalf("missing rebootstrap marker error = %v", err)
	}
	changed := marker
	changed.RecoveryGeneration++
	if err := validateJoinCompletionMarker(
		journal,
		changed,
		true,
	); !errors.Is(err, ErrStateConflict) {
		t.Fatalf("changed rebootstrap marker error = %v", err)
	}

	journal.Mode = pairing.ModeNew
	journal.SubjectDeviceID = nil
	if err := validateJoinCompletionMarker(
		journal,
		store.RebootstrapInstallMarker{},
		false,
	); err != nil {
		t.Fatalf("marker-free new join rejected: %v", err)
	}
	if err := validateJoinCompletionMarker(
		journal,
		marker,
		true,
	); !errors.Is(err, ErrStateConflict) {
		t.Fatalf("unexpected new-join marker error = %v", err)
	}
}

func joinTargetedInvite(
	t testing.TB,
	mode pairing.Mode,
	epoch uint64,
	expected *uint64,
) (
	pairing.SignedInvite,
	ed25519.PrivateKey,
	ed25519.PublicKey,
	domain.DeviceID,
) {
	t.Helper()

	inviterPrivate, inviterPublic, inviterID := joinTestIdentity(t, 0x70)
	localPrivate, localPublic, localID := joinTestIdentity(t, 0x71)
	value := pairing.Invite{
		InviteID:               "018f47de-89ab-7def-8123-6123456789ab",
		SessionID:              "018f47de-89ab-7def-8123-3123456789ab",
		WorkspaceID:            "550e8400-e29b-41d4-a716-446655440000",
		RecoveryGeneration:     2,
		CreatedAt:              "2026-08-31T12:00:00Z",
		ExpiresAt:              "2026-08-31T12:15:00Z",
		InviterDeviceID:        inviterID,
		SignedGenesisDigest:    sha256.Sum256([]byte("successor genesis")),
		Mode:                   mode,
		SubjectDeviceID:        &localID,
		ExpectedEntityVersion:  cloneJournalUint64(expected),
		Role:                   device.RoleEditor,
		InitialCredentialEpoch: epoch,
		Endpoints: []pairing.Endpoint{{
			IP:   netip.MustParseAddr("192.0.2.10"),
			Port: 47831,
		}},
	}
	copy(value.InviterIdentityPublicKey[:], inviterPublic)
	for index := range value.Secret {
		value.Secret[index] = byte(index + 1)
	}
	signed, err := pairing.SignInvite(value, inviterPrivate)
	clear(value.Secret[:])
	if err != nil {
		t.Fatal(err)
	}
	return signed, localPrivate, localPublic, localID
}

func joinUint64Pointer(value uint64) *uint64 {
	return &value
}
