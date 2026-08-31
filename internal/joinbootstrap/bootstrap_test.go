package joinbootstrap

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/ijonahch/codecomm/internal/chain"
	"github.com/ijonahch/codecomm/internal/consensus"
	"github.com/ijonahch/codecomm/internal/credential"
	"github.com/ijonahch/codecomm/internal/domain"
	"github.com/ijonahch/codecomm/internal/domain/credentialauthorization"
	"github.com/ijonahch/codecomm/internal/domain/device"
	"github.com/ijonahch/codecomm/internal/logicalsnapshot"
	"github.com/ijonahch/codecomm/internal/pairing"
	"github.com/ijonahch/codecomm/internal/platform/credentialstore"
	"github.com/ijonahch/codecomm/internal/store"
)

func TestSelectJoinCredentialAdvancesExpiredCommittedEpochDurably(
	t *testing.T,
) {
	t.Parallel()

	journal, _, identityPrivate := joinJournalFixture(t)
	journal.Phase = journalPhaseConfirmed
	statePath := filepath.Join(t.TempDir(), "join", "state.db")
	if err := writePendingJournal(statePath, journal); err != nil {
		t.Fatal(err)
	}
	firstPrivate := ed25519.NewKeyFromSeed(
		bytes.Repeat([]byte{0x33}, ed25519.SeedSize),
	)
	defer clear(firstPrivate)
	first := joinCredentialAuthorization(
		t,
		journal,
		1,
		firstPrivate,
		time.Date(2026, 8, 1, 12, 0, 0, 0, time.UTC),
	)
	secrets := &joinTestCredentialStore{
		values: make(map[credentialstore.Reference][]byte),
	}
	firstReference, err := credentialstore.EpochReference(
		journal.SessionID,
		journal.LocalDeviceID,
		1,
	)
	if err != nil {
		t.Fatal(err)
	}
	secrets.values[firstReference] = bytes.Clone(firstPrivate)
	generated := 0
	options := normalizeOptions(Options{
		StatePath:   statePath,
		Credentials: secrets,
		Now: func() time.Time {
			return time.Date(2026, 8, 2, 12, 0, 0, 0, time.UTC)
		},
		generateKeyPair: func() ([]byte, []byte, error) {
			generated++
			privateKey := ed25519.NewKeyFromSeed(
				bytes.Repeat([]byte{0x44}, ed25519.SeedSize),
			)
			return privateKey.Public().(ed25519.PublicKey),
				privateKey,
				nil
		},
	})
	selected, binding, err := selectJoinCredential(
		t.Context(),
		options,
		&journal,
		consensus.ConsensusStatusResult{
			RequesterMembership: consensus.ConsensusStatusMember{
				CurrentCredentialEpoch: 1,
			},
			RequesterCredentialAuthorization: &first,
		},
		identityPrivate,
		firstPrivate,
	)
	if err != nil {
		t.Fatalf("selectJoinCredential(): %v", err)
	}
	defer clear(selected)
	if generated != 1 ||
		journal.CredentialEpoch != 2 ||
		binding.Epoch != 2 ||
		binding.EpochPublicKey != journal.LocalEpochPublicKey {
		t.Fatalf(
			"selected credential = (generated %d, journal %d, binding %#v)",
			generated,
			journal.CredentialEpoch,
			binding,
		)
	}
	persisted, err := loadPendingJournal(statePath)
	if err != nil ||
		persisted.CredentialEpoch != 2 ||
		persisted.LocalEpochPublicKey != journal.LocalEpochPublicKey {
		t.Fatalf("persisted journal = (%#v, %v)", persisted, err)
	}
	secondReference, err := credentialstore.EpochReference(
		journal.SessionID,
		journal.LocalDeviceID,
		2,
	)
	if err != nil {
		t.Fatal(err)
	}
	stored, err := secrets.Get(t.Context(), secondReference)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(stored)
	if !bytes.Equal(stored, selected) {
		t.Fatal("selected successor differs from native credential")
	}
}

func TestSelectJoinCredentialReusesPreparedSuccessorAfterLostResponse(
	t *testing.T,
) {
	t.Parallel()

	journal, _, identityPrivate := joinJournalFixture(t)
	journal.Phase = journalPhaseConfirmed
	journal.CredentialEpoch = 2
	secondPrivate := ed25519.NewKeyFromSeed(
		bytes.Repeat([]byte{0x45}, ed25519.SeedSize),
	)
	defer clear(secondPrivate)
	copy(
		journal.LocalEpochPublicKey[:],
		secondPrivate.Public().(ed25519.PublicKey),
	)
	statePath := filepath.Join(t.TempDir(), "join", "state.db")
	if err := writePendingJournal(statePath, journal); err != nil {
		t.Fatal(err)
	}
	firstPrivate := ed25519.NewKeyFromSeed(
		bytes.Repeat([]byte{0x33}, ed25519.SeedSize),
	)
	defer clear(firstPrivate)
	first := joinCredentialAuthorization(
		t,
		journal,
		1,
		firstPrivate,
		time.Date(2026, 8, 1, 12, 0, 0, 0, time.UTC),
	)
	secrets := &joinTestCredentialStore{
		values: make(map[credentialstore.Reference][]byte),
	}
	reference, err := credentialstore.EpochReference(
		journal.SessionID,
		journal.LocalDeviceID,
		2,
	)
	if err != nil {
		t.Fatal(err)
	}
	secrets.values[reference] = bytes.Clone(secondPrivate)
	options := normalizeOptions(Options{
		StatePath:   statePath,
		Credentials: secrets,
		Now: func() time.Time {
			return time.Date(2026, 8, 2, 12, 0, 0, 0, time.UTC)
		},
		generateKeyPair: func() ([]byte, []byte, error) {
			t.Fatal("prepared successor generated a replacement")
			return nil, nil, errors.New("unreachable")
		},
	})
	selected, binding, err := selectJoinCredential(
		t.Context(),
		options,
		&journal,
		consensus.ConsensusStatusResult{
			RequesterMembership: consensus.ConsensusStatusMember{
				CurrentCredentialEpoch: 1,
			},
			RequesterCredentialAuthorization: &first,
		},
		identityPrivate,
		secondPrivate,
	)
	if err != nil {
		t.Fatalf("selectJoinCredential(): %v", err)
	}
	defer clear(selected)
	if binding.Epoch != 2 || !bytes.Equal(selected, secondPrivate) {
		t.Fatalf("prepared successor = (epoch %d, key match %t)",
			binding.Epoch, bytes.Equal(selected, secondPrivate))
	}
}

func TestSelectJoinCredentialReusesUnexpiredCommittedEpoch(
	t *testing.T,
) {
	t.Parallel()

	journal, _, identityPrivate := joinJournalFixture(t)
	epochPrivate := ed25519.NewKeyFromSeed(
		bytes.Repeat([]byte{0x33}, ed25519.SeedSize),
	)
	defer clear(epochPrivate)
	now := time.Date(2026, 8, 1, 12, 5, 0, 0, time.UTC)
	current := joinCredentialAuthorization(
		t,
		journal,
		1,
		epochPrivate,
		now.Add(-time.Minute),
	)
	options := normalizeOptions(Options{
		StatePath: filepath.Join(t.TempDir(), "join", "state.db"),
		Credentials: &joinTestCredentialStore{
			values: make(map[credentialstore.Reference][]byte),
		},
		Now: func() time.Time { return now },
		generateKeyPair: func() ([]byte, []byte, error) {
			t.Fatal("unexpired credential generated a successor")
			return nil, nil, errors.New("unreachable")
		},
	})
	selected, binding, err := selectJoinCredential(
		t.Context(),
		options,
		&journal,
		consensus.ConsensusStatusResult{
			RequesterMembership: consensus.ConsensusStatusMember{
				CurrentCredentialEpoch: 1,
			},
			RequesterCredentialAuthorization: &current,
		},
		identityPrivate,
		epochPrivate,
	)
	if err != nil {
		t.Fatalf("selectJoinCredential(): %v", err)
	}
	defer clear(selected)
	if binding.Epoch != 1 ||
		journal.CredentialEpoch != 1 ||
		!bytes.Equal(selected, epochPrivate) {
		t.Fatalf(
			"unexpired selection = (epoch %d, journal %d, key match %t)",
			binding.Epoch,
			journal.CredentialEpoch,
			bytes.Equal(selected, epochPrivate),
		)
	}
}

func TestSelectRebootstrapCredentialUsesInviteSuccessorEpoch(
	t *testing.T,
) {
	t.Parallel()

	journal, _, identityPrivate := joinJournalFixture(t)
	journal.Mode = pairing.ModeRebootstrap
	subject := journal.LocalDeviceID
	journal.SubjectDeviceID = &subject
	journal.InitialCredentialEpoch = 2
	journal.CredentialEpoch = 2
	successorPrivate := ed25519.NewKeyFromSeed(
		bytes.Repeat([]byte{0x46}, ed25519.SeedSize),
	)
	defer clear(successorPrivate)
	copy(
		journal.LocalEpochPublicKey[:],
		successorPrivate.Public().(ed25519.PublicKey),
	)
	currentPrivate := ed25519.NewKeyFromSeed(
		bytes.Repeat([]byte{0x33}, ed25519.SeedSize),
	)
	defer clear(currentPrivate)
	now := time.Date(2026, 8, 1, 12, 5, 0, 0, time.UTC)
	current := joinCredentialAuthorization(
		t,
		journal,
		1,
		currentPrivate,
		now.Add(-time.Minute),
	)
	options := normalizeOptions(Options{
		StatePath: filepath.Join(t.TempDir(), "join", "state.db"),
		Credentials: &joinTestCredentialStore{
			values: make(map[credentialstore.Reference][]byte),
		},
		Now: func() time.Time { return now },
		generateKeyPair: func() ([]byte, []byte, error) {
			t.Fatal("rebootstrap generated a different epoch key")
			return nil, nil, errors.New("unreachable")
		},
	})

	selected, binding, err := selectJoinCredential(
		t.Context(),
		options,
		&journal,
		consensus.ConsensusStatusResult{
			RequesterMembership: consensus.ConsensusStatusMember{
				CurrentCredentialEpoch: 1,
			},
			RequesterCredentialAuthorization: &current,
		},
		identityPrivate,
		successorPrivate,
	)
	if err != nil {
		t.Fatalf("selectJoinCredential(): %v", err)
	}
	defer clear(selected)
	if binding.Epoch != 2 ||
		journal.CredentialEpoch != 2 ||
		!bytes.Equal(selected, successorPrivate) {
		t.Fatalf(
			"rebootstrap selection = (epoch %d, journal %d, key match %t)",
			binding.Epoch,
			journal.CredentialEpoch,
			bytes.Equal(selected, successorPrivate),
		)
	}
}

func TestOpenJoinDestinationRecordsExclusiveOwnershipBeforeReuse(
	t *testing.T,
) {
	t.Parallel()

	journal, inviterPrivate, _ := joinJournalFixture(t)
	journal.Phase = journalPhaseInstalling
	root := joinSnapshotRoot(t, journal, inviterPrivate, 11)
	journal.SnapshotRoot = root.CanonicalBytes()
	journal.SnapshotSignerDeviceID = journal.InviterDeviceID
	journal.SnapshotSignerPublicKey = journal.InviterIdentityPublicKey
	journal.MinimumAuthorizationCut = 10
	statePath := filepath.Join(t.TempDir(), "join", "state.db")
	if err := writePendingJournal(statePath, journal); err != nil {
		t.Fatal(err)
	}
	database, err := openJoinDestination(
		t.Context(),
		statePath,
		&journal,
	)
	if err != nil {
		t.Fatalf("openJoinDestination(create): %v", err)
	}
	if journal.Phase != journalPhaseInstallingOwned {
		t.Fatalf("phase = %q", journal.Phase)
	}
	if err := database.Close(); err != nil {
		t.Fatal(err)
	}
	persisted, err := loadPendingJournal(statePath)
	if err != nil || persisted.Phase != journalPhaseInstallingOwned {
		t.Fatalf("persisted phase = (%q, %v)", persisted.Phase, err)
	}
	reopened, err := openJoinDestination(
		t.Context(),
		statePath,
		&persisted,
	)
	if err != nil {
		t.Fatalf("openJoinDestination(reuse): %v", err)
	}
	if err := reopened.Close(); err != nil {
		t.Fatal(err)
	}

	ambiguousPath := filepath.Join(t.TempDir(), "ambiguous.db")
	ambiguous := journal
	ambiguous.Phase = journalPhaseInstalling
	if err := os.WriteFile(ambiguousPath, []byte("foreign"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := openJoinDestination(
		t.Context(),
		ambiguousPath,
		&ambiguous,
	); !errors.Is(err, ErrStateConflict) {
		t.Fatalf("ambiguous destination error = %v", err)
	}

	missing := journal
	missing.Phase = journalPhaseInstallingOwned
	missingPath := filepath.Join(t.TempDir(), "missing", "state.db")
	if err := prepareJournalDirectory(missingPath); err != nil {
		t.Fatal(err)
	}
	missingDatabase, err := openJoinDestination(
		t.Context(),
		missingPath,
		&missing,
	)
	if err != nil {
		t.Fatalf("missing owned destination recovery: %v", err)
	}
	if err := missingDatabase.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestPreflightSnapshotRootPinsLineageSignerAndAuthorizationCut(
	t *testing.T,
) {
	t.Parallel()

	journal, inviterPrivate, _ := joinJournalFixture(t)
	peer := bootstrapPeer{
		deviceID: journal.InviterDeviceID,
		identityPublicKey: bytes.Clone(
			journal.InviterIdentityPublicKey[:],
		),
	}
	root := joinSnapshotRoot(t, journal, inviterPrivate, 11)
	if err := preflightSnapshotRoot(journal, peer, 10, root); err != nil {
		t.Fatalf("preflightSnapshotRoot(): %v", err)
	}
	if err := preflightSnapshotRoot(
		journal,
		peer,
		12,
		root,
	); !errors.Is(err, ErrBootstrapUnavailable) {
		t.Fatalf("stale snapshot error = %v", err)
	}

	for name, mutate := range map[string]func(*logicalsnapshot.RootInput){
		"session": func(input *logicalsnapshot.RootInput) {
			input.SessionID = "018f47de-89ab-7def-8123-4123456789ab"
		},
		"workspace": func(input *logicalsnapshot.RootInput) {
			input.WorkspaceID = "550e8400-e29b-41d4-a716-446655440001"
		},
		"generation": func(input *logicalsnapshot.RootInput) {
			input.RecoveryGeneration++
		},
		"signer": func(input *logicalsnapshot.RootInput) {
			_, _, input.SignerDeviceID = joinTestIdentity(t, 0x41)
		},
		"record quota": func(input *logicalsnapshot.RootInput) {
			input.RecordCount = joinSnapshotMaxRecords + 1
			input.ExpandedBytes = input.RecordCount
			input.CompressedBytes = input.RecordCount
		},
	} {
		t.Run(name, func(t *testing.T) {
			input := root.Unsigned().Input()
			mutate(&input)
			var candidate logicalsnapshot.Root
			if input.SignerDeviceID == journal.InviterDeviceID {
				candidate = signJoinSnapshotRoot(
					t,
					input,
					inviterPrivate,
				)
			} else {
				otherPrivate, _, _ := joinTestIdentity(t, 0x41)
				candidate = signJoinSnapshotRoot(t, input, otherPrivate)
			}
			if err := preflightSnapshotRoot(
				journal,
				peer,
				10,
				candidate,
			); !errors.Is(err, ErrBootstrapMismatch) {
				t.Fatalf("preflight error = %v", err)
			}
		})
	}

	unsigned, err := logicalsnapshot.NewUnsignedRoot(root.Unsigned().Input())
	if err != nil {
		t.Fatal(err)
	}
	unsignedButUnsigned, err := logicalsnapshot.NewRoot(
		unsigned,
		[ed25519.SignatureSize]byte{},
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := preflightSnapshotRoot(
		journal,
		peer,
		10,
		unsignedButUnsigned,
	); !errors.Is(err, ErrBootstrapMismatch) {
		t.Fatalf("invalid signature error = %v", err)
	}
}

func TestValidateJoinConsensusStatusCountsInviterAsContactedPeer(
	t *testing.T,
) {
	t.Parallel()

	journal, _, _ := joinJournalFixture(t)
	local := device.Device{
		ID:                journal.LocalDeviceID,
		Role:              journal.ApprovedRole,
		IdentityPublicKey: bytes.Clone(journal.LocalIdentityPublicKey[:]),
		DaemonVersion:     journal.ApprovedDaemonVersion,
		MaxApplyLevel:     journal.ApprovedMaxApplyLevel,
		Status:            device.StatusActive,
		EntityVersion:     1,
	}
	inviter := device.Device{
		ID:                journal.InviterDeviceID,
		Role:              device.RoleOwner,
		IdentityPublicKey: bytes.Clone(journal.InviterIdentityPublicKey[:]),
		DaemonVersion:     CurrentDaemonVersion,
		MaxApplyLevel:     CurrentMaxApplyLevel,
		Status:            device.StatusActive,
		EntityVersion:     1,
	}
	status := consensus.ConsensusStatusResult{
		SessionID:          journal.SessionID,
		WorkspaceID:        journal.WorkspaceID,
		RecoveryGeneration: journal.RecoveryGeneration,
		ServerDeviceID:     journal.InviterDeviceID,
		RequesterMembership: consensus.ConsensusStatusMember{
			Device: local,
		},
		ActiveRoster: []consensus.ConsensusStatusMember{
			{Device: inviter},
			{Device: local},
		},
		GenerationZeroState: store.StateView{
			WorkspaceID: journal.WorkspaceID,
		},
	}
	peer := bootstrapPeer{
		deviceID: journal.InviterDeviceID,
		identityPublicKey: bytes.Clone(
			journal.InviterIdentityPublicKey[:],
		),
	}
	if err := validateJoinConsensusStatus(
		status,
		journal,
		peer,
	); err != nil {
		t.Fatalf("validateJoinConsensusStatus(): %v", err)
	}
}

func TestJoinEntityVersionMatchesPairingMode(t *testing.T) {
	t.Parallel()

	journal, _, _ := joinJournalFixture(t)
	if !joinEntityVersionMatches(journal, 1) ||
		joinEntityVersionMatches(journal, 2) {
		t.Fatal("new-member entity version rule changed")
	}

	journal.Mode = pairing.ModeRebootstrap
	subject := journal.LocalDeviceID
	journal.SubjectDeviceID = &subject
	if !joinEntityVersionMatches(journal, 1) ||
		!joinEntityVersionMatches(journal, 9) {
		t.Fatal("rebootstrap rejected an existing valid entity version")
	}

	journal.Mode = pairing.ModeReadmission
	expected := uint64(9)
	journal.ExpectedEntityVersion = &expected
	if !joinEntityVersionMatches(journal, 10) ||
		joinEntityVersionMatches(journal, 9) ||
		joinEntityVersionMatches(journal, 11) {
		t.Fatal("readmission entity version rule changed")
	}
}

func TestLoadOrCreateKeyReusesNativeCredentialAndHandlesCreateRace(
	t *testing.T,
) {
	t.Parallel()

	store := &joinTestCredentialStore{
		values: make(map[credentialstore.Reference][]byte),
	}
	reference := credentialstore.IdentityReference()
	generated := 0
	generate := func() ([]byte, []byte, error) {
		generated++
		privateKey := ed25519.NewKeyFromSeed(
			bytes.Repeat([]byte{byte(0x50 + generated)}, ed25519.SeedSize),
		)
		return privateKey.Public().(ed25519.PublicKey), privateKey, nil
	}
	privateKey, publicKey, err := loadOrCreateKey(
		context.Background(),
		store,
		reference,
		generate,
	)
	if err != nil {
		t.Fatalf("loadOrCreateKey(create): %v", err)
	}
	defer clear(privateKey)
	defer clear(publicKey)
	if generated != 1 {
		t.Fatalf("generate calls = %d", generated)
	}
	firstPublic := bytes.Clone(publicKey)

	reusedPrivate, reusedPublic, err := loadOrCreateKey(
		context.Background(),
		store,
		reference,
		generate,
	)
	if err != nil {
		t.Fatalf("loadOrCreateKey(reuse): %v", err)
	}
	defer clear(reusedPrivate)
	defer clear(reusedPublic)
	if generated != 1 || !bytes.Equal(reusedPublic, firstPublic) {
		t.Fatalf("reused key differs; generate calls = %d", generated)
	}

	racing := &joinTestCredentialStore{
		values:     make(map[credentialstore.Reference][]byte),
		createRace: true,
	}
	racePrivate, racePublic, err := loadOrCreateKey(
		context.Background(),
		racing,
		reference,
		generate,
	)
	if err != nil {
		t.Fatalf("loadOrCreateKey(race): %v", err)
	}
	defer clear(racePrivate)
	defer clear(racePublic)
	if racing.createCalls != 1 || generated != 2 {
		t.Fatalf(
			"race calls = (create %d, generate %d)",
			racing.createCalls,
			generated,
		)
	}
}

type joinTestCredentialStore struct {
	mu sync.Mutex

	values      map[credentialstore.Reference][]byte
	createRace  bool
	createCalls int
}

func joinCredentialAuthorization(
	t testing.TB,
	journal pendingJournal,
	epoch uint64,
	epochPrivate ed25519.PrivateKey,
	notBefore time.Time,
) credentialauthorization.Authorization {
	t.Helper()
	binding, err := credential.SignBinding(
		journal.SessionID,
		journal.LocalDeviceID,
		epoch,
		epochPrivate.Public().(ed25519.PublicKey),
		identityPrivateForJoinFixture(t),
	)
	if err != nil {
		t.Fatal(err)
	}
	timestamp := domain.WholeSecondTimestamp(
		notBefore.UTC().Format(time.RFC3339),
	)
	authorization := credentialauthorization.Authorization{
		SessionID:                journal.SessionID,
		DeviceID:                 journal.LocalDeviceID,
		Epoch:                    epoch,
		EpochPublicKey:           binding.EpochPublicKey,
		KeyDigest:                binding.KeyDigest,
		Role:                     credentialauthorization.Role(device.RoleEditor),
		IssuedAt:                 timestamp,
		NotBefore:                timestamp,
		ValiditySeconds:          credentialauthorization.ValiditySeconds,
		AuthorityVoterSetVersion: 1,
		ClockEndorsements: []credentialauthorization.ClockEndorsement{{
			DeviceID: journal.InviterDeviceID,
		}},
		BindingSignature:        binding.Signature,
		AuthorizationChainIndex: epoch,
	}
	if err := authorization.Validate(); err != nil {
		t.Fatal(err)
	}
	return authorization
}

func identityPrivateForJoinFixture(t testing.TB) ed25519.PrivateKey {
	t.Helper()
	privateKey := ed25519.NewKeyFromSeed(
		bytes.Repeat([]byte{0x32}, ed25519.SeedSize),
	)
	t.Cleanup(func() { clear(privateKey) })
	return privateKey
}

func (store *joinTestCredentialStore) Get(
	ctx context.Context,
	reference credentialstore.Reference,
) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	value, found := store.values[reference]
	if !found {
		return nil, credentialstore.ErrNotFound
	}
	return bytes.Clone(value), nil
}

func (store *joinTestCredentialStore) Create(
	ctx context.Context,
	reference credentialstore.Reference,
	value []byte,
) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	store.createCalls++
	if _, found := store.values[reference]; found {
		return credentialstore.ErrAlreadyExists
	}
	if store.createRace {
		store.createRace = false
		replacement := ed25519.NewKeyFromSeed(
			bytes.Repeat([]byte{0x7f}, ed25519.SeedSize),
		)
		store.values[reference] = bytes.Clone(replacement)
		clear(replacement)
		return credentialstore.ErrAlreadyExists
	}
	store.values[reference] = bytes.Clone(value)
	return nil
}

func joinSnapshotRoot(
	t testing.TB,
	journal pendingJournal,
	privateKey ed25519.PrivateKey,
	chainIndex uint64,
) logicalsnapshot.Root {
	t.Helper()
	return signJoinSnapshotRoot(
		t,
		logicalsnapshot.RootInput{
			ArtifactID:              "snapshot-018f47de",
			SessionID:               journal.SessionID,
			WorkspaceID:             journal.WorkspaceID,
			RecoveryGeneration:      journal.RecoveryGeneration,
			CheckpointEventID:       "018f47de-89ab-7def-8123-5123456789ab",
			ChainIndex:              chainIndex,
			ChainHash:               chain.Digest(sha256.Sum256([]byte("chain"))),
			ResultIndex:             chainIndex,
			ResultHash:              chain.Digest(sha256.Sum256([]byte("result"))),
			ProjectionAccumulator:   chain.Digest(sha256.Sum256([]byte("accumulator"))),
			ProjectionStateDigest:   chain.Digest(sha256.Sum256([]byte("state"))),
			AuthorityVersion:        1,
			SignerDeviceID:          journal.InviterDeviceID,
			DigestVersion:           logicalsnapshot.SupportedDigestVersion,
			ProjectionSchemaVersion: logicalsnapshot.SupportedProjectionSchemaVersion,
			ContentEncoding:         logicalsnapshot.EncodingIdentity,
			ExpandedBytes:           128,
			CompressedBytes:         128,
			RecordCount:             chainIndex,
			DescriptorPageCount:     1,
			ChunkCount:              1,
			ArtifactDigest:          chain.Digest(sha256.Sum256([]byte("artifact"))),
			FinalDescriptorPageHash: chain.Digest(sha256.Sum256([]byte("page"))),
		},
		privateKey,
	)
}

func signJoinSnapshotRoot(
	t testing.TB,
	input logicalsnapshot.RootInput,
	privateKey ed25519.PrivateKey,
) logicalsnapshot.Root {
	t.Helper()
	unsigned, err := logicalsnapshot.NewUnsignedRoot(input)
	if err != nil {
		t.Fatalf("NewUnsignedRoot(): %v", err)
	}
	root, err := logicalsnapshot.SignRoot(unsigned, privateKey)
	if err != nil {
		t.Fatalf("SignRoot(): %v", err)
	}
	return root
}

var _ CredentialStore = (*joinTestCredentialStore)(nil)
