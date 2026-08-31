package joinbootstrap

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"

	"github.com/ijonahch/codecomm/internal/codec"
	"github.com/ijonahch/codecomm/internal/domain"
	"github.com/ijonahch/codecomm/internal/domain/device"
)

func TestPendingJournalRoundTripIsCanonicalAndContainsNoSecrets(
	t *testing.T,
) {
	t.Parallel()

	journal, inviterPrivate, localPrivate := joinJournalFixture(t)
	encoded, err := encodePendingJournal(journal)
	if err != nil {
		t.Fatalf("encodePendingJournal(): %v", err)
	}
	canonical, err := codec.CanonicalizeSignedObject(encoded)
	if err != nil || !bytes.Equal(canonical, encoded) {
		t.Fatalf("journal is not canonical: %v", err)
	}
	decoded, err := decodePendingJournal(encoded)
	if err != nil {
		t.Fatalf("decodePendingJournal(): %v", err)
	}
	if !reflect.DeepEqual(decoded, journal) {
		t.Fatalf("decoded journal = %#v, want %#v", decoded, journal)
	}

	var fields map[string]json.RawMessage
	if err := json.Unmarshal(encoded, &fields); err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{
		"secret",
		"private",
		"invite_code",
	} {
		for name := range fields {
			if strings.Contains(name, forbidden) {
				t.Fatalf("journal persists forbidden field %q", name)
			}
		}
	}
	var inviteSecret [16]byte
	for index := range inviteSecret {
		inviteSecret[index] = byte(index + 1)
	}
	for name, secret := range map[string][]byte{
		"inviter private key": inviterPrivate,
		"local private key":   localPrivate,
		"invite secret":       inviteSecret[:],
	} {
		if bytes.Contains(
			encoded,
			[]byte(codec.EncodeBase64URL(secret)),
		) {
			t.Fatalf("journal contains %s", name)
		}
	}
}

func TestPendingJournalRejectsMutationAndNoncanonicalForms(t *testing.T) {
	t.Parallel()

	journal, _, _ := joinJournalFixture(t)
	encoded, err := encodePendingJournal(journal)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := decodePendingJournal(
		append(bytes.Clone(encoded), ' '),
	); !errors.Is(err, ErrInvalidJournal) {
		t.Fatalf("noncanonical journal error = %v", err)
	}

	var fields map[string]json.RawMessage
	if err := json.Unmarshal(encoded, &fields); err != nil {
		t.Fatal(err)
	}
	fields["invite_secret"] = json.RawMessage(`"not-secret"`)
	raw, err := json.Marshal(fields)
	if err != nil {
		t.Fatal(err)
	}
	unknown, err := codec.CanonicalizeSignedObject(raw)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := decodePendingJournal(
		unknown,
	); !errors.Is(err, ErrInvalidJournal) {
		t.Fatalf("unknown-field journal error = %v", err)
	}

	for name, mutate := range map[string]func(*pendingJournal){
		"phase": func(candidate *pendingJournal) {
			candidate.Phase = "prepared"
		},
		"credential epoch regresses": func(candidate *pendingJournal) {
			candidate.CredentialEpoch = 0
		},
		"missing approved request": func(candidate *pendingJournal) {
			candidate.ApprovedRequestDigest = [sha256.Size]byte{}
		},
		"inviter identity": func(candidate *pendingJournal) {
			candidate.InviterIdentityPublicKey[0] ^= 0xff
		},
		"local identity": func(candidate *pendingJournal) {
			candidate.LocalIdentityPublicKey[0] ^= 0xff
		},
		"duplicate endpoint": func(candidate *pendingJournal) {
			candidate.Endpoints[1] = candidate.Endpoints[0]
		},
		"unsorted endpoint": func(candidate *pendingJournal) {
			candidate.Endpoints[0], candidate.Endpoints[1] =
				candidate.Endpoints[1], candidate.Endpoints[0]
		},
	} {
		t.Run(name, func(t *testing.T) {
			candidate := journal
			candidate.Endpoints = append(
				[]netip.AddrPort(nil),
				journal.Endpoints...,
			)
			mutate(&candidate)
			if _, err := encodePendingJournal(
				candidate,
			); !errors.Is(err, ErrInvalidJournal) {
				t.Fatalf("encode error = %v", err)
			}
		})
	}
}

func TestPendingJournalDurablyWritesAndRemoves(t *testing.T) {
	journal, _, _ := joinJournalFixture(t)
	statePath := filepath.Join(t.TempDir(), "state", "session.db")
	if err := writePendingJournal(statePath, journal); err != nil {
		t.Fatalf("writePendingJournal(): %v", err)
	}
	path, err := journalPath(statePath)
	if err != nil {
		t.Fatal(err)
	}
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		t.Fatalf("journal mode = %s", info.Mode())
	}
	if runtime.GOOS != "windows" && info.Mode().Perm() != 0o600 {
		t.Fatalf("journal permissions = %04o", info.Mode().Perm())
	}
	loaded, err := loadPendingJournal(statePath)
	if err != nil || !reflect.DeepEqual(loaded, journal) {
		t.Fatalf("loadPendingJournal() = (%#v, %v)", loaded, err)
	}
	pending, err := HasPending(statePath)
	if err != nil || !pending {
		t.Fatalf("HasPending() = (%t, %v)", pending, err)
	}
	if err := removePendingJournal(statePath); err != nil {
		t.Fatalf("removePendingJournal(): %v", err)
	}
	pending, err = HasPending(statePath)
	if err != nil || pending {
		t.Fatalf("HasPending(after removal) = (%t, %v)", pending, err)
	}
}

func TestRequireUnusedDestinationRejectsDatabaseAndSidecars(t *testing.T) {
	t.Parallel()

	for _, suffix := range []string{"", "-journal", "-shm", "-wal"} {
		t.Run(suffix, func(t *testing.T) {
			statePath := filepath.Join(t.TempDir(), "state.db")
			if err := os.WriteFile(
				statePath+suffix,
				[]byte("occupied"),
				0o600,
			); err != nil {
				t.Fatal(err)
			}
			if err := requireUnusedDestination(
				statePath,
			); !errors.Is(err, ErrStateConflict) {
				t.Fatalf("requireUnusedDestination() error = %v", err)
			}
		})
	}
	if err := requireUnusedDestination(
		filepath.Join(t.TempDir(), "unused.db"),
	); err != nil {
		t.Fatalf("unused destination error = %v", err)
	}
}

func TestJoinLockExcludesAnotherProcessHandle(t *testing.T) {
	statePath := filepath.Join(t.TempDir(), "join", "state.db")
	if err := prepareJournalDirectory(statePath); err != nil {
		t.Fatal(err)
	}
	first, err := acquireJoinLock(statePath)
	if err != nil {
		t.Fatalf("acquireJoinLock(first): %v", err)
	}
	if _, err := acquireJoinLock(statePath); !errors.Is(
		err,
		ErrStateConflict,
	) {
		t.Fatalf("acquireJoinLock(contended) error = %v", err)
	}
	if err := first.Close(); err != nil {
		t.Fatalf("close first lock: %v", err)
	}
	second, err := acquireJoinLock(statePath)
	if err != nil {
		t.Fatalf("acquireJoinLock(after close): %v", err)
	}
	if err := second.Close(); err != nil {
		t.Fatalf("close second lock: %v", err)
	}
}

func joinJournalFixture(
	t testing.TB,
) (pendingJournal, ed25519.PrivateKey, ed25519.PrivateKey) {
	t.Helper()
	inviterPrivate, inviterPublic, inviterID := joinTestIdentity(t, 0x31)
	localPrivate, localPublic, localID := joinTestIdentity(t, 0x32)
	epochPrivate := ed25519.NewKeyFromSeed(
		bytes.Repeat([]byte{0x33}, ed25519.SeedSize),
	)
	t.Cleanup(func() { clear(epochPrivate) })
	epochPublic := epochPrivate.Public().(ed25519.PublicKey)
	journal := pendingJournal{
		Phase:                  journalPhaseDecisionApproved,
		AttemptID:              "018f47de-89ab-7def-8123-1123456789ab",
		InviteID:               "018f47de-89ab-7def-8123-2123456789ab",
		InviteDigest:           sha256.Sum256([]byte("invite")),
		SessionID:              "018f47de-89ab-7def-8123-3123456789ab",
		WorkspaceID:            "550e8400-e29b-41d4-a716-446655440000",
		RecoveryGeneration:     0,
		InviterDeviceID:        inviterID,
		SignedGenesisDigest:    sha256.Sum256([]byte("genesis")),
		InitialCredentialEpoch: 1,
		CredentialEpoch:        1,
		LocalDeviceID:          localID,
		ApprovedRequestDigest:  sha256.Sum256([]byte("request")),
		ApprovedRole:           device.RoleEditor,
		ApprovedDaemonVersion:  CurrentDaemonVersion,
		ApprovedMaxApplyLevel:  CurrentMaxApplyLevel,
		Endpoints: []netip.AddrPort{
			netip.MustParseAddrPort("10.0.0.5:47831"),
			netip.MustParseAddrPort("[2001:db8::5]:47831"),
		},
	}
	copy(journal.InviterIdentityPublicKey[:], inviterPublic)
	copy(journal.LocalIdentityPublicKey[:], localPublic)
	copy(journal.LocalEpochPublicKey[:], epochPublic)
	return journal, inviterPrivate, localPrivate
}

func joinTestIdentity(
	t testing.TB,
	seed byte,
) (ed25519.PrivateKey, ed25519.PublicKey, domain.DeviceID) {
	t.Helper()
	privateKey := ed25519.NewKeyFromSeed(
		bytes.Repeat([]byte{seed}, ed25519.SeedSize),
	)
	publicKey := privateKey.Public().(ed25519.PublicKey)
	deviceID, err := device.DeriveID(publicKey)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { clear(privateKey) })
	return privateKey, publicKey, deviceID
}
