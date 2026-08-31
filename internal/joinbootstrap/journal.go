package joinbootstrap

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"path/filepath"

	"github.com/ijonahch/codecomm/internal/codec"
	"github.com/ijonahch/codecomm/internal/domain"
	"github.com/ijonahch/codecomm/internal/domain/device"
	"github.com/ijonahch/codecomm/internal/logicalsnapshot"
	"github.com/ijonahch/codecomm/internal/pairing"
)

const (
	journalSchemaVersion uint64 = 3
	journalSuffix               = ".join"
)

var (
	ErrInvalidJournal = errors.New("join bootstrap: invalid pending journal")
	ErrNoPendingJoin  = errors.New("join bootstrap: no pending join")
)

type journalPhase string

const (
	journalPhaseDecisionApproved journalPhase = "decision_approved"
	journalPhaseConfirmed        journalPhase = "confirmed"
	journalPhaseInstalling       journalPhase = "installing"
	journalPhaseInstallingOwned  journalPhase = "installing_owned"
)

type pendingJournal struct {
	Phase                    journalPhase
	AttemptID                domain.UUIDv7
	InviteID                 domain.UUIDv7
	InviteDigest             [sha256.Size]byte
	SessionID                domain.UUIDv7
	WorkspaceID              domain.UUIDv4
	RecoveryGeneration       uint64
	InviterDeviceID          domain.DeviceID
	InviterIdentityPublicKey [ed25519.PublicKeySize]byte
	SignedGenesisDigest      [sha256.Size]byte
	InitialCredentialEpoch   uint64
	CredentialEpoch          uint64
	LocalDeviceID            domain.DeviceID
	LocalIdentityPublicKey   [ed25519.PublicKeySize]byte
	LocalEpochPublicKey      [ed25519.PublicKeySize]byte
	Endpoints                []netip.AddrPort
	ApprovedRequestDigest    [sha256.Size]byte
	ApprovedRole             device.Role
	ApprovedDaemonVersion    string
	ApprovedMaxApplyLevel    uint64
	SnapshotRoot             []byte
	SnapshotSignerDeviceID   domain.DeviceID
	SnapshotSignerPublicKey  [ed25519.PublicKeySize]byte
	MinimumAuthorizationCut  uint64
}

type pendingJournalWire struct {
	SchemaVersion            uint64   `json:"schema_version"`
	Phase                    string   `json:"phase"`
	AttemptID                string   `json:"attempt_id"`
	InviteID                 string   `json:"invite_id"`
	InviteDigest             string   `json:"invite_digest"`
	SessionID                string   `json:"session_id"`
	WorkspaceID              string   `json:"workspace_id"`
	RecoveryGeneration       uint64   `json:"recovery_generation"`
	InviterDeviceID          string   `json:"inviter_device_id"`
	InviterIdentityPublicKey string   `json:"inviter_identity_public_key"`
	SignedGenesisDigest      string   `json:"signed_genesis_digest"`
	InitialCredentialEpoch   uint64   `json:"initial_credential_epoch"`
	CredentialEpoch          uint64   `json:"credential_epoch"`
	LocalDeviceID            string   `json:"local_device_id"`
	LocalIdentityPublicKey   string   `json:"local_identity_public_key"`
	LocalEpochPublicKey      string   `json:"local_epoch_public_key"`
	Endpoints                []string `json:"endpoints"`
	ApprovedRequestDigest    string   `json:"approved_request_digest"`
	ApprovedRole             string   `json:"approved_role"`
	ApprovedDaemonVersion    string   `json:"approved_daemon_version"`
	ApprovedMaxApplyLevel    uint64   `json:"approved_max_apply_level"`
	SnapshotRoot             string   `json:"snapshot_root"`
	SnapshotSignerDeviceID   string   `json:"snapshot_signer_device_id"`
	SnapshotSignerPublicKey  string   `json:"snapshot_signer_public_key"`
	MinimumAuthorizationCut  uint64   `json:"minimum_authorization_cut"`
}

func journalPath(statePath string) (string, error) {
	if statePath == "" ||
		!filepath.IsAbs(statePath) ||
		filepath.Clean(statePath) != statePath {
		return "", ErrInvalidJournal
	}
	return statePath + journalSuffix, nil
}

func prepareJournalDirectory(statePath string) error {
	path, err := journalPath(statePath)
	if err != nil {
		return err
	}
	parent := filepath.Dir(path)
	if err := validateJournalPath(parent); err != nil {
		return err
	}
	if err := os.MkdirAll(parent, 0o700); err != nil {
		return fmt.Errorf("%w: create parent: %v", ErrInvalidJournal, err)
	}
	info, err := os.Lstat(parent)
	if err != nil {
		return fmt.Errorf("%w: inspect parent: %v", ErrInvalidJournal, err)
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("%w: parent is not a real directory", ErrInvalidJournal)
	}
	if err := validateJournalDirectory(parent, info); err != nil {
		return err
	}
	return nil
}

func loadPendingJournal(statePath string) (pendingJournal, error) {
	path, err := journalPath(statePath)
	if err != nil {
		return pendingJournal{}, err
	}
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return pendingJournal{}, ErrNoPendingJoin
	}
	if err != nil {
		return pendingJournal{}, fmt.Errorf("%w: inspect: %v", ErrInvalidJournal, err)
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return pendingJournal{}, fmt.Errorf("%w: insecure file", ErrInvalidJournal)
	}
	if err := validateJournalFile(path, info); err != nil {
		return pendingJournal{}, err
	}
	encoded, err := os.ReadFile(path)
	if err != nil {
		return pendingJournal{}, fmt.Errorf("%w: read: %v", ErrInvalidJournal, err)
	}
	return decodePendingJournal(encoded)
}

func writePendingJournal(
	statePath string,
	journal pendingJournal,
) (resultErr error) {
	if err := prepareJournalDirectory(statePath); err != nil {
		return err
	}
	path, _ := journalPath(statePath)
	encoded, err := encodePendingJournal(journal)
	if err != nil {
		return err
	}
	file, err := os.CreateTemp(filepath.Dir(path), ".join-*.tmp")
	if err != nil {
		return fmt.Errorf("%w: create temporary file: %v", ErrInvalidJournal, err)
	}
	tempPath := file.Name()
	fileOpen := true
	defer func() {
		if fileOpen {
			resultErr = errors.Join(resultErr, file.Close())
		}
		if removeErr := os.Remove(tempPath); removeErr != nil &&
			!errors.Is(removeErr, os.ErrNotExist) {
			resultErr = errors.Join(resultErr, removeErr)
		}
	}()
	if err := file.Chmod(0o600); err != nil {
		return fmt.Errorf("%w: secure temporary file: %v", ErrInvalidJournal, err)
	}
	info, err := file.Stat()
	if err != nil {
		return fmt.Errorf("%w: inspect temporary file: %v", ErrInvalidJournal, err)
	}
	if err := validateJournalFile(tempPath, info); err != nil {
		return err
	}
	if _, err := file.Write(encoded); err != nil {
		return fmt.Errorf("%w: write temporary file: %v", ErrInvalidJournal, err)
	}
	if err := file.Sync(); err != nil {
		return fmt.Errorf("%w: sync temporary file: %v", ErrInvalidJournal, err)
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("%w: close temporary file: %v", ErrInvalidJournal, err)
	}
	fileOpen = false
	if err := os.Rename(tempPath, path); err != nil {
		return fmt.Errorf("%w: publish: %v", ErrInvalidJournal, err)
	}
	published, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("%w: inspect published file: %v", ErrInvalidJournal, err)
	}
	if err := validateJournalFile(path, published); err != nil {
		return err
	}
	if err := syncJournalDirectory(filepath.Dir(path)); err != nil {
		return fmt.Errorf("%w: sync parent: %v", ErrInvalidJournal, err)
	}
	return nil
}

func removePendingJournal(statePath string) error {
	path, err := journalPath(statePath)
	if err != nil {
		return err
	}
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("%w: remove: %v", ErrInvalidJournal, err)
	}
	if err := syncJournalDirectory(filepath.Dir(path)); err != nil {
		return fmt.Errorf("%w: sync removal: %v", ErrInvalidJournal, err)
	}
	return nil
}

func encodePendingJournal(journal pendingJournal) ([]byte, error) {
	if err := journal.validate(); err != nil {
		return nil, err
	}
	endpoints := make([]string, len(journal.Endpoints))
	for index, endpoint := range journal.Endpoints {
		endpoints[index] = endpoint.String()
	}
	raw, err := json.Marshal(pendingJournalWire{
		SchemaVersion:            journalSchemaVersion,
		Phase:                    string(journal.Phase),
		AttemptID:                string(journal.AttemptID),
		InviteID:                 string(journal.InviteID),
		InviteDigest:             codec.EncodeBase64URL(journal.InviteDigest[:]),
		SessionID:                string(journal.SessionID),
		WorkspaceID:              string(journal.WorkspaceID),
		RecoveryGeneration:       journal.RecoveryGeneration,
		InviterDeviceID:          string(journal.InviterDeviceID),
		InviterIdentityPublicKey: codec.EncodeBase64URL(journal.InviterIdentityPublicKey[:]),
		SignedGenesisDigest:      codec.EncodeBase64URL(journal.SignedGenesisDigest[:]),
		InitialCredentialEpoch:   journal.InitialCredentialEpoch,
		CredentialEpoch:          journal.CredentialEpoch,
		LocalDeviceID:            string(journal.LocalDeviceID),
		LocalIdentityPublicKey:   codec.EncodeBase64URL(journal.LocalIdentityPublicKey[:]),
		LocalEpochPublicKey:      codec.EncodeBase64URL(journal.LocalEpochPublicKey[:]),
		Endpoints:                endpoints,
		ApprovedRequestDigest:    codec.EncodeBase64URL(journal.ApprovedRequestDigest[:]),
		ApprovedRole:             string(journal.ApprovedRole),
		ApprovedDaemonVersion:    journal.ApprovedDaemonVersion,
		ApprovedMaxApplyLevel:    journal.ApprovedMaxApplyLevel,
		SnapshotRoot:             codec.EncodeBase64URL(journal.SnapshotRoot),
		SnapshotSignerDeviceID:   string(journal.SnapshotSignerDeviceID),
		SnapshotSignerPublicKey:  codec.EncodeBase64URL(journal.SnapshotSignerPublicKey[:]),
		MinimumAuthorizationCut:  journal.MinimumAuthorizationCut,
	})
	if err != nil {
		return nil, ErrInvalidJournal
	}
	canonical, err := codec.CanonicalizeSignedObject(raw)
	if err != nil {
		return nil, ErrInvalidJournal
	}
	return canonical, nil
}

func decodePendingJournal(encoded []byte) (pendingJournal, error) {
	if len(encoded) == 0 || len(encoded) > pairing.MaxPairingMessageBytes {
		return pendingJournal{}, ErrInvalidJournal
	}
	canonical, err := codec.CanonicalizeSignedObject(encoded)
	if err != nil || !bytes.Equal(canonical, encoded) {
		return pendingJournal{}, ErrInvalidJournal
	}
	var wire pendingJournalWire
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&wire); err != nil {
		return pendingJournal{}, ErrInvalidJournal
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return pendingJournal{}, ErrInvalidJournal
	}
	inviteDigest, inviteErr := codec.DecodeBase64URLExact(
		wire.InviteDigest,
		sha256.Size,
	)
	inviterKey, inviterErr := codec.DecodeBase64URLExact(
		wire.InviterIdentityPublicKey,
		ed25519.PublicKeySize,
	)
	genesisDigest, genesisErr := codec.DecodeBase64URLExact(
		wire.SignedGenesisDigest,
		sha256.Size,
	)
	localIdentity, identityErr := codec.DecodeBase64URLExact(
		wire.LocalIdentityPublicKey,
		ed25519.PublicKeySize,
	)
	localEpoch, epochErr := codec.DecodeBase64URLExact(
		wire.LocalEpochPublicKey,
		ed25519.PublicKeySize,
	)
	requestDigest, requestErr := codec.DecodeBase64URLExact(
		wire.ApprovedRequestDigest,
		sha256.Size,
	)
	snapshotRoot, snapshotErr := codec.DecodeBase64URL(wire.SnapshotRoot)
	if len(snapshotRoot) == 0 {
		snapshotRoot = nil
	}
	var snapshotSignerKey []byte
	var snapshotSignerErr error
	if wire.SnapshotSignerPublicKey != "" {
		snapshotSignerKey, snapshotSignerErr = codec.DecodeBase64URLExact(
			wire.SnapshotSignerPublicKey,
			ed25519.PublicKeySize,
		)
	}
	if wire.SchemaVersion != journalSchemaVersion ||
		inviteErr != nil ||
		inviterErr != nil ||
		genesisErr != nil ||
		identityErr != nil ||
		epochErr != nil ||
		requestErr != nil ||
		snapshotErr != nil ||
		snapshotSignerErr != nil ||
		len(wire.Endpoints) > pairing.MaxInviteEndpoints {
		return pendingJournal{}, ErrInvalidJournal
	}
	journal := pendingJournal{
		Phase:                   journalPhase(wire.Phase),
		AttemptID:               domain.UUIDv7(wire.AttemptID),
		InviteID:                domain.UUIDv7(wire.InviteID),
		SessionID:               domain.UUIDv7(wire.SessionID),
		WorkspaceID:             domain.UUIDv4(wire.WorkspaceID),
		RecoveryGeneration:      wire.RecoveryGeneration,
		InviterDeviceID:         domain.DeviceID(wire.InviterDeviceID),
		InitialCredentialEpoch:  wire.InitialCredentialEpoch,
		CredentialEpoch:         wire.CredentialEpoch,
		LocalDeviceID:           domain.DeviceID(wire.LocalDeviceID),
		ApprovedRole:            device.Role(wire.ApprovedRole),
		ApprovedDaemonVersion:   wire.ApprovedDaemonVersion,
		ApprovedMaxApplyLevel:   wire.ApprovedMaxApplyLevel,
		SnapshotRoot:            snapshotRoot,
		SnapshotSignerDeviceID:  domain.DeviceID(wire.SnapshotSignerDeviceID),
		MinimumAuthorizationCut: wire.MinimumAuthorizationCut,
		Endpoints:               make([]netip.AddrPort, len(wire.Endpoints)),
	}
	copy(journal.InviteDigest[:], inviteDigest)
	copy(journal.InviterIdentityPublicKey[:], inviterKey)
	copy(journal.SignedGenesisDigest[:], genesisDigest)
	copy(journal.LocalIdentityPublicKey[:], localIdentity)
	copy(journal.LocalEpochPublicKey[:], localEpoch)
	copy(journal.ApprovedRequestDigest[:], requestDigest)
	copy(journal.SnapshotSignerPublicKey[:], snapshotSignerKey)
	for index, endpoint := range wire.Endpoints {
		parsed, err := netip.ParseAddrPort(endpoint)
		if err != nil {
			return pendingJournal{}, ErrInvalidJournal
		}
		journal.Endpoints[index] = parsed
	}
	if err := journal.validate(); err != nil {
		return pendingJournal{}, err
	}
	expected, err := encodePendingJournal(journal)
	if err != nil || !bytes.Equal(expected, encoded) {
		return pendingJournal{}, ErrInvalidJournal
	}
	return journal, nil
}

func (journal pendingJournal) validate() error {
	if journal.Phase != journalPhaseDecisionApproved &&
		journal.Phase != journalPhaseConfirmed &&
		journal.Phase != journalPhaseInstalling &&
		journal.Phase != journalPhaseInstallingOwned ||
		!journal.AttemptID.Valid() ||
		!journal.InviteID.Valid() ||
		!journal.SessionID.Valid() ||
		!journal.WorkspaceID.Valid() ||
		!domain.ValidUnsignedInteger(journal.RecoveryGeneration) ||
		!journal.InviterDeviceID.Valid() ||
		journal.InitialCredentialEpoch < 1 ||
		!domain.ValidUnsignedInteger(journal.InitialCredentialEpoch) ||
		journal.CredentialEpoch < journal.InitialCredentialEpoch ||
		!domain.ValidUnsignedInteger(journal.CredentialEpoch) ||
		!journal.LocalDeviceID.Valid() ||
		!journal.ApprovedRole.Valid() ||
		journal.ApprovedDaemonVersion == "" ||
		journal.ApprovedMaxApplyLevel < 1 ||
		!domain.ValidUnsignedInteger(journal.ApprovedMaxApplyLevel) ||
		journal.ApprovedRequestDigest == [sha256.Size]byte{} ||
		len(journal.Endpoints) == 0 ||
		len(journal.Endpoints) > pairing.MaxInviteEndpoints {
		return ErrInvalidJournal
	}
	inviterID, inviterErr := device.DeriveID(
		journal.InviterIdentityPublicKey[:],
	)
	localID, localErr := device.DeriveID(
		journal.LocalIdentityPublicKey[:],
	)
	if inviterErr != nil ||
		inviterID != journal.InviterDeviceID ||
		localErr != nil ||
		localID != journal.LocalDeviceID {
		return ErrInvalidJournal
	}
	for index, endpoint := range journal.Endpoints {
		if !validJoinEndpoint(endpoint) {
			return ErrInvalidJournal
		}
		if index > 0 &&
			compareJoinEndpoints(journal.Endpoints[index-1], endpoint) >= 0 {
			return ErrInvalidJournal
		}
	}
	hasSnapshot := len(journal.SnapshotRoot) != 0 ||
		journal.SnapshotSignerDeviceID != "" ||
		journal.SnapshotSignerPublicKey !=
			[ed25519.PublicKeySize]byte{} ||
		journal.MinimumAuthorizationCut != 0
	requiresSnapshot := journal.Phase == journalPhaseInstalling ||
		journal.Phase == journalPhaseInstallingOwned
	if hasSnapshot != requiresSnapshot {
		return ErrInvalidJournal
	}
	if requiresSnapshot {
		if !journal.SnapshotSignerDeviceID.Valid() ||
			journal.MinimumAuthorizationCut < 1 ||
			!domain.ValidUnsignedInteger(
				journal.MinimumAuthorizationCut,
			) {
			return ErrInvalidJournal
		}
		signerID, err := device.DeriveID(
			journal.SnapshotSignerPublicKey[:],
		)
		if err != nil || signerID != journal.SnapshotSignerDeviceID {
			return ErrInvalidJournal
		}
		root, err := logicalsnapshot.ParseRoot(journal.SnapshotRoot)
		if err != nil {
			return ErrInvalidJournal
		}
		input := root.Unsigned().Input()
		if input.SessionID != journal.SessionID ||
			input.WorkspaceID != journal.WorkspaceID ||
			input.RecoveryGeneration != journal.RecoveryGeneration ||
			input.SignerDeviceID != journal.SnapshotSignerDeviceID ||
			input.ChainIndex < journal.MinimumAuthorizationCut ||
			logicalsnapshot.VerifyRoot(
				root,
				journal.SnapshotSignerPublicKey[:],
			) != nil {
			return ErrInvalidJournal
		}
	}
	return nil
}
