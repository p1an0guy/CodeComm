// Package joinbootstrap composes fresh-device pairing, credential recovery,
// and verified settled-nonvoter snapshot installation.
package joinbootstrap

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"time"

	"github.com/google/uuid"
	"github.com/ijonahch/codecomm/internal/consensus"
	"github.com/ijonahch/codecomm/internal/credential"
	codecommcrypto "github.com/ijonahch/codecomm/internal/crypto"
	"github.com/ijonahch/codecomm/internal/domain"
	"github.com/ijonahch/codecomm/internal/domain/credentialauthorization"
	"github.com/ijonahch/codecomm/internal/domain/device"
	"github.com/ijonahch/codecomm/internal/logicalsnapshot"
	"github.com/ijonahch/codecomm/internal/pairing"
	"github.com/ijonahch/codecomm/internal/pairingjoiner"
	"github.com/ijonahch/codecomm/internal/platform/credentialstore"
	"github.com/ijonahch/codecomm/internal/store"
)

const (
	CurrentDaemonVersion = "0.1.0"
	CurrentMaxApplyLevel = 1
)

var (
	ErrInvalidOptions = errors.New("join bootstrap: invalid options")
	ErrJoinDeclined   = errors.New("join bootstrap: pairing was not confirmed")
	ErrJoinIncomplete = errors.New("join bootstrap: pairing is not yet committed")
	ErrStateConflict  = errors.New("join bootstrap: destination state conflicts with join")
)

// CredentialStore is the narrow native-secret interface required by join.
type CredentialStore interface {
	Get(context.Context, credentialstore.Reference) ([]byte, error)
	Create(context.Context, credentialstore.Reference, []byte) error
}

// ConfirmationFunc presents the immutable pairing subject and returns the
// local operator's exact yes/no decision.
type ConfirmationFunc func(
	context.Context,
	pairingjoiner.ReviewSubject,
) (bool, error)

// Options configures either a new pairing attempt or a journal-only resume.
// Invite must be zero when Resume is true.
type Options struct {
	StatePath   string
	Credentials CredentialStore
	Invite      pairing.SignedInvite
	Resume      bool
	Confirm     ConfirmationFunc

	Dial func(context.Context, string, string) (net.Conn, error)
	Now  func() time.Time

	newUUIDv7       func() (domain.UUIDv7, error)
	generateKeyPair func() ([]byte, []byte, error)
	applyClock      consensus.ApplyClock
}

// Result identifies the locally installed settled-nonvoter session.
type Result struct {
	SessionID          domain.UUIDv7
	WorkspaceID        domain.UUIDv4
	RecoveryGeneration uint64
	DeviceID           domain.DeviceID
	StatePath          string
	Resumed            bool
}

// HasPending reports whether statePath has a durable nonsecret join journal.
func HasPending(statePath string) (bool, error) {
	path, err := journalPath(statePath)
	if err != nil {
		return false, err
	}
	_, err = os.Lstat(path)
	switch {
	case err == nil:
		if _, loadErr := loadPendingJournal(statePath); loadErr != nil {
			return false, loadErr
		}
		return true, nil
	case errors.Is(err, os.ErrNotExist):
		return false, nil
	default:
		return false, err
	}
}

// Run completes a new pairing or resumes the post-confirmation identity and
// content-plane bootstrap from a nonsecret journal.
func Run(
	ctx context.Context,
	options Options,
) (_ Result, resultErr error) {
	options = normalizeOptions(options)
	defer options.Invite.Clear()
	if err := validateOptions(ctx, options); err != nil {
		return Result{}, err
	}
	if err := prepareJournalDirectory(options.StatePath); err != nil {
		return Result{}, err
	}
	lock, err := acquireJoinLock(options.StatePath)
	if err != nil {
		return Result{}, err
	}
	defer func() {
		resultErr = errors.Join(resultErr, lock.Close())
	}()

	journal, err := loadPendingJournal(options.StatePath)
	resumed := err == nil
	switch {
	case resumed && !options.Resume:
		return Result{}, fmt.Errorf(
			"%w: resume the existing pending join",
			ErrStateConflict,
		)
	case errors.Is(err, ErrNoPendingJoin) && options.Resume:
		return Result{}, ErrNoPendingJoin
	case errors.Is(err, ErrNoPendingJoin):
		if err := requireUnusedDestination(options.StatePath); err != nil {
			return Result{}, err
		}
		journal, err = prepareNewJoin(ctx, options)
	case err != nil:
		return Result{}, err
	}
	if err != nil {
		return Result{}, err
	}
	if resumed &&
		(journal.Phase == journalPhaseDecisionApproved ||
			journal.Phase == journalPhaseConfirmed ||
			journal.Phase == journalPhaseInstalling) {
		if err := requireUnusedDestination(options.StatePath); err != nil {
			return Result{}, err
		}
	}

	identityPrivate, epochPrivate, err := loadJournalKeys(
		ctx,
		options.Credentials,
		journal,
	)
	if err != nil {
		return Result{}, err
	}
	defer clear(identityPrivate)
	defer clear(epochPrivate)

	bootID, err := options.newUUIDv7()
	if err != nil {
		return Result{}, fmt.Errorf("join bootstrap: generate boot ID: %w", err)
	}
	if journal.Phase == journalPhaseInstallingOwned {
		completed, err := verifyCompletedState(
			ctx,
			options.StatePath,
			journal,
			bootID,
		)
		if err != nil {
			return Result{}, err
		}
		if completed {
			if err := removePendingJournal(options.StatePath); err != nil {
				return Result{}, err
			}
			return journalResult(journal, options.StatePath, true), nil
		}
	}

	routes, err := newPinnedEndpoints(
		journal.InviterDeviceID,
		journal.Endpoints,
		options.Dial,
	)
	if err != nil {
		return Result{}, err
	}
	if !resumed {
		if err := completePairing(
			ctx,
			options,
			routes,
			identityPrivate,
			epochPrivate,
			&journal,
		); err != nil {
			return Result{}, err
		}
	}

	if err := completeBootstrap(
		ctx,
		options,
		routes,
		&journal,
		identityPrivate,
		epochPrivate,
		bootID,
	); err != nil {
		return Result{}, err
	}
	if err := removePendingJournal(options.StatePath); err != nil {
		return Result{}, err
	}
	return journalResult(journal, options.StatePath, resumed), nil
}

func normalizeOptions(options Options) Options {
	if options.Now == nil {
		options.Now = time.Now
	}
	if options.newUUIDv7 == nil {
		options.newUUIDv7 = func() (domain.UUIDv7, error) {
			value, err := uuid.NewV7()
			if err != nil {
				return "", err
			}
			result := domain.UUIDv7(value.String())
			if !result.Valid() {
				return "", domain.ErrInvalidUUIDv7
			}
			return result, nil
		}
	}
	if options.generateKeyPair == nil {
		options.generateKeyPair = codecommcrypto.GenerateEd25519KeyPair
	}
	if options.applyClock == nil {
		options.applyClock = consensus.NewSystemApplyClock()
	}
	return options
}

func validateOptions(ctx context.Context, options Options) error {
	if ctx == nil ||
		options.Credentials == nil ||
		options.Now == nil ||
		options.newUUIDv7 == nil ||
		options.generateKeyPair == nil ||
		options.applyClock == nil ||
		options.StatePath == "" ||
		!filepath.IsAbs(options.StatePath) ||
		filepath.Clean(options.StatePath) != options.StatePath ||
		options.Resume && len(options.Invite.CanonicalBytes()) != 0 ||
		!options.Resume &&
			(options.Confirm == nil || options.Invite.Validate() != nil) {
		return ErrInvalidOptions
	}
	return ctx.Err()
}

func prepareNewJoin(
	ctx context.Context,
	options Options,
) (pendingJournal, error) {
	invite := options.Invite.Invite()
	defer clear(invite.Secret[:])
	var identityPrivate, identityPublic []byte
	var err error
	switch invite.Mode {
	case pairing.ModeNew:
		identityPrivate, identityPublic, err = loadOrCreateKey(
			ctx,
			options.Credentials,
			credentialstore.IdentityReference(),
			options.generateKeyPair,
		)
	case pairing.ModeRebootstrap, pairing.ModeReadmission:
		identityPrivate, identityPublic, err = loadRetainedIdentity(
			ctx,
			options.Credentials,
			invite.SubjectDeviceID,
		)
	default:
		err = ErrInvalidOptions
	}
	if err != nil {
		return pendingJournal{}, err
	}
	defer clear(identityPrivate)
	defer clear(identityPublic)
	localDeviceID, err := device.DeriveID(identityPublic)
	if err != nil {
		return pendingJournal{}, err
	}
	epochReference, err := credentialstore.EpochReference(
		invite.SessionID,
		localDeviceID,
		invite.InitialCredentialEpoch,
	)
	if err != nil {
		return pendingJournal{}, err
	}
	epochPrivate, epochPublic, err := loadOrCreateKey(
		ctx,
		options.Credentials,
		epochReference,
		options.generateKeyPair,
	)
	if err != nil {
		return pendingJournal{}, err
	}
	defer clear(epochPrivate)
	defer clear(epochPublic)
	attemptID, err := options.newUUIDv7()
	if err != nil {
		return pendingJournal{}, err
	}
	journal := pendingJournal{
		Phase:                    journalPhaseDecisionApproved,
		AttemptID:                attemptID,
		InviteID:                 invite.InviteID,
		InviteDigest:             options.Invite.Digest(),
		SessionID:                invite.SessionID,
		WorkspaceID:              invite.WorkspaceID,
		RecoveryGeneration:       invite.RecoveryGeneration,
		InviterDeviceID:          invite.InviterDeviceID,
		InviterIdentityPublicKey: invite.InviterIdentityPublicKey,
		SignedGenesisDigest:      invite.SignedGenesisDigest,
		Mode:                     invite.Mode,
		InitialCredentialEpoch:   invite.InitialCredentialEpoch,
		CredentialEpoch:          invite.InitialCredentialEpoch,
		LocalDeviceID:            localDeviceID,
		ApprovedRole:             invite.Role,
		ApprovedDaemonVersion:    CurrentDaemonVersion,
		ApprovedMaxApplyLevel:    CurrentMaxApplyLevel,
		Endpoints: make(
			[]netip.AddrPort,
			len(invite.Endpoints),
		),
	}
	if invite.SubjectDeviceID != nil {
		subject := *invite.SubjectDeviceID
		journal.SubjectDeviceID = &subject
	}
	journal.ExpectedEntityVersion = cloneJournalUint64(
		invite.ExpectedEntityVersion,
	)
	copy(journal.LocalIdentityPublicKey[:], identityPublic)
	copy(journal.LocalEpochPublicKey[:], epochPublic)
	for index, endpoint := range invite.Endpoints {
		journal.Endpoints[index] = netip.AddrPortFrom(
			endpoint.IP,
			endpoint.Port,
		)
	}
	return journal, nil
}

func loadRetainedIdentity(
	ctx context.Context,
	secrets CredentialStore,
	subject *domain.DeviceID,
) ([]byte, []byte, error) {
	if ctx == nil || secrets == nil || subject == nil || !subject.Valid() {
		return nil, nil, ErrInvalidOptions
	}
	privateKey, err := secrets.Get(
		ctx,
		credentialstore.IdentityReference(),
	)
	if err != nil {
		if errors.Is(err, credentialstore.ErrNotFound) {
			return nil, nil, fmt.Errorf(
				"%w: retained installation identity is unavailable",
				ErrStateConflict,
			)
		}
		return nil, nil, err
	}
	publicKey, err :=
		codecommcrypto.Ed25519PublicKeyFromPrivateKey(privateKey)
	if err != nil {
		clear(privateKey)
		return nil, nil, fmt.Errorf(
			"%w: retained installation identity is invalid",
			ErrStateConflict,
		)
	}
	deviceID, err := device.DeriveID(publicKey)
	if err != nil || deviceID != *subject {
		clear(publicKey)
		clear(privateKey)
		return nil, nil, fmt.Errorf(
			"%w: retained installation identity does not match invite subject",
			ErrStateConflict,
		)
	}
	return privateKey, publicKey, nil
}

func requireUnusedDestination(statePath string) error {
	for _, path := range []string{
		statePath,
		statePath + "-journal",
		statePath + "-shm",
		statePath + "-wal",
	} {
		_, err := os.Lstat(path)
		switch {
		case errors.Is(err, os.ErrNotExist):
			continue
		case err != nil:
			return err
		default:
			return ErrStateConflict
		}
	}
	return nil
}

func loadOrCreateKey(
	ctx context.Context,
	secrets CredentialStore,
	reference credentialstore.Reference,
	generate func() ([]byte, []byte, error),
) ([]byte, []byte, error) {
	privateKey, err := secrets.Get(ctx, reference)
	if err == nil {
		publicKey, publicErr :=
			codecommcrypto.Ed25519PublicKeyFromPrivateKey(privateKey)
		if publicErr != nil {
			clear(privateKey)
			return nil, nil, publicErr
		}
		return privateKey, publicKey, nil
	}
	if !errors.Is(err, credentialstore.ErrNotFound) {
		return nil, nil, err
	}
	publicKey, privateKey, err := generate()
	if err != nil {
		return nil, nil, err
	}
	if err := secrets.Create(ctx, reference, privateKey); err != nil {
		clear(publicKey)
		clear(privateKey)
		if errors.Is(err, credentialstore.ErrAlreadyExists) {
			return loadOrCreateKey(ctx, secrets, reference, generate)
		}
		return nil, nil, err
	}
	return privateKey, publicKey, nil
}

func loadJournalKeys(
	ctx context.Context,
	secrets CredentialStore,
	journal pendingJournal,
) ([]byte, []byte, error) {
	identityPrivate, err := secrets.Get(
		ctx,
		credentialstore.IdentityReference(),
	)
	if err != nil {
		return nil, nil, err
	}
	identityPublic, err :=
		codecommcrypto.Ed25519PublicKeyFromPrivateKey(identityPrivate)
	if err != nil ||
		!bytes.Equal(identityPublic, journal.LocalIdentityPublicKey[:]) {
		clear(identityPublic)
		clear(identityPrivate)
		return nil, nil, ErrStateConflict
	}
	clear(identityPublic)
	epochReference, err := credentialstore.EpochReference(
		journal.SessionID,
		journal.LocalDeviceID,
		journal.CredentialEpoch,
	)
	if err != nil {
		clear(identityPrivate)
		return nil, nil, err
	}
	epochPrivate, err := secrets.Get(ctx, epochReference)
	if err != nil {
		clear(identityPrivate)
		return nil, nil, err
	}
	epochPublic, err :=
		codecommcrypto.Ed25519PublicKeyFromPrivateKey(epochPrivate)
	if err != nil ||
		!bytes.Equal(epochPublic, journal.LocalEpochPublicKey[:]) {
		clear(epochPublic)
		clear(epochPrivate)
		clear(identityPrivate)
		return nil, nil, ErrStateConflict
	}
	clear(epochPublic)
	return identityPrivate, epochPrivate, nil
}

func completePairing(
	ctx context.Context,
	options Options,
	routes *pinnedEndpoints,
	identityPrivate []byte,
	epochPrivate []byte,
	journal *pendingJournal,
) error {
	joiner, err := pairingjoiner.New(pairingjoiner.Options{
		Invite:                 options.Invite,
		IdentityPrivateKey:     identityPrivate,
		InitialEpochPrivateKey: epochPrivate,
		AttemptID:              journal.AttemptID,
		DaemonVersion:          CurrentDaemonVersion,
		MaxApplyLevel:          CurrentMaxApplyLevel,
		Dialer:                 routes,
	})
	if err != nil {
		return err
	}
	defer joiner.Close()
	review, err := joiner.Begin(ctx)
	if err != nil {
		return err
	}
	if !reviewMatchesJournal(review, *journal) {
		return ErrStateConflict
	}
	confirmed, err := options.Confirm(ctx, review)
	if err != nil {
		return err
	}
	if confirmed {
		journal.ApprovedRequestDigest = review.RequestDigest
		journal.Phase = journalPhaseDecisionApproved
		if err := writePendingJournal(
			options.StatePath,
			*journal,
		); err != nil {
			return err
		}
	}
	result, err := joiner.Decide(ctx, confirmed)
	if err != nil {
		return err
	}
	if result.Confirmation.Status != pairing.StatusConfirmed {
		if terminalPairingStatus(result.Confirmation.Status) {
			_ = removePendingJournal(options.StatePath)
		}
		return ErrJoinDeclined
	}
	journal.Phase = journalPhaseConfirmed
	return writePendingJournal(options.StatePath, *journal)
}

func reviewMatchesJournal(
	review pairingjoiner.ReviewSubject,
	journal pendingJournal,
) bool {
	return review.AttemptID == journal.AttemptID &&
		review.InviteID == journal.InviteID &&
		review.InviteDigest == journal.InviteDigest &&
		review.SessionID == journal.SessionID &&
		review.WorkspaceID == journal.WorkspaceID &&
		review.RecoveryGeneration == journal.RecoveryGeneration &&
		review.InviterDeviceID == journal.InviterDeviceID &&
		review.InviterIdentityPublicKey ==
			journal.InviterIdentityPublicKey &&
		review.SignedGenesisDigest == journal.SignedGenesisDigest &&
		review.Mode == journal.Mode &&
		equalJournalDeviceID(
			review.SubjectDeviceID,
			journal.SubjectDeviceID,
		) &&
		equalJournalUint64(
			review.ExpectedEntityVersion,
			journal.ExpectedEntityVersion,
		) &&
		review.Core.JoinerDeviceID == journal.LocalDeviceID &&
		review.Core.JoinerIdentityPublicKey ==
			journal.LocalIdentityPublicKey &&
		(review.RequestDigest == journal.ApprovedRequestDigest ||
			journal.ApprovedRequestDigest == [sha256.Size]byte{}) &&
		review.Core.InitialEpochBinding.Epoch ==
			journal.InitialCredentialEpoch &&
		journal.CredentialEpoch == journal.InitialCredentialEpoch &&
		review.Core.InitialEpochBinding.EpochPublicKey ==
			journal.LocalEpochPublicKey &&
		review.Role == journal.ApprovedRole &&
		review.Core.DaemonVersion == journal.ApprovedDaemonVersion &&
		review.Core.MaxApplyLevel == journal.ApprovedMaxApplyLevel
}

func equalJournalDeviceID(left, right *domain.DeviceID) bool {
	return left == nil && right == nil ||
		left != nil && right != nil && *left == *right
}

func equalJournalUint64(left, right *uint64) bool {
	return left == nil && right == nil ||
		left != nil && right != nil && *left == *right
}

func terminalPairingStatus(status pairing.ConfirmationStatus) bool {
	return status == pairing.StatusConfirmed ||
		status == pairing.StatusDeclined ||
		status == pairing.StatusExpired ||
		status == pairing.StatusRevoked
}

func verifyCompletedState(
	ctx context.Context,
	statePath string,
	journal pendingJournal,
	bootID domain.UUIDv7,
) (bool, error) {
	expectedRoot, err := logicalsnapshot.ParseRoot(journal.SnapshotRoot)
	if err != nil {
		return false, ErrStateConflict
	}
	info, err := os.Lstat(statePath)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return false, ErrStateConflict
	}
	if err := validateJournalFile(statePath, info); err != nil {
		return false, errors.Join(ErrStateConflict, err)
	}
	database, err := store.Open(ctx, store.Options{Path: statePath})
	if err != nil {
		return false, err
	}
	mode, modeErr := database.ReplicaEvidenceMode(ctx)
	baseline, baselineFound, baselineErr :=
		database.VerifiedStandaloneLogicalSnapshotBaseline(ctx)
	historyErr := database.VerifyCommitmentHistory(ctx)
	closeErr := database.Close()
	if modeErr != nil {
		if errors.Is(modeErr, store.ErrReplicaEvidenceMode) {
			return false, errors.Join(closeErr, baselineErr, historyErr)
		}
		return false, errors.Join(modeErr, closeErr)
	}
	if mode != store.ReplicaEvidenceSettledNonvoter {
		return false, errors.Join(ErrStateConflict, closeErr)
	}
	if baselineErr != nil ||
		!baselineFound ||
		!bytes.Equal(
			baseline.CanonicalBytes(),
			journal.SnapshotRoot,
		) ||
		historyErr != nil ||
		closeErr != nil {
		return false, errors.Join(
			ErrStateConflict,
			baselineErr,
			historyErr,
			closeErr,
		)
	}
	replica, err := consensus.OpenSettledReplica(
		ctx,
		consensus.SettledReplicaOptions{
			StatePath:     statePath,
			OriginBootID:  bootID,
			LocalDeviceID: journal.LocalDeviceID,
		},
	)
	if err != nil {
		return false, err
	}
	view, viewErr := replica.View(ctx)
	admission, admissionErr := replica.PeerAdmissionSnapshot()
	closeErr = replica.Close()
	if viewErr != nil || admissionErr != nil {
		return false, errors.Join(viewErr, admissionErr, closeErr)
	}
	input := expectedRoot.Unsigned().Input()
	if view.SessionID != journal.SessionID ||
		view.WorkspaceID != journal.WorkspaceID ||
		view.RecoveryGeneration != journal.RecoveryGeneration ||
		input.SessionID != view.SessionID ||
		input.WorkspaceID != view.WorkspaceID ||
		input.RecoveryGeneration != view.RecoveryGeneration ||
		input.ChainIndex != view.Heads.ChainIndex ||
		store.Digest(input.ChainHash) != view.Heads.ChainHash ||
		input.ResultIndex != view.Heads.ResultIndex ||
		store.Digest(input.ResultHash) != view.Heads.ResultHash ||
		store.Digest(input.ProjectionAccumulator) !=
			view.Heads.ProjectionAccumulator ||
		store.Digest(input.ProjectionStateDigest) !=
			view.ProjectionStateDigest {
		return false, errors.Join(ErrStateConflict, closeErr)
	}
	local, localFound := admission.Member(journal.LocalDeviceID)
	inviter, inviterFound := admission.Member(journal.InviterDeviceID)
	signer, signerFound := admission.Member(
		journal.SnapshotSignerDeviceID,
	)
	authorization, authorizationFound := admission.Authorization(
		credentialauthorization.Key{
			SessionID: journal.SessionID,
			DeviceID:  journal.LocalDeviceID,
			Epoch:     journal.CredentialEpoch,
		},
	)
	binding := credential.Binding{
		SessionID:      authorization.SessionID,
		DeviceID:       authorization.DeviceID,
		Epoch:          authorization.Epoch,
		EpochPublicKey: authorization.EpochPublicKey,
		KeyDigest:      authorization.KeyDigest,
		Signature:      authorization.BindingSignature,
	}
	if !localFound ||
		local.Role != journal.ApprovedRole ||
		local.DaemonVersion != journal.ApprovedDaemonVersion ||
		local.MaxApplyLevel != journal.ApprovedMaxApplyLevel ||
		local.Status != device.StatusActive ||
		!joinEntityVersionMatches(journal, local.EntityVersion) ||
		!bytes.Equal(
			local.IdentityPublicKey,
			journal.LocalIdentityPublicKey[:],
		) ||
		!inviterFound ||
		!bytes.Equal(
			inviter.IdentityPublicKey,
			journal.InviterIdentityPublicKey[:],
		) ||
		!signerFound ||
		!bytes.Equal(
			signer.IdentityPublicKey,
			journal.SnapshotSignerPublicKey[:],
		) ||
		!authorizationFound ||
		authorization.AuthorizationChainIndex <
			journal.MinimumAuthorizationCut ||
		string(authorization.Role) != string(journal.ApprovedRole) ||
		binding.Validate(journal.LocalIdentityPublicKey[:]) != nil ||
		authorization.EpochPublicKey != journal.LocalEpochPublicKey {
		return false, errors.Join(ErrStateConflict, closeErr)
	}
	return true, closeErr
}

func joinEntityVersionMatches(
	journal pendingJournal,
	entityVersion uint64,
) bool {
	if entityVersion < 1 || !domain.ValidUnsignedInteger(entityVersion) {
		return false
	}
	switch journal.Mode {
	case pairing.ModeNew:
		return entityVersion == 1
	case pairing.ModeRebootstrap:
		return true
	case pairing.ModeReadmission:
		return journal.ExpectedEntityVersion != nil &&
			*journal.ExpectedEntityVersion < domain.MaxSafeInteger &&
			entityVersion == *journal.ExpectedEntityVersion+1
	default:
		return false
	}
}

func journalResult(
	journal pendingJournal,
	statePath string,
	resumed bool,
) Result {
	return Result{
		SessionID:          journal.SessionID,
		WorkspaceID:        journal.WorkspaceID,
		RecoveryGeneration: journal.RecoveryGeneration,
		DeviceID:           journal.LocalDeviceID,
		StatePath:          statePath,
		Resumed:            resumed,
	}
}

func credentialBinding(
	journal pendingJournal,
	identityPrivate []byte,
) (credential.Binding, error) {
	return credential.SignBinding(
		journal.SessionID,
		journal.LocalDeviceID,
		journal.CredentialEpoch,
		journal.LocalEpochPublicKey[:],
		identityPrivate,
	)
}

func clearTLSCertificate(certificate *tls.Certificate) {
	if certificate == nil {
		return
	}
	for index := range certificate.Certificate {
		clear(certificate.Certificate[index])
	}
	switch key := certificate.PrivateKey.(type) {
	case ed25519.PrivateKey:
		clear(key)
	case []byte:
		clear(key)
	}
	*certificate = tls.Certificate{}
}
