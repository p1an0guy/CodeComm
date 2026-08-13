package agent

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/ijonahch/codecomm/internal/domain"
	"github.com/ijonahch/codecomm/internal/store"
)

var (
	ErrManagedRootDestinationExists = errors.New(
		"agent: managed-root destination already exists",
	)
	ErrManagedRootIdentityChanged = errors.New(
		"agent: managed-root filesystem identity changed",
	)
	ErrManagedRootCleanup = errors.New(
		"agent: managed-root cleanup refused",
	)
)

// ManagedRootOptions identifies a destination that CodeComm must create.
// RepositoryCommonDirectory must come from trusted Git discovery, never agent
// or model input. Its stored identity is always derived from the directory.
type ManagedRootOptions struct {
	DestinationPath           string
	RepositoryCommonDirectory string
	Kind                      store.ManagedRootKind
}

// ManagedRootHandle is the local handle returned after durable registration.
type ManagedRootHandle struct {
	ManagedRootID domain.UUIDv7
	CanonicalPath string
	Kind          store.ManagedRootKind
}

type nativeDirectoryIdentity struct {
	canonicalPath string
	value         string
}

// CreateManagedRoot creates and registers a new CodeComm-owned directory.
// Any pre-existing destination is refused, including an empty directory.
func (service *Service) CreateManagedRoot(
	ctx context.Context,
	options ManagedRootOptions,
) (ManagedRootHandle, error) {
	if ctx == nil {
		return ManagedRootHandle{}, ErrInvalidOptions
	}
	if err := ctx.Err(); err != nil {
		return ManagedRootHandle{}, err
	}
	if err := service.available(); err != nil {
		return ManagedRootHandle{}, err
	}
	if options.DestinationPath == "" ||
		options.RepositoryCommonDirectory == "" ||
		!validManagedRootKind(options.Kind) {
		return ManagedRootHandle{}, ErrInvalidOptions
	}

	destination, err := filepath.Abs(options.DestinationPath)
	if err != nil {
		return ManagedRootHandle{}, fmt.Errorf(
			"agent: resolve managed-root destination: %w",
			err,
		)
	}
	destination = filepath.Clean(destination)

	repository, err := inspectNativeDirectory(
		options.RepositoryCommonDirectory,
	)
	if err != nil {
		return ManagedRootHandle{}, fmt.Errorf(
			"agent: inspect repository common directory: %w",
			err,
		)
	}
	generation, err := service.local.CurrentRecoveryGeneration(
		ctx,
		service.sessionID,
		service.workspaceID,
	)
	if err != nil {
		return ManagedRootHandle{}, fmt.Errorf(
			"agent: read managed-root generation: %w",
			err,
		)
	}
	managedRootID, err := service.generateID()
	if err != nil {
		return ManagedRootHandle{}, fmt.Errorf(
			"agent: generate managed-root ID: %w",
			err,
		)
	}
	if !managedRootID.Valid() {
		return ManagedRootHandle{}, ErrInvalidOptions
	}
	verifiedAt := service.clock()
	if !verifiedAt.Valid() {
		return ManagedRootHandle{}, ErrInvalidOptions
	}

	if err := os.Mkdir(destination, 0o700); err != nil {
		if errors.Is(err, fs.ErrExist) {
			return ManagedRootHandle{}, fmt.Errorf(
				"%w: %w",
				ErrManagedRootDestinationExists,
				err,
			)
		}
		return ManagedRootHandle{}, fmt.Errorf(
			"agent: create managed-root destination: %w",
			err,
		)
	}

	root, err := inspectNativeDirectory(destination)
	if err != nil {
		// The directory cannot be proven to still be the object just created,
		// so leave it in place rather than risk deleting a replacement.
		return ManagedRootHandle{}, fmt.Errorf(
			"agent: inspect created managed root: %w",
			err,
		)
	}
	fail := func(cause error) (ManagedRootHandle, error) {
		cleanupErr := removeOwnedEmptyDirectory(root)
		if cleanupErr != nil {
			return ManagedRootHandle{}, errors.Join(cause, cleanupErr)
		}
		return ManagedRootHandle{}, cause
	}

	currentRepository, err := inspectNativeDirectory(
		options.RepositoryCommonDirectory,
	)
	if err != nil {
		return fail(fmt.Errorf(
			"agent: revalidate repository common directory: %w",
			err,
		))
	}
	if currentRepository.value != repository.value {
		return fail(ErrManagedRootIdentityChanged)
	}
	currentRoot, err := inspectNativeDirectory(root.canonicalPath)
	if err != nil {
		return fail(fmt.Errorf("agent: revalidate managed root: %w", err))
	}
	if currentRoot.value != root.value {
		return fail(ErrManagedRootIdentityChanged)
	}
	if err := service.available(); err != nil {
		return fail(err)
	}
	if err := ctx.Err(); err != nil {
		return fail(err)
	}

	record := store.ManagedRootRecord{
		ManagedRootID:      managedRootID,
		SessionID:          service.sessionID,
		WorkspaceID:        service.workspaceID,
		RecoveryGeneration: generation,
		CanonicalPath:      root.canonicalPath,
		FilesystemIdentity: root.value,
		RepositoryIdentity: repository.value,
		Kind:               options.Kind,
		GuardStatus:        store.RootGuardHealthy,
		Active:             true,
		LastVerifiedAt:     &verifiedAt,
	}
	if err := service.local.RegisterManagedRoot(ctx, record); err != nil {
		return fail(fmt.Errorf("agent: register managed root: %w", err))
	}

	return ManagedRootHandle{
		ManagedRootID: managedRootID,
		CanonicalPath: root.canonicalPath,
		Kind:          options.Kind,
	}, nil
}

func validManagedRootKind(kind store.ManagedRootKind) bool {
	switch kind {
	case store.ManagedRootPrimary,
		store.ManagedRootIsolated,
		store.ManagedRootShared:
		return true
	default:
		return false
	}
}

func removeOwnedEmptyDirectory(created nativeDirectoryIdentity) error {
	current, err := inspectNativeDirectory(created.canonicalPath)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf(
			"%w: inspect created directory: %w",
			ErrManagedRootCleanup,
			err,
		)
	}
	if current.value != created.value {
		return fmt.Errorf(
			"%w: %w",
			ErrManagedRootCleanup,
			ErrManagedRootIdentityChanged,
		)
	}
	if err := os.Remove(created.canonicalPath); err != nil {
		return fmt.Errorf(
			"%w: remove empty created directory: %w",
			ErrManagedRootCleanup,
			err,
		)
	}
	return nil
}
