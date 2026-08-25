package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/ijonahch/codecomm/internal/contenthttp"
	"github.com/ijonahch/codecomm/internal/domain"
	"github.com/ijonahch/codecomm/internal/logicalsnapshot"
	"github.com/ijonahch/codecomm/internal/snapshotbuilder"
)

const (
	daemonSnapshotDirectoryName = "logical-snapshots"
	daemonSnapshotRootFilename  = "root.json"
	daemonSnapshotRetention     = 2
	daemonSnapshotStagingMaxAge = 24 * time.Hour
	daemonSnapshotHandoff       = 30 * time.Second
	daemonSnapshotInventoryMax  = 1024
)

var (
	errDaemonSnapshotRepository = errors.New(
		"codecommd: logical snapshot repository failure",
	)
	errDaemonSnapshotIntegrity = errors.New(
		"codecommd: logical snapshot artifact integrity failure",
	)
	errDaemonSnapshotCleanupPending = errors.New(
		"codecommd: logical snapshot cleanup pending",
	)
)

type daemonSnapshotArtifact struct {
	root              logicalsnapshot.Root
	scope             contenthttp.SnapshotRequestScope
	baseDirectory     string
	directory         string
	transfers         uint64
	handoffUntil      time.Time
	handoffTimer      *time.Timer
	cleanupInProgress bool
	cleanupErr        error
}

type daemonSnapshotTransfer struct {
	repository *daemonLogicalSnapshotRepository
	artifact   *daemonSnapshotArtifact
	scope      contenthttp.SnapshotRequestScope

	mu       sync.Mutex
	closed   bool
	closeErr error
}

// daemonLogicalSnapshotRepository owns immutable, generation-scoped snapshot
// artifacts. A final artifact directory is never modified after promotion.
type daemonLogicalSnapshotRepository struct {
	baseDirectory      string
	artifactsDirectory string
	sessionID          domain.UUIDv7
	workspaceID        domain.UUIDv4
	recoveryGeneration uint64
	signerDeviceID     domain.DeviceID
	signerPublicKey    ed25519.PublicKey

	mu        sync.RWMutex
	publishMu sync.Mutex
	artifacts map[string]*daemonSnapshotArtifact
	retired   map[string]*daemonSnapshotArtifact
	latest    *daemonSnapshotArtifact
	closed    bool

	handoffLifetime time.Duration
	cleanupContext  context.Context
	cleanupCancel   context.CancelFunc
	cleanupGate     chan struct{}
	cleanupWait     sync.WaitGroup
	closeOnce       sync.Once

	removeArtifact func(context.Context, string) error
	syncInventory  func(context.Context, string) error
}

type daemonSnapshotArtifactWriter struct {
	artifactID      string
	baseDirectory   string
	directory       string
	chunkCount      uint64
	pageCount       uint64
	compressedBytes uint64
	expandedBytes   uint64
}

type daemonSnapshotContextReader struct {
	ctx    context.Context
	reader io.Reader
}

func (reader daemonSnapshotContextReader) Read(buffer []byte) (int, error) {
	if reader.ctx == nil || reader.reader == nil {
		return 0, errDaemonSnapshotRepository
	}
	if err := reader.ctx.Err(); err != nil {
		return 0, err
	}
	return reader.reader.Read(buffer)
}

func daemonLogicalSnapshotRepositoryPath(
	statePath string,
	recoveryGeneration uint64,
) string {
	return filepath.Join(
		filepath.Dir(statePath),
		daemonSnapshotDirectoryName,
		"generation-"+strconv.FormatUint(recoveryGeneration, 10),
	)
}

func openDaemonLogicalSnapshotRepository(
	ctx context.Context,
	statePath string,
	sessionID domain.UUIDv7,
	workspaceID domain.UUIDv4,
	recoveryGeneration uint64,
	signerDeviceID domain.DeviceID,
	signerPublicKey ed25519.PublicKey,
) (*daemonLogicalSnapshotRepository, error) {
	if ctx == nil ||
		!cleanAbsolutePath(statePath) ||
		!sessionID.Valid() ||
		!workspaceID.Valid() ||
		!domain.ValidUnsignedInteger(recoveryGeneration) ||
		!signerDeviceID.Valid() ||
		len(signerPublicKey) != ed25519.PublicKeySize {
		return nil, errDaemonSnapshotRepository
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	root := daemonLogicalSnapshotRepositoryPath(
		statePath,
		recoveryGeneration,
	)
	base := filepath.Dir(statePath)
	artifacts := filepath.Join(root, "artifacts")
	if err := createDaemonSnapshotDirectoryTree(
		base,
		artifacts,
	); err != nil {
		return nil, fmt.Errorf(
			"%w: create artifact directory: %v",
			errDaemonSnapshotRepository,
			err,
		)
	}
	if err := os.Chmod(root, 0o700); err != nil {
		return nil, fmt.Errorf(
			"%w: secure repository directory: %v",
			errDaemonSnapshotRepository,
			err,
		)
	}
	if err := os.Chmod(artifacts, 0o700); err != nil {
		return nil, fmt.Errorf(
			"%w: secure artifact directory: %v",
			errDaemonSnapshotRepository,
			err,
		)
	}
	cleanupContext, cleanupCancel := context.WithCancel(ctx)
	repository := &daemonLogicalSnapshotRepository{
		baseDirectory:      base,
		artifactsDirectory: artifacts,
		sessionID:          sessionID,
		workspaceID:        workspaceID,
		recoveryGeneration: recoveryGeneration,
		signerDeviceID:     signerDeviceID,
		signerPublicKey:    bytes.Clone(signerPublicKey),
		artifacts:          make(map[string]*daemonSnapshotArtifact),
		retired:            make(map[string]*daemonSnapshotArtifact),
		handoffLifetime:    daemonSnapshotHandoff,
		cleanupContext:     cleanupContext,
		cleanupCancel:      cleanupCancel,
		cleanupGate:        make(chan struct{}, 1),
		removeArtifact: func(ctx context.Context, path string) error {
			return removeDaemonSnapshotArtifactUnder(ctx, base, path)
		},
		syncInventory: syncDaemonSnapshotInventory,
	}
	if err := repository.load(ctx); err != nil {
		cleanupCancel()
		return nil, err
	}
	return repository, nil
}

func (repository *daemonLogicalSnapshotRepository) load(
	ctx context.Context,
) error {
	if repository == nil || ctx == nil {
		return errDaemonSnapshotRepository
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	entries, err := readDaemonSnapshotDirectoryUnder(
		ctx,
		repository.baseDirectory,
		repository.artifactsDirectory,
		daemonSnapshotInventoryMax,
	)
	if err != nil {
		return fmt.Errorf(
			"%w: list artifacts: %v",
			errDaemonSnapshotRepository,
			err,
		)
	}
	removedStaging := false
	for _, entry := range entries {
		if err := ctx.Err(); err != nil {
			return err
		}
		entryPath := filepath.Join(
			repository.artifactsDirectory,
			entry.Name(),
		)
		if err := requireDaemonSnapshotDirectoryUnder(
			repository.baseDirectory,
			entryPath,
		); err != nil {
			return fmt.Errorf(
				"%w: linked or non-directory repository entry %q",
				errDaemonSnapshotIntegrity,
				entry.Name(),
			)
		}
		if strings.HasPrefix(entry.Name(), ".staging-") {
			info, infoErr := entry.Info()
			if infoErr != nil {
				return fmt.Errorf(
					"%w: inspect staging artifact: %v",
					errDaemonSnapshotRepository,
					infoErr,
				)
			}
			if time.Since(info.ModTime()) <
				daemonSnapshotStagingMaxAge {
				continue
			}
			if err := removeDaemonSnapshotTreeUnder(
				repository.baseDirectory,
				entryPath,
			); err != nil {
				return fmt.Errorf(
					"%w: remove abandoned staging artifact: %v",
					errDaemonSnapshotRepository,
					err,
				)
			}
			removedStaging = true
			continue
		}
		artifact, err := repository.loadArtifact(
			ctx,
			entryPath,
		)
		if err != nil {
			return fmt.Errorf(
				"%w: load artifact %q: %v",
				errDaemonSnapshotIntegrity,
				entry.Name(),
				err,
			)
		}
		if artifact.scope.ArtifactID != entry.Name() {
			return fmt.Errorf(
				"%w: artifact directory and root differ",
				errDaemonSnapshotIntegrity,
			)
		}
		repository.artifacts[entry.Name()] = artifact
		if newerDaemonSnapshot(artifact, repository.latest) {
			repository.latest = artifact
		}
	}
	if err := repository.prune(ctx); err != nil {
		return err
	}
	if removedStaging {
		if err := repository.syncInventory(
			ctx,
			repository.artifactsDirectory,
		); err != nil {
			return fmt.Errorf(
				"%w: sync loaded artifact inventory: %v",
				errDaemonSnapshotRepository,
				err,
			)
		}
	}
	return nil
}

func (repository *daemonLogicalSnapshotRepository) prune(
	ctx context.Context,
) error {
	if ctx == nil {
		return errDaemonSnapshotRepository
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	candidates, err := repository.retireSnapshotArtifacts()
	if err != nil {
		return err
	}
	var cleanupErr error
	for index, artifact := range candidates {
		if err := ctx.Err(); err != nil {
			for _, pending := range candidates[index:] {
				repository.finishRetiredCleanup(pending, err)
			}
			return errors.Join(cleanupErr, err)
		}
		cleanupErr = errors.Join(
			cleanupErr,
			repository.cleanupRetiredArtifact(ctx, artifact),
		)
	}
	return cleanupErr
}

func (repository *daemonLogicalSnapshotRepository) retireSnapshotArtifacts() (
	[]*daemonSnapshotArtifact,
	error,
) {
	if repository == nil ||
		repository.removeArtifact == nil ||
		repository.syncInventory == nil {
		return nil, errDaemonSnapshotRepository
	}
	repository.mu.Lock()
	defer repository.mu.Unlock()
	if repository.closed {
		return nil, context.Canceled
	}
	artifacts := make([]*daemonSnapshotArtifact, 0, len(repository.artifacts))
	for _, artifact := range repository.artifacts {
		artifacts = append(artifacts, artifact)
	}
	sort.Slice(artifacts, func(left, right int) bool {
		return newerDaemonSnapshot(artifacts[left], artifacts[right])
	})
	if len(artifacts) > daemonSnapshotRetention {
		now := time.Now()
		for _, artifact := range artifacts[daemonSnapshotRetention:] {
			if artifact.handoffUntil.After(now) {
				continue
			}
			if artifact.handoffTimer != nil {
				artifact.handoffTimer.Stop()
				artifact.handoffTimer = nil
			}
			artifact.handoffUntil = time.Time{}
			artifactID := artifact.scope.ArtifactID
			delete(repository.artifacts, artifactID)
			repository.retired[artifactID] = artifact
		}
	}
	candidates := make([]*daemonSnapshotArtifact, 0, len(repository.retired))
	for _, artifact := range repository.retired {
		if artifact.transfers != 0 || artifact.cleanupInProgress {
			continue
		}
		artifact.cleanupInProgress = true
		candidates = append(candidates, artifact)
	}
	return candidates, nil
}

func (repository *daemonLogicalSnapshotRepository) scheduleSnapshotPrune() error {
	candidates, err := repository.retireSnapshotArtifacts()
	if err != nil {
		return err
	}
	for _, artifact := range candidates {
		repository.scheduleRetiredCleanup(artifact)
	}
	return nil
}

func (repository *daemonLogicalSnapshotRepository) scheduleRetiredCleanup(
	artifact *daemonSnapshotArtifact,
) {
	if repository == nil || artifact == nil {
		return
	}
	repository.mu.Lock()
	if repository.closed {
		if current := repository.retired[artifact.scope.ArtifactID]; current == artifact {
			artifact.cleanupInProgress = false
			artifact.cleanupErr = context.Canceled
		}
		repository.mu.Unlock()
		return
	}
	repository.cleanupWait.Add(1)
	ctx := repository.cleanupContext
	repository.mu.Unlock()
	go func() {
		defer repository.cleanupWait.Done()
		_ = repository.cleanupRetiredArtifact(ctx, artifact)
	}()
}

func (repository *daemonLogicalSnapshotRepository) cleanupRetiredArtifact(
	ctx context.Context,
	artifact *daemonSnapshotArtifact,
) error {
	if repository == nil ||
		ctx == nil ||
		artifact == nil ||
		repository.removeArtifact == nil ||
		repository.syncInventory == nil ||
		repository.cleanupGate == nil {
		return errDaemonSnapshotRepository
	}
	if err := ctx.Err(); err != nil {
		repository.finishRetiredCleanup(artifact, err)
		return err
	}
	select {
	case repository.cleanupGate <- struct{}{}:
		defer func() { <-repository.cleanupGate }()
	case <-ctx.Done():
		repository.finishRetiredCleanup(artifact, ctx.Err())
		return ctx.Err()
	}
	err := repository.removeArtifact(ctx, artifact.directory)
	if err == nil {
		err = repository.syncInventory(ctx, repository.artifactsDirectory)
	}
	if err != nil {
		err = fmt.Errorf(
			"%w: clean retired artifact %q: %w",
			errDaemonSnapshotRepository,
			artifact.scope.ArtifactID,
			err,
		)
	}

	repository.finishRetiredCleanup(artifact, err)
	return err
}

func (repository *daemonLogicalSnapshotRepository) finishRetiredCleanup(
	artifact *daemonSnapshotArtifact,
	err error,
) {
	if repository == nil || artifact == nil {
		return
	}
	repository.mu.Lock()
	defer repository.mu.Unlock()
	current := repository.retired[artifact.scope.ArtifactID]
	if current != artifact {
		return
	}
	artifact.cleanupInProgress = false
	artifact.cleanupErr = err
	if err == nil {
		delete(repository.retired, artifact.scope.ArtifactID)
	}
}

func (repository *daemonLogicalSnapshotRepository) LatestSnapshot(
	ctx context.Context,
) (logicalsnapshot.Root, error) {
	if repository == nil || ctx == nil {
		return logicalsnapshot.Root{}, errDaemonSnapshotRepository
	}
	if err := ctx.Err(); err != nil {
		return logicalsnapshot.Root{}, err
	}
	repository.mu.Lock()
	latest := repository.latest
	if repository.closed {
		repository.mu.Unlock()
		return logicalsnapshot.Root{}, context.Canceled
	}
	if latest == nil {
		repository.mu.Unlock()
		return logicalsnapshot.Root{}, contenthttp.ErrSnapshotUnavailable
	}
	repository.reserveSnapshotHandoffLocked(latest)
	repository.mu.Unlock()
	return latest.root, nil
}

func (repository *daemonLogicalSnapshotRepository) reserveSnapshotHandoffLocked(
	artifact *daemonSnapshotArtifact,
) {
	if repository == nil ||
		artifact == nil ||
		repository.handoffLifetime <= 0 ||
		repository.closed {
		return
	}
	artifact.handoffUntil = time.Now().Add(repository.handoffLifetime)
	if artifact.handoffTimer == nil {
		artifact.handoffTimer = time.AfterFunc(
			repository.handoffLifetime,
			func() {
				repository.expireSnapshotHandoff(artifact)
			},
		)
		return
	}
	artifact.handoffTimer.Reset(repository.handoffLifetime)
}

func (repository *daemonLogicalSnapshotRepository) expireSnapshotHandoff(
	artifact *daemonSnapshotArtifact,
) {
	if repository == nil || artifact == nil {
		return
	}
	repository.mu.Lock()
	if repository.closed {
		repository.mu.Unlock()
		return
	}
	remaining := time.Until(artifact.handoffUntil)
	if remaining > 0 {
		artifact.handoffTimer.Reset(remaining)
		repository.mu.Unlock()
		return
	}
	artifact.handoffUntil = time.Time{}
	if artifact.handoffTimer != nil {
		artifact.handoffTimer.Stop()
	}
	artifact.handoffTimer = nil
	repository.mu.Unlock()
	_ = repository.scheduleSnapshotPrune()
}

func (repository *daemonLogicalSnapshotRepository) OpenSnapshotTransfer(
	ctx context.Context,
	scope contenthttp.SnapshotRequestScope,
) (contenthttp.SnapshotTransfer, error) {
	if repository == nil || ctx == nil {
		return nil, errDaemonSnapshotRepository
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	repository.mu.Lock()
	if repository.closed {
		repository.mu.Unlock()
		return nil, context.Canceled
	}
	artifact := repository.artifacts[scope.ArtifactID]
	if artifact == nil || artifact.scope != scope {
		repository.mu.Unlock()
		return nil, contenthttp.ErrSnapshotNotFound
	}
	artifact.transfers++
	repository.mu.Unlock()
	return &daemonSnapshotTransfer{
		repository: repository,
		artifact:   artifact,
		scope:      scope,
	}, nil
}

func (transfer *daemonSnapshotTransfer) Scope() contenthttp.SnapshotRequestScope {
	if transfer == nil {
		return contenthttp.SnapshotRequestScope{}
	}
	return transfer.scope
}

func (transfer *daemonSnapshotTransfer) SnapshotManifestPage(
	ctx context.Context,
	pageIndex uint64,
) (contenthttp.SnapshotManifestPage, error) {
	if transfer == nil || ctx == nil {
		return contenthttp.SnapshotManifestPage{},
			errDaemonSnapshotRepository
	}
	transfer.mu.Lock()
	defer transfer.mu.Unlock()
	if transfer.closed || transfer.artifact == nil {
		return contenthttp.SnapshotManifestPage{},
			contenthttp.ErrSnapshotUnavailable
	}
	if err := ctx.Err(); err != nil {
		return contenthttp.SnapshotManifestPage{}, err
	}
	artifact := transfer.artifact
	if pageIndex >= artifact.root.Unsigned().Input().DescriptorPageCount {
		return contenthttp.SnapshotManifestPage{},
			contenthttp.ErrSnapshotNotFound
	}
	page, err := artifact.manifestPage(ctx, pageIndex)
	if err != nil {
		return contenthttp.SnapshotManifestPage{}, err
	}
	return contenthttp.NewSnapshotManifestPage(
		transfer.scope,
		page,
	)
}

func (transfer *daemonSnapshotTransfer) SnapshotChunk(
	ctx context.Context,
	chunkIndex uint64,
) (contenthttp.SnapshotChunk, error) {
	if transfer == nil || ctx == nil {
		return contenthttp.SnapshotChunk{}, errDaemonSnapshotRepository
	}
	transfer.mu.Lock()
	defer transfer.mu.Unlock()
	if transfer.closed || transfer.artifact == nil {
		return contenthttp.SnapshotChunk{},
			contenthttp.ErrSnapshotUnavailable
	}
	if err := ctx.Err(); err != nil {
		return contenthttp.SnapshotChunk{}, err
	}
	artifact := transfer.artifact
	if chunkIndex >= artifact.root.Unsigned().Input().ChunkCount {
		return contenthttp.SnapshotChunk{}, contenthttp.ErrSnapshotNotFound
	}
	pageIndex := chunkIndex / uint64(logicalsnapshot.MaxDescriptorsPerPage)
	descriptorOffset := int(
		chunkIndex % uint64(logicalsnapshot.MaxDescriptorsPerPage),
	)
	page, err := artifact.manifestPage(ctx, pageIndex)
	if err != nil {
		return contenthttp.SnapshotChunk{}, err
	}
	descriptors := page.Input().Descriptors
	if descriptorOffset >= len(descriptors) ||
		descriptors[descriptorOffset].ChunkIndex != chunkIndex {
		return contenthttp.SnapshotChunk{}, fmt.Errorf(
			"%w: chunk %d has no manifest descriptor",
			errDaemonSnapshotIntegrity,
			chunkIndex,
		)
	}
	descriptor := descriptors[descriptorOffset]
	content, err := readDaemonSnapshotChunk(
		ctx,
		artifact.baseDirectory,
		filepath.Join(
			artifact.directory,
			"chunks",
			daemonSnapshotIndexedFilename(chunkIndex, ".bin"),
		),
		descriptor,
	)
	if err != nil {
		return contenthttp.SnapshotChunk{}, fmt.Errorf(
			"%w: read chunk %d: %v",
			errDaemonSnapshotIntegrity,
			chunkIndex,
			err,
		)
	}
	return contenthttp.NewSnapshotChunk(
		transfer.scope,
		chunkIndex,
		content,
	)
}

func (transfer *daemonSnapshotTransfer) Close() error {
	if transfer == nil {
		return nil
	}
	transfer.mu.Lock()
	defer transfer.mu.Unlock()
	if transfer.closed {
		return transfer.closeErr
	}
	transfer.closed = true
	if transfer.repository == nil || transfer.artifact == nil {
		transfer.closeErr = errDaemonSnapshotRepository
		return transfer.closeErr
	}
	transfer.closeErr = transfer.repository.releaseSnapshotTransfer(
		transfer.artifact,
	)
	transfer.repository = nil
	transfer.artifact = nil
	return transfer.closeErr
}

func (artifact *daemonSnapshotArtifact) manifestPage(
	ctx context.Context,
	requestedPageIndex uint64,
) (logicalsnapshot.DescriptorPage, error) {
	if artifact == nil || ctx == nil {
		return logicalsnapshot.DescriptorPage{},
			errDaemonSnapshotRepository
	}
	if err := ctx.Err(); err != nil {
		return logicalsnapshot.DescriptorPage{}, err
	}
	input := artifact.root.Unsigned().Input()
	if requestedPageIndex >= input.DescriptorPageCount {
		return logicalsnapshot.DescriptorPage{},
			contenthttp.ErrSnapshotNotFound
	}
	page, err := readDaemonSnapshotManifestPage(
		ctx,
		artifact.baseDirectory,
		artifact.directory,
		requestedPageIndex,
	)
	if err != nil {
		return logicalsnapshot.DescriptorPage{}, fmt.Errorf(
			"%w: read manifest page %d: %v",
			errDaemonSnapshotIntegrity,
			requestedPageIndex,
			err,
		)
	}
	pageInput := page.Input()
	descriptorsPerPage := uint64(logicalsnapshot.MaxDescriptorsPerPage)
	if requestedPageIndex > domain.MaxSafeInteger/descriptorsPerPage {
		return logicalsnapshot.DescriptorPage{},
			errDaemonSnapshotIntegrity
	}
	firstChunk := requestedPageIndex * descriptorsPerPage
	lastPage := requestedPageIndex+1 == input.DescriptorPageCount
	if pageInput.ArtifactID != input.ArtifactID ||
		pageInput.PageIndex != requestedPageIndex ||
		pageInput.Descriptors[0].ChunkIndex != firstChunk ||
		!lastPage &&
			len(pageInput.Descriptors) !=
				logicalsnapshot.MaxDescriptorsPerPage {
		return logicalsnapshot.DescriptorPage{},
			errDaemonSnapshotIntegrity
	}
	lastDescriptor := pageInput.Descriptors[len(pageInput.Descriptors)-1]
	if lastPage {
		if page.Hash() != input.FinalDescriptorPageHash ||
			lastDescriptor.ChunkIndex+1 != input.ChunkCount {
			return logicalsnapshot.DescriptorPage{},
				errDaemonSnapshotIntegrity
		}
	} else {
		if err := ctx.Err(); err != nil {
			return logicalsnapshot.DescriptorPage{}, err
		}
		next, err := readDaemonSnapshotManifestPage(
			ctx,
			artifact.baseDirectory,
			artifact.directory,
			requestedPageIndex+1,
		)
		if err != nil {
			return logicalsnapshot.DescriptorPage{}, fmt.Errorf(
				"%w: read successor manifest page %d: %v",
				errDaemonSnapshotIntegrity,
				requestedPageIndex+1,
				err,
			)
		}
		nextInput := next.Input()
		if nextInput.ArtifactID != input.ArtifactID ||
			nextInput.PageIndex != requestedPageIndex+1 ||
			nextInput.PreviousPageHash != page.Hash() {
			return logicalsnapshot.DescriptorPage{},
				errDaemonSnapshotIntegrity
		}
	}
	return page, nil
}

func readDaemonSnapshotManifestPage(
	ctx context.Context,
	baseDirectory string,
	artifactDirectory string,
	pageIndex uint64,
) (logicalsnapshot.DescriptorPage, error) {
	encoded, err := readDaemonSnapshotFileContextUnder(
		ctx,
		baseDirectory,
		filepath.Join(
			artifactDirectory,
			"pages",
			daemonSnapshotIndexedFilename(pageIndex, ".json"),
		),
		logicalsnapshot.MaxDescriptorPageBytes,
	)
	if err != nil {
		return logicalsnapshot.DescriptorPage{}, err
	}
	return logicalsnapshot.ParseDescriptorPage(encoded)
}

func (repository *daemonLogicalSnapshotRepository) releaseSnapshotTransfer(
	artifact *daemonSnapshotArtifact,
) error {
	if repository == nil || artifact == nil {
		return errDaemonSnapshotRepository
	}
	repository.mu.Lock()
	if artifact.transfers == 0 {
		repository.mu.Unlock()
		return errDaemonSnapshotRepository
	}
	artifact.transfers--
	retired := repository.retired[artifact.scope.ArtifactID] == artifact
	if !retired ||
		artifact.transfers != 0 ||
		artifact.cleanupInProgress {
		repository.mu.Unlock()
		return nil
	}
	artifact.cleanupInProgress = true
	repository.mu.Unlock()
	repository.scheduleRetiredCleanup(artifact)
	return nil
}

func (repository *daemonLogicalSnapshotRepository) publish(
	ctx context.Context,
	source snapshotbuilder.RecordSource,
	options snapshotbuilder.Options,
	build daemonSnapshotBuild,
) (logicalsnapshot.Root, error) {
	if repository == nil ||
		ctx == nil ||
		source == nil ||
		build == nil ||
		options.ArtifactID == "" {
		return logicalsnapshot.Root{}, errDaemonSnapshotRepository
	}
	if err := ctx.Err(); err != nil {
		return logicalsnapshot.Root{}, err
	}
	repository.publishMu.Lock()
	defer repository.publishMu.Unlock()
	if err := repository.requireSnapshotPublicationCapacity(
		options.ArtifactID,
	); err != nil {
		return logicalsnapshot.Root{}, err
	}
	if err := requireDaemonSnapshotDirectoryUnder(
		repository.baseDirectory,
		repository.artifactsDirectory,
	); err != nil {
		return logicalsnapshot.Root{}, fmt.Errorf(
			"%w: insecure artifact directory: %v",
			errDaemonSnapshotIntegrity,
			err,
		)
	}

	stage, err := createDaemonSnapshotTempDirectoryUnder(
		repository.baseDirectory,
		repository.artifactsDirectory,
		".staging-"+options.ArtifactID+"-",
	)
	if err != nil {
		return logicalsnapshot.Root{}, fmt.Errorf(
			"%w: create staging directory: %v",
			errDaemonSnapshotRepository,
			err,
		)
	}
	promoted := false
	defer func() {
		if !promoted {
			_ = removeDaemonSnapshotTreeUnder(
				repository.baseDirectory,
				stage,
			)
		}
	}()
	for _, name := range []string{"pages", "chunks"} {
		if err := os.Mkdir(filepath.Join(stage, name), 0o700); err != nil {
			return logicalsnapshot.Root{}, fmt.Errorf(
				"%w: create staging %s directory: %v",
				errDaemonSnapshotRepository,
				name,
				err,
			)
		}
	}
	writer := &daemonSnapshotArtifactWriter{
		artifactID:    options.ArtifactID,
		baseDirectory: repository.baseDirectory,
		directory:     stage,
	}
	artifactScratch, err := createDaemonSnapshotFileUnder(
		repository.baseDirectory,
		filepath.Join(stage, ".artifact.scratch"),
		os.O_CREATE|os.O_EXCL|os.O_RDWR,
		0o600,
	)
	if err != nil {
		return logicalsnapshot.Root{}, fmt.Errorf(
			"%w: create artifact scratch: %v",
			errDaemonSnapshotRepository,
			err,
		)
	}
	sequenceScratch, err := createDaemonSnapshotFileUnder(
		repository.baseDirectory,
		filepath.Join(stage, ".sequence.scratch"),
		os.O_CREATE|os.O_EXCL|os.O_RDWR,
		0o600,
	)
	if err != nil {
		_ = artifactScratch.Close()
		return logicalsnapshot.Root{}, fmt.Errorf(
			"%w: create sequence scratch: %v",
			errDaemonSnapshotRepository,
			err,
		)
	}
	options.ArtifactScratch = artifactScratch
	options.SequenceScratch = sequenceScratch
	options.ChunkSink = writer.writeChunk
	options.PageSink = writer.writePage
	built, buildErr := build(ctx, source, options)
	closeErr := errors.Join(
		artifactScratch.Close(),
		sequenceScratch.Close(),
	)
	removeErr := errors.Join(
		removeDaemonSnapshotFileUnder(
			repository.baseDirectory,
			artifactScratch.Name(),
		),
		removeDaemonSnapshotFileUnder(
			repository.baseDirectory,
			sequenceScratch.Name(),
		),
	)
	if buildErr != nil {
		return logicalsnapshot.Root{}, buildErr
	}
	if err := errors.Join(closeErr, removeErr); err != nil {
		return logicalsnapshot.Root{}, fmt.Errorf(
			"%w: dispose builder scratch: %v",
			errDaemonSnapshotRepository,
			err,
		)
	}
	input := built.Root.Unsigned().Input()
	if input.ArtifactID != options.ArtifactID ||
		input.SessionID != repository.sessionID ||
		input.WorkspaceID != repository.workspaceID ||
		input.RecoveryGeneration != repository.recoveryGeneration ||
		input.SignerDeviceID != repository.signerDeviceID {
		return logicalsnapshot.Root{}, fmt.Errorf(
			"%w: builder returned a mismatched root",
			errDaemonSnapshotIntegrity,
		)
	}
	if err := validateDaemonSnapshotOperationalLimits(built.Root); err != nil {
		return logicalsnapshot.Root{}, err
	}
	if err := writeDaemonSnapshotBytes(
		repository.baseDirectory,
		filepath.Join(stage, daemonSnapshotRootFilename),
		built.Root.CanonicalBytes(),
	); err != nil {
		return logicalsnapshot.Root{}, err
	}
	if _, err := repository.loadArtifact(ctx, stage); err != nil {
		return logicalsnapshot.Root{}, fmt.Errorf(
			"%w: verify staged artifact: %v",
			errDaemonSnapshotIntegrity,
			err,
		)
	}
	for _, name := range []string{"pages", "chunks"} {
		if err := syncDaemonSnapshotDirectory(
			filepath.Join(stage, name),
		); err != nil {
			return logicalsnapshot.Root{}, fmt.Errorf(
				"%w: sync staged %s inventory: %v",
				errDaemonSnapshotRepository,
				name,
				err,
			)
		}
	}
	if err := syncDaemonSnapshotDirectory(stage); err != nil {
		return logicalsnapshot.Root{}, fmt.Errorf(
			"%w: sync staged artifact: %v",
			errDaemonSnapshotRepository,
			err,
		)
	}

	final := filepath.Join(repository.artifactsDirectory, options.ArtifactID)
	if err := renameDaemonSnapshotPathUnder(
		repository.baseDirectory,
		stage,
		final,
		true,
	); err != nil {
		existing, loadErr := repository.loadArtifact(ctx, final)
		if loadErr != nil ||
			!bytes.Equal(
				existing.root.CanonicalBytes(),
				built.Root.CanonicalBytes(),
			) {
			return logicalsnapshot.Root{}, fmt.Errorf(
				"%w: promote artifact or resolve collision: %v",
				errDaemonSnapshotIntegrity,
				err,
			)
		}
	} else {
		promoted = true
	}
	if err := repository.syncInventory(
		ctx,
		repository.artifactsDirectory,
	); err != nil {
		return logicalsnapshot.Root{}, fmt.Errorf(
			"%w: sync artifact inventory: %v",
			errDaemonSnapshotRepository,
			err,
		)
	}
	artifact, err := repository.loadArtifact(ctx, final)
	if err != nil {
		return logicalsnapshot.Root{}, fmt.Errorf(
			"%w: reload promoted artifact: %v",
			errDaemonSnapshotIntegrity,
			err,
		)
	}
	repository.mu.Lock()
	if existing := repository.artifacts[options.ArtifactID]; existing != nil {
		if !bytes.Equal(
			existing.root.CanonicalBytes(),
			artifact.root.CanonicalBytes(),
		) {
			repository.mu.Unlock()
			return logicalsnapshot.Root{}, fmt.Errorf(
				"%w: published artifact metadata changed",
				errDaemonSnapshotIntegrity,
			)
		}
		artifact = existing
	} else {
		repository.artifacts[options.ArtifactID] = artifact
	}
	if newerDaemonSnapshot(artifact, repository.latest) {
		repository.latest = artifact
	}
	repository.mu.Unlock()
	if err := repository.scheduleSnapshotPrune(); err != nil {
		return logicalsnapshot.Root{}, err
	}
	return artifact.root, nil
}

func (repository *daemonLogicalSnapshotRepository) requireSnapshotPublicationCapacity(
	artifactID string,
) error {
	if repository == nil {
		return errDaemonSnapshotRepository
	}
	repository.mu.RLock()
	if repository.closed {
		repository.mu.RUnlock()
		return context.Canceled
	}
	_, alreadyPublished := repository.artifacts[artifactID]
	cleanupPending := len(repository.artifacts) > daemonSnapshotRetention ||
		len(repository.retired) != 0
	repository.mu.RUnlock()
	if alreadyPublished || !cleanupPending {
		return nil
	}
	if err := repository.scheduleSnapshotPrune(); err != nil {
		return err
	}
	return errDaemonSnapshotCleanupPending
}

func (repository *daemonLogicalSnapshotRepository) requireNewSnapshotPublicationCapacity() error {
	return repository.requireSnapshotPublicationCapacity("")
}

func (repository *daemonLogicalSnapshotRepository) BeginClose() error {
	if repository == nil || repository.cleanupCancel == nil {
		return errDaemonSnapshotRepository
	}
	repository.closeOnce.Do(func() {
		repository.mu.Lock()
		repository.closed = true
		for _, artifact := range repository.artifacts {
			if artifact.handoffTimer != nil {
				artifact.handoffTimer.Stop()
				artifact.handoffTimer = nil
			}
			artifact.handoffUntil = time.Time{}
		}
		repository.mu.Unlock()
		repository.cleanupCancel()
	})
	return nil
}

func (repository *daemonLogicalSnapshotRepository) Wait() error {
	if repository == nil {
		return errDaemonSnapshotRepository
	}
	if err := repository.BeginClose(); err != nil {
		return err
	}
	repository.cleanupWait.Wait()
	return nil
}

func (repository *daemonLogicalSnapshotRepository) loadArtifact(
	ctx context.Context,
	directory string,
) (*daemonSnapshotArtifact, error) {
	if repository == nil || ctx == nil {
		return nil, errDaemonSnapshotRepository
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	rootBytes, err := readDaemonSnapshotFileContextUnder(
		ctx,
		repository.baseDirectory,
		filepath.Join(directory, daemonSnapshotRootFilename),
		logicalsnapshot.MaxRootBytes,
	)
	if err != nil {
		return nil, err
	}
	root, err := logicalsnapshot.ParseRoot(rootBytes)
	if err != nil {
		return nil, err
	}
	input := root.Unsigned().Input()
	if input.SessionID != repository.sessionID ||
		input.WorkspaceID != repository.workspaceID ||
		input.RecoveryGeneration != repository.recoveryGeneration ||
		input.SignerDeviceID != repository.signerDeviceID {
		return nil, errDaemonSnapshotIntegrity
	}
	if err := logicalsnapshot.VerifyRoot(
		root,
		repository.signerPublicKey,
	); err != nil {
		return nil, err
	}
	scope, err := contenthttp.NewSnapshotRequestScope(root)
	if err != nil {
		return nil, err
	}
	artifact := &daemonSnapshotArtifact{
		root:          root,
		scope:         scope,
		baseDirectory: repository.baseDirectory,
		directory:     directory,
	}
	if err := validateDaemonSnapshotInventory(
		ctx,
		repository.baseDirectory,
		directory,
		input,
	); err != nil {
		return nil, err
	}
	artifactHash := sha256.New()
	validator, err := logicalsnapshot.NewManifestValidator(
		root,
		func(descriptor logicalsnapshot.ChunkDescriptor) error {
			content, err := readDaemonSnapshotChunk(
				ctx,
				repository.baseDirectory,
				filepath.Join(
					directory,
					"chunks",
					daemonSnapshotIndexedFilename(
						descriptor.ChunkIndex,
						".bin",
					),
				),
				descriptor,
			)
			if err != nil {
				return err
			}
			_, _ = artifactHash.Write(content)
			return nil
		},
	)
	if err != nil {
		return nil, err
	}
	for pageIndex := uint64(0); pageIndex < input.DescriptorPageCount; pageIndex++ {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		encoded, err := readDaemonSnapshotFileContextUnder(
			ctx,
			repository.baseDirectory,
			filepath.Join(
				directory,
				"pages",
				daemonSnapshotIndexedFilename(pageIndex, ".json"),
			),
			logicalsnapshot.MaxDescriptorPageBytes,
		)
		if err != nil {
			return nil, err
		}
		page, err := logicalsnapshot.ParseDescriptorPage(encoded)
		if err != nil {
			return nil, err
		}
		if err := validator.Consume(page); err != nil {
			return nil, err
		}
	}
	if err := validator.Finish(); err != nil {
		return nil, err
	}
	var digest [sha256.Size]byte
	copy(digest[:], artifactHash.Sum(nil))
	if digest != input.ArtifactDigest {
		return nil, errDaemonSnapshotIntegrity
	}
	return artifact, nil
}

func (writer *daemonSnapshotArtifactWriter) writeChunk(
	ctx context.Context,
	descriptor logicalsnapshot.ChunkDescriptor,
	content io.Reader,
) error {
	if writer == nil ||
		ctx == nil ||
		content == nil ||
		descriptor.ChunkIndex != writer.chunkCount {
		return errDaemonSnapshotRepository
	}
	if writer.chunkCount >= daemonSnapshotOperationalMaxChunks ||
		writer.compressedBytes > daemonSnapshotOperationalMaxBytes ||
		writer.expandedBytes > daemonSnapshotOperationalMaxBytes ||
		descriptor.CompressedLength >
			daemonSnapshotOperationalMaxBytes-writer.compressedBytes ||
		descriptor.ExpandedLength >
			daemonSnapshotOperationalMaxBytes-writer.expandedBytes {
		return errDaemonSnapshotReceiveQuota
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	path := filepath.Join(
		writer.directory,
		"chunks",
		daemonSnapshotIndexedFilename(descriptor.ChunkIndex, ".bin"),
	)
	file, err := createDaemonSnapshotFileUnder(
		writer.baseDirectory,
		path,
		os.O_CREATE|os.O_EXCL|os.O_WRONLY,
		0o600,
	)
	if err != nil {
		return err
	}
	success := false
	defer func() {
		_ = file.Close()
		if !success {
			_ = removeDaemonSnapshotFileUnder(
				writer.baseDirectory,
				path,
			)
		}
	}()
	hasher := sha256.New()
	written, err := io.Copy(
		io.MultiWriter(file, hasher),
		&io.LimitedReader{
			R: daemonSnapshotContextReader{
				ctx:    ctx,
				reader: content,
			},
			N: int64(logicalsnapshot.MaxChunkCompressedBytes) + 1,
		},
	)
	if err != nil ||
		written != int64(descriptor.CompressedLength) ||
		descriptor.CompressedLength != descriptor.ExpandedLength {
		return errDaemonSnapshotIntegrity
	}
	var digest [sha256.Size]byte
	copy(digest[:], hasher.Sum(nil))
	if digest != descriptor.SHA256 {
		return errDaemonSnapshotIntegrity
	}
	if err := file.Sync(); err != nil {
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	writer.chunkCount++
	writer.compressedBytes += descriptor.CompressedLength
	writer.expandedBytes += descriptor.ExpandedLength
	success = true
	return nil
}

func (writer *daemonSnapshotArtifactWriter) writePage(
	ctx context.Context,
	page logicalsnapshot.DescriptorPage,
	content io.Reader,
) error {
	if writer == nil || ctx == nil || content == nil {
		return errDaemonSnapshotRepository
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	input := page.Input()
	if input.ArtifactID != writer.artifactID ||
		input.PageIndex != writer.pageCount {
		return errDaemonSnapshotIntegrity
	}
	if writer.pageCount >= daemonSnapshotOperationalMaxPages {
		return errDaemonSnapshotReceiveQuota
	}
	encoded, err := io.ReadAll(&io.LimitedReader{
		R: daemonSnapshotContextReader{
			ctx:    ctx,
			reader: content,
		},
		N: int64(logicalsnapshot.MaxDescriptorPageBytes) + 1,
	})
	if err != nil || !bytes.Equal(encoded, page.CanonicalBytes()) {
		return errDaemonSnapshotIntegrity
	}
	if err := writeDaemonSnapshotBytes(
		writer.baseDirectory,
		filepath.Join(
			writer.directory,
			"pages",
			daemonSnapshotIndexedFilename(input.PageIndex, ".json"),
		),
		encoded,
	); err != nil {
		return err
	}
	writer.pageCount++
	return nil
}

func readDaemonSnapshotChunk(
	ctx context.Context,
	baseDirectory string,
	path string,
	descriptor logicalsnapshot.ChunkDescriptor,
) ([]byte, error) {
	content, err := readDaemonSnapshotFileContextUnder(
		ctx,
		baseDirectory,
		path,
		logicalsnapshot.MaxChunkCompressedBytes,
	)
	if err != nil {
		return nil, err
	}
	if uint64(len(content)) != descriptor.CompressedLength ||
		descriptor.CompressedLength != descriptor.ExpandedLength ||
		sha256.Sum256(content) != descriptor.SHA256 {
		return nil, errDaemonSnapshotIntegrity
	}
	return content, nil
}

func readDaemonSnapshotFile(path string, maximum int) ([]byte, error) {
	return readDaemonSnapshotFileContext(
		context.Background(),
		path,
		maximum,
	)
}

func readDaemonSnapshotFileUnder(
	baseDirectory string,
	path string,
	maximum int,
) ([]byte, error) {
	return readDaemonSnapshotFileContextUnder(
		context.Background(),
		baseDirectory,
		path,
		maximum,
	)
}

func removeDaemonSnapshotArtifactUnder(
	ctx context.Context,
	baseDirectory string,
	path string,
) error {
	if ctx == nil {
		return errDaemonSnapshotRepository
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if _, err := os.Lstat(path); errors.Is(err, os.ErrNotExist) {
		return nil
	} else if err != nil {
		return err
	}
	if err := requireDaemonSnapshotDirectoryUnder(
		baseDirectory,
		path,
	); err != nil {
		return errDaemonSnapshotIntegrity
	}
	return removeDaemonSnapshotTreeUnder(baseDirectory, path)
}

func syncDaemonSnapshotInventory(ctx context.Context, path string) error {
	if ctx == nil {
		return errDaemonSnapshotRepository
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	return syncDaemonSnapshotDirectory(path)
}

func readDaemonSnapshotFileContext(
	ctx context.Context,
	path string,
	maximum int,
) ([]byte, error) {
	return readDaemonSnapshotFileContextUnder(
		ctx,
		filepath.Dir(path),
		path,
		maximum,
	)
}

func readDaemonSnapshotFileContextUnder(
	ctx context.Context,
	baseDirectory string,
	path string,
	maximum int,
) ([]byte, error) {
	if ctx == nil || maximum < 1 {
		return nil, errDaemonSnapshotRepository
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	file, err := openDaemonSnapshotPathUnder(
		baseDirectory,
		path,
		false,
	)
	if err != nil {
		return nil, err
	}
	cancellationDone := make(chan struct{})
	stopCancellation := context.AfterFunc(ctx, func() {
		_ = file.Close()
		close(cancellationDone)
	})
	defer func() {
		if !stopCancellation() {
			<-cancellationDone
		}
		_ = file.Close()
	}()
	limited := &io.LimitedReader{
		R: file,
		N: int64(maximum) + 1,
	}
	var content bytes.Buffer
	content.Grow(min(maximum, 64<<10))
	buffer := make([]byte, 64<<10)
	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		read, readErr := limited.Read(buffer)
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if read > 0 {
			if _, err := content.Write(buffer[:read]); err != nil {
				return nil, err
			}
		}
		if errors.Is(readErr, io.EOF) {
			break
		}
		if readErr != nil {
			return nil, readErr
		}
	}
	if content.Len() < 1 || content.Len() > maximum {
		return nil, errDaemonSnapshotIntegrity
	}
	return content.Bytes(), nil
}

func readDaemonSnapshotDirectory(
	ctx context.Context,
	path string,
	maximum int,
) ([]os.DirEntry, error) {
	return readDaemonSnapshotDirectoryUnder(ctx, path, path, maximum)
}

func readDaemonSnapshotDirectoryUnder(
	ctx context.Context,
	baseDirectory string,
	path string,
	maximum int,
) ([]os.DirEntry, error) {
	if ctx == nil || maximum < 1 {
		return nil, errDaemonSnapshotRepository
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	directory, err := openDaemonSnapshotPathUnder(
		baseDirectory,
		path,
		true,
	)
	if err != nil {
		return nil, err
	}
	cancellationDone := make(chan struct{})
	stopCancellation := context.AfterFunc(ctx, func() {
		_ = directory.Close()
		close(cancellationDone)
	})
	defer func() {
		if !stopCancellation() {
			<-cancellationDone
		}
		_ = directory.Close()
	}()

	entries := make([]os.DirEntry, 0, min(maximum, 256))
	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		batch, readErr := directory.ReadDir(min(256, maximum-len(entries)+1))
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		entries = append(entries, batch...)
		if len(entries) > maximum {
			return nil, errDaemonSnapshotIntegrity
		}
		if errors.Is(readErr, io.EOF) {
			sort.Slice(entries, func(left, right int) bool {
				return entries[left].Name() < entries[right].Name()
			})
			return entries, nil
		}
		if readErr != nil {
			return nil, readErr
		}
		if len(batch) == 0 {
			return nil, io.ErrNoProgress
		}
	}
}

func writeDaemonSnapshotBytes(
	baseDirectory string,
	path string,
	content []byte,
) error {
	if len(content) < 1 {
		return errDaemonSnapshotRepository
	}
	file, err := createDaemonSnapshotFileUnder(
		baseDirectory,
		path,
		os.O_CREATE|os.O_EXCL|os.O_WRONLY,
		0o600,
	)
	if err != nil {
		return err
	}
	success := false
	defer func() {
		_ = file.Close()
		if !success {
			_ = removeDaemonSnapshotFileUnder(baseDirectory, path)
		}
	}()
	written, err := file.Write(content)
	if err != nil {
		return err
	}
	if written != len(content) {
		return io.ErrShortWrite
	}
	if err := file.Sync(); err != nil {
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	success = true
	return nil
}

func validateDaemonSnapshotInventory(
	ctx context.Context,
	baseDirectory string,
	directory string,
	input logicalsnapshot.RootInput,
) error {
	if ctx == nil {
		return errDaemonSnapshotRepository
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	rootEntries, err := readDaemonSnapshotDirectoryUnder(
		ctx,
		baseDirectory,
		directory,
		4,
	)
	if err != nil {
		return err
	}
	if len(rootEntries) != 3 {
		return errDaemonSnapshotIntegrity
	}
	expectedRoot := map[string]bool{
		daemonSnapshotRootFilename: false,
		"pages":                    true,
		"chunks":                   true,
	}
	for _, entry := range rootEntries {
		if err := ctx.Err(); err != nil {
			return err
		}
		wantDirectory, exists := expectedRoot[entry.Name()]
		if !exists {
			return errDaemonSnapshotIntegrity
		}
		path := filepath.Join(directory, entry.Name())
		if wantDirectory {
			if err := requireDaemonSnapshotDirectoryUnder(
				baseDirectory,
				path,
			); err != nil {
				return errDaemonSnapshotIntegrity
			}
		} else if err := requireDaemonSnapshotRegularFileUnder(
			baseDirectory,
			path,
		); err != nil {
			return errDaemonSnapshotIntegrity
		}
	}
	if err := validateDaemonSnapshotIndexedDirectory(
		ctx,
		baseDirectory,
		filepath.Join(directory, "pages"),
		input.DescriptorPageCount,
		".json",
	); err != nil {
		return err
	}
	return validateDaemonSnapshotIndexedDirectory(
		ctx,
		baseDirectory,
		filepath.Join(directory, "chunks"),
		input.ChunkCount,
		".bin",
	)
}

func validateDaemonSnapshotIndexedDirectory(
	ctx context.Context,
	baseDirectory string,
	directory string,
	count uint64,
	suffix string,
) error {
	if ctx == nil {
		return errDaemonSnapshotRepository
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if count >= uint64(^uint(0)>>1) {
		return errDaemonSnapshotIntegrity
	}
	entries, err := readDaemonSnapshotDirectoryUnder(
		ctx,
		baseDirectory,
		directory,
		int(count)+1,
	)
	if err != nil || uint64(len(entries)) != count {
		return errDaemonSnapshotIntegrity
	}
	for index, entry := range entries {
		if err := ctx.Err(); err != nil {
			return err
		}
		if entry.Name() != daemonSnapshotIndexedFilename(
			uint64(index),
			suffix,
		) {
			return errDaemonSnapshotIntegrity
		}
		if err := requireDaemonSnapshotRegularFileUnder(
			baseDirectory,
			filepath.Join(directory, entry.Name()),
		); err != nil {
			return errDaemonSnapshotIntegrity
		}
	}
	return nil
}

func daemonSnapshotIndexedFilename(index uint64, suffix string) string {
	return fmt.Sprintf("%020d%s", index, suffix)
}

func newerDaemonSnapshot(
	candidate *daemonSnapshotArtifact,
	current *daemonSnapshotArtifact,
) bool {
	if candidate == nil {
		return false
	}
	if current == nil {
		return true
	}
	left := candidate.root.Unsigned().Input()
	right := current.root.Unsigned().Input()
	if left.ResultIndex != right.ResultIndex {
		return left.ResultIndex > right.ResultIndex
	}
	if left.ChainIndex != right.ChainIndex {
		return left.ChainIndex > right.ChainIndex
	}
	return left.ArtifactID > right.ArtifactID
}

var _ phasedDaemonComponent = (*daemonLogicalSnapshotRepository)(nil)

var _ contenthttp.SnapshotService = (*daemonLogicalSnapshotRepository)(nil)
