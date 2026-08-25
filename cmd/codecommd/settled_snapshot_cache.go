package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/ijonahch/codecomm/internal/contenthttp"
	"github.com/ijonahch/codecomm/internal/logicalsnapshot"
)

const (
	daemonSettledSnapshotCachePrefix    = "artifact-"
	daemonSettledSnapshotAttemptPrefix  = ".attempt-"
	daemonSettledSnapshotCacheRetention = 2
	daemonSettledSnapshotCacheMaxAge    = 24 * time.Hour
)

type daemonSettledSnapshotCache struct {
	baseDirectory string
	rootDirectory string
	directory     string
	pages         string
	chunks        string
	root          logicalsnapshot.Root
	scope         contenthttp.SnapshotRequestScope
	fetchFailed   bool
}

type daemonSettledSnapshotCacheCandidate struct {
	name    string
	modTime time.Time
}

func openDaemonSettledSnapshotCache(
	rootDirectory string,
	root logicalsnapshot.Root,
) (*daemonSettledSnapshotCache, error) {
	if !cleanAbsolutePath(rootDirectory) ||
		len(root.CanonicalBytes()) < 1 {
		return nil, errDaemonSettledReplication
	}
	scope, err := contenthttp.NewSnapshotRequestScope(root)
	if err != nil {
		return nil, err
	}
	key := daemonSettledSnapshotCacheKey(root)
	if key == "" {
		return nil, errDaemonSettledReplication
	}
	directory := filepath.Join(rootDirectory, key)
	cache := &daemonSettledSnapshotCache{
		baseDirectory: filepath.Dir(rootDirectory),
		rootDirectory: rootDirectory,
		directory:     directory,
		pages:         filepath.Join(directory, "pages"),
		chunks:        filepath.Join(directory, "chunks"),
		root:          root,
		scope:         scope,
	}
	if err := cache.openOrCreate(); err != nil {
		return nil, err
	}
	if err := pruneDaemonSettledSnapshotCaches(
		rootDirectory,
		key,
		time.Now(),
	); err != nil {
		return nil, err
	}
	return cache, nil
}

func (cache *daemonSettledSnapshotCache) openOrCreate() error {
	if cache == nil ||
		!cleanAbsolutePath(cache.rootDirectory) ||
		!cleanAbsolutePath(cache.directory) {
		return errDaemonSettledReplication
	}
	if err := cache.validateExisting(); err == nil {
		return cache.touch()
	}
	if _, err := os.Lstat(cache.directory); err == nil {
		if err := requireDaemonSnapshotDirectoryUnder(
			cache.baseDirectory,
			cache.directory,
		); err != nil {
			return fmt.Errorf(
				"%w: refuse linked snapshot cache: %v",
				errDaemonSettledReplication,
				err,
			)
		}
		if removeErr := removeDaemonSnapshotTreeUnder(
			cache.baseDirectory,
			cache.directory,
		); removeErr != nil {
			return fmt.Errorf(
				"%w: discard invalid snapshot cache: %v",
				errDaemonSettledReplication,
				removeErr,
			)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf(
			"%w: inspect snapshot cache: %v",
			errDaemonSettledReplication,
			err,
		)
	}
	if syncErr := syncDaemonSnapshotDirectory(
		cache.rootDirectory,
	); syncErr != nil {
		return fmt.Errorf(
			"%w: sync discarded snapshot cache: %v",
			errDaemonSettledReplication,
			syncErr,
		)
	}

	if err := createDaemonSnapshotDirectoryTree(
		cache.rootDirectory,
		cache.directory,
	); err != nil {
		return fmt.Errorf(
			"%w: create snapshot cache: %v",
			errDaemonSettledReplication,
			err,
		)
	}
	created := false
	defer func() {
		if !created {
			_ = removeDaemonSnapshotTreeUnder(
				cache.baseDirectory,
				cache.directory,
			)
		}
	}()
	for _, directory := range []string{cache.pages, cache.chunks} {
		if err := createDaemonSnapshotDirectoryTree(
			cache.directory,
			directory,
		); err != nil {
			return fmt.Errorf(
				"%w: create snapshot cache inventory: %v",
				errDaemonSettledReplication,
				err,
			)
		}
	}
	if err := writeDaemonSnapshotCacheBytes(
		cache.baseDirectory,
		cache.directory,
		filepath.Join(cache.directory, daemonSnapshotRootFilename),
		cache.root.CanonicalBytes(),
	); err != nil {
		return fmt.Errorf(
			"%w: write snapshot cache root: %v",
			errDaemonSettledReplication,
			err,
		)
	}
	for _, directory := range []string{
		cache.pages,
		cache.chunks,
		cache.directory,
	} {
		if err := syncDaemonSnapshotDirectory(directory); err != nil {
			return fmt.Errorf(
				"%w: sync snapshot cache inventory: %v",
				errDaemonSettledReplication,
				err,
			)
		}
	}
	if err := syncDaemonSnapshotDirectory(cache.rootDirectory); err != nil {
		return fmt.Errorf(
			"%w: sync snapshot cache root: %v",
			errDaemonSettledReplication,
			err,
		)
	}
	created = true
	return nil
}

func (cache *daemonSettledSnapshotCache) validateExisting() error {
	if err := requireDaemonSnapshotDirectoryUnder(
		cache.baseDirectory,
		cache.directory,
	); err != nil {
		return err
	}
	for _, directory := range []string{cache.pages, cache.chunks} {
		if err := requireDaemonSnapshotDirectoryUnder(
			cache.baseDirectory,
			directory,
		); err != nil {
			return err
		}
		if err := removeDaemonSnapshotPartFiles(
			cache.baseDirectory,
			directory,
		); err != nil {
			return err
		}
	}
	encoded, err := readDaemonSnapshotFileUnder(
		cache.baseDirectory,
		filepath.Join(cache.directory, daemonSnapshotRootFilename),
		logicalsnapshot.MaxRootBytes,
	)
	if err != nil {
		return err
	}
	if !bytes.Equal(encoded, cache.root.CanonicalBytes()) {
		return errDaemonSnapshotIntegrity
	}
	return nil
}

func (cache *daemonSettledSnapshotCache) openPage(
	ctx context.Context,
	pageIndex uint64,
	fetch func(
		context.Context,
		uint64,
	) (logicalsnapshot.DescriptorPage, error),
) (io.ReadCloser, error) {
	if cache == nil ||
		ctx == nil ||
		fetch == nil ||
		pageIndex >= cache.root.Unsigned().Input().DescriptorPageCount {
		return nil, errDaemonSettledReplication
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	path := filepath.Join(
		cache.pages,
		daemonSnapshotIndexedFilename(pageIndex, ".json"),
	)
	if encoded, valid := cache.cachedPage(path, pageIndex); valid {
		if err := cache.touch(); err != nil {
			return nil, err
		}
		return io.NopCloser(bytes.NewReader(encoded)), nil
	}
	page, err := fetch(ctx, pageIndex)
	if err != nil {
		cache.fetchFailed = true
		return nil, err
	}
	input := page.Input()
	encoded := page.CanonicalBytes()
	if input.ArtifactID != cache.scope.ArtifactID ||
		input.PageIndex != pageIndex ||
		len(encoded) < 1 ||
		len(encoded) > logicalsnapshot.MaxDescriptorPageBytes {
		return nil, contenthttp.ErrInvalidSnapshotPage
	}
	if err := writeDaemonSnapshotCacheBytes(
		cache.baseDirectory,
		cache.pages,
		path,
		encoded,
	); err != nil {
		return nil, err
	}
	if err := cache.touch(); err != nil {
		return nil, err
	}
	return io.NopCloser(bytes.NewReader(encoded)), nil
}

func (cache *daemonSettledSnapshotCache) cachedPage(
	path string,
	pageIndex uint64,
) ([]byte, bool) {
	encoded, err := readDaemonSnapshotFileUnder(
		cache.baseDirectory,
		path,
		logicalsnapshot.MaxDescriptorPageBytes,
	)
	if err == nil {
		page, parseErr := logicalsnapshot.ParseDescriptorPage(encoded)
		if parseErr == nil {
			input := page.Input()
			if input.ArtifactID == cache.scope.ArtifactID &&
				input.PageIndex == pageIndex {
				return encoded, true
			}
		}
	}
	_ = removeDaemonSnapshotFileUnder(cache.baseDirectory, path)
	return nil, false
}

func (cache *daemonSettledSnapshotCache) openChunk(
	ctx context.Context,
	chunkIndex uint64,
	fetch func(
		context.Context,
		uint64,
	) (contenthttp.SnapshotChunk, error),
) (io.ReadCloser, error) {
	if cache == nil ||
		ctx == nil ||
		fetch == nil ||
		chunkIndex >= cache.root.Unsigned().Input().ChunkCount {
		return nil, errDaemonSettledReplication
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	path := filepath.Join(
		cache.chunks,
		daemonSnapshotIndexedFilename(chunkIndex, ".bin"),
	)
	if encoded, err := readDaemonSnapshotFileUnder(
		cache.baseDirectory,
		path,
		logicalsnapshot.MaxChunkCompressedBytes,
	); err == nil {
		if touchErr := cache.touch(); touchErr != nil {
			return nil, touchErr
		}
		return io.NopCloser(bytes.NewReader(encoded)), nil
	}
	_ = removeDaemonSnapshotFileUnder(cache.baseDirectory, path)

	chunk, err := fetch(ctx, chunkIndex)
	if err != nil {
		cache.fetchFailed = true
		return nil, err
	}
	content := chunk.Bytes()
	if chunk.Scope() != cache.scope ||
		chunk.ChunkIndex() != chunkIndex ||
		len(content) < 1 ||
		len(content) > logicalsnapshot.MaxChunkCompressedBytes {
		return nil, contenthttp.ErrInvalidSnapshotChunk
	}
	if err := writeDaemonSnapshotCacheBytes(
		cache.baseDirectory,
		cache.chunks,
		path,
		content,
	); err != nil {
		return nil, err
	}
	if err := cache.touch(); err != nil {
		return nil, err
	}
	return io.NopCloser(bytes.NewReader(content)), nil
}

func (cache *daemonSettledSnapshotCache) touch() error {
	if cache == nil || !cleanAbsolutePath(cache.directory) {
		return errDaemonSettledReplication
	}
	now := time.Now()
	if err := os.Chtimes(cache.directory, now, now); err != nil {
		return fmt.Errorf(
			"%w: update snapshot cache activity: %v",
			errDaemonSettledReplication,
			err,
		)
	}
	return nil
}

func (cache *daemonSettledSnapshotCache) discard() error {
	if cache == nil || cache.directory == "" {
		return nil
	}
	directory := cache.directory
	if err := removeDaemonSnapshotTreeUnder(
		cache.baseDirectory,
		directory,
	); err != nil {
		return fmt.Errorf(
			"%w: remove snapshot cache: %v",
			errDaemonSettledReplication,
			err,
		)
	}
	if err := syncDaemonSnapshotDirectory(cache.rootDirectory); err != nil {
		return fmt.Errorf(
			"%w: sync snapshot cache removal: %v",
			errDaemonSettledReplication,
			err,
		)
	}
	cache.directory = ""
	cache.pages = ""
	cache.chunks = ""
	return nil
}

func daemonSettledSnapshotCacheKey(root logicalsnapshot.Root) string {
	encoded := root.CanonicalBytes()
	if len(encoded) < 1 {
		return ""
	}
	digest := sha256.Sum256(encoded)
	return daemonSettledSnapshotCachePrefix + hex.EncodeToString(digest[:])
}

func prepareDaemonSettledSnapshotScratchAt(
	path string,
	now time.Time,
) error {
	if !cleanAbsolutePath(path) || now.IsZero() {
		return errDaemonSettledReplication
	}
	if err := createDaemonSnapshotDirectoryTree(
		filepath.Dir(path),
		path,
	); err != nil {
		return fmt.Errorf(
			"%w: create snapshot scratch root: %v",
			errDaemonSettledReplication,
			err,
		)
	}
	baseDirectory := filepath.Dir(path)
	entries, err := readDaemonSnapshotDirectoryUnder(
		context.Background(),
		baseDirectory,
		path,
		daemonSnapshotInventoryMax,
	)
	if err != nil {
		return fmt.Errorf(
			"%w: inspect snapshot scratch root: %v",
			errDaemonSettledReplication,
			err,
		)
	}
	removed := false
	for _, entry := range entries {
		if !strings.HasPrefix(
			entry.Name(),
			daemonSettledSnapshotAttemptPrefix,
		) {
			continue
		}
		attemptPath := filepath.Join(path, entry.Name())
		if err := requireDaemonSnapshotDirectoryUnder(
			baseDirectory,
			attemptPath,
		); err != nil {
			return fmt.Errorf(
				"%w: unexpected snapshot attempt entry %q",
				errDaemonSettledReplication,
				entry.Name(),
			)
		}
		if err := removeDaemonSnapshotTreeUnder(
			baseDirectory,
			attemptPath,
		); err != nil {
			return fmt.Errorf(
				"%w: remove abandoned snapshot attempt: %v",
				errDaemonSettledReplication,
				err,
			)
		}
		removed = true
	}
	if err := pruneDaemonSettledSnapshotCaches(path, "", now); err != nil {
		return err
	}
	if removed {
		if err := syncDaemonSnapshotDirectory(path); err != nil {
			return fmt.Errorf(
				"%w: sync abandoned snapshot cleanup: %v",
				errDaemonSettledReplication,
				err,
			)
		}
	}
	return nil
}

func pruneDaemonSettledSnapshotCaches(
	rootDirectory string,
	protected string,
	now time.Time,
) error {
	if !cleanAbsolutePath(rootDirectory) ||
		protected != "" && !validDaemonSettledSnapshotCacheName(protected) ||
		now.IsZero() {
		return errDaemonSettledReplication
	}
	baseDirectory := filepath.Dir(rootDirectory)
	entries, err := readDaemonSnapshotDirectoryUnder(
		context.Background(),
		baseDirectory,
		rootDirectory,
		daemonSnapshotInventoryMax,
	)
	if err != nil {
		return fmt.Errorf(
			"%w: list snapshot caches: %v",
			errDaemonSettledReplication,
			err,
		)
	}
	candidates := make([]daemonSettledSnapshotCacheCandidate, 0, len(entries))
	removed := false
	for _, entry := range entries {
		name := entry.Name()
		if strings.HasPrefix(name, daemonSettledSnapshotAttemptPrefix) {
			continue
		}
		candidatePath := filepath.Join(rootDirectory, name)
		if !validDaemonSettledSnapshotCacheName(name) {
			return fmt.Errorf(
				"%w: unexpected snapshot scratch entry %q",
				errDaemonSettledReplication,
				name,
			)
		}
		if err := requireDaemonSnapshotDirectoryUnder(
			baseDirectory,
			candidatePath,
		); err != nil {
			return fmt.Errorf(
				"%w: linked snapshot scratch entry %q",
				errDaemonSettledReplication,
				name,
			)
		}
		info, err := entry.Info()
		if err != nil {
			return fmt.Errorf(
				"%w: inspect snapshot cache %q: %v",
				errDaemonSettledReplication,
				name,
				err,
			)
		}
		if name != protected &&
			now.Sub(info.ModTime()) >= daemonSettledSnapshotCacheMaxAge {
			if err := removeDaemonSnapshotTreeUnder(
				baseDirectory,
				filepath.Join(rootDirectory, name),
			); err != nil {
				return fmt.Errorf(
					"%w: expire snapshot cache %q: %v",
					errDaemonSettledReplication,
					name,
					err,
				)
			}
			removed = true
			continue
		}
		candidates = append(candidates, daemonSettledSnapshotCacheCandidate{
			name:    name,
			modTime: info.ModTime(),
		})
	}
	sort.Slice(candidates, func(left, right int) bool {
		if candidates[left].name == protected {
			return true
		}
		if candidates[right].name == protected {
			return false
		}
		if candidates[left].modTime.Equal(candidates[right].modTime) {
			return candidates[left].name > candidates[right].name
		}
		return candidates[left].modTime.After(candidates[right].modTime)
	})
	if len(candidates) > daemonSettledSnapshotCacheRetention {
		for _, candidate := range candidates[daemonSettledSnapshotCacheRetention:] {
			if err := removeDaemonSnapshotTreeUnder(
				baseDirectory,
				filepath.Join(rootDirectory, candidate.name),
			); err != nil {
				return fmt.Errorf(
					"%w: prune snapshot cache %q: %v",
					errDaemonSettledReplication,
					candidate.name,
					err,
				)
			}
			removed = true
		}
	}
	if removed {
		if err := syncDaemonSnapshotDirectory(rootDirectory); err != nil {
			return fmt.Errorf(
				"%w: sync snapshot cache inventory: %v",
				errDaemonSettledReplication,
				err,
			)
		}
	}
	return nil
}

func validDaemonSettledSnapshotCacheName(name string) bool {
	const digestHexLength = sha256.Size * 2
	if len(name) != len(daemonSettledSnapshotCachePrefix)+digestHexLength ||
		!strings.HasPrefix(name, daemonSettledSnapshotCachePrefix) {
		return false
	}
	_, err := hex.DecodeString(
		strings.TrimPrefix(name, daemonSettledSnapshotCachePrefix),
	)
	return err == nil
}

func removeDaemonSnapshotPartFiles(
	baseDirectory string,
	directory string,
) error {
	entries, err := readDaemonSnapshotDirectoryUnder(
		context.Background(),
		baseDirectory,
		directory,
		daemonSnapshotInventoryMax,
	)
	if err != nil {
		return err
	}
	removed := false
	for _, entry := range entries {
		if !strings.HasPrefix(entry.Name(), ".part-") {
			continue
		}
		path := filepath.Join(directory, entry.Name())
		if err := requireDaemonSnapshotRegularFileUnder(
			baseDirectory,
			path,
		); err != nil {
			return errDaemonSnapshotIntegrity
		}
		if err := removeDaemonSnapshotFileUnder(
			baseDirectory,
			path,
		); err != nil {
			return err
		}
		removed = true
	}
	if removed {
		return syncDaemonSnapshotDirectory(directory)
	}
	return nil
}

func writeDaemonSnapshotCacheBytes(
	baseDirectory string,
	directory string,
	path string,
	content []byte,
) error {
	if !cleanAbsolutePath(directory) ||
		!cleanAbsolutePath(path) ||
		filepath.Dir(path) != directory ||
		len(content) < 1 {
		return errDaemonSettledReplication
	}
	part, partPath, err := createDaemonSnapshotTempFileUnder(
		baseDirectory,
		directory,
		".part-",
	)
	if err != nil {
		return err
	}
	defer func() {
		_ = part.Close()
		_ = removeDaemonSnapshotFileUnder(baseDirectory, partPath)
	}()
	if err := part.Chmod(0o600); err != nil {
		return err
	}
	written, err := part.Write(content)
	if err != nil {
		return err
	}
	if written != len(content) {
		return io.ErrShortWrite
	}
	if err := part.Sync(); err != nil {
		return err
	}
	if err := part.Close(); err != nil {
		return err
	}
	if err := renameDaemonSnapshotPathUnder(
		baseDirectory,
		partPath,
		path,
		false,
	); err != nil {
		return err
	}
	if err := syncDaemonSnapshotDirectory(directory); err != nil {
		return err
	}
	return nil
}
