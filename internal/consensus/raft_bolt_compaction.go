package consensus

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"hash"
	"os"
	"path/filepath"
	"time"

	"go.etcd.io/bbolt"
)

const (
	raftBoltCompactionMinSourceBytes = int64(8 << 20)
	raftBoltCompactionMaxSourceBytes = int64(128 << 20)
	raftBoltCompactionMinReclaim     = int64(4 << 20)
	raftBoltCompactionLargeReclaim   = int64(16 << 20)
	raftBoltCompactionTxMaxSize      = int64(4 << 20)
	raftBoltCompactionCheckErrors    = 8
)

var errRaftBoltCompaction = errors.New("consensus: Raft store compaction failed")

type raftBoltCompactionOps struct {
	replace       func(string, string) error
	syncDirectory func(string) error
}

type raftBoltLogicalIdentity struct {
	digest          [sha256.Size]byte
	bucketCount     uint64
	valueCount      uint64
	logicalBytes    int64
	liveEstimate    int64
	hasLogsBucket   bool
	hasConfigBucket bool
}

func compactRaftBoltStore(path string) error {
	return compactRaftBoltStoreWithOps(path, raftBoltCompactionOps{
		replace:       replaceRaftBoltFile,
		syncDirectory: syncConsensusDirectory,
	})
}

func compactRaftBoltStoreWithOps(
	path string,
	ops raftBoltCompactionOps,
) (resultErr error) {
	if path == "" || !filepath.IsAbs(path) {
		return fmt.Errorf("%w: invalid path", errRaftBoltCompaction)
	}
	if ops.replace == nil {
		ops.replace = replaceRaftBoltFile
	}
	if ops.syncDirectory == nil {
		ops.syncDirectory = syncConsensusDirectory
	}

	path = filepath.Clean(path)
	directory := filepath.Dir(path)
	if err := validateRaftBoltCompactionDirectory(directory); err != nil {
		return err
	}
	sourceInfo, err := lstatRaftBoltRegular(path)
	if err != nil {
		return err
	}
	if sourceInfo.Size() < raftBoltCompactionMinSourceBytes {
		return nil
	}
	// Automatic close maintenance is deliberately bounded. Larger stores use
	// explicit offline maintenance rather than extending daemon shutdown.
	if sourceInfo.Size() > raftBoltCompactionMaxSourceBytes {
		return nil
	}

	source, err := openRaftBoltForCompaction(path, sourceInfo, true)
	if err != nil {
		return fmt.Errorf("%w: open source: %w", errRaftBoltCompaction, err)
	}
	sourceOpen := true
	defer func() {
		if sourceOpen {
			resultErr = errors.Join(
				resultErr,
				wrapRaftBoltClose("source", source.Close()),
			)
		}
	}()

	sourceIdentity, err := inspectRaftBolt(source)
	if err != nil {
		return fmt.Errorf("%w: inspect source: %w", errRaftBoltCompaction, err)
	}
	if !raftBoltReclaimMeaningful(
		sourceInfo.Size(),
		sourceIdentity.liveEstimate,
	) {
		return nil
	}

	tempPath := filepath.Join(
		directory,
		"."+filepath.Base(path)+".compact.tmp",
	)
	if err := removeRaftBoltCompactionTemp(tempPath); err != nil {
		return fmt.Errorf("%w: clear stale temporary file: %w", errRaftBoltCompaction, err)
	}
	defer func() {
		resultErr = errors.Join(
			resultErr,
			wrapRaftBoltCleanup(removeRaftBoltCompactionTemp(tempPath)),
		)
	}()

	tempInfo, err := createRaftBoltCompactionTemp(tempPath)
	if err != nil {
		return fmt.Errorf("%w: create temporary file: %w", errRaftBoltCompaction, err)
	}
	destination, err := openRaftBoltForCompaction(
		tempPath,
		tempInfo,
		false,
	)
	if err != nil {
		return fmt.Errorf("%w: open destination: %w", errRaftBoltCompaction, err)
	}
	var destinationErr error
	if err := bbolt.Compact(
		destination,
		source,
		raftBoltCompactionTxMaxSize,
	); err != nil {
		destinationErr = fmt.Errorf("copy logical database: %w", err)
	}
	if destinationErr == nil {
		if err := destination.Sync(); err != nil {
			destinationErr = fmt.Errorf("sync compacted database: %w", err)
		}
	}
	var highWater int64
	if destinationErr == nil {
		if err := destination.View(func(tx *bbolt.Tx) error {
			highWater = tx.Size()
			return nil
		}); err != nil {
			destinationErr = fmt.Errorf(
				"read compacted high-water mark: %w",
				err,
			)
		}
	}
	destinationErr = errors.Join(
		destinationErr,
		wrapRaftBoltClose("destination", destination.Close()),
	)
	if destinationErr != nil {
		return fmt.Errorf("%w: %w", errRaftBoltCompaction, destinationErr)
	}

	if err := trimRaftBoltCompactionTemp(
		tempPath,
		tempInfo,
		highWater,
	); err != nil {
		return fmt.Errorf("%w: trim destination: %w", errRaftBoltCompaction, err)
	}
	candidateInfo, err := lstatMatchingRaftBoltRegular(tempPath, tempInfo)
	if err != nil {
		return fmt.Errorf("%w: inspect destination: %w", errRaftBoltCompaction, err)
	}
	candidate, err := openRaftBoltForCompaction(
		tempPath,
		candidateInfo,
		true,
	)
	if err != nil {
		return fmt.Errorf("%w: reopen destination: %w", errRaftBoltCompaction, err)
	}
	candidateIdentity, inspectErr := inspectRaftBolt(candidate)
	closeErr := wrapRaftBoltClose("verified destination", candidate.Close())
	if err := errors.Join(inspectErr, closeErr); err != nil {
		return fmt.Errorf("%w: verify destination: %w", errRaftBoltCompaction, err)
	}
	if !sourceIdentity.sameLogicalContent(candidateIdentity) {
		return fmt.Errorf(
			"%w: compacted logical content differs from source",
			errRaftBoltCompaction,
		)
	}
	candidateInfo, err = lstatMatchingRaftBoltRegular(
		tempPath,
		candidateInfo,
	)
	if err != nil {
		return fmt.Errorf("%w: recheck destination: %w", errRaftBoltCompaction, err)
	}
	if candidateInfo.Size() != highWater ||
		candidateIdentity.logicalBytes != highWater {
		return fmt.Errorf(
			"%w: destination size %d, logical high-water mark %d",
			errRaftBoltCompaction,
			candidateInfo.Size(),
			highWater,
		)
	}
	if !raftBoltReclaimMeaningful(sourceInfo.Size(), candidateInfo.Size()) {
		return nil
	}
	if _, err := lstatMatchingRaftBoltRegular(path, sourceInfo); err != nil {
		return fmt.Errorf("%w: source changed before replacement: %w", errRaftBoltCompaction, err)
	}
	if err := ops.replace(tempPath, path); err != nil {
		return fmt.Errorf("%w: replace source: %w", errRaftBoltCompaction, err)
	}
	sourceCloseErr := wrapRaftBoltClose("replaced source", source.Close())
	sourceOpen = false
	syncErr := ops.syncDirectory(directory)
	if err := errors.Join(sourceCloseErr, syncErr); err != nil {
		return fmt.Errorf("%w: finalize replacement: %w", errRaftBoltCompaction, err)
	}
	return nil
}

func validateRaftBoltCompactionDirectory(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("%w: inspect directory: %w", errRaftBoltCompaction, err)
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf(
			"%w: %w: compaction directory is not a real directory",
			errRaftBoltCompaction,
			ErrInsecureConsensusPath,
		)
	}
	if err := validatePrivateDirectory(path, info); err != nil {
		return fmt.Errorf("%w: %w", errRaftBoltCompaction, err)
	}
	return nil
}

func lstatRaftBoltRegular(path string) (os.FileInfo, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, fmt.Errorf("%w: inspect %q: %w", errRaftBoltCompaction, path, err)
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return nil, fmt.Errorf(
			"%w: %w: %q is not a regular file",
			errRaftBoltCompaction,
			ErrInsecureConsensusPath,
			path,
		)
	}
	return info, nil
}

func lstatMatchingRaftBoltRegular(
	path string,
	expected os.FileInfo,
) (os.FileInfo, error) {
	actual, err := lstatRaftBoltRegular(path)
	if err != nil {
		return nil, err
	}
	if expected == nil || !os.SameFile(expected, actual) {
		return nil, fmt.Errorf(
			"%w: %w: %q changed identity",
			errRaftBoltCompaction,
			ErrInsecureConsensusPath,
			path,
		)
	}
	return actual, nil
}

func openRaftBoltForCompaction(
	path string,
	expected os.FileInfo,
	readOnly bool,
) (*bbolt.DB, error) {
	options := *bbolt.DefaultOptions
	options.ReadOnly = readOnly
	options.Timeout = 5 * time.Second
	options.NoFreelistSync = false
	options.OpenFile = func(
		openPath string,
		flag int,
		mode os.FileMode,
	) (*os.File, error) {
		return openValidatedRaftBoltFile(
			openPath,
			flag,
			mode,
			expected,
		)
	}
	return bbolt.Open(path, 0o600, &options)
}

func openValidatedRaftBoltFile(
	path string,
	flag int,
	mode os.FileMode,
	expected os.FileInfo,
) (*os.File, error) {
	file, err := openRaftBoltFileNoFollow(path, flag, mode)
	if err != nil {
		return nil, err
	}
	info, validationErr := file.Stat()
	if validationErr == nil {
		validationErr = validateRaftBoltFileHandle(file, info)
	}
	pathInfo, pathErr := os.Lstat(path)
	if validationErr == nil && pathErr != nil {
		validationErr = pathErr
	}
	if validationErr == nil &&
		(!pathInfo.Mode().IsRegular() ||
			pathInfo.Mode()&os.ModeSymlink != 0 ||
			!os.SameFile(pathInfo, info) ||
			expected != nil && !os.SameFile(expected, info)) {
		validationErr = fmt.Errorf(
			"%w: Raft store file identity changed",
			ErrInsecureConsensusPath,
		)
	}
	if validationErr != nil {
		return nil, errors.Join(validationErr, file.Close())
	}
	return file, nil
}

func createRaftBoltCompactionTemp(path string) (_ os.FileInfo, resultErr error) {
	file, err := os.OpenFile(
		path,
		os.O_RDWR|os.O_CREATE|os.O_EXCL,
		0o600,
	)
	if err != nil {
		return nil, err
	}
	defer func() {
		resultErr = errors.Join(resultErr, file.Close())
	}()
	if err := file.Chmod(0o600); err != nil {
		return nil, err
	}
	info, err := file.Stat()
	if err != nil {
		return nil, err
	}
	if err := validateRaftBoltFileHandle(file, info); err != nil {
		return nil, err
	}
	return info, nil
}

func trimRaftBoltCompactionTemp(
	path string,
	expected os.FileInfo,
	highWater int64,
) (resultErr error) {
	if highWater <= 0 {
		return fmt.Errorf("invalid logical high-water mark %d", highWater)
	}
	if _, err := lstatMatchingRaftBoltRegular(path, expected); err != nil {
		return err
	}
	file, err := openRaftBoltFileNoFollow(path, os.O_RDWR, 0o600)
	if err != nil {
		return err
	}
	defer func() {
		resultErr = errors.Join(resultErr, file.Close())
	}()
	info, err := file.Stat()
	if err != nil {
		return err
	}
	if err := validateRaftBoltFileHandle(file, info); err != nil {
		return err
	}
	if !os.SameFile(expected, info) {
		return fmt.Errorf("%w: temporary file identity changed", ErrInsecureConsensusPath)
	}
	if highWater > info.Size() {
		return fmt.Errorf(
			"logical high-water mark %d exceeds physical size %d",
			highWater,
			info.Size(),
		)
	}
	if err := file.Truncate(highWater); err != nil {
		return err
	}
	return file.Sync()
}

func removeRaftBoltCompactionTemp(path string) error {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() && info.Mode()&os.ModeSymlink == 0 {
		return fmt.Errorf(
			"%w: temporary path has unsupported type",
			ErrInsecureConsensusPath,
		)
	}
	return os.Remove(path)
}

func inspectRaftBolt(database *bbolt.DB) (
	raftBoltLogicalIdentity,
	error,
) {
	var identity raftBoltLogicalIdentity
	err := database.View(func(tx *bbolt.Tx) error {
		if err := checkRaftBoltTransaction(tx); err != nil {
			return err
		}
		identity.logicalBytes = tx.Size()
		pageSize := int64(database.Info().PageSize)
		identity.liveEstimate = 4 * pageSize

		digest := sha256.New()
		_, _ = digest.Write([]byte("codecomm/raft-bbolt/logical/v1"))
		if err := tx.ForEach(func(name []byte, bucket *bbolt.Bucket) error {
			switch {
			case bytes.Equal(name, []byte("logs")):
				identity.hasLogsBucket = true
			case bytes.Equal(name, []byte("conf")):
				identity.hasConfigBucket = true
			}
			stats := bucket.Stats()
			identity.liveEstimate += int64(
				stats.BranchInuse + stats.LeafInuse,
			)
			return digestRaftBoltBucket(
				digest,
				name,
				bucket,
				&identity,
			)
		}); err != nil {
			return err
		}
		copy(identity.digest[:], digest.Sum(nil))
		return nil
	})
	if err != nil {
		return raftBoltLogicalIdentity{}, err
	}
	if !identity.hasLogsBucket || !identity.hasConfigBucket {
		return raftBoltLogicalIdentity{}, errors.New(
			"required raft-boltdb buckets are missing",
		)
	}
	return identity, nil
}

func checkRaftBoltTransaction(tx *bbolt.Tx) error {
	var (
		count   int
		sampled []error
	)
	for err := range tx.Check() {
		if err == nil {
			continue
		}
		count++
		if len(sampled) < raftBoltCompactionCheckErrors {
			sampled = append(sampled, err)
		}
	}
	if count == 0 {
		return nil
	}
	return fmt.Errorf(
		"%d structural errors (first %d): %w",
		count,
		len(sampled),
		errors.Join(sampled...),
	)
}

func digestRaftBoltBucket(
	digest hash.Hash,
	name []byte,
	bucket *bbolt.Bucket,
	identity *raftBoltLogicalIdentity,
) error {
	if bucket == nil {
		return errors.New("nil bucket")
	}
	identity.bucketCount++
	_, _ = digest.Write([]byte{0x01})
	writeRaftBoltDigestBytes(digest, name)
	writeRaftBoltDigestUint64(digest, bucket.Sequence())
	if err := bucket.ForEach(func(key, value []byte) error {
		if value == nil {
			return digestRaftBoltBucket(
				digest,
				key,
				bucket.Bucket(key),
				identity,
			)
		}
		identity.valueCount++
		_, _ = digest.Write([]byte{0x02})
		writeRaftBoltDigestBytes(digest, key)
		writeRaftBoltDigestBytes(digest, value)
		return nil
	}); err != nil {
		return err
	}
	_, _ = digest.Write([]byte{0xff})
	return nil
}

func writeRaftBoltDigestBytes(digest hash.Hash, value []byte) {
	writeRaftBoltDigestUint64(digest, uint64(len(value)))
	_, _ = digest.Write(value)
}

func writeRaftBoltDigestUint64(digest hash.Hash, value uint64) {
	var encoded [8]byte
	binary.BigEndian.PutUint64(encoded[:], value)
	_, _ = digest.Write(encoded[:])
}

func (identity raftBoltLogicalIdentity) sameLogicalContent(
	other raftBoltLogicalIdentity,
) bool {
	return identity.digest == other.digest &&
		identity.bucketCount == other.bucketCount &&
		identity.valueCount == other.valueCount &&
		identity.hasLogsBucket == other.hasLogsBucket &&
		identity.hasConfigBucket == other.hasConfigBucket
}

func raftBoltReclaimMeaningful(sourceSize, candidateSize int64) bool {
	if sourceSize <= 0 || candidateSize < 0 || candidateSize >= sourceSize {
		return false
	}
	reclaim := sourceSize - candidateSize
	if reclaim < raftBoltCompactionMinReclaim {
		return false
	}
	return reclaim >= raftBoltCompactionLargeReclaim ||
		reclaim >= (sourceSize+9)/10
}

func wrapRaftBoltClose(name string, err error) error {
	if err == nil {
		return nil
	}
	return fmt.Errorf("close %s: %w", name, err)
}

func wrapRaftBoltCleanup(err error) error {
	if err == nil {
		return nil
	}
	return fmt.Errorf("clean temporary file: %w", err)
}
