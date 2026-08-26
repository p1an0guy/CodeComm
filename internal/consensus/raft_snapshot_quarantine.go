package consensus

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

const raftSnapshotQuarantineDirectory = "snapshot-quarantine"

func newRaftSnapshotFileRejecter(
	consensusDir string,
) (func(string) error, error) {
	consensusDir = filepath.Clean(consensusDir)
	liveRoot := filepath.Join(consensusDir, "snapshots")
	quarantineRoot := filepath.Join(
		consensusDir,
		raftSnapshotQuarantineDirectory,
	)
	if _, err := prepareConsensusDirectory(quarantineRoot); err != nil {
		return nil, fmt.Errorf(
			"consensus: prepare snapshot quarantine: %w",
			err,
		)
	}
	return func(id string) error {
		if !validRaftSnapshotID(id) {
			return ErrInvalidRaftSnapshotStore
		}
		source := filepath.Join(liveRoot, id)
		target := filepath.Join(quarantineRoot, id)
		if filepath.Dir(source) != liveRoot ||
			filepath.Dir(target) != quarantineRoot {
			return ErrInvalidRaftSnapshotStore
		}
		info, err := os.Lstat(source)
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		if err != nil {
			return err
		}
		if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return ErrInvalidRaftSnapshotStore
		}
		if _, err := os.Lstat(target); err == nil {
			return fmt.Errorf(
				"%w: quarantine target already exists",
				ErrInvalidRaftSnapshotStore,
			)
		} else if !errors.Is(err, os.ErrNotExist) {
			return err
		}
		if err := os.Rename(source, target); err != nil {
			return err
		}
		return errors.Join(
			syncConsensusDirectory(liveRoot),
			syncConsensusDirectory(quarantineRoot),
		)
	}, nil
}
