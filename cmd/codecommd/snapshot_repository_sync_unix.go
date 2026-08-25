//go:build !windows

package main

func syncDaemonSnapshotDirectory(path string) error {
	directory, err := openDaemonSnapshotPath(path, true)
	if err != nil {
		return err
	}
	defer directory.Close()
	return directory.Sync()
}
