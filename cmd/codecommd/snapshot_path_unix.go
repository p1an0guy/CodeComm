//go:build !windows

package main

import (
	"errors"
	"os"

	"golang.org/x/sys/unix"
)

func openDaemonSnapshotPath(path string, directory bool) (*os.File, error) {
	if !cleanAbsolutePath(path) {
		return nil, errDaemonSnapshotIntegrity
	}
	fd, err := unix.Open(
		path,
		unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK,
		0,
	)
	if err != nil {
		return nil, err
	}
	closeFD := true
	defer func() {
		if closeFD {
			_ = unix.Close(fd)
		}
	}()

	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil {
		return nil, err
	}
	fileType := stat.Mode & unix.S_IFMT
	if directory && fileType != unix.S_IFDIR ||
		!directory && fileType != unix.S_IFREG {
		return nil, errDaemonSnapshotIntegrity
	}
	file := os.NewFile(uintptr(fd), path)
	if file == nil {
		return nil, errors.New("codecommd: wrap snapshot file descriptor")
	}
	closeFD = false
	return file, nil
}

func daemonSnapshotOpenFlags() int {
	return unix.O_NOFOLLOW | unix.O_NONBLOCK
}

func validDaemonSnapshotFileInfo(info os.FileInfo, directory bool) bool {
	if info == nil {
		return false
	}
	fileType := info.Mode().Type()
	return directory && fileType == os.ModeDir ||
		!directory && fileType == 0
}
