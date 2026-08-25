package main

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

type daemonSnapshotPathRoot struct {
	base string
	root *os.Root
}

func openDaemonSnapshotPathRoot(base string) (*daemonSnapshotPathRoot, error) {
	if !cleanAbsolutePath(base) {
		return nil, errDaemonSnapshotIntegrity
	}
	baseFile, err := openDaemonSnapshotPath(base, true)
	if err != nil {
		return nil, err
	}
	defer func() { _ = baseFile.Close() }()
	baseInfo, err := baseFile.Stat()
	if err != nil {
		return nil, err
	}
	root, err := os.OpenRoot(base)
	if err != nil {
		return nil, err
	}
	rootInfo, err := root.Stat(".")
	if err != nil ||
		!validDaemonSnapshotFileInfo(rootInfo, true) ||
		!os.SameFile(baseInfo, rootInfo) {
		_ = root.Close()
		return nil, errDaemonSnapshotIntegrity
	}
	return &daemonSnapshotPathRoot{base: base, root: root}, nil
}

func (root *daemonSnapshotPathRoot) Close() error {
	if root == nil || root.root == nil {
		return errDaemonSnapshotIntegrity
	}
	return root.root.Close()
}

func (root *daemonSnapshotPathRoot) open(
	path string,
	directory bool,
) (*os.File, error) {
	relative, err := root.relative(path, true)
	if err != nil {
		return nil, err
	}
	expected, err := root.inspect(relative, directory)
	if err != nil {
		return nil, err
	}
	file, err := root.root.OpenFile(
		relative,
		os.O_RDONLY|daemonSnapshotOpenFlags(),
		0,
	)
	if err != nil {
		return nil, err
	}
	info, err := file.Stat()
	if err != nil ||
		!validDaemonSnapshotFileInfo(info, directory) ||
		!os.SameFile(expected, info) {
		_ = file.Close()
		return nil, errDaemonSnapshotIntegrity
	}
	return file, nil
}

func (root *daemonSnapshotPathRoot) removeAll(path string) error {
	relative, err := root.relative(path, false)
	if err != nil {
		return err
	}
	if _, err := root.root.Lstat(relative); errors.Is(err, os.ErrNotExist) {
		return nil
	} else if err != nil {
		return err
	}
	file, err := root.open(path, true)
	if err != nil {
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	return root.root.RemoveAll(relative)
}

func (root *daemonSnapshotPathRoot) remove(path string, directory bool) error {
	relative, err := root.relative(path, false)
	if err != nil {
		return err
	}
	file, err := root.open(path, directory)
	if err != nil {
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	return root.root.Remove(relative)
}

func (root *daemonSnapshotPathRoot) createFile(
	path string,
	flag int,
	permission os.FileMode,
) (*os.File, error) {
	relative, err := root.relative(path, false)
	if err != nil || flag&os.O_CREATE == 0 {
		return nil, errDaemonSnapshotIntegrity
	}
	parent := filepath.Dir(path)
	parentFile, err := root.open(parent, true)
	if err != nil {
		return nil, err
	}
	if err := parentFile.Close(); err != nil {
		return nil, err
	}
	file, err := root.root.OpenFile(
		relative,
		flag|daemonSnapshotOpenFlags(),
		permission,
	)
	if err != nil {
		return nil, err
	}
	info, err := file.Stat()
	if err != nil || !validDaemonSnapshotFileInfo(info, false) {
		_ = file.Close()
		return nil, errDaemonSnapshotIntegrity
	}
	return file, nil
}

func (root *daemonSnapshotPathRoot) rename(
	oldPath string,
	newPath string,
	directory bool,
) error {
	oldRelative, err := root.relative(oldPath, false)
	if err != nil {
		return err
	}
	newRelative, err := root.relative(newPath, false)
	if err != nil {
		return err
	}
	oldFile, err := root.open(oldPath, directory)
	if err != nil {
		return err
	}
	if err := oldFile.Close(); err != nil {
		return err
	}
	parentFile, err := root.open(filepath.Dir(newPath), true)
	if err != nil {
		return err
	}
	if err := parentFile.Close(); err != nil {
		return err
	}
	return root.root.Rename(oldRelative, newRelative)
}

func (root *daemonSnapshotPathRoot) inspect(
	relative string,
	directory bool,
) (os.FileInfo, error) {
	if root == nil || root.root == nil {
		return nil, errDaemonSnapshotIntegrity
	}
	if relative == "." {
		info, err := root.root.Lstat(relative)
		if err != nil || !validDaemonSnapshotFileInfo(info, directory) {
			return nil, errDaemonSnapshotIntegrity
		}
		return info, nil
	}
	components := strings.Split(relative, string(filepath.Separator))
	current := ""
	var result os.FileInfo
	for index, component := range components {
		if component == "" || component == "." || component == ".." {
			return nil, errDaemonSnapshotIntegrity
		}
		current = filepath.Join(current, component)
		info, err := root.root.Lstat(current)
		wantDirectory := index < len(components)-1 || directory
		if err != nil || !validDaemonSnapshotFileInfo(info, wantDirectory) {
			return nil, errDaemonSnapshotIntegrity
		}
		result = info
	}
	return result, nil
}

func (root *daemonSnapshotPathRoot) relative(
	path string,
	allowRoot bool,
) (string, error) {
	if root == nil ||
		root.root == nil ||
		!cleanAbsolutePath(root.base) ||
		!cleanAbsolutePath(path) {
		return "", errDaemonSnapshotIntegrity
	}
	relative, err := filepath.Rel(root.base, path)
	if err != nil ||
		filepath.IsAbs(relative) ||
		relative == ".." ||
		strings.HasPrefix(relative, ".."+string(filepath.Separator)) ||
		relative == "." && !allowRoot {
		return "", errDaemonSnapshotIntegrity
	}
	return relative, nil
}

func openDaemonSnapshotPathUnder(
	base string,
	path string,
	directory bool,
) (*os.File, error) {
	root, err := openDaemonSnapshotPathRoot(base)
	if err != nil {
		return nil, err
	}
	defer func() { _ = root.Close() }()
	return root.open(path, directory)
}

func removeDaemonSnapshotTreeUnder(base, path string) error {
	root, err := openDaemonSnapshotPathRoot(base)
	if err != nil {
		return err
	}
	defer func() { _ = root.Close() }()
	return root.removeAll(path)
}

func removeDaemonSnapshotFileUnder(base, path string) error {
	root, err := openDaemonSnapshotPathRoot(base)
	if err != nil {
		return err
	}
	defer func() { _ = root.Close() }()
	return root.remove(path, false)
}

func createDaemonSnapshotFileUnder(
	base string,
	path string,
	flag int,
	permission os.FileMode,
) (*os.File, error) {
	root, err := openDaemonSnapshotPathRoot(base)
	if err != nil {
		return nil, err
	}
	defer func() { _ = root.Close() }()
	return root.createFile(path, flag, permission)
}

func createDaemonSnapshotTempFileUnder(
	base string,
	directory string,
	prefix string,
) (*os.File, string, error) {
	if prefix == "" || filepath.Base(prefix) != prefix {
		return nil, "", errDaemonSnapshotIntegrity
	}
	for range 100 {
		suffix := make([]byte, 16)
		if _, err := rand.Read(suffix); err != nil {
			return nil, "", err
		}
		path := filepath.Join(directory, prefix+hex.EncodeToString(suffix))
		file, err := createDaemonSnapshotFileUnder(
			base,
			path,
			os.O_CREATE|os.O_EXCL|os.O_RDWR,
			0o600,
		)
		if errors.Is(err, os.ErrExist) {
			continue
		}
		return file, path, err
	}
	return nil, "", errDaemonSnapshotIntegrity
}

func createDaemonSnapshotTempDirectoryUnder(
	base string,
	directory string,
	prefix string,
) (string, error) {
	if prefix == "" || filepath.Base(prefix) != prefix {
		return "", errDaemonSnapshotIntegrity
	}
	root, err := openDaemonSnapshotPathRoot(base)
	if err != nil {
		return "", err
	}
	defer func() { _ = root.Close() }()
	parent, err := root.open(directory, true)
	if err != nil {
		return "", err
	}
	if err := parent.Close(); err != nil {
		return "", err
	}
	for range 100 {
		suffix := make([]byte, 16)
		if _, err := rand.Read(suffix); err != nil {
			return "", err
		}
		path := filepath.Join(directory, prefix+hex.EncodeToString(suffix))
		relative, err := root.relative(path, false)
		if err != nil {
			return "", err
		}
		err = root.root.Mkdir(relative, 0o700)
		if errors.Is(err, os.ErrExist) {
			continue
		}
		if err != nil {
			return "", err
		}
		file, err := root.open(path, true)
		if err != nil {
			_ = root.root.Remove(relative)
			return "", err
		}
		if err := file.Close(); err != nil {
			_ = root.root.Remove(relative)
			return "", err
		}
		return path, nil
	}
	return "", errDaemonSnapshotIntegrity
}

func renameDaemonSnapshotPathUnder(
	base string,
	oldPath string,
	newPath string,
	directory bool,
) error {
	root, err := openDaemonSnapshotPathRoot(base)
	if err != nil {
		return err
	}
	defer func() { _ = root.Close() }()
	return root.rename(oldPath, newPath, directory)
}

func requireDaemonSnapshotDirectoryUnder(base, path string) error {
	file, err := openDaemonSnapshotPathUnder(base, path, true)
	if err != nil {
		return err
	}
	return file.Close()
}

func requireDaemonSnapshotRegularFileUnder(base, path string) error {
	file, err := openDaemonSnapshotPathUnder(base, path, false)
	if err != nil {
		return err
	}
	return file.Close()
}

// createDaemonSnapshotDirectoryTree creates only descendants of an already
// trusted owner-only directory and refuses links or reparse points at every
// existing component.
func createDaemonSnapshotDirectoryTree(base, target string) error {
	if !cleanAbsolutePath(base) ||
		!cleanAbsolutePath(target) {
		return errDaemonSnapshotIntegrity
	}
	relative, err := filepath.Rel(base, target)
	if err != nil ||
		relative == "." ||
		relative == ".." ||
		strings.HasPrefix(relative, ".."+string(filepath.Separator)) ||
		filepath.IsAbs(relative) {
		return errDaemonSnapshotIntegrity
	}
	root, err := openDaemonSnapshotPathRoot(base)
	if err != nil {
		return fmt.Errorf(
			"%w: insecure snapshot base: %v",
			errDaemonSnapshotIntegrity,
			err,
		)
	}
	defer func() { _ = root.Close() }()
	current := base
	for _, component := range strings.Split(relative, string(filepath.Separator)) {
		if component == "" || component == "." || component == ".." {
			return errDaemonSnapshotIntegrity
		}
		current = filepath.Join(current, component)
		relativeCurrent, relativeErr := root.relative(current, false)
		if relativeErr != nil {
			return relativeErr
		}
		err := root.root.Mkdir(relativeCurrent, 0o700)
		if err != nil && !errors.Is(err, os.ErrExist) {
			return err
		}
		file, openErr := root.open(current, true)
		if openErr != nil {
			return fmt.Errorf(
				"%w: insecure snapshot directory %q: %v",
				errDaemonSnapshotIntegrity,
				current,
				openErr,
			)
		}
		if err := file.Chmod(0o700); err != nil {
			_ = file.Close()
			return err
		}
		if err := file.Close(); err != nil {
			return err
		}
	}
	return nil
}
