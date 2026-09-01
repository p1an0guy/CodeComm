package store

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
)

func openDatabaseFile(path string, syncParent func(string) error) (bool, error) {
	parent := filepath.Dir(path)
	if err := os.MkdirAll(parent, 0o700); err != nil {
		return false, fmt.Errorf("store: create database directory: %w", err)
	}
	parentInfo, err := os.Lstat(parent)
	if err != nil {
		return false, fmt.Errorf("store: inspect database directory: %w", err)
	}
	if !parentInfo.IsDir() || parentInfo.Mode()&os.ModeSymlink != 0 {
		return false, fmt.Errorf("%w: parent is not a real directory", ErrInsecurePath)
	}
	if insecurePermissions(parentInfo.Mode()) {
		return false, fmt.Errorf(
			"%w: parent mode %04o permits group or other access",
			ErrInsecurePath,
			parentInfo.Mode().Perm(),
		)
	}

	file, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE|os.O_EXCL, 0o600)
	switch {
	case err == nil:
		if syncParent == nil {
			_ = file.Close()
			return false, fmt.Errorf("%w: nil parent sync function", ErrInvalidOptions)
		}
		if validationErr := validateOpenedDatabaseFile(
			path,
			file,
		); validationErr != nil {
			_ = file.Close()
			return false, validationErr
		}
		if syncErr := file.Sync(); syncErr != nil {
			_ = file.Close()
			return false, fmt.Errorf("store: sync new database file: %w", syncErr)
		}
		if closeErr := file.Close(); closeErr != nil {
			return false, fmt.Errorf("store: close new database file: %w", closeErr)
		}
		if syncErr := syncParent(parent); syncErr != nil {
			return false, fmt.Errorf("store: sync database directory: %w", syncErr)
		}
		return true, nil
	case !errors.Is(err, fs.ErrExist):
		return false, fmt.Errorf("store: create database file: %w", err)
	}

	info, err := os.Lstat(path)
	if err != nil {
		return false, fmt.Errorf("store: inspect database file: %w", err)
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return false, fmt.Errorf("%w: database is not a regular file", ErrInsecurePath)
	}
	if insecurePermissions(info.Mode()) {
		return false, fmt.Errorf(
			"%w: database mode %04o permits group or other access",
			ErrInsecurePath,
			info.Mode().Perm(),
		)
	}
	file, err = os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		return false, fmt.Errorf("store: open database file: %w", err)
	}
	validationErr := validateOpenedDatabaseFile(path, file)
	closeErr := file.Close()
	if closeErr != nil {
		closeErr = fmt.Errorf(
			"store: close validated database file: %w",
			closeErr,
		)
	}
	if validationErr != nil || closeErr != nil {
		return false, errors.Join(validationErr, closeErr)
	}
	return false, nil
}

func validateOpenedDatabaseFile(path string, file *os.File) error {
	if file == nil {
		return fmt.Errorf("%w: database handle is unavailable", ErrInsecurePath)
	}
	info, err := file.Stat()
	if err != nil {
		return fmt.Errorf("store: inspect open database file: %w", err)
	}
	pathInfo, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("store: re-inspect database file: %w", err)
	}
	if !info.Mode().IsRegular() ||
		!pathInfo.Mode().IsRegular() ||
		pathInfo.Mode()&os.ModeSymlink != 0 ||
		!os.SameFile(info, pathInfo) {
		return fmt.Errorf(
			"%w: database path does not name its opened regular file",
			ErrInsecurePath,
		)
	}
	if insecurePermissions(info.Mode()) {
		return fmt.Errorf(
			"%w: database mode %04o permits group or other access",
			ErrInsecurePath,
			info.Mode().Perm(),
		)
	}
	if err := validateDatabaseLinkCount(file, info); err != nil {
		return errors.Join(ErrInsecurePath, err)
	}
	return nil
}
