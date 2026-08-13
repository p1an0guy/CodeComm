//go:build unix

package agent

import (
	"fmt"
	"os"
	"path/filepath"
	"syscall"
)

func inspectNativeDirectory(path string) (_ nativeDirectoryIdentity, err error) {
	absolute, err := filepath.Abs(path)
	if err != nil {
		return nativeDirectoryIdentity{}, err
	}
	canonical, err := filepath.EvalSymlinks(absolute)
	if err != nil {
		return nativeDirectoryIdentity{}, err
	}
	canonical = filepath.Clean(canonical)

	directory, err := os.Open(canonical)
	if err != nil {
		return nativeDirectoryIdentity{}, err
	}
	defer func() {
		if closeErr := directory.Close(); err == nil && closeErr != nil {
			err = closeErr
		}
	}()

	info, err := directory.Stat()
	if err != nil {
		return nativeDirectoryIdentity{}, err
	}
	if !info.IsDir() {
		return nativeDirectoryIdentity{}, fmt.Errorf("%q is not a directory", canonical)
	}
	current, err := os.Stat(canonical)
	if err != nil {
		return nativeDirectoryIdentity{}, err
	}
	if !os.SameFile(info, current) {
		return nativeDirectoryIdentity{}, ErrManagedRootIdentityChanged
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat == nil {
		return nativeDirectoryIdentity{}, fmt.Errorf(
			"native directory identity is unavailable",
		)
	}
	return nativeDirectoryIdentity{
		canonicalPath: canonical,
		value: fmt.Sprintf(
			"codecomm-directory-v1:unix:%x:%x",
			stat.Dev,
			stat.Ino,
		),
	}, nil
}
