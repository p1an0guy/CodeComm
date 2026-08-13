//go:build linux || darwin

package ipc

import (
	"os"
	"path/filepath"
	"testing"
)

func testEndpointAddress(directory string) string {
	return filepath.Join(directory, "codecomm.sock")
}

func testRuntimeDirectory(t *testing.T) string {
	t.Helper()
	directory, err := os.MkdirTemp("/tmp", "cc-ipc-")
	if err != nil {
		t.Fatalf("create short IPC runtime directory: %v", err)
	}
	if err := os.Chmod(directory, 0o700); err != nil {
		_ = os.RemoveAll(directory)
		t.Fatalf("chmod IPC runtime directory: %v", err)
	}
	t.Cleanup(func() {
		_ = os.RemoveAll(directory)
	})
	return directory
}
