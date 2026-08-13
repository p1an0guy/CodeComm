//go:build windows

package ipc

import (
	"fmt"
	"os"
	"testing"
	"time"
)

func testEndpointAddress(string) string {
	return fmt.Sprintf(
		`\\.\pipe\codecomm-test-%d-%d`,
		os.Getpid(),
		time.Now().UnixNano(),
	)
}

func testRuntimeDirectory(t *testing.T) string {
	t.Helper()
	return t.TempDir()
}
