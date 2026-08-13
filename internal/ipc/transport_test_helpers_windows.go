//go:build windows

package ipc

import (
	"fmt"
	"os"
	"sync/atomic"
	"testing"
)

var testEndpointSequence atomic.Uint64

func testEndpointAddress(string) string {
	return fmt.Sprintf(
		`\\.\pipe\codecomm-test-%d-%d`,
		os.Getpid(),
		testEndpointSequence.Add(1),
	)
}

func testRuntimeDirectory(t *testing.T) string {
	t.Helper()
	return t.TempDir()
}
