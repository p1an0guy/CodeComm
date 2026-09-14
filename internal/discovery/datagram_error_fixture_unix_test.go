//go:build !windows

package discovery

import "syscall"

func testTruncatedDatagramError() error {
	return syscall.EMSGSIZE
}
