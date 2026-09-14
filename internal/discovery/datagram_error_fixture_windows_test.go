//go:build windows

package discovery

import "golang.org/x/sys/windows"

func testTruncatedDatagramError() error {
	return windows.WSAEMSGSIZE
}
