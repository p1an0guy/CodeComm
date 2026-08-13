//go:build windows

package discovery

import (
	"errors"
	"golang.org/x/sys/windows"
)

func isDatagramTooLargeError(err error) bool {
	return errors.Is(err, windows.WSAEMSGSIZE)
}
