//go:build !windows

package discovery

import (
	"errors"
	"syscall"
)

func isDatagramTooLargeError(err error) bool {
	return errors.Is(err, syscall.EMSGSIZE)
}
