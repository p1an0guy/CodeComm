//go:build (!darwin && !linux && !windows) || (darwin && !cgo)

package credentialstore

import (
	"context"
	"fmt"
	"runtime"
)

func nativeProviderName() string {
	return "unsupported-" + runtime.GOOS
}

// OpenNative refuses unsupported platforms and macOS builds that cannot call
// Security.framework. It never substitutes file or in-memory storage.
func OpenNative(ctx context.Context) (*Store, error) {
	if ctx == nil {
		return nil, ErrInvalidContext
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return nil, fmt.Errorf(
		"%w: no native credential-store adapter for %s",
		ErrUnavailable,
		runtime.GOOS,
	)
}
