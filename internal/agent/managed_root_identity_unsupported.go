//go:build !unix && !windows

package agent

import "fmt"

func inspectNativeDirectory(string) (nativeDirectoryIdentity, error) {
	return nativeDirectoryIdentity{}, fmt.Errorf(
		"native directory identity is unsupported on this platform",
	)
}
