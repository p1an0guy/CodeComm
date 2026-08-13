//go:build windows

package ipc

import (
	"fmt"
	"net"
	"runtime"
	"unsafe"

	"golang.org/x/sys/windows"
)

var peekNamedPipe = windows.NewLazySystemDLL(
	"kernel32.dll",
).NewProc("PeekNamedPipe")

func pendingNativeBytes(connection net.Conn) (bool, error) {
	handle, err := pipeHandle(connection)
	if err != nil {
		return false, err
	}
	var available uint32
	success, _, callErr := peekNamedPipe.Call(
		uintptr(handle),
		0,
		0,
		0,
		uintptr(unsafe.Pointer(&available)),
		0,
	)
	runtime.KeepAlive(connection)
	if success == 0 {
		return false, fmt.Errorf("ipc: probe named-pipe pipeline: %w", callErr)
	}
	return available > 0, nil
}
