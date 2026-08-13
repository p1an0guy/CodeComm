//go:build windows

package ipc

import (
	"context"
	"errors"
	"fmt"
	"net"
	"runtime"
	"strings"
	"unsafe"

	"github.com/Microsoft/go-winio"
	"golang.org/x/sys/windows"
)

const windowsPipePrefix = `\\.\pipe\`

// x/sys/windows does not expose FILE_ALL_ACCESS, which is the object-specific
// mask Windows produces when it maps GENERIC_ALL for a named pipe.
const windowsFileAllAccess windows.ACCESS_MASK = windows.STANDARD_RIGHTS_REQUIRED |
	windows.SYNCHRONIZE |
	0x1ff

var impersonateNamedPipeClient = windows.NewLazySystemDLL(
	"advapi32.dll",
).NewProc("ImpersonateNamedPipeClient")

func validateEndpointAddress(address string) error {
	if !strings.HasPrefix(address, windowsPipePrefix) ||
		len(address) <= len(windowsPipePrefix) ||
		len(address) > 256 {
		return errors.New("named pipe must use a bounded local \\\\.\\pipe\\ path")
	}
	name := address[len(windowsPipePrefix):]
	for index := 0; index < len(name); index++ {
		character := name[index]
		if character >= 'a' && character <= 'z' ||
			character >= 'A' && character <= 'Z' ||
			character >= '0' && character <= '9' ||
			character == '-' ||
			character == '_' ||
			character == '.' {
			continue
		}
		return errors.New("named-pipe name must contain only ASCII letters, digits, '.', '_', or '-'")
	}
	return nil
}

func listenNative(
	endpoint Endpoint,
) (net.Listener, string, func() error, error) {
	ownerSID, err := currentUserSID()
	if err != nil {
		return nil, "", nil, err
	}
	securityDescriptor := "O:" + ownerSID + "D:P(A;;GA;;;" + ownerSID + ")"
	if err := validateSecurityDescriptorString(securityDescriptor, ownerSID); err != nil {
		return nil, "", nil, err
	}
	listener, err := winio.ListenPipe(endpoint.address, &winio.PipeConfig{
		SecurityDescriptor: securityDescriptor,
		MessageMode:        false,
		InputBufferSize:    64 << 10,
		OutputBufferSize:   64 << 10,
	})
	if err != nil {
		return nil, "", nil, fmt.Errorf("ipc: listen on Windows named pipe: %w", err)
	}
	return listener, ownerSID, func() error { return nil }, nil
}

func dialNative(
	ctx context.Context,
	endpoint Endpoint,
) (net.Conn, VerifiedPeer, error) {
	ownerSID, err := currentUserSID()
	if err != nil {
		return nil, VerifiedPeer{}, err
	}
	connection, err := winio.DialPipeAccessImpLevel(
		ctx,
		endpoint.address,
		uint32(windows.GENERIC_READ|windows.GENERIC_WRITE),
		winio.PipeImpLevelIdentification,
	)
	if err != nil {
		return nil, VerifiedPeer{}, fmt.Errorf("ipc: dial Windows named pipe: %w", err)
	}
	handle, err := pipeHandle(connection)
	if err != nil {
		_ = connection.Close()
		return nil, VerifiedPeer{}, err
	}
	if err := validatePipeSecurity(handle, ownerSID); err != nil {
		_ = connection.Close()
		if peerGoneWindowsError(err) {
			return nil, VerifiedPeer{}, fmt.Errorf(
				"%w: server closed before descriptor verification",
				ErrEndpointUnavailable,
			)
		}
		return nil, VerifiedPeer{}, err
	}
	var processID uint32
	if err := windows.GetNamedPipeServerProcessId(handle, &processID); err != nil {
		_ = connection.Close()
		if peerGoneWindowsError(err) {
			return nil, VerifiedPeer{}, fmt.Errorf(
				"%w: server closed before PID verification",
				ErrEndpointUnavailable,
			)
		}
		return nil, VerifiedPeer{}, fmt.Errorf(
			"%w: read named-pipe server PID: %w",
			ErrPeerAuthentication,
			err,
		)
	}
	runtime.KeepAlive(connection)
	if processID == 0 {
		_ = connection.Close()
		return nil, VerifiedPeer{}, fmt.Errorf(
			"%w: named-pipe server PID is zero",
			ErrPeerAuthentication,
		)
	}
	return connection, VerifiedPeer{
		processID: processID,
		userID:    ownerSID,
	}, nil
}

func authenticateAcceptedPeer(
	connection net.Conn,
	ownerSID string,
) (VerifiedPeer, error) {
	handle, err := pipeHandle(connection)
	if err != nil {
		return VerifiedPeer{}, err
	}
	if err := validatePipeSecurity(handle, ownerSID); err != nil {
		return VerifiedPeer{}, err
	}
	var processID uint32
	if err := windows.GetNamedPipeClientProcessId(handle, &processID); err != nil {
		return VerifiedPeer{}, fmt.Errorf(
			"%w: read named-pipe client PID: %v",
			ErrPeerAuthentication,
			err,
		)
	}
	clientSID, err := namedPipeClientSID(handle)
	runtime.KeepAlive(connection)
	if err != nil {
		return VerifiedPeer{}, err
	}
	expected, err := windows.StringToSid(ownerSID)
	if err != nil {
		return VerifiedPeer{}, fmt.Errorf(
			"%w: parse expected owner SID: %v",
			ErrPeerAuthentication,
			err,
		)
	}
	actual, err := windows.StringToSid(clientSID)
	if err != nil || !actual.Equals(expected) || processID == 0 {
		return VerifiedPeer{}, fmt.Errorf(
			"%w: named-pipe client account mismatch",
			ErrPeerAuthentication,
		)
	}
	return VerifiedPeer{processID: processID, userID: clientSID}, nil
}

func pipeHandle(connection net.Conn) (windows.Handle, error) {
	connection = nativeConnection(connection)
	provider, ok := connection.(interface{ Fd() uintptr })
	if !ok {
		return 0, fmt.Errorf(
			"%w: named-pipe connection exposes no kernel handle",
			ErrTransportIntegrity,
		)
	}
	handle := windows.Handle(provider.Fd())
	if handle == 0 || handle == windows.InvalidHandle {
		return 0, fmt.Errorf(
			"%w: named-pipe connection has an invalid kernel handle",
			ErrTransportIntegrity,
		)
	}
	return handle, nil
}

func currentUserSID() (string, error) {
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return "", fmt.Errorf("ipc: read current Windows user SID: %w", err)
	}
	return user.User.Sid.String(), nil
}

func validateSecurityDescriptorString(descriptorText, ownerSID string) error {
	descriptor, err := windows.SecurityDescriptorFromString(descriptorText)
	if err != nil {
		return fmt.Errorf("ipc: parse named-pipe security descriptor: %w", err)
	}
	return validateOwnerOnlyDescriptor(descriptor, ownerSID)
}

func validatePipeSecurity(handle windows.Handle, ownerSID string) error {
	descriptor, err := windows.GetSecurityInfo(
		handle,
		windows.SE_KERNEL_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION,
	)
	if err != nil {
		return fmt.Errorf(
			"%w: read named-pipe security descriptor: %w",
			ErrEndpointInsecure,
			err,
		)
	}
	if descriptor == nil {
		return fmt.Errorf(
			"%w: named pipe has no security descriptor",
			ErrEndpointInsecure,
		)
	}
	return validateOwnerOnlyDescriptor(descriptor, ownerSID)
}

func peerGoneWindowsError(err error) bool {
	return errors.Is(err, windows.ERROR_BROKEN_PIPE) ||
		errors.Is(err, windows.ERROR_NO_DATA) ||
		errors.Is(err, windows.ERROR_PIPE_NOT_CONNECTED) ||
		errors.Is(err, windows.ERROR_INVALID_HANDLE)
}

func validateOwnerOnlyDescriptor(
	descriptor *windows.SECURITY_DESCRIPTOR,
	ownerSID string,
) error {
	expected, err := windows.StringToSid(ownerSID)
	if err != nil {
		return fmt.Errorf("ipc: parse Windows owner SID: %w", err)
	}
	owner, _, err := descriptor.Owner()
	if err != nil || owner == nil || !owner.Equals(expected) {
		return fmt.Errorf(
			"%w: named-pipe descriptor owner does not match current user",
			ErrEndpointInsecure,
		)
	}
	control, _, err := descriptor.Control()
	if err != nil || control&windows.SE_DACL_PROTECTED == 0 {
		return fmt.Errorf(
			"%w: named-pipe DACL is not protected",
			ErrEndpointInsecure,
		)
	}
	dacl, _, err := descriptor.DACL()
	if err != nil || dacl == nil || dacl.AceCount != 1 {
		return fmt.Errorf(
			"%w: named-pipe DACL must contain exactly one ACE",
			ErrEndpointInsecure,
		)
	}
	var ace *windows.ACCESS_ALLOWED_ACE
	if err := windows.GetAce(dacl, 0, &ace); err != nil {
		return fmt.Errorf(
			"%w: read named-pipe DACL: %v",
			ErrEndpointInsecure,
			err,
		)
	}
	granted := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
	grantsFullAccess := ace.Mask == windows.GENERIC_ALL ||
		ace.Mask == windowsFileAllAccess
	if ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE ||
		ace.Header.AceFlags != 0 ||
		!grantsFullAccess ||
		!granted.Equals(expected) {
		return fmt.Errorf(
			"%w: named-pipe DACL is not an exact owner-only grant (mask %#x)",
			ErrEndpointInsecure,
			ace.Mask,
		)
	}
	return nil
}

type impersonationResult struct {
	sid string
	err error
}

func namedPipeClientSID(handle windows.Handle) (string, error) {
	result := make(chan impersonationResult, 1)
	go inspectNamedPipeClient(handle, result)
	inspected := <-result
	return inspected.sid, inspected.err
}

func inspectNamedPipeClient(
	handle windows.Handle,
	result chan<- impersonationResult,
) {
	runtime.LockOSThread()
	unlockThread := true
	defer func() {
		if unlockThread {
			runtime.UnlockOSThread()
		}
	}()

	success, _, callErr := impersonateNamedPipeClient.Call(uintptr(handle))
	if success == 0 {
		result <- impersonationResult{
			err: fmt.Errorf(
				"%w: impersonate named-pipe client: %v",
				ErrPeerAuthentication,
				callErr,
			),
		}
		return
	}

	inspected := readImpersonationToken()
	if err := windows.RevertToSelf(); err != nil {
		// The goroutine exits while locked so the runtime discards this OS
		// thread instead of returning an impersonated thread to its pool.
		unlockThread = false
		result <- impersonationResult{
			err: fmt.Errorf(
				"%w: revert named-pipe impersonation: %v",
				ErrTransportIntegrity,
				err,
			),
		}
		return
	}
	result <- inspected
}

func readImpersonationToken() impersonationResult {
	thread, err := windows.GetCurrentThread()
	if err != nil {
		return impersonationResult{err: fmt.Errorf(
			"%w: get current Windows thread: %v",
			ErrPeerAuthentication,
			err,
		)}
	}
	var token windows.Token
	if err := windows.OpenThreadToken(
		thread,
		windows.TOKEN_QUERY,
		true,
		&token,
	); err != nil {
		return impersonationResult{err: fmt.Errorf(
			"%w: open named-pipe impersonation token: %v",
			ErrPeerAuthentication,
			err,
		)}
	}
	defer token.Close()

	var (
		level    uint32
		returned uint32
	)
	if err := windows.GetTokenInformation(
		token,
		windows.TokenImpersonationLevel,
		(*byte)(unsafe.Pointer(&level)),
		uint32(unsafe.Sizeof(level)),
		&returned,
	); err != nil || returned != uint32(unsafe.Sizeof(level)) ||
		level < windows.SecurityIdentification {
		return impersonationResult{err: fmt.Errorf(
			"%w: named-pipe token lacks identification impersonation",
			ErrPeerAuthentication,
		)}
	}
	user, err := token.GetTokenUser()
	if err != nil {
		return impersonationResult{err: fmt.Errorf(
			"%w: read named-pipe impersonation SID: %v",
			ErrPeerAuthentication,
			err,
		)}
	}
	return impersonationResult{sid: user.User.Sid.String()}
}

func normalizeListenerCloseError(err error) error {
	if errors.Is(err, net.ErrClosed) ||
		errors.Is(err, winio.ErrPipeListenerClosed) ||
		errors.Is(err, winio.ErrFileClosed) {
		return nil
	}
	return err
}
