//go:build windows

package localipc

import (
	"context"
	"fmt"
	"os"
	"runtime"
	"testing"
	"time"
	"unsafe"

	"github.com/Microsoft/go-winio"
	"golang.org/x/sys/windows"
)

type acceptedPipePeer struct {
	pid  uint32
	sid  string
	dacl *windows.SECURITY_DESCRIPTOR
	err  error
}

var impersonateNamedPipeClient = windows.NewLazySystemDLL("advapi32.dll").NewProc("ImpersonateNamedPipeClient")

// assertOwnerOnlyDACL proves a descriptor grants exactly one ACCESS_ALLOWED ACE,
// to want, with inheritance blocked. It inspects parsed ACEs rather than
// descriptor.String(), because Windows canonicalizes well-known SIDs to
// two-letter SDDL abbreviations on render ("LA" for the built-in Administrator
// that CI runs as), so substring checks against a full SID give false failures
// while also failing to bound the total number of trustees.
func assertOwnerOnlyDACL(t *testing.T, descriptor *windows.SECURITY_DESCRIPTOR, want *windows.SID, label string) {
	t.Helper()
	dacl, _, err := descriptor.DACL()
	if err != nil {
		t.Fatalf("%s: read parsed DACL: %v", label, err)
	}
	if dacl == nil {
		t.Fatalf("%s: DACL is absent; a NULL DACL grants everyone access", label)
	}
	control, _, err := descriptor.Control()
	if err != nil {
		t.Fatalf("%s: read descriptor control bits: %v", label, err)
	}
	if control&windows.SE_DACL_PROTECTED == 0 {
		t.Fatalf("%s: DACL is not protected; inherited ACEs may widen access (control=%#x)", label, control)
	}
	if dacl.AceCount != 1 {
		t.Fatalf("%s: DACL grants %d trustees, want exactly one", label, dacl.AceCount)
	}
	var ace *windows.ACCESS_ALLOWED_ACE
	if err := windows.GetAce(dacl, 0, &ace); err != nil {
		t.Fatalf("%s: read DACL ACE 0: %v", label, err)
	}
	if ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE {
		t.Fatalf("%s: DACL ACE 0 type = %#x, want ACCESS_ALLOWED", label, ace.Header.AceType)
	}
	granted := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
	if !granted.Equals(want) {
		t.Fatalf("%s: DACL grants %q, want %q", label, granted.String(), want.String())
	}
}

func TestNamedPipeIsOwnerOnlyRejectsRemoteAndIdentifiesPeer(t *testing.T) {
	tokenUser, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatalf("read current token user: %v", err)
	}
	sid := tokenUser.User.Sid.String()
	sddl := "D:P(A;;GA;;;" + sid + ")"
	descriptor, err := windows.SecurityDescriptorFromString(sddl)
	if err != nil {
		t.Fatalf("parse owner-only DACL: %v", err)
	}
	assertOwnerOnlyDACL(t, descriptor, tokenUser.User.Sid, "constructed")

	pipePath := fmt.Sprintf(`\\.\pipe\codecomm-phase1-%d-%d`, os.Getpid(), time.Now().UnixNano())
	listener, err := winio.ListenPipe(pipePath, &winio.PipeConfig{
		SecurityDescriptor: sddl,
		InputBufferSize:    64 << 10,
		OutputBufferSize:   64 << 10,
	})
	if err != nil {
		t.Fatalf("listen on named pipe: %v", err)
	}
	t.Cleanup(func() { _ = listener.Close() })

	accepted := make(chan acceptedPipePeer, 1)
	go func() {
		connection, acceptErr := listener.Accept()
		if acceptErr != nil {
			accepted <- acceptedPipePeer{err: acceptErr}
			return
		}
		defer connection.Close()
		handleProvider, ok := connection.(interface{ Fd() uintptr })
		if !ok {
			accepted <- acceptedPipePeer{err: fmt.Errorf("accepted pipe does not expose its handle")}
			return
		}
		var pid uint32
		if err := windows.GetNamedPipeClientProcessId(windows.Handle(handleProvider.Fd()), &pid); err != nil {
			accepted <- acceptedPipePeer{err: err}
			return
		}
		clientSID, err := namedPipeClientSID(windows.Handle(handleProvider.Fd()))
		if err != nil {
			accepted <- acceptedPipePeer{err: err}
			return
		}
		appliedDescriptor, err := windows.GetSecurityInfo(
			windows.Handle(handleProvider.Fd()),
			windows.SE_KERNEL_OBJECT,
			windows.DACL_SECURITY_INFORMATION,
		)
		if err != nil {
			accepted <- acceptedPipePeer{err: fmt.Errorf("read named-pipe DACL: %w", err)}
			return
		}
		if appliedDescriptor == nil {
			accepted <- acceptedPipePeer{err: fmt.Errorf("named pipe has no security descriptor")}
			return
		}
		var request [1]byte
		if _, err := connection.Read(request[:]); err != nil {
			accepted <- acceptedPipePeer{err: err}
			return
		}
		if _, err := connection.Write([]byte{request[0] + 1}); err != nil {
			accepted <- acceptedPipePeer{err: err}
			return
		}
		accepted <- acceptedPipePeer{pid: pid, sid: clientSID, dacl: appliedDescriptor}
	}()

	timeout := 5 * time.Second
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	client, err := winio.DialPipeAccessImpLevel(
		ctx,
		pipePath,
		uint32(windows.GENERIC_READ|windows.GENERIC_WRITE),
		winio.PipeImpLevelIdentification,
	)
	if err != nil {
		t.Fatalf("dial named pipe: %v", err)
	}
	defer client.Close()
	if err := client.SetDeadline(time.Now().Add(timeout)); err != nil {
		t.Fatal(err)
	}
	if _, err := client.Write([]byte{41}); err != nil {
		t.Fatalf("write local request: %v", err)
	}
	var response [1]byte
	if _, err := client.Read(response[:]); err != nil {
		t.Fatalf("read local response: %v", err)
	}
	if response[0] != 42 {
		t.Fatalf("response = %d, want 42", response[0])
	}

	result := <-accepted
	if result.err != nil {
		t.Fatalf("accept/authenticate named-pipe peer: %v", result.err)
	}
	if result.pid != uint32(os.Getpid()) {
		t.Fatalf("peer pid = %d, want %d", result.pid, os.Getpid())
	}
	if result.sid != sid {
		t.Fatalf("peer SID = %q, want %q", result.sid, sid)
	}
	assertOwnerOnlyDACL(t, result.dacl, tokenUser.User.Sid, "applied")
	if listener.Addr().Network() != "pipe" || listener.Addr().String() != pipePath {
		t.Fatalf("named-pipe listener address = %s %q", listener.Addr().Network(), listener.Addr())
	}
}

func namedPipeClientSID(handle windows.Handle) (sid string, returnErr error) {
	runtime.LockOSThread()

	result, _, callErr := impersonateNamedPipeClient.Call(uintptr(handle))
	if result == 0 {
		runtime.UnlockOSThread()
		return "", fmt.Errorf("impersonate named-pipe client: %w", callErr)
	}
	defer func() {
		if err := windows.RevertToSelf(); err != nil {
			sid = ""
			returnErr = fmt.Errorf("revert named-pipe impersonation: %w", err)
			// Exiting while locked makes the runtime discard this OS thread.
			return
		}
		runtime.UnlockOSThread()
	}()

	thread, err := windows.GetCurrentThread()
	if err != nil {
		return "", fmt.Errorf("get current thread: %w", err)
	}
	var token windows.Token
	if err := windows.OpenThreadToken(thread, windows.TOKEN_QUERY, true, &token); err != nil {
		return "", fmt.Errorf("open impersonation token: %w", err)
	}
	defer token.Close()
	tokenUser, err := token.GetTokenUser()
	if err != nil {
		return "", fmt.Errorf("read impersonation token user: %w", err)
	}
	return tokenUser.User.Sid.String(), nil
}
