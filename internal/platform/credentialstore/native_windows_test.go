//go:build windows

package credentialstore

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/danieljoos/wincred"
	"golang.org/x/sys/windows"
)

func TestOpenNativeContract(t *testing.T) {
	t.Parallel()

	store, err := OpenNative(context.Background())
	if err != nil {
		t.Fatalf("OpenNative() error = %v", err)
	}
	if got := store.Provider(); got != windowsProviderName {
		t.Fatalf("Store.Provider() = %q, want %q", got, windowsProviderName)
	}
	if got := (&windowsBackend{}).Name(); got != "windows-credential-manager" {
		t.Fatalf("windowsBackend.Name() = %q", got)
	}
}

func TestWindowsTargetUsesFixedNamespace(t *testing.T) {
	t.Parallel()

	for _, test := range []struct {
		key  string
		want string
	}{
		{key: "identity/v1", want: "CodeComm/credential/v1/identity/v1"},
		{
			key:  "epoch/v1/018f22a0-7ab3-7abc-8def-1234567890ab/device/2",
			want: "CodeComm/credential/v1/epoch/v1/018f22a0-7ab3-7abc-8def-1234567890ab/device/2",
		},
	} {
		if got := windowsTarget(test.key); got != test.want {
			t.Errorf("windowsTarget(%q) = %q, want %q", test.key, got, test.want)
		}
	}
}

func TestNewWindowsCredentialPreservesExactBytesAndPersistence(t *testing.T) {
	t.Parallel()

	value := []byte{0x00, 0xff, 0x7f, 0x01}
	credential := newWindowsCredential("CodeComm/test", value)
	if credential.TargetName != "CodeComm/test" {
		t.Fatalf("TargetName = %q", credential.TargetName)
	}
	if credential.Persist != wincred.PersistLocalMachine {
		t.Fatalf("Persist = %v, want PersistLocalMachine", credential.Persist)
	}
	if !bytes.Equal(credential.CredentialBlob, value) {
		t.Fatalf("CredentialBlob = %x, want %x", credential.CredentialBlob, value)
	}
	if credential.UserName != "" || credential.TargetAlias != "" ||
		credential.Comment != "" || len(credential.Attributes) != 0 {
		t.Fatal("generic credential contains unexpected metadata")
	}
}

func TestClassifyWindowsError(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		native error
		want   error
	}{
		{name: "not found", native: wincred.ErrElementNotFound, want: ErrNotFound},
		{name: "already exists", native: windows.ERROR_ALREADY_EXISTS, want: ErrAlreadyExists},
		{
			name:   "locked key state",
			native: windows.Errno(windows.NTE_BAD_KEY_STATE),
			want:   ErrLocked,
		},
		{name: "locked account", native: windows.ERROR_ACCOUNT_LOCKED_OUT, want: ErrLocked},
		{
			name:   "no logon session",
			native: windows.ERROR_NO_SUCH_LOGON_SESSION,
			want:   ErrUnavailable,
		},
		{
			name:   "service unavailable",
			native: windows.RPC_S_SERVER_UNAVAILABLE,
			want:   ErrUnavailable,
		},
		{name: "access denied", native: windows.ERROR_ACCESS_DENIED, want: ErrAccessDenied},
		{
			name:   "crypto access denied",
			native: windows.Errno(windows.NTE_PERM),
			want:   ErrAccessDenied,
		},
		{name: "invalid parameter", native: wincred.ErrInvalidParameter, want: ErrUnreadable},
		{name: "invalid data", native: windows.ERROR_INVALID_DATA, want: ErrCorrupt},
		{name: "unknown", native: windows.ERROR_BUSY, want: ErrUnreadable},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			native := fmt.Errorf("binding: %w", test.native)
			got := classifyWindowsError(native)
			if !errors.Is(got, test.want) {
				t.Fatalf("classifyWindowsError() = %v, want %v", got, test.want)
			}
			if !errors.Is(got, test.native) {
				t.Fatalf("classifyWindowsError() lost native error %v: %v", test.native, got)
			}
		})
	}

	if err := classifyWindowsError(nil); err != nil {
		t.Fatalf("classifyWindowsError(nil) = %v, want nil", err)
	}
}

func TestWindowsCallErrorPreservesContextCancellation(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	err := windowsCallError(ctx, windows.ERROR_ACCESS_DENIED)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("windowsCallError() = %v, want context.Canceled", err)
	}
	if errors.Is(err, ErrAccessDenied) {
		t.Fatalf("windowsCallError() = %v, native error overrode context", err)
	}
	//lint:ignore SA1012 This is deliberate invalid-input coverage for a private boundary.
	if err := windowsCallError(nil, windows.ERROR_ACCESS_DENIED); !errors.Is(err, ErrInvalidContext) {
		t.Fatalf("windowsCallError(nil) = %v, want ErrInvalidContext", err)
	}

	deadlineErr := classifyWindowsError(context.DeadlineExceeded)
	if !errors.Is(deadlineErr, context.DeadlineExceeded) {
		t.Fatalf("classifyWindowsError(deadline) = %v", deadlineErr)
	}
}

func TestWindowsCreateMutexNameIsStablePerUserWithoutExposingSID(t *testing.T) {
	t.Parallel()

	const sid = "S-1-5-21-111-222-333-1001"
	first := windowsCreateMutexName(sid)
	second := windowsCreateMutexName(sid)
	other := windowsCreateMutexName("S-1-5-21-111-222-333-1002")

	if first != second {
		t.Fatalf("mutex name is not stable: %q != %q", first, second)
	}
	if first == other {
		t.Fatalf("different users received the same mutex name %q", first)
	}
	if !strings.HasPrefix(first, windowsMutexNamePrefix) {
		t.Fatalf("mutex name = %q, want prefix %q", first, windowsMutexNamePrefix)
	}
	if strings.Contains(first, sid) {
		t.Fatalf("mutex name exposes the user SID: %q", first)
	}
	if got, want := len(strings.TrimPrefix(first, windowsMutexNamePrefix)), 32; got != want {
		t.Fatalf("mutex digest length = %d, want %d", got, want)
	}
}

func TestClearBytes(t *testing.T) {
	t.Parallel()

	value := []byte("private key material")
	clearBytes(value)
	if !bytes.Equal(value, make([]byte, len(value))) {
		t.Fatalf("clearBytes() left data behind: %x", value)
	}
}
