//go:build darwin && cgo

package credentialstore

import (
	"context"
	"errors"
	"os"
	"runtime"
	"strings"
	"testing"
)

func TestOpenNativeUsesMacOSKeychain(t *testing.T) {
	t.Parallel()

	store, err := OpenNative(context.Background())
	if err != nil {
		t.Fatalf("OpenNative() error = %v", err)
	}
	if got := store.Provider(); got != darwinProviderName {
		t.Fatalf("Store.Provider() = %q, want %q", got, darwinProviderName)
	}
}

func TestClassifyDarwinStatus(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		status int32
		want   error
	}{
		{name: "success", status: darwinStatusSuccess},
		{name: "not found", status: darwinStatusItemNotFound, want: ErrNotFound},
		{name: "duplicate", status: darwinStatusDuplicateItem, want: ErrAlreadyExists},
		{name: "locked", status: darwinStatusInteractionNotAllowed, want: ErrLocked},
		{name: "interaction required", status: darwinStatusInteractionRequired, want: ErrLocked},
		{name: "dark wake", status: darwinStatusInDarkWake, want: ErrLocked},
		{name: "unavailable", status: darwinStatusNotAvailable, want: ErrUnavailable},
		{name: "missing keychain", status: darwinStatusNoSuchKeychain, want: ErrUnavailable},
		{name: "missing default keychain", status: darwinStatusNoDefaultKeychain, want: ErrUnavailable},
		{name: "missing storage module", status: darwinStatusNoStorageModule, want: ErrUnavailable},
		{name: "missing service", status: darwinStatusServiceNotAvailable, want: ErrUnavailable},
		{name: "authentication failed", status: darwinStatusAuthFailed, want: ErrAccessDenied},
		{name: "write denied", status: darwinStatusWritePermission, want: ErrAccessDenied},
		{name: "read only", status: darwinStatusReadOnly, want: ErrAccessDenied},
		{name: "user canceled", status: darwinStatusUserCanceled, want: ErrAccessDenied},
		{name: "missing entitlement", status: darwinStatusMissingEntitlement, want: ErrAccessDenied},
		{name: "restricted API", status: darwinStatusRestrictedAPI, want: ErrAccessDenied},
		{name: "read-only attribute", status: darwinStatusReadOnlyAttribute, want: ErrAccessDenied},
		{name: "no item access", status: darwinStatusNoAccessForItem, want: ErrAccessDenied},
		{name: "bad client identity", status: darwinStatusInsufficientClientID, want: ErrAccessDenied},
		{name: "invalid keychain", status: darwinStatusInvalidKeychain, want: ErrCorrupt},
		{name: "invalid item", status: darwinStatusInvalidItemRef, want: ErrCorrupt},
		{name: "invalid class", status: darwinStatusNoSuchClass, want: ErrCorrupt},
		{name: "wrong version", status: darwinStatusWrongVersion, want: ErrCorrupt},
		{name: "decode", status: darwinStatusDecode, want: ErrCorrupt},
		{name: "unknown", status: -987654, want: ErrUnreadable},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			err := classifyDarwinStatus(test.status)
			if test.want == nil {
				if err != nil {
					t.Fatalf("classifyDarwinStatus(%d) = %v, want nil", test.status, err)
				}
				return
			}
			if !errors.Is(err, test.want) {
				t.Fatalf(
					"classifyDarwinStatus(%d) = %v, want errors.Is(_, %v)",
					test.status,
					err,
					test.want,
				)
			}
			var statusError *darwinKeychainError
			if !errors.As(err, &statusError) || statusError.status != test.status {
				t.Fatalf("classified error = %#v, want status %d", err, test.status)
			}
		})
	}
}

func TestNativeBackendChecksContextBeforeCalls(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	called := false
	calls := &darwinCalls{
		get: func(string) ([]byte, error) {
			called = true
			return nil, nil
		},
		create: func(string, []byte) error {
			called = true
			return nil
		},
		delete: func(string) error {
			called = true
			return nil
		},
	}
	backend := &nativeBackend{calls: calls}

	if _, err := backend.Get(ctx, "identity/v1"); !errors.Is(err, context.Canceled) {
		t.Fatalf("nativeBackend.Get() error = %v, want %v", err, context.Canceled)
	}
	if err := backend.Create(ctx, "identity/v1", []byte("secret")); !errors.Is(err, context.Canceled) {
		t.Fatalf("nativeBackend.Create() error = %v, want %v", err, context.Canceled)
	}
	if err := backend.Delete(ctx, "identity/v1"); !errors.Is(err, context.Canceled) {
		t.Fatalf("nativeBackend.Delete() error = %v, want %v", err, context.Canceled)
	}
	if called {
		t.Fatal("native backend called Keychain after context cancellation")
	}
}

func TestNativeBackendChecksContextAfterCallsAndClearsSecrets(t *testing.T) {
	t.Parallel()

	getContext, cancelGet := context.WithCancel(context.Background())
	getSecret := []byte("retrieved secret")
	getBackend := &nativeBackend{calls: &darwinCalls{
		get: func(string) ([]byte, error) {
			cancelGet()
			return getSecret, nil
		},
	}}
	got, err := getBackend.Get(getContext, "identity/v1")
	if !errors.Is(err, context.Canceled) || got != nil {
		t.Fatalf("nativeBackend.Get() = (%q, %v), want (nil, context.Canceled)", got, err)
	}
	assertCleared(t, getSecret)

	createContext, cancelCreate := context.WithCancel(context.Background())
	createSecret := []byte("created secret")
	var backendCopy []byte
	createBackend := &nativeBackend{calls: &darwinCalls{
		create: func(_ string, value []byte) error {
			backendCopy = value
			cancelCreate()
			return nil
		},
	}}
	err = createBackend.Create(createContext, "identity/v1", createSecret)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("nativeBackend.Create() error = %v, want %v", err, context.Canceled)
	}
	assertCleared(t, backendCopy)

	deleteContext, cancelDelete := context.WithCancel(context.Background())
	deleteBackend := &nativeBackend{calls: &darwinCalls{
		delete: func(string) error {
			cancelDelete()
			return nil
		},
	}}
	if err := deleteBackend.Delete(deleteContext, "identity/v1"); !errors.Is(err, context.Canceled) {
		t.Fatalf("nativeBackend.Delete() error = %v, want %v", err, context.Canceled)
	}
}

func TestDarwinNativeSourceUsesRequiredSecurityAPIs(t *testing.T) {
	t.Parallel()

	_, testFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller() did not return this test file")
	}
	source, err := os.ReadFile(strings.TrimSuffix(testFile, "_test.go") + ".go")
	if err != nil {
		t.Fatalf("read native Darwin source: %v", err)
	}
	text := string(source)

	required := []string{
		"#cgo LDFLAGS: -framework CoreFoundation -framework Security",
		"#cgo CFLAGS: -Wno-deprecated-declarations",
		"SecItemCopyMatching(",
		"SecItemAdd(",
		"SecItemDelete(",
		"SecTrustedApplicationCreateFromPath(NULL",
		"SecAccessCreate(",
		"kSecAttrAccess",
		"kSecAttrAccessibleWhenUnlockedThisDeviceOnly",
		"kSecAttrSynchronizable, kCFBooleanFalse",
		"kSecUseAuthenticationUIFail",
	}
	for _, fragment := range required {
		if !strings.Contains(text, fragment) {
			t.Errorf("native Darwin source does not contain %q", fragment)
		}
	}
	for _, forbidden := range []string{"os/exec", "exec.Command", "/usr/bin/security"} {
		if strings.Contains(text, forbidden) {
			t.Errorf("native Darwin source contains forbidden command integration %q", forbidden)
		}
	}
}

func assertCleared(t *testing.T, value []byte) {
	t.Helper()
	for index, current := range value {
		if current != 0 {
			t.Fatalf("secret byte %d = %d after operation, want zero", index, current)
		}
	}
}
