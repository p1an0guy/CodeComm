//go:build windows

package credentialstore

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/danieljoos/wincred"
	"golang.org/x/sys/windows"
)

const (
	windowsProviderName     = "windows-credential-manager"
	windowsTargetPrefix     = "CodeComm/credential/v1/"
	windowsMutexNamePrefix  = `Global\CodeComm.CredentialStore.Create.v1.`
	windowsMutexPollMillis  = 50
	windowsMutexDigestBytes = 16
)

type windowsBackend struct{}

var _ backend = (*windowsBackend)(nil)

func nativeProviderName() string {
	return windowsProviderName
}

// OpenNative opens the current user's Windows Credential Manager store.
func OpenNative(ctx context.Context) (*Store, error) {
	if err := windowsContextError(ctx); err != nil {
		return nil, err
	}
	return newStore(&windowsBackend{})
}

func (*windowsBackend) Name() string {
	return windowsProviderName
}

func (*windowsBackend) Close() error {
	return nil
}

func (*windowsBackend) Get(ctx context.Context, key string) ([]byte, error) {
	if err := windowsContextError(ctx); err != nil {
		return nil, err
	}

	target := windowsTarget(key)
	credential, nativeErr := wincred.GetGenericCredential(target)
	if credential != nil {
		defer clearBytes(credential.CredentialBlob)
	}
	if err := windowsCallError(ctx, nativeErr); err != nil {
		return nil, err
	}
	if credential == nil ||
		credential.TargetName != target ||
		credential.Persist != wincred.PersistLocalMachine {
		return nil, fmt.Errorf("%w: malformed generic credential", ErrCorrupt)
	}

	value := append([]byte(nil), credential.CredentialBlob...)
	if err := ctx.Err(); err != nil {
		clearBytes(value)
		return nil, err
	}
	return value, nil
}

func (*windowsBackend) Create(ctx context.Context, key string, value []byte) (result error) {
	defer clearBytes(value)
	if err := windowsContextError(ctx); err != nil {
		return err
	}

	mutex, err := acquireWindowsCreateMutex(ctx)
	if err != nil {
		return err
	}
	defer func() {
		if releaseErr := mutex.release(); result == nil && releaseErr != nil {
			result = releaseErr
		}
	}()

	target := windowsTarget(key)
	existing, nativeErr := wincred.GetGenericCredential(target)
	if existing != nil {
		clearBytes(existing.CredentialBlob)
	}
	if nativeErr == nil {
		if err := ctx.Err(); err != nil {
			return err
		}
		return ErrAlreadyExists
	}
	if err := windowsCallError(ctx, nativeErr); !errors.Is(err, ErrNotFound) {
		return err
	}

	credential := newWindowsCredential(target, value)
	if err := ctx.Err(); err != nil {
		return err
	}
	nativeErr = credential.Write()
	return windowsCallError(ctx, nativeErr)
}

func (*windowsBackend) Delete(ctx context.Context, key string) (result error) {
	if err := windowsContextError(ctx); err != nil {
		return err
	}

	mutex, err := acquireWindowsCreateMutex(ctx)
	if err != nil {
		return err
	}
	defer func() {
		if releaseErr := mutex.release(); result == nil && releaseErr != nil {
			result = releaseErr
		}
	}()

	credential := wincred.NewGenericCredential(windowsTarget(key))
	nativeErr := credential.Delete()
	return windowsCallError(ctx, nativeErr)
}

func windowsTarget(key string) string {
	return windowsTargetPrefix + key
}

func newWindowsCredential(target string, value []byte) *wincred.GenericCredential {
	credential := wincred.NewGenericCredential(target)
	credential.Persist = wincred.PersistLocalMachine
	credential.CredentialBlob = value
	return credential
}

func windowsCallError(ctx context.Context, nativeErr error) error {
	if err := windowsContextError(ctx); err != nil {
		return err
	}
	return classifyWindowsError(nativeErr)
}

func windowsContextError(ctx context.Context) error {
	if ctx == nil {
		return ErrInvalidContext
	}
	return ctx.Err()
}

func classifyWindowsError(nativeErr error) error {
	if nativeErr == nil {
		return nil
	}
	if errors.Is(nativeErr, context.Canceled) ||
		errors.Is(nativeErr, context.DeadlineExceeded) {
		return nativeErr
	}

	category := ErrUnreadable
	switch {
	case errors.Is(nativeErr, wincred.ErrElementNotFound):
		category = ErrNotFound
	case errors.Is(nativeErr, windows.ERROR_ALREADY_EXISTS):
		category = ErrAlreadyExists
	case errors.Is(nativeErr, windows.Errno(windows.NTE_BAD_KEY_STATE)),
		errors.Is(nativeErr, windows.ERROR_ACCOUNT_LOCKED_OUT):
		category = ErrLocked
	case errors.Is(nativeErr, windows.ERROR_NO_SUCH_LOGON_SESSION),
		errors.Is(nativeErr, windows.ERROR_NOT_LOGGED_ON),
		errors.Is(nativeErr, windows.ERROR_SERVICE_NOT_ACTIVE),
		errors.Is(nativeErr, windows.RPC_S_SERVER_UNAVAILABLE):
		category = ErrUnavailable
	case errors.Is(nativeErr, windows.ERROR_ACCESS_DENIED),
		errors.Is(nativeErr, windows.ERROR_PRIVILEGE_NOT_HELD),
		errors.Is(nativeErr, windows.ERROR_BAD_IMPERSONATION_LEVEL),
		errors.Is(nativeErr, windows.ERROR_LOGON_FAILURE),
		errors.Is(nativeErr, windows.ERROR_ACCOUNT_RESTRICTION),
		errors.Is(nativeErr, windows.Errno(windows.NTE_PERM)):
		category = ErrAccessDenied
	case errors.Is(nativeErr, windows.ERROR_INVALID_DATA),
		errors.Is(nativeErr, windows.ERROR_INVALID_DATATYPE):
		category = ErrCorrupt
	}
	return fmt.Errorf("%w: native Windows error: %w", category, nativeErr)
}

type windowsCreateMutex struct {
	handle windows.Handle
}

func acquireWindowsCreateMutex(ctx context.Context) (*windowsCreateMutex, error) {
	if err := windowsContextError(ctx); err != nil {
		return nil, err
	}

	tokenUser, nativeErr := windows.GetCurrentProcessToken().GetTokenUser()
	if err := windowsCallError(ctx, nativeErr); err != nil {
		return nil, err
	}
	if tokenUser == nil || tokenUser.User.Sid == nil {
		return nil, fmt.Errorf("%w: current user has no SID", ErrCorrupt)
	}

	name, nativeErr := windows.UTF16PtrFromString(windowsCreateMutexName(tokenUser.User.Sid.String()))
	if err := windowsCallError(ctx, nativeErr); err != nil {
		return nil, err
	}
	handle, nativeErr := windows.CreateMutex(nil, false, name)
	if nativeErr != nil && !errors.Is(nativeErr, windows.ERROR_ALREADY_EXISTS) {
		if handle != 0 {
			_ = windows.CloseHandle(handle)
		}
		return nil, windowsCallError(ctx, nativeErr)
	}
	if handle == 0 {
		return nil, fmt.Errorf("%w: create mutex returned a null handle", ErrUnreadable)
	}
	mutex := &windowsCreateMutex{handle: handle}
	if err := ctx.Err(); err != nil {
		_ = windows.CloseHandle(handle)
		return nil, err
	}

	for {
		if err := ctx.Err(); err != nil {
			_ = windows.CloseHandle(handle)
			return nil, err
		}

		status, nativeErr := windows.WaitForSingleObject(handle, windowsMutexPollMillis)
		if err := windowsCallError(ctx, nativeErr); err != nil {
			_ = windows.CloseHandle(handle)
			return nil, err
		}
		switch status {
		case windows.WAIT_OBJECT_0, windows.WAIT_ABANDONED:
			if err := ctx.Err(); err != nil {
				_ = windows.ReleaseMutex(handle)
				_ = windows.CloseHandle(handle)
				return nil, err
			}
			return mutex, nil
		case uint32(windows.WAIT_TIMEOUT):
			continue
		default:
			_ = windows.CloseHandle(handle)
			return nil, fmt.Errorf(
				"%w: unexpected mutex wait status %#x",
				ErrUnreadable,
				status,
			)
		}
	}
}

func (mutex *windowsCreateMutex) release() error {
	if mutex == nil || mutex.handle == 0 {
		return fmt.Errorf("%w: invalid create mutex", ErrCorrupt)
	}

	releaseErr := windows.ReleaseMutex(mutex.handle)
	closeErr := windows.CloseHandle(mutex.handle)
	mutex.handle = 0
	switch {
	case releaseErr != nil:
		return classifyWindowsError(releaseErr)
	case closeErr != nil:
		return classifyWindowsError(closeErr)
	default:
		return nil
	}
}

func windowsCreateMutexName(userSID string) string {
	digest := sha256.Sum256([]byte(userSID))
	return windowsMutexNamePrefix +
		hex.EncodeToString(digest[:windowsMutexDigestBytes])
}

func clearBytes(value []byte) {
	for index := range value {
		value[index] = 0
	}
}
