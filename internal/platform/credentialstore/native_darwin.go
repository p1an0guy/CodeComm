//go:build darwin

package credentialstore

/*
#cgo LDFLAGS: -framework CoreFoundation -framework Security
#cgo CFLAGS: -Wno-deprecated-declarations

#include <CoreFoundation/CoreFoundation.h>
#include <Security/Security.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

static const CFStringRef codecomm_service(void) {
	return CFSTR("dev.codecomm.credentials.v1");
}

static CFMutableDictionaryRef codecomm_query(const char *account) {
	CFStringRef account_ref = CFStringCreateWithCString(
		kCFAllocatorDefault,
		account,
		kCFStringEncodingUTF8
	);
	if (account_ref == NULL) {
		return NULL;
	}

	CFMutableDictionaryRef query = CFDictionaryCreateMutable(
		kCFAllocatorDefault,
		0,
		&kCFTypeDictionaryKeyCallBacks,
		&kCFTypeDictionaryValueCallBacks
	);
	if (query != NULL) {
		CFDictionarySetValue(query, kSecClass, kSecClassGenericPassword);
		CFDictionarySetValue(query, kSecAttrService, codecomm_service());
		CFDictionarySetValue(query, kSecAttrAccount, account_ref);
		CFDictionarySetValue(query, kSecAttrSynchronizable, kCFBooleanFalse);
		CFDictionarySetValue(
			query,
			kSecUseAuthenticationUI,
			kSecUseAuthenticationUIFail
		);
	}
	CFRelease(account_ref);
	return query;
}

static OSStatus codecomm_keychain_get(
	const char *account,
	size_t maximum_secret_length,
	unsigned char **secret,
	size_t *secret_length
) {
	*secret = NULL;
	*secret_length = 0;

	CFMutableDictionaryRef query = codecomm_query(account);
	if (query == NULL) {
		return errSecAllocate;
	}
	CFDictionarySetValue(query, kSecReturnData, kCFBooleanTrue);
	CFDictionarySetValue(query, kSecMatchLimit, kSecMatchLimitOne);

	CFTypeRef result = NULL;
	OSStatus status = SecItemCopyMatching(query, &result);
	CFRelease(query);
	if (status != errSecSuccess) {
		if (result != NULL) {
			CFRelease(result);
		}
		return status;
	}
	if (result == NULL || CFGetTypeID(result) != CFDataGetTypeID()) {
		if (result != NULL) {
			CFRelease(result);
		}
		return errSecDecode;
	}

	CFDataRef data = (CFDataRef)result;
	CFIndex length = CFDataGetLength(data);
	if (
		length <= 0 ||
		(uint64_t)length > SIZE_MAX ||
		(uint64_t)length > maximum_secret_length
	) {
		CFRelease(result);
		return errSecDecode;
	}

	unsigned char *copy = malloc((size_t)length);
	if (copy == NULL) {
		CFRelease(result);
		return errSecAllocate;
	}
	CFDataGetBytes(data, CFRangeMake(0, length), copy);
	CFRelease(result);
	*secret = copy;
	*secret_length = (size_t)length;
	return errSecSuccess;
}

static OSStatus codecomm_keychain_create(
	const char *account,
	const unsigned char *secret,
	size_t secret_length
) {
	OSStatus status = errSecSuccess;
	SecTrustedApplicationRef trusted_application = NULL;
	CFArrayRef trusted_applications = NULL;
	SecAccessRef access = NULL;
	CFDataRef data = NULL;
	CFMutableDictionaryRef attributes = NULL;

	status = SecTrustedApplicationCreateFromPath(NULL, &trusted_application);
	if (status != errSecSuccess) {
		goto cleanup;
	}
	const void *trusted_values[] = { trusted_application };
	trusted_applications = CFArrayCreate(
		kCFAllocatorDefault,
		trusted_values,
		1,
		&kCFTypeArrayCallBacks
	);
	if (trusted_applications == NULL) {
		status = errSecAllocate;
		goto cleanup;
	}
	status = SecAccessCreate(
		CFSTR("CodeComm credential"),
		trusted_applications,
		&access
	);
	if (status != errSecSuccess) {
		goto cleanup;
	}

	attributes = codecomm_query(account);
	if (attributes == NULL) {
		status = errSecAllocate;
		goto cleanup;
	}
	data = CFDataCreateWithBytesNoCopy(
		kCFAllocatorDefault,
		secret,
		(CFIndex)secret_length,
		kCFAllocatorNull
	);
	if (data == NULL) {
		status = errSecAllocate;
		goto cleanup;
	}

	CFDictionarySetValue(attributes, kSecValueData, data);
	CFDictionarySetValue(
		attributes,
		kSecAttrAccessible,
		kSecAttrAccessibleWhenUnlockedThisDeviceOnly
	);
	CFDictionarySetValue(attributes, kSecAttrAccess, access);
	status = SecItemAdd(attributes, NULL);

cleanup:
	if (attributes != NULL) {
		CFRelease(attributes);
	}
	if (data != NULL) {
		CFRelease(data);
	}
	if (access != NULL) {
		CFRelease(access);
	}
	if (trusted_applications != NULL) {
		CFRelease(trusted_applications);
	}
	if (trusted_application != NULL) {
		CFRelease(trusted_application);
	}
	return status;
}

static OSStatus codecomm_keychain_delete(const char *account) {
	CFMutableDictionaryRef query = codecomm_query(account);
	if (query == NULL) {
		return errSecAllocate;
	}
	OSStatus status = SecItemDelete(query);
	CFRelease(query);
	return status;
}

static void codecomm_clear_free(unsigned char *buffer, size_t length) {
	if (buffer == NULL) {
		return;
	}
	volatile unsigned char *cursor = buffer;
	while (length-- > 0) {
		*cursor++ = 0;
	}
	free(buffer);
}
*/
import "C"

import (
	"context"
	"fmt"
	"unsafe"
)

const darwinProviderName = "macos-keychain"

const (
	darwinStatusSuccess               = int32(C.errSecSuccess)
	darwinStatusWritePermission       = int32(C.errSecWrPerm)
	darwinStatusUserCanceled          = int32(C.errSecUserCanceled)
	darwinStatusMissingEntitlement    = int32(C.errSecMissingEntitlement)
	darwinStatusRestrictedAPI         = int32(C.errSecRestrictedAPI)
	darwinStatusNotAvailable          = int32(C.errSecNotAvailable)
	darwinStatusReadOnly              = int32(C.errSecReadOnly)
	darwinStatusAuthFailed            = int32(C.errSecAuthFailed)
	darwinStatusNoSuchKeychain        = int32(C.errSecNoSuchKeychain)
	darwinStatusInvalidKeychain       = int32(C.errSecInvalidKeychain)
	darwinStatusDuplicateItem         = int32(C.errSecDuplicateItem)
	darwinStatusItemNotFound          = int32(C.errSecItemNotFound)
	darwinStatusInvalidItemRef        = int32(C.errSecInvalidItemRef)
	darwinStatusNoSuchClass           = int32(C.errSecNoSuchClass)
	darwinStatusNoDefaultKeychain     = int32(C.errSecNoDefaultKeychain)
	darwinStatusInteractionNotAllowed = int32(C.errSecInteractionNotAllowed)
	darwinStatusReadOnlyAttribute     = int32(C.errSecReadOnlyAttr)
	darwinStatusWrongVersion          = int32(C.errSecWrongSecVersion)
	darwinStatusNoStorageModule       = int32(C.errSecNoStorageModule)
	darwinStatusInteractionRequired   = int32(C.errSecInteractionRequired)
	darwinStatusInDarkWake            = int32(C.errSecInDarkWake)
	darwinStatusNoAccessForItem       = int32(C.errSecNoAccessForItem)
	darwinStatusDecode                = int32(C.errSecDecode)
	darwinStatusServiceNotAvailable   = int32(C.errSecServiceNotAvailable)
	darwinStatusInsufficientClientID  = int32(C.errSecInsufficientClientID)
)

type darwinCalls struct {
	get    func(string) ([]byte, error)
	create func(string, []byte) error
	delete func(string) error
}

var systemDarwinCalls = darwinCalls{
	get:    darwinKeychainGet,
	create: darwinKeychainCreate,
	delete: darwinKeychainDelete,
}

type nativeBackend struct {
	calls *darwinCalls
}

func nativeProviderName() string {
	return darwinProviderName
}

// OpenNative opens the login Keychain-backed credential store.
func OpenNative(ctx context.Context) (*Store, error) {
	if err := darwinContextError(ctx); err != nil {
		return nil, err
	}
	return newStore(&nativeBackend{})
}

func (*nativeBackend) Name() string {
	return darwinProviderName
}

func (*nativeBackend) Close() error {
	return nil
}

func (backend *nativeBackend) Get(ctx context.Context, key string) ([]byte, error) {
	if err := darwinContextError(ctx); err != nil {
		return nil, err
	}
	value, err := backend.activeCalls().get(key)
	if contextErr := ctx.Err(); contextErr != nil {
		clearBytes(value)
		return nil, contextErr
	}
	return value, err
}

func (backend *nativeBackend) Create(ctx context.Context, key string, value []byte) error {
	if err := darwinContextError(ctx); err != nil {
		return err
	}
	defer clearBytes(value)
	err := backend.activeCalls().create(key, value)
	if contextErr := ctx.Err(); contextErr != nil {
		return contextErr
	}
	return err
}

func (backend *nativeBackend) Delete(ctx context.Context, key string) error {
	if err := darwinContextError(ctx); err != nil {
		return err
	}
	err := backend.activeCalls().delete(key)
	if contextErr := ctx.Err(); contextErr != nil {
		return contextErr
	}
	return err
}

func (backend *nativeBackend) activeCalls() *darwinCalls {
	if backend != nil && backend.calls != nil {
		return backend.calls
	}
	return &systemDarwinCalls
}

func darwinContextError(ctx context.Context) error {
	if ctx == nil {
		return ErrInvalidContext
	}
	return ctx.Err()
}

func darwinKeychainGet(key string) ([]byte, error) {
	account := C.CString(key)
	defer C.free(unsafe.Pointer(account))

	var secret *C.uchar
	var secretLength C.size_t
	status := C.codecomm_keychain_get(
		account,
		C.size_t(MaxSecretBytes),
		&secret,
		&secretLength,
	)
	if secret != nil {
		defer C.codecomm_clear_free(secret, secretLength)
	}
	if err := classifyDarwinStatus(int32(status)); err != nil {
		return nil, err
	}
	if secret == nil || secretLength < 1 || secretLength > C.size_t(MaxSecretBytes) {
		return nil, fmt.Errorf(
			"%w: macOS Keychain returned %d bytes",
			ErrCorrupt,
			uint64(secretLength),
		)
	}
	return C.GoBytes(unsafe.Pointer(secret), C.int(secretLength)), nil
}

func darwinKeychainCreate(key string, value []byte) error {
	account := C.CString(key)
	defer C.free(unsafe.Pointer(account))

	secret := C.CBytes(value)
	defer C.codecomm_clear_free((*C.uchar)(secret), C.size_t(len(value)))
	status := C.codecomm_keychain_create(
		account,
		(*C.uchar)(secret),
		C.size_t(len(value)),
	)
	return classifyDarwinStatus(int32(status))
}

func darwinKeychainDelete(key string) error {
	account := C.CString(key)
	defer C.free(unsafe.Pointer(account))
	return classifyDarwinStatus(int32(C.codecomm_keychain_delete(account)))
}

type darwinKeychainError struct {
	status int32
	class  error
}

func (failure *darwinKeychainError) Error() string {
	return fmt.Sprintf("macOS Keychain status %d: %v", failure.status, failure.class)
}

func (failure *darwinKeychainError) Unwrap() error {
	return failure.class
}

func classifyDarwinStatus(status int32) error {
	if status == darwinStatusSuccess {
		return nil
	}

	var class error
	switch status {
	case darwinStatusItemNotFound:
		class = ErrNotFound
	case darwinStatusDuplicateItem:
		class = ErrAlreadyExists
	case darwinStatusInteractionNotAllowed,
		darwinStatusInteractionRequired,
		darwinStatusInDarkWake:
		class = ErrLocked
	case darwinStatusNotAvailable,
		darwinStatusNoSuchKeychain,
		darwinStatusNoDefaultKeychain,
		darwinStatusNoStorageModule,
		darwinStatusServiceNotAvailable:
		class = ErrUnavailable
	case darwinStatusWritePermission,
		darwinStatusUserCanceled,
		darwinStatusMissingEntitlement,
		darwinStatusRestrictedAPI,
		darwinStatusReadOnly,
		darwinStatusAuthFailed,
		darwinStatusReadOnlyAttribute,
		darwinStatusNoAccessForItem,
		darwinStatusInsufficientClientID:
		class = ErrAccessDenied
	case darwinStatusInvalidKeychain,
		darwinStatusInvalidItemRef,
		darwinStatusNoSuchClass,
		darwinStatusWrongVersion,
		darwinStatusDecode:
		class = ErrCorrupt
	default:
		class = ErrUnreadable
	}
	return &darwinKeychainError{status: status, class: class}
}

func clearBytes(value []byte) {
	for index := range value {
		value[index] = 0
	}
}
