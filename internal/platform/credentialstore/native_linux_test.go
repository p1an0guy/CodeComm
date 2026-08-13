//go:build linux

package credentialstore

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/godbus/dbus/v5"
)

type linuxBusCall struct {
	destination string
	path        dbus.ObjectPath
	method      string
	flags       dbus.Flags
	args        []any
}

type fakeLinuxBus struct {
	mu      sync.Mutex
	handler func(linuxBusCall) ([]any, error)
	calls   []linuxBusCall
}

func (bus *fakeLinuxBus) call(
	_ context.Context,
	destination string,
	path dbus.ObjectPath,
	method string,
	flags dbus.Flags,
	args ...any,
) ([]any, error) {
	call := linuxBusCall{destination, path, method, flags, append([]any(nil), args...)}
	bus.mu.Lock()
	bus.calls = append(bus.calls, call)
	handler := bus.handler
	bus.mu.Unlock()
	return handler(call)
}

func (bus *fakeLinuxBus) close() error {
	return nil
}

func TestLinuxGetUsesExactAttributesAndPlainSession(t *testing.T) {
	t.Parallel()

	account := "identity/v1"
	item := dbus.ObjectPath("/org/freedesktop/secrets/collection/default/1")
	session := dbus.ObjectPath("/org/freedesktop/secrets/session/1")
	secret := []byte("private-key")
	bus := &fakeLinuxBus{}
	bus.handler = standardLinuxHandler(account, item, session, secret)
	backend := &linuxSecretService{bus: bus}

	got, err := backend.Get(context.Background(), account)
	if err != nil {
		t.Fatalf("Get() error = %v", err)
	}
	if !bytes.Equal(got, secret) {
		t.Fatalf("Get() = %q, want %q", got, secret)
	}
	got[0] ^= 0xff
	if bytes.Equal(got, secret) {
		t.Fatal("Get() did not return a private copy")
	}

	assertSecretCallsDoNotAutostart(t, bus.calls)
	for _, call := range bus.calls {
		if call.method == "org.freedesktop.Secret.Service.Unlock" ||
			call.method == "org.freedesktop.Secret.Prompt.Prompt" {
			t.Fatalf("Get() made forbidden call %s", call.method)
		}
	}
}

func TestLinuxCreateIsCreateOnlyAndNoninteractive(t *testing.T) {
	t.Parallel()

	account := "identity/v1"
	session := dbus.ObjectPath("/org/freedesktop/secrets/session/2")
	created := false
	bus := &fakeLinuxBus{}
	bus.handler = func(call linuxBusCall) ([]any, error) {
		switch call.method {
		case requestName:
			if call.args[0] != mutationLockName ||
				call.args[1] != uint32(dbus.NameFlagDoNotQueue) {
				t.Fatalf("RequestName args = %#v", call.args)
			}
			return []any{uint32(dbus.RequestNameReplyPrimaryOwner)}, nil
		case releaseName:
			return []any{uint32(dbus.ReleaseNameReplyReleased)}, nil
		case nameHasOwner:
			return []any{true}, nil
		case propertiesGet:
			if len(call.args) == 2 && call.args[1] == "Attributes" {
				return []any{dbus.MakeVariant(map[string]string{
					"service": codeCommService,
					"account": account,
				})}, nil
			}
			return []any{dbus.MakeVariant(false)}, nil
		case searchItems:
			if created {
				return []any{[]dbus.ObjectPath{"/org/freedesktop/secrets/collection/default/new"}}, nil
			}
			return []any{[]dbus.ObjectPath{}}, nil
		case openSession:
			return []any{dbus.MakeVariant(""), session}, nil
		case createItem:
			if replace, ok := call.args[2].(bool); !ok || replace {
				t.Fatalf("CreateItem replace = %#v, want false", call.args[2])
			}
			properties := call.args[0].(map[string]dbus.Variant)
			attributes := properties[itemKind+".Attributes"].Value().(map[string]string)
			if attributes["service"] != codeCommService || attributes["account"] != account ||
				len(attributes) != 2 {
				t.Fatalf("CreateItem attributes = %#v", attributes)
			}
			createdSecret := call.args[1].(linuxSecret)
			if createdSecret.Session != session || len(createdSecret.Parameters) != 0 ||
				createdSecret.ContentType != secretContentType ||
				!bytes.Equal(createdSecret.Value, []byte("new-secret")) {
				t.Fatalf("CreateItem secret = %#v", createdSecret)
			}
			created = true
			return []any{
				dbus.ObjectPath("/org/freedesktop/secrets/collection/default/new"),
				dbus.ObjectPath("/"),
			}, nil
		case closeSession:
			return nil, nil
		default:
			return nil, fmt.Errorf("unexpected method %s", call.method)
		}
	}
	backend := &linuxSecretService{bus: bus}

	if err := backend.Create(context.Background(), account, []byte("new-secret")); err != nil {
		t.Fatalf("Create() error = %v", err)
	}
	assertSecretCallsDoNotAutostart(t, bus.calls)

	err := backend.Create(context.Background(), account, []byte("replacement"))
	if !errors.Is(err, ErrAlreadyExists) {
		t.Fatalf("second Create() error = %v, want %v", err, ErrAlreadyExists)
	}
}

func TestLinuxDeleteRejectsPrompt(t *testing.T) {
	t.Parallel()

	account := "identity/v1"
	item := dbus.ObjectPath("/org/freedesktop/secrets/collection/default/1")
	bus := &fakeLinuxBus{handler: func(call linuxBusCall) ([]any, error) {
		switch call.method {
		case requestName:
			return []any{uint32(dbus.RequestNameReplyPrimaryOwner)}, nil
		case releaseName:
			return []any{uint32(dbus.ReleaseNameReplyReleased)}, nil
		case nameHasOwner:
			return []any{true}, nil
		case propertiesGet:
			if call.args[1] == "Attributes" {
				return []any{dbus.MakeVariant(map[string]string{
					"service": codeCommService,
					"account": account,
				})}, nil
			}
			return []any{dbus.MakeVariant(false)}, nil
		case searchItems:
			return []any{[]dbus.ObjectPath{item}}, nil
		case deleteItem:
			return []any{dbus.ObjectPath("/org/freedesktop/secrets/prompt/1")}, nil
		default:
			return nil, fmt.Errorf("unexpected method %s", call.method)
		}
	}}
	backend := &linuxSecretService{bus: bus}

	if err := backend.Delete(context.Background(), account); !errors.Is(err, ErrAccessDenied) {
		t.Fatalf("Delete() error = %v, want %v", err, ErrAccessDenied)
	}
	for _, call := range bus.calls {
		if call.method == "org.freedesktop.Secret.Prompt.Prompt" {
			t.Fatal("Delete() invoked a prompt")
		}
	}
}

func TestLinuxClassifiesOperationalFailures(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		err  error
		want error
	}{
		{"service unavailable", dbus.Error{Name: "org.freedesktop.DBus.Error.ServiceUnknown"}, ErrUnavailable},
		{"collection missing", dbus.Error{Name: "org.freedesktop.DBus.Error.UnknownObject"}, ErrUnavailable},
		{"locked", dbus.Error{Name: "org.freedesktop.Secret.Error.IsLocked"}, ErrLocked},
		{"denied", dbus.Error{Name: "org.freedesktop.DBus.Error.AccessDenied"}, ErrAccessDenied},
		{"malformed request", dbus.Error{Name: "org.freedesktop.DBus.Error.InvalidArgs"}, ErrUnreadable},
		{"bus closed", dbus.ErrClosed, ErrUnavailable},
		{"unknown", errors.New("transport failed"), ErrUnreadable},
		{"cancelled", context.Canceled, context.Canceled},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			got := classifyLinuxError(test.err, ErrUnavailable)
			if !errors.Is(got, test.want) {
				t.Fatalf("classifyLinuxError() = %v, want %v", got, test.want)
			}
		})
	}
}

func TestLinuxRejectsLockedMissingDuplicateAndMalformedObjects(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		handler func(linuxBusCall) ([]any, error)
		want    error
	}{
		{
			name: "service absent",
			handler: func(call linuxBusCall) ([]any, error) {
				return []any{false}, nil
			},
			want: ErrUnavailable,
		},
		{
			name: "collection locked",
			handler: func(call linuxBusCall) ([]any, error) {
				if call.method == nameHasOwner {
					return []any{true}, nil
				}
				return []any{dbus.MakeVariant(true)}, nil
			},
			want: ErrLocked,
		},
		{
			name: "missing item",
			handler: func(call linuxBusCall) ([]any, error) {
				switch call.method {
				case nameHasOwner:
					return []any{true}, nil
				case propertiesGet:
					return []any{dbus.MakeVariant(false)}, nil
				default:
					return []any{[]dbus.ObjectPath{}}, nil
				}
			},
			want: ErrNotFound,
		},
		{
			name: "duplicate items",
			handler: func(call linuxBusCall) ([]any, error) {
				switch call.method {
				case nameHasOwner:
					return []any{true}, nil
				case propertiesGet:
					return []any{dbus.MakeVariant(false)}, nil
				default:
					return []any{[]dbus.ObjectPath{"/item/1", "/item/2"}}, nil
				}
			},
			want: ErrCorrupt,
		},
		{
			name: "item locked",
			handler: func(call linuxBusCall) ([]any, error) {
				switch call.method {
				case nameHasOwner:
					return []any{true}, nil
				case searchItems:
					return []any{[]dbus.ObjectPath{"/item/1"}}, nil
				case propertiesGet:
					if call.path == defaultCollectionPath {
						return []any{dbus.MakeVariant(false)}, nil
					}
					return []any{dbus.MakeVariant(true)}, nil
				default:
					return nil, fmt.Errorf("unexpected method %s", call.method)
				}
			},
			want: ErrLocked,
		},
		{
			name: "inexact attributes",
			handler: func(call linuxBusCall) ([]any, error) {
				switch call.method {
				case nameHasOwner:
					return []any{true}, nil
				case searchItems:
					return []any{[]dbus.ObjectPath{"/item/1"}}, nil
				case propertiesGet:
					if call.args[1] == "Attributes" {
						return []any{dbus.MakeVariant(map[string]string{
							"service": codeCommService,
							"account": "different",
						})}, nil
					}
					return []any{dbus.MakeVariant(false)}, nil
				default:
					return nil, fmt.Errorf("unexpected method %s", call.method)
				}
			},
			want: ErrCorrupt,
		},
		{
			name: "malformed response",
			handler: func(call linuxBusCall) ([]any, error) {
				return []any{"not-a-boolean"}, nil
			},
			want: ErrCorrupt,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			backend := &linuxSecretService{bus: &fakeLinuxBus{handler: test.handler}}
			_, err := backend.Get(context.Background(), "identity/v1")
			if !errors.Is(err, test.want) {
				t.Fatalf("Get() error = %v, want %v", err, test.want)
			}
		})
	}
}

func TestLinuxCreateLockHonorsContext(t *testing.T) {
	t.Parallel()

	bus := &fakeLinuxBus{handler: func(call linuxBusCall) ([]any, error) {
		if call.method != requestName {
			return nil, fmt.Errorf("unexpected method %s", call.method)
		}
		return []any{uint32(dbus.RequestNameReplyExists)}, nil
	}}
	backend := &linuxSecretService{bus: bus}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Millisecond)
	defer cancel()

	err := backend.Create(ctx, "identity/v1", []byte("secret"))
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Create() error = %v, want %v", err, context.DeadlineExceeded)
	}
}

func TestLinuxBackendRejectsNilContext(t *testing.T) {
	t.Parallel()

	backend := &linuxSecretService{bus: &fakeLinuxBus{
		handler: func(linuxBusCall) ([]any, error) {
			t.Fatal("native backend called D-Bus with nil context")
			return nil, nil
		},
	}}
	if _, err := backend.Get(nil, "identity/v1"); !errors.Is(err, ErrInvalidContext) {
		t.Fatalf("Get(nil) error = %v, want %v", err, ErrInvalidContext)
	}
	if err := backend.Create(nil, "identity/v1", []byte("secret")); !errors.Is(err, ErrInvalidContext) {
		t.Fatalf("Create(nil) error = %v, want %v", err, ErrInvalidContext)
	}
	if err := backend.Delete(nil, "identity/v1"); !errors.Is(err, ErrInvalidContext) {
		t.Fatalf("Delete(nil) error = %v, want %v", err, ErrInvalidContext)
	}
}

func TestLinuxBackendProvider(t *testing.T) {
	t.Parallel()

	store, err := newStore(&linuxSecretService{bus: &fakeLinuxBus{}})
	if err != nil {
		t.Fatalf("newStore() error = %v", err)
	}
	if got := store.Provider(); got != linuxProvider {
		t.Fatalf("Provider() = %q, want %q", got, linuxProvider)
	}
}

func TestLinuxBusAddressMustBeLocalUnix(t *testing.T) {
	t.Parallel()

	tests := []struct {
		address string
		want    bool
	}{
		{"unix:path=/run/user/1000/bus", true},
		{"unix:abstract=/tmp/dbus;unix:path=/run/user/1000/bus", true},
		{"", false},
		{"autolaunch:", false},
		{"tcp:host=127.0.0.1", false},
		{"unix:path=/run/user/1000/bus;tcp:host=127.0.0.1", false},
	}
	for _, test := range tests {
		if got := localUnixBusAddress(test.address); got != test.want {
			t.Errorf("localUnixBusAddress(%q) = %v, want %v", test.address, got, test.want)
		}
	}
}

func standardLinuxHandler(
	account string,
	item dbus.ObjectPath,
	session dbus.ObjectPath,
	secret []byte,
) func(linuxBusCall) ([]any, error) {
	return func(call linuxBusCall) ([]any, error) {
		switch call.method {
		case nameHasOwner:
			return []any{true}, nil
		case propertiesGet:
			if call.args[1] == "Attributes" {
				return []any{dbus.MakeVariant(map[string]string{
					"service": codeCommService,
					"account": account,
				})}, nil
			}
			return []any{dbus.MakeVariant(false)}, nil
		case searchItems:
			return []any{[]dbus.ObjectPath{item}}, nil
		case openSession:
			if call.args[0] != "plain" || call.args[1].(dbus.Variant).Value() != "" {
				return nil, errors.New("non-plain session")
			}
			return []any{dbus.MakeVariant(""), session}, nil
		case getSecret:
			return []any{linuxSecret{
				Session:     session,
				Parameters:  []byte{},
				Value:       append([]byte(nil), secret...),
				ContentType: secretContentType,
			}}, nil
		case closeSession:
			return nil, nil
		default:
			return nil, fmt.Errorf("unexpected method %s", call.method)
		}
	}
}

func assertSecretCallsDoNotAutostart(t *testing.T, calls []linuxBusCall) {
	t.Helper()
	for _, call := range calls {
		if call.destination == secretServiceName && call.flags&dbus.FlagNoAutoStart == 0 {
			t.Errorf("call %s can autostart Secret Service", call.method)
		}
	}
}
