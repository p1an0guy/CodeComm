//go:build windows

package ipc

import (
	"context"
	"errors"
	"net"
	"os"
	"testing"
	"time"

	"github.com/Microsoft/go-winio"
	"golang.org/x/sys/windows"
)

func TestWindowsProductionTransportAuthenticatesBothPeers(t *testing.T) {
	t.Parallel()

	endpoint, err := ParseEndpoint(testEndpointAddress(""))
	if err != nil {
		t.Fatal(err)
	}
	listener, err := Listen(endpoint)
	if err != nil {
		t.Fatalf("Listen() error = %v", err)
	}
	defer listener.Close()

	accepted := make(chan *Conn, 1)
	acceptError := make(chan error, 1)
	go func() {
		connection, err := listener.Accept()
		if err != nil {
			acceptError <- err
			return
		}
		accepted <- connection
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	client, err := Dial(ctx, endpoint)
	if err != nil {
		t.Fatalf("Dial() error = %v", err)
	}
	defer client.Close()
	var server *Conn
	select {
	case server = <-accepted:
		defer server.Close()
	case err := <-acceptError:
		t.Fatalf("Accept() error = %v", err)
	case <-ctx.Done():
		t.Fatal("Accept() timed out")
	}
	wantSID, err := currentUserSID()
	if err != nil {
		t.Fatal(err)
	}
	for label, peer := range map[string]VerifiedPeer{
		"server sees client": server.Peer(),
		"client sees server": client.Peer(),
	} {
		if peer.PID() != uint32(os.Getpid()) || peer.UserID() != wantSID {
			t.Errorf(
				"%s peer = PID %d, SID %q; want PID %d, SID %q",
				label,
				peer.PID(),
				peer.UserID(),
				os.Getpid(),
				wantSID,
			)
		}
	}
}

func TestWindowsEndpointRejectsRemoteOrAmbiguousPipeNames(t *testing.T) {
	t.Parallel()

	for _, address := range []string{
		"",
		`\\server\pipe\codecomm`,
		`\\.\pipe\`,
		`\\.\pipe\codecomm\child`,
		`\\.\pipe\codecomm:alternate`,
	} {
		endpoint, err := ParseEndpoint(address)
		if endpoint != (Endpoint{}) || !errors.Is(err, ErrInvalidEndpoint) {
			t.Errorf("ParseEndpoint(%q) = %#v, %v", address, endpoint, err)
		}
	}
}

func TestWindowsOwnerOnlyDescriptorRejectsEveryWidening(t *testing.T) {
	t.Parallel()

	ownerSID, err := currentUserSID()
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name string
		sddl string
	}{
		{
			name: "unprotected DACL",
			sddl: "O:" + ownerSID + "D:(A;;GA;;;" + ownerSID + ")",
		},
		{
			name: "extra trustee",
			sddl: "O:" + ownerSID + "D:P(A;;GA;;;" + ownerSID + ")(A;;GR;;;SY)",
		},
		{
			name: "narrow owner grant",
			sddl: "O:" + ownerSID + "D:P(A;;GR;;;" + ownerSID + ")",
		},
		{
			name: "inheritable owner grant",
			sddl: "O:" + ownerSID + "D:P(A;OICI;GA;;;" + ownerSID + ")",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if err := validateSecurityDescriptorString(
				test.sddl,
				ownerSID,
			); !errors.Is(err, ErrEndpointInsecure) {
				t.Fatalf(
					"validateSecurityDescriptorString() error = %v, want ErrEndpointInsecure",
					err,
				)
			}
		})
	}
}

func TestWindowsOwnerOnlyDescriptorAcceptsMappedFullAccess(t *testing.T) {
	t.Parallel()

	ownerSID, err := currentUserSID()
	if err != nil {
		t.Fatal(err)
	}
	descriptor, err := windows.SecurityDescriptorFromString(
		"O:" + ownerSID + "D:P(A;;GA;;;" + ownerSID + ")",
	)
	if err != nil {
		t.Fatal(err)
	}
	dacl, _, err := descriptor.DACL()
	if err != nil {
		t.Fatal(err)
	}
	var ace *windows.ACCESS_ALLOWED_ACE
	if err := windows.GetAce(dacl, 0, &ace); err != nil {
		t.Fatal(err)
	}
	ace.Mask = windowsFileAllAccess
	if err := validateOwnerOnlyDescriptor(descriptor, ownerSID); err != nil {
		t.Fatalf("validateOwnerOnlyDescriptor(mapped full access): %v", err)
	}
}

func TestWindowsAnonymousClientIsRejectedBeforeValidClient(t *testing.T) {
	t.Parallel()

	endpoint, err := ParseEndpoint(testEndpointAddress(""))
	if err != nil {
		t.Fatal(err)
	}
	listener, err := Listen(endpoint)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	accepted := make(chan *Conn, 1)
	acceptError := make(chan error, 1)
	go func() {
		connection, err := listener.Accept()
		if err != nil {
			acceptError <- err
			return
		}
		accepted <- connection
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	anonymous, err := winio.DialPipeContext(ctx, endpoint.String())
	if err != nil {
		t.Fatalf("dial anonymous pipe client: %v", err)
	}
	if err := anonymous.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	var one [1]byte
	if _, err := anonymous.Read(one[:]); err == nil {
		t.Fatal("anonymous client remained connected")
	} else {
		var networkError net.Error
		if errors.As(err, &networkError) && networkError.Timeout() {
			t.Fatalf("anonymous client was not rejected before timeout: %v", err)
		}
	}
	_ = anonymous.Close()

	valid, err := Dial(ctx, endpoint)
	if err != nil {
		t.Fatalf("Dial() after anonymous rejection: %v", err)
	}
	defer valid.Close()
	select {
	case connection := <-accepted:
		_ = connection.Close()
	case err := <-acceptError:
		t.Fatalf("Accept() error = %v", err)
	case <-ctx.Done():
		t.Fatal("valid client was not accepted")
	}
}
