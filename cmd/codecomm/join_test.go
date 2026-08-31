package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ijonahch/codecomm/internal/credential"
	"github.com/ijonahch/codecomm/internal/domain"
	"github.com/ijonahch/codecomm/internal/domain/device"
	"github.com/ijonahch/codecomm/internal/joinbootstrap"
	"github.com/ijonahch/codecomm/internal/pairing"
	"github.com/ijonahch/codecomm/internal/pairingjoiner"
	"github.com/ijonahch/codecomm/internal/pairingservice"
	"github.com/ijonahch/codecomm/internal/platform/credentialstore"
)

func TestJoinCommandReadsSecretFromStdinAndConfirmsImmutableReview(
	t *testing.T,
) {
	t.Parallel()

	inviterPrivate, inviterPublic, inviterID := cliJoinIdentity(t, 0x61)
	issued := cliIssuedInvite(
		t,
		inviterPrivate,
		inviterID,
		pairingservice.CreateInviteRequest{
			Mode:                   pairing.ModeNew,
			Role:                   device.RoleEditor,
			InitialCredentialEpoch: 1,
		},
	)
	review := cliJoinReview(t, issued.Invite, inviterPublic)
	statePath := filepath.Join(t.TempDir(), "joined", "state.db")
	credentials := &cliJoinCredentialHandle{}
	var captured joinbootstrap.Options
	var capturedInviteCode string
	dependencies := cliJoinDependencies(credentials)
	dependencies.bootstrap = func(
		ctx context.Context,
		options joinbootstrap.Options,
	) (joinbootstrap.Result, error) {
		captured = options
		capturedInviteCode = options.Invite.Code()
		confirmed, err := options.Confirm(ctx, review)
		if err != nil {
			return joinbootstrap.Result{}, err
		}
		if !confirmed {
			return joinbootstrap.Result{}, errors.New("review declined")
		}
		return joinbootstrap.Result{
			SessionID:          review.SessionID,
			WorkspaceID:        review.WorkspaceID,
			RecoveryGeneration: review.RecoveryGeneration,
			DeviceID:           review.Core.JoinerDeviceID,
			StatePath:          options.StatePath,
		}, nil
	}
	var output, errorOutput bytes.Buffer
	err := runJoinCommand(
		context.Background(),
		[]string{"--state", statePath},
		strings.NewReader(issued.Invite.Code()+"\nyes\n"),
		&output,
		&errorOutput,
		dependencies,
	)
	if err != nil {
		t.Fatalf("runJoinCommand(): %v; stderr = %q", err, errorOutput.String())
	}
	if captured.Resume ||
		captured.StatePath != statePath ||
		capturedInviteCode != issued.Invite.Code() ||
		!credentials.closed {
		t.Fatalf(
			"captured options = %#v, credentials closed = %t",
			captured,
			credentials.closed,
		)
	}
	prompt := errorOutput.String()
	for _, expected := range []string{
		review.SAS,
		string(review.SessionID),
		string(review.WorkspaceID),
		string(review.InviterDeviceID),
		string(review.Core.JoinerDeviceID),
		review.ConnectedEndpoint.String(),
	} {
		if !strings.Contains(prompt, expected) {
			t.Fatalf("join prompt omits %q: %q", expected, prompt)
		}
	}
	if strings.Contains(prompt, issued.Invite.Code()) {
		t.Fatal("join prompt echoed the invite code")
	}
	var result joinCommandResult
	if err := json.Unmarshal(output.Bytes(), &result); err != nil {
		t.Fatalf("decode output %q: %v", output.String(), err)
	}
	if result.SessionID != string(review.SessionID) ||
		result.DeviceID != string(review.Core.JoinerDeviceID) ||
		result.StatePath != statePath ||
		result.Resumed {
		t.Fatalf("join result = %#v", result)
	}
}

func TestJoinCommandResumesWithoutReadingInviteOrPrompting(t *testing.T) {
	t.Parallel()

	statePath := filepath.Join(t.TempDir(), "state.db")
	credentials := &cliJoinCredentialHandle{}
	dependencies := cliJoinDependencies(credentials)
	dependencies.hasPending = func(path string) (bool, error) {
		return path == statePath, nil
	}
	dependencies.bootstrap = func(
		_ context.Context,
		options joinbootstrap.Options,
	) (joinbootstrap.Result, error) {
		if !options.Resume ||
			len(options.Invite.CanonicalBytes()) != 0 ||
			options.Confirm != nil {
			return joinbootstrap.Result{}, errors.New("resume carried fresh input")
		}
		return joinbootstrap.Result{
			SessionID:          cliPairingSessionID,
			WorkspaceID:        cliPairingWorkspaceID,
			RecoveryGeneration: 2,
			DeviceID:           cliJoinDeviceID(t, 0x71),
			StatePath:          statePath,
			Resumed:            true,
		}, nil
	}
	var output, errorOutput bytes.Buffer
	err := runJoinCommand(
		context.Background(),
		[]string{"--state", statePath},
		cliJoinFailReader{},
		&output,
		&errorOutput,
		dependencies,
	)
	if err != nil {
		t.Fatalf("runJoinCommand(resume): %v", err)
	}
	if errorOutput.Len() != 0 || !credentials.closed {
		t.Fatalf(
			"resume stderr = %q, credentials closed = %t",
			errorOutput.String(),
			credentials.closed,
		)
	}
	var result joinCommandResult
	if err := json.Unmarshal(output.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if !result.Resumed || result.RecoveryGeneration != 2 {
		t.Fatalf("resume result = %#v", result)
	}
}

func TestJoinCommandRejectsSecretBearingOrAmbiguousArguments(t *testing.T) {
	t.Parallel()

	absolute := filepath.Join(t.TempDir(), "state.db")
	for name, args := range map[string][]string{
		"missing state": nil,
		"relative state": {
			"--state", "state.db",
		},
		"unclean state": {
			"--state", absolute + string(os.PathSeparator) + ".." +
				string(os.PathSeparator) + "state.db",
		},
		"positional invite": {
			"--state", absolute, "ccinvite1_secret",
		},
		"invite flag": {
			"--state", absolute, "--invite", "ccinvite1_secret",
		},
	} {
		t.Run(name, func(t *testing.T) {
			var output, errorOutput bytes.Buffer
			err := runJoinCommand(
				context.Background(),
				args,
				strings.NewReader(""),
				&output,
				&errorOutput,
				cliJoinDependencies(&cliJoinCredentialHandle{}),
			)
			if !errors.Is(err, errInvalidCLI) {
				t.Fatalf("runJoinCommand(%q) error = %v", args, err)
			}
			if output.Len() != 0 {
				t.Fatalf("unexpected output = %q", output.String())
			}
		})
	}
}

func TestReadJoinInviteUsesNoEchoTerminalReader(t *testing.T) {
	t.Parallel()

	inviterPrivate, _, inviterID := cliJoinIdentity(t, 0x72)
	issued := cliIssuedInvite(
		t,
		inviterPrivate,
		inviterID,
		pairingservice.CreateInviteRequest{
			Mode:                   pairing.ModeNew,
			Role:                   device.RoleEditor,
			InitialCredentialEpoch: 1,
		},
	)
	input, outputFile, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer input.Close()
	defer outputFile.Close()
	var prompt bytes.Buffer
	readCalls := 0
	invite, remaining, err := readJoinInvite(
		t.Context(),
		input,
		&prompt,
		joinCommandDependencies{
			isTerminal: func(fd uintptr) bool {
				return fd == input.Fd()
			},
			readSecret: func(
				_ context.Context,
				file *os.File,
				maxBytes int,
			) ([]byte, error) {
				readCalls++
				if file != input ||
					maxBytes != pairing.MaxPairingMessageBytes {
					t.Fatalf(
						"secret input = (%p, %d)",
						file,
						maxBytes,
					)
				}
				return []byte(issued.Invite.Code()), nil
			},
		},
	)
	if err != nil ||
		invite.Code() != issued.Invite.Code() ||
		remaining != input ||
		readCalls != 1 ||
		prompt.String() != "Invite code: \n" {
		t.Fatalf(
			"readJoinInvite() = (%q, %T, %v, calls %d, prompt %q)",
			invite.Code(),
			remaining,
			err,
			readCalls,
			prompt.String(),
		)
	}
}

func TestReadBoundedJoinLinePreservesExactInputAndLimit(t *testing.T) {
	t.Parallel()

	reader := bufio.NewReader(strings.NewReader("  exact  \r\nyes\n"))
	line, err := readBoundedJoinLine(t.Context(), reader)
	if err != nil || string(line) != "  exact  " {
		t.Fatalf("readBoundedJoinLine() = (%q, %v)", line, err)
	}
	decision, err := reader.ReadString('\n')
	if err != nil || decision != "yes\n" {
		t.Fatalf("remaining input = (%q, %v)", decision, err)
	}
	oversized := strings.Repeat("x", pairing.MaxPairingMessageBytes+1)
	if _, err := readBoundedJoinLine(
		t.Context(),
		bufio.NewReader(strings.NewReader(oversized)),
	); !errors.Is(err, errInvalidCLI) {
		t.Fatalf("oversized line error = %v", err)
	}
}

type cliJoinCredentialHandle struct {
	closed bool
}

func (*cliJoinCredentialHandle) Get(
	context.Context,
	credentialstore.Reference,
) ([]byte, error) {
	return nil, credentialstore.ErrNotFound
}

func (*cliJoinCredentialHandle) Create(
	context.Context,
	credentialstore.Reference,
	[]byte,
) error {
	return nil
}

func (handle *cliJoinCredentialHandle) Close() error {
	handle.closed = true
	return nil
}

type cliJoinFailReader struct{}

func (cliJoinFailReader) Read([]byte) (int, error) {
	return 0, errors.New("input must not be read")
}

func cliJoinDependencies(
	credentials joinCredentialHandle,
) joinCommandDependencies {
	return joinCommandDependencies{
		hasPending: func(string) (bool, error) { return false, nil },
		openCredentials: func(
			context.Context,
		) (joinCredentialHandle, error) {
			return credentials, nil
		},
		bootstrap: func(
			context.Context,
			joinbootstrap.Options,
		) (joinbootstrap.Result, error) {
			return joinbootstrap.Result{}, errors.New("unexpected bootstrap")
		},
		isTerminal: func(uintptr) bool { return false },
		readSecret: func(
			context.Context,
			*os.File,
			int,
		) ([]byte, error) {
			return nil, errors.New("unexpected terminal read")
		},
	}
}

func cliJoinReview(
	t testing.TB,
	invite pairing.SignedInvite,
	inviterPublic ed25519.PublicKey,
) pairingjoiner.ReviewSubject {
	t.Helper()
	value := invite.Invite()
	t.Cleanup(func() { clear(value.Secret[:]) })
	joinerPrivate, joinerPublic, joinerID := cliJoinIdentity(t, 0x62)
	epochPrivate := ed25519.NewKeyFromSeed(
		bytes.Repeat([]byte{0x63}, ed25519.SeedSize),
	)
	t.Cleanup(func() { clear(epochPrivate) })
	binding, err := credential.SignBinding(
		value.SessionID,
		joinerID,
		value.InitialCredentialEpoch,
		epochPrivate.Public().(ed25519.PublicKey),
		joinerPrivate,
	)
	if err != nil {
		t.Fatal(err)
	}
	core := pairing.RequestCore{
		AttemptID:           "018f47de-89ab-7def-8123-d123456789ab",
		JoinerDeviceID:      joinerID,
		DaemonVersion:       "0.1.0",
		MaxApplyLevel:       1,
		InitialEpochBinding: binding,
	}
	copy(core.JoinerIdentityPublicKey[:], joinerPublic)
	var inviterKey [ed25519.PublicKeySize]byte
	copy(inviterKey[:], inviterPublic)
	return pairingjoiner.ReviewSubject{
		AttemptID:                core.AttemptID,
		InviteID:                 value.InviteID,
		InviteDigest:             invite.Digest(),
		RequestDigest:            sha256.Sum256([]byte("request")),
		SessionID:                value.SessionID,
		WorkspaceID:              value.WorkspaceID,
		RecoveryGeneration:       value.RecoveryGeneration,
		CreatedAt:                value.CreatedAt,
		ExpiresAt:                value.ExpiresAt,
		Mode:                     value.Mode,
		Role:                     value.Role,
		InviterDeviceID:          value.InviterDeviceID,
		InviterIdentityPublicKey: inviterKey,
		SignedGenesisDigest:      value.SignedGenesisDigest,
		Core:                     core,
		SAS:                      "0001 0002 0003 0004 0005",
		ConnectedEndpoint:        netip.MustParseAddrPort("10.0.0.5:47831"),
	}
}

func cliJoinIdentity(
	t testing.TB,
	seed byte,
) (ed25519.PrivateKey, ed25519.PublicKey, domain.DeviceID) {
	t.Helper()
	privateKey := ed25519.NewKeyFromSeed(
		bytes.Repeat([]byte{seed}, ed25519.SeedSize),
	)
	publicKey := privateKey.Public().(ed25519.PublicKey)
	deviceID, err := device.DeriveID(publicKey)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { clear(privateKey) })
	return privateKey, publicKey, deviceID
}

func cliJoinDeviceID(t testing.TB, seed byte) domain.DeviceID {
	t.Helper()
	_, _, deviceID := cliJoinIdentity(t, seed)
	return deviceID
}

var _ joinCredentialHandle = (*cliJoinCredentialHandle)(nil)
var _ io.Reader = cliJoinFailReader{}
