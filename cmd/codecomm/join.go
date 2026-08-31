package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/charmbracelet/x/term"
	"github.com/ijonahch/codecomm/internal/codec"
	"github.com/ijonahch/codecomm/internal/joinbootstrap"
	"github.com/ijonahch/codecomm/internal/pairing"
	"github.com/ijonahch/codecomm/internal/pairingjoiner"
	"github.com/ijonahch/codecomm/internal/platform/credentialstore"
)

type joinCredentialHandle interface {
	joinbootstrap.CredentialStore
	Close() error
}

type joinCommandDependencies struct {
	hasPending      func(string) (bool, error)
	openCredentials func(context.Context) (joinCredentialHandle, error)
	bootstrap       func(
		context.Context,
		joinbootstrap.Options,
	) (joinbootstrap.Result, error)
	isTerminal func(uintptr) bool
	readSecret func(context.Context, *os.File, int) ([]byte, error)
}

type joinCommandResult struct {
	SessionID          string `json:"session_id"`
	WorkspaceID        string `json:"workspace_id"`
	RecoveryGeneration uint64 `json:"recovery_generation"`
	DeviceID           string `json:"device_id"`
	StatePath          string `json:"state_path"`
	Resumed            bool   `json:"resumed"`
}

func productionJoinCommandDependencies() joinCommandDependencies {
	return joinCommandDependencies{
		hasPending: joinbootstrap.HasPending,
		openCredentials: func(
			ctx context.Context,
		) (joinCredentialHandle, error) {
			return credentialstore.OpenNative(ctx)
		},
		bootstrap:  joinbootstrap.Run,
		isTerminal: term.IsTerminal,
		readSecret: readTerminalSecret,
	}
}

func runJoin(
	ctx context.Context,
	args []string,
	input io.Reader,
	output io.Writer,
	errorOutput io.Writer,
) error {
	return runJoinCommand(
		ctx,
		args,
		input,
		output,
		errorOutput,
		productionJoinCommandDependencies(),
	)
}

func runJoinCommand(
	ctx context.Context,
	args []string,
	input io.Reader,
	output io.Writer,
	errorOutput io.Writer,
	dependencies joinCommandDependencies,
) error {
	if ctx == nil ||
		input == nil ||
		output == nil ||
		errorOutput == nil ||
		dependencies.hasPending == nil ||
		dependencies.openCredentials == nil ||
		dependencies.bootstrap == nil ||
		dependencies.isTerminal == nil ||
		dependencies.readSecret == nil {
		return fmt.Errorf("%w: invalid join dependencies", errInvalidCLI)
	}
	flags := flag.NewFlagSet("codecomm join", flag.ContinueOnError)
	flags.SetOutput(errorOutput)
	statePath := flags.String(
		"state",
		"",
		"absolute path for the joined session database",
	)
	if err := flags.Parse(args); err != nil {
		return fmt.Errorf("%w: %v", errInvalidCLI, err)
	}
	if flags.NArg() != 0 ||
		*statePath == "" ||
		!filepath.IsAbs(*statePath) ||
		filepath.Clean(*statePath) != *statePath {
		return fmt.Errorf(
			"%w: --state must be a clean absolute path and positional arguments are forbidden",
			errInvalidCLI,
		)
	}
	pending, err := dependencies.hasPending(*statePath)
	if err != nil {
		return err
	}
	credentials, err := dependencies.openCredentials(ctx)
	if err != nil {
		return err
	}
	if credentials == nil {
		return fmt.Errorf("%w: native credential store is unavailable", errInvalidCLI)
	}

	options := joinbootstrap.Options{
		StatePath:   *statePath,
		Credentials: credentials,
		Resume:      pending,
	}
	decisionInput := input
	if !pending {
		invite, remainingInput, err := readJoinInvite(
			ctx,
			input,
			errorOutput,
			dependencies,
		)
		if err != nil {
			return errors.Join(err, credentials.Close())
		}
		defer invite.Clear()
		options.Invite = invite
		decisionInput = remainingInput
		options.Confirm = func(
			confirmContext context.Context,
			review pairingjoiner.ReviewSubject,
		) (bool, error) {
			return confirmJoinReview(
				confirmContext,
				decisionInput,
				errorOutput,
				review,
			)
		}
	}
	result, runErr := dependencies.bootstrap(ctx, options)
	closeErr := credentials.Close()
	if runErr != nil || closeErr != nil {
		return errors.Join(runErr, closeErr)
	}
	return encodePairingResult(output, joinCommandResult{
		SessionID:          string(result.SessionID),
		WorkspaceID:        string(result.WorkspaceID),
		RecoveryGeneration: result.RecoveryGeneration,
		DeviceID:           string(result.DeviceID),
		StatePath:          result.StatePath,
		Resumed:            result.Resumed,
	})
}

func readJoinInvite(
	ctx context.Context,
	input io.Reader,
	output io.Writer,
	dependencies joinCommandDependencies,
) (pairing.SignedInvite, io.Reader, error) {
	if _, err := io.WriteString(output, "Invite code: "); err != nil {
		return pairing.SignedInvite{}, input, err
	}
	var encoded []byte
	remaining := input
	if file, ok := input.(*os.File); ok &&
		dependencies.isTerminal(file.Fd()) {
		var err error
		encoded, err = dependencies.readSecret(
			ctx,
			file,
			pairing.MaxPairingMessageBytes,
		)
		if _, writeErr := io.WriteString(output, "\n"); err == nil {
			err = writeErr
		}
		if err != nil {
			clear(encoded)
			return pairing.SignedInvite{}, input, err
		}
	} else {
		var err error
		encoded, err = readBoundedJoinLine(ctx, input)
		if err != nil {
			clear(encoded)
			return pairing.SignedInvite{}, input, err
		}
	}
	defer clear(encoded)
	if len(encoded) == 0 || len(encoded) > pairing.MaxPairingMessageBytes {
		return pairing.SignedInvite{}, remaining,
			fmt.Errorf("%w: invalid invite input", errInvalidCLI)
	}
	invite, err := pairing.ParseInviteCodeBytes(encoded)
	if err != nil {
		return pairing.SignedInvite{}, remaining,
			fmt.Errorf("%w: invalid invite code", errInvalidCLI)
	}
	return invite, remaining, nil
}

func readBoundedJoinLine(
	ctx context.Context,
	reader io.Reader,
) ([]byte, error) {
	if reader == nil {
		return nil, fmt.Errorf("%w: invite input is unavailable", errInvalidCLI)
	}
	return readContextLine(
		ctx,
		reader,
		pairing.MaxPairingMessageBytes,
		false,
	)
}

func confirmJoinReview(
	ctx context.Context,
	input io.Reader,
	output io.Writer,
	review pairingjoiner.ReviewSubject,
) (bool, error) {
	core := review.Core
	prompt := fmt.Sprintf(
		"Confirm SAS %s for %s pairing to session %s, workspace %s, generation %d, inviter %s key %s, joiner %s key %s, role %s, epoch %d key %s, genesis %s, request %s, endpoint %s? Type yes or no: ",
		review.SAS,
		review.Mode,
		review.SessionID,
		review.WorkspaceID,
		review.RecoveryGeneration,
		review.InviterDeviceID,
		codec.EncodeBase64URL(review.InviterIdentityPublicKey[:]),
		core.JoinerDeviceID,
		codec.EncodeBase64URL(core.JoinerIdentityPublicKey[:]),
		review.Role,
		core.InitialEpochBinding.Epoch,
		codec.EncodeBase64URL(
			core.InitialEpochBinding.EpochPublicKey[:],
		),
		codec.EncodeBase64URL(review.SignedGenesisDigest[:]),
		codec.EncodeBase64URL(review.RequestDigest[:]),
		review.ConnectedEndpoint,
	)
	return promptPairingDecision(ctx, input, output, prompt)
}
