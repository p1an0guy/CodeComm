package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"strings"

	"github.com/ijonahch/codecomm/internal/domain"
	"github.com/ijonahch/codecomm/internal/domain/device"
	"github.com/ijonahch/codecomm/internal/pairing"
	"github.com/ijonahch/codecomm/internal/pairingservice"
	"github.com/ijonahch/codecomm/internal/ui"
)

func runPeerInvite(
	ctx context.Context,
	args []string,
	input io.Reader,
	output io.Writer,
	errorOutput io.Writer,
) error {
	if len(args) == 0 {
		return fmt.Errorf(
			"%w: expected peer invite create, list, revoke, show, or confirm",
			errInvalidCLI,
		)
	}
	switch args[0] {
	case "create":
		return runPeerInviteCreate(ctx, args[1:], output, errorOutput)
	case "list":
		return runPeerInviteList(ctx, args[1:], output, errorOutput)
	case "revoke":
		return runPeerInviteRevoke(ctx, args[1:], output, errorOutput)
	case "show":
		return runPeerInviteShow(ctx, args[1:], output, errorOutput)
	case "confirm":
		return runPeerInviteConfirm(
			ctx,
			args[1:],
			input,
			output,
			errorOutput,
		)
	default:
		return fmt.Errorf(
			"%w: unknown peer invite command %q",
			errInvalidCLI,
			args[0],
		)
	}
}

func runPeerInviteCreate(
	ctx context.Context,
	args []string,
	output io.Writer,
	errorOutput io.Writer,
) error {
	flags := flag.NewFlagSet("codecomm peer invite create", flag.ContinueOnError)
	flags.SetOutput(errorOutput)
	localFlags := addLocalClientFlags(flags)
	modeText := flags.String("mode", string(pairing.ModeNew), "pairing mode")
	roleText := flags.String("role", string(device.RoleEditor), "admitted role")
	subjectText := flags.String("subject", "", "existing subject device ID")
	expectedVersion := flags.Uint64(
		"expected-version",
		0,
		"expected readmission entity version",
	)
	epoch := flags.Uint64("epoch", 1, "initial content credential epoch")
	if err := flags.Parse(args); err != nil {
		return fmt.Errorf("%w: %v", errInvalidCLI, err)
	}
	if flags.NArg() != 0 {
		return fmt.Errorf("%w: no positional arguments are allowed", errInvalidCLI)
	}
	options, err := localFlags.options()
	if err != nil {
		return err
	}
	var subject *domain.DeviceID
	if *subjectText != "" {
		value := domain.DeviceID(*subjectText)
		if !value.Valid() {
			return fmt.Errorf("%w: invalid subject device ID", errInvalidCLI)
		}
		subject = &value
	}
	var version *uint64
	if *expectedVersion != 0 {
		value := *expectedVersion
		version = &value
	}
	client, err := dialLocalOperator(ctx, options)
	if err != nil {
		return err
	}
	defer func() { _ = client.Close() }()
	result, err := client.CreatePairingInvite(
		ctx,
		pairingservice.CreateInviteRequest{
			Mode: pairing.Mode(*modeText), SubjectDeviceID: subject,
			ExpectedEntityVersion: version, Role: device.Role(*roleText),
			InitialCredentialEpoch: *epoch,
		},
	)
	if err != nil {
		return err
	}
	return encodePairingResult(output, result)
}

func runPeerInviteList(
	ctx context.Context,
	args []string,
	output io.Writer,
	errorOutput io.Writer,
) error {
	options, err := parseLocalClientOptions("peer invite list", args, errorOutput)
	if err != nil {
		return err
	}
	client, err := dialLocalOperator(ctx, options)
	if err != nil {
		return err
	}
	defer func() { _ = client.Close() }()
	result, err := client.PairingInvites(ctx)
	if err != nil {
		return err
	}
	return encodePairingResult(output, result)
}

func runPeerInviteRevoke(
	ctx context.Context,
	args []string,
	output io.Writer,
	errorOutput io.Writer,
) error {
	flags := flag.NewFlagSet("codecomm peer invite revoke", flag.ContinueOnError)
	flags.SetOutput(errorOutput)
	localFlags := addLocalClientFlags(flags)
	inviteText := flags.String("invite", "", "invite UUIDv7")
	if err := flags.Parse(args); err != nil {
		return fmt.Errorf("%w: %v", errInvalidCLI, err)
	}
	if flags.NArg() != 0 {
		return fmt.Errorf("%w: no positional arguments are allowed", errInvalidCLI)
	}
	inviteID := domain.UUIDv7(*inviteText)
	if !inviteID.Valid() {
		return fmt.Errorf("%w: --invite is required", errInvalidCLI)
	}
	options, err := localFlags.options()
	if err != nil {
		return err
	}
	client, err := dialLocalOperator(ctx, options)
	if err != nil {
		return err
	}
	defer func() { _ = client.Close() }()
	result, err := client.RevokePairingInvite(ctx, inviteID)
	if err != nil {
		return err
	}
	return encodePairingResult(output, result)
}

func runPeerInviteShow(
	ctx context.Context,
	args []string,
	output io.Writer,
	errorOutput io.Writer,
) error {
	options, attemptID, err := parsePairingAttemptOptions(
		"peer invite show",
		args,
		errorOutput,
	)
	if err != nil {
		return err
	}
	client, err := dialLocalOperator(ctx, options)
	if err != nil {
		return err
	}
	defer func() { _ = client.Close() }()
	result, err := client.PairingAttempt(ctx, attemptID)
	if err != nil {
		return err
	}
	return encodePairingResult(output, result)
}

func runPeerInviteConfirm(
	ctx context.Context,
	args []string,
	input io.Reader,
	output io.Writer,
	errorOutput io.Writer,
) error {
	options, attemptID, accept, decline, err := parsePairingConfirmOptions(
		args,
		errorOutput,
	)
	if err != nil {
		return err
	}
	client, err := dialLocalOperator(ctx, options)
	if err != nil {
		return err
	}
	defer func() { _ = client.Close() }()
	attempt, err := client.PairingAttempt(ctx, attemptID)
	if err != nil {
		return err
	}
	confirmed := accept
	if !accept && !decline {
		prompt := fmt.Sprintf(
			"Confirm SAS %s for %s pairing of device %s, role %s, daemon %s, apply level %d, expected entity version %s, epoch %d, key %s, key digest %s, request %s? Type yes or no: ",
			attempt.SAS,
			attempt.Mode,
			attempt.JoinerDeviceID,
			attempt.Role,
			attempt.DaemonVersion,
			attempt.MaxApplyLevel,
			formatOptionalVersion(attempt.ExpectedEntityVersion),
			attempt.InitialCredentialEpoch,
			attempt.EpochPublicKey,
			attempt.EpochKeyDigest,
			attempt.RequestDigest,
		)
		confirmed, err = promptPairingDecision(
			ctx,
			input,
			errorOutput,
			prompt,
		)
		if err != nil {
			return err
		}
	}
	result, err := client.ConfirmPairing(ctx, attempt, confirmed)
	if err != nil {
		return err
	}
	return encodePairingResult(output, result)
}

func promptPairingDecision(
	ctx context.Context,
	input io.Reader,
	output io.Writer,
	prompt string,
) (bool, error) {
	if _, err := io.WriteString(output, prompt); err != nil {
		return false, err
	}
	line, err := readContextLine(
		ctx,
		input,
		maxDecisionInputBytes,
		false,
	)
	if err != nil {
		return false, err
	}
	if len(line) == 0 {
		return false, fmt.Errorf("%w: pairing confirmation was not entered", errInvalidCLI)
	}
	switch strings.TrimSpace(string(line)) {
	case "yes":
		return true, nil
	case "no":
		return false, nil
	default:
		return false, fmt.Errorf(
			"%w: pairing confirmation must be exactly yes or no",
			errInvalidCLI,
		)
	}
}

func formatOptionalVersion(value *uint64) string {
	if value == nil {
		return "none"
	}
	return fmt.Sprintf("%d", *value)
}

func parsePairingAttemptOptions(
	name string,
	args []string,
	errorOutput io.Writer,
) (localClientOptions, domain.UUIDv7, error) {
	flags := flag.NewFlagSet("codecomm "+name, flag.ContinueOnError)
	flags.SetOutput(errorOutput)
	localFlags := addLocalClientFlags(flags)
	attemptText := flags.String("attempt", "", "pairing attempt UUIDv7")
	if err := flags.Parse(args); err != nil {
		return localClientOptions{}, "", fmt.Errorf("%w: %v", errInvalidCLI, err)
	}
	if flags.NArg() != 0 {
		return localClientOptions{}, "", fmt.Errorf(
			"%w: no positional arguments are allowed",
			errInvalidCLI,
		)
	}
	attemptID := domain.UUIDv7(*attemptText)
	if !attemptID.Valid() {
		return localClientOptions{}, "", fmt.Errorf(
			"%w: --attempt is required",
			errInvalidCLI,
		)
	}
	options, err := localFlags.options()
	return options, attemptID, err
}

func parsePairingConfirmOptions(
	args []string,
	errorOutput io.Writer,
) (
	localClientOptions,
	domain.UUIDv7,
	bool,
	bool,
	error,
) {
	flags := flag.NewFlagSet("codecomm peer invite confirm", flag.ContinueOnError)
	flags.SetOutput(errorOutput)
	localFlags := addLocalClientFlags(flags)
	attemptText := flags.String("attempt", "", "pairing attempt UUIDv7")
	accept := flags.Bool("yes", false, "accept the displayed pairing details")
	decline := flags.Bool("decline", false, "decline this pairing attempt")
	if err := flags.Parse(args); err != nil {
		return localClientOptions{}, "", false, false,
			fmt.Errorf("%w: %v", errInvalidCLI, err)
	}
	if flags.NArg() != 0 || *accept && *decline {
		return localClientOptions{}, "", false, false,
			fmt.Errorf("%w: invalid confirmation flags", errInvalidCLI)
	}
	attemptID := domain.UUIDv7(*attemptText)
	if !attemptID.Valid() {
		return localClientOptions{}, "", false, false,
			fmt.Errorf("%w: --attempt is required", errInvalidCLI)
	}
	options, err := localFlags.options()
	return options, attemptID, *accept, *decline, err
}

func dialLocalOperator(
	ctx context.Context,
	options localClientOptions,
) (*ui.OperatorClient, error) {
	return ui.DialOperator(ctx, ui.OperatorDialOptions{
		Endpoint:    options.endpoint,
		SessionID:   options.sessionID,
		WorkspaceID: options.workspaceID,
	})
}

func encodePairingResult(output io.Writer, result any) error {
	encoder := json.NewEncoder(output)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(result); err != nil {
		return fmt.Errorf("codecomm: encode pairing result: %w", err)
	}
	return nil
}
