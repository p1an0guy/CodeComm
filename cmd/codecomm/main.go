package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"sort"
	"strings"
	"syscall"
	"unicode/utf8"

	"github.com/ijonahch/codecomm/internal/domain"
	"github.com/ijonahch/codecomm/internal/ipc"
	"github.com/ijonahch/codecomm/internal/ui"
)

var errInvalidCLI = errors.New("codecomm: invalid command")

type localClientOptions struct {
	endpoint    ipc.Endpoint
	sessionID   domain.UUIDv7
	workspaceID domain.UUIDv4
}

func main() {
	ctx, stop := signal.NotifyContext(
		context.Background(),
		os.Interrupt,
		syscall.SIGTERM,
	)
	defer stop()
	if err := runCLI(
		ctx,
		os.Args[1:],
		os.Stdin,
		os.Stdout,
		os.Stderr,
	); err != nil {
		_, _ = fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func runCLI(
	ctx context.Context,
	args []string,
	input io.Reader,
	output io.Writer,
	errorOutput io.Writer,
) error {
	if ctx == nil ||
		input == nil ||
		output == nil ||
		errorOutput == nil ||
		len(args) == 0 {
		return fmt.Errorf(
			"%w: expected tui, status, join, cluster, or peer",
			errInvalidCLI,
		)
	}
	switch args[0] {
	case "join":
		return runJoin(
			ctx,
			args[1:],
			input,
			output,
			errorOutput,
		)
	case "tui":
		options, err := parseLocalClientOptions("tui", args[1:], errorOutput)
		if err != nil {
			return err
		}
		client, err := ui.DialOperator(ctx, ui.OperatorDialOptions{
			Endpoint:    options.endpoint,
			SessionID:   options.sessionID,
			WorkspaceID: options.workspaceID,
		})
		if err != nil {
			return err
		}
		runErr := ui.Run(ctx, client, input, output)
		return errors.Join(runErr, client.Close())
	case "status":
		options, err := parseLocalClientOptions(
			"status",
			args[1:],
			errorOutput,
		)
		if err != nil {
			return err
		}
		client, err := ui.DialOperator(ctx, ui.OperatorDialOptions{
			Endpoint:    options.endpoint,
			SessionID:   options.sessionID,
			WorkspaceID: options.workspaceID,
		})
		if err != nil {
			return err
		}
		snapshot, statusErr := client.Status(ctx)
		closeErr := client.Close()
		if statusErr != nil || closeErr != nil {
			return errors.Join(statusErr, closeErr)
		}
		encoder := json.NewEncoder(output)
		encoder.SetEscapeHTML(false)
		if err := encoder.Encode(snapshot); err != nil {
			return fmt.Errorf("codecomm: encode status: %w", err)
		}
		return nil
	case "cluster":
		if len(args) < 2 || args[1] != "set-voters" {
			return fmt.Errorf(
				"%w: expected cluster set-voters",
				errInvalidCLI,
			)
		}
		return runSetVoters(
			ctx,
			args[2:],
			input,
			output,
			errorOutput,
		)
	case "peer":
		if len(args) < 2 {
			return fmt.Errorf(
				"%w: expected peer revoke or peer invite",
				errInvalidCLI,
			)
		}
		if args[1] == "invite" {
			return runPeerInvite(
				ctx,
				args[2:],
				input,
				output,
				errorOutput,
			)
		}
		if args[1] == "endpoint" {
			return runPeerEndpoint(
				ctx,
				args[2:],
				output,
				errorOutput,
			)
		}
		if args[1] != "revoke" {
			return fmt.Errorf(
				"%w: expected peer revoke, peer invite, or peer endpoint",
				errInvalidCLI,
			)
		}
		return runPeerRevoke(
			ctx,
			args[2:],
			input,
			output,
			errorOutput,
		)
	default:
		return fmt.Errorf(
			"%w: unknown command %q",
			errInvalidCLI,
			args[0],
		)
	}
}

type stringListFlag []string

func (values *stringListFlag) String() string {
	return strings.Join(*values, ",")
}

func (values *stringListFlag) Set(value string) error {
	if value == "" {
		return errInvalidCLI
	}
	*values = append(*values, value)
	return nil
}

type localClientFlagValues struct {
	endpoint  *string
	session   *string
	workspace *string
}

func addLocalClientFlags(
	flags *flag.FlagSet,
) localClientFlagValues {
	return localClientFlagValues{
		endpoint: flags.String(
			"endpoint",
			"",
			"foreground daemon Unix socket or named pipe",
		),
		session:   flags.String("session", "", "session UUIDv7"),
		workspace: flags.String("workspace", "", "workspace UUIDv4"),
	}
}

func (values localClientFlagValues) options() (localClientOptions, error) {
	endpoint, err := ipc.ParseEndpoint(*values.endpoint)
	if err != nil {
		return localClientOptions{}, fmt.Errorf(
			"%w: endpoint: %v",
			errInvalidCLI,
			err,
		)
	}
	sessionID := domain.UUIDv7(*values.session)
	workspaceID := domain.UUIDv4(*values.workspace)
	if !sessionID.Valid() || !workspaceID.Valid() {
		return localClientOptions{}, fmt.Errorf(
			"%w: invalid session or workspace identifier",
			errInvalidCLI,
		)
	}
	return localClientOptions{
		endpoint:    endpoint,
		sessionID:   sessionID,
		workspaceID: workspaceID,
	}, nil
}

func runSetVoters(
	ctx context.Context,
	args []string,
	input io.Reader,
	output io.Writer,
	errorOutput io.Writer,
) error {
	flags := flag.NewFlagSet("codecomm cluster set-voters", flag.ContinueOnError)
	flags.SetOutput(errorOutput)
	localFlags := addLocalClientFlags(flags)
	var voters stringListFlag
	flags.Var(&voters, "voter", "device ID in the complete resulting target")
	confirmed := flags.Bool("yes", false, "confirm the voter target")
	if err := flags.Parse(args); err != nil {
		return fmt.Errorf("%w: %v", errInvalidCLI, err)
	}
	if flags.NArg() != 0 {
		return fmt.Errorf(
			"%w: no positional arguments are allowed",
			errInvalidCLI,
		)
	}
	if len(voters) == 0 && *confirmed {
		return fmt.Errorf(
			"%w: --yes requires an explicit --voter target",
			errInvalidCLI,
		)
	}
	options, err := localFlags.options()
	if err != nil {
		return err
	}
	client, err := ui.DialOperator(ctx, ui.OperatorDialOptions{
		Endpoint:    options.endpoint,
		SessionID:   options.sessionID,
		WorkspaceID: options.workspaceID,
	})
	if err != nil {
		return err
	}
	defer func() { _ = client.Close() }()
	if len(voters) == 0 {
		changed, result, err := runGuidedVoterPlacement(
			ctx,
			client,
			"",
			input,
			errorOutput,
		)
		if err != nil || !changed {
			return err
		}
		return encodeCommandResult(output, result)
	}
	target, err := parseVoterTarget(voters)
	if err != nil {
		return err
	}
	snapshot, err := client.Status(ctx)
	if err != nil {
		return err
	}
	if !*confirmed {
		prompt := fmt.Sprintf(
			"Set voter target at version %d to %s? Type yes: ",
			snapshot.Consensus.VoterSetVersion,
			joinDeviceIDs(target),
		)
		ok, err := confirmOperatorAction(ctx, input, errorOutput, prompt)
		if err != nil {
			return err
		}
		if !ok {
			return fmt.Errorf("%w: confirmation declined", errInvalidCLI)
		}
	}
	result, err := client.SetVoters(ctx, ui.SetVotersRequest{
		ExpectedVoterSetVersion: snapshot.Consensus.VoterSetVersion,
		VoterDeviceIDs:          target,
	})
	if err != nil {
		return err
	}
	return encodeCommandResult(output, result)
}

func runPeerRevoke(
	ctx context.Context,
	args []string,
	input io.Reader,
	output io.Writer,
	errorOutput io.Writer,
) error {
	flags := flag.NewFlagSet("codecomm peer revoke", flag.ContinueOnError)
	flags.SetOutput(errorOutput)
	localFlags := addLocalClientFlags(flags)
	deviceText := flags.String("device", "", "device ID to revoke")
	reason := flags.String("reason", "", "revocation reason")
	var voters stringListFlag
	flags.Var(&voters, "voter", "device ID in the complete resulting target")
	confirmed := flags.Bool("yes", false, "confirm the revocation")
	if err := flags.Parse(args); err != nil {
		return fmt.Errorf("%w: %v", errInvalidCLI, err)
	}
	if flags.NArg() != 0 {
		return fmt.Errorf(
			"%w: no positional arguments are allowed",
			errInvalidCLI,
		)
	}
	subject := domain.DeviceID(*deviceText)
	if !subject.Valid() ||
		len(*reason) < 1 ||
		len(*reason) > 1024 ||
		!utf8.ValidString(*reason) {
		return fmt.Errorf(
			"%w: --device and a 1-1024 byte UTF-8 --reason are required",
			errInvalidCLI,
		)
	}
	options, err := localFlags.options()
	if err != nil {
		return err
	}
	client, err := ui.DialOperator(ctx, ui.OperatorDialOptions{
		Endpoint:    options.endpoint,
		SessionID:   options.sessionID,
		WorkspaceID: options.workspaceID,
	})
	if err != nil {
		return err
	}
	defer func() { _ = client.Close() }()
	snapshot, err := client.Status(ctx)
	if err != nil {
		return err
	}
	member, found, err := client.Member(ctx, subject)
	if err != nil {
		return err
	}
	if !found {
		return fmt.Errorf(
			"%w: device is not a committed member",
			errInvalidCLI,
		)
	}
	target := snapshotVoterTarget(snapshot)
	subjectIsVoter := containsDeviceID(target, subject)
	if len(voters) > 0 {
		proposed, parseErr := parseVoterTarget(voters)
		if parseErr != nil {
			return parseErr
		}
		switch {
		case subjectIsVoter && containsDeviceID(proposed, subject):
			return fmt.Errorf(
				"%w: resulting voter target must exclude the revoked device",
				errInvalidCLI,
			)
		case !subjectIsVoter && !equalDeviceIDs(proposed, target):
			return fmt.Errorf(
				"%w: revoking a nonvoter requires the unchanged voter target",
				errInvalidCLI,
			)
		}
		target = proposed
	} else if subjectIsVoter {
		return fmt.Errorf(
			"%w: revoking a target voter requires the complete resulting --voter set",
			errInvalidCLI,
		)
	}
	if !*confirmed {
		prompt := fmt.Sprintf(
			"Revoke %s at entity version %d for reason %q; resulting voter target %s? Type yes: ",
			subject,
			member.EntityVersion,
			*reason,
			joinDeviceIDs(target),
		)
		ok, err := confirmOperatorAction(ctx, input, errorOutput, prompt)
		if err != nil {
			return err
		}
		if !ok {
			return fmt.Errorf("%w: confirmation declined", errInvalidCLI)
		}
	}
	result, err := client.RevokePeer(ctx, ui.RevokePeerRequest{
		DeviceID:                subject,
		ExpectedEntityVersion:   member.EntityVersion,
		ExpectedVoterSetVersion: snapshot.Consensus.VoterSetVersion,
		VoterDeviceIDs:          target,
		Reason:                  *reason,
	})
	if err != nil {
		return err
	}
	return encodeCommandResult(output, result)
}

func parseVoterTarget(values []string) ([]domain.DeviceID, error) {
	result := make([]domain.DeviceID, len(values))
	for index, value := range values {
		result[index] = domain.DeviceID(value)
		if !result[index].Valid() {
			return nil, fmt.Errorf("%w: invalid voter device ID", errInvalidCLI)
		}
	}
	sort.Slice(result, func(left, right int) bool {
		return result[left] < result[right]
	})
	for index := 1; index < len(result); index++ {
		if result[index-1] == result[index] {
			return nil, fmt.Errorf("%w: duplicate voter device ID", errInvalidCLI)
		}
	}
	if len(result) != 1 && len(result) != 3 && len(result) != 5 {
		return nil, fmt.Errorf(
			"%w: voter target must contain exactly 1, 3, or 5 devices",
			errInvalidCLI,
		)
	}
	return result, nil
}

func snapshotVoterTarget(snapshot ui.Snapshot) []domain.DeviceID {
	result := make(
		[]domain.DeviceID,
		len(snapshot.Consensus.TargetVoterDeviceIDs),
	)
	for index, value := range snapshot.Consensus.TargetVoterDeviceIDs {
		result[index] = domain.DeviceID(value)
	}
	return result
}

func containsDeviceID(
	values []domain.DeviceID,
	deviceID domain.DeviceID,
) bool {
	index := sort.Search(len(values), func(index int) bool {
		return values[index] >= deviceID
	})
	return index < len(values) && values[index] == deviceID
}

func equalDeviceIDs(left, right []domain.DeviceID) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

func joinDeviceIDs(values []domain.DeviceID) string {
	encoded := make([]string, len(values))
	for index, value := range values {
		encoded[index] = string(value)
	}
	return strings.Join(encoded, ",")
}

func confirmOperatorAction(
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
	return strings.TrimSpace(string(line)) == "yes", nil
}

func encodeCommandResult(
	output io.Writer,
	result ui.CommandResult,
) error {
	encoder := json.NewEncoder(output)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(result); err != nil {
		return fmt.Errorf("codecomm: encode command result: %w", err)
	}
	return nil
}

func parseLocalClientOptions(
	name string,
	args []string,
	errorOutput io.Writer,
) (localClientOptions, error) {
	flags := flag.NewFlagSet("codecomm "+name, flag.ContinueOnError)
	flags.SetOutput(errorOutput)
	values := addLocalClientFlags(flags)
	if err := flags.Parse(args); err != nil {
		return localClientOptions{}, fmt.Errorf("%w: %v", errInvalidCLI, err)
	}
	if flags.NArg() != 0 {
		return localClientOptions{}, fmt.Errorf(
			"%w: unexpected positional arguments",
			errInvalidCLI,
		)
	}
	return values.options()
}
