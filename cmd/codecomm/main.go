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
	"syscall"

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
		return fmt.Errorf("%w: expected tui or status", errInvalidCLI)
	}
	switch args[0] {
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
	default:
		return fmt.Errorf(
			"%w: unknown command %q",
			errInvalidCLI,
			args[0],
		)
	}
}

func parseLocalClientOptions(
	name string,
	args []string,
	errorOutput io.Writer,
) (localClientOptions, error) {
	flags := flag.NewFlagSet("codecomm "+name, flag.ContinueOnError)
	flags.SetOutput(errorOutput)
	endpointText := flags.String(
		"endpoint",
		"",
		"foreground daemon Unix socket or named pipe",
	)
	sessionText := flags.String("session", "", "session UUIDv7")
	workspaceText := flags.String("workspace", "", "workspace UUIDv4")
	if err := flags.Parse(args); err != nil {
		return localClientOptions{}, fmt.Errorf("%w: %v", errInvalidCLI, err)
	}
	if flags.NArg() != 0 {
		return localClientOptions{}, fmt.Errorf(
			"%w: unexpected positional arguments",
			errInvalidCLI,
		)
	}
	endpoint, err := ipc.ParseEndpoint(*endpointText)
	if err != nil {
		return localClientOptions{}, fmt.Errorf(
			"%w: endpoint: %v",
			errInvalidCLI,
			err,
		)
	}
	sessionID := domain.UUIDv7(*sessionText)
	workspaceID := domain.UUIDv4(*workspaceText)
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
