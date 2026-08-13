package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/google/uuid"
	"github.com/ijonahch/codecomm/internal/agent"
	"github.com/ijonahch/codecomm/internal/consensus"
	codecommcrypto "github.com/ijonahch/codecomm/internal/crypto"
	"github.com/ijonahch/codecomm/internal/domain"
	"github.com/ijonahch/codecomm/internal/domain/device"
	"github.com/ijonahch/codecomm/internal/event"
	"github.com/ijonahch/codecomm/internal/ipc"
	"github.com/ijonahch/codecomm/internal/platform/credentialstore"
	"github.com/ijonahch/codecomm/internal/ui"
)

const fatalPollInterval = 100 * time.Millisecond

var (
	errInvalidDaemonOptions      = errors.New("codecommd: invalid options")
	errDaemonLineageMismatch     = errors.New("codecommd: state lineage mismatch")
	errInvalidDaemonDependencies = errors.New("codecommd: invalid dependencies")
)

type daemonOptions struct {
	statePath    string
	consensusDir string
	endpoint     ipc.Endpoint
	sessionID    domain.UUIDv7
	workspaceID  domain.UUIDv4
}

type identityHandle interface {
	Close() error
}

type daemonDependencies struct {
	loadIdentity func(context.Context) (identityHandle, []byte, error)
	newBootID    func() (domain.UUIDv7, error)
}

func main() {
	ctx, stop := signal.NotifyContext(
		context.Background(),
		os.Interrupt,
		syscall.SIGTERM,
	)
	defer stop()

	options, err := parseDaemonOptions(os.Args[1:], os.Stderr)
	if err == nil {
		err = runDaemon(ctx, options, productionDaemonDependencies())
	}
	if err != nil {
		_, _ = fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func parseDaemonOptions(
	args []string,
	errorOutput io.Writer,
) (daemonOptions, error) {
	if errorOutput == nil {
		return daemonOptions{}, errInvalidDaemonOptions
	}
	flags := flag.NewFlagSet("codecommd", flag.ContinueOnError)
	flags.SetOutput(errorOutput)
	foreground := flags.Bool(
		"foreground",
		false,
		"run as an explicitly managed foreground daemon",
	)
	statePath := flags.String("state", "", "absolute state.db path")
	consensusDir := flags.String(
		"consensus-dir",
		"",
		"absolute Raft storage directory",
	)
	endpointText := flags.String(
		"endpoint",
		"",
		"supervisor-assigned Unix socket or named pipe",
	)
	sessionText := flags.String("session", "", "session UUIDv7")
	workspaceText := flags.String("workspace", "", "workspace UUIDv4")
	if err := flags.Parse(args); err != nil {
		return daemonOptions{}, fmt.Errorf("%w: %v", errInvalidDaemonOptions, err)
	}
	if !*foreground || flags.NArg() != 0 {
		return daemonOptions{}, fmt.Errorf(
			"%w: --foreground and no positional arguments are required",
			errInvalidDaemonOptions,
		)
	}
	if !cleanAbsolutePath(*statePath) ||
		!cleanAbsolutePath(*consensusDir) {
		return daemonOptions{}, fmt.Errorf(
			"%w: state and consensus paths must be clean and absolute",
			errInvalidDaemonOptions,
		)
	}
	endpoint, err := ipc.ParseEndpoint(*endpointText)
	if err != nil {
		return daemonOptions{}, fmt.Errorf(
			"%w: endpoint: %v",
			errInvalidDaemonOptions,
			err,
		)
	}
	sessionID := domain.UUIDv7(*sessionText)
	workspaceID := domain.UUIDv4(*workspaceText)
	if !sessionID.Valid() || !workspaceID.Valid() {
		return daemonOptions{}, fmt.Errorf(
			"%w: invalid session or workspace identifier",
			errInvalidDaemonOptions,
		)
	}
	return daemonOptions{
		statePath:    *statePath,
		consensusDir: *consensusDir,
		endpoint:     endpoint,
		sessionID:    sessionID,
		workspaceID:  workspaceID,
	}, nil
}

func cleanAbsolutePath(path string) bool {
	return path != "" &&
		filepath.IsAbs(path) &&
		filepath.Clean(path) == path
}

func productionDaemonDependencies() daemonDependencies {
	return daemonDependencies{
		loadIdentity: func(
			ctx context.Context,
		) (identityHandle, []byte, error) {
			return credentialstore.OpenRequired(
				ctx,
				credentialstore.IdentityReference(),
			)
		},
		newBootID: func() (domain.UUIDv7, error) {
			value, err := uuid.NewV7()
			if err != nil {
				return "", err
			}
			result := domain.UUIDv7(value.String())
			if !result.Valid() {
				return "", domain.ErrInvalidUUIDv7
			}
			return result, nil
		},
	}
}

func runDaemon(
	ctx context.Context,
	options daemonOptions,
	dependencies daemonDependencies,
) (resultErr error) {
	if ctx == nil ||
		dependencies.loadIdentity == nil ||
		dependencies.newBootID == nil {
		return errInvalidDaemonDependencies
	}
	if !cleanAbsolutePath(options.statePath) ||
		!cleanAbsolutePath(options.consensusDir) ||
		!options.sessionID.Valid() ||
		!options.workspaceID.Valid() {
		return errInvalidDaemonOptions
	}
	if _, err := ipc.ParseEndpoint(options.endpoint.String()); err != nil {
		return fmt.Errorf("%w: endpoint: %v", errInvalidDaemonOptions, err)
	}
	if err := ctx.Err(); err != nil {
		return err
	}

	credentialHandle, identityPrivateKey, err :=
		dependencies.loadIdentity(ctx)
	if err != nil {
		return err
	}
	if credentialHandle == nil {
		clear(identityPrivateKey)
		return errInvalidDaemonDependencies
	}
	defer func() {
		clear(identityPrivateKey)
		resultErr = errors.Join(resultErr, credentialHandle.Close())
	}()

	identityPublicKey, err :=
		codecommcrypto.Ed25519PublicKeyFromPrivateKey(identityPrivateKey)
	if err != nil {
		return fmt.Errorf("codecommd: load identity key: %w", err)
	}
	deviceID, err := device.DeriveID(identityPublicKey)
	if err != nil {
		return fmt.Errorf("codecommd: derive device identity: %w", err)
	}
	originBootID, err := dependencies.newBootID()
	if err != nil {
		return fmt.Errorf("codecommd: generate origin boot ID: %w", err)
	}
	if !originBootID.Valid() {
		return fmt.Errorf(
			"%w: generated origin boot ID is invalid",
			errInvalidDaemonDependencies,
		)
	}

	processClock := consensus.NewSystemApplyClock()
	node, err := consensus.OpenSingleNode(
		ctx,
		consensus.SingleNodeOptions{
			ServerID:     deviceID,
			StatePath:    options.statePath,
			ConsensusDir: options.consensusDir,
			OriginBootID: originBootID,
			Clock:        processClock,
		},
	)
	if err != nil {
		return err
	}
	defer func() {
		resultErr = errors.Join(resultErr, node.Close())
	}()
	if err := node.WaitForLeader(ctx); err != nil {
		return fmt.Errorf("codecommd: wait for local consensus: %w", err)
	}
	view, err := node.View(ctx)
	if err != nil {
		return fmt.Errorf("codecommd: read initialized state: %w", err)
	}
	if view.SessionID != options.sessionID ||
		view.WorkspaceID != options.workspaceID {
		return fmt.Errorf(
			"%w: got session %s and workspace %s",
			errDaemonLineageMismatch,
			view.SessionID,
			view.WorkspaceID,
		)
	}

	localState, err := node.LocalState()
	if err != nil {
		return err
	}
	authority, err := event.NewLocalAuthority(deviceID, originBootID)
	if err != nil {
		return fmt.Errorf("codecommd: create local authority: %w", err)
	}
	daemonBinding, err := authority.DaemonBinding()
	if err != nil {
		return fmt.Errorf("codecommd: create daemon binding: %w", err)
	}
	agentService, err := agent.New(agent.Options{
		Consensus:          node,
		LocalState:         localState,
		SessionID:          options.sessionID,
		WorkspaceID:        options.workspaceID,
		DeviceID:           deviceID,
		OriginBootID:       originBootID,
		IdentityPrivateKey: identityPrivateKey,
		LifecycleOrigin:    daemonBinding,
	})
	if err != nil {
		return err
	}
	defer func() {
		resultErr = errors.Join(resultErr, agentService.Close())
	}()
	if err := agentService.Recover(ctx); err != nil {
		return fmt.Errorf("codecommd: recover local agent state: %w", err)
	}

	operatorService, err := ui.NewOperatorService(ui.OperatorServiceOptions{
		Source:      node,
		SessionID:   options.sessionID,
		WorkspaceID: options.workspaceID,
	})
	if err != nil {
		return err
	}
	router, err := ipc.NewClassRouter(operatorService, agentService)
	if err != nil {
		return err
	}
	localServer, err := ipc.NewServer(ipc.Config{
		Endpoint:    options.endpoint,
		SessionID:   options.sessionID,
		WorkspaceID: options.workspaceID,
		Binder:      router,
	})
	if err != nil {
		return err
	}
	return serveUntilStopped(ctx, localServer, node, agentService)
}

func serveUntilStopped(
	ctx context.Context,
	server *ipc.Server,
	node *consensus.SingleNode,
	agentService *agent.Service,
) error {
	serveContext, cancel := context.WithCancel(ctx)
	defer cancel()
	serveDone := make(chan error, 1)
	go func() {
		serveDone <- server.Serve(serveContext)
	}()

	ticker := time.NewTicker(fatalPollInterval)
	defer ticker.Stop()
	for {
		select {
		case err := <-serveDone:
			return err
		case <-ctx.Done():
			cancel()
			return <-serveDone
		case <-ticker.C:
			if fatal := node.FatalError(); fatal != nil {
				cancel()
				return errors.Join(fatal, <-serveDone)
			}
			if fatal := agentService.FatalError(); fatal != nil {
				cancel()
				return errors.Join(fatal, <-serveDone)
			}
		}
	}
}
