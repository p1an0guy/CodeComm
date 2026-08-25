package consensus

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/ijonahch/codecomm/internal/codec"
	codecommcrypto "github.com/ijonahch/codecomm/internal/crypto"
	"github.com/ijonahch/codecomm/internal/domain"
	"github.com/ijonahch/codecomm/internal/event"
	"github.com/ijonahch/codecomm/internal/reducer"
	"github.com/ijonahch/codecomm/internal/store"
)

var (
	checkpointCommitEventID = domain.UUIDv7(
		"018f47de-89ab-7def-8123-5123456789ab",
	)
	checkpointCommitRetryEventID = domain.UUIDv7(
		"018f47de-89ab-7def-8123-5223456789ab",
	)
)

type checkpointCommitOrigin struct {
	deviceID  domain.DeviceID
	bootID    domain.UUIDv7
	private   ed25519.PrivateKey
	eventID   domain.UUIDv7
	eventIDs  []domain.UUIDv7
	createdAt domain.Timestamp

	exclusive      chan struct{}
	nextSequence   uint64
	reservations   int
	signed         []event.SignedEvent
	reserveEntered chan struct{}
	reserveRelease chan struct{}
	beforeReserve  func(context.Context, domain.Checkpoint) error
	mutateCommand  func(*event.Command)
	swallowError   bool
}

func (origin *checkpointCommitOrigin) DeviceID() domain.DeviceID {
	if origin == nil {
		return ""
	}
	return origin.deviceID
}

func (origin *checkpointCommitOrigin) BootID() domain.UUIDv7 {
	if origin == nil {
		return ""
	}
	return origin.bootID
}

func (origin *checkpointCommitOrigin) RunExclusive(
	ctx context.Context,
	operation func(CheckpointReservation) error,
) error {
	if origin == nil || ctx == nil || operation == nil {
		return ErrCheckpointOriginUnavailable
	}
	select {
	case origin.exclusive <- struct{}{}:
		defer func() { <-origin.exclusive }()
	case <-ctx.Done():
		return ctx.Err()
	}

	err := operation(origin.reserve)
	if origin.swallowError {
		return nil
	}
	return err
}

func (origin *checkpointCommitOrigin) reserve(
	ctx context.Context,
	checkpoint domain.Checkpoint,
	signature store.Signature,
) (event.SignedEvent, error) {
	if err := ctx.Err(); err != nil {
		return event.SignedEvent{}, err
	}
	if origin.beforeReserve != nil {
		if err := origin.beforeReserve(ctx, checkpoint); err != nil {
			return event.SignedEvent{}, err
		}
	}
	if origin.reserveEntered != nil {
		select {
		case <-origin.reserveEntered:
		default:
			close(origin.reserveEntered)
		}
	}
	if origin.reserveRelease != nil {
		select {
		case <-origin.reserveRelease:
		case <-ctx.Done():
			return event.SignedEvent{}, ctx.Err()
		}
	}
	payload, err := event.EncodeCheckpointPayload(
		checkpoint,
		[ed25519.SignatureSize]byte(signature),
	)
	if err != nil {
		return event.SignedEvent{}, err
	}
	authority, err := event.NewLocalAuthority(
		origin.deviceID,
		origin.bootID,
	)
	if err != nil {
		return event.SignedEvent{}, err
	}
	binding, err := authority.DaemonBinding()
	if err != nil {
		return event.SignedEvent{}, err
	}
	command := event.Command{
		Kind:     event.KindConsensusCheckpoint,
		EntityID: event.NullEntityID(),
		Actions:  []event.Action{},
		Payload:  payload,
		Redaction: event.Redaction{
			Policy:        event.RedactionDefault,
			FieldsRemoved: []event.RedactionField{},
		},
	}
	if origin.mutateCommand != nil {
		origin.mutateCommand(&command)
	}
	eventID := origin.eventID
	if origin.reservations < len(origin.eventIDs) {
		eventID = origin.eventIDs[origin.reservations]
	}
	sequence := origin.nextSequence
	proposal, err := event.BuildProposal(
		command,
		binding,
		event.BuildContext{
			EventID:        eventID,
			SessionID:      checkpoint.SessionID,
			WorkspaceID:    checkpoint.WorkspaceID,
			CreatedAt:      origin.createdAt,
			OriginSequence: sequence,
		},
	)
	if err != nil {
		return event.SignedEvent{}, err
	}
	signed, err := event.Sign(proposal, origin.private)
	if err != nil {
		return event.SignedEvent{}, err
	}
	origin.nextSequence++
	origin.reservations++
	origin.signed = append(origin.signed, signed)
	return signed, nil
}

func TestForceCheckpointCommitsExactCapturedSuccessor(t *testing.T) {
	node, origin, _, deviceID := openCheckpointCommitNode(t, nil)

	result, err := node.ForceCheckpoint(testContext(t))
	if err != nil {
		t.Fatalf("ForceCheckpoint() = (%#v, %v)", result, err)
	}
	if result.Record.SignerDeviceID != deviceID ||
		result.AppliedLogIndex !=
			result.Record.CoveredAppliedLogIndex+1 {
		t.Fatalf("checkpoint successor = %#v", result)
	}
	publicKey := origin.private.Public().(ed25519.PublicKey)
	if err := codecommcrypto.VerifyEd25519(
		publicKey,
		codec.SignatureCheckpoint,
		result.Record.CheckpointJSON,
		result.Record.AuthoritySignature[:],
	); err != nil {
		t.Fatalf("stored authority signature: %v", err)
	}
}

func TestVerifyCheckpointReplayRequiresExactDurableOutcome(t *testing.T) {
	node, origin, _, _ := openCheckpointCommitNode(t, nil)
	result, err := node.ForceCheckpoint(testContext(t))
	if err != nil {
		t.Fatalf("ForceCheckpoint(): %v", err)
	}
	committed, found, err := node.state.LookupCommandResult(
		testContext(t),
		result.Record.CheckpointEventID,
	)
	if err != nil || !found || len(origin.signed) != 1 {
		t.Fatalf(
			"checkpoint lookup = (%#v, %t, %v), proposals=%d",
			committed,
			found,
			err,
			len(origin.signed),
		)
	}
	replayed := store.ApplyResult{
		Heads:   committed.CurrentHeads,
		Outcome: committed.Outcome,
	}
	if err := node.VerifyCheckpointReplay(
		testContext(t),
		origin.signed[0],
		replayed,
	); err != nil {
		t.Fatalf("VerifyCheckpointReplay(exact): %v", err)
	}
	replayed.Outcome.Code = "unexpected_checkpoint_result"
	if err := node.VerifyCheckpointReplay(
		testContext(t),
		origin.signed[0],
		replayed,
	); err == nil {
		t.Fatal("VerifyCheckpointReplay(tampered) succeeded")
	}
	if node.FatalError() == nil {
		t.Fatal("tampered replay outcome did not halt the node")
	}
}

func TestVerifyCheckpointReplayAllowsCurrentHeadsAfterLaterCommand(
	t *testing.T,
) {
	node, origin, privateKey, deviceID := openCheckpointCommitNode(t, nil)
	checkpoint, err := node.ForceCheckpoint(testContext(t))
	if err != nil {
		t.Fatalf("ForceCheckpoint(): %v", err)
	}
	if len(origin.signed) != 1 {
		t.Fatalf("checkpoint proposals = %d, want 1", len(origin.signed))
	}
	later := nodeTestTaskEvent(
		t,
		privateKey,
		deviceID,
		nodeTestBootID1,
		nodeTestEventID1,
		nodeTestTaskID1,
		nodeTestTimestamp2,
		2,
		"later task",
	)
	if result, err := node.Apply(
		testContext(t),
		later,
	); err != nil || result.Outcome.Status != store.OutcomeAccepted {
		t.Fatalf("Apply(later) = (%#v, %v)", result, err)
	}
	replayed, err := node.Apply(testContext(t), origin.signed[0])
	if err != nil {
		t.Fatalf("Apply(checkpoint duplicate): %v", err)
	}
	if !replayed.Duplicate ||
		replayed.Heads.ResultIndex <= checkpoint.Record.CoveredResultIndex+1 {
		t.Fatalf("checkpoint replay result = %#v", replayed)
	}
	if err := node.VerifyCheckpointReplay(
		testContext(t),
		origin.signed[0],
		replayed,
	); err != nil {
		t.Fatalf("VerifyCheckpointReplay(current heads): %v", err)
	}
}

func TestVerifyCheckpointReplayHaltsOnCorruptDurableResult(t *testing.T) {
	node, origin, _, _ := openCheckpointCommitNode(t, nil)
	result, err := node.ForceCheckpoint(testContext(t))
	if err != nil {
		t.Fatalf("ForceCheckpoint(): %v", err)
	}
	committed, found, err := node.state.LookupCommandResult(
		testContext(t),
		result.Record.CheckpointEventID,
	)
	if err != nil || !found || len(origin.signed) != 1 {
		t.Fatalf(
			"checkpoint lookup = (%#v, %t, %v), proposals=%d",
			committed,
			found,
			err,
			len(origin.signed),
		)
	}
	tamperSQLite(
		t,
		node.state.Path(),
		`UPDATE command_results
		    SET outcome_json = '{"code":"accepted","status":"accepted","x":1}'
		  WHERE event_id = '`+string(result.Record.CheckpointEventID)+`';`,
	)
	err = node.VerifyCheckpointReplay(
		testContext(t),
		origin.signed[0],
		store.ApplyResult{
			Heads:   committed.CurrentHeads,
			Outcome: committed.Outcome,
		},
	)
	if !errors.Is(err, store.ErrCommandResultCorrupt) {
		t.Fatalf(
			"VerifyCheckpointReplay() error = %v, want ErrCommandResultCorrupt",
			err,
		)
	}
	if !errors.Is(node.FatalError(), store.ErrCommandResultCorrupt) {
		t.Fatalf(
			"FatalError() = %v, want ErrCommandResultCorrupt",
			node.FatalError(),
		)
	}
}

func TestForceCheckpointSerializesConcurrentProposalAfterCut(
	t *testing.T,
) {
	entered := make(chan struct{})
	release := make(chan struct{})
	node, origin, privateKey, deviceID := openCheckpointCommitNode(
		t,
		func(origin *checkpointCommitOrigin) {
			origin.reserveEntered = entered
			origin.reserveRelease = release
		},
	)

	forceDone := make(chan struct {
		result store.AppliedCheckpointLookup
		err    error
	}, 1)
	go func() {
		result, err := node.ForceCheckpoint(testContext(t))
		forceDone <- struct {
			result store.AppliedCheckpointLookup
			err    error
		}{result: result, err: err}
	}()
	select {
	case <-entered:
	case <-testContext(t).Done():
		t.Fatal("checkpoint reservation did not begin")
	}

	task := nodeTestTaskEvent(
		t,
		privateKey,
		deviceID,
		nodeTestBootID1,
		nodeTestEventID1,
		nodeTestTaskID1,
		nodeTestTimestamp2,
		2,
		"ordered after checkpoint",
	)
	applyDone := make(chan struct {
		result store.ApplyResult
		err    error
	}, 1)
	go func() {
		result, err := node.Apply(testContext(t), task)
		applyDone <- struct {
			result store.ApplyResult
			err    error
		}{result: result, err: err}
	}()
	select {
	case completed := <-applyDone:
		t.Fatalf(
			"ordinary proposal crossed checkpoint cut: (%#v, %v)",
			completed.result,
			completed.err,
		)
	case <-time.After(100 * time.Millisecond):
	}
	close(release)

	forced := <-forceDone
	if forced.err != nil {
		t.Fatalf(
			"ForceCheckpoint() = (%#v, %v)",
			forced.result,
			forced.err,
		)
	}
	applied := <-applyDone
	if applied.err != nil ||
		applied.result.Outcome.Status != store.OutcomeAccepted {
		t.Fatalf(
			"Apply() = (%#v, %v)",
			applied.result,
			applied.err,
		)
	}

	checkpointResult, checkpointFound, err :=
		node.state.LookupCommandResult(
			testContext(t),
			origin.eventID,
		)
	if err != nil || !checkpointFound ||
		checkpointResult.Tuple.ChainIndex == nil {
		t.Fatalf(
			"checkpoint result = (%#v, %t, %v)",
			checkpointResult,
			checkpointFound,
			err,
		)
	}
	taskResult, taskFound, err := node.state.LookupCommandResult(
		testContext(t),
		nodeTestEventID1,
	)
	if err != nil || !taskFound || taskResult.Tuple.ChainIndex == nil {
		t.Fatalf(
			"task result = (%#v, %t, %v)",
			taskResult,
			taskFound,
			err,
		)
	}
	if *taskResult.Tuple.ChainIndex !=
		*checkpointResult.Tuple.ChainIndex+1 {
		t.Fatalf(
			"chain order checkpoint=%d task=%d",
			*checkpointResult.Tuple.ChainIndex,
			*taskResult.Tuple.ChainIndex,
		)
	}
}

func TestForceCheckpointRetriesStaleInterleavingWithFreshEvent(t *testing.T) {
	node, origin, privateKey, deviceID := openCheckpointCommitNode(t, nil)
	prepareStaleCheckpointRetry(
		t,
		node,
		origin,
		privateKey,
		deviceID,
		[]domain.UUIDv7{
			checkpointCommitEventID,
			checkpointCommitRetryEventID,
		},
	)

	result, err := node.ForceCheckpoint(testContext(t))
	if err != nil {
		t.Fatalf("ForceCheckpoint() = (%#v, %v)", result, err)
	}
	if result.Record.CheckpointEventID !=
		checkpointCommitRetryEventID {
		t.Fatalf("checkpoint event ID = %q", result.Record.CheckpointEventID)
	}
	stale, found, err := node.state.LookupCommandResult(
		testContext(t),
		checkpointCommitEventID,
	)
	if err != nil ||
		!found ||
		stale.Outcome.Status != store.OutcomeRejected ||
		stale.Outcome.Code != string(reducer.CodeStaleCheckpoint) {
		t.Fatalf(
			"stale checkpoint result = (%#v, %t, %v)",
			stale,
			found,
			err,
		)
	}
	if len(origin.signed) != 2 {
		t.Fatalf("reserved proposals = %d, want 2", len(origin.signed))
	}
	if err := node.VerifyCheckpointReplay(
		testContext(t),
		origin.signed[0],
		store.ApplyResult{
			Heads:   stale.CurrentHeads,
			Outcome: stale.Outcome,
		},
	); err != nil {
		t.Fatalf("VerifyCheckpointReplay(stale): %v", err)
	}
	if origin.reservations != 2 || origin.nextSequence != 4 {
		t.Fatalf(
			"reservations = %d, next sequence = %d",
			origin.reservations,
			origin.nextSequence,
		)
	}
}

func TestForceCheckpointHaltsWhenStaleRetryReusesEventID(t *testing.T) {
	node, origin, privateKey, deviceID := openCheckpointCommitNode(t, nil)
	prepareStaleCheckpointRetry(
		t,
		node,
		origin,
		privateKey,
		deviceID,
		[]domain.UUIDv7{
			checkpointCommitEventID,
			checkpointCommitEventID,
		},
	)

	if _, err := node.ForceCheckpoint(
		testContext(t),
	); !errors.Is(err, ErrInvalidCheckpointEvent) {
		t.Fatalf("ForceCheckpoint() error = %v", err)
	}
	if err := node.FatalError(); !errors.Is(
		err,
		ErrInvalidCheckpointEvent,
	) {
		t.Fatalf("FatalError() = %v", err)
	}
}

func TestForceCheckpointHaltsOnInvalidReservedEvent(
	t *testing.T,
) {
	node, origin, _, _ := openCheckpointCommitNode(
		t,
		func(origin *checkpointCommitOrigin) {
			origin.mutateCommand = func(command *event.Command) {
				command.RationaleSummary = "not allowed"
			}
			origin.swallowError = true
		},
	)

	if _, err := node.ForceCheckpoint(
		testContext(t),
	); !errors.Is(err, ErrInvalidCheckpointEvent) {
		t.Fatalf("ForceCheckpoint(invalid event) error = %v", err)
	}
	if _, found, err := node.state.LookupCommandResult(
		testContext(t),
		origin.eventID,
	); err != nil || found {
		t.Fatalf("invalid checkpoint result = (found=%t, err=%v)", found, err)
	}
	if err := node.FatalError(); !errors.Is(
		err,
		ErrInvalidCheckpointEvent,
	) {
		t.Fatalf("FatalError() = %v", err)
	}
}

func TestForceCheckpointHaltsOnUnexpectedReducerRejection(t *testing.T) {
	node, origin, _, _ := openCheckpointCommitNode(
		t,
		func(origin *checkpointCommitOrigin) {
			origin.nextSequence = 2
		},
	)

	if _, err := node.ForceCheckpoint(
		testContext(t),
	); !errors.Is(err, ErrCheckpointCommitRejected) {
		t.Fatalf("ForceCheckpoint() error = %v", err)
	}
	if err := node.FatalError(); !errors.Is(
		err,
		ErrCheckpointCommitRejected,
	) {
		t.Fatalf("FatalError() = %v", err)
	}
	result, found, err := node.state.LookupCommandResult(
		testContext(t),
		origin.eventID,
	)
	if err != nil ||
		!found ||
		result.Outcome.Code != string(reducer.CodeOriginSequenceGap) {
		t.Fatalf(
			"rejected checkpoint = (%#v, %t, %v)",
			result,
			found,
			err,
		)
	}
}

func TestForceCheckpointCancelsWhileWaitingForOriginExclusivity(
	t *testing.T,
) {
	node, origin, _, _ := openCheckpointCommitNode(t, nil)
	origin.exclusive <- struct{}{}
	defer func() { <-origin.exclusive }()

	forceDone := make(chan error, 1)
	go func() {
		_, err := node.ForceCheckpoint(context.Background())
		forceDone <- err
	}()
	select {
	case err := <-forceDone:
		t.Fatalf("ForceCheckpoint() bypassed origin exclusivity: %v", err)
	case <-time.After(100 * time.Millisecond):
	}

	closeDone := make(chan error, 1)
	go func() {
		closeDone <- node.Close()
	}()
	select {
	case err := <-forceDone:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("ForceCheckpoint() error = %v", err)
		}
	case <-testContext(t).Done():
		t.Fatal("ForceCheckpoint() ignored close while waiting for origin")
	}
	select {
	case err := <-closeDone:
		if err != nil {
			t.Fatalf("Close() error = %v", err)
		}
	case <-testContext(t).Done():
		t.Fatal("Close() waited on blocked checkpoint origin")
	}
}

func TestForceCheckpointCancelsCooperativeSignerOnNodeTermination(
	t *testing.T,
) {
	for _, test := range []struct {
		name      string
		terminate func(*SingleNode) error
	}{
		{
			name: "close",
			terminate: func(node *SingleNode) error {
				return node.Close()
			},
		},
		{
			name: "fatal",
			terminate: func(node *SingleNode) error {
				return node.haltNode(errors.New("test integrity halt"))
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			entered := make(chan struct{})
			node, _, _, _ := openCheckpointCommitNodeWithSigner(
				t,
				nil,
				func(
					ctx context.Context,
					_ domain.Checkpoint,
				) (store.Signature, error) {
					close(entered)
					<-ctx.Done()
					return store.Signature{}, ctx.Err()
				},
			)

			forceDone := make(chan error, 1)
			go func() {
				_, err := node.ForceCheckpoint(context.Background())
				forceDone <- err
			}()
			select {
			case <-entered:
			case <-testContext(t).Done():
				t.Fatal("checkpoint signer was not invoked")
			}

			terminateDone := make(chan error, 1)
			go func() {
				terminateDone <- test.terminate(node)
			}()
			select {
			case err := <-forceDone:
				if !errors.Is(err, context.Canceled) {
					t.Fatalf(
						"ForceCheckpoint() error = %v",
						err,
					)
				}
			case <-testContext(t).Done():
				t.Fatal("ForceCheckpoint() ignored node termination")
			}
			select {
			case err := <-terminateDone:
				if test.name == "close" && err != nil {
					t.Fatalf("Close() error = %v", err)
				}
				if test.name == "fatal" && err == nil {
					t.Fatal("haltNode() returned nil")
				}
			case <-testContext(t).Done():
				t.Fatal("node termination waited on canceled signer")
			}
		})
	}
}

func TestForceCheckpointBoundsSignerSelection(t *testing.T) {
	node, _, _, _ := openCheckpointCommitNodeWithSigner(
		t,
		nil,
		func(
			ctx context.Context,
			_ domain.Checkpoint,
		) (store.Signature, error) {
			<-ctx.Done()
			return store.Signature{}, ctx.Err()
		},
	)

	started := time.Now()
	_, err := node.ForceCheckpoint(context.Background())
	elapsed := time.Since(started)
	if !errors.Is(err, ErrCheckpointProofUnavailable) ||
		!errors.Is(err, errCheckpointSignerTimeout) {
		t.Fatalf("ForceCheckpoint() error = %v", err)
	}
	if elapsed > checkpointSignerTimeout+time.Second {
		t.Fatalf("ForceCheckpoint() signer timeout took %s", elapsed)
	}
}

func TestForceCheckpointFailsClosedWithoutOrigin(t *testing.T) {
	node, _, _ := openApplyAtGenerationTestNode(t)
	if _, err := node.ForceCheckpoint(
		testContext(t),
	); !errors.Is(err, ErrCheckpointOriginUnavailable) {
		t.Fatalf("ForceCheckpoint() error = %v", err)
	}
}

func TestMeshCheckpointOriginRequiresProofCapableTransport(t *testing.T) {
	var transport RaftTransport
	origin := &checkpointCommitOrigin{
		exclusive: make(chan struct{}, 1),
	}
	if err := validateCheckpointCapabilities(
		nil,
		origin,
	); !errors.Is(err, ErrInvalidNodeOptions) {
		t.Fatalf("validateCheckpointCapabilities() error = %v", err)
	}
	if _, err := checkpointRequesterForTransport(
		false,
		origin,
		transport,
	); !errors.Is(err, ErrInvalidNodeOptions) {
		t.Fatalf("checkpointRequesterForTransport(mesh) error = %v", err)
	}
	if requester, err := checkpointRequesterForTransport(
		true,
		origin,
		transport,
	); err != nil || requester != nil {
		t.Fatalf(
			"checkpointRequesterForTransport(single) = (%#v, %v)",
			requester,
			err,
		)
	}
}

func prepareStaleCheckpointRetry(
	t *testing.T,
	node *SingleNode,
	origin *checkpointCommitOrigin,
	privateKey ed25519.PrivateKey,
	deviceID domain.DeviceID,
	eventIDs []domain.UUIDv7,
) {
	t.Helper()

	task := nodeTestTaskEvent(
		t,
		privateKey,
		deviceID,
		nodeTestBootID1,
		nodeTestEventID1,
		nodeTestTaskID1,
		nodeTestTimestamp1,
		1,
		"stale checkpoint interleaving",
	)
	applied, err := node.Apply(testContext(t), task)
	if err != nil || applied.Outcome.Status != store.OutcomeAccepted {
		t.Fatalf("Apply() = (%#v, %v)", applied, err)
	}

	origin.nextSequence = 2
	origin.eventIDs = eventIDs
	origin.beforeReserve = func(
		ctx context.Context,
		_ domain.Checkpoint,
	) error {
		if origin.reservations != 0 {
			return nil
		}
		future := node.raft.Apply(
			task.CanonicalBytes(),
			contextTimeout(ctx),
		)
		return waitFuture(ctx, future)
	}
}

func openCheckpointCommitNode(
	t *testing.T,
	configure func(*checkpointCommitOrigin),
) (
	*SingleNode,
	*checkpointCommitOrigin,
	ed25519.PrivateKey,
	domain.DeviceID,
) {
	t.Helper()
	return openCheckpointCommitNodeWithSigner(t, configure, nil)
}

func openCheckpointCommitNodeWithInitial(
	t *testing.T,
	configureOrigin func(*checkpointCommitOrigin),
	configureInitial func(*store.InitialState),
) (
	*SingleNode,
	*checkpointCommitOrigin,
	ed25519.PrivateKey,
	domain.DeviceID,
) {
	t.Helper()
	return openCheckpointCommitNodeWithSignerAndInitial(
		t,
		configureOrigin,
		nil,
		configureInitial,
	)
}

func openCheckpointCommitNodeWithSigner(
	t *testing.T,
	configure func(*checkpointCommitOrigin),
	sign func(
		context.Context,
		domain.Checkpoint,
	) (store.Signature, error),
) (
	*SingleNode,
	*checkpointCommitOrigin,
	ed25519.PrivateKey,
	domain.DeviceID,
) {
	t.Helper()
	return openCheckpointCommitNodeWithSignerAndInitial(
		t,
		configure,
		sign,
		nil,
	)
}

func openCheckpointCommitNodeWithSignerAndInitial(
	t *testing.T,
	configure func(*checkpointCommitOrigin),
	sign func(
		context.Context,
		domain.Checkpoint,
	) (store.Signature, error),
	configureInitial func(*store.InitialState),
) (
	*SingleNode,
	*checkpointCommitOrigin,
	ed25519.PrivateKey,
	domain.DeviceID,
) {
	t.Helper()

	root := t.TempDir()
	initial, privateKey, deviceID := nodeTestInitialState(t)
	if configureInitial != nil {
		configureInitial(&initial)
	}
	origin := &checkpointCommitOrigin{
		deviceID:     deviceID,
		bootID:       nodeTestBootID1,
		private:      bytes.Clone(privateKey),
		eventID:      checkpointCommitEventID,
		createdAt:    nodeTestTimestamp1,
		exclusive:    make(chan struct{}, 1),
		nextSequence: 1,
	}
	if configure != nil {
		configure(origin)
	}
	if sign == nil {
		sign = func(
			ctx context.Context,
			checkpoint domain.Checkpoint,
		) (store.Signature, error) {
			if err := ctx.Err(); err != nil {
				return store.Signature{}, err
			}
			signature, err := event.SignCheckpoint(
				checkpoint,
				privateKey,
			)
			return store.Signature(signature), err
		}
	}
	signer := CheckpointSignerAdapter{
		SignerDeviceID: deviceID,
		Sign:           sign,
	}
	node, err := OpenSingleNode(
		context.Background(),
		SingleNodeOptions{
			ServerID:         deviceID,
			StatePath:        filepath.Join(root, "state", "state.db"),
			ConsensusDir:     filepath.Join(root, "consensus"),
			OriginBootID:     nodeTestBootID1,
			InitialState:     &initial,
			CheckpointSigner: signer,
			CheckpointOrigin: origin,
			Clock:            nodeTestClock(),
			RaftConfig:       nodeTestRaftConfig(),
		},
	)
	if err != nil {
		t.Fatalf("OpenSingleNode(): %v", err)
	}
	t.Cleanup(func() {
		_ = node.Close()
		clear(origin.private)
	})
	waitForNodeLeader(t, node)
	return node, origin, privateKey, deviceID
}

var _ CheckpointOrigin = (*checkpointCommitOrigin)(nil)
