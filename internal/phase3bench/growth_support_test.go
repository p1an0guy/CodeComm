package phase3bench

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"io/fs"
	"math"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/hashicorp/raft"
	"github.com/ijonahch/codecomm/internal/agent"
	"github.com/ijonahch/codecomm/internal/codec"
	"github.com/ijonahch/codecomm/internal/consensus"
	"github.com/ijonahch/codecomm/internal/domain"
	"github.com/ijonahch/codecomm/internal/domain/agentsession"
	"github.com/ijonahch/codecomm/internal/domain/auditcounter"
	"github.com/ijonahch/codecomm/internal/domain/credentialauthority"
	"github.com/ijonahch/codecomm/internal/domain/device"
	"github.com/ijonahch/codecomm/internal/domain/lease"
	"github.com/ijonahch/codecomm/internal/domain/plan"
	"github.com/ijonahch/codecomm/internal/domain/policy"
	"github.com/ijonahch/codecomm/internal/domain/publication"
	"github.com/ijonahch/codecomm/internal/domain/voterset"
	"github.com/ijonahch/codecomm/internal/event"
	"github.com/ijonahch/codecomm/internal/localcommand"
	"github.com/ijonahch/codecomm/internal/reducer"
	"github.com/ijonahch/codecomm/internal/store"
	"zombiezen.com/go/sqlite"
)

const (
	// CoordinationGrowthWorkloadVersion changes only through benchmark review.
	CoordinationGrowthWorkloadVersion = 2
	// CoordinationGrowthEventCount is the service-target measurement window.
	CoordinationGrowthEventCount = 10_000
	// CoordinationGrowthBudgetBytes is the §14 ceiling per measurement window.
	CoordinationGrowthBudgetBytes int64 = 50 << 20
	// CoordinationGrowthTraceSHA256 pins framed local requests, signed
	// proposals, and expected outcomes.
	CoordinationGrowthTraceSHA256 = "c92094c9829132f0f96bf859e81c3bce8837b9bb8bcd5c948312abd159d26fe6"

	growthBlockSize        = 20
	growthAcceptedPerBlock = 19
	growthRejectedPerBlock = 1
	growthCheckpointCount  = 19
)

var (
	growthSessionID        = benchmarkUUID(0x60, 1)
	growthWorkspaceID      = domain.UUIDv4("5a7e8400-e29b-41d4-a716-446655440000")
	growthAgentID          = benchmarkUUID(0x50, 1)
	growthManagedRootID    = benchmarkUUID(0x50, 2)
	growthWorkingRootID    = benchmarkUUID(0x51, 1)
	growthClientInstanceID = benchmarkUUID(0x52, 1)
	growthLaunchID         = benchmarkUUID(0x53, 1)
	growthInitialBootID    = benchmarkUUID(0x61, 1)
	growthTraceBootID      = benchmarkUUID(0x61, 2)
	growthReopenBootID     = benchmarkUUID(0x61, 3)
	growthBaseTime         = time.Date(2026, 9, 2, 12, 0, 0, 0, time.UTC)
)

// StorageBytes is the logical-byte footprint covered by the growth budget.
type StorageBytes struct {
	StateDB        int64 `json:"state_db"`
	StateWAL       int64 `json:"state_wal"`
	StateSHM       int64 `json:"state_shm"`
	Consensus      int64 `json:"consensus"`
	ConsensusFiles int   `json:"consensus_files"`
	Total          int64 `json:"total"`
}

// CoordinationGrowthReport is one complete, reproducible budget measurement.
type CoordinationGrowthReport struct {
	WorkloadVersion  int            `json:"workload_version"`
	TraceSHA256      string         `json:"trace_sha256"`
	EventCount       int            `json:"event_count"`
	AcceptedCount    int            `json:"accepted_count"`
	RejectedCount    int            `json:"rejected_count"`
	CheckpointCount  int            `json:"checkpoint_count"`
	LocalBytes       int64          `json:"canonical_local_request_bytes"`
	ProposalBytes    int64          `json:"signed_proposal_bytes"`
	KindHistogram    map[string]int `json:"kind_histogram"`
	OutcomeHistogram map[string]int `json:"outcome_histogram"`
	BaselineBytes    StorageBytes   `json:"baseline_bytes"`
	FinalBytes       StorageBytes   `json:"final_bytes"`
	GrowthBytes      int64          `json:"growth_bytes"`
	GrowthMiB        float64        `json:"growth_mib"`
	BudgetBytes      int64          `json:"budget_bytes"`
	WithinBudget     bool           `json:"within_budget"`
	ElapsedMillis    int64          `json:"elapsed_millis"`
	ResultIndex      uint64         `json:"result_index"`
	ChainIndex       uint64         `json:"chain_index"`
	GOOS             string         `json:"goos"`
	GOARCH           string         `json:"goarch"`
}

// CoordinationGrowthContract identifies the frozen generated trace.
type CoordinationGrowthContract struct {
	WorkloadVersion   int
	TraceSHA256       string
	EventCount        int
	AcceptedCount     int
	RejectedCount     int
	LocalRequestBytes int64
	SignedEventBytes  int64
	KindHistogram     map[string]int
	OutcomeHistogram  map[string]int
}

type growthFixture struct {
	private  ed25519.PrivateKey
	deviceID domain.DeviceID
	binding  event.Binding
	initial  store.InitialState
}

type growthCommand struct {
	command          event.Command
	clientInstanceID domain.UUIDv7
	requestID        domain.UUIDv7
	eventID          domain.UUIDv7
	createdAt        domain.Timestamp
	canonicalRequest []byte
	signed           event.SignedEvent
	wantStatus       store.OutcomeStatus
	wantCode         string
}

type growthJSONEncoder struct {
	err error
}

type growthRequestExpectation struct {
	clientInstanceID domain.UUIDv7
	requestID        domain.UUIDv7
	eventID          domain.UUIDv7
	requestKind      event.Kind
	requestDigest    store.Digest
	outcome          store.CommandOutcome
}

type growthNodeRuntime struct {
	node   *consensus.SingleNode
	origin *agent.BootOrigin
}

type growthCheckpointIDs struct {
	mu     sync.Mutex
	values []domain.UUIDv7
	next   int
}

// CoordinationGrowthContractValue generates and fingerprints the exact trace
// without opening durable state.
func CoordinationGrowthContractValue() (CoordinationGrowthContract, error) {
	fixture, err := newGrowthFixture()
	if err != nil {
		return CoordinationGrowthContract{}, err
	}
	defer clear(fixture.private)
	return walkCoordinationGrowth(fixture, nil)
}

// runCoordinationGrowth measures one frozen trace through durable local
// requests, the outbox, real Raft, reducers, and SQLite.
func runCoordinationGrowth(
	ctx context.Context,
	root string,
) (CoordinationGrowthReport, error) {
	if ctx == nil {
		return CoordinationGrowthReport{}, fmt.Errorf("phase3bench: nil context")
	}
	if err := ctx.Err(); err != nil {
		return CoordinationGrowthReport{}, err
	}
	if err := requireEmptyDirectory(root); err != nil {
		return CoordinationGrowthReport{}, err
	}
	fixture, err := newGrowthFixture()
	if err != nil {
		return CoordinationGrowthReport{}, err
	}
	defer clear(fixture.private)
	statePath := filepath.Join(root, "state", "state.db")
	consensusDir := filepath.Join(root, "consensus")

	if err := seedGrowthBaseline(
		ctx,
		fixture,
		statePath,
		consensusDir,
	); err != nil {
		return CoordinationGrowthReport{}, err
	}
	baseline, err := measureStorage(statePath, consensusDir)
	if err != nil {
		return CoordinationGrowthReport{}, err
	}

	runtimeState, checkpointIDs, err := openGrowthNode(
		ctx,
		fixture,
		statePath,
		consensusDir,
		growthTraceBootID,
		nil,
		true,
	)
	if err != nil {
		return CoordinationGrowthReport{}, err
	}
	closed := false
	defer func() {
		if !closed {
			_ = runtimeState.close()
		}
	}()
	if err := runtimeState.node.WaitForLeader(ctx); err != nil {
		return CoordinationGrowthReport{}, fmt.Errorf(
			"phase3bench: wait for trace leader: %w",
			err,
		)
	}
	local, err := runtimeState.node.LocalState()
	if err != nil {
		return CoordinationGrowthReport{}, fmt.Errorf(
			"phase3bench: acquire local state: %w",
			err,
		)
	}

	started := time.Now()
	acceptedWorkload := 0
	expectations := make(
		[]growthRequestExpectation,
		0,
		CoordinationGrowthEventCount,
	)
	contract, err := walkCoordinationGrowth(
		fixture,
		func(index int, command growthCommand) error {
			result, resolved, err := applyGrowthCommand(
				ctx,
				runtimeState.node,
				local,
				fixture,
				index,
				command,
			)
			if err != nil {
				return err
			}
			expectations = append(
				expectations,
				growthRequestExpectation{
					clientInstanceID: command.clientInstanceID,
					requestID:        command.requestID,
					eventID:          command.eventID,
					requestKind:      command.command.Kind,
					requestDigest: store.Digest(
						sha256.Sum256(command.canonicalRequest),
					),
					outcome: cloneGrowthOutcome(result.Outcome),
				},
			)
			if !sameGrowthOutcome(*resolved.Outcome, result.Outcome) {
				return fmt.Errorf(
					"phase3bench: request %d durable outcome differs from apply result",
					index+1,
				)
			}
			if command.wantStatus != store.OutcomeAccepted {
				return nil
			}
			acceptedWorkload++
			if acceptedWorkload%500 != 0 {
				return nil
			}
			ordinal := acceptedWorkload / 500
			if ordinal > growthCheckpointCount {
				return fmt.Errorf(
					"phase3bench: unexpected checkpoint ordinal %d",
					ordinal,
				)
			}
			if err := forceGrowthCheckpoint(
				ctx,
				runtimeState.node,
				local,
				checkpointIDs,
				ordinal,
			); err != nil {
				return err
			}
			return nil
		},
	)
	if err != nil {
		return CoordinationGrowthReport{}, err
	}
	if contract.TraceSHA256 != CoordinationGrowthTraceSHA256 {
		return CoordinationGrowthReport{}, fmt.Errorf(
			"phase3bench: trace digest %s differs from frozen %s",
			contract.TraceSHA256,
			CoordinationGrowthTraceSHA256,
		)
	}
	if acceptedWorkload != contract.AcceptedCount ||
		checkpointIDs == nil ||
		checkpointIDs.consumed() != growthCheckpointCount*2 {
		consumed := 0
		if checkpointIDs != nil {
			consumed = checkpointIDs.consumed()
		}
		return CoordinationGrowthReport{}, fmt.Errorf(
			"phase3bench: checkpoint cadence produced %d accepted commands and %d IDs",
			acceptedWorkload,
			consumed,
		)
	}
	if err := requireEmptyOutbox(ctx, local); err != nil {
		return CoordinationGrowthReport{}, err
	}
	if err := runtimeState.node.Barrier(ctx); err != nil {
		return CoordinationGrowthReport{}, fmt.Errorf(
			"phase3bench: final barrier: %w",
			err,
		)
	}
	view, err := runtimeState.node.View(ctx)
	if err != nil {
		return CoordinationGrowthReport{}, fmt.Errorf(
			"phase3bench: inspect final view: %w",
			err,
		)
	}
	if err := validateGrowthView(
		view,
		contract,
		growthCheckpointCount,
	); err != nil {
		return CoordinationGrowthReport{}, err
	}
	elapsed := time.Since(started)
	if err := runtimeState.close(); err != nil {
		return CoordinationGrowthReport{}, fmt.Errorf(
			"phase3bench: close trace node: %w",
			err,
		)
	}
	closed = true

	final, err := measureStorage(statePath, consensusDir)
	if err != nil {
		return CoordinationGrowthReport{}, err
	}
	if err := verifyGrowthReopen(
		ctx,
		fixture,
		statePath,
		consensusDir,
		view,
		contract,
		expectations,
	); err != nil {
		return CoordinationGrowthReport{}, err
	}
	growth := final.Total - baseline.Total
	if growth < 0 {
		return CoordinationGrowthReport{}, fmt.Errorf(
			"phase3bench: final storage %d is smaller than baseline %d",
			final.Total,
			baseline.Total,
		)
	}
	return CoordinationGrowthReport{
		WorkloadVersion: contract.WorkloadVersion,
		TraceSHA256:     contract.TraceSHA256,
		EventCount:      contract.EventCount,
		AcceptedCount:   contract.AcceptedCount,
		RejectedCount:   contract.RejectedCount,
		CheckpointCount: growthCheckpointCount,
		LocalBytes:      contract.LocalRequestBytes,
		ProposalBytes:   contract.SignedEventBytes,
		KindHistogram:   cloneGrowthHistogram(contract.KindHistogram),
		OutcomeHistogram: cloneGrowthHistogram(
			contract.OutcomeHistogram,
		),
		BaselineBytes: baseline,
		FinalBytes:    final,
		GrowthBytes:   growth,
		GrowthMiB:     float64(growth) / float64(1<<20),
		BudgetBytes:   CoordinationGrowthBudgetBytes,
		WithinBudget:  growth <= CoordinationGrowthBudgetBytes,
		ElapsedMillis: elapsed.Milliseconds(),
		ResultIndex:   view.Heads.ResultIndex,
		ChainIndex:    view.Heads.ChainIndex,
		GOOS:          runtime.GOOS,
		GOARCH:        runtime.GOARCH,
	}, nil
}

func applyGrowthCommand(
	ctx context.Context,
	node *consensus.SingleNode,
	local store.LocalState,
	fixture growthFixture,
	index int,
	command growthCommand,
) (store.ApplyResult, store.LocalCommandRecord, error) {
	record, duplicate, err := local.ReserveCommand(
		ctx,
		store.LocalCommandInput{
			ClientInstanceID: command.clientInstanceID,
			RequestID:        command.requestID,
			SessionID:        growthSessionID,
			WorkspaceID:      growthWorkspaceID,
			BindingClass:     store.LocalBindingAgent,
			OriginDeviceID:   fixture.deviceID,
			OriginScopeKind:  store.OriginScopeKindAgent,
			OriginScopeID:    growthAgentID,
			RequestKind:      command.command.Kind,
			CanonicalRequest: command.canonicalRequest,
			CreatedAt:        command.createdAt,
		},
		func() (domain.UUIDv7, error) {
			return command.eventID, nil
		},
		func(
			eventID domain.UUIDv7,
			originSequence uint64,
		) (event.SignedEvent, error) {
			proposal, err := event.BuildProposal(
				command.command,
				fixture.binding,
				event.BuildContext{
					EventID:        eventID,
					SessionID:      growthSessionID,
					WorkspaceID:    growthWorkspaceID,
					CreatedAt:      command.createdAt,
					OriginSequence: originSequence,
				},
			)
			if err != nil {
				return event.SignedEvent{}, err
			}
			return event.Sign(proposal, fixture.private)
		},
	)
	if err != nil {
		return store.ApplyResult{}, store.LocalCommandRecord{}, fmt.Errorf(
			"phase3bench: reserve workload request %d: %w",
			index+1,
			err,
		)
	}
	if duplicate ||
		record.EventID != command.eventID ||
		record.RequestDigest !=
			store.Digest(sha256.Sum256(command.canonicalRequest)) ||
		!bytes.Equal(record.SignedProposal, command.signed.CanonicalBytes()) {
		return store.ApplyResult{}, store.LocalCommandRecord{}, fmt.Errorf(
			"phase3bench: workload request %d reservation differs from frozen command",
			index+1,
		)
	}
	scope := store.OutboxScope{
		OriginDeviceID:  fixture.deviceID,
		OriginScopeKind: store.OriginScopeKindAgent,
		OriginScopeID:   growthAgentID,
	}
	outbox, found, err := local.ClaimNextOutbox(ctx, scope)
	if err != nil {
		return store.ApplyResult{}, store.LocalCommandRecord{}, fmt.Errorf(
			"phase3bench: claim workload request %d: %w",
			index+1,
			err,
		)
	}
	if !found ||
		outbox.ClientInstanceID != command.clientInstanceID ||
		outbox.RequestID != command.requestID ||
		outbox.EventID != command.eventID ||
		outbox.OriginSequence != uint64(index+2) ||
		!bytes.Equal(outbox.SignedProposal, command.signed.CanonicalBytes()) {
		return store.ApplyResult{}, store.LocalCommandRecord{}, fmt.Errorf(
			"phase3bench: workload request %d claimed the wrong outbox row",
			index+1,
		)
	}
	signed, err := event.ParseAndVerify(
		outbox.SignedProposal,
		event.VerificationContext{
			SessionID:         growthSessionID,
			WorkspaceID:       growthWorkspaceID,
			IdentityPublicKey: fixture.private.Public().(ed25519.PublicKey),
		},
	)
	if err != nil ||
		!bytes.Equal(signed.CanonicalBytes(), command.signed.CanonicalBytes()) {
		return store.ApplyResult{}, store.LocalCommandRecord{}, fmt.Errorf(
			"phase3bench: verify workload request %d outbox proposal: %w",
			index+1,
			err,
		)
	}
	result, err := node.ApplyAtGeneration(
		ctx,
		outbox.SessionID,
		outbox.RecoveryGeneration,
		signed,
	)
	if err != nil {
		return store.ApplyResult{}, store.LocalCommandRecord{}, fmt.Errorf(
			"phase3bench: apply workload request %d: %w",
			index+1,
			err,
		)
	}
	if result.Duplicate ||
		result.Outcome.Status != command.wantStatus ||
		result.Outcome.Code != command.wantCode {
		return store.ApplyResult{}, store.LocalCommandRecord{}, fmt.Errorf(
			"phase3bench: workload request %d outcome = (%q, %q, duplicate=%t), want (%q, %q, false)",
			index+1,
			result.Outcome.Status,
			result.Outcome.Code,
			result.Duplicate,
			command.wantStatus,
			command.wantCode,
		)
	}
	resolved, found, err := local.LookupRequest(
		ctx,
		command.clientInstanceID,
		command.requestID,
	)
	if err != nil ||
		!found ||
		resolved.State != store.LocalRequestResolved ||
		resolved.Outcome == nil ||
		resolved.EventID != command.eventID ||
		!sameGrowthOutcome(*resolved.Outcome, result.Outcome) {
		return store.ApplyResult{}, store.LocalCommandRecord{}, fmt.Errorf(
			"phase3bench: workload request %d did not resolve exactly: found=%t err=%v",
			index+1,
			found,
			err,
		)
	}
	return result, resolved, nil
}

func seedGrowthBaseline(
	ctx context.Context,
	fixture growthFixture,
	statePath string,
	consensusDir string,
) error {
	// OpenSingleNode verifies startup integrity and Raft/SQLite coverage before
	// returning. The explicit store scrub below proves full commitment history.
	runtimeState, _, err := openGrowthNode(
		ctx,
		fixture,
		statePath,
		consensusDir,
		growthInitialBootID,
		&fixture.initial,
		false,
	)
	if err != nil {
		return err
	}
	closed := false
	defer func() {
		if !closed {
			_ = runtimeState.close()
		}
	}()
	if err := runtimeState.node.WaitForLeader(ctx); err != nil {
		return fmt.Errorf("phase3bench: wait for baseline leader: %w", err)
	}
	local, err := runtimeState.node.LocalState()
	if err != nil {
		return fmt.Errorf("phase3bench: acquire baseline local state: %w", err)
	}
	verifiedAt := domain.Timestamp(
		growthBaseTime.Add(-3 * time.Second).Format(time.RFC3339),
	)
	if err := local.RegisterManagedRoot(
		ctx,
		store.ManagedRootRecord{
			ManagedRootID:      growthManagedRootID,
			SessionID:          growthSessionID,
			WorkspaceID:        growthWorkspaceID,
			RecoveryGeneration: 0,
			CanonicalPath: filepath.Join(
				filepath.Dir(filepath.Dir(statePath)),
				"workspace",
			),
			FilesystemIdentity: "phase3bench-filesystem",
			RepositoryIdentity: "phase3bench-repository",
			Kind:               store.ManagedRootIsolated,
			GuardStatus:        store.RootGuardHealthy,
			Active:             true,
			LastVerifiedAt:     &verifiedAt,
		},
	); err != nil {
		return fmt.Errorf("phase3bench: register baseline root: %w", err)
	}
	selectorDigest := store.Digest(
		sha256.Sum256([]byte("codecomm/phase3/growth-launch-selector")),
	)
	launchCreatedAt := domain.Timestamp(
		growthBaseTime.Add(-2 * time.Second).Format(time.RFC3339),
	)
	if err := local.RegisterLaunch(ctx, store.LaunchRegistration{
		LaunchID:        growthLaunchID,
		SelectorDigest:  selectorDigest,
		SessionID:       growthSessionID,
		WorkspaceID:     growthWorkspaceID,
		ClientKind:      agentsession.ClientKindCodex,
		ConcurrencyMode: store.ConcurrencyIsolated,
		ManagedRootID:   growthManagedRootID,
		CreatedAt:       launchCreatedAt,
	}); err != nil {
		return fmt.Errorf("phase3bench: register baseline launch: %w", err)
	}
	launchRequest, err := canonicalGrowthLaunchRequest()
	if err != nil {
		return err
	}
	start, duplicate, err := local.ReserveLaunchStart(
		ctx,
		selectorDigest,
		growthClientInstanceID,
		launchRequest,
		fixture.deviceID,
		func() (store.LaunchStartIDs, error) {
			return store.LaunchStartIDs{
				AgentSessionID: growthAgentID,
				WorkingRootID:  growthWorkingRootID,
				EventID:        benchmarkUUID(0x10, 1),
			}, nil
		},
		func(
			launch store.LaunchRecord,
			ids store.LaunchStartIDs,
		) (event.SignedEvent, error) {
			if launch.LaunchID != growthLaunchID ||
				ids.AgentSessionID != growthAgentID ||
				ids.WorkingRootID != growthWorkingRootID ||
				ids.EventID != benchmarkUUID(0x10, 1) {
				return event.SignedEvent{}, fmt.Errorf(
					"phase3bench: launch reservation changed frozen IDs",
				)
			}
			return growthAgentStart(fixture)
		},
	)
	if err != nil {
		return fmt.Errorf("phase3bench: reserve baseline launch: %w", err)
	}
	if duplicate {
		return fmt.Errorf("phase3bench: baseline launch was a duplicate")
	}
	scope := store.OutboxScope{
		OriginDeviceID:  fixture.deviceID,
		OriginScopeKind: store.OriginScopeKindAgent,
		OriginScopeID:   growthAgentID,
	}
	outbox, found, err := local.ClaimNextOutbox(ctx, scope)
	if err != nil || !found ||
		outbox.EventID != start.Command.EventID ||
		!bytes.Equal(
			outbox.SignedProposal,
			start.Command.SignedProposal,
		) {
		return fmt.Errorf(
			"phase3bench: claim baseline launch: found=%t err=%v",
			found,
			err,
		)
	}
	signed, err := event.ParseAndVerify(
		outbox.SignedProposal,
		event.VerificationContext{
			SessionID:         growthSessionID,
			WorkspaceID:       growthWorkspaceID,
			IdentityPublicKey: fixture.private.Public().(ed25519.PublicKey),
		},
	)
	if err != nil {
		return fmt.Errorf(
			"phase3bench: verify baseline launch proposal: %w",
			err,
		)
	}
	result, err := runtimeState.node.ApplyAtGeneration(
		ctx,
		outbox.SessionID,
		outbox.RecoveryGeneration,
		signed,
	)
	if err != nil {
		return fmt.Errorf("phase3bench: seed agent session: %w", err)
	}
	if result.Duplicate ||
		result.Outcome.Status != store.OutcomeAccepted ||
		result.Outcome.Code != string(reducer.CodeAccepted) {
		return fmt.Errorf(
			"phase3bench: seed agent outcome = (%q, %q, duplicate=%t)",
			result.Outcome.Status,
			result.Outcome.Code,
			result.Duplicate,
		)
	}
	resolved, found, err := local.LookupRequest(
		ctx,
		growthClientInstanceID,
		growthLaunchID,
	)
	if err != nil ||
		!found ||
		resolved.State != store.LocalRequestResolved ||
		resolved.EventID != start.Command.EventID ||
		resolved.Outcome == nil ||
		!sameGrowthOutcome(*resolved.Outcome, result.Outcome) {
		return fmt.Errorf(
			"phase3bench: baseline launch did not resolve: found=%t err=%v",
			found,
			err,
		)
	}
	if err := requireEmptyOutbox(ctx, local); err != nil {
		return err
	}
	if err := runtimeState.node.Barrier(ctx); err != nil {
		return fmt.Errorf("phase3bench: baseline barrier: %w", err)
	}
	if err := runtimeState.close(); err != nil {
		return fmt.Errorf("phase3bench: close baseline node: %w", err)
	}
	closed = true
	return nil
}

func openGrowthNode(
	ctx context.Context,
	fixture growthFixture,
	statePath string,
	consensusDir string,
	bootID domain.UUIDv7,
	initial *store.InitialState,
	withCheckpoints bool,
) (*growthNodeRuntime, *growthCheckpointIDs, error) {
	options := consensus.SingleNodeOptions{
		ServerID:     fixture.deviceID,
		StatePath:    statePath,
		ConsensusDir: consensusDir,
		OriginBootID: bootID,
		InitialState: initial,
		Clock:        growthApplyClock(),
		RaftConfig:   growthRaftConfig(),
	}
	var (
		bootOrigin    *agent.BootOrigin
		checkpointIDs *growthCheckpointIDs
	)
	if withCheckpoints {
		authority, err := event.NewLocalAuthority(
			fixture.deviceID,
			bootID,
		)
		if err != nil {
			return nil, nil, fmt.Errorf(
				"phase3bench: create checkpoint authority: %w",
				err,
			)
		}
		daemonBinding, err := authority.DaemonBinding()
		if err != nil {
			return nil, nil, fmt.Errorf(
				"phase3bench: create checkpoint daemon binding: %w",
				err,
			)
		}
		operatorBinding, err := authority.OperatorBinding()
		if err != nil {
			return nil, nil, fmt.Errorf(
				"phase3bench: create checkpoint operator binding: %w",
				err,
			)
		}
		checkpointIDs = newGrowthCheckpointIDs()
		options.CheckpointSigner = consensus.CheckpointSignerAdapter{
			SignerDeviceID: fixture.deviceID,
			Sign: func(
				ctx context.Context,
				checkpoint domain.Checkpoint,
			) (store.Signature, error) {
				if err := ctx.Err(); err != nil {
					return store.Signature{}, err
				}
				signature, err := event.SignCheckpoint(
					checkpoint,
					fixture.private,
				)
				return store.Signature(signature), err
			},
		}
		options.CheckpointOriginFactory = func(
			local store.LocalState,
			submitter consensus.CheckpointCommandSubmitter,
		) (consensus.CheckpointOrigin, error) {
			created, err := agent.NewBootOrigin(agent.BootOriginOptions{
				Consensus:          submitter,
				LocalState:         local,
				SessionID:          growthSessionID,
				WorkspaceID:        growthWorkspaceID,
				DeviceID:           fixture.deviceID,
				OriginBootID:       bootID,
				IdentityPrivateKey: fixture.private,
				DaemonOrigin:       daemonBinding,
				OperatorOrigin:     operatorBinding,
				Clock:              growthCheckpointClock(),
				GenerateID:         checkpointIDs.generate,
			})
			if err == nil {
				bootOrigin = created
			}
			return created, err
		}
	}
	node, err := consensus.OpenSingleNode(ctx, options)
	if err != nil {
		return nil, nil, fmt.Errorf("phase3bench: open node: %w", err)
	}
	return &growthNodeRuntime{
		node:   node,
		origin: bootOrigin,
	}, checkpointIDs, nil
}

func (runtimeState *growthNodeRuntime) close() error {
	if runtimeState == nil {
		return nil
	}
	var errs []error
	if runtimeState.origin != nil {
		if err := runtimeState.origin.BeginClose(); err != nil {
			errs = append(errs, fmt.Errorf(
				"begin checkpoint-origin close: %w",
				err,
			))
		}
	}
	if runtimeState.node != nil {
		if err := runtimeState.node.Close(); err != nil {
			errs = append(errs, fmt.Errorf("close node: %w", err))
		}
	}
	if runtimeState.origin != nil {
		if err := runtimeState.origin.Wait(); err != nil {
			errs = append(errs, fmt.Errorf(
				"wait for checkpoint-origin close: %w",
				err,
			))
		}
	}
	return errors.Join(errs...)
}

func walkCoordinationGrowth(
	fixture growthFixture,
	visit func(int, growthCommand) error,
) (CoordinationGrowthContract, error) {
	digest := sha256.New()
	writeGrowthTraceFrame(
		digest,
		"trace-domain",
		[]byte("codecomm/phase3/coordination-growth/v2"),
	)
	accepted := 0
	rejected := 0
	var localRequestBytes, signedEventBytes int64
	kindHistogram := make(map[string]int)
	outcomeHistogram := make(map[string]int)
	for index := 0; index < CoordinationGrowthEventCount; index++ {
		command, err := buildGrowthCommand(fixture, index)
		if err != nil {
			return CoordinationGrowthContract{}, fmt.Errorf(
				"phase3bench: build event %d: %w",
				index+1,
				err,
			)
		}
		var ordinal [8]byte
		binary.BigEndian.PutUint64(ordinal[:], uint64(index+1))
		writeGrowthTraceFrame(digest, "command-index", ordinal[:])
		writeGrowthTraceFrame(
			digest,
			"canonical-local-request",
			command.canonicalRequest,
		)
		canonical := command.signed.CanonicalBytes()
		writeGrowthTraceFrame(
			digest,
			"signed-proposal",
			canonical,
		)
		writeGrowthTraceFrame(
			digest,
			"expected-status",
			[]byte(command.wantStatus),
		)
		writeGrowthTraceFrame(
			digest,
			"expected-code",
			[]byte(command.wantCode),
		)
		localRequestBytes += int64(len(command.canonicalRequest))
		signedEventBytes += int64(len(canonical))
		kindHistogram[string(command.command.Kind)]++
		outcomeKey := string(command.wantStatus) + "/" + command.wantCode
		outcomeHistogram[outcomeKey]++
		switch command.wantStatus {
		case store.OutcomeAccepted:
			accepted++
		case store.OutcomeRejected:
			rejected++
		default:
			return CoordinationGrowthContract{}, fmt.Errorf(
				"phase3bench: event %d has invalid expected status %q",
				index+1,
				command.wantStatus,
			)
		}
		if visit != nil {
			if err := visit(index, command); err != nil {
				return CoordinationGrowthContract{}, err
			}
		}
	}
	return CoordinationGrowthContract{
		WorkloadVersion:   CoordinationGrowthWorkloadVersion,
		TraceSHA256:       hex.EncodeToString(digest.Sum(nil)),
		EventCount:        CoordinationGrowthEventCount,
		AcceptedCount:     accepted,
		RejectedCount:     rejected,
		LocalRequestBytes: localRequestBytes,
		SignedEventBytes:  signedEventBytes,
		KindHistogram:     kindHistogram,
		OutcomeHistogram:  outcomeHistogram,
	}, nil
}

func writeGrowthTraceFrame(
	digest hash.Hash,
	label string,
	payload []byte,
) {
	var labelLength [4]byte
	binary.BigEndian.PutUint32(labelLength[:], uint32(len(label)))
	_, _ = digest.Write(labelLength[:])
	_, _ = digest.Write([]byte(label))
	var payloadLength [8]byte
	binary.BigEndian.PutUint64(payloadLength[:], uint64(len(payload)))
	_, _ = digest.Write(payloadLength[:])
	_, _ = digest.Write(payload)
}

func buildGrowthCommand(
	fixture growthFixture,
	index int,
) (growthCommand, error) {
	block := index / growthBlockSize
	slot := index % growthBlockSize
	taskA := benchmarkUUID(0x30, uint64(block*2+1))
	taskB := benchmarkUUID(0x30, uint64(block*2+2))
	leaseA := benchmarkUUID(0x40, uint64(block*2+1))
	leaseB := benchmarkUUID(0x40, uint64(block*2+2))

	command := event.Command{
		Actions: []event.Action{},
		Redaction: event.Redaction{
			Policy:        event.RedactionDefault,
			FieldsRemoved: []event.RedactionField{},
		},
	}
	encoder := &growthJSONEncoder{}
	wantStatus := store.OutcomeAccepted
	wantCode := string(reducer.CodeAccepted)

	switch slot {
	case 0:
		command.Kind = event.KindTaskCreated
		command.EntityID = event.StringEntityID(string(taskA))
		command.Payload = encoder.encode(map[string]any{
			"priority": 2,
			"title":    fmt.Sprintf("benchmark task %04d-a", block),
		})
	case 1:
		command = growthTaskMutation(
			command,
			event.KindTaskUpdated,
			taskA,
			1,
			map[string]any{"body": "bounded benchmark work item"},
			encoder,
		)
	case 2:
		command.Kind = event.KindLeaseAcquired
		command.EntityID = event.StringEntityID(string(leaseA))
		command.Payload = encoder.encode(map[string]any{
			"path_globs": []string{
				fmt.Sprintf("src/benchmark/%04d/a/**", block),
			},
			"scope":       lease.ScopePath,
			"task_id":     taskA,
			"ttl_seconds": 900,
		})
	case 3:
		command = growthActivity(
			command,
			taskA,
			event.ActionFileRead,
			fmt.Sprintf("src/benchmark/task-%04d-a.go", block),
			"inspect task input",
			encoder,
		)
	case 4:
		command = growthLeaseMutation(
			command,
			event.KindLeaseRenewed,
			leaseA,
			1,
			map[string]any{"ttl_seconds": 900},
			encoder,
		)
	case 5:
		command = growthTaskMutation(
			command,
			event.KindTaskUpdated,
			taskA,
			2,
			map[string]any{"priority": 3},
			encoder,
		)
	case 6:
		command = growthActivity(
			command,
			taskA,
			event.ActionTestRun,
			"phase3-coordination-workload",
			"verify task result",
			encoder,
		)
	case 7:
		command = growthLeaseMutation(
			command,
			event.KindLeaseReleased,
			leaseA,
			2,
			map[string]any{"release_reason": lease.ReleaseVoluntary},
			encoder,
		)
	case 8:
		command = growthTaskMutation(
			command,
			event.KindTaskUpdated,
			taskA,
			3,
			map[string]any{
				"title": fmt.Sprintf("reviewed benchmark task %04d-a", block),
			},
			encoder,
		)
	case 9:
		command = growthActivity(
			command,
			taskA,
			event.ActionDecisionRecorded,
			"task-triage",
			"record task disposition",
			encoder,
		)
	case 10:
		command.Kind = event.KindTaskCreated
		command.EntityID = event.StringEntityID(string(taskB))
		command.Payload = encoder.encode(map[string]any{
			"priority": 1,
			"title":    fmt.Sprintf("benchmark task %04d-b", block),
		})
	case 11:
		command = growthTaskMutation(
			command,
			event.KindTaskUpdated,
			taskB,
			1,
			map[string]any{"body": "bounded benchmark follow-up"},
			encoder,
		)
	case 12:
		command.Kind = event.KindLeaseAcquired
		command.EntityID = event.StringEntityID(string(leaseB))
		command.Payload = encoder.encode(map[string]any{
			"path_globs": []string{
				fmt.Sprintf("src/benchmark/%04d/b/**", block),
			},
			"scope":       lease.ScopePath,
			"task_id":     taskB,
			"ttl_seconds": 900,
		})
	case 13:
		command = growthActivity(
			command,
			taskB,
			event.ActionFileEdit,
			fmt.Sprintf("src/benchmark/task-%04d-b.go", block),
			"edit task output",
			encoder,
		)
	case 14:
		command = growthLeaseMutation(
			command,
			event.KindLeaseRenewed,
			leaseB,
			1,
			map[string]any{"ttl_seconds": 900},
			encoder,
		)
	case 15:
		command = growthTaskMutation(
			command,
			event.KindTaskUpdated,
			taskB,
			2,
			map[string]any{"priority": 2},
			encoder,
		)
	case 16:
		command = growthActivity(
			command,
			taskB,
			event.ActionCommandRun,
			"go",
			"format task output",
			encoder,
		)
	case 17:
		command = growthLeaseMutation(
			command,
			event.KindLeaseReleased,
			leaseB,
			2,
			map[string]any{"release_reason": lease.ReleaseVoluntary},
			encoder,
		)
	case 18:
		command = growthTaskMutation(
			command,
			event.KindTaskUpdated,
			taskB,
			3,
			map[string]any{
				"title": fmt.Sprintf("reviewed benchmark task %04d-b", block),
			},
			encoder,
		)
	case 19:
		command = growthTaskMutation(
			command,
			event.KindTaskUpdated,
			taskB,
			3,
			map[string]any{"title": "stale benchmark update"},
			encoder,
		)
		wantStatus = store.OutcomeRejected
		wantCode = string(reducer.CodeEntityVersionMismatch)
	default:
		return growthCommand{}, fmt.Errorf("invalid workload slot %d", slot)
	}
	if encoder.err != nil {
		return growthCommand{}, encoder.err
	}

	eventID := benchmarkUUID(0x20, uint64(index+1))
	requestID := benchmarkUUID(0x21, uint64(index+1))
	createdAt := domain.Timestamp(
		growthBaseTime.
			Add(time.Duration(index+1) * time.Millisecond).
			Format(time.RFC3339Nano),
	)
	proposal, err := event.BuildProposal(
		command,
		fixture.binding,
		event.BuildContext{
			EventID:        eventID,
			SessionID:      growthSessionID,
			WorkspaceID:    growthWorkspaceID,
			CreatedAt:      createdAt,
			OriginSequence: uint64(index + 2),
		},
	)
	if err != nil {
		return growthCommand{}, err
	}
	signed, err := event.Sign(proposal, fixture.private)
	if err != nil {
		return growthCommand{}, err
	}
	canonicalRequest, err := canonicalGrowthLocalRequest(
		signed,
		requestID,
		command,
	)
	if err != nil {
		return growthCommand{}, err
	}
	return growthCommand{
		command:          command,
		clientInstanceID: growthClientInstanceID,
		requestID:        requestID,
		eventID:          eventID,
		createdAt:        createdAt,
		canonicalRequest: canonicalRequest,
		signed:           signed,
		wantStatus:       wantStatus,
		wantCode:         wantCode,
	}, nil
}

func canonicalGrowthLocalRequest(
	signed event.SignedEvent,
	requestID domain.UUIDv7,
	wantCommand event.Command,
) ([]byte, error) {
	var proposalMembers map[string]json.RawMessage
	if err := json.Unmarshal(
		signed.CanonicalBytes(),
		&proposalMembers,
	); err != nil {
		return nil, fmt.Errorf(
			"phase3bench: decode signed proposal for local request: %w",
			err,
		)
	}
	commandMembers := make(map[string]json.RawMessage, 7)
	for _, field := range []string{
		"kind",
		"entity_id",
		"rationale_summary",
		"actions",
		"payload",
		"redaction",
	} {
		value, exists := proposalMembers[field]
		if !exists {
			return nil, fmt.Errorf(
				"phase3bench: signed proposal lacks %q",
				field,
			)
		}
		commandMembers[field] = value
	}
	if value, exists := proposalMembers["expected_entity_version"]; exists {
		commandMembers["expected_entity_version"] = value
	}
	commandJSON, err := json.Marshal(commandMembers)
	if err != nil {
		return nil, fmt.Errorf(
			"phase3bench: encode local command: %w",
			err,
		)
	}
	raw, err := json.Marshal(map[string]any{
		"command":    json.RawMessage(commandJSON),
		"operation":  string(wantCommand.Kind),
		"request_id": requestID,
	})
	if err != nil {
		return nil, fmt.Errorf(
			"phase3bench: encode local request: %w",
			err,
		)
	}
	canonical, err := codec.CanonicalizeSignedObject(raw)
	if err != nil {
		return nil, fmt.Errorf(
			"phase3bench: canonicalize local request: %w",
			err,
		)
	}
	decoded, err := localcommand.Decode(canonical)
	if err != nil {
		return nil, fmt.Errorf(
			"phase3bench: verify canonical local request: %w",
			err,
		)
	}
	if decoded.RequestID != requestID ||
		decoded.Operation != string(wantCommand.Kind) ||
		!reflect.DeepEqual(decoded.Command, wantCommand) {
		return nil, fmt.Errorf(
			"phase3bench: canonical local request changed its command",
		)
	}
	return canonical, nil
}

func growthTaskMutation(
	command event.Command,
	kind event.Kind,
	id domain.UUIDv7,
	version uint64,
	payload map[string]any,
	encoder *growthJSONEncoder,
) event.Command {
	command.Kind = kind
	command.EntityID = event.StringEntityID(string(id))
	command.ExpectedEntityVersion = &version
	command.Payload = encoder.encode(payload)
	return command
}

func growthLeaseMutation(
	command event.Command,
	kind event.Kind,
	id domain.UUIDv7,
	version uint64,
	payload map[string]any,
	encoder *growthJSONEncoder,
) event.Command {
	return growthTaskMutation(command, kind, id, version, payload, encoder)
}

func growthActivity(
	command event.Command,
	taskID domain.UUIDv7,
	actionType event.ActionType,
	target string,
	summary string,
	encoder *growthJSONEncoder,
) event.Command {
	command.Kind = event.KindActivityRecorded
	command.EntityID = event.NullEntityID()
	command.RationaleSummary = summary
	command.Actions = []event.Action{{
		Type:    actionType,
		Target:  target,
		Summary: summary,
		Status:  event.ActionSucceeded,
		TaskID:  &taskID,
	}}
	command.Payload = encoder.encode(map[string]any{"task_id": taskID})
	return command
}

func growthAgentStart(fixture growthFixture) (event.SignedEvent, error) {
	payload, err := json.Marshal(map[string]any{
		"client_kind":     agentsession.ClientKindCodex,
		"working_root_id": growthWorkingRootID,
	})
	if err != nil {
		return event.SignedEvent{}, fmt.Errorf(
			"phase3bench: encode seed agent session: %w",
			err,
		)
	}
	proposal, err := event.BuildProposal(
		event.Command{
			Kind:     event.KindAgentSessionStarted,
			EntityID: event.StringEntityID(string(growthAgentID)),
			Actions:  []event.Action{},
			Payload:  payload,
			Redaction: event.Redaction{
				Policy:        event.RedactionDefault,
				FieldsRemoved: []event.RedactionField{},
			},
		},
		fixture.binding,
		event.BuildContext{
			EventID:        benchmarkUUID(0x10, 1),
			SessionID:      growthSessionID,
			WorkspaceID:    growthWorkspaceID,
			CreatedAt:      domain.Timestamp(growthBaseTime.Add(-time.Second).Format(time.RFC3339)),
			OriginSequence: 1,
		},
	)
	if err != nil {
		return event.SignedEvent{}, fmt.Errorf(
			"phase3bench: build seed agent session: %w",
			err,
		)
	}
	signed, err := event.Sign(proposal, fixture.private)
	if err != nil {
		return event.SignedEvent{}, fmt.Errorf(
			"phase3bench: sign seed agent session: %w",
			err,
		)
	}
	return signed, nil
}

func canonicalGrowthLaunchRequest() ([]byte, error) {
	raw, err := json.Marshal(map[string]any{
		"client_instance_id": growthClientInstanceID,
		"launch_id":          growthLaunchID,
		"operation":          event.KindAgentSessionStarted,
	})
	if err != nil {
		return nil, fmt.Errorf(
			"phase3bench: encode baseline launch request: %w",
			err,
		)
	}
	canonical, err := codec.CanonicalizeSignedObject(raw)
	if err != nil {
		return nil, fmt.Errorf(
			"phase3bench: canonicalize baseline launch request: %w",
			err,
		)
	}
	return canonical, nil
}

func newGrowthFixture() (growthFixture, error) {
	private := ed25519.NewKeyFromSeed(
		bytes.Repeat([]byte{0x5b}, ed25519.SeedSize),
	)
	public := append(
		ed25519.PublicKey(nil),
		private.Public().(ed25519.PublicKey)...,
	)
	deviceID, err := device.DeriveID(public)
	if err != nil {
		return growthFixture{}, err
	}
	binding, err := event.NewMCPBinding(deviceID, growthAgentID, nil)
	if err != nil {
		return growthFixture{}, err
	}
	voterSet, err := voterset.New(
		growthSessionID,
		[]domain.DeviceID{deviceID},
		1,
	)
	if err != nil {
		return growthFixture{}, err
	}
	recoveryPrivate := ed25519.NewKeyFromSeed(
		bytes.Repeat([]byte{0x6c}, ed25519.SeedSize),
	)
	defer clear(recoveryPrivate)
	rawGenesis, err := json.Marshal(map[string]any{
		"recovery_generation": uint64(0),
		"recovery_public_key": codec.EncodeBase64URL(
			recoveryPrivate.Public().(ed25519.PublicKey),
		),
		"session_id":   growthSessionID,
		"workspace_id": growthWorkspaceID,
	})
	if err != nil {
		return growthFixture{}, err
	}
	genesisJSON, err := codec.CanonicalizeSignedObject(rawGenesis)
	if err != nil {
		return growthFixture{}, err
	}
	initial := store.InitialState{
		SessionID:               growthSessionID,
		WorkspaceID:             growthWorkspaceID,
		GenesisJSON:             genesisJSON,
		DigestVersion:           1,
		ProjectionSchemaVersion: 1,
		Projections: store.ProjectionWrites{
			AuditCounters: []auditcounter.Counter{{DeviceID: deviceID}},
			PlanCurrent: []plan.Current{{
				SessionID:     growthSessionID,
				EntityVersion: 1,
			}},
			Devices: []device.Device{{
				ID:                deviceID,
				Role:              device.RoleOwner,
				IdentityPublicKey: public,
				DaemonVersion:     "0.1.0",
				MaxApplyLevel:     event.MaxSupportedApplyLevel,
				Status:            device.StatusActive,
				EntityVersion:     1,
			}},
			VoterSet: []voterset.Set{voterSet},
			CredentialAuthority: []store.CredentialAuthorityRow{{
				SessionID:        growthSessionID,
				VoterDeviceIDs:   []domain.DeviceID{deviceID},
				VoterSetVersion:  1,
				ActivationSource: credentialauthority.ActivationGenesis,
			}},
			CanonicalRefs: []publication.CanonicalRef{{
				RefName:       publication.CanonicalRefName,
				CommitOID:     domain.GitOID("sha1:" + strings.Repeat("1", 40)),
				EntityVersion: 1,
			}},
			SessionPolicy: []policy.Policy{{
				SessionID:     growthSessionID,
				Values:        policy.DefaultValues(),
				EntityVersion: 1,
			}},
		},
	}
	return growthFixture{
		private:  private,
		deviceID: deviceID,
		binding:  binding,
		initial:  initial,
	}, nil
}

func forceGrowthCheckpoint(
	ctx context.Context,
	node *consensus.SingleNode,
	local store.LocalState,
	ids *growthCheckpointIDs,
	ordinal int,
) error {
	if ids == nil ||
		ordinal < 1 ||
		ordinal > growthCheckpointCount ||
		ids.consumed() != (ordinal-1)*2 {
		return fmt.Errorf(
			"phase3bench: invalid checkpoint cadence at ordinal %d",
			ordinal,
		)
	}
	checkpoint, err := node.ForceCheckpoint(ctx)
	if err != nil {
		return fmt.Errorf(
			"phase3bench: force checkpoint %d: %w",
			ordinal,
			err,
		)
	}
	wantEventID := growthCheckpointEventID(ordinal)
	if checkpoint.Record.CheckpointEventID != wantEventID ||
		ids.consumed() != ordinal*2 {
		return fmt.Errorf(
			"phase3bench: checkpoint %d used event %q after %d generated IDs",
			ordinal,
			checkpoint.Record.CheckpointEventID,
			ids.consumed(),
		)
	}
	record, found, err := local.LookupRequest(
		ctx,
		growthTraceBootID,
		growthCheckpointRequestID(ordinal),
	)
	if err != nil ||
		!found ||
		record.State != store.LocalRequestResolved ||
		record.EventID != wantEventID ||
		record.RequestKind != event.KindConsensusCheckpoint ||
		record.Outcome == nil ||
		record.Outcome.Status != store.OutcomeAccepted ||
		record.Outcome.Code != string(reducer.CodeAccepted) {
		return fmt.Errorf(
			"phase3bench: checkpoint request %d is not durably resolved: found=%t err=%v",
			ordinal,
			found,
			err,
		)
	}
	return nil
}

func newGrowthCheckpointIDs() *growthCheckpointIDs {
	values := make([]domain.UUIDv7, 0, growthCheckpointCount*2)
	for ordinal := 1; ordinal <= growthCheckpointCount; ordinal++ {
		values = append(
			values,
			growthCheckpointRequestID(ordinal),
			growthCheckpointEventID(ordinal),
		)
	}
	return &growthCheckpointIDs{values: values}
}

func (ids *growthCheckpointIDs) generate() (domain.UUIDv7, error) {
	if ids == nil {
		return "", fmt.Errorf("phase3bench: nil checkpoint ID source")
	}
	ids.mu.Lock()
	defer ids.mu.Unlock()
	if ids.next >= len(ids.values) {
		return "", fmt.Errorf(
			"phase3bench: checkpoint ID source exhausted after %d values",
			ids.next,
		)
	}
	value := ids.values[ids.next]
	ids.next++
	return value, nil
}

func (ids *growthCheckpointIDs) consumed() int {
	if ids == nil {
		return 0
	}
	ids.mu.Lock()
	defer ids.mu.Unlock()
	return ids.next
}

func growthCheckpointRequestID(ordinal int) domain.UUIDv7 {
	return benchmarkUUID(0x70, uint64(ordinal))
}

func growthCheckpointEventID(ordinal int) domain.UUIDv7 {
	return benchmarkUUID(0x71, uint64(ordinal))
}

func requireEmptyOutbox(
	ctx context.Context,
	local store.LocalState,
) error {
	records, err := local.OutboxRecords(ctx)
	if err != nil {
		return fmt.Errorf("phase3bench: inspect final outbox: %w", err)
	}
	if len(records) != 0 {
		return fmt.Errorf(
			"phase3bench: final outbox contains %d records",
			len(records),
		)
	}
	return nil
}

func verifyGrowthReopen(
	ctx context.Context,
	fixture growthFixture,
	statePath string,
	consensusDir string,
	expectedView store.StateView,
	contract CoordinationGrowthContract,
	expectations []growthRequestExpectation,
) error {
	runtimeState, _, err := openGrowthNode(
		ctx,
		fixture,
		statePath,
		consensusDir,
		growthReopenBootID,
		nil,
		false,
	)
	if err != nil {
		return fmt.Errorf("phase3bench: reopen integrity check: %w", err)
	}
	closed := false
	defer func() {
		if !closed {
			_ = runtimeState.close()
		}
	}()
	reopenedView, err := runtimeState.node.View(ctx)
	if err != nil {
		return fmt.Errorf("phase3bench: inspect reopened view: %w", err)
	}
	if reopenedView.Heads != expectedView.Heads ||
		reopenedView.ProjectionStateDigest !=
			expectedView.ProjectionStateDigest {
		return fmt.Errorf(
			"phase3bench: reopened commitments differ from the measured cut",
		)
	}
	if err := validateGrowthView(
		reopenedView,
		contract,
		growthCheckpointCount,
	); err != nil {
		return err
	}
	if len(expectations) != CoordinationGrowthEventCount {
		return fmt.Errorf(
			"phase3bench: reopen audit has %d workload expectations",
			len(expectations),
		)
	}
	local, err := runtimeState.node.LocalState()
	if err != nil {
		return fmt.Errorf(
			"phase3bench: acquire reopened local state: %w",
			err,
		)
	}
	for index, want := range expectations {
		record, found, err := local.LookupRequest(
			ctx,
			want.clientInstanceID,
			want.requestID,
		)
		if err != nil ||
			!found ||
			record.State != store.LocalRequestResolved ||
			record.EventID != want.eventID ||
			record.RequestKind != want.requestKind ||
			record.RequestDigest != want.requestDigest ||
			record.Outcome == nil ||
			!sameGrowthOutcome(*record.Outcome, want.outcome) {
			return fmt.Errorf(
				"phase3bench: reopened workload request %d differs: found=%t err=%v",
				index+1,
				found,
				err,
			)
		}
	}
	for ordinal := 1; ordinal <= growthCheckpointCount; ordinal++ {
		record, found, err := local.LookupRequest(
			ctx,
			growthTraceBootID,
			growthCheckpointRequestID(ordinal),
		)
		if err != nil ||
			!found ||
			record.State != store.LocalRequestResolved ||
			record.EventID != growthCheckpointEventID(ordinal) ||
			record.RequestKind != event.KindConsensusCheckpoint ||
			record.Outcome == nil ||
			record.Outcome.Status != store.OutcomeAccepted ||
			record.Outcome.Code != string(reducer.CodeAccepted) {
			return fmt.Errorf(
				"phase3bench: reopened checkpoint request %d differs: found=%t err=%v",
				ordinal,
				found,
				err,
			)
		}
	}
	if err := requireEmptyOutbox(ctx, local); err != nil {
		return err
	}
	if err := runtimeState.close(); err != nil {
		return fmt.Errorf("phase3bench: close reopened node: %w", err)
	}
	closed = true
	if err := verifyGrowthActivityCount(ctx, statePath); err != nil {
		return err
	}
	reopenedStore, err := store.Open(ctx, store.Options{Path: statePath})
	if err != nil {
		return fmt.Errorf(
			"phase3bench: reopen store for commitment scrub: %w",
			err,
		)
	}
	if err := reopenedStore.VerifyCommitmentHistory(ctx); err != nil {
		_ = reopenedStore.Close()
		return fmt.Errorf(
			"phase3bench: verify commitment history after reopen: %w",
			err,
		)
	}
	if err := reopenedStore.Close(); err != nil {
		return fmt.Errorf(
			"phase3bench: close commitment scrub store: %w",
			err,
		)
	}
	return nil
}

func cloneGrowthOutcome(outcome store.CommandOutcome) store.CommandOutcome {
	outcome.JSON = bytes.Clone(outcome.JSON)
	return outcome
}

func sameGrowthOutcome(
	left store.CommandOutcome,
	right store.CommandOutcome,
) bool {
	return left.Status == right.Status &&
		left.Code == right.Code &&
		bytes.Equal(left.JSON, right.JSON)
}

func cloneGrowthHistogram(input map[string]int) map[string]int {
	result := make(map[string]int, len(input))
	for key, value := range input {
		result[key] = value
	}
	return result
}

func validateGrowthView(
	view store.StateView,
	contract CoordinationGrowthContract,
	checkpointCount int,
) error {
	wantResults := uint64(contract.EventCount + checkpointCount + 1)
	wantChain := uint64(contract.AcceptedCount + checkpointCount + 1)
	if view.Heads.ResultIndex != wantResults ||
		view.Heads.ChainIndex != wantChain {
		return fmt.Errorf(
			"phase3bench: final heads = (result %d, chain %d), want (%d, %d)",
			view.Heads.ResultIndex,
			view.Heads.ChainIndex,
			wantResults,
			wantChain,
		)
	}
	counts := make(map[string]int)
	for _, row := range view.ProjectionRows {
		counts[row.Table]++
	}
	const (
		wantTasks  = CoordinationGrowthEventCount / growthBlockSize * 2
		wantLeases = CoordinationGrowthEventCount / growthBlockSize * 2
	)
	for table, want := range map[string]int{
		"tasks":  wantTasks,
		"leases": wantLeases,
	} {
		if counts[table] != want {
			return fmt.Errorf(
				"phase3bench: %s rows = %d, want %d",
				table,
				counts[table],
				want,
			)
		}
	}
	return nil
}

func verifyGrowthActivityCount(
	ctx context.Context,
	statePath string,
) error {
	if ctx == nil {
		return fmt.Errorf("phase3bench: nil activity-count context")
	}
	conn, err := sqlite.OpenConn(
		statePath,
		sqlite.OpenReadOnly|sqlite.OpenPrivateCache,
	)
	if err != nil {
		return fmt.Errorf(
			"phase3bench: open activity-count database: %w",
			err,
		)
	}
	defer conn.Close()
	conn.SetInterrupt(ctx.Done())
	statement, _, err := conn.PrepareTransient(
		"SELECT count(*) FROM activity;",
	)
	if err != nil {
		return fmt.Errorf(
			"phase3bench: prepare activity count: %w",
			err,
		)
	}
	defer statement.Finalize()
	row, err := statement.Step()
	if err != nil {
		return fmt.Errorf("phase3bench: read activity count: %w", err)
	}
	const want = CoordinationGrowthEventCount / growthBlockSize * 5
	if !row || statement.ColumnInt64(0) != want {
		return fmt.Errorf(
			"phase3bench: activity rows = %d, want %d",
			statement.ColumnInt64(0),
			want,
		)
	}
	if row, err := statement.Step(); err != nil || row {
		return fmt.Errorf(
			"phase3bench: activity count returned multiple rows: row=%t err=%v",
			row,
			err,
		)
	}
	return nil
}

func measureStorage(
	statePath string,
	consensusDir string,
) (StorageBytes, error) {
	var result StorageBytes
	stateDir := filepath.Dir(statePath)
	stateBase := filepath.Base(statePath)
	entries, err := os.ReadDir(stateDir)
	if err != nil {
		return StorageBytes{}, fmt.Errorf(
			"phase3bench: read state directory: %w",
			err,
		)
	}
	for _, entry := range entries {
		if entry.Name() != stateBase &&
			entry.Name() != stateBase+"-wal" &&
			entry.Name() != stateBase+"-shm" {
			continue
		}
		if entry.Type()&os.ModeSymlink != 0 {
			return StorageBytes{}, fmt.Errorf(
				"phase3bench: state file %q is a symlink",
				entry.Name(),
			)
		}
		info, err := entry.Info()
		if err != nil {
			return StorageBytes{}, fmt.Errorf(
				"phase3bench: inspect state file %q: %w",
				entry.Name(),
				err,
			)
		}
		if !info.Mode().IsRegular() {
			return StorageBytes{}, fmt.Errorf(
				"phase3bench: state file %q is not regular",
				entry.Name(),
			)
		}
		switch entry.Name() {
		case stateBase:
			result.StateDB = info.Size()
		case stateBase + "-wal":
			result.StateWAL = info.Size()
		case stateBase + "-shm":
			result.StateSHM = info.Size()
		}
	}
	if result.StateDB == 0 {
		return StorageBytes{}, fmt.Errorf(
			"phase3bench: state database is absent",
		)
	}
	err = filepath.WalkDir(
		consensusDir,
		func(path string, entry fs.DirEntry, walkErr error) error {
			if walkErr != nil {
				return walkErr
			}
			if entry.Type()&os.ModeSymlink != 0 {
				return fmt.Errorf(
					"phase3bench: consensus path %q is a symlink",
					path,
				)
			}
			if entry.IsDir() {
				return nil
			}
			info, err := entry.Info()
			if err != nil {
				return err
			}
			if !info.Mode().IsRegular() {
				return fmt.Errorf(
					"phase3bench: consensus path %q is not regular",
					path,
				)
			}
			result.Consensus += info.Size()
			result.ConsensusFiles++
			return nil
		},
	)
	if err != nil {
		return StorageBytes{}, fmt.Errorf(
			"phase3bench: measure consensus storage: %w",
			err,
		)
	}
	if result.ConsensusFiles == 0 {
		return StorageBytes{}, fmt.Errorf(
			"phase3bench: consensus storage is absent",
		)
	}
	result.Total = result.StateDB +
		result.StateWAL +
		result.StateSHM +
		result.Consensus
	return result, nil
}

func requireEmptyDirectory(root string) error {
	if root == "" || !filepath.IsAbs(root) {
		return fmt.Errorf(
			"phase3bench: root must be a nonempty absolute path",
		)
	}
	info, err := os.Lstat(root)
	if err != nil {
		return fmt.Errorf("phase3bench: inspect root: %w", err)
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("phase3bench: root must be a real directory")
	}
	entries, err := os.ReadDir(root)
	if err != nil {
		return fmt.Errorf("phase3bench: read root: %w", err)
	}
	if len(entries) != 0 {
		return fmt.Errorf("phase3bench: root must be empty")
	}
	return nil
}

func growthApplyClock() consensus.ApplyClock {
	var calls atomic.Int64
	return func() (domain.Timestamp, int64, error) {
		call := calls.Add(1)
		at := growthBaseTime.Add(time.Duration(call) * time.Millisecond)
		return domain.Timestamp(at.Format(time.RFC3339Nano)),
			call * int64(time.Millisecond),
			nil
	}
}

func growthCheckpointClock() agent.Clock {
	var calls atomic.Int64
	return func() domain.Timestamp {
		call := calls.Add(1)
		return domain.Timestamp(
			growthBaseTime.
				Add(time.Duration(call) * time.Millisecond).
				Format(time.RFC3339Nano),
		)
	}
}

func growthRaftConfig() *raft.Config {
	config := raft.DefaultConfig()
	config.HeartbeatTimeout = 500 * time.Millisecond
	config.ElectionTimeout = 500 * time.Millisecond
	config.CommitTimeout = 10 * time.Millisecond
	config.LeaderLeaseTimeout = 250 * time.Millisecond
	config.SnapshotInterval = 100 * 365 * 24 * time.Hour
	config.SnapshotThreshold = math.MaxUint64
	config.TrailingLogs = 32
	config.LogLevel = "ERROR"
	return config
}

func (encoder *growthJSONEncoder) encode(value any) []byte {
	if encoder == nil || encoder.err != nil {
		return nil
	}
	var encoded []byte
	encoded, encoder.err = json.Marshal(value)
	return encoded
}

func benchmarkUUID(namespace uint16, sequence uint64) domain.UUIDv7 {
	return domain.UUIDv7(fmt.Sprintf(
		"019b17cc-%04x-7%03x-8%03x-%012x",
		namespace,
		namespace&0x0fff,
		namespace&0x0fff,
		sequence,
	))
}
