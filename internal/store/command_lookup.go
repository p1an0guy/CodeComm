package store

import (
	"bytes"
	"context"
	"fmt"

	"github.com/ijonahch/codecomm/internal/domain"
	"zombiezen.com/go/sqlite"
	"zombiezen.com/go/sqlite/sqlitex"
)

// CommandResultTuple is the immutable result-chain position of one first-seen
// command. ChainIndex and ChainHash are both nil for a rejected command.
type CommandResultTuple struct {
	ResultIndex        uint64
	PreviousResultHash Digest
	ResultHash         Digest
	ChainIndex         *uint64
	ChainHash          *Digest
}

// CommandResultLookup is an integrity-verified command result and the current
// store heads observed in the same SQLite read transaction. Callers own all
// returned memory.
type CommandResultLookup struct {
	EventID            domain.UUIDv7
	SessionID          domain.UUIDv7
	RecoveryGeneration uint64
	CanonicalProposal  []byte
	ProposalDigest     Digest
	Outcome            CommandOutcome
	Tuple              CommandResultTuple
	CurrentHeads       ApplyHeads
}

// LookupCommandResult returns the immutable first-seen result for eventID.
// A miss returns the zero value and found=false. The lookup never advances the
// Raft watermark or otherwise writes store state.
func (store *Store) LookupCommandResult(
	ctx context.Context,
	eventID domain.UUIDv7,
) (CommandResultLookup, bool, error) {
	if ctx == nil {
		return CommandResultLookup{}, false, fmt.Errorf(
			"%w: nil context",
			ErrInvalidOptions,
		)
	}
	if err := ctx.Err(); err != nil {
		return CommandResultLookup{}, false, err
	}
	if !eventID.Valid() {
		return CommandResultLookup{}, false, fmt.Errorf(
			"%w: invalid event ID",
			ErrInvalidOptions,
		)
	}

	var (
		lookup CommandResultLookup
		found  bool
	)
	err := store.withConn(ctx, func(conn *sqlite.Conn) (err error) {
		previousInterrupt := conn.SetInterrupt(ctx.Done())
		defer conn.SetInterrupt(previousInterrupt)

		end := sqlitex.Transaction(conn)
		defer end(&err)

		stored, exists, err := readStoredCommandResult(conn, eventID)
		if err != nil {
			return err
		}
		if !exists {
			return nil
		}
		if err := verifyStoredCommandResult(conn, stored); err != nil {
			return err
		}

		state, hasState, err := readConsensusState(conn)
		if err != nil {
			return err
		}
		if !hasState {
			return fmt.Errorf(
				"%w: command result exists without consensus state",
				ErrCommandResultCorrupt,
			)
		}
		heads := headsFromConsensus(state)
		if err := validateLookupHeads(state, stored, heads); err != nil {
			return err
		}

		lookup = cloneCommandResultLookup(stored, heads)
		found = true
		return nil
	})
	if err != nil {
		return CommandResultLookup{}, false, err
	}
	return lookup, found, nil
}

func validateLookupHeads(
	state consensusState,
	stored storedCommandResult,
	heads ApplyHeads,
) error {
	if !state.sessionID.Valid() ||
		!domain.ValidUnsignedInteger(state.recoveryGeneration) ||
		state.chainIndex > state.resultIndex ||
		state.resultIndex < stored.resultIndex {
		return fmt.Errorf(
			"%w: current consensus state does not cover command result",
			ErrCommandResultCorrupt,
		)
	}
	if stored.chainIndex != nil && state.chainIndex < *stored.chainIndex {
		return fmt.Errorf(
			"%w: current event head does not cover command result",
			ErrCommandResultCorrupt,
		)
	}
	if err := heads.validate(); err != nil {
		return fmt.Errorf(
			"%w: invalid current heads: %v",
			ErrCommandResultCorrupt,
			err,
		)
	}
	return nil
}

func cloneCommandResultLookup(
	stored storedCommandResult,
	currentHeads ApplyHeads,
) CommandResultLookup {
	lookup := CommandResultLookup{
		EventID:            stored.eventID,
		SessionID:          stored.sessionID,
		RecoveryGeneration: stored.recoveryGeneration,
		CanonicalProposal:  bytes.Clone(stored.proposalJSON),
		ProposalDigest:     stored.proposalDigest,
		Outcome: CommandOutcome{
			Status: stored.outcome.Status,
			Code:   stored.outcome.Code,
			JSON:   bytes.Clone(stored.outcome.JSON),
		},
		Tuple: CommandResultTuple{
			ResultIndex:        stored.resultIndex,
			PreviousResultHash: stored.previousResultHash,
			ResultHash:         stored.resultHash,
		},
		CurrentHeads: currentHeads,
	}
	if stored.chainIndex != nil {
		value := *stored.chainIndex
		lookup.Tuple.ChainIndex = &value
	}
	if stored.chainHash != nil {
		value := *stored.chainHash
		lookup.Tuple.ChainHash = &value
	}
	return lookup
}
