package reducer

import (
	"crypto/sha256"
	"errors"

	"github.com/ijonahch/codecomm/internal/domain"
)

const CodeStaleCheckpoint Code = "stale_checkpoint"

var ErrCheckpointIntegrityMismatch = errors.New(
	"reducer: checkpoint does not match local committed heads",
)

// CheckpointApplyContext is the local state immediately before applying the
// checkpoint command. It is supplied by the FSM/chain layer, not signed by the
// event origin and not retained as reducer projection state.
type CheckpointApplyContext struct {
	Term                    uint64
	LogIndex                uint64
	ChainIndex              uint64
	ChainHash               [sha256.Size]byte
	ResultIndex             uint64
	ResultHash              [sha256.Size]byte
	ProjectionAccumulator   [sha256.Size]byte
	DigestVersion           uint64
	ProjectionSchemaVersion uint64
}

func (context CheckpointApplyContext) validate() error {
	if context.Term < 1 ||
		context.LogIndex < 2 ||
		context.DigestVersion != checkpointDigestVersion ||
		context.ProjectionSchemaVersion !=
			checkpointProjectionSchemaVersion ||
		!domain.ValidUnsignedInteger(context.Term) ||
		!domain.ValidUnsignedInteger(context.LogIndex) ||
		!domain.ValidUnsignedInteger(context.ChainIndex) ||
		!domain.ValidUnsignedInteger(context.ResultIndex) ||
		context.ChainIndex > context.ResultIndex {
		return invalidState("invalid checkpoint apply context")
	}
	return nil
}

func validateCheckpointAtApply(
	directive CheckpointDirective,
	context CheckpointApplyContext,
) (Code, error) {
	if err := context.validate(); err != nil {
		return "", err
	}
	if err := directive.Checkpoint.Validate(); err != nil {
		return "", invalidState("invalid checkpoint directive: %v", err)
	}
	checkpoint := directive.Checkpoint
	if checkpoint.Term != context.Term ||
		checkpoint.CoveredAppliedLogIndex != context.LogIndex-1 {
		return CodeStaleCheckpoint, nil
	}
	if checkpoint.CoveredChainIndex != context.ChainIndex ||
		checkpoint.CoveredChainHash != context.ChainHash ||
		checkpoint.CoveredResultIndex != context.ResultIndex ||
		checkpoint.CoveredResultHash != context.ResultHash ||
		checkpoint.ProjectionAccumulator != context.ProjectionAccumulator ||
		checkpoint.DigestVersion != context.DigestVersion ||
		checkpoint.ProjectionSchemaVersion !=
			context.ProjectionSchemaVersion {
		return "", ErrCheckpointIntegrityMismatch
	}
	return "", nil
}
