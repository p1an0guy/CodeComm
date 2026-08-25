package logicalsnapshot

import (
	"github.com/ijonahch/codecomm/internal/chain"
	"github.com/ijonahch/codecomm/internal/domain"
)

// GenesisMetadata is a copy-safe, value-only view of the lineage metadata
// bound by one validated genesis payload. Predecessor fields and digest
// versions are zero for an initial genesis.
type GenesisMetadata struct {
	SessionID                        domain.UUIDv7
	WorkspaceID                      domain.UUIDv4
	RecoveryGeneration               uint64
	GenesisDigest                    chain.Digest
	HasPredecessor                   bool
	PredecessorGenesisDigest         chain.Digest
	PredecessorChainIndex            uint64
	PredecessorChainHash             chain.Digest
	PredecessorResultIndex           uint64
	PredecessorResultHash            chain.Digest
	PredecessorProjectionAccumulator chain.Digest
	BoundaryTransformDigest          chain.Digest
	DigestVersion                    uint64
	ProjectionSchemaVersion          uint64
}

// InspectGenesisPayload validates a decoded GenesisPayload and returns the
// signed genesis metadata needed to bind its generation boundary.
func InspectGenesisPayload(payload GenesisPayload) (GenesisMetadata, error) {
	encoded, err := EncodeGenesisPayload(payload)
	if err != nil {
		return GenesisMetadata{}, err
	}
	payload, err = DecodeGenesisPayload(encoded)
	if err != nil {
		return GenesisMetadata{}, err
	}
	metadata, err := inspectGenesis(payload.GenesisJSON)
	if err != nil {
		return GenesisMetadata{}, err
	}
	return GenesisMetadata{
		SessionID:                        metadata.sessionID,
		WorkspaceID:                      metadata.workspaceID,
		RecoveryGeneration:               metadata.generation,
		GenesisDigest:                    metadata.genesisDigest,
		HasPredecessor:                   metadata.hasPredecessor,
		PredecessorGenesisDigest:         metadata.predecessorGenesisDigest,
		PredecessorChainIndex:            metadata.predecessorChainIndex,
		PredecessorChainHash:             metadata.predecessorChainHash,
		PredecessorResultIndex:           metadata.predecessorResultIndex,
		PredecessorResultHash:            metadata.predecessorResultHash,
		PredecessorProjectionAccumulator: metadata.predecessorAccumulator,
		BoundaryTransformDigest:          payload.BoundaryTransformDigest,
		DigestVersion:                    metadata.digestVersion,
		ProjectionSchemaVersion:          metadata.projectionSchemaVersion,
	}, nil
}
