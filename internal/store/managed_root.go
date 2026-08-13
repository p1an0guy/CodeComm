package store

import (
	"context"

	"github.com/ijonahch/codecomm/internal/domain"
	"zombiezen.com/go/sqlite"
)

// CurrentRecoveryGeneration returns the active generation only when the
// caller's session and workspace match the durable local lineage.
func (state LocalState) CurrentRecoveryGeneration(
	ctx context.Context,
	sessionID domain.UUIDv7,
	workspaceID domain.UUIDv4,
) (uint64, error) {
	if !sessionID.Valid() || !workspaceID.Valid() {
		return 0, ErrInvalidLocalState
	}
	var generation uint64
	err := state.withImmediate(ctx, func(conn *sqlite.Conn) error {
		lineage, err := readLocalLineage(conn)
		if err != nil {
			return err
		}
		if !lineage.matches(sessionID, workspaceID) {
			return ErrLocalLineageMismatch
		}
		generation = lineage.recoveryGeneration
		return nil
	})
	if err != nil {
		return 0, err
	}
	return generation, nil
}
