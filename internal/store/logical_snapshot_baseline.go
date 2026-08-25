package store

import (
	"context"
	"fmt"

	"github.com/ijonahch/codecomm/internal/logicalsnapshot"
	"zombiezen.com/go/sqlite"
	"zombiezen.com/go/sqlite/sqlitex"
)

// HasVerifiedStandaloneLogicalSnapshotBaseline reports whether the active
// settled-nonvoter lineage starts from a fully reverified standalone snapshot.
// A true result is the only case in which settled startup may lack historical
// Raft configuration evidence.
func (store *Store) HasVerifiedStandaloneLogicalSnapshotBaseline(
	ctx context.Context,
) (bool, error) {
	_, found, err := store.VerifiedStandaloneLogicalSnapshotBaseline(ctx)
	return found, err
}

// VerifiedStandaloneLogicalSnapshotBaseline returns the exact signed root
// after revalidating the active settled lineage and all retained evidence.
func (store *Store) VerifiedStandaloneLogicalSnapshotBaseline(
	ctx context.Context,
) (logicalsnapshot.Root, bool, error) {
	if store == nil || ctx == nil {
		return logicalsnapshot.Root{}, false,
			fmt.Errorf(
				"%w: invalid snapshot baseline query",
				ErrInvalidOptions,
			)
	}
	if err := ctx.Err(); err != nil {
		return logicalsnapshot.Root{}, false, err
	}

	store.applyMu.Lock()
	defer store.applyMu.Unlock()
	var (
		root  logicalsnapshot.Root
		found bool
	)
	err := store.withConn(ctx, func(conn *sqlite.Conn) (err error) {
		previousInterrupt := conn.SetInterrupt(ctx.Done())
		defer conn.SetInterrupt(previousInterrupt)
		end := sqlitex.Transaction(conn)
		defer end(&err)

		state, active, err := readConsensusState(conn)
		if err != nil {
			return err
		}
		if !active {
			return ErrReplicaEvidenceMode
		}
		settled, active, err := readSettledNonvoterState(conn)
		if err != nil {
			return err
		}
		if !active {
			return nil
		}
		if err := verifyCommitmentHistory(conn, state); err != nil {
			return err
		}
		if err := verifySettledNonvoterEvidence(conn, state, settled); err != nil {
			return err
		}
		attestation, present, err :=
			readLogicalSnapshotAttestation(conn, state)
		if err != nil {
			return err
		}
		if present {
			root = attestation.root
			found = true
		}
		return err
	})
	if err != nil {
		return logicalsnapshot.Root{}, false, err
	}
	return root, found, nil
}
