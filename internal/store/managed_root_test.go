package store

import (
	"context"
	"errors"
	"path/filepath"
	"testing"

	"github.com/ijonahch/codecomm/internal/domain"
	"zombiezen.com/go/sqlite"
)

func TestManagedRootRepositoryIdentityCollisionIsRejected(t *testing.T) {
	state, _, _ := newLocalStateFixture(t)
	first := ManagedRootRecord{
		ManagedRootID:      testManagedRootID,
		SessionID:          domain.UUIDv7(testSessionID),
		WorkspaceID:        testWorkspaceID,
		RecoveryGeneration: 0,
		CanonicalPath:      filepath.Join(t.TempDir(), "first-root"),
		FilesystemIdentity: "codecomm-directory-v1:unix:1:1",
		RepositoryIdentity: "codecomm-directory-v1:unix:2:2",
		Kind:               ManagedRootIsolated,
		GuardStatus:        RootGuardHealthy,
		Active:             true,
		LastVerifiedAt:     &testAppliedAt,
	}
	if err := state.RegisterManagedRoot(context.Background(), first); err != nil {
		t.Fatalf("RegisterManagedRoot(first): %v", err)
	}

	second := first
	second.ManagedRootID = domain.UUIDv7(
		"01890f47-3e72-7000-8000-000000000034",
	)
	second.CanonicalPath = filepath.Join(t.TempDir(), "second-root")
	second.FilesystemIdentity = "codecomm-directory-v1:unix:1:2"
	if err := state.RegisterManagedRoot(
		context.Background(),
		second,
	); !errors.Is(err, ErrManagedRootConflict) {
		t.Fatalf(
			"RegisterManagedRoot(repository collision) error = %v, want %v",
			err,
			ErrManagedRootConflict,
		)
	}

	err := state.withImmediate(context.Background(), func(conn *sqlite.Conn) error {
		return execute(
			conn,
			`INSERT INTO managed_roots(
			    managed_root_id, session_id, workspace_id, recovery_generation,
			    canonical_path, filesystem_identity, repository_identity,
			    root_kind, guard_status, active, last_verified_at
			) VALUES (?1, ?2, ?3, 0, ?4, ?5, ?6, 'shared', 'healthy', 1, ?7);`,
			"01890f47-3e72-7000-8000-000000000035",
			string(testSessionID),
			string(testWorkspaceID),
			filepath.Join(t.TempDir(), "direct-root"),
			"codecomm-directory-v1:unix:1:3",
			first.RepositoryIdentity,
			string(testAppliedAt),
		)
	})
	if code := sqlite.ErrCode(err); code != sqlite.ResultConstraintUnique {
		t.Fatalf(
			"direct duplicate repository identity error = %v (%v), want %v",
			err,
			code,
			sqlite.ResultConstraintUnique,
		)
	}
}
