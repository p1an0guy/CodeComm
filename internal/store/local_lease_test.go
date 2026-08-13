package store

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/ijonahch/codecomm/internal/domain"
	"github.com/ijonahch/codecomm/internal/domain/lease"
	"zombiezen.com/go/sqlite"
)

const leaseRestartBootID = domain.UUIDv7(
	"01890f47-3e72-7000-8000-000000000014",
)

func TestRearmLeaseDeadlinesUsesFullTTLForNewBoot(t *testing.T) {
	value := openLocalLeaseTestStore(t)
	local := value.LocalState()
	now := domain.Timestamp("2026-08-12T15:00:00Z")
	monotonicNowNS := int64(7 * time.Second)

	if err := local.RearmLeaseDeadlines(
		context.Background(),
		leaseRestartBootID,
		now,
		monotonicNowNS,
	); err != nil {
		t.Fatalf("RearmLeaseDeadlines(): %v", err)
	}
	record, found, err := local.NextLeaseDeadline(
		context.Background(),
		leaseRestartBootID,
	)
	if err != nil {
		t.Fatalf("NextLeaseDeadline(): %v", err)
	}
	if !found ||
		record.LeaseID != testLeaseID ||
		record.EntityVersion != 1 ||
		record.OriginBootID != leaseRestartBootID ||
		record.MonotonicDeadlineNS !=
			monotonicNowNS+int64(900*time.Second) ||
		record.DisplayDeadlineAt !=
			domain.Timestamp("2026-08-12T15:15:00Z") {
		t.Fatalf("rearmed deadline = %#v", record)
	}
	if _, _, err := local.NextLeaseDeadline(
		context.Background(),
		testBootID,
	); !errors.Is(err, ErrLocalStateIntegrity) {
		t.Fatalf(
			"NextLeaseDeadline(old boot) error = %v, want %v",
			err,
			ErrLocalStateIntegrity,
		)
	}
}

func TestNextLeaseDeadlineFailsClosedOnMissingOrMismatchedTimer(t *testing.T) {
	tests := []struct {
		name   string
		tamper func(*sqlite.Conn) error
	}{
		{
			name: "missing",
			tamper: func(conn *sqlite.Conn) error {
				return execute(conn, "DELETE FROM lease_deadlines;")
			},
		},
		{
			name: "wrong version",
			tamper: func(conn *sqlite.Conn) error {
				return execute(
					conn,
					"UPDATE lease_deadlines SET entity_version = 2;",
				)
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			value := openLocalLeaseTestStore(t)
			if err := value.withConn(
				context.Background(),
				test.tamper,
			); err != nil {
				t.Fatalf("tamper deadline: %v", err)
			}
			if _, _, err := value.LocalState().NextLeaseDeadline(
				context.Background(),
				testBootID,
			); !errors.Is(err, ErrLocalStateIntegrity) {
				t.Fatalf(
					"NextLeaseDeadline() error = %v, want %v",
					err,
					ErrLocalStateIntegrity,
				)
			}
		})
	}
}

func openLocalLeaseTestStore(t *testing.T) *Store {
	t.Helper()
	value := openTestStore(
		t,
		filepath.Join(t.TempDir(), "session", "state.db"),
		nil,
	)
	initializeTestStore(t, value)
	first := acceptedApplyRequest(
		t,
		testSignedTaskEvent(t, testEventID, 1),
	)
	firstResult, err := value.Apply(context.Background(), first)
	if err != nil {
		t.Fatalf("apply first command: %v", err)
	}
	request := nextCheckpointApplyRequest(
		t,
		firstResult.Heads,
		testCheckpointEventID,
		1,
		2,
		domain.Timestamp("2026-08-10T12:00:01Z"),
	)
	active := testActiveLease(t, request.Proposal.Proposal().Origin.DeviceID())
	if active.TTLSeconds != 900 ||
		active.Status != lease.StatusActive {
		t.Fatalf("test lease = %#v", active)
	}
	request.Projections.Leases = []lease.Lease{active}
	request.LeaseDeadlines = []LeaseDeadlineRecord{{
		LeaseID:             active.ID,
		EntityVersion:       active.EntityVersion,
		OriginBootID:        testBootID,
		MonotonicDeadlineNS: 1,
		DisplayDeadlineAt: domain.Timestamp(
			"2026-08-10T12:00:01.000000001Z",
		),
	}}
	if _, err := value.Apply(context.Background(), request); err != nil {
		t.Fatalf("apply active lease: %v", err)
	}
	return value
}
