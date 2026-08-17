package store

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"path/filepath"
	"testing"

	"github.com/ijonahch/codecomm/internal/domain"
	"zombiezen.com/go/sqlite"
)

func TestCommittedRaftConfigurationIsMonotonicAndExact(t *testing.T) {
	value := openTestStore(
		t,
		filepath.Join(t.TempDir(), "session", "state.db"),
		nil,
	)
	initial := commitmentInitialState(
		t,
		domain.UUIDv7(testSessionID),
		0,
		ProjectionWrites{},
	)
	if _, err := value.Initialize(context.Background(), initial); err != nil {
		t.Fatalf("Initialize(): %v", err)
	}

	first := []byte(`{"servers":[{"address":"cc1a","id":"cc1a","suffrage":"voter"}]}`)
	second := []byte(`{"servers":[{"address":"cc1b","id":"cc1b","suffrage":"voter"}]}`)
	stored, err := value.StoreCommittedRaftConfiguration(
		context.Background(),
		5,
		first,
	)
	if err != nil || !stored {
		t.Fatalf("StoreCommittedRaftConfiguration(first) = (%t, %v)", stored, err)
	}
	if stored, err := value.StoreCommittedRaftConfiguration(
		context.Background(),
		3,
		second,
	); err != nil || stored {
		t.Fatalf("older replay = (%t, %v), want (false, nil)", stored, err)
	}
	if stored, err := value.StoreCommittedRaftConfiguration(
		context.Background(),
		5,
		first,
	); err != nil || stored {
		t.Fatalf("exact replay = (%t, %v), want (false, nil)", stored, err)
	}
	if _, err := value.StoreCommittedRaftConfiguration(
		context.Background(),
		5,
		second,
	); !errors.Is(err, ErrRaftConfigurationConflict) {
		t.Fatalf("same-index conflict error = %v", err)
	}

	record, found, err := value.CommittedRaftConfiguration(
		context.Background(),
	)
	if err != nil || !found {
		t.Fatalf("CommittedRaftConfiguration() = (%#v, %t, %v)", record, found, err)
	}
	if record.SessionID != initial.SessionID ||
		record.RecoveryGeneration != 0 ||
		record.LogIndex != 5 ||
		!bytes.Equal(record.ConfigurationJSON, first) {
		t.Fatalf("record = %#v", record)
	}
}

func TestCommittedRaftConfigurationRejectsNoncanonicalBytes(t *testing.T) {
	value := openTestStore(
		t,
		filepath.Join(t.TempDir(), "session", "state.db"),
		nil,
	)
	initial := commitmentInitialState(
		t,
		domain.UUIDv7(testSessionID),
		0,
		ProjectionWrites{},
	)
	if _, err := value.Initialize(context.Background(), initial); err != nil {
		t.Fatalf("Initialize(): %v", err)
	}
	for _, raw := range [][]byte{
		nil,
		[]byte(`[]`),
		[]byte(`{"b":1,"a":2}`),
	} {
		if _, err := value.StoreCommittedRaftConfiguration(
			context.Background(),
			1,
			raw,
		); !errors.Is(err, ErrInvalidRaftConfiguration) {
			t.Fatalf("StoreCommittedRaftConfiguration(%q) error = %v", raw, err)
		}
	}
}

func TestOpenRejectsCommittedRaftConfigurationAheadOfRaft(t *testing.T) {
	path := filepath.Join(t.TempDir(), "session", "state.db")
	value := openTestStore(t, path, nil)
	initial := commitmentInitialState(
		t,
		domain.UUIDv7(testSessionID),
		0,
		ProjectionWrites{},
	)
	if _, err := value.Initialize(context.Background(), initial); err != nil {
		t.Fatalf("Initialize(): %v", err)
	}
	configuration := []byte(
		`{"servers":[{"address":"cc1a","id":"cc1a","suffrage":"voter"}]}`,
	)
	if stored, err := value.StoreCommittedRaftConfiguration(
		context.Background(),
		5,
		configuration,
	); err != nil || !stored {
		t.Fatalf("StoreCommittedRaftConfiguration() = (%t, %v)", stored, err)
	}
	if err := value.Close(); err != nil {
		t.Fatalf("Close(): %v", err)
	}

	reopened, err := Open(context.Background(), Options{
		Path:    path,
		RaftLog: fixedRaftLog{lastIndex: 4},
	})
	if err == nil {
		_ = reopened.Close()
		t.Fatal("Open() succeeded with configuration ahead of Raft")
	}
	if !errors.Is(err, ErrRaftIndexAhead) {
		t.Fatalf("Open() error = %v, want ErrRaftIndexAhead", err)
	}
}

func TestOpenRejectsTamperedCommittedRaftConfiguration(t *testing.T) {
	tests := []struct {
		name   string
		tamper func(*sqlite.Conn) error
	}{
		{
			name: "digest",
			tamper: func(conn *sqlite.Conn) error {
				return execute(
					conn,
					`UPDATE raft_committed_configuration
					    SET configuration_digest = ?1
					  WHERE singleton = 1;`,
					bytes.Repeat([]byte{0x7a}, sha256.Size),
				)
			},
		},
		{
			name: "generation binding",
			tamper: func(conn *sqlite.Conn) error {
				return execute(
					conn,
					`UPDATE raft_committed_configuration
					    SET recovery_generation = 1
					  WHERE singleton = 1;`,
				)
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "session", "state.db")
			value := openTestStore(t, path, nil)
			initial := commitmentInitialState(
				t,
				domain.UUIDv7(testSessionID),
				0,
				ProjectionWrites{},
			)
			if _, err := value.Initialize(
				context.Background(),
				initial,
			); err != nil {
				t.Fatalf("Initialize(): %v", err)
			}
			configuration := []byte(
				`{"servers":[{"address":"cc1a","id":"cc1a","suffrage":"voter"}]}`,
			)
			if _, err := value.StoreCommittedRaftConfiguration(
				context.Background(),
				5,
				configuration,
			); err != nil {
				t.Fatalf("StoreCommittedRaftConfiguration(): %v", err)
			}
			if err := value.withConn(
				context.Background(),
				test.tamper,
			); err != nil {
				t.Fatalf("tamper configuration: %v", err)
			}
			if err := value.Close(); err != nil {
				t.Fatalf("Close(): %v", err)
			}

			reopened, err := Open(context.Background(), Options{
				Path:    path,
				RaftLog: fixedRaftLog{lastIndex: 5},
			})
			if err == nil {
				_ = reopened.Close()
				t.Fatal("Open() succeeded with tampered configuration")
			}
			if !errors.Is(err, ErrRaftConfigurationConflict) {
				t.Fatalf(
					"Open() error = %v, want ErrRaftConfigurationConflict",
					err,
				)
			}
		})
	}
}
