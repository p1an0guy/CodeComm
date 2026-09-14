package joinbootstrap

import (
	"context"
	"crypto/tls"
	"errors"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/ijonahch/codecomm/internal/consensus"
	"github.com/ijonahch/codecomm/internal/pairing"
)

func TestDecisionApprovedResumeRequiresCommittedAdmission(t *testing.T) {
	t.Parallel()

	for name, resolutionErr := range map[string]error{
		"unavailable": ErrBootstrapUnavailable,
		"rejected":    consensus.ErrConsensusStatusRejected,
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			journal, _, _ := joinJournalFixture(t)
			statePath := filepath.Join(t.TempDir(), "join", "state.db")
			if err := writePendingJournal(statePath, journal); err != nil {
				t.Fatal(err)
			}
			leader, err := resolveDecisionApprovedBootstrapLeader(
				t.Context(),
				statePath,
				&journal,
				nil,
				tls.Certificate{},
				func(
					context.Context,
					pendingJournal,
					*pinnedEndpoints,
					tls.Certificate,
				) (*bootstrapLeaderConnection, error) {
					return nil, resolutionErr
				},
			)
			if leader != nil ||
				!errors.Is(err, ErrJoinIncomplete) ||
				journal.Phase != journalPhaseDecisionApproved {
				t.Fatalf(
					"resolution = (%#v, %v, phase %q)",
					leader,
					err,
					journal.Phase,
				)
			}
			persisted, loadErr := loadPendingJournal(statePath)
			if loadErr != nil ||
				persisted.Phase != journalPhaseDecisionApproved {
				t.Fatalf(
					"persisted phase = (%q, %v)",
					persisted.Phase,
					loadErr,
				)
			}
		})
	}
}

func TestDecisionApprovedResumePersistsExactAdmissionProof(t *testing.T) {
	t.Parallel()

	journal, _, _ := joinJournalFixture(t)
	statePath := filepath.Join(t.TempDir(), "join", "state.db")
	if err := writePendingJournal(statePath, journal); err != nil {
		t.Fatal(err)
	}
	expected := &bootstrapLeaderConnection{}
	leader, err := resolveDecisionApprovedBootstrapLeader(
		t.Context(),
		statePath,
		&journal,
		nil,
		tls.Certificate{},
		func(
			context.Context,
			pendingJournal,
			*pinnedEndpoints,
			tls.Certificate,
		) (*bootstrapLeaderConnection, error) {
			return expected, nil
		},
	)
	if err != nil || leader != expected ||
		journal.Phase != journalPhaseConfirmed {
		t.Fatalf(
			"resolution = (%#v, %v, phase %q)",
			leader,
			err,
			journal.Phase,
		)
	}
	persisted, err := loadPendingJournal(statePath)
	if err != nil || persisted.Phase != journalPhaseConfirmed {
		t.Fatalf("persisted phase = (%q, %v)", persisted.Phase, err)
	}
}

func TestDecisionApprovedRebootstrapResumeRequiresFreshInvite(
	t *testing.T,
) {
	t.Parallel()

	journal, _, _ := joinJournalFixture(t)
	journal.Mode = pairing.ModeRebootstrap
	subject := journal.LocalDeviceID
	journal.SubjectDeviceID = &subject
	statePath := filepath.Join(t.TempDir(), "join", "state.db")
	if err := writePendingJournal(statePath, journal); err != nil {
		t.Fatal(err)
	}

	leader, err := resolveDecisionApprovedBootstrapLeader(
		t.Context(),
		statePath,
		&journal,
		nil,
		tls.Certificate{},
		func(
			context.Context,
			pendingJournal,
			*pinnedEndpoints,
			tls.Certificate,
		) (*bootstrapLeaderConnection, error) {
			t.Fatal("ambiguous rebootstrap queried membership")
			return nil, nil
		},
	)
	if leader != nil || !errors.Is(err, ErrJoinIncomplete) {
		t.Fatalf("resolution = (%#v, %v), want incomplete", leader, err)
	}
	if pending, pendingErr := HasPending(statePath); pendingErr != nil ||
		pending {
		t.Fatalf(
			"pending journal after ambiguous rebootstrap = (%t, %v)",
			pending,
			pendingErr,
		)
	}
}

func TestBootstrapLeaderRetryUsesCappedExponentialBackoff(t *testing.T) {
	t.Parallel()

	journal, _, _ := joinJournalFixture(t)
	expected := &bootstrapLeaderConnection{}
	attempts := 0
	var delays []time.Duration
	leader, err := waitForBootstrapLeaderWithRetry(
		t.Context(),
		journal,
		nil,
		tls.Certificate{},
		func(
			context.Context,
			pendingJournal,
			*pinnedEndpoints,
			tls.Certificate,
		) (*bootstrapLeaderConnection, error) {
			attempts++
			if attempts == 11 {
				return expected, nil
			}
			return nil, ErrBootstrapUnavailable
		},
		func(_ context.Context, delay time.Duration) error {
			delays = append(delays, delay)
			return nil
		},
	)
	if err != nil || leader != expected {
		t.Fatalf("waitForBootstrapLeaderWithRetry() = (%#v, %v)", leader, err)
	}
	want := []time.Duration{
		250 * time.Millisecond,
		500 * time.Millisecond,
		time.Second,
		2 * time.Second,
		4 * time.Second,
		8 * time.Second,
		16 * time.Second,
		30 * time.Second,
		30 * time.Second,
		30 * time.Second,
	}
	if !reflect.DeepEqual(delays, want) {
		t.Fatalf("retry delays = %v, want %v", delays, want)
	}
}
