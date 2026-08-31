package joinbootstrap

import (
	"context"
	"crypto/tls"
	"errors"
	"path/filepath"
	"testing"

	"github.com/ijonahch/codecomm/internal/consensus"
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
