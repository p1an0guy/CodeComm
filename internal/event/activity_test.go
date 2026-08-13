package event

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/ijonahch/codecomm/internal/domain"
)

func TestActionValidationCoversClosedTargetGrammarsAndBounds(t *testing.T) {
	t.Parallel()

	taskID := domain.UUIDv7("01890f47-3e72-7000-8000-000000000005")
	digest := SHA256Digest{31: 1}
	startedAt := domain.Timestamp("2026-08-10T12:13:14.123Z")
	duration := uint64(MaxActivityDurationMS)
	base := Action{
		Type:           ActionFileEdit,
		Target:         "internal/event/envelope.go",
		Summary:        "updated the event envelope",
		Status:         ActionSucceeded,
		TaskID:         &taskID,
		ArtifactDigest: &digest,
		StartedAt:      &startedAt,
		DurationMS:     &duration,
	}
	if err := base.Validate(); err != nil {
		t.Fatalf("valid action error = %v", err)
	}

	tests := []struct {
		name   string
		mutate func(*Action)
	}{
		{"unknown type", func(a *Action) { a.Type = "shell.exec" }},
		{"invalid file path", func(a *Action) { a.Target = "../outside" }},
		{"empty summary", func(a *Action) { a.Summary = "" }},
		{"summary over limit", func(a *Action) { a.Summary = strings.Repeat("x", MaxActionSummaryBytes+1) }},
		{"unknown status", func(a *Action) { a.Status = "ok" }},
		{"invalid task ID", func(a *Action) { invalid := domain.UUIDv7("bad"); a.TaskID = &invalid }},
		{"invalid timestamp", func(a *Action) { invalid := domain.Timestamp("2026-08-10T12:13:14+00:00"); a.StartedAt = &invalid }},
		{"duration over limit", func(a *Action) { over := uint64(MaxActivityDurationMS + 1); a.DurationMS = &over }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			action := base
			test.mutate(&action)
			if err := action.Validate(); !errors.Is(err, ErrInvalidAction) {
				t.Fatalf("Validate() error = %v, want ErrInvalidAction", err)
			}
		})
	}

	targets := []struct {
		actionType ActionType
		target     string
	}{
		{ActionFileRead, "docs/design/README.md"},
		{ActionFileEdit, "internal/event/event.go"},
		{ActionCommandRun, "go"},
		{ActionToolCall, "functions.exec_command"},
		{ActionTestRun, "TestActionValidation/subtest"},
		{ActionDecisionRecorded, "event envelope API"},
		{ActionArtifactCreated, "class:test-report"},
		{ActionArtifactCreated, "build/report.json"},
	}
	for _, target := range targets {
		action := base
		action.Type = target.actionType
		action.Target = target.target
		if err := action.Validate(); err != nil {
			t.Errorf("%q target %q error = %v", target.actionType, target.target, err)
		}
	}

	zero := uint64(0)
	base.DurationMS = &zero
	if err := base.Validate(); err != nil {
		t.Fatalf("zero duration error = %v", err)
	}
}

func TestActionRejectsTargetSubstitutionAndControlText(t *testing.T) {
	t.Parallel()

	tests := []struct {
		actionType ActionType
		target     string
	}{
		{ActionCommandRun, "/usr/bin/go"},
		{ActionCommandRun, "go test"},
		{ActionToolCall, "tool call"},
		{ActionTestRun, "suite\nother"},
		{ActionDecisionRecorded, "topic\tsecret"},
		{ActionArtifactCreated, "class:bad/value"},
	}
	for _, test := range tests {
		action := Action{
			Type:    test.actionType,
			Target:  test.target,
			Summary: "attempted operation",
			Status:  ActionAttempted,
		}
		if err := action.Validate(); !errors.Is(err, ErrInvalidAction) {
			t.Errorf("%q target %q error = %v, want ErrInvalidAction", test.actionType, test.target, err)
		}
	}

	action := Action{
		Type:      ActionTestRun,
		Target:    "suite",
		Summary:   "bad\x00summary",
		Status:    ActionFailed,
		StartedAt: timestampPointer(domain.Timestamp(time.Date(2026, 8, 10, 1, 2, 3, 0, time.UTC).Format(time.RFC3339Nano))),
	}
	if err := action.Validate(); !errors.Is(err, ErrInvalidAction) {
		t.Fatalf("control summary error = %v, want ErrInvalidAction", err)
	}
}

func TestRedactionValidationRequiresSortedUniqueClosedFields(t *testing.T) {
	t.Parallel()

	valid := Redaction{
		Policy: RedactionDefault,
		FieldsRemoved: []RedactionField{
			RedactionArguments,
			RedactionPrivateReasoning,
			RedactionSecret,
		},
	}
	if err := valid.Validate(); err != nil {
		t.Fatalf("valid redaction error = %v", err)
	}

	tests := []Redaction{
		{},
		{Policy: "custom", FieldsRemoved: []RedactionField{}},
		{Policy: RedactionDefault, FieldsRemoved: []RedactionField{"unknown"}},
		{Policy: RedactionDefault, FieldsRemoved: []RedactionField{RedactionSecret, RedactionArguments}},
		{Policy: RedactionDefault, FieldsRemoved: []RedactionField{RedactionSecret, RedactionSecret}},
	}
	for _, value := range tests {
		if err := value.Validate(); !errors.Is(err, ErrInvalidRedaction) {
			t.Errorf("Redaction %#v error = %v, want ErrInvalidRedaction", value, err)
		}
	}
}

func timestampPointer(value domain.Timestamp) *domain.Timestamp {
	return &value
}
