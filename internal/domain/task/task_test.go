package task

import (
	"errors"
	"fmt"
	"sort"
	"strings"
	"testing"

	"github.com/ijonahch/codecomm/internal/domain"
)

const (
	validTaskID         = domain.UUIDv7("01890f47-3e72-7d5a-8c9b-123456789abc")
	validAgentSessionID = domain.UUIDv7("01890f47-3e72-7d5a-8c9b-123456789abd")
	validDeviceID       = domain.DeviceID("cc10000000000000000000000000000000000000000000000000000000000000000")
	otherDeviceID       = domain.DeviceID("cc11111111111111111111111111111111111111111111111111111111111111111")
)

func TestTaskValidateAcceptsBoundaryValues(t *testing.T) {
	t.Parallel()

	reason := strings.Repeat("r", MaxStateReasonBytes)
	task := validTask()
	task.Title = strings.Repeat("t", MaxTitleBytes)
	task.Body = strings.Repeat("b", MaxBodyBytes)
	task.State = StateBlocked
	task.StateReason = &reason
	task.Priority = MaxPriority
	task.BlockedBy = makeUUIDs(MaxBlockedBy)
	task.Labels = makeLabels(MaxLabels, MaxLabelBytes)
	task.OwnerDeviceID = validDeviceID
	task.OwnerAgentSessionID = validAgentSessionID

	if err := task.Validate(); err != nil {
		t.Fatalf("Task.Validate() error = %v", err)
	}
}

func TestTaskValidateRejectsOnePastFieldBounds(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		mutate func(*Task)
		want   error
	}{
		{
			name: "empty title",
			mutate: func(task *Task) {
				task.Title = ""
			},
			want: ErrInvalidTitle,
		},
		{
			name: "title bytes",
			mutate: func(task *Task) {
				task.Title = strings.Repeat("t", MaxTitleBytes+1)
			},
			want: ErrInvalidTitle,
		},
		{
			name: "body bytes",
			mutate: func(task *Task) {
				task.Body = strings.Repeat("b", MaxBodyBytes+1)
			},
			want: ErrInvalidBody,
		},
		{
			name: "state reason bytes",
			mutate: func(task *Task) {
				task.State = StateBlocked
				reason := strings.Repeat("r", MaxStateReasonBytes+1)
				task.StateReason = &reason
				task.OwnerDeviceID = validDeviceID
				task.OwnerAgentSessionID = validAgentSessionID
			},
			want: ErrInvalidStateReason,
		},
		{
			name: "priority",
			mutate: func(task *Task) {
				task.Priority = MaxPriority + 1
			},
			want: ErrInvalidPriority,
		},
		{
			name: "blocked by count",
			mutate: func(task *Task) {
				task.BlockedBy = makeUUIDs(MaxBlockedBy + 1)
			},
			want: ErrInvalidBlockedBy,
		},
		{
			name: "label count",
			mutate: func(task *Task) {
				task.Labels = makeLabels(MaxLabels+1, 1)
			},
			want: ErrInvalidLabels,
		},
		{
			name: "label bytes",
			mutate: func(task *Task) {
				task.Labels = []string{strings.Repeat("l", MaxLabelBytes+1)}
			},
			want: ErrInvalidLabels,
		},
		{
			name: "entity version",
			mutate: func(task *Task) {
				task.EntityVersion = 0
			},
			want: ErrInvalidEntityVersion,
		},
		{
			name: "entity version over signed JSON limit",
			mutate: func(task *Task) {
				task.EntityVersion = domain.MaxSafeInteger + 1
			},
			want: ErrInvalidEntityVersion,
		},
		{
			name: "created timestamp",
			mutate: func(task *Task) {
				task.CreatedAt = domain.Timestamp("2026-08-10T13:00:00-07:00")
			},
			want: ErrInvalidTimestamp,
		},
		{
			name: "updated timestamp",
			mutate: func(task *Task) {
				task.UpdatedAt = domain.Timestamp("2026-08-10T20:00:00.0Z")
			},
			want: ErrInvalidTimestamp,
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			task := validTask()
			test.mutate(&task)
			if err := task.Validate(); !errors.Is(err, test.want) {
				t.Fatalf("Task.Validate() error = %v, want %v", err, test.want)
			}
		})
	}
}

func TestTaskValidateAcceptsEntityVersionBounds(t *testing.T) {
	t.Parallel()

	for _, version := range []uint64{1, domain.MaxSafeInteger} {
		task := validTask()
		task.EntityVersion = version
		if err := task.Validate(); err != nil {
			t.Errorf("Task.Validate() at entity version %d error = %v", version, err)
		}
	}
}

func TestTaskValidateUsesUTF8ByteBounds(t *testing.T) {
	t.Parallel()

	task := validTask()
	task.Title = strings.Repeat("é", MaxTitleBytes/2)
	if err := task.Validate(); err != nil {
		t.Fatalf("Task.Validate() at %d UTF-8 bytes error = %v", MaxTitleBytes, err)
	}

	task.Title += "é"
	if err := task.Validate(); !errors.Is(err, ErrInvalidTitle) {
		t.Fatalf("Task.Validate() over %d UTF-8 bytes error = %v, want ErrInvalidTitle", MaxTitleBytes, err)
	}
}

func TestTaskValidateRejectsMalformedText(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		mutate func(*Task)
		want   error
	}{
		{
			name: "multiline title",
			mutate: func(task *Task) {
				task.Title = "one\ntwo"
			},
			want: ErrInvalidTitle,
		},
		{
			name: "title control",
			mutate: func(task *Task) {
				task.Title = "one\u007ftwo"
			},
			want: ErrInvalidTitle,
		},
		{
			name: "title Unicode line separator",
			mutate: func(task *Task) {
				task.Title = "one\u2028two"
			},
			want: ErrInvalidTitle,
		},
		{
			name: "title Unicode paragraph separator",
			mutate: func(task *Task) {
				task.Title = "one\u2029two"
			},
			want: ErrInvalidTitle,
		},
		{
			name: "title invalid UTF-8",
			mutate: func(task *Task) {
				task.Title = string([]byte{0xff})
			},
			want: ErrInvalidTitle,
		},
		{
			name: "body invalid UTF-8",
			mutate: func(task *Task) {
				task.Body = string([]byte{0xff})
			},
			want: ErrInvalidBody,
		},
		{
			name: "reason invalid UTF-8",
			mutate: func(task *Task) {
				task.State = StateBlocked
				reason := string([]byte{0xff})
				task.StateReason = &reason
				task.OwnerDeviceID = validDeviceID
				task.OwnerAgentSessionID = validAgentSessionID
			},
			want: ErrInvalidStateReason,
		},
		{
			name: "label invalid UTF-8",
			mutate: func(task *Task) {
				task.Labels = []string{string([]byte{0xff})}
			},
			want: ErrInvalidLabels,
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			task := validTask()
			test.mutate(&task)
			if err := task.Validate(); !errors.Is(err, test.want) {
				t.Fatalf("Task.Validate() error = %v, want %v", err, test.want)
			}
		})
	}
}

func TestTaskValidateEnforcesStateReasonInvariant(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		mutate func(*Task)
	}{
		{
			name: "blocked reason absent",
			mutate: func(task *Task) {
				task.State = StateBlocked
				task.StateReason = nil
				task.OwnerDeviceID = validDeviceID
				task.OwnerAgentSessionID = validAgentSessionID
			},
		},
		{
			name: "blocked reason empty",
			mutate: func(task *Task) {
				task.State = StateBlocked
				reason := ""
				task.StateReason = &reason
				task.OwnerDeviceID = validDeviceID
				task.OwnerAgentSessionID = validAgentSessionID
			},
		},
		{
			name: "reason outside blocked",
			mutate: func(task *Task) {
				reason := "not blocked"
				task.StateReason = &reason
			},
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			task := validTask()
			test.mutate(&task)
			if err := task.Validate(); !errors.Is(err, ErrInvalidStateReason) {
				t.Fatalf("Task.Validate() error = %v, want ErrInvalidStateReason", err)
			}
		})
	}
}

func TestTaskValidateEnforcesOwnershipInvariant(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		mutate func(*Task)
	}{
		{
			name: "only device owner",
			mutate: func(task *Task) {
				task.State = StateClaimed
				task.OwnerDeviceID = validDeviceID
			},
		},
		{
			name: "only session owner",
			mutate: func(task *Task) {
				task.State = StateClaimed
				task.OwnerAgentSessionID = validAgentSessionID
			},
		},
		{
			name: "owned state has no owner",
			mutate: func(task *Task) {
				task.State = StateInProgress
			},
		},
		{
			name: "unowned state has owner",
			mutate: func(task *Task) {
				task.OwnerDeviceID = validDeviceID
				task.OwnerAgentSessionID = validAgentSessionID
			},
		},
		{
			name: "owned state has release reason",
			mutate: func(task *Task) {
				task.State = StateClaimed
				task.OwnerDeviceID = validDeviceID
				task.OwnerAgentSessionID = validAgentSessionID
				task.LastReleaseReason = ReleaseVoluntary
			},
		},
		{
			name: "owned state retains intended device",
			mutate: func(task *Task) {
				task.State = StateClaimed
				task.OwnerDeviceID = validDeviceID
				task.OwnerAgentSessionID = validAgentSessionID
				task.IntendedDeviceID = otherDeviceID
			},
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			task := validTask()
			test.mutate(&task)
			if err := task.Validate(); !errors.Is(err, ErrInvalidOwnership) {
				t.Fatalf("Task.Validate() error = %v, want ErrInvalidOwnership", err)
			}
		})
	}
}

func TestTaskValidateEnforcesTerminalOwnershipInvariant(t *testing.T) {
	t.Parallel()

	for _, state := range []State{StateDone, StateCancelled} {
		state := state
		t.Run(string(state), func(t *testing.T) {
			t.Parallel()
			task := validTask()
			task.State = state
			task.IntendedDeviceID = otherDeviceID
			if err := task.Validate(); !errors.Is(err, ErrInvalidOwnership) {
				t.Fatalf("Task.Validate() error = %v, want ErrInvalidOwnership", err)
			}
		})
	}
}

func TestTaskValidateRejectsInvalidIdentifiersAndEnums(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		mutate func(*Task)
		want   error
	}{
		{
			name: "task ID",
			mutate: func(task *Task) {
				task.ID = domain.UUIDv7("not-a-uuid")
			},
			want: ErrInvalidID,
		},
		{
			name: "state",
			mutate: func(task *Task) {
				task.State = State("unknown")
			},
			want: ErrInvalidState,
		},
		{
			name: "owner device ID",
			mutate: func(task *Task) {
				task.State = StateClaimed
				task.OwnerDeviceID = domain.DeviceID("bad")
				task.OwnerAgentSessionID = validAgentSessionID
			},
			want: ErrInvalidOwnership,
		},
		{
			name: "owner session ID",
			mutate: func(task *Task) {
				task.State = StateClaimed
				task.OwnerDeviceID = validDeviceID
				task.OwnerAgentSessionID = domain.UUIDv7("bad")
			},
			want: ErrInvalidOwnership,
		},
		{
			name: "intended device ID",
			mutate: func(task *Task) {
				task.IntendedDeviceID = domain.DeviceID("bad")
			},
			want: ErrInvalidOwnership,
		},
		{
			name: "release reason",
			mutate: func(task *Task) {
				task.LastReleaseReason = ReleaseReason("unknown")
			},
			want: ErrInvalidReleaseReason,
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			task := validTask()
			test.mutate(&task)
			if err := task.Validate(); !errors.Is(err, test.want) {
				t.Fatalf("Task.Validate() error = %v, want %v", err, test.want)
			}
		})
	}
}

func TestTaskValidateRequiresSortedUniqueCollections(t *testing.T) {
	t.Parallel()

	first := domain.UUIDv7("01890f47-3e72-7d5a-8c9b-000000000001")
	second := domain.UUIDv7("01890f47-3e72-7d5a-8c9b-000000000002")
	tests := []struct {
		name   string
		mutate func(*Task)
		want   error
	}{
		{
			name: "blocked by unsorted",
			mutate: func(task *Task) {
				task.BlockedBy = []domain.UUIDv7{second, first}
			},
			want: ErrInvalidBlockedBy,
		},
		{
			name: "blocked by duplicate",
			mutate: func(task *Task) {
				task.BlockedBy = []domain.UUIDv7{first, first}
			},
			want: ErrInvalidBlockedBy,
		},
		{
			name: "blocked by self",
			mutate: func(task *Task) {
				task.BlockedBy = []domain.UUIDv7{validTaskID}
			},
			want: ErrDependencyCycle,
		},
		{
			name: "labels unsorted",
			mutate: func(task *Task) {
				task.Labels = []string{"z", "a"}
			},
			want: ErrInvalidLabels,
		},
		{
			name: "labels duplicate",
			mutate: func(task *Task) {
				task.Labels = []string{"a", "a"}
			},
			want: ErrInvalidLabels,
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			task := validTask()
			test.mutate(&task)
			if err := task.Validate(); !errors.Is(err, test.want) {
				t.Fatalf("Task.Validate() error = %v, want %v", err, test.want)
			}
		})
	}
}

func TestNormalizeLabelsSortsAndDeduplicatesWithoutAliasing(t *testing.T) {
	t.Parallel()

	input := []string{"z", "a", "z", "m"}
	got, err := NormalizeLabels(input)
	if err != nil {
		t.Fatalf("NormalizeLabels() error = %v", err)
	}
	want := []string{"a", "m", "z"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("NormalizeLabels() = %v, want %v", got, want)
	}
	if !sort.StringsAreSorted(got) {
		t.Fatalf("NormalizeLabels() = %v, want sorted output", got)
	}
	got[0] = "changed"
	if input[1] != "a" {
		t.Fatalf("NormalizeLabels() aliased its input: %v", input)
	}
}

func TestNormalizeLabelsValidatesBeforeDeduplication(t *testing.T) {
	t.Parallel()

	tooManyDuplicates := make([]string, MaxLabels+1)
	for index := range tooManyDuplicates {
		tooManyDuplicates[index] = "duplicate"
	}
	if _, err := NormalizeLabels(tooManyDuplicates); !errors.Is(err, ErrInvalidLabels) {
		t.Fatalf("NormalizeLabels(over limit) error = %v, want ErrInvalidLabels", err)
	}

	if _, err := NormalizeLabels([]string{strings.Repeat("x", MaxLabelBytes+1)}); !errors.Is(err, ErrInvalidLabels) {
		t.Fatalf("NormalizeLabels(oversized item) error = %v, want ErrInvalidLabels", err)
	}
}

func TestTaskActionableAndClaimable(t *testing.T) {
	t.Parallel()

	task := validTask()
	if !task.Actionable(true, false) {
		t.Fatal("ready task with completed dependencies and no conflict is not actionable")
	}
	if task.Actionable(false, false) {
		t.Fatal("task with incomplete dependencies is actionable")
	}
	if task.Actionable(true, true) {
		t.Fatal("task with unresolved conflict is actionable")
	}

	task.IntendedDeviceID = otherDeviceID
	if task.ClaimableBy(validDeviceID, true, false) {
		t.Fatal("task is claimable by a device other than its intended target")
	}
	if !task.ClaimableBy(otherDeviceID, true, false) {
		t.Fatal("task is not claimable by its intended target")
	}
	task.IntendedDeviceID = ""
	if task.ClaimableBy("", true, false) {
		t.Fatal("task is claimable by an invalid device ID")
	}
}

func validTask() Task {
	return Task{
		ID:            validTaskID,
		Title:         "Implement the task domain",
		State:         StateReady,
		Priority:      PriorityNormal,
		EntityVersion: 1,
		CreatedAt:     domain.Timestamp("2026-08-10T20:00:00Z"),
		UpdatedAt:     domain.Timestamp("2026-08-10T20:00:00Z"),
	}
}

func makeUUIDs(count int) []domain.UUIDv7 {
	values := make([]domain.UUIDv7, count)
	for i := range values {
		values[i] = domain.UUIDv7("01890f47-3e72-7d5a-8c9b-" + leftPadDecimal(i+1, 12))
	}
	return values
}

func makeLabels(count, length int) []string {
	values := make([]string, count)
	for i := range values {
		if length == 1 {
			values[i] = string(rune('a' + i))
			continue
		}
		prefix := leftPadDecimal(i+1, 2)
		values[i] = prefix + strings.Repeat("x", length-len(prefix))
	}
	return values
}

func leftPadDecimal(value, width int) string {
	return fmt.Sprintf("%0*d", width, value)
}
