package lease

import (
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/ijonahch/codecomm/internal/domain"
)

const (
	validLeaseID      = domain.UUIDv7("01890f47-3e72-7d5a-8c9b-123456789abc")
	validTaskID       = domain.UUIDv7("01890f47-3e72-7d5a-8c9b-123456789abd")
	validAgentSession = domain.UUIDv7("01890f47-3e72-7d5a-8c9b-123456789abe")
	validHolderDevice = domain.DeviceID("cc10000000000000000000000000000000000000000000000000000000000000000")
	defaultTTLSeconds = int64(900)
	defaultEntity     = uint64(1)
)

func TestNewAcceptsTaskAndPathScopes(t *testing.T) {
	t.Parallel()

	taskFields := validFields()
	taskFields.Scope = ScopeTask
	taskFields.TaskID = validTaskID
	taskLease, err := New(taskFields, nil)
	if err != nil {
		t.Fatalf("New(task) error = %v", err)
	}
	if got := taskLease.PathPatterns(); got != nil {
		t.Fatalf("task PathPatterns() = %v, want nil", got)
	}
	if err := taskLease.Validate(); err != nil {
		t.Fatalf("task Lease.Validate() error = %v", err)
	}

	pathFields := validFields()
	pathFields.Scope = ScopePath
	pathFields.TaskID = validTaskID
	pathLease, err := New(pathFields, []string{"src/**", "README.md"})
	if err != nil {
		t.Fatalf("New(path) error = %v", err)
	}
	want := []string{"README.md", "src/**"}
	if got := patternStrings(pathLease.PathPatterns()); !reflect.DeepEqual(got, want) {
		t.Fatalf("path PathPatterns() = %v, want %v", got, want)
	}
	if err := pathLease.Validate(); err != nil {
		t.Fatalf("path Lease.Validate() error = %v", err)
	}

	pathFields.TaskID = ""
	if _, err := New(pathFields, []string{"src"}); err != nil {
		t.Fatalf("New(path without task association) error = %v", err)
	}
}

func TestNewEnforcesScopeSpecificFields(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		mutate   func(*Fields)
		patterns []string
		want     error
	}{
		{
			name: "task requires task ID",
			mutate: func(fields *Fields) {
				fields.Scope = ScopeTask
				fields.TaskID = ""
			},
			want: ErrInvalidTaskID,
		},
		{
			name: "task rejects patterns",
			mutate: func(fields *Fields) {
				fields.Scope = ScopeTask
				fields.TaskID = validTaskID
			},
			patterns: []string{"src"},
			want:     ErrInvalidPathPatternCount,
		},
		{
			name: "path permits no task association",
			mutate: func(fields *Fields) {
				fields.Scope = ScopePath
				fields.TaskID = ""
			},
			patterns: []string{"src"},
		},
		{
			name: "path permits task association",
			mutate: func(fields *Fields) {
				fields.Scope = ScopePath
				fields.TaskID = validTaskID
			},
			patterns: []string{"src"},
		},
		{
			name: "path rejects malformed task association",
			mutate: func(fields *Fields) {
				fields.Scope = ScopePath
				fields.TaskID = "not-a-uuid"
			},
			patterns: []string{"src"},
			want:     ErrInvalidTaskID,
		},
		{
			name: "path requires patterns",
			mutate: func(fields *Fields) {
				fields.Scope = ScopePath
			},
			want: ErrInvalidPathPatternCount,
		},
		{
			name: "unknown scope",
			mutate: func(fields *Fields) {
				fields.Scope = "unknown"
			},
			want: ErrInvalidScope,
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			fields := validFields()
			test.mutate(&fields)
			_, err := New(fields, test.patterns)
			if !errors.Is(err, test.want) {
				t.Fatalf("New() error = %v, want %v", err, test.want)
			}
		})
	}
}

func TestNewValidatesRawPatternCountBeforeNormalization(t *testing.T) {
	t.Parallel()

	fields := validFields()
	fields.Scope = ScopePath

	distinct := make([]string, MaxPathPatterns)
	for index := range distinct {
		distinct[index] = fmt.Sprintf("path-%02d", index)
	}
	full, err := New(fields, distinct)
	if err != nil {
		t.Fatalf("New(%d distinct patterns) error = %v", MaxPathPatterns, err)
	}
	if got := len(full.PathPatterns()); got != MaxPathPatterns {
		t.Fatalf("PathPatterns() length = %d, want %d", got, MaxPathPatterns)
	}

	maximum := make([]string, MaxPathPatterns)
	for index := range maximum {
		maximum[index] = "same/path"
	}
	got, err := New(fields, maximum)
	if err != nil {
		t.Fatalf("New(%d duplicate patterns) error = %v", MaxPathPatterns, err)
	}
	if patterns := got.PathPatterns(); len(patterns) != 1 || patterns[0].String() != "same/path" {
		t.Fatalf("PathPatterns() = %v, want one normalized pattern", patternStrings(patterns))
	}

	over := append(append([]string(nil), maximum...), "same/path")
	if _, err := New(fields, over); !errors.Is(err, ErrInvalidPathPatternCount) {
		t.Fatalf("New(%d duplicate patterns) error = %v, want %v", len(over), err, ErrInvalidPathPatternCount)
	}
}

func TestLeasePathPatternsDoNotAliasInputsOrResults(t *testing.T) {
	t.Parallel()

	fields := validFields()
	fields.Scope = ScopePath
	input := []string{"src/**", "README.md"}
	lease, err := New(fields, input)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	want := []string{"README.md", "src/**"}

	input[0] = "changed"
	if got := patternStrings(lease.PathPatterns()); !reflect.DeepEqual(got, want) {
		t.Fatalf("input mutation changed lease patterns: got %v, want %v", got, want)
	}

	exposed := lease.PathPatterns()
	exposed[0] = PathPattern{}
	if got := patternStrings(lease.PathPatterns()); !reflect.DeepEqual(got, want) {
		t.Fatalf("result mutation changed lease patterns: got %v, want %v", got, want)
	}

	copied := lease
	copied.pathPatterns[0] = PathPattern{}
	if got := patternStrings(lease.PathPatterns()); !reflect.DeepEqual(got, want) {
		t.Fatalf("lease copy aliased pattern storage: got %v, want %v", got, want)
	}
}

func TestLeaseValidateAcceptsExactBoundsAndReleaseReasons(t *testing.T) {
	t.Parallel()

	for _, ttl := range []int64{MinTTLSeconds, MaxTTLSeconds} {
		for _, version := range []uint64{1, domain.MaxSafeInteger} {
			fields := validFields()
			fields.TTLSeconds = ttl
			fields.EntityVersion = version
			if _, err := New(fields, nil); err != nil {
				t.Errorf("New(ttl=%d, version=%d) error = %v", ttl, version, err)
			}
		}
	}

	for _, reason := range ReleaseReasons() {
		reason := reason
		t.Run(string(reason), func(t *testing.T) {
			t.Parallel()
			fields := validFields()
			fields.Status = StatusReleased
			fields.ReleaseReason = reason
			if _, err := New(fields, nil); err != nil {
				t.Fatalf("New(released, %q) error = %v", reason, err)
			}
		})
	}
}

func TestLeaseValidateRejectsInvalidScalarFields(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		mutate func(*Fields)
		want   error
	}{
		{
			name: "lease ID",
			mutate: func(fields *Fields) {
				fields.ID = "not-a-uuid"
			},
			want: ErrInvalidID,
		},
		{
			name: "holder device ID",
			mutate: func(fields *Fields) {
				fields.HolderDeviceID = "not-a-device"
			},
			want: ErrInvalidHolderDeviceID,
		},
		{
			name: "holder agent session ID",
			mutate: func(fields *Fields) {
				fields.HolderAgentSessionID = "not-a-uuid"
			},
			want: ErrInvalidHolderAgentSessionID,
		},
		{
			name: "TTL below hard minimum",
			mutate: func(fields *Fields) {
				fields.TTLSeconds = MinTTLSeconds - 1
			},
			want: ErrInvalidTTL,
		},
		{
			name: "TTL above hard maximum",
			mutate: func(fields *Fields) {
				fields.TTLSeconds = MaxTTLSeconds + 1
			},
			want: ErrInvalidTTL,
		},
		{
			name: "unknown status",
			mutate: func(fields *Fields) {
				fields.Status = "unknown"
			},
			want: ErrInvalidStatus,
		},
		{
			name: "active with release reason",
			mutate: func(fields *Fields) {
				fields.ReleaseReason = ReleaseVoluntary
			},
			want: ErrInvalidReleaseReason,
		},
		{
			name: "released without release reason",
			mutate: func(fields *Fields) {
				fields.Status = StatusReleased
			},
			want: ErrInvalidReleaseReason,
		},
		{
			name: "released with unknown reason",
			mutate: func(fields *Fields) {
				fields.Status = StatusReleased
				fields.ReleaseReason = "unknown"
			},
			want: ErrInvalidReleaseReason,
		},
		{
			name: "zero entity version",
			mutate: func(fields *Fields) {
				fields.EntityVersion = 0
			},
			want: ErrInvalidEntityVersion,
		},
		{
			name: "entity version above safe integer",
			mutate: func(fields *Fields) {
				fields.EntityVersion = domain.MaxSafeInteger + 1
			},
			want: ErrInvalidEntityVersion,
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			fields := validFields()
			test.mutate(&fields)
			_, err := New(fields, nil)
			if !errors.Is(err, test.want) {
				t.Fatalf("New() error = %v, want %v", err, test.want)
			}
		})
	}
}

func TestLeaseValidateChecksStoredPatternCanonicalityAndOrdering(t *testing.T) {
	t.Parallel()

	fields := validFields()
	fields.Scope = ScopePath
	lease, err := New(fields, []string{"a", "b/**"})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	tests := []struct {
		name   string
		mutate func(*Lease)
		want   error
	}{
		{
			name: "invalid pattern",
			mutate: func(lease *Lease) {
				lease.pathPatterns[0] = PathPattern{path: domain.RepositoryPath("bad//path")}
			},
			want: ErrInvalidPathPattern,
		},
		{
			name: "unsorted patterns",
			mutate: func(lease *Lease) {
				lease.pathPatterns[0], lease.pathPatterns[1] =
					lease.pathPatterns[1], lease.pathPatterns[0]
			},
			want: ErrPathPatternsNotSortedUnique,
		},
		{
			name: "duplicate patterns",
			mutate: func(lease *Lease) {
				lease.pathPatterns[1] = lease.pathPatterns[0]
			},
			want: ErrPathPatternsNotSortedUnique,
		},
		{
			name: "too many stored patterns",
			mutate: func(lease *Lease) {
				lease.pathPatternCount = MaxPathPatterns + 1
			},
			want: ErrInvalidPathPatternCount,
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			candidate := lease
			test.mutate(&candidate)
			if err := candidate.Validate(); !errors.Is(err, test.want) {
				t.Fatalf("Lease.Validate() error = %v, want %v", err, test.want)
			}
		})
	}
}

func TestValidateRequestedTTLUsesHardAndCommittedBounds(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name          string
		ttl, min, max int64
		want          error
	}{
		{name: "committed minimum", ttl: 60, min: 60, max: 3600},
		{name: "committed maximum", ttl: 3600, min: 60, max: 3600},
		{name: "below committed minimum", ttl: 59, min: 60, max: 3600, want: ErrInvalidTTL},
		{name: "above committed maximum", ttl: 3601, min: 60, max: 3600, want: ErrInvalidTTL},
		{name: "minimum below hard bound", ttl: 30, min: 29, max: 3600, want: ErrInvalidTTLPolicy},
		{name: "minimum above hard bound", ttl: 86400, min: 86401, max: 86401, want: ErrInvalidTTLPolicy},
		{name: "maximum below hard bound", ttl: 30, min: 30, max: 29, want: ErrInvalidTTLPolicy},
		{name: "maximum above hard bound", ttl: 30, min: 30, max: 86401, want: ErrInvalidTTLPolicy},
		{name: "inverted policy range", ttl: 60, min: 120, max: 60, want: ErrInvalidTTLPolicy},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			err := ValidateRequestedTTL(test.ttl, test.min, test.max)
			if !errors.Is(err, test.want) {
				t.Fatalf(
					"ValidateRequestedTTL(%d, %d, %d) error = %v, want %v",
					test.ttl,
					test.min,
					test.max,
					err,
					test.want,
				)
			}
		})
	}
}

func TestEnumCollectionsAreClosedAndDefensivelyCopied(t *testing.T) {
	t.Parallel()

	scopes := Scopes()
	if !reflect.DeepEqual(scopes, []Scope{ScopeTask, ScopePath}) {
		t.Fatalf("Scopes() = %v", scopes)
	}
	scopes[0] = "changed"
	if Scopes()[0] != ScopeTask {
		t.Fatal("Scopes() returned aliased storage")
	}

	statuses := Statuses()
	if !reflect.DeepEqual(statuses, []Status{StatusActive, StatusReleased}) {
		t.Fatalf("Statuses() = %v", statuses)
	}
	statuses[0] = "changed"
	if Statuses()[0] != StatusActive {
		t.Fatal("Statuses() returned aliased storage")
	}

	reasons := ReleaseReasons()
	wantReasons := []ReleaseReason{
		ReleaseVoluntary,
		ReleaseForced,
		ReleaseExpired,
		ReleaseSessionEnded,
		ReleaseRecovery,
	}
	if !reflect.DeepEqual(reasons, wantReasons) {
		t.Fatalf("ReleaseReasons() = %v, want %v", reasons, wantReasons)
	}
	reasons[0] = "changed"
	if ReleaseReasons()[0] != ReleaseVoluntary {
		t.Fatal("ReleaseReasons() returned aliased storage")
	}

	for _, invalid := range []string{"", "TASK", "other"} {
		if Scope(invalid).Valid() {
			t.Errorf("Scope(%q).Valid() = true", invalid)
		}
		if Status(invalid).Valid() {
			t.Errorf("Status(%q).Valid() = true", invalid)
		}
		if ReleaseReason(invalid).Valid() {
			t.Errorf("ReleaseReason(%q).Valid() = true", invalid)
		}
	}
}

func validFields() Fields {
	return Fields{
		ID:                   validLeaseID,
		HolderDeviceID:       validHolderDevice,
		HolderAgentSessionID: validAgentSession,
		Scope:                ScopeTask,
		TaskID:               validTaskID,
		TTLSeconds:           defaultTTLSeconds,
		Status:               StatusActive,
		EntityVersion:        defaultEntity,
	}
}

func patternStrings(patterns []PathPattern) []string {
	result := make([]string, len(patterns))
	for index, pattern := range patterns {
		result[index] = pattern.String()
	}
	return result
}

func repeatedPathComponent(length int) string {
	return strings.Repeat("a", length)
}
