package lease

import (
	"errors"
	"testing"

	"github.com/ijonahch/codecomm/internal/domain"
)

func TestActiveLeaseIntersectionByScope(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		left, right Lease
		want        bool
	}{
		{
			name:  "equal task scope",
			left:  mustTaskLease(t, validTaskID),
			right: mustTaskLease(t, validTaskID),
			want:  true,
		},
		{
			name:  "different task scope",
			left:  mustTaskLease(t, validTaskID),
			right: mustTaskLease(t, "01890f47-3e72-7d5a-8c9b-123456789abf"),
		},
		{
			name:  "task and associated path are disjoint",
			left:  mustTaskLease(t, validTaskID),
			right: mustPathLease(t, validTaskID, "src/**"),
		},
		{
			name:  "path exact equality",
			left:  mustPathLease(t, "", "src/main.go"),
			right: mustPathLease(t, "", "src/main.go"),
			want:  true,
		},
		{
			name:  "path prefix contains exact",
			left:  mustPathLease(t, "", "src/**"),
			right: mustPathLease(t, "", "src/main.go"),
			want:  true,
		},
		{
			name:  "path prefix containment across arrays",
			left:  mustPathLease(t, "", "docs/**", "src/pkg/**"),
			right: mustPathLease(t, "", "cmd/**", "src/**"),
			want:  true,
		},
		{
			name:  "disjoint paths despite equal task association",
			left:  mustPathLease(t, validTaskID, "src/**"),
			right: mustPathLease(t, validTaskID, "test/**"),
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			got, err := ActiveLeasesIntersect(test.left, test.right)
			if err != nil {
				t.Fatalf("ActiveLeasesIntersect(left, right) error = %v", err)
			}
			if got != test.want {
				t.Errorf("ActiveLeasesIntersect(left, right) = %t, want %t", got, test.want)
			}
			got, err = ActiveLeasesIntersect(test.right, test.left)
			if err != nil {
				t.Fatalf("ActiveLeasesIntersect(right, left) error = %v", err)
			}
			if got != test.want {
				t.Errorf("ActiveLeasesIntersect(right, left) = %t, want %t", got, test.want)
			}
		})
	}
}

func TestReleasedLeasesAreDisjointAndInvalidLeasesFailClosed(t *testing.T) {
	t.Parallel()

	active := mustPathLease(t, "", "src/**")

	fields := validFields()
	fields.Scope = ScopePath
	fields.Status = StatusReleased
	fields.ReleaseReason = ReleaseExpired
	released, err := New(fields, []string{"src/main.go"})
	if err != nil {
		t.Fatalf("New(released) error = %v", err)
	}

	for _, operands := range [][2]Lease{{active, released}, {released, active}} {
		intersects, err := ActiveLeasesIntersect(operands[0], operands[1])
		if err != nil {
			t.Fatalf("ActiveLeasesIntersect(active, released) error = %v", err)
		}
		if intersects {
			t.Fatal("released lease intersects an active lease")
		}
	}

	invalid := active
	invalid.EntityVersion = 0
	for _, operands := range [][2]Lease{{active, invalid}, {invalid, active}} {
		intersects, err := ActiveLeasesIntersect(operands[0], operands[1])
		if intersects {
			t.Fatal("invalid lease intersects an active lease")
		}
		if !errors.Is(err, ErrInvalidEntityVersion) {
			t.Fatalf(
				"ActiveLeasesIntersect() error = %v, want ErrInvalidEntityVersion",
				err,
			)
		}
	}
}

func mustTaskLease(t *testing.T, taskID domain.UUIDv7) Lease {
	t.Helper()
	fields := validFields()
	fields.Scope = ScopeTask
	fields.TaskID = taskID
	lease, err := New(fields, nil)
	if err != nil {
		t.Fatalf("New(task %q) error = %v", taskID, err)
	}
	return lease
}

func mustPathLease(t *testing.T, taskID domain.UUIDv7, patterns ...string) Lease {
	t.Helper()
	fields := validFields()
	fields.Scope = ScopePath
	fields.TaskID = taskID
	lease, err := New(fields, patterns)
	if err != nil {
		t.Fatalf("New(path %v) error = %v", patterns, err)
	}
	return lease
}
