package task

import (
	"errors"
	"fmt"
	"reflect"
	"testing"

	"github.com/ijonahch/codecomm/internal/domain"
)

func TestValidateDependencyGraphVisitsBreadthFirstInSortedOrder(t *testing.T) {
	t.Parallel()

	subject := dependencyID(0)
	graph := map[domain.UUIDv7][]domain.UUIDv7{
		dependencyID(1): {dependencyID(3), dependencyID(4)},
		dependencyID(2): {dependencyID(4), dependencyID(5)},
		dependencyID(3): nil,
		dependencyID(4): {dependencyID(6)},
		dependencyID(5): nil,
		dependencyID(6): nil,
	}
	candidate := []domain.UUIDv7{dependencyID(1), dependencyID(2)}
	var visited []domain.UUIDv7

	err := ValidateDependencyGraph(subject, candidate, func(id domain.UUIDv7) ([]domain.UUIDv7, bool) {
		visited = append(visited, id)
		dependencies, ok := graph[id]
		return dependencies, ok
	})
	if err != nil {
		t.Fatalf("ValidateDependencyGraph() error = %v", err)
	}
	want := []domain.UUIDv7{
		dependencyID(1),
		dependencyID(2),
		dependencyID(3),
		dependencyID(4),
		dependencyID(5),
		dependencyID(6),
	}
	if !reflect.DeepEqual(visited, want) {
		t.Fatalf("visit order = %v, want %v", visited, want)
	}
}

func TestValidateDependencyGraphAcceptsExactWalkLimit(t *testing.T) {
	t.Parallel()

	subject := dependencyID(0)
	candidate := []domain.UUIDv7{dependencyID(1)}
	lookups := 0
	err := ValidateDependencyGraph(subject, candidate, func(id domain.UUIDv7) ([]domain.UUIDv7, bool) {
		lookups++
		index := dependencyIndex(id)
		if index < DependencyWalkMax {
			return []domain.UUIDv7{dependencyID(index + 1)}, true
		}
		return nil, true
	})
	if err != nil {
		t.Fatalf("ValidateDependencyGraph(exact limit) error = %v", err)
	}
	if lookups != DependencyWalkMax {
		t.Fatalf("lookups = %d, want %d", lookups, DependencyWalkMax)
	}
}

func TestValidateDependencyGraphRejectsBeforeReadingOnePastLimit(t *testing.T) {
	t.Parallel()

	subject := dependencyID(0)
	candidate := []domain.UUIDv7{dependencyID(1)}
	lookups := 0
	err := ValidateDependencyGraph(subject, candidate, func(id domain.UUIDv7) ([]domain.UUIDv7, bool) {
		lookups++
		index := dependencyIndex(id)
		return []domain.UUIDv7{dependencyID(index + 1)}, true
	})
	if !errors.Is(err, ErrDependencyGraphTooComplex) {
		t.Fatalf("ValidateDependencyGraph() error = %v, want ErrDependencyGraphTooComplex", err)
	}
	if lookups != DependencyWalkMax {
		t.Fatalf("lookups = %d, want %d before rejection", lookups, DependencyWalkMax)
	}
}

func TestValidateDependencyGraphCycleAtLastAllowedRowWins(t *testing.T) {
	t.Parallel()

	subject := dependencyID(0)
	candidate := []domain.UUIDv7{dependencyID(1)}
	lookups := 0
	err := ValidateDependencyGraph(subject, candidate, func(id domain.UUIDv7) ([]domain.UUIDv7, bool) {
		lookups++
		index := dependencyIndex(id)
		if index == DependencyWalkMax {
			return []domain.UUIDv7{subject, dependencyID(index + 1)}, true
		}
		return []domain.UUIDv7{dependencyID(index + 1)}, true
	})
	if !errors.Is(err, ErrDependencyCycle) {
		t.Fatalf("ValidateDependencyGraph() error = %v, want ErrDependencyCycle", err)
	}
	if lookups != DependencyWalkMax {
		t.Fatalf("lookups = %d, want %d", lookups, DependencyWalkMax)
	}
}

func TestValidateDependencyGraphRejectsDirectAndIndirectCycles(t *testing.T) {
	t.Parallel()

	subject := dependencyID(0)
	tests := []struct {
		name      string
		candidate []domain.UUIDv7
		graph     map[domain.UUIDv7][]domain.UUIDv7
	}{
		{
			name:      "direct",
			candidate: []domain.UUIDv7{subject},
		},
		{
			name:      "indirect",
			candidate: []domain.UUIDv7{dependencyID(1)},
			graph: map[domain.UUIDv7][]domain.UUIDv7{
				dependencyID(1): {dependencyID(2)},
				dependencyID(2): {subject},
			},
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			err := ValidateDependencyGraph(
				subject,
				test.candidate,
				func(id domain.UUIDv7) ([]domain.UUIDv7, bool) {
					dependencies, ok := test.graph[id]
					return dependencies, ok
				},
			)
			if !errors.Is(err, ErrDependencyCycle) {
				t.Fatalf("ValidateDependencyGraph() error = %v, want ErrDependencyCycle", err)
			}
		})
	}
}

func TestValidateDependencyGraphRejectsMissingAndMalformedRows(t *testing.T) {
	t.Parallel()

	subject := dependencyID(0)
	tests := []struct {
		name      string
		candidate []domain.UUIDv7
		lookup    DependencyLookup
		want      error
	}{
		{
			name:      "nil lookup",
			candidate: []domain.UUIDv7{dependencyID(1)},
			want:      ErrDependencyNotFound,
		},
		{
			name:      "missing task",
			candidate: []domain.UUIDv7{dependencyID(1)},
			lookup: func(domain.UUIDv7) ([]domain.UUIDv7, bool) {
				return nil, false
			},
			want: ErrDependencyNotFound,
		},
		{
			name:      "malformed candidate ID",
			candidate: []domain.UUIDv7{"bad"},
			lookup: func(domain.UUIDv7) ([]domain.UUIDv7, bool) {
				return nil, true
			},
			want: ErrInvalidBlockedBy,
		},
		{
			name:      "unsorted candidate",
			candidate: []domain.UUIDv7{dependencyID(2), dependencyID(1)},
			lookup: func(domain.UUIDv7) ([]domain.UUIDv7, bool) {
				return nil, true
			},
			want: ErrInvalidBlockedBy,
		},
		{
			name:      "malformed retained row",
			candidate: []domain.UUIDv7{dependencyID(1)},
			lookup: func(domain.UUIDv7) ([]domain.UUIDv7, bool) {
				return []domain.UUIDv7{"bad"}, true
			},
			want: ErrInvalidBlockedBy,
		},
		{
			name:      "oversized retained row",
			candidate: []domain.UUIDv7{dependencyID(1)},
			lookup: func(domain.UUIDv7) ([]domain.UUIDv7, bool) {
				return makeDependencyIDs(MaxBlockedBy+1, 10), true
			},
			want: ErrInvalidBlockedBy,
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			err := ValidateDependencyGraph(subject, test.candidate, test.lookup)
			if !errors.Is(err, test.want) {
				t.Fatalf("ValidateDependencyGraph() error = %v, want %v", err, test.want)
			}
		})
	}
}

func dependencyID(index int) domain.UUIDv7 {
	return domain.UUIDv7(fmt.Sprintf("01890f47-3e72-7d5a-8c9b-%012d", index))
}

func dependencyIndex(id domain.UUIDv7) int {
	var index int
	if _, err := fmt.Sscanf(string(id), "01890f47-3e72-7d5a-8c9b-%012d", &index); err != nil {
		panic(err)
	}
	return index
}

func makeDependencyIDs(count, offset int) []domain.UUIDv7 {
	result := make([]domain.UUIDv7, count)
	for index := range result {
		result[index] = dependencyID(offset + index)
	}
	return result
}
