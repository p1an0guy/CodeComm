package task

import (
	"errors"
	"fmt"
	"sort"

	"github.com/ijonahch/codecomm/internal/domain"
)

const DependencyWalkMax = 4_096

var (
	ErrDependencyCycle           = errors.New("task: dependency cycle")
	ErrDependencyNotFound        = errors.New("task: dependency not found")
	ErrDependencyGraphTooComplex = errors.New("task: dependency graph too complex")
)

// DependencyLookup returns the retained blocked_by IDs for one task. The
// boolean is false when the task does not exist in the current session.
type DependencyLookup func(domain.UUIDv7) ([]domain.UUIDv7, bool)

// ValidateDependencyGraph performs the bounded deterministic cycle walk for a
// candidate blocked_by value. The callback supplies committed state; this
// function itself performs no I/O.
func ValidateDependencyGraph(
	subject domain.UUIDv7,
	candidate []domain.UUIDv7,
	lookup DependencyLookup,
) error {
	if !subject.Valid() {
		return fmt.Errorf("%w: %q", ErrInvalidID, subject)
	}
	if err := validateDependencyList(subject, candidate); err != nil {
		return err
	}
	if len(candidate) == 0 {
		return nil
	}
	if lookup == nil {
		return ErrDependencyNotFound
	}

	frontier := append([]domain.UUIDv7(nil), candidate...)
	seen := make(map[domain.UUIDv7]struct{}, min(DependencyWalkMax, len(candidate)))
	for len(frontier) > 0 {
		next := make(map[domain.UUIDv7]struct{})
		for _, id := range frontier {
			if id == subject {
				return fmt.Errorf("%w: %q", ErrDependencyCycle, subject)
			}
			if _, alreadyRead := seen[id]; alreadyRead {
				continue
			}
			if len(seen) == DependencyWalkMax {
				return fmt.Errorf(
					"%w: limit %d",
					ErrDependencyGraphTooComplex,
					DependencyWalkMax,
				)
			}
			seen[id] = struct{}{}

			dependencies, ok := lookup(id)
			if !ok {
				return fmt.Errorf("%w: %q", ErrDependencyNotFound, id)
			}
			if err := validateDependencyList(subject, dependencies); err != nil {
				return err
			}
			for _, dependency := range dependencies {
				if dependency == subject {
					return fmt.Errorf("%w: %q", ErrDependencyCycle, subject)
				}
				if _, alreadyRead := seen[dependency]; !alreadyRead {
					next[dependency] = struct{}{}
				}
			}
		}

		frontier = frontier[:0]
		for id := range next {
			frontier = append(frontier, id)
		}
		sort.Slice(frontier, func(left, right int) bool {
			return frontier[left] < frontier[right]
		})
	}
	return nil
}

func validateDependencyList(subject domain.UUIDv7, dependencies []domain.UUIDv7) error {
	if len(dependencies) > MaxBlockedBy {
		return fmt.Errorf(
			"%w: got %d entries, limit %d",
			ErrInvalidBlockedBy,
			len(dependencies),
			MaxBlockedBy,
		)
	}
	var previous domain.UUIDv7
	for index, dependency := range dependencies {
		if dependency == subject {
			return fmt.Errorf("%w: %q", ErrDependencyCycle, subject)
		}
		if !dependency.Valid() {
			return fmt.Errorf("%w: entry %d is not UUIDv7", ErrInvalidBlockedBy, index)
		}
		if index > 0 && previous >= dependency {
			return fmt.Errorf("%w: entries must be sorted and unique", ErrInvalidBlockedBy)
		}
		previous = dependency
	}
	return nil
}
