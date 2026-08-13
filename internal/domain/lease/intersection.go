package lease

import "fmt"

// ActiveLeasesIntersect reports whether two active leases reserve an
// overlapping V1 scope. Invalid operands return an error so an apply-time
// overlap check cannot silently treat malformed state as disjoint.
func ActiveLeasesIntersect(left, right Lease) (bool, error) {
	if err := left.Validate(); err != nil {
		return false, fmt.Errorf("lease: invalid left intersection operand: %w", err)
	}
	if err := right.Validate(); err != nil {
		return false, fmt.Errorf("lease: invalid right intersection operand: %w", err)
	}
	if left.Status != StatusActive || right.Status != StatusActive {
		return false, nil
	}

	if left.Scope == ScopeTask && right.Scope == ScopeTask {
		return left.TaskID == right.TaskID, nil
	}
	if left.Scope != ScopePath || right.Scope != ScopePath {
		return false, nil
	}

	for leftIndex := 0; leftIndex < int(left.pathPatternCount); leftIndex++ {
		for rightIndex := 0; rightIndex < int(right.pathPatternCount); rightIndex++ {
			if left.pathPatterns[leftIndex].Intersects(right.pathPatterns[rightIndex]) {
				return true, nil
			}
		}
	}
	return false, nil
}
