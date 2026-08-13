package lease

import (
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/ijonahch/codecomm/internal/domain"
)

const MaxPathPatternBytes = domain.MaxRepositoryPathBytes

var (
	ErrInvalidPathPatternCount     = errors.New("lease: invalid path-pattern count")
	ErrInvalidPathPattern          = errors.New("lease: invalid path pattern")
	ErrPathPatternsNotSortedUnique = errors.New("lease: path patterns are not sorted and unique")
)

// PathPattern is either one exact canonical repository path or a canonical
// directory path followed by the sole V1 wildcard form "/**".
type PathPattern struct {
	path   domain.RepositoryPath
	prefix bool
}

// ParsePathPattern validates and returns an exact or terminal-prefix pattern.
func ParsePathPattern(text string) (PathPattern, error) {
	if len(text) < 1 || len(text) > MaxPathPatternBytes {
		return PathPattern{}, fmt.Errorf(
			"%w: byte length must be 1..%d",
			ErrInvalidPathPattern,
			MaxPathPatternBytes,
		)
	}

	pathText := text
	prefix := strings.HasSuffix(text, "/**")
	if prefix {
		pathText = strings.TrimSuffix(text, "/**")
	}
	path, err := domain.ParseRepositoryPath(pathText)
	if err != nil {
		return PathPattern{}, fmt.Errorf("%w: %q", ErrInvalidPathPattern, text)
	}
	return PathPattern{path: path, prefix: prefix}, nil
}

// Valid reports whether pattern is a canonical exact or terminal-prefix
// pattern.
func (pattern PathPattern) Valid() bool {
	if !pattern.path.Valid() {
		return false
	}
	return len(pattern.String()) <= MaxPathPatternBytes
}

// String returns the canonical textual pattern.
func (pattern PathPattern) String() string {
	if pattern.path == "" {
		return ""
	}
	if pattern.prefix {
		return string(pattern.path) + "/**"
	}
	return string(pattern.path)
}

// Path returns the exact path or the directory at the root of a prefix.
func (pattern PathPattern) Path() domain.RepositoryPath {
	return pattern.path
}

// Prefix reports whether pattern reserves its path and all descendants.
func (pattern PathPattern) Prefix() bool {
	return pattern.prefix
}

// Intersects reports whether two valid patterns overlap under the finite V1
// exact/terminal-prefix grammar.
func (pattern PathPattern) Intersects(other PathPattern) bool {
	if !pattern.Valid() || !other.Valid() {
		return false
	}
	if !pattern.prefix && !other.prefix {
		return pattern.path == other.path
	}
	if pattern.prefix && pattern.path.Contains(other.path) {
		return true
	}
	return other.prefix && other.path.Contains(pattern.path)
}

// NormalizePathPatterns validates raw cardinality and every value before
// returning a separately allocated, sorted, deduplicated slice.
func NormalizePathPatterns(raw []string) ([]PathPattern, error) {
	if len(raw) < 1 || len(raw) > MaxPathPatterns {
		return nil, fmt.Errorf(
			"%w: got %d, want 1..%d",
			ErrInvalidPathPatternCount,
			len(raw),
			MaxPathPatterns,
		)
	}

	result := make([]PathPattern, len(raw))
	for index, text := range raw {
		pattern, err := ParsePathPattern(text)
		if err != nil {
			return nil, fmt.Errorf("%w: entry %d", err, index)
		}
		result[index] = pattern
	}
	sort.Slice(result, func(i, j int) bool {
		return result[i].String() < result[j].String()
	})

	write := 1
	for read := 1; read < len(result); read++ {
		if result[read] == result[write-1] {
			continue
		}
		result[write] = result[read]
		write++
	}
	return result[:write], nil
}
