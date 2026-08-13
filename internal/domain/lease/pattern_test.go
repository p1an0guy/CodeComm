package lease

import (
	"errors"
	"reflect"
	"sort"
	"testing"

	"github.com/ijonahch/codecomm/internal/domain"
)

func TestParsePathPatternAcceptsExactAndTerminalPrefixForms(t *testing.T) {
	t.Parallel()

	tests := []struct {
		text   string
		path   domain.RepositoryPath
		prefix bool
	}{
		{text: "README.md", path: "README.md"},
		{text: "src/[ab]", path: "src/[ab]"},
		{text: "src/pkg/file.go", path: "src/pkg/file.go"},
		{text: "src/**", path: "src", prefix: true},
		{text: "src/pkg/**", path: "src/pkg", prefix: true},
		{text: repeatedPathComponent(domain.MaxRepositoryPathBytes), path: domain.RepositoryPath(repeatedPathComponent(domain.MaxRepositoryPathBytes))},
		{
			text:   repeatedPathComponent(MaxPathPatternBytes-len("/**")) + "/**",
			path:   domain.RepositoryPath(repeatedPathComponent(MaxPathPatternBytes - len("/**"))),
			prefix: true,
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.text[:min(len(test.text), 32)], func(t *testing.T) {
			t.Parallel()
			got, err := ParsePathPattern(test.text)
			if err != nil {
				t.Fatalf("ParsePathPattern(%q) error = %v", test.text, err)
			}
			if !got.Valid() {
				t.Fatalf("ParsePathPattern(%q).Valid() = false", test.text)
			}
			if got.String() != test.text {
				t.Fatalf("PathPattern.String() = %q, want %q", got.String(), test.text)
			}
			if got.Path() != test.path {
				t.Fatalf("PathPattern.Path() = %q, want %q", got.Path(), test.path)
			}
			if got.Prefix() != test.prefix {
				t.Fatalf("PathPattern.Prefix() = %t, want %t", got.Prefix(), test.prefix)
			}
		})
	}
}

func TestParsePathPatternRejectsNoncanonicalAndGeneralGlobForms(t *testing.T) {
	t.Parallel()

	tests := []string{
		"",
		"/**",
		"src/",
		"src//file",
		"src/../file",
		"src/*",
		"src/?",
		"src/**/file",
		"src/**/**",
		"src\\file",
		"src/\u0065\u0301",
		repeatedPathComponent(MaxPathPatternBytes-len("/**")+1) + "/**",
	}

	for _, input := range tests {
		input := input
		t.Run(input[:min(len(input), 32)], func(t *testing.T) {
			t.Parallel()
			got, err := ParsePathPattern(input)
			if !errors.Is(err, ErrInvalidPathPattern) {
				t.Fatalf("ParsePathPattern(%q) error = %v, want %v", input, err, ErrInvalidPathPattern)
			}
			if got != (PathPattern{}) {
				t.Fatalf("ParsePathPattern(%q) = %#v after error, want zero value", input, got)
			}
		})
	}
}

func TestNormalizePathPatternsSortsDeduplicatesAndDoesNotAlias(t *testing.T) {
	t.Parallel()

	input := []string{"src/**", "README.md", "src/**", "cmd/main.go"}
	got, err := NormalizePathPatterns(input)
	if err != nil {
		t.Fatalf("NormalizePathPatterns() error = %v", err)
	}
	want := []string{"README.md", "cmd/main.go", "src/**"}
	if stringsGot := patternStrings(got); !reflect.DeepEqual(stringsGot, want) {
		t.Fatalf("NormalizePathPatterns() = %v, want %v", stringsGot, want)
	}
	if !sort.SliceIsSorted(got, func(i, j int) bool {
		return got[i].String() < got[j].String()
	}) {
		t.Fatalf("NormalizePathPatterns() = %v, want sorted values", patternStrings(got))
	}

	input[0] = "changed"
	got[0] = PathPattern{}
	if input[1] != "README.md" {
		t.Fatalf("NormalizePathPatterns() aliased input: %v", input)
	}
}

func TestNormalizePathPatternsValidatesRawCountBeforeDeduplication(t *testing.T) {
	t.Parallel()

	if _, err := NormalizePathPatterns(nil); !errors.Is(err, ErrInvalidPathPatternCount) {
		t.Fatalf("NormalizePathPatterns(nil) error = %v, want %v", err, ErrInvalidPathPatternCount)
	}

	maximum := make([]string, MaxPathPatterns)
	for index := range maximum {
		maximum[index] = "duplicate"
	}
	got, err := NormalizePathPatterns(maximum)
	if err != nil {
		t.Fatalf("NormalizePathPatterns(max duplicates) error = %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("NormalizePathPatterns(max duplicates) length = %d, want 1", len(got))
	}

	over := append(append([]string(nil), maximum...), "duplicate")
	if _, err := NormalizePathPatterns(over); !errors.Is(err, ErrInvalidPathPatternCount) {
		t.Fatalf("NormalizePathPatterns(over limit) error = %v, want %v", err, ErrInvalidPathPatternCount)
	}
}

func TestPathPatternIntersectionIsSymmetricAndComponentAware(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		left, right string
		want        bool
	}{
		{name: "equal exact", left: "src/main.go", right: "src/main.go", want: true},
		{name: "different exact", left: "src/main.go", right: "src/other.go"},
		{name: "prefix contains exact", left: "src/**", right: "src/main.go", want: true},
		{name: "exact equals prefix root", left: "src", right: "src/**", want: true},
		{name: "exact contains no descendant", left: "src", right: "src/main.go"},
		{name: "prefix contains prefix", left: "src/**", right: "src/pkg/**", want: true},
		{name: "nested prefix reverse", left: "src/pkg/**", right: "src/**", want: true},
		{name: "component boundary", left: "src/**", right: "src2/main.go"},
		{name: "disjoint prefixes", left: "src/**", right: "test/**"},
		{name: "case sensitive", left: "src/**", right: "Src/main.go"},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			left := mustPattern(t, test.left)
			right := mustPattern(t, test.right)
			if got := left.Intersects(right); got != test.want {
				t.Errorf("%q.Intersects(%q) = %t, want %t", test.left, test.right, got, test.want)
			}
			if got := right.Intersects(left); got != test.want {
				t.Errorf("%q.Intersects(%q) = %t, want %t", test.right, test.left, got, test.want)
			}
		})
	}
}

func TestInvalidPathPatternsNeverIntersect(t *testing.T) {
	t.Parallel()

	valid := mustPattern(t, "src/**")
	if (PathPattern{}).Intersects(valid) {
		t.Fatal("zero PathPattern intersects a valid pattern")
	}
	if valid.Intersects(PathPattern{}) {
		t.Fatal("valid pattern intersects zero PathPattern")
	}
}

func mustPattern(t *testing.T, text string) PathPattern {
	t.Helper()
	pattern, err := ParsePathPattern(text)
	if err != nil {
		t.Fatalf("ParsePathPattern(%q) error = %v", text, err)
	}
	return pattern
}
