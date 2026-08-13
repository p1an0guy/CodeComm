package domain

import (
	"errors"
	"strings"
	"testing"
)

func TestParseRepositoryPathAcceptsCanonicalBoundaries(t *testing.T) {
	t.Parallel()

	tests := []string{
		"a",
		"src/main.go",
		"Case/Preserved.TXT",
		"café/日本語.txt",
		".git/config",
		strings.Repeat("a", MaxRepositoryPathBytes),
		"console/auxiliary/com10/lpt0",
	}
	for _, input := range tests {
		input := input
		t.Run(input[:min(len(input), 32)], func(t *testing.T) {
			t.Parallel()
			got, err := ParseRepositoryPath(input)
			if err != nil {
				t.Fatalf("ParseRepositoryPath(%q) error = %v", input, err)
			}
			if got != RepositoryPath(input) || !got.Valid() {
				t.Fatalf("ParseRepositoryPath(%q) = %q, valid = %t", input, got, got.Valid())
			}
		})
	}
}

func TestParseRepositoryPathRejectsNoncanonicalForms(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		input string
	}{
		{name: "empty", input: ""},
		{name: "over byte limit", input: strings.Repeat("a", MaxRepositoryPathBytes+1)},
		{name: "invalid UTF-8", input: string([]byte{0xff})},
		{name: "not NFC", input: "cafe\u0301.txt"},
		{name: "absolute", input: "/src/main.go"},
		{name: "UNC", input: "//server/share"},
		{name: "drive", input: "C:/src/main.go"},
		{name: "backslash", input: `src\main.go`},
		{name: "empty component", input: "src//main.go"},
		{name: "trailing separator", input: "src/"},
		{name: "dot component", input: "src/./main.go"},
		{name: "parent component", input: "src/../main.go"},
		{name: "NUL", input: "src/\x00main.go"},
		{name: "control", input: "src/\u007fmain.go"},
		{name: "trailing dot", input: "src/name."},
		{name: "trailing space", input: "src/name "},
		{name: "ADS", input: "src/name:stream"},
		{name: "less than", input: "src/<name"},
		{name: "greater than", input: "src/>name"},
		{name: "quote", input: "src/\"name"},
		{name: "pipe", input: "src/|name"},
		{name: "question", input: "src/?name"},
		{name: "asterisk", input: "src/*name"},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			got, err := ParseRepositoryPath(test.input)
			if !errors.Is(err, ErrInvalidRepositoryPath) {
				t.Fatalf(
					"ParseRepositoryPath(%q) error = %v, want ErrInvalidRepositoryPath",
					test.input,
					err,
				)
			}
			if got != "" {
				t.Fatalf("ParseRepositoryPath(%q) = %q after error, want zero value", test.input, got)
			}
			if RepositoryPath(test.input).Valid() {
				t.Fatalf("RepositoryPath(%q).Valid() = true", test.input)
			}
		})
	}
}

func TestParseRepositoryPathRejectsWindowsReservedComponents(t *testing.T) {
	t.Parallel()

	reserved := []string{
		"CON",
		"con.txt",
		"PrN",
		"aux.json",
		"NUL",
		"COM1",
		"com9.log",
		"LPT1",
		"lpt9.txt",
		"COM¹",
		"com².txt",
		"LPT³",
		"CONIN$",
		"conout$.txt",
	}
	for _, component := range reserved {
		component := component
		t.Run(component, func(t *testing.T) {
			t.Parallel()
			input := "src/" + component + "/file"
			if _, err := ParseRepositoryPath(input); !errors.Is(err, ErrInvalidRepositoryPath) {
				t.Fatalf("ParseRepositoryPath(%q) error = %v, want ErrInvalidRepositoryPath", input, err)
			}
		})
	}
}

func TestRepositoryPathContainsUsesComponentBoundaries(t *testing.T) {
	t.Parallel()

	dir := RepositoryPath("src/pkg")
	tests := []struct {
		path RepositoryPath
		want bool
	}{
		{path: "src/pkg", want: true},
		{path: "src/pkg/file.go", want: true},
		{path: "src/package/file.go", want: false},
		{path: "src/pk", want: false},
		{path: "other/src/pkg", want: false},
		{path: "invalid//path", want: false},
	}
	for _, test := range tests {
		if got := dir.Contains(test.path); got != test.want {
			t.Errorf("%q.Contains(%q) = %t, want %t", dir, test.path, got, test.want)
		}
	}
	if RepositoryPath("invalid//path").Contains("invalid/path") {
		t.Fatal("invalid directory contains a canonical path")
	}
}

func TestRepositoryPathComponentsReturnsDefensiveCopy(t *testing.T) {
	t.Parallel()

	path := RepositoryPath("src/pkg/file.go")
	got := path.Components()
	want := []string{"src", "pkg", "file.go"}
	if strings.Join(got, "/") != strings.Join(want, "/") {
		t.Fatalf("RepositoryPath.Components() = %v, want %v", got, want)
	}
	got[0] = "changed"
	if path != "src/pkg/file.go" {
		t.Fatalf("mutating Components() changed path to %q", path)
	}
	if got := RepositoryPath("invalid//path").Components(); got != nil {
		t.Fatalf("invalid RepositoryPath.Components() = %v, want nil", got)
	}
}
