package controlpath

import (
	"testing"

	"github.com/ijonahch/codecomm/internal/domain"
)

func TestIsControlledV1(t *testing.T) {
	t.Parallel()

	tests := []struct {
		path domain.RepositoryPath
		want bool
	}{
		{path: "AGENTS.md", want: true},
		{path: "docs/agents.override.md", want: true},
		{path: "nested/CLAUDE.md", want: true},
		{path: ".GitIgnore", want: true},
		{path: ".CODEX", want: true},
		{path: ".codex/config.toml", want: true},
		{path: ".Claude/settings.json", want: true},
		{path: ".MCP.JSON", want: true},
		{path: ".codecommignore/child", want: true},
		{path: "src/agents.md.go", want: false},
		{path: "nested/.codex/config.toml", want: false},
		{path: "README.md", want: false},
		{path: "", want: false},
	}
	for _, test := range tests {
		test := test
		t.Run(string(test.path), func(t *testing.T) {
			t.Parallel()
			if got := IsControlledV1(test.path); got != test.want {
				t.Fatalf("IsControlledV1(%q) = %v, want %v", test.path, got, test.want)
			}
		})
	}
}
