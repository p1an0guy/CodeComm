// Package controlpath defines the immutable V1 classifier for repository
// files whose content requires per-device approval.
package controlpath

import (
	"strings"

	"github.com/ijonahch/codecomm/internal/domain"
)

const PolicyVersion uint64 = 1

// IsControlledV1 reports whether path is a version-1 control path. Matching
// folds ASCII only; canonical path identity remains case-sensitive elsewhere.
func IsControlledV1(path domain.RepositoryPath) bool {
	if !path.Valid() {
		return false
	}
	folded := foldASCII(string(path))
	base := folded
	if separator := strings.LastIndexByte(folded, '/'); separator >= 0 {
		base = folded[separator+1:]
	}
	switch base {
	case "agents.md", "agents.override.md", "claude.md", ".gitignore":
		return true
	}
	for _, root := range [...]string{
		".codex",
		".claude",
		".mcp.json",
		".codecommignore",
	} {
		if folded == root || strings.HasPrefix(folded, root+"/") {
			return true
		}
	}
	return false
}

func foldASCII(value string) string {
	var builder strings.Builder
	builder.Grow(len(value))
	for _, character := range value {
		if character >= 'A' && character <= 'Z' {
			character += 'a' - 'A'
		}
		builder.WriteRune(character)
	}
	return builder.String()
}
