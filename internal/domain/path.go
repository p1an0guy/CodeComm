package domain

import (
	"errors"
	"strings"
	"unicode"
	"unicode/utf8"

	"golang.org/x/text/unicode/norm"
)

const MaxRepositoryPathBytes = 512

var ErrInvalidRepositoryPath = errors.New("domain: invalid canonical repository path")

// RepositoryPath is a case-sensitive NFC UTF-8 path relative to a repository
// root. Slash is its only separator.
type RepositoryPath string

// ParseRepositoryPath validates a canonical repository path.
func ParseRepositoryPath(text string) (RepositoryPath, error) {
	path := RepositoryPath(text)
	if !path.Valid() {
		return "", ErrInvalidRepositoryPath
	}
	return path, nil
}

// Valid reports whether path satisfies the platform-independent V1 grammar.
func (path RepositoryPath) Valid() bool {
	text := string(path)
	if len(text) < 1 ||
		len(text) > MaxRepositoryPathBytes ||
		!utf8.ValidString(text) ||
		!norm.NFC.IsNormalString(text) ||
		text[0] == '/' {
		return false
	}

	components := strings.Split(text, "/")
	for _, component := range components {
		if !validPathComponent(component) {
			return false
		}
	}
	return true
}

// Components returns a copy of path's components, or nil when path is
// invalid.
func (path RepositoryPath) Components() []string {
	if !path.Valid() {
		return nil
	}
	return strings.Split(string(path), "/")
}

// Contains reports whether candidate is path itself or one of its
// descendants.
func (path RepositoryPath) Contains(candidate RepositoryPath) bool {
	if !path.Valid() || !candidate.Valid() {
		return false
	}
	return candidate == path || strings.HasPrefix(string(candidate), string(path)+"/")
}

func validPathComponent(component string) bool {
	if component == "" ||
		component == "." ||
		component == ".." ||
		component[len(component)-1] == '.' ||
		component[len(component)-1] == ' ' ||
		windowsReservedComponent(component) {
		return false
	}
	for _, char := range component {
		if unicode.IsControl(char) || strings.ContainsRune(`\<>:"|?*`, char) {
			return false
		}
	}
	return true
}

func windowsReservedComponent(component string) bool {
	base, _, _ := strings.Cut(component, ".")
	base = foldASCII(base)
	switch base {
	case "con", "prn", "aux", "nul", "clock$", "conin$", "conout$",
		"com1", "com2", "com3", "com4", "com5", "com6", "com7", "com8", "com9",
		"lpt1", "lpt2", "lpt3", "lpt4", "lpt5", "lpt6", "lpt7", "lpt8", "lpt9",
		"com¹", "com²", "com³", "lpt¹", "lpt²", "lpt³":
		return true
	default:
		return false
	}
}

func foldASCII(text string) string {
	var builder strings.Builder
	builder.Grow(len(text))
	for _, char := range text {
		if char >= 'A' && char <= 'Z' {
			char += 'a' - 'A'
		}
		builder.WriteRune(char)
	}
	return builder.String()
}
