package domain

import "errors"

var (
	ErrInvalidGitOID     = errors.New("domain: invalid algorithm-tagged Git OID")
	ErrInvalidConflictID = errors.New("domain: invalid conflict ID")
)

// GitObjectFormat is the repository's immutable Git object format.
type GitObjectFormat string

const (
	GitObjectSHA1   GitObjectFormat = "sha1"
	GitObjectSHA256 GitObjectFormat = "sha256"
)

// Valid reports whether format is supported by V1.
func (format GitObjectFormat) Valid() bool {
	return format == GitObjectSHA1 || format == GitObjectSHA256
}

// GitOID is a lowercase, algorithm-tagged full Git object identifier.
type GitOID string

// ParseGitOID validates a V1 algorithm-tagged Git object identifier.
func ParseGitOID(text string) (GitOID, error) {
	oid := GitOID(text)
	if !oid.Valid() {
		return "", ErrInvalidGitOID
	}
	return oid, nil
}

// Valid reports whether oid is exactly sha1:<40 hex> or sha256:<64 hex>.
func (oid GitOID) Valid() bool {
	text := string(oid)
	switch {
	case len(text) == len("sha1:")+40 && text[:len("sha1:")] == "sha1:":
		return allLowerHex(text[len("sha1:"):])
	case len(text) == len("sha256:")+64 && text[:len("sha256:")] == "sha256:":
		return allLowerHex(text[len("sha256:"):])
	default:
		return false
	}
}

// ObjectFormat returns oid's algorithm, or the zero value for an invalid OID.
func (oid GitOID) ObjectFormat() GitObjectFormat {
	if !oid.Valid() {
		return ""
	}
	if len(oid) == len("sha1:")+40 {
		return GitObjectSHA1
	}
	return GitObjectSHA256
}

// Hex returns the untagged object ID, or an empty string for an invalid OID.
func (oid GitOID) Hex() string {
	if !oid.Valid() {
		return ""
	}
	if oid.ObjectFormat() == GitObjectSHA1 {
		return string(oid[len("sha1:"):])
	}
	return string(oid[len("sha256:"):])
}

// ConflictID is "ccf1" followed by a full lowercase SHA-256 digest.
type ConflictID string

// ParseConflictID validates a deterministic V1 conflict identifier.
func ParseConflictID(text string) (ConflictID, error) {
	id := ConflictID(text)
	if !id.Valid() {
		return "", ErrInvalidConflictID
	}
	return id, nil
}

// Valid reports whether id is exactly ccf1 followed by 64 lowercase hex
// characters.
func (id ConflictID) Valid() bool {
	text := string(id)
	return len(text) == len("ccf1")+64 &&
		text[:len("ccf1")] == "ccf1" &&
		allLowerHex(text[len("ccf1"):])
}

func allLowerHex(text string) bool {
	for index := range len(text) {
		if !isLowerHex(text[index]) {
			return false
		}
	}
	return true
}
