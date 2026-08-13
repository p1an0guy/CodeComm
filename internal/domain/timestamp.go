package domain

import (
	"errors"
	"time"
)

var (
	ErrInvalidTimestamp            = errors.New("domain: invalid canonical RFC 3339 timestamp")
	ErrInvalidWholeSecondTimestamp = errors.New("domain: invalid whole-second UTC RFC 3339 timestamp")
)

// Timestamp is canonical UTC RFC 3339 text with zero or 1-9 fractional
// second digits. A nonzero fraction has no trailing zero.
type Timestamp string

// ParseTimestamp validates canonical fractional-or-whole-second timestamp
// text.
func ParseTimestamp(text string) (Timestamp, error) {
	timestamp := Timestamp(text)
	if !timestamp.Valid() {
		return "", ErrInvalidTimestamp
	}
	return timestamp, nil
}

// Valid reports whether timestamp uses CodeComm's canonical UTC RFC 3339
// representation.
func (timestamp Timestamp) Valid() bool {
	_, err := parseCanonicalTimestamp(string(timestamp), false)
	return err == nil
}

// Time returns the represented UTC instant.
func (timestamp Timestamp) Time() (time.Time, error) {
	value, err := parseCanonicalTimestamp(string(timestamp), false)
	if err != nil {
		return time.Time{}, ErrInvalidTimestamp
	}
	return value, nil
}

// WholeSecondTimestamp is exactly YYYY-MM-DDTHH:MM:SSZ.
type WholeSecondTimestamp string

// ParseWholeSecondTimestamp validates a canonical whole-second timestamp.
func ParseWholeSecondTimestamp(text string) (WholeSecondTimestamp, error) {
	timestamp := WholeSecondTimestamp(text)
	if !timestamp.Valid() {
		return "", ErrInvalidWholeSecondTimestamp
	}
	return timestamp, nil
}

// Valid reports whether timestamp is canonical whole-second UTC text.
func (timestamp WholeSecondTimestamp) Valid() bool {
	_, err := parseCanonicalTimestamp(string(timestamp), true)
	return err == nil
}

// Time returns the represented UTC instant.
func (timestamp WholeSecondTimestamp) Time() (time.Time, error) {
	value, err := parseCanonicalTimestamp(string(timestamp), true)
	if err != nil {
		return time.Time{}, ErrInvalidWholeSecondTimestamp
	}
	return value, nil
}

func parseCanonicalTimestamp(text string, wholeSeconds bool) (time.Time, error) {
	if wholeSeconds && len(text) != len("2006-01-02T15:04:05Z") {
		return time.Time{}, ErrInvalidWholeSecondTimestamp
	}
	value, err := time.Parse(time.RFC3339Nano, text)
	if err != nil || value.Location() != time.UTC || value.Format(time.RFC3339Nano) != text {
		if wholeSeconds {
			return time.Time{}, ErrInvalidWholeSecondTimestamp
		}
		return time.Time{}, ErrInvalidTimestamp
	}
	return value, nil
}
