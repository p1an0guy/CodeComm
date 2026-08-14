package pairinghttp

import (
	"testing"
	"time"

	"golang.org/x/net/http2"
)

func TestHTTP2DeadlineStateTracksEveryHeaderBlock(t *testing.T) {
	t.Parallel()

	const (
		headerTimeout = 10 * time.Second
		noProgress    = 30 * time.Second
	)
	now := time.Unix(1_700_000_000, 0)
	initialDeadline := now.Add(headerTimeout)
	state := http2DeadlineState{
		prefaceRemaining: len(http2.ClientPreface),
		phaseDeadline:    initialDeadline,
	}
	preface := []byte(http2.ClientPreface)
	state.observe(
		preface[:len(preface)-1],
		now,
		headerTimeout,
		noProgress,
	)
	if !state.phaseDeadline.Equal(initialDeadline) {
		t.Fatalf(
			"partial preface deadline = %s, want %s",
			state.phaseDeadline,
			initialDeadline,
		)
	}
	state.observe(
		preface[len(preface)-1:],
		now,
		headerTimeout,
		noProgress,
	)
	if !state.phaseDeadline.IsZero() {
		t.Fatalf("completed preface deadline = %s, want zero", state.phaseDeadline)
	}

	firstHeaderAt := now.Add(time.Minute)
	headers := testHTTP2Frame(
		2,
		http2FrameTypeHeaders,
		0,
		[]byte{0x01, 0x02},
	)
	state.observe(
		headers[:1],
		firstHeaderAt,
		headerTimeout,
		noProgress,
	)
	firstHeaderDeadline := firstHeaderAt.Add(headerTimeout)
	if !state.phaseDeadline.Equal(firstHeaderDeadline) {
		t.Fatalf(
			"first header deadline = %s, want %s",
			state.phaseDeadline,
			firstHeaderDeadline,
		)
	}
	state.observe(
		headers[1:],
		firstHeaderAt.Add(time.Second),
		headerTimeout,
		noProgress,
	)
	if !state.headerBlock ||
		!state.phaseDeadline.Equal(firstHeaderDeadline) {
		t.Fatalf(
			"continued header state = block %t, deadline %s",
			state.headerBlock,
			state.phaseDeadline,
		)
	}

	continuation := testHTTP2Frame(
		1,
		http2FrameTypeContinuation,
		http2FlagEndHeaders,
		[]byte{0x03},
	)
	state.observe(
		continuation,
		firstHeaderAt.Add(2*time.Second),
		headerTimeout,
		noProgress,
	)
	if state.headerBlock || !state.phaseDeadline.IsZero() {
		t.Fatalf(
			"completed continuation state = block %t, deadline %s",
			state.headerBlock,
			state.phaseDeadline,
		)
	}

	secondHeaderAt := firstHeaderAt.Add(time.Minute)
	state.observe(
		testHTTP2Frame(
			1,
			http2FrameTypeHeaders,
			0,
			[]byte{0x04},
		)[:1],
		secondHeaderAt,
		headerTimeout,
		noProgress,
	)
	if want := secondHeaderAt.Add(headerTimeout); !state.phaseDeadline.Equal(want) {
		t.Fatalf(
			"second header deadline = %s, want %s",
			state.phaseDeadline,
			want,
		)
	}
}

func TestHTTP2DeadlineStateBoundsPartialNonHeaderFrames(t *testing.T) {
	t.Parallel()

	const (
		headerTimeout = 10 * time.Second
		noProgress    = 30 * time.Second
	)
	now := time.Unix(1_700_000_000, 0)
	state := http2DeadlineState{}
	data := testHTTP2Frame(2, 0, 0, []byte{0x01, 0x02})
	state.observe(
		data[:http2FrameHeaderSize+1],
		now,
		headerTimeout,
		noProgress,
	)
	if want := now.Add(noProgress); !state.phaseDeadline.Equal(want) {
		t.Fatalf(
			"partial DATA deadline = %s, want %s",
			state.phaseDeadline,
			want,
		)
	}
	state.observe(
		data[http2FrameHeaderSize+1:],
		now.Add(time.Second),
		headerTimeout,
		noProgress,
	)
	if !state.phaseDeadline.IsZero() {
		t.Fatalf("completed DATA deadline = %s, want zero", state.phaseDeadline)
	}
}

func testHTTP2Frame(
	length uint32,
	frameType byte,
	flags byte,
	payload []byte,
) []byte {
	result := make([]byte, http2FrameHeaderSize+len(payload))
	result[0] = byte(length >> 16)
	result[1] = byte(length >> 8)
	result[2] = byte(length)
	result[3] = frameType
	result[4] = flags
	result[8] = 1
	copy(result[http2FrameHeaderSize:], payload)
	return result
}
