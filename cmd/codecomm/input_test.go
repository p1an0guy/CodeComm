package main

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"
)

func TestReadContextLineCancelsBlockedFileRead(t *testing.T) {
	input, output, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer input.Close()
	defer output.Close()

	ctx, cancel := context.WithCancel(t.Context())
	result := make(chan error, 1)
	go func() {
		_, err := readContextLine(ctx, input, 16, false)
		result <- err
	}()
	cancel()

	select {
	case err := <-result:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("readContextLine() error = %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("canceled input read remained blocked")
	}
}

func TestReadContextLineRejectsOversizedInputAndCanceledContext(
	t *testing.T,
) {
	t.Parallel()

	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := readContextLine(
		ctx,
		zeroReader{},
		16,
		false,
	); !errors.Is(err, context.Canceled) {
		t.Fatalf("pre-canceled read error = %v", err)
	}
	if _, err := readContextLine(
		t.Context(),
		&repeatingReader{remaining: 17},
		16,
		false,
	); !errors.Is(err, errInvalidCLI) {
		t.Fatalf("oversized read error = %v", err)
	}
}

type zeroReader struct{}

func (zeroReader) Read([]byte) (int, error) {
	return 0, nil
}

type repeatingReader struct {
	remaining int
}

func (reader *repeatingReader) Read(destination []byte) (int, error) {
	if reader.remaining == 0 {
		return 0, nil
	}
	reader.remaining--
	destination[0] = 'x'
	return 1, nil
}
