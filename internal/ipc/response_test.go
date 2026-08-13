package ipc

import (
	"bytes"
	"errors"
	"io"
	"testing"
)

type shortWriter struct {
	buffer bytes.Buffer
	limit  int
	zero   bool
}

func (writer *shortWriter) Write(value []byte) (int, error) {
	if writer.zero {
		return 0, nil
	}
	if len(value) > writer.limit {
		value = value[:writer.limit]
	}
	return writer.buffer.Write(value)
}

func TestWriteFullHandlesShortWritesAndRejectsNoProgress(t *testing.T) {
	t.Parallel()

	const value = "complete response bytes"
	writer := &shortWriter{limit: 3}
	if err := writeFull(writer, []byte(value)); err != nil {
		t.Fatalf("writeFull() error = %v", err)
	}
	if writer.buffer.String() != value {
		t.Fatalf("written value = %q", writer.buffer.String())
	}

	if err := writeFull(
		&shortWriter{zero: true},
		[]byte(value),
	); !errors.Is(err, io.ErrShortWrite) {
		t.Fatalf("zero-progress error = %v, want io.ErrShortWrite", err)
	}
}
