package logicalsnapshot

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"io"
	"testing"
)

func TestRecordFramingGoldenAndRoundTrip(t *testing.T) {
	t.Parallel()

	payload := []byte(`{"a":1,"b":"two"}`)
	var encoded bytes.Buffer
	written, err := WriteRecord(&encoded, RecordResult, payload)
	if err != nil {
		t.Fatalf("WriteRecord(): %v", err)
	}
	const wantHex = "0006726573756c7400000000000000117b2261223a312c2262223a2274776f227d"
	if got := hex.EncodeToString(encoded.Bytes()); got != wantHex {
		t.Fatalf("encoded record = %s, want %s", got, wantHex)
	}
	if written != uint64(encoded.Len()) {
		t.Fatalf("WriteRecord() count = %d, want %d", written, encoded.Len())
	}

	reader := NewRecordReader(bytes.NewReader(encoded.Bytes()))
	record, err := reader.Next()
	if err != nil {
		t.Fatalf("Next(): %v", err)
	}
	if record.Type != RecordResult || !bytes.Equal(record.Payload, payload) {
		t.Fatalf("Next() = %#v, want result %s", record, payload)
	}
	record.Payload[0] = '!'
	if _, err := reader.Next(); !errors.Is(err, io.EOF) {
		t.Fatalf("Next(EOF) = %v, want io.EOF", err)
	}
}

func TestRecordReaderRejectsTruncationAndBoundsBeforeAllocation(t *testing.T) {
	t.Parallel()

	var valid bytes.Buffer
	if _, err := WriteRecord(
		&valid,
		RecordCheckpoint,
		[]byte(`{"ok":true}`),
	); err != nil {
		t.Fatalf("WriteRecord(): %v", err)
	}
	for length := 1; length < valid.Len(); length++ {
		_, err := NewRecordReader(
			bytes.NewReader(valid.Bytes()[:length]),
		).Next()
		if !errors.Is(err, ErrTruncatedRecord) {
			t.Fatalf(
				"Next(truncated at %d) = %v, want ErrTruncatedRecord",
				length,
				err,
			)
		}
	}

	var oversized bytes.Buffer
	var header [10]byte
	binary.BigEndian.PutUint16(header[:2], uint16(len(RecordResult)))
	binary.BigEndian.PutUint64(
		header[2:],
		MaxRecordPayloadBytes+1,
	)
	oversized.Write(header[:2])
	oversized.WriteString(string(RecordResult))
	oversized.Write(header[2:])
	if _, err := NewRecordReader(&oversized).Next(); !errors.Is(
		err,
		ErrRecordTooLarge,
	) {
		t.Fatalf("Next(oversized declaration) = %v, want ErrRecordTooLarge", err)
	}

	for _, payloadLength := range []uint64{0, 1} {
		var undersized bytes.Buffer
		binary.BigEndian.PutUint16(
			header[:2],
			uint16(len(RecordResult)),
		)
		binary.BigEndian.PutUint64(header[2:], payloadLength)
		undersized.Write(header[:2])
		undersized.WriteString(string(RecordResult))
		undersized.Write(header[2:])
		if _, err := NewRecordReader(&undersized).Next(); !errors.Is(
			err,
			ErrInvalidRecord,
		) {
			t.Fatalf(
				"Next(payload length %d) = %v, want ErrInvalidRecord",
				payloadLength,
				err,
			)
		}
	}
}

func TestRecordRejectsUnknownAndNoncanonicalPayload(t *testing.T) {
	t.Parallel()

	for name, payload := range map[string][]byte{
		"noncanonical": []byte(`{"b":2,"a":1}`),
		"array":        []byte(`[]`),
		"duplicate":    []byte(`{"a":1,"a":1}`),
		"float":        []byte(`{"a":1.5}`),
	} {
		var output bytes.Buffer
		if _, err := WriteRecord(&output, RecordEvent, payload); !errors.Is(
			err,
			ErrInvalidRecord,
		) {
			t.Errorf(
				"WriteRecord(%s) = %v, want ErrInvalidRecord",
				name,
				err,
			)
		}
	}

	var unknown bytes.Buffer
	unknown.Write([]byte{0, 7})
	unknown.WriteString("unknown")
	unknown.Write(make([]byte, 8))
	if _, err := NewRecordReader(&unknown).Next(); !errors.Is(
		err,
		ErrInvalidRecord,
	) {
		t.Fatalf("Next(unknown type) = %v, want ErrInvalidRecord", err)
	}
}

func TestWriteRecordHandlesShortWrites(t *testing.T) {
	t.Parallel()

	writer := &oneByteWriter{}
	written, err := WriteRecord(
		writer,
		RecordGenesis,
		[]byte(`{"generation":0}`),
	)
	if err != nil {
		t.Fatalf("WriteRecord(one byte): %v", err)
	}
	if written != uint64(len(writer.value)) {
		t.Fatalf("written = %d, buffered = %d", written, len(writer.value))
	}
}

type oneByteWriter struct {
	value []byte
}

func (writer *oneByteWriter) Write(value []byte) (int, error) {
	if len(value) == 0 {
		return 0, nil
	}
	writer.value = append(writer.value, value[0])
	return 1, nil
}
