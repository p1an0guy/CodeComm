package logicalsnapshot

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"

	"github.com/ijonahch/codecomm/internal/codec"
)

const (
	MaxRecordTypeBytes    = 64
	MaxRecordPayloadBytes = 3 << 20
)

var (
	ErrInvalidRecord   = errors.New("logicalsnapshot: invalid artifact record")
	ErrRecordTooLarge  = errors.New("logicalsnapshot: artifact record exceeds size limit")
	ErrTruncatedRecord = errors.New("logicalsnapshot: truncated artifact record")
)

// RecordType is the closed V1 logical-snapshot record namespace.
type RecordType string

const (
	RecordGenesis    RecordType = "genesis"
	RecordResult     RecordType = "result"
	RecordMutation   RecordType = "result_mutation_chunk"
	RecordEvent      RecordType = "event"
	RecordProjection RecordType = "projection"
	RecordCheckpoint RecordType = "checkpoint"
)

func (recordType RecordType) valid() bool {
	switch recordType {
	case RecordGenesis,
		RecordResult,
		RecordMutation,
		RecordEvent,
		RecordProjection,
		RecordCheckpoint:
		return true
	default:
		return false
	}
}

// Record is one independently bounded canonical artifact record.
type Record struct {
	Type    RecordType
	Payload []byte
}

// WriteRecord emits u16be(type_len) || type || u64be(payload_len) ||
// JCS(payload). It returns the exact expanded byte count.
func WriteRecord(
	writer io.Writer,
	recordType RecordType,
	payload []byte,
) (uint64, error) {
	if writer == nil || !recordType.valid() {
		return 0, ErrInvalidRecord
	}
	if err := validateRecordPayload(payload); err != nil {
		return 0, err
	}
	typeBytes := []byte(recordType)
	var header [10]byte
	binary.BigEndian.PutUint16(header[:2], uint16(len(typeBytes)))
	binary.BigEndian.PutUint64(header[2:], uint64(len(payload)))
	for _, value := range [][]byte{header[:2], typeBytes, header[2:], payload} {
		if err := writeAll(writer, value); err != nil {
			return 0, err
		}
	}
	return uint64(len(header) + len(typeBytes) + len(payload)), nil
}

// RecordReader incrementally decodes one bounded record at a time.
type RecordReader struct {
	reader io.Reader
}

// NewRecordReader constructs a reader over one expanded artifact stream.
func NewRecordReader(reader io.Reader) *RecordReader {
	return &RecordReader{reader: reader}
}

// Next returns io.EOF only at a clean record boundary.
func (reader *RecordReader) Next() (Record, error) {
	if reader == nil || reader.reader == nil {
		return Record{}, ErrInvalidRecord
	}
	var typeLengthBytes [2]byte
	n, err := io.ReadFull(reader.reader, typeLengthBytes[:])
	if errors.Is(err, io.EOF) && n == 0 {
		return Record{}, io.EOF
	}
	if err != nil {
		return Record{}, fmt.Errorf("%w: type length", ErrTruncatedRecord)
	}
	typeLength := int(binary.BigEndian.Uint16(typeLengthBytes[:]))
	if typeLength < 1 || typeLength > MaxRecordTypeBytes {
		return Record{}, ErrInvalidRecord
	}
	typeBytes := make([]byte, typeLength)
	if _, err := io.ReadFull(reader.reader, typeBytes); err != nil {
		return Record{}, fmt.Errorf("%w: type", ErrTruncatedRecord)
	}
	recordType := RecordType(typeBytes)
	if !recordType.valid() {
		return Record{}, ErrInvalidRecord
	}
	var payloadLengthBytes [8]byte
	if _, err := io.ReadFull(reader.reader, payloadLengthBytes[:]); err != nil {
		return Record{}, fmt.Errorf("%w: payload length", ErrTruncatedRecord)
	}
	payloadLength := binary.BigEndian.Uint64(payloadLengthBytes[:])
	if payloadLength < 2 {
		return Record{}, ErrInvalidRecord
	}
	if payloadLength > MaxRecordPayloadBytes {
		return Record{}, ErrRecordTooLarge
	}
	payload := make([]byte, int(payloadLength))
	if _, err := io.ReadFull(reader.reader, payload); err != nil {
		return Record{}, fmt.Errorf("%w: payload", ErrTruncatedRecord)
	}
	if err := validateRecordPayload(payload); err != nil {
		return Record{}, err
	}
	return Record{Type: recordType, Payload: payload}, nil
}

func validateRecordPayload(payload []byte) error {
	if len(payload) < 2 {
		return ErrInvalidRecord
	}
	if len(payload) > MaxRecordPayloadBytes {
		return ErrRecordTooLarge
	}
	canonical, err := codec.Canonicalize(payload)
	if err != nil ||
		!bytes.Equal(canonical, payload) ||
		payload[0] != '{' ||
		payload[len(payload)-1] != '}' {
		return fmt.Errorf("%w: payload is not a canonical object", ErrInvalidRecord)
	}
	return nil
}

func writeAll(writer io.Writer, value []byte) error {
	for len(value) != 0 {
		written, err := writer.Write(value)
		if err != nil {
			return err
		}
		if written < 1 || written > len(value) {
			return io.ErrShortWrite
		}
		value = value[written:]
	}
	return nil
}
