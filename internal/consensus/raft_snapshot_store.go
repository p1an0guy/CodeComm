package consensus

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"hash"
	"io"
	"reflect"
	"sync"

	"github.com/hashicorp/raft"
	"github.com/ijonahch/codecomm/internal/domain"
)

const maxRaftSnapshotReaderWrapperDepth = 16

var ErrInvalidRaftSnapshotStore = errors.New(
	"consensus: invalid Raft snapshot store",
)

// raftSnapshotStore binds HashiCorp's out-of-band snapshot metadata to one
// closed, self-digesting application frame. It never rewrites a replicated
// frame, so an inbound snapshot cannot acquire a second envelope.
type raftSnapshotStore struct {
	delegate raft.SnapshotStore
	reject   func(string) error
}

func newRaftSnapshotStore(
	delegate raft.SnapshotStore,
) (*raftSnapshotStore, error) {
	if isNilSnapshotInterface(delegate) {
		return nil, ErrInvalidRaftSnapshotStore
	}
	return &raftSnapshotStore{delegate: delegate}, nil
}

func newRaftSnapshotStoreWithReject(
	delegate raft.SnapshotStore,
	reject func(string) error,
) (*raftSnapshotStore, error) {
	store, err := newRaftSnapshotStore(delegate)
	if err != nil {
		return nil, err
	}
	if reject == nil {
		return nil, ErrInvalidRaftSnapshotStore
	}
	store.reject = reject
	return store, nil
}

func (store *raftSnapshotStore) Create(
	version raft.SnapshotVersion,
	index uint64,
	term uint64,
	configuration raft.Configuration,
	configurationIndex uint64,
	transport raft.Transport,
) (raft.SnapshotSink, error) {
	if store == nil || isNilSnapshotInterface(store.delegate) {
		return nil, ErrInvalidRaftSnapshotStore
	}
	meta := &raft.SnapshotMeta{
		Version:            version,
		Index:              index,
		Term:               term,
		Configuration:      configuration.Clone(),
		ConfigurationIndex: configurationIndex,
	}
	if err := validateRaftSnapshotMetadata(meta, false); err != nil {
		return nil, err
	}
	delegate, err := store.delegate.Create(
		version,
		index,
		term,
		configuration.Clone(),
		configurationIndex,
		transport,
	)
	if err != nil {
		return nil, err
	}
	if isNilSnapshotInterface(delegate) ||
		!validRaftSnapshotID(delegate.ID()) {
		if !isNilSnapshotInterface(delegate) {
			_ = delegate.Cancel()
		}
		return nil, ErrInvalidRaftSnapshotStore
	}
	meta.ID = delegate.ID()
	return &raftSnapshotSink{
		delegate: delegate,
		meta:     cloneRaftSnapshotMeta(meta),
		verifier: newRaftSnapshotFrameVerifier(meta),
	}, nil
}

func (store *raftSnapshotStore) List() ([]*raft.SnapshotMeta, error) {
	if store == nil || isNilSnapshotInterface(store.delegate) {
		return nil, ErrInvalidRaftSnapshotStore
	}
	metas, err := store.delegate.List()
	if err != nil {
		return nil, err
	}
	result := make([]*raft.SnapshotMeta, len(metas))
	seen := make(map[string]struct{}, len(metas))
	var previousIndex uint64
	for index, meta := range metas {
		if err := validateRaftSnapshotMetadata(meta, true); err != nil {
			return nil, err
		}
		if _, duplicate := seen[meta.ID]; duplicate {
			return nil, ErrInvalidRaftSnapshotStore
		}
		if index != 0 && meta.Index > previousIndex {
			return nil, ErrInvalidRaftSnapshotStore
		}
		seen[meta.ID] = struct{}{}
		previousIndex = meta.Index
		result[index] = cloneRaftSnapshotMeta(meta)
	}
	return result, nil
}

func (store *raftSnapshotStore) Open(
	id string,
) (*raft.SnapshotMeta, io.ReadCloser, error) {
	if store == nil ||
		isNilSnapshotInterface(store.delegate) ||
		!validRaftSnapshotID(id) {
		return nil, nil, ErrInvalidRaftSnapshotStore
	}
	meta, reader, err := store.delegate.Open(id)
	if err != nil {
		if reader != nil {
			_ = reader.Close()
		}
		return nil, nil, err
	}
	if isNilSnapshotInterface(reader) {
		return nil, nil, ErrInvalidRaftSnapshotStore
	}
	closeOnError := true
	defer func() {
		if closeOnError {
			_ = reader.Close()
		}
	}()
	if err := validateRaftSnapshotMetadata(meta, true); err != nil {
		return nil, nil, err
	}
	if meta.ID != id {
		return nil, nil, ErrRaftSnapshotMetadataMismatch
	}
	envelope, framing, err := readRaftSnapshotFrameHeader(reader)
	if err != nil {
		return nil, nil, err
	}
	if err := validateRaftSnapshotEnvelopeMetadata(
		envelope,
		meta,
		len(framing)-raftSnapshotFramePrefixBytes,
		true,
	); err != nil {
		return nil, nil, err
	}
	cloned := cloneRaftSnapshotMeta(meta)
	var reject func() error
	if store.reject != nil {
		reject = func() error {
			return store.reject(id)
		}
	}
	closeOnError = false
	return cloneRaftSnapshotMeta(meta), &raftSnapshotMetadataReader{
		reader: io.MultiReader(bytes.NewReader(framing), reader),
		closer: reader,
		metadata: raftSnapshotRestoreMetadata{
			Meta:     *cloned,
			Envelope: cloneRaftSnapshotEnvelope(envelope),
			Reject:   reject,
		},
	}, nil
}

type raftSnapshotSink struct {
	mu       sync.Mutex
	delegate raft.SnapshotSink
	meta     *raft.SnapshotMeta
	verifier *raftSnapshotFrameVerifier

	closed      bool
	canceled    bool
	terminalErr error
}

func (sink *raftSnapshotSink) ID() string {
	if sink == nil || sink.meta == nil {
		return ""
	}
	return sink.meta.ID
}

// SnapshotMetadata returns the immutable Create metadata needed by a local
// FSMSnapshot.Persist implementation to construct the application envelope.
func (sink *raftSnapshotSink) SnapshotMetadata() *raft.SnapshotMeta {
	if sink == nil {
		return nil
	}
	sink.mu.Lock()
	defer sink.mu.Unlock()
	return cloneRaftSnapshotMeta(sink.meta)
}

func (sink *raftSnapshotSink) Write(value []byte) (int, error) {
	if sink == nil {
		return 0, ErrInvalidRaftSnapshotStore
	}
	sink.mu.Lock()
	defer sink.mu.Unlock()
	if sink.closed || sink.canceled {
		if sink.terminalErr != nil {
			return 0, sink.terminalErr
		}
		return 0, ErrInvalidRaftSnapshotStore
	}
	if sink.terminalErr != nil {
		return 0, sink.terminalErr
	}
	written, writeErr := sink.delegate.Write(value)
	if written < 0 || written > len(value) {
		sink.terminalErr = io.ErrShortWrite
		return 0, sink.terminalErr
	}
	if written != 0 {
		if err := sink.verifier.Consume(value[:written]); err != nil {
			sink.terminalErr = err
		}
	}
	if sink.terminalErr != nil {
		return written, sink.terminalErr
	}
	if writeErr != nil {
		sink.terminalErr = writeErr
		return written, writeErr
	}
	if written != len(value) {
		sink.terminalErr = io.ErrShortWrite
		return written, sink.terminalErr
	}
	return written, nil
}

func (sink *raftSnapshotSink) Close() error {
	if sink == nil {
		return ErrInvalidRaftSnapshotStore
	}
	sink.mu.Lock()
	defer sink.mu.Unlock()
	if sink.closed || sink.canceled {
		return sink.terminalErr
	}
	if sink.terminalErr == nil {
		sink.terminalErr = sink.verifier.Finish()
	}
	if sink.terminalErr != nil {
		cancelErr := sink.delegate.Cancel()
		sink.canceled = true
		sink.terminalErr = errors.Join(sink.terminalErr, cancelErr)
		return sink.terminalErr
	}
	sink.terminalErr = sink.delegate.Close()
	sink.closed = true
	return sink.terminalErr
}

func (sink *raftSnapshotSink) Cancel() error {
	if sink == nil {
		return ErrInvalidRaftSnapshotStore
	}
	sink.mu.Lock()
	defer sink.mu.Unlock()
	if sink.closed || sink.canceled {
		return sink.terminalErr
	}
	sink.canceled = true
	cancelErr := sink.delegate.Cancel()
	sink.terminalErr = errors.Join(sink.terminalErr, cancelErr)
	return sink.terminalErr
}

type raftSnapshotFrameVerifier struct {
	meta       *raft.SnapshotMeta
	framing    []byte
	headerSize int
	envelope   *raftSnapshotEnvelope
	hasher     hash.Hash
	payload    uint64
	failed     error
}

func newRaftSnapshotFrameVerifier(
	meta *raft.SnapshotMeta,
) *raftSnapshotFrameVerifier {
	return &raftSnapshotFrameVerifier{
		meta:    cloneRaftSnapshotMeta(meta),
		framing: make([]byte, 0, raftSnapshotFramePrefixBytes),
	}
}

func (verifier *raftSnapshotFrameVerifier) Consume(value []byte) error {
	if verifier == nil {
		return ErrInvalidRaftSnapshotEnvelope
	}
	if verifier.failed != nil {
		return verifier.failed
	}
	for len(value) != 0 && verifier.envelope == nil {
		target := raftSnapshotFramePrefixBytes
		if len(verifier.framing) >= raftSnapshotFramePrefixBytes {
			if verifier.headerSize == 0 {
				verifier.headerSize = int(binaryHeaderSize(verifier.framing))
				if verifier.headerSize < 1 ||
					verifier.headerSize > maxRaftSnapshotEnvelopeBytes {
					return verifier.fail(ErrInvalidRaftSnapshotEnvelope)
				}
			}
			target += verifier.headerSize
		}
		needed := target - len(verifier.framing)
		if needed > len(value) {
			needed = len(value)
		}
		verifier.framing = append(verifier.framing, value[:needed]...)
		value = value[needed:]
		if len(verifier.framing) < raftSnapshotFramePrefixBytes {
			continue
		}
		if !bytes.Equal(
			verifier.framing[:len(raftSnapshotFrameMagic)],
			raftSnapshotFrameMagic[:],
		) {
			return verifier.fail(ErrInvalidRaftSnapshotEnvelope)
		}
		if verifier.headerSize == 0 {
			verifier.headerSize = int(binaryHeaderSize(verifier.framing))
			if verifier.headerSize < 1 ||
				verifier.headerSize > maxRaftSnapshotEnvelopeBytes {
				return verifier.fail(ErrInvalidRaftSnapshotEnvelope)
			}
		}
		if len(verifier.framing) ==
			raftSnapshotFramePrefixBytes+verifier.headerSize {
			envelope, err := decodeRaftSnapshotEnvelope(
				verifier.framing[raftSnapshotFramePrefixBytes:],
			)
			if err != nil {
				return verifier.fail(err)
			}
			if err := validateRaftSnapshotEnvelopeMetadata(
				envelope,
				verifier.meta,
				verifier.headerSize,
				verifier.meta.Size != 0,
			); err != nil {
				return verifier.fail(err)
			}
			verifier.envelope = &envelope
			verifier.hasher = sha256.New()
		}
	}
	if len(value) != 0 {
		if verifier.envelope == nil ||
			uint64(len(value)) >
				verifier.envelope.PayloadBytes-verifier.payload {
			return verifier.fail(ErrRaftSnapshotPayloadIntegrity)
		}
		if _, err := verifier.hasher.Write(value); err != nil {
			return verifier.fail(err)
		}
		verifier.payload += uint64(len(value))
	}
	return nil
}

func (verifier *raftSnapshotFrameVerifier) Write(value []byte) (int, error) {
	if err := verifier.Consume(value); err != nil {
		return 0, err
	}
	return len(value), nil
}

func (verifier *raftSnapshotFrameVerifier) Finish() error {
	if verifier == nil {
		return ErrInvalidRaftSnapshotEnvelope
	}
	if verifier.failed != nil {
		return verifier.failed
	}
	if verifier.envelope == nil ||
		verifier.hasher == nil ||
		verifier.payload != verifier.envelope.PayloadBytes {
		return verifier.fail(ErrRaftSnapshotPayloadIntegrity)
	}
	if !bytes.Equal(
		verifier.hasher.Sum(nil),
		verifier.envelope.PayloadDigest[:],
	) {
		return verifier.fail(ErrRaftSnapshotPayloadIntegrity)
	}
	return nil
}

func (verifier *raftSnapshotFrameVerifier) fail(err error) error {
	if verifier.failed == nil {
		verifier.failed = err
	}
	return verifier.failed
}

func binaryHeaderSize(framing []byte) uint32 {
	if len(framing) < raftSnapshotFramePrefixBytes {
		return 0
	}
	return binary.BigEndian.Uint32(framing[len(raftSnapshotFrameMagic):])
}

type raftSnapshotRestoreMetadata struct {
	Meta     raft.SnapshotMeta
	Envelope raftSnapshotEnvelope
	Reject   func() error
}

func (metadata raftSnapshotRestoreMetadata) clone() raftSnapshotRestoreMetadata {
	cloned := cloneRaftSnapshotMeta(&metadata.Meta)
	return raftSnapshotRestoreMetadata{
		Meta:     *cloned,
		Envelope: cloneRaftSnapshotEnvelope(metadata.Envelope),
		Reject:   metadata.Reject,
	}
}

type raftSnapshotMetadataCarrier interface {
	raftSnapshotMetadata() raftSnapshotRestoreMetadata
}

type raftSnapshotMetadataReader struct {
	reader    io.Reader
	closer    io.Closer
	metadata  raftSnapshotRestoreMetadata
	closeOnce sync.Once
	closeErr  error
}

func (reader *raftSnapshotMetadataReader) Read(value []byte) (int, error) {
	if reader == nil || reader.reader == nil {
		return 0, ErrInvalidRaftSnapshotStore
	}
	return reader.reader.Read(value)
}

func (reader *raftSnapshotMetadataReader) Close() error {
	if reader == nil || reader.closer == nil {
		return ErrInvalidRaftSnapshotStore
	}
	reader.closeOnce.Do(func() {
		reader.closeErr = reader.closer.Close()
	})
	return reader.closeErr
}

func (reader *raftSnapshotMetadataReader) raftSnapshotMetadata() (
	metadata raftSnapshotRestoreMetadata,
) {
	if reader == nil {
		return raftSnapshotRestoreMetadata{}
	}
	return reader.metadata.clone()
}

func raftSnapshotMetadataFromReader(
	reader io.ReadCloser,
) (raftSnapshotRestoreMetadata, error) {
	if isNilSnapshotInterface(reader) {
		return raftSnapshotRestoreMetadata{}, ErrInvalidRaftSnapshotStore
	}
	current := reader
	seen := make(map[uintptr]struct{}, maxRaftSnapshotReaderWrapperDepth)
	for depth := 0; depth < maxRaftSnapshotReaderWrapperDepth; depth++ {
		if carrier, ok := current.(raftSnapshotMetadataCarrier); ok {
			metadata := carrier.raftSnapshotMetadata()
			if err := validateRaftSnapshotMetadata(
				&metadata.Meta,
				true,
			); err != nil {
				return raftSnapshotRestoreMetadata{}, err
			}
			header, err := encodeRaftSnapshotEnvelope(metadata.Envelope)
			if err != nil {
				return raftSnapshotRestoreMetadata{}, err
			}
			if err := validateRaftSnapshotEnvelopeMetadata(
				metadata.Envelope,
				&metadata.Meta,
				len(header),
				true,
			); err != nil {
				return raftSnapshotRestoreMetadata{}, err
			}
			return metadata.clone(), nil
		}
		wrapper, ok := current.(raft.ReadCloserWrapper)
		if !ok {
			return raftSnapshotRestoreMetadata{}, ErrInvalidRaftSnapshotStore
		}
		pointer := interfacePointer(current)
		if pointer != 0 {
			if _, duplicate := seen[pointer]; duplicate {
				return raftSnapshotRestoreMetadata{},
					ErrInvalidRaftSnapshotStore
			}
			seen[pointer] = struct{}{}
		}
		next := wrapper.WrappedReadCloser()
		nextPointer := interfacePointer(next)
		if isNilSnapshotInterface(next) ||
			pointer != 0 && nextPointer == pointer {
			return raftSnapshotRestoreMetadata{}, ErrInvalidRaftSnapshotStore
		}
		current = next
	}
	return raftSnapshotRestoreMetadata{}, ErrInvalidRaftSnapshotStore
}

func validateRaftSnapshotMetadata(
	meta *raft.SnapshotMeta,
	requireSize bool,
) error {
	if meta == nil ||
		meta.Version != raft.SnapshotVersionMax ||
		(meta.ID != "" && !validRaftSnapshotID(meta.ID)) ||
		meta.Index < 1 ||
		!domain.ValidUnsignedInteger(meta.Index) ||
		meta.Term < 1 ||
		!domain.ValidUnsignedInteger(meta.Term) ||
		meta.ConfigurationIndex < 1 ||
		meta.ConfigurationIndex > meta.Index ||
		!domain.ValidUnsignedInteger(meta.ConfigurationIndex) ||
		validateDeviceAddressedSnapshotConfiguration(meta.Configuration) != nil {
		return ErrInvalidRaftSnapshotStore
	}
	if requireSize {
		maxFrameBytes := uint64(raftSnapshotFramePrefixBytes) +
			maxRaftSnapshotEnvelopeBytes +
			maxRaftSnapshotPayloadBytes
		if !validRaftSnapshotID(meta.ID) ||
			meta.Size < int64(raftSnapshotFramePrefixBytes+1) ||
			uint64(meta.Size) > maxFrameBytes {
			return ErrInvalidRaftSnapshotStore
		}
	} else if meta.Size != 0 {
		return ErrInvalidRaftSnapshotStore
	}
	return nil
}

func validRaftSnapshotID(id string) bool {
	if len(id) < 1 || len(id) > 128 {
		return false
	}
	for index := 0; index < len(id); index++ {
		value := id[index]
		if value >= 'a' && value <= 'z' ||
			value >= 'A' && value <= 'Z' ||
			value >= '0' && value <= '9' ||
			value == '.' ||
			value == '_' ||
			value == ':' ||
			value == '-' {
			continue
		}
		return false
	}
	return true
}

func cloneRaftSnapshotMeta(meta *raft.SnapshotMeta) *raft.SnapshotMeta {
	if meta == nil {
		return nil
	}
	clone := *meta
	clone.Peers = bytes.Clone(meta.Peers)
	clone.Configuration = meta.Configuration.Clone()
	return &clone
}

func interfacePointer(value any) uintptr {
	reflected := reflect.ValueOf(value)
	switch reflected.Kind() {
	case reflect.Chan, reflect.Func, reflect.Map, reflect.Pointer,
		reflect.Slice, reflect.UnsafePointer:
		return reflected.Pointer()
	default:
		return 0
	}
}

var (
	_ raft.SnapshotStore = (*raftSnapshotStore)(nil)
	_ raft.SnapshotSink  = (*raftSnapshotSink)(nil)
	_ io.ReadCloser      = (*raftSnapshotMetadataReader)(nil)
)
