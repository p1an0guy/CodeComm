package consensus

import (
	"bytes"
	"errors"
	"io"
	"testing"

	"github.com/hashicorp/raft"
)

func TestRaftSnapshotStorePersistsAndOpensBoundFrame(t *testing.T) {
	t.Parallel()

	adapter, _, transport := newRaftSnapshotTestStore(t)
	defer transport.Close()
	frame, envelope, snapshotID := persistRaftSnapshotTestFrame(
		t,
		adapter,
		transport,
	)

	metas, err := adapter.List()
	if err != nil {
		t.Fatalf("List(): %v", err)
	}
	if len(metas) != 1 ||
		metas[0].ID != snapshotID ||
		metas[0].Size != int64(len(frame)) {
		t.Fatalf("List() = %#v", metas)
	}
	metas[0].Configuration.Servers[0].Address = "mutated"
	again, err := adapter.List()
	if err != nil {
		t.Fatalf("List(after caller mutation): %v", err)
	}
	if again[0].Configuration.Servers[0].Address == "mutated" {
		t.Fatal("List returned aliased configuration metadata")
	}

	meta, reader, err := adapter.Open(snapshotID)
	if err != nil {
		t.Fatalf("Open(): %v", err)
	}
	defer reader.Close()
	meta.Configuration.Servers[0].Address = "mutated"
	metadata, err := raftSnapshotMetadataFromReader(
		&raftSnapshotTestReadCloserWrapper{next: reader},
	)
	if err != nil {
		t.Fatalf("raftSnapshotMetadataFromReader(): %v", err)
	}
	if metadata.Meta.Configuration.Servers[0].Address == "mutated" ||
		!sameRaftSnapshotEnvelope(metadata.Envelope, envelope) {
		t.Fatal("restore metadata was aliased or changed")
	}
	metadata.Envelope.BaselineCommandLogIndex = nil
	metadataAgain, err := raftSnapshotMetadataFromReader(reader)
	if err != nil {
		t.Fatalf("raftSnapshotMetadataFromReader(second): %v", err)
	}
	if metadataAgain.Envelope.BaselineCommandLogIndex == nil {
		t.Fatal("restore metadata carrier returned an aliased envelope")
	}
	got, err := io.ReadAll(reader)
	if err != nil {
		t.Fatalf("ReadAll(): %v", err)
	}
	if !bytes.Equal(got, frame) {
		t.Fatal("Open changed the framed snapshot bytes")
	}
}

func TestRaftSnapshotStoreReplicatesFrameWithoutNesting(t *testing.T) {
	t.Parallel()

	source, _, sourceTransport := newRaftSnapshotTestStore(t)
	defer sourceTransport.Close()
	frame, _, snapshotID := persistRaftSnapshotTestFrame(
		t,
		source,
		sourceTransport,
	)
	_, sourceReader, err := source.Open(snapshotID)
	if err != nil {
		t.Fatalf("source Open(): %v", err)
	}
	defer sourceReader.Close()

	target, _, targetTransport := newRaftSnapshotTestStore(t)
	defer targetTransport.Close()
	configuration, _ := raftSnapshotTestConfiguration()
	targetSink, err := target.Create(
		raft.SnapshotVersionMax,
		11,
		3,
		configuration,
		7,
		targetTransport,
	)
	if err != nil {
		t.Fatalf("target Create(): %v", err)
	}
	if _, err := io.Copy(targetSink, sourceReader); err != nil {
		_ = targetSink.Cancel()
		t.Fatalf("copy replicated frame: %v", err)
	}
	if err := targetSink.Close(); err != nil {
		t.Fatalf("target Close(): %v", err)
	}
	_, targetReader, err := target.Open(targetSink.ID())
	if err != nil {
		t.Fatalf("target Open(): %v", err)
	}
	defer targetReader.Close()
	replicated, err := io.ReadAll(targetReader)
	if err != nil {
		t.Fatalf("read replicated frame: %v", err)
	}
	if !bytes.Equal(replicated, frame) {
		t.Fatal("replication nested or rewrote the snapshot frame")
	}
}

func TestRaftSnapshotStoreRejectsFrameTampering(t *testing.T) {
	t.Parallel()

	configuration, sourceID := raftSnapshotTestConfiguration()
	payload := []byte("bound payload")
	validEnvelope := raftSnapshotTestEnvelope(
		t,
		configuration,
		sourceID,
		payload,
	)
	validFrame := encodeRaftSnapshotTestFrame(t, validEnvelope, payload)
	tests := []struct {
		name  string
		frame func() []byte
	}{
		{
			name: "payload digest",
			frame: func() []byte {
				value := bytes.Clone(validFrame)
				value[len(value)-1] ^= 1
				return value
			},
		},
		{
			name: "truncated",
			frame: func() []byte {
				return bytes.Clone(validFrame[:len(validFrame)-1])
			},
		},
		{
			name: "appended",
			frame: func() []byte {
				return append(bytes.Clone(validFrame), 0)
			},
		},
		{
			name: "magic",
			frame: func() []byte {
				value := bytes.Clone(validFrame)
				value[0] ^= 1
				return value
			},
		},
		{
			name: "metadata index",
			frame: func() []byte {
				value := cloneRaftSnapshotEnvelope(validEnvelope)
				value.SnapshotIndex++
				return encodeRaftSnapshotTestFrame(t, value, payload)
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			adapter, _, transport := newRaftSnapshotTestStore(t)
			defer transport.Close()
			sink, err := adapter.Create(
				raft.SnapshotVersionMax,
				11,
				3,
				configuration,
				7,
				transport,
			)
			if err != nil {
				t.Fatalf("Create(): %v", err)
			}
			_, writeErr := sink.Write(test.frame())
			closeErr := sink.Close()
			if writeErr == nil && closeErr == nil {
				t.Fatal("tampered frame was finalized")
			}
			if err := sink.Close(); err == nil {
				t.Fatal("repeated Close lost terminal error")
			}
		})
	}
}

func TestRaftSnapshotStoreRejectsCorruptDelegateMetadata(t *testing.T) {
	t.Parallel()

	adapter, delegate, transport := newRaftSnapshotTestStore(t)
	defer transport.Close()
	_, _, snapshotID := persistRaftSnapshotTestFrame(
		t,
		adapter,
		transport,
	)
	metas, err := delegate.List()
	if err != nil {
		t.Fatalf("delegate List(): %v", err)
	}
	metas[0].Configuration.Servers[0].Address = "wrong"
	if _, err := adapter.List(); !errors.Is(err, ErrInvalidRaftSnapshotStore) {
		t.Fatalf("List(corrupt metadata) error = %v", err)
	}
	metas[0].Configuration.Servers[0].Address =
		raft.ServerAddress(metas[0].Configuration.Servers[0].ID)
	mutating, err := newRaftSnapshotStore(
		&raftSnapshotTestOpenIDStore{SnapshotStore: delegate},
	)
	if err != nil {
		t.Fatalf("newRaftSnapshotStore(mutating): %v", err)
	}
	if _, _, err := mutating.Open(
		snapshotID,
	); !errors.Is(err, ErrRaftSnapshotMetadataMismatch) {
		t.Fatalf("Open(mismatched ID) error = %v", err)
	}
	if _, _, err := adapter.Open(
		"../escape",
	); !errors.Is(err, ErrInvalidRaftSnapshotStore) {
		t.Fatalf("Open(invalid requested ID) error = %v", err)
	}
}

func TestRaftSnapshotMetadataReaderRejectsInvalidWrapperChains(t *testing.T) {
	t.Parallel()

	adapter, _, transport := newRaftSnapshotTestStore(t)
	defer transport.Close()
	_, _, snapshotID := persistRaftSnapshotTestFrame(
		t,
		adapter,
		transport,
	)
	_, carrier, err := adapter.Open(snapshotID)
	if err != nil {
		t.Fatalf("Open(): %v", err)
	}
	defer carrier.Close()
	var wrapped io.ReadCloser = carrier
	for range maxRaftSnapshotReaderWrapperDepth - 1 {
		wrapped = &raftSnapshotTestReadCloserWrapper{next: wrapped}
	}
	if _, err := raftSnapshotMetadataFromReader(wrapped); err != nil {
		t.Fatalf("bounded wrapper chain rejected: %v", err)
	}

	_, deepCarrier, err := adapter.Open(snapshotID)
	if err != nil {
		t.Fatalf("Open(deep): %v", err)
	}
	defer deepCarrier.Close()
	var deep io.ReadCloser = deepCarrier
	for range maxRaftSnapshotReaderWrapperDepth {
		deep = &raftSnapshotTestReadCloserWrapper{next: deep}
	}
	if _, err := raftSnapshotMetadataFromReader(
		deep,
	); !errors.Is(err, ErrInvalidRaftSnapshotStore) {
		t.Fatalf("deep wrapper chain error = %v", err)
	}
	self := &raftSnapshotTestSelfWrapper{}
	if _, err := raftSnapshotMetadataFromReader(
		self,
	); !errors.Is(err, ErrInvalidRaftSnapshotStore) {
		t.Fatalf("self wrapper error = %v", err)
	}
	if _, err := raftSnapshotMetadataFromReader(
		&raftSnapshotTestReadCloserWrapper{},
	); !errors.Is(err, ErrInvalidRaftSnapshotStore) {
		t.Fatalf("nil wrapper error = %v", err)
	}
	if _, err := raftSnapshotMetadataFromReader(
		io.NopCloser(bytes.NewReader(nil)),
	); !errors.Is(err, ErrInvalidRaftSnapshotStore) {
		t.Fatalf("plain reader error = %v", err)
	}
}

func newRaftSnapshotTestStore(
	t *testing.T,
) (
	*raftSnapshotStore,
	*raft.InmemSnapshotStore,
	*raft.InmemTransport,
) {
	t.Helper()
	delegate := raft.NewInmemSnapshotStore()
	adapter, err := newRaftSnapshotStore(delegate)
	if err != nil {
		t.Fatalf("newRaftSnapshotStore(): %v", err)
	}
	configuration, _ := raftSnapshotTestConfiguration()
	_, transport := raft.NewInmemTransport(
		configuration.Servers[0].Address,
	)
	return adapter, delegate, transport
}

func persistRaftSnapshotTestFrame(
	t *testing.T,
	adapter *raftSnapshotStore,
	transport raft.Transport,
) ([]byte, raftSnapshotEnvelope, string) {
	t.Helper()
	configuration, sourceID := raftSnapshotTestConfiguration()
	payload := []byte("complete logical snapshot payload")
	sink, err := adapter.Create(
		raft.SnapshotVersionMax,
		11,
		3,
		configuration,
		7,
		transport,
	)
	if err != nil {
		t.Fatalf("Create(): %v", err)
	}
	metadataSink, ok := sink.(interface {
		SnapshotMetadata() *raft.SnapshotMeta
	})
	if !ok {
		t.Fatalf("Create() sink type = %T", sink)
	}
	meta := metadataSink.SnapshotMetadata()
	if meta == nil ||
		meta.Index != 11 ||
		meta.Term != 3 ||
		meta.ConfigurationIndex != 7 {
		t.Fatalf("SnapshotMetadata() = %#v", meta)
	}
	envelope := raftSnapshotTestEnvelope(
		t,
		configuration,
		sourceID,
		payload,
	)
	frame := encodeRaftSnapshotTestFrame(t, envelope, payload)
	for offset := 0; offset < len(frame); {
		end := offset + 3
		if end > len(frame) {
			end = len(frame)
		}
		written, err := sink.Write(frame[offset:end])
		if err != nil {
			_ = sink.Cancel()
			t.Fatalf("Write(%d): %v", offset, err)
		}
		if written != end-offset {
			t.Fatalf("Write(%d) = %d", offset, written)
		}
		offset = end
	}
	if err := sink.Close(); err != nil {
		t.Fatalf("Close(): %v", err)
	}
	if err := sink.Close(); err != nil {
		t.Fatalf("Close(second): %v", err)
	}
	return frame, envelope, sink.ID()
}

func encodeRaftSnapshotTestFrame(
	t *testing.T,
	envelope raftSnapshotEnvelope,
	payload []byte,
) []byte {
	t.Helper()
	var frame bytes.Buffer
	if err := writeRaftSnapshotFrame(
		&frame,
		envelope,
		bytes.NewReader(payload),
	); err != nil {
		t.Fatalf("writeRaftSnapshotFrame(): %v", err)
	}
	return frame.Bytes()
}

type raftSnapshotTestReadCloserWrapper struct {
	next io.ReadCloser
}

func (wrapper *raftSnapshotTestReadCloserWrapper) Read(
	value []byte,
) (int, error) {
	if wrapper == nil || wrapper.next == nil {
		return 0, io.EOF
	}
	return wrapper.next.Read(value)
}

func (wrapper *raftSnapshotTestReadCloserWrapper) Close() error {
	if wrapper == nil || wrapper.next == nil {
		return nil
	}
	return wrapper.next.Close()
}

func (wrapper *raftSnapshotTestReadCloserWrapper) WrappedReadCloser() io.ReadCloser {
	if wrapper == nil {
		return nil
	}
	return wrapper.next
}

type raftSnapshotTestSelfWrapper struct{}

func (*raftSnapshotTestSelfWrapper) Read([]byte) (int, error) {
	return 0, io.EOF
}

func (*raftSnapshotTestSelfWrapper) Close() error {
	return nil
}

func (wrapper *raftSnapshotTestSelfWrapper) WrappedReadCloser() io.ReadCloser {
	return wrapper
}

type raftSnapshotTestOpenIDStore struct {
	raft.SnapshotStore
}

func (store *raftSnapshotTestOpenIDStore) Open(
	id string,
) (*raft.SnapshotMeta, io.ReadCloser, error) {
	meta, reader, err := store.SnapshotStore.Open(id)
	if err != nil {
		return nil, reader, err
	}
	cloned := cloneRaftSnapshotMeta(meta)
	cloned.ID = "different"
	return cloned, reader, nil
}

var _ raft.ReadCloserWrapper = (*raftSnapshotTestReadCloserWrapper)(nil)
var _ raft.ReadCloserWrapper = (*raftSnapshotTestSelfWrapper)(nil)
