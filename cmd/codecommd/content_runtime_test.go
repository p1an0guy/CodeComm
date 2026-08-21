package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"testing"
	"time"

	"github.com/hashicorp/raft"
	"github.com/ijonahch/codecomm/internal/chain"
	"github.com/ijonahch/codecomm/internal/consensus"
	"github.com/ijonahch/codecomm/internal/contenthttp"
	"github.com/ijonahch/codecomm/internal/discovery"
	"github.com/ijonahch/codecomm/internal/domain"
	"github.com/ijonahch/codecomm/internal/domain/device"
	"github.com/ijonahch/codecomm/internal/domain/voterset"
	"github.com/ijonahch/codecomm/internal/event"
	"github.com/ijonahch/codecomm/internal/replication"
	coordstatus "github.com/ijonahch/codecomm/internal/status"
	"github.com/ijonahch/codecomm/internal/store"
)

const daemonContentTestAdvertisementInterval = 20 * time.Second

type daemonContentStateStub struct {
	snapshot     coordstatus.DurableSnapshot
	snapshotErr  error
	endpointSets []store.MemberSignedEndpointSet
	endpointsErr error
	now          domain.Timestamp

	resultRange   store.ResultRange
	resultFound   bool
	resultErr     error
	resultOptions store.ResultRangeOptions

	replicationWatermark store.ReplicationWatermark
	watermarkErr         error
	watermarkSigner      domain.DeviceID
}

func (state *daemonContentStateStub) StatusSnapshot(
	context.Context,
	domain.DeviceID,
	int,
) (coordstatus.DurableSnapshot, error) {
	if state.snapshotErr != nil {
		return coordstatus.DurableSnapshot{}, state.snapshotErr
	}
	return state.snapshot, nil
}

func (state *daemonContentStateStub) ListMemberSignedEndpointSets(
	_ context.Context,
	now domain.Timestamp,
) ([]store.MemberSignedEndpointSet, error) {
	state.now = now
	if state.endpointsErr != nil {
		return nil, state.endpointsErr
	}
	result := make([]store.MemberSignedEndpointSet, len(state.endpointSets))
	for index, value := range state.endpointSets {
		result[index] = store.MemberSignedEndpointSet{
			DeviceID:        value.DeviceID,
			EndpointSetJSON: bytes.Clone(value.EndpointSetJSON),
		}
	}
	return result, nil
}

func (state *daemonContentStateStub) ExportResultRange(
	_ context.Context,
	options store.ResultRangeOptions,
) (store.ResultRange, bool, error) {
	state.resultOptions = options
	if state.resultErr != nil {
		return store.ResultRange{}, false, state.resultErr
	}
	result := state.resultRange
	result.Results = make([][]byte, len(state.resultRange.Results))
	for index := range state.resultRange.Results {
		result.Results[index] = bytes.Clone(state.resultRange.Results[index])
	}
	return result, state.resultFound, nil
}

func (state *daemonContentStateStub) ExportReplicationWatermark(
	_ context.Context,
	requiredSigner domain.DeviceID,
) (store.ReplicationWatermark, error) {
	state.watermarkSigner = requiredSigner
	if state.watermarkErr != nil {
		return store.ReplicationWatermark{}, state.watermarkErr
	}
	return state.replicationWatermark, nil
}

type daemonEndpointSetSourceStub struct {
	value []byte
	found bool
}

type daemonEventProposalConsensusStub struct {
	lookup store.CommandResultLookup
	err    error

	calls     int
	sender    domain.DeviceID
	canonical []byte
	hop       contenthttp.ProposalHop
}

func (stub *daemonEventProposalConsensusStub) apply(
	sender domain.DeviceID,
	canonical []byte,
	hop contenthttp.ProposalHop,
) (store.CommandResultLookup, error) {
	stub.calls++
	stub.sender = sender
	stub.canonical = bytes.Clone(canonical)
	stub.hop = hop
	return stub.lookup, stub.err
}

func (stub *daemonEventProposalConsensusStub) ApplyPeerProposal(
	_ context.Context,
	sender domain.DeviceID,
	canonical []byte,
) (store.CommandResultLookup, error) {
	return stub.apply(sender, canonical, contenthttp.ProposalHopInitial)
}

func (stub *daemonEventProposalConsensusStub) ApplyForwardedProposal(
	_ context.Context,
	sender domain.DeviceID,
	canonical []byte,
) (store.CommandResultLookup, error) {
	return stub.apply(sender, canonical, contenthttp.ProposalHopForwarded)
}

func (source *daemonEndpointSetSourceStub) CurrentEndpointSet() (
	[]byte,
	time.Duration,
	bool,
) {
	return bytes.Clone(source.value),
		daemonContentTestAdvertisementInterval,
		source.found
}

func TestDaemonContentServiceReturnsAppliedSessionAndExactEndpointSets(
	t *testing.T,
) {
	snapshot := daemonContentTestSnapshot(t)
	remoteID := daemonContentTestDeviceID(t, 0xc7)
	snapshot.Members = append(
		snapshot.Members,
		coordstatus.MemberSummary{
			ID: remoteID, Role: device.RoleEditor,
			Status: device.StatusActive, EntityVersion: 1,
		},
	)
	sort.Slice(snapshot.Members, func(left, right int) bool {
		return snapshot.Members[left].ID < snapshot.Members[right].ID
	})
	snapshot.MemberTotal = uint64(len(snapshot.Members))

	testNow := time.Date(2026, 8, 19, 12, 0, 0, 0, time.UTC)
	localSet := daemonContentTestEndpointSet(t, snapshot, testNow)
	remoteSet := []byte(`{"remote":2}`)
	state := &daemonContentStateStub{
		snapshot: snapshot,
		endpointSets: []store.MemberSignedEndpointSet{{
			DeviceID: remoteID, EndpointSetJSON: remoteSet,
		}},
	}
	service, err := newDaemonContentService(
		snapshot.SessionID,
		snapshot.WorkspaceID,
		snapshot.RecoveryGeneration,
		snapshot.Member.ID,
		state,
		&daemonEndpointSetSourceStub{value: localSet, found: true},
		&daemonEventProposalConsensusStub{},
		daemonContentTestBatchSigner(t),
		func() time.Time { return testNow },
	)
	if err != nil {
		t.Fatalf("newDaemonContentService(): %v", err)
	}

	session, err := service.Session(context.Background())
	if err != nil {
		t.Fatalf("Session(): %v", err)
	}
	if session.SessionID() != snapshot.SessionID ||
		session.WorkspaceID() != snapshot.WorkspaceID ||
		session.RecoveryGeneration() != snapshot.RecoveryGeneration ||
		session.ServerDeviceID() != snapshot.Member.ID ||
		session.DaemonVersion() != snapshot.Member.DaemonVersion ||
		session.MaxApplyLevel() != snapshot.Member.MaxApplyLevel ||
		len(session.RequiredCapabilities()) != 0 {
		t.Fatalf("session response = %#v", session)
	}

	peers, err := service.Peers(context.Background())
	if err != nil {
		t.Fatalf("Peers(): %v", err)
	}
	if !state.now.Valid() {
		t.Fatalf("endpoint read time = %q", state.now)
	}
	members := peers.Members()
	if len(members) != 2 ||
		members[0].DeviceID() >= members[1].DeviceID() {
		t.Fatalf("members = %#v", members)
	}
	endpoints := make(map[domain.DeviceID][]byte, len(members))
	for _, member := range members {
		endpoints[member.DeviceID()] = member.EndpointSet()
	}
	if !bytes.Equal(endpoints[snapshot.Member.ID], localSet) ||
		!bytes.Equal(endpoints[remoteID], remoteSet) {
		t.Fatalf("relayed endpoint sets = %#v", endpoints)
	}
	localSet[0] ^= 0xff
	remoteSet[0] ^= 0xff
	if bytes.Equal(
		daemonContentMember(t, peers, snapshot.Member.ID).EndpointSet(),
		localSet,
	) || bytes.Equal(
		daemonContentMember(t, peers, remoteID).EndpointSet(),
		remoteSet,
	) {
		t.Fatal("response retained caller-owned endpoint-set storage")
	}
}

func TestDaemonContentServiceSuppressesInactiveEndpointSet(t *testing.T) {
	snapshot := daemonContentTestSnapshot(t)
	remoteID := daemonContentTestDeviceID(t, 0xc8)
	snapshot.Members = append(
		snapshot.Members,
		coordstatus.MemberSummary{
			ID: remoteID, Role: device.RoleEditor,
			Status: device.StatusRevoked, EntityVersion: 2,
		},
	)
	sort.Slice(snapshot.Members, func(left, right int) bool {
		return snapshot.Members[left].ID < snapshot.Members[right].ID
	})
	snapshot.MemberTotal = uint64(len(snapshot.Members))
	testNow := time.Date(2026, 8, 19, 12, 5, 0, 0, time.UTC)
	service, err := newDaemonContentService(
		snapshot.SessionID,
		snapshot.WorkspaceID,
		snapshot.RecoveryGeneration,
		snapshot.Member.ID,
		&daemonContentStateStub{
			snapshot: snapshot,
			endpointSets: []store.MemberSignedEndpointSet{{
				DeviceID:        remoteID,
				EndpointSetJSON: []byte(`{"stale":1}`),
			}},
		},
		&daemonEndpointSetSourceStub{
			value: daemonContentTestEndpointSet(t, snapshot, testNow),
			found: true,
		},
		&daemonEventProposalConsensusStub{},
		daemonContentTestBatchSigner(t),
		func() time.Time { return testNow },
	)
	if err != nil {
		t.Fatalf("newDaemonContentService(): %v", err)
	}
	peers, err := service.Peers(context.Background())
	if err != nil {
		t.Fatalf("Peers(): %v", err)
	}
	if endpointSet := daemonContentMember(
		t,
		peers,
		remoteID,
	).EndpointSet(); endpointSet != nil {
		t.Fatalf("revoked member endpoint set = %q", endpointSet)
	}
}

func TestDaemonContentServiceProposesBoundCommittedResult(t *testing.T) {
	snapshot := daemonContentTestSnapshot(t)
	_, privateKey, deviceID := daemonTestInitialState(t)
	defer clear(privateKey)
	if deviceID != snapshot.Member.ID {
		t.Fatal("event fixture identity mismatch")
	}
	signed := daemonTestTaskEvent(t, privateKey, deviceID)
	proposals := &daemonEventProposalConsensusStub{
		lookup: daemonContentTestCommandLookup(t, signed, snapshot),
	}
	service, err := newDaemonContentService(
		snapshot.SessionID,
		snapshot.WorkspaceID,
		snapshot.RecoveryGeneration,
		snapshot.Member.ID,
		&daemonContentStateStub{snapshot: snapshot},
		&daemonEndpointSetSourceStub{},
		proposals,
		daemonContentTestBatchSigner(t),
		time.Now,
	)
	if err != nil {
		t.Fatalf("newDaemonContentService(): %v", err)
	}
	sender := daemonContentTestDeviceID(t, 0xd8)
	result, err := service.ProposeEvent(
		context.Background(),
		sender,
		signed.CanonicalBytes(),
		contenthttp.ProposalHopInitial,
	)
	if err != nil {
		t.Fatalf("ProposeEvent(): %v", err)
	}
	if proposals.calls != 1 ||
		proposals.sender != sender ||
		!bytes.Equal(proposals.canonical, signed.CanonicalBytes()) ||
		proposals.hop != contenthttp.ProposalHopInitial ||
		!bytes.Equal(result.Proposal(), signed.CanonicalBytes()) ||
		result.Outcome().Status != store.OutcomeAccepted {
		t.Fatalf(
			"proposal call/result = (%d, %s, %q, %+v)",
			proposals.calls,
			proposals.sender,
			proposals.canonical,
			result.Outcome(),
		)
	}
	if _, err := service.ProposeEvent(
		context.Background(),
		sender,
		signed.CanonicalBytes(),
		contenthttp.ProposalHopForwarded,
	); err != nil {
		t.Fatalf("ProposeEvent(forwarded): %v", err)
	}
	if proposals.calls != 2 ||
		proposals.hop != contenthttp.ProposalHopForwarded {
		t.Fatalf(
			"forwarded proposal call = (%d, %d)",
			proposals.calls,
			proposals.hop,
		)
	}

	for _, test := range []struct {
		name   string
		mutate func(*store.CommandResultLookup)
	}{
		{
			name: "session",
			mutate: func(lookup *store.CommandResultLookup) {
				lookup.SessionID =
					"01890f47-3e72-7000-8000-000000000799"
			},
		},
		{
			name: "generation",
			mutate: func(lookup *store.CommandResultLookup) {
				lookup.RecoveryGeneration++
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			lookup := daemonContentTestCommandLookup(
				t,
				signed,
				snapshot,
			)
			test.mutate(&lookup)
			proposals := &daemonEventProposalConsensusStub{
				lookup: lookup,
			}
			service.proposals = proposals
			if _, err := service.ProposeEvent(
				context.Background(),
				sender,
				signed.CanonicalBytes(),
				contenthttp.ProposalHopInitial,
			); !errors.Is(err, errDaemonContentConstruction) {
				t.Fatalf("ProposeEvent() error = %v", err)
			}
		})
	}
}

func TestDaemonContentServiceSignsAuthorityBoundResultBatch(t *testing.T) {
	snapshot := daemonContentTestSnapshot(t)
	exported := daemonContentTestResultRange(t, snapshot)
	state := &daemonContentStateStub{
		snapshot:    snapshot,
		resultRange: exported,
		resultFound: true,
	}
	service, err := newDaemonContentService(
		snapshot.SessionID,
		snapshot.WorkspaceID,
		snapshot.RecoveryGeneration,
		snapshot.Member.ID,
		state,
		&daemonEndpointSetSourceStub{},
		&daemonEventProposalConsensusStub{},
		daemonContentTestBatchSigner(t),
		time.Now,
	)
	if err != nil {
		t.Fatalf("newDaemonContentService(): %v", err)
	}

	batch, err := service.Replication(context.Background(), 0)
	if err != nil {
		t.Fatalf("Replication(): %v", err)
	}
	input := batch.Unsigned().Input()
	if input.SessionID != snapshot.SessionID ||
		input.WorkspaceID != snapshot.WorkspaceID ||
		input.RecoveryGeneration != snapshot.RecoveryGeneration ||
		input.ServerDeviceID != snapshot.Member.ID ||
		input.ServerAuthorityVersion !=
			snapshot.CredentialAuthority.VoterSetVersion ||
		input.FromResultIndex != 1 ||
		input.ToResultIndex != 1 ||
		state.resultOptions.AfterResultIndex != 0 ||
		state.resultOptions.MaxResults != replication.MaxBatchResults ||
		state.resultOptions.MaxBytes != replication.MaxBatchResultsBytes ||
		state.resultOptions.RequiredAuthorityDeviceID != snapshot.Member.ID {
		t.Fatalf(
			"signed batch/input options = %+v / %+v",
			input,
			state.resultOptions,
		)
	}
	_, privateKey, _ := daemonTestInitialState(t)
	defer clear(privateKey)
	if err := replication.VerifyBatch(
		batch,
		privateKey.Public().(ed25519.PublicKey),
	); err != nil {
		t.Fatalf("replication.VerifyBatch(): %v", err)
	}
}

func TestDaemonContentServiceSignsCurrentReplicationAcknowledgement(
	t *testing.T,
) {
	snapshot := daemonContentTestSnapshot(t)
	watermark := store.ReplicationWatermark{
		SessionID:             snapshot.SessionID,
		WorkspaceID:           snapshot.WorkspaceID,
		RecoveryGeneration:    snapshot.RecoveryGeneration,
		ResultIndex:           0,
		ResultHash:            store.Digest{0x11},
		ChainIndex:            0,
		ChainHash:             store.Digest{0x22},
		ProjectionAccumulator: store.Digest{0x33},
		ProjectionStateDigest: store.Digest{0x44},
		Authority:             snapshot.CredentialAuthority,
	}
	state := &daemonContentStateStub{
		snapshot:             snapshot,
		replicationWatermark: watermark,
	}
	service, err := newDaemonContentService(
		snapshot.SessionID,
		snapshot.WorkspaceID,
		snapshot.RecoveryGeneration,
		snapshot.Member.ID,
		state,
		&daemonEndpointSetSourceStub{},
		&daemonEventProposalConsensusStub{},
		daemonContentTestBatchSigner(t),
		time.Now,
	)
	if err != nil {
		t.Fatalf("newDaemonContentService(): %v", err)
	}
	_, privateKey, deviceID := daemonTestInitialState(t)
	defer clear(privateKey)
	service.signAcknowledgement = func(
		unsigned replication.UnsignedAcknowledgement,
	) (replication.Acknowledgement, error) {
		return replication.SignAcknowledgement(unsigned, privateKey)
	}

	acknowledgement, err := service.ReplicationAcknowledgement(
		context.Background(),
		0,
	)
	if err != nil {
		t.Fatalf("ReplicationAcknowledgement(): %v", err)
	}
	metadata := acknowledgement.Unsigned().Metadata()
	if state.watermarkSigner != deviceID ||
		metadata.SessionID != watermark.SessionID ||
		metadata.WorkspaceID != watermark.WorkspaceID ||
		metadata.RecoveryGeneration != watermark.RecoveryGeneration ||
		metadata.ServerDeviceID != deviceID ||
		metadata.ServerAuthorityVersion !=
			watermark.Authority.VoterSetVersion ||
		metadata.ResultIndex != watermark.ResultIndex ||
		metadata.ResultHash != chain.Digest(watermark.ResultHash) ||
		metadata.ChainIndex != watermark.ChainIndex ||
		metadata.ChainHash != chain.Digest(watermark.ChainHash) ||
		metadata.ProjectionAccumulator !=
			chain.Digest(watermark.ProjectionAccumulator) ||
		metadata.ProjectionStateDigest !=
			chain.Digest(watermark.ProjectionStateDigest) ||
		metadata.ServerAppliedResultIndex != watermark.ResultIndex {
		t.Fatalf("signed acknowledgement metadata = %+v", metadata)
	}
	if err := replication.VerifyAcknowledgement(
		acknowledgement,
		privateKey.Public().(ed25519.PublicKey),
	); err != nil {
		t.Fatalf("VerifyAcknowledgement(): %v", err)
	}
}

func TestDaemonContentServiceMapsReplicationAcknowledgementErrors(
	t *testing.T,
) {
	snapshot := daemonContentTestSnapshot(t)
	validWatermark := store.ReplicationWatermark{
		SessionID:          snapshot.SessionID,
		WorkspaceID:        snapshot.WorkspaceID,
		RecoveryGeneration: snapshot.RecoveryGeneration,
		ResultIndex:        0,
		Authority:          snapshot.CredentialAuthority,
	}
	sentinel := errors.New("watermark unavailable")
	for _, test := range []struct {
		name      string
		atResult  uint64
		watermark store.ReplicationWatermark
		storeErr  error
		want      error
	}{
		{
			name:      "cursor differs",
			atResult:  1,
			watermark: validWatermark,
			want:      contenthttp.ErrReplicationUnavailable,
		},
		{
			name:      "signer is not authority",
			watermark: validWatermark,
			storeErr:  store.ErrResultRangeAuthorityNotCovered,
			want:      contenthttp.ErrReplicationUnavailable,
		},
		{
			name:      "storage failure",
			watermark: validWatermark,
			storeErr:  sentinel,
			want:      errDaemonContentConstruction,
		},
		{
			name:      "invalid cursor",
			atResult:  domain.MaxSafeInteger + 1,
			watermark: validWatermark,
			want:      contenthttp.ErrInvalidReplicationCursor,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			state := &daemonContentStateStub{
				snapshot:             snapshot,
				replicationWatermark: test.watermark,
				watermarkErr:         test.storeErr,
			}
			service, err := newDaemonContentService(
				snapshot.SessionID,
				snapshot.WorkspaceID,
				snapshot.RecoveryGeneration,
				snapshot.Member.ID,
				state,
				&daemonEndpointSetSourceStub{},
				&daemonEventProposalConsensusStub{},
				daemonContentTestBatchSigner(t),
				time.Now,
			)
			if err != nil {
				t.Fatalf("newDaemonContentService(): %v", err)
			}
			_, privateKey, _ := daemonTestInitialState(t)
			defer clear(privateKey)
			service.signAcknowledgement = func(
				unsigned replication.UnsignedAcknowledgement,
			) (replication.Acknowledgement, error) {
				return replication.SignAcknowledgement(
					unsigned,
					privateKey,
				)
			}
			if _, err := service.ReplicationAcknowledgement(
				context.Background(),
				test.atResult,
			); !errors.Is(err, test.want) {
				t.Fatalf(
					"ReplicationAcknowledgement() error = %v, want %v",
					err,
					test.want,
				)
			}
		})
	}
}

func TestDaemonContentServiceMapsReplicationErrors(t *testing.T) {
	snapshot := daemonContentTestSnapshot(t)
	sentinel := errors.New("storage unavailable")
	tests := []struct {
		name   string
		found  bool
		err    error
		mutate func(*coordstatus.DurableSnapshot)
		want   error
	}{
		{
			name: "cursor outside generation",
			err:  store.ErrResultRangeNotCovered,
			want: contenthttp.ErrInvalidReplicationCursor,
		},
		{
			name: "cursor before generation",
			err:  store.ErrResultRangeSnapshotRequired,
			want: contenthttp.ErrReplicationSnapshotRequired,
		},
		{
			name:  "current cursor",
			found: false,
			want:  contenthttp.ErrReplicationUnavailable,
		},
		{
			name: "authority beyond page",
			err:  store.ErrResultRangeAuthorityNotCovered,
			want: contenthttp.ErrReplicationSnapshotRequired,
		},
		{
			name: "non-authority server",
			err:  store.ErrResultRangeAuthorityNotCovered,
			mutate: func(value *coordstatus.DurableSnapshot) {
				authority, err := voterset.New(
					value.SessionID,
					[]domain.DeviceID{
						daemonContentTestDeviceID(t, 0xf1),
					},
					value.CredentialAuthority.VoterSetVersion,
				)
				if err != nil {
					t.Fatalf("voterset.New(non-authority): %v", err)
				}
				value.CredentialAuthority = authority
			},
			want: contenthttp.ErrReplicationUnavailable,
		},
		{
			name: "first result exceeds page",
			err:  store.ErrResultRangeTooLarge,
			want: contenthttp.ErrReplicationSnapshotRequired,
		},
		{
			name: "storage",
			err:  sentinel,
			want: errDaemonContentConstruction,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			testSnapshot := snapshot
			if test.mutate != nil {
				test.mutate(&testSnapshot)
			}
			service, err := newDaemonContentService(
				testSnapshot.SessionID,
				testSnapshot.WorkspaceID,
				testSnapshot.RecoveryGeneration,
				testSnapshot.Member.ID,
				&daemonContentStateStub{
					snapshot:    testSnapshot,
					resultFound: test.found,
					resultErr:   test.err,
				},
				&daemonEndpointSetSourceStub{},
				&daemonEventProposalConsensusStub{},
				daemonContentTestBatchSigner(t),
				time.Now,
			)
			if err != nil {
				t.Fatalf("newDaemonContentService(): %v", err)
			}
			if _, err := service.Replication(
				context.Background(),
				0,
			); !errors.Is(err, test.want) {
				t.Fatalf("Replication() error = %v, want %v", err, test.want)
			}
		})
	}

	service, err := newDaemonContentService(
		snapshot.SessionID,
		snapshot.WorkspaceID,
		snapshot.RecoveryGeneration,
		snapshot.Member.ID,
		&daemonContentStateStub{snapshot: snapshot},
		&daemonEndpointSetSourceStub{},
		&daemonEventProposalConsensusStub{},
		daemonContentTestBatchSigner(t),
		time.Now,
	)
	if err != nil {
		t.Fatalf("newDaemonContentService(): %v", err)
	}
	if _, err := service.Replication(
		context.Background(),
		domain.MaxSafeInteger+1,
	); !errors.Is(err, contenthttp.ErrInvalidReplicationCursor) {
		t.Fatalf("Replication(invalid cursor) error = %v", err)
	}
}

func TestDaemonContentServiceMapsProposalErrors(t *testing.T) {
	snapshot := daemonContentTestSnapshot(t)
	sentinel := errors.New("unexpected proposal failure")
	tests := []struct {
		name string
		err  error
		want error
	}{
		{
			name: "invalid",
			err:  consensus.ErrInvalidPeerProposal,
			want: contenthttp.ErrInvalidEventProposal,
		},
		{
			name: "idempotency conflict",
			err:  store.ErrIdempotencyConflict,
			want: contenthttp.ErrEventIdempotencyConflict,
		},
		{
			name: "rate limited",
			err:  consensus.ErrProposalIngressRateLimited,
			want: contenthttp.ErrEventProposalRateLimited,
		},
		{
			name: "canceled",
			err:  context.Canceled,
			want: context.Canceled,
		},
		{
			name: "not leader",
			err:  raft.ErrNotLeader,
			want: contenthttp.ErrEventProposalUnavailable,
		},
		{
			name: "leadership lost",
			err:  raft.ErrLeadershipLost,
			want: contenthttp.ErrEventProposalUnavailable,
		},
		{
			name: "forwarding unavailable",
			err:  consensus.ErrProposalForwardingUnavailable,
			want: contenthttp.ErrEventProposalUnavailable,
		},
		{
			name: "node closed",
			err:  consensus.ErrNodeClosed,
			want: contenthttp.ErrEventProposalUnavailable,
		},
		{
			name: "unexpected",
			err:  sentinel,
			want: errDaemonContentConstruction,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			service, err := newDaemonContentService(
				snapshot.SessionID,
				snapshot.WorkspaceID,
				snapshot.RecoveryGeneration,
				snapshot.Member.ID,
				&daemonContentStateStub{snapshot: snapshot},
				&daemonEndpointSetSourceStub{},
				&daemonEventProposalConsensusStub{err: test.err},
				daemonContentTestBatchSigner(t),
				time.Now,
			)
			if err != nil {
				t.Fatalf("newDaemonContentService(): %v", err)
			}
			if _, err := service.ProposeEvent(
				context.Background(),
				daemonContentTestDeviceID(t, 0xd9),
				[]byte(`{}`),
				contenthttp.ProposalHopInitial,
			); !errors.Is(err, test.want) {
				t.Fatalf("ProposeEvent() error = %v, want %v", err, test.want)
			}
		})
	}
}

func TestDaemonContentServiceFailsClosed(t *testing.T) {
	sentinel := errors.New("state unavailable")
	valid := daemonContentTestSnapshot(t)
	tests := []struct {
		name       string
		snapshot   coordstatus.DurableSnapshot
		stateErr   error
		sets       []store.MemberSignedEndpointSet
		setErr     error
		localSet   []byte
		localFound bool
	}{
		{
			name: "snapshot unavailable", snapshot: valid,
			stateErr: sentinel, localSet: []byte(`{}`), localFound: true,
		},
		{
			name: "truncated roster",
			snapshot: func() coordstatus.DurableSnapshot {
				value := valid
				value.MembersTruncated = true
				value.MemberTotal++
				return value
			}(),
			localSet: []byte(`{}`), localFound: true,
		},
		{
			name: "endpoint state unavailable", snapshot: valid,
			setErr: sentinel, localSet: []byte(`{}`), localFound: true,
		},
		{
			name: "local endpoint set unavailable", snapshot: valid,
		},
		{
			name: "noncanonical local endpoint set", snapshot: valid,
			localSet: []byte(`{"b":1,"a":2}`), localFound: true,
		},
		{
			name: "unsorted relayed endpoint sets", snapshot: valid,
			sets: []store.MemberSignedEndpointSet{
				{
					DeviceID:        daemonContentTestDeviceID(t, 0xd2),
					EndpointSetJSON: []byte(`{}`),
				},
				{
					DeviceID:        daemonContentTestDeviceID(t, 0xd1),
					EndpointSetJSON: []byte(`{}`),
				},
			},
			localSet: []byte(`{}`), localFound: true,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			service, err := newDaemonContentService(
				test.snapshot.SessionID,
				test.snapshot.WorkspaceID,
				test.snapshot.RecoveryGeneration,
				test.snapshot.Member.ID,
				&daemonContentStateStub{
					snapshot: test.snapshot, snapshotErr: test.stateErr,
					endpointSets: test.sets, endpointsErr: test.setErr,
				},
				&daemonEndpointSetSourceStub{
					value: test.localSet, found: test.localFound,
				},
				&daemonEventProposalConsensusStub{},
				daemonContentTestBatchSigner(t),
				time.Now,
			)
			if err != nil {
				t.Fatalf("newDaemonContentService(): %v", err)
			}
			if _, err := service.Peers(context.Background()); !errors.Is(
				err,
				errDaemonContentConstruction,
			) {
				t.Fatalf("Peers() error = %v", err)
			}
		})
	}
}

func daemonContentTestCommandLookup(
	t *testing.T,
	signed event.SignedEvent,
	snapshot coordstatus.DurableSnapshot,
) store.CommandResultLookup {
	t.Helper()
	canonical := signed.CanonicalBytes()
	proposalDigest := sha256.Sum256(canonical)
	chainHash := store.Digest(sha256.Sum256([]byte("daemon-content-chain")))
	chainIndex := uint64(1)
	return store.CommandResultLookup{
		EventID:            signed.Proposal().EventID,
		SessionID:          snapshot.SessionID,
		RecoveryGeneration: snapshot.RecoveryGeneration,
		CanonicalProposal:  canonical,
		ProposalDigest:     proposalDigest,
		Outcome: store.CommandOutcome{
			Status: store.OutcomeAccepted,
			Code:   "accepted",
			JSON:   []byte(`{"code":"accepted","status":"accepted"}`),
		},
		Tuple: store.CommandResultTuple{
			ResultIndex: 1,
			ChainIndex:  &chainIndex,
			ChainHash:   &chainHash,
		},
	}
}

func daemonContentTestResultRange(
	t *testing.T,
	snapshot coordstatus.DurableSnapshot,
) store.ResultRange {
	t.Helper()
	_, privateKey, deviceID := daemonTestInitialState(t)
	defer clear(privateKey)
	if deviceID != snapshot.Member.ID {
		t.Fatal("result-range fixture identity mismatch")
	}
	signed := daemonTestTaskEvent(t, privateKey, deviceID)
	proposal := signed.CanonicalBytes()
	startResult := chain.Digest{}
	startChain := chain.Digest{}
	endChain, err := chain.AppendEvent(startChain, proposal)
	if err != nil {
		t.Fatalf("chain.AppendEvent(): %v", err)
	}
	proposalDigest := sha256.Sum256(proposal)
	chainIndex := uint64(1)
	result := chain.Result{
		ResultIndex:    1,
		Proposal:       proposal,
		Outcome:        []byte(`{"code":"accepted","status":"accepted"}`),
		ProposalDigest: proposalDigest,
		ChainIndex:     &chainIndex,
		ChainHash:      &endChain,
	}
	endResult, encoded, err := chain.AppendResult(startResult, result)
	if err != nil {
		t.Fatalf("chain.AppendResult(): %v", err)
	}
	return store.ResultRange{
		SessionID:                snapshot.SessionID,
		WorkspaceID:              snapshot.WorkspaceID,
		RecoveryGeneration:       snapshot.RecoveryGeneration,
		FromResultIndex:          1,
		ToResultIndex:            1,
		StartResultHash:          startResult,
		EndResultHash:            endResult,
		StartChainIndex:          0,
		StartChainHash:           startChain,
		EndChainIndex:            1,
		EndChainHash:             endChain,
		Results:                  [][]byte{encoded},
		ServerAppliedResultIndex: 1,
		Authority:                snapshot.CredentialAuthority,
	}
}

func daemonContentTestSnapshot(t *testing.T) coordstatus.DurableSnapshot {
	t.Helper()
	initial, _, deviceID := daemonTestInitialState(t)
	directory := t.TempDir()
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatalf("secure content test directory: %v", err)
	}
	database, err := store.Open(
		context.Background(),
		store.Options{Path: filepath.Join(directory, "state.db")},
	)
	if err != nil {
		t.Fatalf("store.Open(): %v", err)
	}
	t.Cleanup(func() {
		if err := database.Close(); err != nil {
			t.Errorf("close content test store: %v", err)
		}
	})
	if _, err := database.Initialize(context.Background(), initial); err != nil {
		t.Fatalf("Initialize(): %v", err)
	}
	snapshot, err := database.LocalState().StatusSnapshot(
		context.Background(),
		deviceID,
		1,
	)
	if err != nil {
		t.Fatalf("StatusSnapshot(): %v", err)
	}
	return snapshot
}

func daemonContentTestEndpointSet(
	t *testing.T,
	snapshot coordstatus.DurableSnapshot,
	now time.Time,
) []byte {
	t.Helper()
	_, privateKey, deviceID := daemonTestInitialState(t)
	defer clear(privateKey)
	if deviceID != snapshot.Member.ID {
		t.Fatal("content endpoint fixture identity mismatch")
	}
	address := netip.MustParseAddr("192.0.2.31")
	signer, err := discovery.NewEndpointSigner(
		daemonContentTestAdvertisementInterval,
		47831,
		[]netip.Addr{address},
	)
	if err != nil {
		t.Fatalf("discovery.NewEndpointSigner(): %v", err)
	}
	now = now.UTC().Truncate(time.Second)
	encoded, err := signer.Sign(
		discovery.EndpointSet{
			SessionID:          snapshot.SessionID,
			WorkspaceID:        snapshot.WorkspaceID,
			RecoveryGeneration: snapshot.RecoveryGeneration,
			DeviceID:           snapshot.Member.ID,
			EndpointSequence:   uint64(now.UnixMilli()),
			IssuedAt: domain.WholeSecondTimestamp(
				now.Format(time.RFC3339),
			),
			ExpiresAt: domain.WholeSecondTimestamp(
				now.Add(
					discovery.EndpointHintTTLIntervals *
						daemonContentTestAdvertisementInterval,
				).Format(time.RFC3339),
			),
			Endpoints: []discovery.Endpoint{{IP: address, Port: 47831}},
		},
		privateKey,
	)
	if err != nil {
		t.Fatalf("EndpointSigner.Sign(): %v", err)
	}
	return encoded
}

func daemonContentTestDeviceID(t *testing.T, seed byte) domain.DeviceID {
	t.Helper()
	privateKey := ed25519.NewKeyFromSeed(
		bytes.Repeat([]byte{seed}, ed25519.SeedSize),
	)
	defer clear(privateKey)
	value, err := device.DeriveID(
		privateKey.Public().(ed25519.PublicKey),
	)
	if err != nil {
		t.Fatalf("device.DeriveID(): %v", err)
	}
	return value
}

func daemonContentTestBatchSigner(t *testing.T) daemonResultBatchSigner {
	t.Helper()
	_, privateKey, _ := daemonTestInitialState(t)
	t.Cleanup(func() {
		clear(privateKey)
	})
	return func(
		unsigned replication.UnsignedBatch,
	) (replication.Batch, error) {
		return replication.SignBatch(unsigned, privateKey)
	}
}

func daemonContentMember(
	t *testing.T,
	response contenthttp.PeersResponse,
	deviceID domain.DeviceID,
) contenthttp.PeerMember {
	t.Helper()
	for _, member := range response.Members() {
		if member.DeviceID() == deviceID {
			return member
		}
	}
	t.Fatalf("member %s not found", deviceID)
	return contenthttp.PeerMember{}
}
