package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"sort"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/ijonahch/codecomm/internal/codec"
	"github.com/ijonahch/codecomm/internal/consensus"
	"github.com/ijonahch/codecomm/internal/contenthttp"
	"github.com/ijonahch/codecomm/internal/discovery"
	"github.com/ijonahch/codecomm/internal/domain"
	"github.com/ijonahch/codecomm/internal/domain/device"
	"github.com/ijonahch/codecomm/internal/domain/policy"
	"github.com/ijonahch/codecomm/internal/logicalsnapshot"
	"github.com/ijonahch/codecomm/internal/store"
	"github.com/ijonahch/codecomm/internal/transport"
	"golang.org/x/net/http2"
)

var errDaemonMeshContentHarness = errors.New(
	"codecommd test: invalid content mesh harness",
)

type daemonMeshIntegrationFactoryCapture struct {
	mu          sync.RWMutex
	certificate transport.ContentCertificateProvider
	localState  store.LocalState
	consensus   *consensus.Node
	fatal       daemonFatalComponent
	stage       string
	ready       bool
}

func (capture *daemonMeshIntegrationFactoryCapture) reset() {
	if capture == nil {
		return
	}
	capture.mu.Lock()
	capture.certificate = nil
	capture.localState = store.LocalState{}
	capture.consensus = nil
	capture.fatal = nil
	capture.stage = "factory-created"
	capture.ready = false
	capture.mu.Unlock()
}

func (capture *daemonMeshIntegrationFactoryCapture) mark(stage string) {
	if capture == nil {
		return
	}
	capture.mu.Lock()
	capture.stage = stage
	capture.mu.Unlock()
}

func (capture *daemonMeshIntegrationFactoryCapture) replace(
	certificate transport.ContentCertificateProvider,
	localState store.LocalState,
	node *consensus.Node,
	admission daemonPeerAdmissionRuntime,
) {
	capture.mu.Lock()
	capture.certificate = certificate
	capture.localState = localState
	capture.consensus = node
	capture.fatal, _ = admission.(daemonFatalComponent)
	capture.stage = "ingress-created"
	capture.ready = true
	capture.mu.Unlock()
}

func (capture *daemonMeshIntegrationFactoryCapture) snapshot() (
	transport.ContentCertificateProvider,
	store.LocalState,
	bool,
) {
	if capture == nil {
		return nil, store.LocalState{}, false
	}
	capture.mu.RLock()
	defer capture.mu.RUnlock()
	return capture.certificate, capture.localState, capture.ready
}

func (capture *daemonMeshIntegrationFactoryCapture) consensusNode() (
	*consensus.Node,
	bool,
) {
	if capture == nil {
		return nil, false
	}
	capture.mu.RLock()
	defer capture.mu.RUnlock()
	return capture.consensus,
		capture.ready && capture.consensus != nil
}

func (capture *daemonMeshIntegrationFactoryCapture) fatalError() error {
	if capture == nil {
		return nil
	}
	capture.mu.RLock()
	fatal := capture.fatal
	capture.mu.RUnlock()
	if fatal == nil {
		return nil
	}
	return fatal.FatalError()
}

func (capture *daemonMeshIntegrationFactoryCapture) lifecycleState() (
	string,
	bool,
) {
	if capture == nil {
		return "", false
	}
	capture.mu.RLock()
	defer capture.mu.RUnlock()
	return capture.stage, capture.ready
}

type daemonMeshIntegrationTransportFactory struct {
	delegate daemonConsensusTransportFactory
	capture  *daemonMeshIntegrationFactoryCapture
}

func newDaemonMeshIntegrationFactoryConstructor(
	capture *daemonMeshIntegrationFactoryCapture,
) daemonMeshFactoryConstructor {
	return func(
		options daemonOptions,
		deviceID domain.DeviceID,
		identityCertificate tls.Certificate,
		credentialNow func() time.Time,
	) (daemonConsensusTransportFactory, error) {
		if capture == nil {
			return nil, errDaemonMeshContentHarness
		}
		delegate, err := newDaemonMeshTransportFactory(
			options,
			deviceID,
			identityCertificate,
			credentialNow,
		)
		if err != nil {
			return nil, err
		}
		return &daemonMeshIntegrationTransportFactory{
			delegate: delegate,
			capture:  capture,
		}, nil
	}
}

func (factory *daemonMeshIntegrationTransportFactory) Build(
	gate consensus.ConsensusTransportGate,
) (consensus.RaftTransport, error) {
	if factory == nil || factory.delegate == nil {
		return nil, errDaemonMeshContentHarness
	}
	factory.capture.mark("build-raft-transport")
	return factory.delegate.Build(gate)
}

func (factory *daemonMeshIntegrationTransportFactory) BuildSettledControl(
	admission daemonSettledControlAdmission,
) (daemonSettledControlTransport, error) {
	if factory == nil || factory.delegate == nil || admission == nil {
		return nil, errDaemonMeshContentHarness
	}
	factory.capture.mark("build-settled-control")
	return factory.delegate.BuildSettledControl(admission)
}

func (factory *daemonMeshIntegrationTransportFactory) NewIngress(
	ctx context.Context,
	options daemonOptions,
	node daemonPeerAdmissionRuntime,
	certificate transport.ContentCertificateProvider,
	pairingHandler transport.ConnectionHandler,
	contentHandler transport.ConnectionHandler,
	listener net.Listener,
) (*transport.Ingress, error) {
	if factory == nil || factory.delegate == nil || factory.capture == nil ||
		node == nil || certificate == nil || contentHandler == nil {
		return nil, errDaemonMeshContentHarness
	}
	factory.capture.mark("create-ingress")
	localStateSource, ok := node.(interface {
		LocalState() (store.LocalState, error)
	})
	if !ok {
		return nil, errDaemonMeshContentHarness
	}
	localState, err := localStateSource.LocalState()
	if err != nil {
		return nil, err
	}
	consensusNode, _ := node.(*consensus.Node)
	ingress, err := factory.delegate.NewIngress(
		ctx,
		options,
		node,
		certificate,
		pairingHandler,
		contentHandler,
		listener,
	)
	if err != nil {
		return nil, err
	}
	factory.capture.replace(certificate, localState, consensusNode, node)
	return ingress, nil
}

func (factory *daemonMeshIntegrationTransportFactory) ConsensusRoutes() *transport.ConsensusRouteTable {
	if factory == nil || factory.delegate == nil {
		return nil
	}
	return factory.delegate.ConsensusRoutes()
}

func (factory *daemonMeshIntegrationTransportFactory) SetAuthenticatedConnectivity(
	observer transport.ConsensusAuthenticatedDialObserver,
	notifier daemonConnectivityNotifier,
) error {
	if factory == nil || factory.delegate == nil {
		return errDaemonMeshContentHarness
	}
	factory.capture.mark("set-authenticated-connectivity")
	return factory.delegate.SetAuthenticatedConnectivity(observer, notifier)
}

func (factory *daemonMeshIntegrationTransportFactory) ClearIdentityCertificate() {
	if factory != nil && factory.delegate != nil {
		factory.delegate.ClearIdentityCertificate()
	}
}

type daemonMeshIntegrationMulticast struct {
	triggers chan struct{}
	closed   chan struct{}
	close    sync.Once
}

func openDaemonMeshIntegrationMulticast(
	port uint16,
	selected []discovery.MulticastInterfaceSelection,
) (daemonDiscoveryMulticast, discovery.MulticastReport, error) {
	report, err := daemonMeshIntegrationMulticastReport(port, selected)
	if err != nil {
		return nil, discovery.MulticastReport{}, err
	}
	multicast := &daemonMeshIntegrationMulticast{
		triggers: make(chan struct{}, 1),
		closed:   make(chan struct{}),
	}
	multicast.triggers <- struct{}{}
	return multicast, report, nil
}

func daemonMeshIntegrationMulticastReport(
	port uint16,
	selected []discovery.MulticastInterfaceSelection,
) (discovery.MulticastReport, error) {
	if port != discovery.DefaultMulticastPort || len(selected) == 0 {
		return discovery.MulticastReport{}, errDaemonMeshContentHarness
	}
	report := discovery.MulticastReport{
		Joins: make([]discovery.InterfaceJoin, 0, len(selected)*2),
	}
	for _, selection := range selected {
		networkInterface := selection.Interface
		if networkInterface.Index < 1 || networkInterface.Name == "" ||
			networkInterface.Flags&net.FlagUp == 0 ||
			networkInterface.Flags&net.FlagLoopback != 0 ||
			len(selection.Families) == 0 {
			return discovery.MulticastReport{}, errDaemonMeshContentHarness
		}
		for _, family := range selection.Families {
			report.Joins = append(report.Joins, discovery.InterfaceJoin{
				InterfaceIndex: networkInterface.Index,
				InterfaceName:  networkInterface.Name,
				Family:         family,
			})
		}
	}
	return report, nil
}

func (multicast *daemonMeshIntegrationMulticast) AdvertisementTriggers() <-chan struct{} {
	return multicast.triggers
}

func (multicast *daemonMeshIntegrationMulticast) Send(payload []byte) error {
	if len(payload) == 0 || len(payload) > discovery.MaxDatagramBytes {
		return discovery.ErrMulticastDatagramSize
	}
	select {
	case <-multicast.closed:
		return discovery.ErrMulticastClosed
	default:
		return nil
	}
}

func (multicast *daemonMeshIntegrationMulticast) ReceiveDatagram(
	ctx context.Context,
) (discovery.ReceivedDatagram, error) {
	select {
	case <-ctx.Done():
		return discovery.ReceivedDatagram{}, ctx.Err()
	case <-multicast.closed:
		return discovery.ReceivedDatagram{}, discovery.ErrMulticastClosed
	}
}

func (multicast *daemonMeshIntegrationMulticast) RefreshSelected(
	selected []discovery.MulticastInterfaceSelection,
) (discovery.MulticastReport, error) {
	select {
	case <-multicast.closed:
		return discovery.MulticastReport{}, discovery.ErrMulticastClosed
	default:
		return daemonMeshIntegrationMulticastReport(
			discovery.DefaultMulticastPort,
			selected,
		)
	}
}

func (multicast *daemonMeshIntegrationMulticast) Close() error {
	if multicast == nil {
		return errDaemonMeshContentHarness
	}
	multicast.close.Do(func() {
		close(multicast.closed)
	})
	return nil
}

type daemonMeshPeersResponse struct {
	SchemaVersion      uint64                 `json:"schema_version"`
	SessionID          string                 `json:"session_id"`
	WorkspaceID        string                 `json:"workspace_id"`
	RecoveryGeneration uint64                 `json:"recovery_generation"`
	ServerDeviceID     string                 `json:"server_device_id"`
	Members            []daemonMeshPeerMember `json:"members"`
}

type daemonMeshPeerMember struct {
	DeviceID      string  `json:"device_id"`
	Role          string  `json:"role"`
	Status        string  `json:"status"`
	EntityVersion uint64  `json:"entity_version"`
	EndpointSet   *string `json:"endpoint_set,omitempty"`
}

func exerciseDaemonContentMesh(
	t *testing.T,
	nodes []*daemonMeshIntegrationNode,
	nonvoter device.Device,
) {
	t.Helper()
	if len(nodes) != 3 {
		t.Fatalf("content mesh nodes = %d, want 3", len(nodes))
	}
	waitForDaemonMeshContentCredentials(t, nodes)
	source, target, relay := nodes[0], nodes[1], nodes[2]
	exerciseDaemonLogicalSnapshotContent(t, nodes)

	targetResponse := requestDaemonMeshPeers(t, source, target)
	assertDaemonMeshPeersRoster(t, targetResponse, target, nodes, nonvoter)
	targetEncoded := daemonMeshMemberEndpointSet(
		t,
		targetResponse,
		target.deviceID,
		true,
	)
	targetBytes, err := codec.DecodeBase64URL(targetEncoded)
	if err != nil {
		t.Fatalf("decode target endpoint set: %v", err)
	}
	verifiedTarget := validateDaemonMeshEndpointSet(
		t,
		target,
		targetBytes,
	)
	if verifiedTarget.OpaqueRelay() != targetEncoded ||
		!bytes.Equal(verifiedTarget.CanonicalBytes(), targetBytes) {
		t.Fatal("target endpoint set was not relayed as exact base64url JCS")
	}
	targetBytes = waitForDaemonMeshRelayedEndpointSet(
		t, relay, target.deviceID, targetBytes,
	)
	targetEncoded = codec.EncodeBase64URL(targetBytes)
	verifiedTarget = validateDaemonMeshEndpointSet(
		t,
		target,
		targetBytes,
	)
	relayResponse := requestDaemonMeshPeers(t, source, relay)
	assertDaemonMeshPeersRoster(t, relayResponse, relay, nodes, nonvoter)
	relayedEncoded := daemonMeshMemberEndpointSet(
		t,
		relayResponse,
		target.deviceID,
		true,
	)
	if relayedEncoded != targetEncoded {
		relayedBytes, err := codec.DecodeBase64URL(relayedEncoded)
		if err != nil {
			t.Fatalf("decode relayed endpoint successor: %v", err)
		}
		relayed := validateDaemonMeshEndpointSet(
			t,
			target,
			relayedBytes,
		)
		if relayed.EndpointSet().EndpointSequence <=
			verifiedTarget.EndpointSet().EndpointSequence {
			t.Fatalf(
				"relayed endpoint bytes changed without a successor: got %q, want %q",
				relayedEncoded,
				targetEncoded,
			)
		}
		verifiedTarget = relayed
	}

	_, relayState, ready := relay.meshCapture.snapshot()
	if !ready {
		t.Fatal("relay local state was not captured")
	}
	shortSet, expiresAt := signDaemonMeshShortEndpointSet(
		t,
		target,
		verifiedTarget.EndpointSet(),
	)
	update, err := relayState.ReplaceMemberSignedEndpointSet(
		context.Background(),
		shortSet,
		daemonMeshTimestamp(t, time.Now()),
	)
	if err != nil || update != store.MemberEndpointSetReplaced {
		t.Fatalf(
			"ReplaceMemberSignedEndpointSet(successor) = (%v, %v)",
			update,
			err,
		)
	}
	shortEncoded := codec.EncodeBase64URL(shortSet)
	currentResponse := requestDaemonMeshPeers(t, source, relay)
	if current := daemonMeshMemberEndpointSet(
		t,
		currentResponse,
		target.deviceID,
		true,
	); current != shortEncoded {
		t.Fatalf("successor relay = %q, want %q", current, shortEncoded)
	}

	if delay := time.Until(expiresAt.Add(150 * time.Millisecond)); delay > 0 {
		time.Sleep(delay)
	}
	expiredResponse := requestDaemonMeshPeers(t, source, relay)
	assertDaemonMeshPeersRoster(t, expiredResponse, relay, nodes, nonvoter)
	replacement, present := daemonMeshOptionalMemberEndpointSet(
		t,
		expiredResponse,
		target.deviceID,
	)
	if present {
		if replacement == shortEncoded {
			t.Fatal("expired endpoint set remained available for relay")
		}
		replacementBytes, err := codec.DecodeBase64URL(replacement)
		if err != nil {
			t.Fatalf("decode replacement endpoint set: %v", err)
		}
		validateDaemonMeshEndpointSet(t, target, replacementBytes)
	}
}

type daemonMeshSnapshotBulkConnection struct {
	client    *contenthttp.SnapshotBulkClient
	tlsConfig *tls.Config
}

func (connection *daemonMeshSnapshotBulkConnection) Close() error {
	if connection == nil {
		return nil
	}
	var err error
	if connection.client != nil {
		err = connection.client.Close()
		connection.client = nil
	}
	clearDaemonClientTLSConfig(connection.tlsConfig)
	connection.tlsConfig = nil
	return err
}

func exerciseDaemonLogicalSnapshotContent(
	t *testing.T,
	nodes []*daemonMeshIntegrationNode,
) {
	t.Helper()
	if len(nodes) < 2 {
		t.Fatal("logical snapshot mesh requires two nodes")
	}
	var target *daemonMeshIntegrationNode
	deadline := time.Now().Add(daemonMeshIntegrationTimeout)
	for time.Now().Before(deadline) {
		for _, candidate := range nodes {
			node, ready := candidate.meshCapture.consensusNode()
			if ready && node.IsLeader() {
				target = candidate
				break
			}
		}
		if target != nil {
			break
		}
		time.Sleep(25 * time.Millisecond)
	}
	if target == nil {
		t.Fatal("logical snapshot publisher leader is unavailable")
	}
	var source *daemonMeshIntegrationNode
	for _, candidate := range nodes {
		if candidate != target {
			source = candidate
			break
		}
	}
	if source == nil {
		t.Fatal("logical snapshot content source is unavailable")
	}
	sourceProvider, _, ready := source.meshCapture.snapshot()
	if !ready || sourceProvider == nil {
		t.Fatal("logical snapshot client credential is unavailable")
	}
	sourceCertificate, err := sourceProvider()
	if err != nil {
		t.Fatalf("logical snapshot client credential: %v", err)
	}
	defer clearDaemonTLSCertificate(&sourceCertificate)
	ctx, cancel := context.WithTimeout(
		context.Background(),
		daemonMeshIntegrationTimeout,
	)
	defer cancel()
	var control *daemonMeshPairedContentConnection
	var lastErr error
	for ctx.Err() == nil {
		control, err = dialDaemonMeshExternalContentClient(
			ctx,
			sourceCertificate,
			source.peerEndpoint.Addr(),
			target,
		)
		if err == nil {
			if _, err = control.client.Session(ctx); err == nil {
				break
			}
			err = errors.Join(err, control.Close())
			control = nil
		}
		lastErr = err
		select {
		case <-ctx.Done():
		case <-time.After(25 * time.Millisecond):
		}
	}
	if control == nil {
		t.Fatalf(
			"logical snapshot control did not stabilize: %v",
			errors.Join(lastErr, ctx.Err()),
		)
	}
	defer func() {
		if err := control.Close(); err != nil {
			t.Errorf("close logical snapshot control: %v", err)
		}
	}()
	var root logicalsnapshot.Root
	for {
		root, err = control.client.LatestSnapshot(ctx)
		if err == nil {
			break
		}
		if !errors.Is(err, contenthttp.ErrSnapshotUnavailable) {
			t.Fatalf("fetch latest logical snapshot: %v", err)
		}
		select {
		case <-ctx.Done():
			t.Fatalf(
				"logical snapshot publication timed out: %v",
				ctx.Err(),
			)
		case <-time.After(50 * time.Millisecond):
		}
	}
	rootInput := root.Unsigned().Input()
	if rootInput.SignerDeviceID != target.deviceID ||
		rootInput.ChunkCount < 1 ||
		rootInput.DescriptorPageCount < 1 {
		t.Fatalf("published logical snapshot root = %+v", rootInput)
	}
	bulk, err := dialDaemonMeshExternalSnapshotBulk(
		ctx,
		sourceCertificate,
		source.peerEndpoint.Addr(),
		target,
		root,
	)
	if err != nil {
		t.Fatalf("dial logical snapshot bulk: %v", err)
	}
	defer func() {
		if err := bulk.Close(); err != nil {
			t.Errorf("close logical snapshot bulk: %v", err)
		}
	}()
	page, err := bulk.client.SnapshotManifestPage(ctx, 0)
	if err != nil {
		t.Fatalf("fetch logical snapshot page: %v", err)
	}
	pageInput := page.Input()
	if len(pageInput.Descriptors) < 1 ||
		pageInput.Descriptors[0].ChunkIndex != 0 {
		t.Fatalf("logical snapshot first page = %+v", pageInput)
	}
	chunk, err := bulk.client.SnapshotChunk(ctx, 0)
	if err != nil {
		t.Fatalf("fetch logical snapshot chunk: %v", err)
	}
	content := chunk.Bytes()
	descriptor := pageInput.Descriptors[0]
	if uint64(len(content)) != descriptor.CompressedLength ||
		sha256.Sum256(content) != descriptor.SHA256 {
		t.Fatal("logical snapshot bulk chunk differs from signed descriptor")
	}
}

func dialDaemonMeshExternalSnapshotBulk(
	ctx context.Context,
	certificate tls.Certificate,
	selectedAddress netip.Addr,
	target *daemonMeshIntegrationNode,
	root logicalsnapshot.Root,
) (*daemonMeshSnapshotBulkConnection, error) {
	if ctx == nil ||
		ctx.Err() != nil ||
		!selectedAddress.IsValid() ||
		target == nil ||
		!target.deviceID.Valid() ||
		len(root.CanonicalBytes()) == 0 {
		return nil, errDaemonMeshContentHarness
	}
	targetProvider, _, ready := target.meshCapture.snapshot()
	if !ready || targetProvider == nil {
		return nil, errDaemonMeshContentHarness
	}
	targetCertificate, err := targetProvider()
	if err != nil {
		return nil, err
	}
	defer clearDaemonTLSCertificate(&targetCertificate)
	if len(targetCertificate.Certificate) != 1 {
		return nil, errDaemonMeshContentHarness
	}
	expected, err := transport.ParseContentCertificate(
		targetCertificate.Certificate[0],
	)
	if err != nil || expected.Binding.DeviceID != target.deviceID {
		return nil, errDaemonMeshContentHarness
	}
	expectedDER := bytes.Clone(expected.Leaf.Raw)
	admission, err := transport.NewContentAdmissionRecorder(func(
		remote transport.ContentCertificate,
	) (transport.ContentPeerAdmission, error) {
		if remote.Binding != expected.Binding ||
			!bytes.Equal(remote.Leaf.Raw, expectedDER) {
			return transport.ContentPeerAdmission{},
				errDaemonMeshContentHarness
		}
		closeAfter, err := remote.CloseAfter(time.Now())
		if err != nil {
			return transport.ContentPeerAdmission{}, err
		}
		return transport.ContentPeerAdmission{
			CloseAfter: closeAfter,
		}, nil
	})
	if err != nil {
		return nil, err
	}
	tlsConfig, err := transport.NewClientTLSConfig(
		transport.ClientTLSOptions{
			Plane:             transport.PlaneContent,
			Certificate:       certificate,
			VerifyContentPeer: admission.Verify,
		},
	)
	if err != nil {
		return nil, err
	}
	ownedConfig := true
	defer func() {
		if ownedConfig {
			clearDaemonClientTLSConfig(tlsConfig)
		}
	}()
	dialer := net.Dialer{
		Timeout: 5 * time.Second,
		LocalAddr: &net.TCPAddr{
			IP: net.IP(selectedAddress.AsSlice()),
		},
	}
	raw, err := dialer.DialContext(
		ctx,
		"tcp4",
		target.peerEndpoint.String(),
	)
	if err != nil {
		return nil, err
	}
	client, err := contenthttp.OpenSnapshotBulkClient(
		ctx,
		tls.Client(raw, tlsConfig),
		target.deviceID,
		admission,
		root,
	)
	if err != nil {
		return nil, err
	}
	ownedConfig = false
	return &daemonMeshSnapshotBulkConnection{
		client:    client,
		tlsConfig: tlsConfig,
	}, nil
}

func waitForDaemonMeshRelayedEndpointSet(
	t *testing.T,
	relay *daemonMeshIntegrationNode,
	deviceID domain.DeviceID,
	want []byte,
) []byte {
	t.Helper()
	if relay == nil || !deviceID.Valid() || len(want) == 0 {
		t.Fatal("invalid endpoint-relay wait")
	}
	expected, err := discovery.ParseEndpointSet(want)
	if err != nil || expected.EndpointSet().DeviceID != deviceID {
		t.Fatalf("parse expected endpoint set: %v", err)
	}
	minimumSequence := expected.EndpointSet().EndpointSequence
	_, state, ready := relay.meshCapture.snapshot()
	if !ready {
		t.Fatal("relay local state was not captured")
	}
	deadline := time.Now().Add(daemonMeshIntegrationTimeout)
	var lastErr error
	for time.Now().Before(deadline) {
		now := domain.Timestamp(time.Now().UTC().Format(time.RFC3339Nano))
		if !now.Valid() {
			t.Fatal("invalid endpoint-relay observation time")
		}
		sets, err := state.ListMemberSignedEndpointSets(
			context.Background(),
			now,
		)
		if err == nil {
			for _, set := range sets {
				if set.DeviceID != deviceID {
					continue
				}
				if bytes.Equal(set.EndpointSetJSON, want) {
					return bytes.Clone(want)
				}
				successor, parseErr := discovery.ParseEndpointSet(
					set.EndpointSetJSON,
				)
				if parseErr == nil &&
					successor.EndpointSet().DeviceID == deviceID &&
					successor.EndpointSet().EndpointSequence >
						minimumSequence {
					return bytes.Clone(set.EndpointSetJSON)
				}
				lastErr = fmt.Errorf(
					"relay stored a non-successor endpoint set for %s: %v",
					deviceID,
					parseErr,
				)
			}
		} else {
			lastErr = err
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf(
		"relay did not durably ingest endpoint set for %s: %v",
		deviceID,
		lastErr,
	)
	return nil
}

type daemonMeshPairedContentConnection struct {
	client    *contenthttp.Client
	tlsConfig *tls.Config
}

func (connection *daemonMeshPairedContentConnection) Close() error {
	if connection == nil {
		return nil
	}
	var err error
	if connection.client != nil {
		err = connection.client.Close()
		connection.client = nil
	}
	clearDaemonClientTLSConfig(connection.tlsConfig)
	connection.tlsConfig = nil
	return err
}

func establishDaemonMeshPairedContent(
	t *testing.T,
	nodes []*daemonMeshIntegrationNode,
	leader *daemonMeshIntegrationNode,
	selectedAddress netip.Addr,
	paired daemonMeshIntegrationPairedMember,
) *daemonMeshPairedContentConnection {
	t.Helper()
	if len(nodes) < 2 || leader == nil ||
		!selectedAddress.IsValid() ||
		paired.member.Status != device.StatusActive ||
		len(paired.endpointSet) == 0 {
		t.Fatal("invalid paired content fixture")
	}
	var relay *daemonMeshIntegrationNode
	for _, candidate := range nodes {
		if candidate.deviceID != leader.deviceID {
			relay = candidate
			break
		}
	}
	if relay == nil {
		t.Fatal("paired content relay is unavailable")
	}
	_, leaderState, ready := leader.meshCapture.snapshot()
	if !ready {
		t.Fatal("leader local state was not captured")
	}
	update, err := leaderState.ReplaceMemberSignedEndpointSet(
		context.Background(),
		paired.endpointSet,
		daemonMeshTimestamp(t, time.Now()),
	)
	if err != nil || update != store.MemberEndpointSetStored {
		t.Fatalf("store paired endpoint set = (%v, %v)", update, err)
	}
	if relayed := waitForDaemonMeshRelayedEndpointSet(
		t,
		relay,
		paired.member.ID,
		paired.endpointSet,
	); !bytes.Equal(relayed, paired.endpointSet) {
		t.Fatal("paired endpoint set was unexpectedly superseded")
	}
	response := requestDaemonMeshPeers(t, leader, relay)
	if got := daemonMeshMemberEndpointSet(
		t,
		response,
		paired.member.ID,
		true,
	); got != codec.EncodeBase64URL(paired.endpointSet) {
		t.Fatalf("paired endpoint relay changed bytes: %q", got)
	}

	ctx, cancel := context.WithTimeout(
		context.Background(),
		daemonMeshIntegrationTimeout,
	)
	defer cancel()
	connection, err := dialDaemonMeshExternalContentClient(
		ctx,
		paired.certificate,
		selectedAddress,
		leader,
	)
	if err != nil {
		t.Fatalf("dial paired content client: %v", err)
	}
	session, err := connection.client.Session(ctx)
	if err != nil ||
		session.SessionID() != daemonTestSessionID ||
		session.WorkspaceID() != daemonTestWorkspaceID ||
		session.ServerDeviceID() != leader.deviceID {
		_ = connection.Close()
		t.Fatalf("paired content session = (%+v, %v)", session, err)
	}
	if _, err := connection.client.Peers(ctx); err != nil {
		_ = connection.Close()
		t.Fatalf("paired content peers: %v", err)
	}
	return connection
}

func assertDaemonMeshPairedContentRevoked(
	t *testing.T,
	nodes []*daemonMeshIntegrationNode,
	leader *daemonMeshIntegrationNode,
	selectedAddress netip.Addr,
	paired daemonMeshIntegrationPairedMember,
	connection *daemonMeshPairedContentConnection,
) {
	t.Helper()
	if connection == nil || connection.client == nil {
		t.Fatal("paired content connection is unavailable")
	}
	deadline := time.Now().Add(daemonMeshIntegrationTimeout)
	var accessErr error
	for time.Now().Before(deadline) {
		requestContext, cancel := context.WithTimeout(
			context.Background(),
			time.Second,
		)
		_, accessErr = connection.client.Peers(requestContext)
		cancel()
		if accessErr != nil {
			break
		}
		time.Sleep(25 * time.Millisecond)
	}
	if accessErr == nil {
		t.Fatal("revoked member retained its established content access")
	}
	if err := connection.Close(); err != nil {
		t.Fatalf("close revoked content connection: %v", err)
	}

	freshContext, cancel := context.WithTimeout(
		context.Background(),
		5*time.Second,
	)
	fresh, err := dialDaemonMeshExternalContentClient(
		freshContext,
		paired.certificate,
		selectedAddress,
		leader,
	)
	if err == nil {
		_, requestErr := fresh.client.Session(freshContext)
		closeErr := fresh.Close()
		if requestErr == nil {
			cancel()
			t.Fatal("revoked member completed a fresh content request")
		}
		if closeErr != nil {
			cancel()
			t.Fatalf("close rejected fresh content client: %v", closeErr)
		}
	}
	cancel()

	waitForDaemonMeshLearnedEndpointsPurged(
		t,
		nodes,
		paired.member.ID,
	)
	var relay *daemonMeshIntegrationNode
	for _, candidate := range nodes {
		if candidate.deviceID != leader.deviceID {
			relay = candidate
			break
		}
	}
	if relay == nil {
		t.Fatal("revocation relay is unavailable")
	}
	response := requestDaemonMeshPeers(t, leader, relay)
	daemonMeshMemberEndpointSet(
		t,
		response,
		paired.member.ID,
		false,
	)
}

func dialDaemonMeshExternalContentClient(
	ctx context.Context,
	certificate tls.Certificate,
	selectedAddress netip.Addr,
	target *daemonMeshIntegrationNode,
) (*daemonMeshPairedContentConnection, error) {
	if ctx == nil || ctx.Err() != nil ||
		!selectedAddress.IsValid() || target == nil ||
		!target.deviceID.Valid() {
		return nil, errDaemonMeshContentHarness
	}
	targetProvider, _, ready := target.meshCapture.snapshot()
	if !ready || targetProvider == nil {
		return nil, errDaemonMeshContentHarness
	}
	targetCertificate, err := targetProvider()
	if err != nil {
		return nil, err
	}
	defer clearDaemonTLSCertificate(&targetCertificate)
	if len(targetCertificate.Certificate) != 1 {
		return nil, errDaemonMeshContentHarness
	}
	expected, err := transport.ParseContentCertificate(
		targetCertificate.Certificate[0],
	)
	if err != nil || expected.Binding.DeviceID != target.deviceID {
		return nil, errDaemonMeshContentHarness
	}
	expectedDER := bytes.Clone(expected.Leaf.Raw)
	admission, err := transport.NewContentAdmissionRecorder(func(
		remote transport.ContentCertificate,
	) (transport.ContentPeerAdmission, error) {
		if remote.Binding != expected.Binding ||
			!bytes.Equal(remote.Leaf.Raw, expectedDER) {
			return transport.ContentPeerAdmission{},
				errDaemonMeshContentHarness
		}
		closeAfter, err := remote.CloseAfter(time.Now())
		if err != nil {
			return transport.ContentPeerAdmission{}, err
		}
		return transport.ContentPeerAdmission{
			CloseAfter: closeAfter,
		}, nil
	})
	if err != nil {
		return nil, err
	}
	tlsConfig, err := transport.NewClientTLSConfig(
		transport.ClientTLSOptions{
			Plane:             transport.PlaneContent,
			Certificate:       certificate,
			VerifyContentPeer: admission.Verify,
		},
	)
	if err != nil {
		return nil, err
	}
	ownedConfig := true
	defer func() {
		if ownedConfig {
			clearDaemonClientTLSConfig(tlsConfig)
		}
	}()
	dialer := net.Dialer{
		Timeout: 5 * time.Second,
		LocalAddr: &net.TCPAddr{
			IP: net.IP(selectedAddress.AsSlice()),
		},
	}
	raw, err := dialer.DialContext(
		ctx,
		"tcp4",
		target.peerEndpoint.String(),
	)
	if err != nil {
		return nil, err
	}
	client, err := contenthttp.OpenClient(
		ctx,
		tls.Client(raw, tlsConfig),
		target.deviceID,
		admission,
	)
	if err != nil {
		return nil, err
	}
	ownedConfig = false
	return &daemonMeshPairedContentConnection{
		client:    client,
		tlsConfig: tlsConfig,
	}, nil
}

func waitForDaemonMeshLearnedEndpointsPurged(
	t *testing.T,
	nodes []*daemonMeshIntegrationNode,
	deviceID domain.DeviceID,
) {
	t.Helper()
	deadline := time.Now().Add(daemonMeshIntegrationTimeout)
	var lastErr error
	for time.Now().Before(deadline) {
		purged := true
		now := domain.Timestamp(time.Now().UTC().Format(time.RFC3339Nano))
		if !now.Valid() {
			t.Fatal("invalid endpoint-purge observation time")
		}
		for _, node := range nodes {
			_, state, ready := node.meshCapture.snapshot()
			if !ready {
				purged = false
				lastErr = fmt.Errorf("%s local state unavailable", node.deviceID)
				break
			}
			candidates, err := state.ListPeerEndpointCandidates(
				context.Background(),
				deviceID,
				now,
			)
			if err != nil {
				purged = false
				lastErr = err
				break
			}
			for _, candidate := range candidates {
				if candidate.SourceKind == store.PeerEndpointManual {
					continue
				}
				purged = false
				lastErr = fmt.Errorf(
					"%s retained %s endpoint state",
					node.deviceID,
					candidate.SourceKind,
				)
				break
			}
			if !purged {
				break
			}
		}
		if purged {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf(
		"learned endpoints for revoked member %s were not purged: %v",
		deviceID,
		lastErr,
	)
}

func waitForDaemonMeshContentCredentials(
	t *testing.T,
	nodes []*daemonMeshIntegrationNode,
) {
	waitForDaemonMeshContentCredentialEpoch(t, nodes, 1)
}

func waitForDaemonMeshContentCredentialEpoch(
	t *testing.T,
	nodes []*daemonMeshIntegrationNode,
	want uint64,
) {
	t.Helper()
	if want < 1 {
		t.Fatal("invalid content credential epoch")
	}
	deadline := time.Now().Add(daemonMeshIntegrationTimeout)
	var lastErr error
	for time.Now().Before(deadline) {
		ready := true
		for _, node := range nodes {
			epoch, err := daemonMeshContentCredentialEpoch(node)
			if err != nil || epoch != want {
				ready = false
				if err != nil {
					lastErr = fmt.Errorf(
						"%s content credential: %w",
						node.deviceID,
						err,
					)
				} else {
					lastErr = fmt.Errorf(
						"%s content credential epoch = %d, want %d",
						node.deviceID,
						epoch,
						want,
					)
				}
				break
			}
		}
		if ready {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("content credentials did not become available: %v", lastErr)
}

func daemonMeshContentCredentialEpoch(
	node *daemonMeshIntegrationNode,
) (uint64, error) {
	if node == nil || node.meshCapture == nil {
		return 0, errDaemonMeshContentHarness
	}
	provider, _, captured := node.meshCapture.snapshot()
	if !captured || provider == nil {
		return 0, errDaemonMeshContentHarness
	}
	certificate, err := provider()
	if err != nil {
		return 0, err
	}
	defer clearDaemonTLSCertificate(&certificate)
	if len(certificate.Certificate) != 1 {
		return 0, errDaemonMeshContentHarness
	}
	parsed, err := transport.ParseContentCertificate(
		certificate.Certificate[0],
	)
	if err != nil || parsed.Binding.DeviceID != node.deviceID {
		return 0, errors.Join(errDaemonMeshContentHarness, err)
	}
	return parsed.Binding.Epoch, nil
}

func exerciseDaemonContentCredentialRollover(
	t *testing.T,
	nodes []*daemonMeshIntegrationNode,
	clock *daemonMeshIntegrationCredentialClock,
	renewalTime time.Time,
) {
	t.Helper()
	if len(nodes) < 2 || clock == nil || renewalTime.IsZero() {
		t.Fatal("invalid credential rollover fixture")
	}
	waitForDaemonMeshContentCredentialEpoch(t, nodes, 1)
	source, target := nodes[0], nodes[1]
	client := openReadyDaemonMeshPeersClient(
		t,
		source,
		target,
		clock.Now,
	)
	defer func() {
		if err := client.Close(); err != nil {
			t.Errorf("close rollover content client: %v", err)
		}
	}()

	clock.Set(renewalTime)
	deadline := time.Now().Add(daemonMeshIntegrationTimeout)
	requests := 0
	for time.Now().Before(deadline) {
		_, requestErr := client.roundTrip(target)
		requests++
		if requestErr != nil {
			waitForDaemonMeshContentCredentialEpoch(
				t,
				[]*daemonMeshIntegrationNode{target},
				2,
			)
			break
		}
		allCurrent := true
		for _, node := range nodes {
			epoch, err := daemonMeshContentCredentialEpoch(node)
			if err != nil || epoch != 2 {
				allCurrent = false
				break
			}
		}
		if allCurrent {
			break
		}
		time.Sleep(25 * time.Millisecond)
	}
	waitForDaemonMeshContentCredentialEpoch(t, nodes, 2)
	if requests < 1 {
		t.Fatal("rollover completed without active content traffic")
	}

	fresh := openReadyDaemonMeshPeersClient(
		t,
		source,
		target,
		clock.Now,
	)
	if err := fresh.Close(); err != nil {
		t.Fatalf("close successor content client: %v", err)
	}
}

func openReadyDaemonMeshPeersClient(
	t *testing.T,
	source, target *daemonMeshIntegrationNode,
	now func() time.Time,
) *daemonMeshPeersClient {
	t.Helper()
	deadline := time.Now().Add(daemonMeshIntegrationTimeout)
	var lastErr error
	for time.Now().Before(deadline) {
		client, err := dialDaemonMeshPeersClient(source, target, now)
		if err != nil {
			lastErr = err
			time.Sleep(25 * time.Millisecond)
			continue
		}
		if _, err := client.roundTrip(target); err == nil {
			return client
		} else {
			lastErr = errors.Join(err, client.Close())
		}
		time.Sleep(25 * time.Millisecond)
	}
	t.Fatalf(
		"GET %s from %s did not establish a stable connection: %v",
		contenthttp.PeersPath,
		target.deviceID,
		lastErr,
	)
	return nil
}

func requestDaemonMeshPeers(
	t *testing.T,
	source, target *daemonMeshIntegrationNode,
) daemonMeshPeersResponse {
	t.Helper()
	deadline := time.Now().Add(daemonMeshIntegrationTimeout)
	var lastErr error
	for time.Now().Before(deadline) {
		client, err := dialDaemonMeshPeersClient(
			source,
			target,
			time.Now,
		)
		if err != nil {
			lastErr = err
			time.Sleep(25 * time.Millisecond)
			continue
		}
		response, err := client.roundTrip(target)
		closeErr := client.Close()
		if err == nil {
			if closeErr != nil {
				t.Fatalf("close content peers client: %v", closeErr)
			}
			return response
		}
		lastErr = errors.Join(err, closeErr)
		time.Sleep(25 * time.Millisecond)
	}
	t.Fatalf(
		"GET %s from %s did not stabilize: %v",
		contenthttp.PeersPath,
		target.deviceID,
		lastErr,
	)
	return daemonMeshPeersResponse{}
}

type daemonMeshPeersClient struct {
	client   *http2.ClientConn
	close    sync.Once
	closeErr error
}

func dialDaemonMeshPeersClient(
	source, target *daemonMeshIntegrationNode,
	now func() time.Time,
) (*daemonMeshPeersClient, error) {
	if source == nil || target == nil || now == nil {
		return nil, errDaemonMeshContentHarness
	}
	sourceProvider, _, sourceReady := source.meshCapture.snapshot()
	targetProvider, _, targetReady := target.meshCapture.snapshot()
	if !sourceReady || !targetReady || sourceProvider == nil || targetProvider == nil {
		return nil, errDaemonMeshContentHarness
	}
	sourceCertificate, err := sourceProvider()
	if err != nil {
		return nil, fmt.Errorf(
			"%w: source content certificate: %v",
			errDaemonMeshContentHarness,
			err,
		)
	}
	defer clearDaemonTLSCertificate(&sourceCertificate)
	targetCertificate, err := targetProvider()
	if err != nil {
		return nil, fmt.Errorf(
			"%w: target content certificate: %v",
			errDaemonMeshContentHarness,
			err,
		)
	}
	defer clearDaemonTLSCertificate(&targetCertificate)
	if len(targetCertificate.Certificate) != 1 {
		return nil, errDaemonMeshContentHarness
	}
	expected, err := transport.ParseContentCertificate(
		targetCertificate.Certificate[0],
	)
	if err != nil {
		return nil, fmt.Errorf(
			"%w: parse target content certificate: %v",
			errDaemonMeshContentHarness,
			err,
		)
	}
	expectedDER := bytes.Clone(expected.Leaf.Raw)
	clientTLS, err := transport.NewClientTLSConfig(
		transport.ClientTLSOptions{
			Plane:       transport.PlaneContent,
			Certificate: sourceCertificate,
			VerifyContentPeer: func(
				certificate transport.ContentCertificate,
			) (transport.ContentPeerAdmission, error) {
				if certificate.Binding != expected.Binding ||
					certificate.Binding.DeviceID != target.deviceID ||
					!bytes.Equal(certificate.Leaf.Raw, expectedDER) {
					return transport.ContentPeerAdmission{}, errDaemonMeshContentHarness
				}
				closeAfter, err := certificate.CloseAfter(now())
				if err != nil {
					return transport.ContentPeerAdmission{}, err
				}
				return transport.ContentPeerAdmission{CloseAfter: closeAfter}, nil
			},
		},
	)
	if err != nil {
		return nil, fmt.Errorf(
			"%w: content TLS config: %v",
			errDaemonMeshContentHarness,
			err,
		)
	}
	defer func() {
		for index := range clientTLS.Certificates {
			clearDaemonTLSCertificate(&clientTLS.Certificates[index])
		}
	}()

	ctx, cancel := context.WithTimeout(
		context.Background(),
		daemonMeshIntegrationTimeout,
	)
	defer cancel()
	dialer := net.Dialer{
		Timeout: 5 * time.Second,
		LocalAddr: &net.TCPAddr{
			IP: net.IP(source.peerEndpoint.Addr().AsSlice()),
		},
	}
	raw, err := dialer.DialContext(ctx, "tcp4", target.peerEndpoint.String())
	if err != nil {
		return nil, fmt.Errorf(
			"%w: dial content endpoint %s: %v",
			errDaemonMeshContentHarness,
			target.deviceID,
			err,
		)
	}
	connection := tls.Client(raw, clientTLS)
	if err := connection.HandshakeContext(ctx); err != nil {
		_ = raw.Close()
		return nil, fmt.Errorf(
			"%w: content TLS handshake %s -> %s: %v",
			errDaemonMeshContentHarness,
			source.deviceID,
			target.deviceID,
			err,
		)
	}
	owned := true
	defer func() {
		if owned {
			_ = connection.Close()
		}
	}()
	state := connection.ConnectionState()
	if !state.HandshakeComplete || state.Version != tls.VersionTLS13 ||
		state.DidResume || state.NegotiatedProtocol != transport.ALPNContent ||
		len(state.PeerCertificates) != 1 {
		return nil, fmt.Errorf(
			"%w: invalid content TLS state",
			errDaemonMeshContentHarness,
		)
	}

	http2Transport := &http2.Transport{
		DisableCompression: true,
		MaxHeaderListSize:  contenthttp.HeaderMaxBytes,
		ReadIdleTimeout:    contenthttp.StreamNoProgress,
		PingTimeout:        contenthttp.RequestHeaderTimeout,
		WriteByteTimeout:   contenthttp.StreamNoProgress,
	}
	client, err := http2Transport.NewClientConn(connection)
	if err != nil {
		return nil, fmt.Errorf(
			"%w: open content HTTP/2 connection: %v",
			errDaemonMeshContentHarness,
			err,
		)
	}
	owned = false
	return &daemonMeshPeersClient{
		client: client,
	}, nil
}

func (client *daemonMeshPeersClient) roundTrip(
	target *daemonMeshIntegrationNode,
) (daemonMeshPeersResponse, error) {
	if client == nil || client.client == nil || target == nil {
		return daemonMeshPeersResponse{}, errDaemonMeshContentHarness
	}
	ctx, cancel := context.WithTimeout(
		context.Background(),
		daemonMeshIntegrationTimeout,
	)
	defer cancel()
	request, err := http.NewRequestWithContext(
		ctx,
		http.MethodGet,
		"https://codecomm.invalid"+contenthttp.PeersPath,
		nil,
	)
	if err != nil {
		return daemonMeshPeersResponse{}, fmt.Errorf(
			"create peers request: %w",
			err,
		)
	}
	request.Header.Set("Accept", "application/json")
	request.Header.Set("Accept-Encoding", "identity")
	response, err := client.client.RoundTrip(request)
	if err != nil {
		return daemonMeshPeersResponse{}, err
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(
		response.Body,
		contenthttp.ResponseMaxBytes+1,
	))
	if err != nil {
		return daemonMeshPeersResponse{}, fmt.Errorf(
			"read peers response: %w",
			err,
		)
	}
	if len(body) == 0 || len(body) > contenthttp.ResponseMaxBytes ||
		response.StatusCode != http.StatusOK || response.ProtoMajor != 2 ||
		response.Header.Get("Content-Type") != "application/json" ||
		response.Header.Get("Cache-Control") != "no-store" ||
		response.Header.Get("X-Content-Type-Options") != "nosniff" ||
		response.Header.Get("Content-Encoding") != "" ||
		response.Header.Get("Content-Length") != strconv.Itoa(len(body)) {
		return daemonMeshPeersResponse{}, fmt.Errorf(
			"peers response = %s headers=%v body=%s",
			response.Status,
			response.Header,
			body,
		)
	}
	canonical, err := codec.CanonicalizeSignedObject(body)
	if err != nil {
		return daemonMeshPeersResponse{}, fmt.Errorf(
			"peers response is not canonical: %w",
			err,
		)
	}
	if !bytes.Equal(canonical, body) {
		return daemonMeshPeersResponse{},
			errors.New("peers response is not canonical")
	}
	var decoded daemonMeshPeersResponse
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&decoded); err != nil {
		return daemonMeshPeersResponse{}, fmt.Errorf(
			"decode peers response: %w",
			err,
		)
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return daemonMeshPeersResponse{}, fmt.Errorf(
			"peers response has trailing JSON: %w",
			err,
		)
	}
	return decoded, nil
}

func (client *daemonMeshPeersClient) Close() error {
	if client == nil {
		return nil
	}
	client.close.Do(func() {
		client.closeErr = client.client.Close()
		if errors.Is(client.closeErr, net.ErrClosed) {
			client.closeErr = nil
		}
	})
	return client.closeErr
}

func assertDaemonMeshPeersRoster(
	t *testing.T,
	response daemonMeshPeersResponse,
	server *daemonMeshIntegrationNode,
	nodes []*daemonMeshIntegrationNode,
	nonvoter device.Device,
) {
	t.Helper()
	if response.SchemaVersion != contenthttp.SchemaVersion ||
		response.SessionID != string(daemonTestSessionID) ||
		response.WorkspaceID != string(daemonTestWorkspaceID) ||
		response.RecoveryGeneration != 0 ||
		response.ServerDeviceID != string(server.deviceID) ||
		len(response.Members) != len(nodes)+1 {
		t.Fatalf("peers response envelope = %+v", response)
	}
	expected := make(map[string]device.Role, len(nodes)+1)
	var expectedIDs []string
	for _, node := range nodes {
		expected[string(node.deviceID)] = device.RoleOwner
		expectedIDs = append(expectedIDs, string(node.deviceID))
	}
	expected[string(nonvoter.ID)] = nonvoter.Role
	expectedIDs = append(expectedIDs, string(nonvoter.ID))
	sort.Strings(expectedIDs)
	for index, member := range response.Members {
		role, found := expected[member.DeviceID]
		if !found || member.DeviceID != expectedIDs[index] ||
			member.Role != string(role) ||
			member.Status != string(device.StatusActive) ||
			member.EntityVersion != 1 {
			t.Fatalf("peers roster member %d = %+v", index, member)
		}
	}
}

func daemonMeshMemberEndpointSet(
	t *testing.T,
	response daemonMeshPeersResponse,
	deviceID domain.DeviceID,
	want bool,
) string {
	t.Helper()
	value, present := daemonMeshOptionalMemberEndpointSet(
		t,
		response,
		deviceID,
	)
	if present != want {
		t.Fatalf(
			"member %s endpoint-set presence = %t, want %t",
			deviceID,
			present,
			want,
		)
	}
	return value
}

func daemonMeshOptionalMemberEndpointSet(
	t *testing.T,
	response daemonMeshPeersResponse,
	deviceID domain.DeviceID,
) (string, bool) {
	t.Helper()
	for _, member := range response.Members {
		if member.DeviceID != string(deviceID) {
			continue
		}
		if member.EndpointSet == nil {
			return "", false
		}
		return *member.EndpointSet, true
	}
	t.Fatalf("member %s absent from peers response", deviceID)
	return "", false
}

func validateDaemonMeshEndpointSet(
	t *testing.T,
	target *daemonMeshIntegrationNode,
	canonical []byte,
) discovery.VerifiedEndpointSet {
	t.Helper()
	member := device.Device{
		ID:                target.deviceID,
		Role:              device.RoleOwner,
		IdentityPublicKey: bytes.Clone(target.privateKey.Public().(ed25519.PublicKey)),
		DaemonVersion:     "0.1.0",
		MaxApplyLevel:     1,
		Status:            device.StatusActive,
		EntityVersion:     1,
	}
	verified, err := discovery.ValidateEndpointSet(
		canonical,
		discovery.EndpointSetExpectation{
			SessionID:             daemonTestSessionID,
			WorkspaceID:           daemonTestWorkspaceID,
			RecoveryGeneration:    0,
			Member:                member,
			AdvertisementInterval: time.Duration(policy.DefaultAdvertisementIntervalSeconds) * time.Second,
			Now:                   time.Now(),
		},
	)
	if err != nil {
		t.Fatalf("validate target endpoint set: %v", err)
	}
	value := verified.EndpointSet()
	if len(value.Endpoints) != 1 ||
		value.Endpoints[0].IP != target.peerEndpoint.Addr() ||
		value.Endpoints[0].Port != target.peerEndpoint.Port() {
		t.Fatalf("target endpoint set = %+v", value)
	}
	return verified
}

func signDaemonMeshShortEndpointSet(
	t *testing.T,
	target *daemonMeshIntegrationNode,
	value discovery.EndpointSet,
) ([]byte, time.Time) {
	t.Helper()
	if value.EndpointSequence >= domain.MaxSafeInteger {
		t.Fatal("target endpoint sequence cannot advance")
	}
	addresses := make([]netip.Addr, len(value.Endpoints))
	for index, endpoint := range value.Endpoints {
		addresses[index] = endpoint.IP
	}
	interval := time.Duration(policy.DefaultAdvertisementIntervalSeconds) * time.Second
	signer, err := discovery.NewEndpointSigner(
		interval,
		target.peerEndpoint.Port(),
		addresses,
	)
	if err != nil {
		t.Fatalf("NewEndpointSigner(short-lived): %v", err)
	}
	issuedAt := time.Now().UTC().Truncate(time.Second)
	expiresAt := issuedAt.Add(3 * time.Second)
	value.EndpointSequence++
	value.IssuedAt = domain.WholeSecondTimestamp(issuedAt.Format(time.RFC3339))
	value.ExpiresAt = domain.WholeSecondTimestamp(expiresAt.Format(time.RFC3339))
	encoded, err := signer.Sign(value, target.privateKey)
	if err != nil {
		t.Fatalf("sign short-lived endpoint set: %v", err)
	}
	return encoded, expiresAt
}

func daemonMeshTimestamp(t *testing.T, value time.Time) domain.Timestamp {
	t.Helper()
	timestamp, err := domain.ParseTimestamp(value.UTC().Format(time.RFC3339Nano))
	if err != nil {
		t.Fatalf("parse test timestamp: %v", err)
	}
	return timestamp
}

var _ daemonConsensusTransportFactory = (*daemonMeshIntegrationTransportFactory)(nil)
var _ daemonDiscoveryMulticast = (*daemonMeshIntegrationMulticast)(nil)
