package transport

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/raft"
	"github.com/ijonahch/codecomm/internal/domain"
	"golang.org/x/net/http2"
)

func TestGODEBUGSettingEnabledRequiresExactLastValue(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		settings string
		enabled  bool
	}{
		"exact":             {"http2xconnect=1", true},
		"among settings":    {"x=1,http2xconnect=1,y=2", true},
		"missing":           {"x=1", false},
		"substring key":     {"xhttp2xconnect=1", false},
		"substring value":   {"http2xconnect=10", false},
		"last disables":     {"http2xconnect=1,http2xconnect=0", false},
		"last enables":      {"http2xconnect=0,http2xconnect=1", true},
		"malformed ignored": {"http2xconnect", false},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if got := godebugSettingEnabled(
				test.settings,
				"http2xconnect",
			); got != test.enabled {
				t.Fatalf("godebugSettingEnabled() = %t, want %t", got, test.enabled)
			}
		})
	}
}

func TestConsensusHTTP2ClientSetupHonorsCancellation(t *testing.T) {
	t.Parallel()

	client, server := net.Pipe()
	t.Cleanup(func() {
		_ = client.Close()
		_ = server.Close()
	})
	ctx, cancel := context.WithTimeout(t.Context(), 25*time.Millisecond)
	defer cancel()
	started := time.Now()
	connection, err := newConsensusHTTP2ClientConn(ctx, client)
	if connection != nil {
		_ = connection.Close()
		t.Fatal("canceled setup returned a client connection")
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("newConsensusHTTP2ClientConn() error = %v", err)
	}
	if elapsed := time.Since(started); elapsed > time.Second {
		t.Fatalf("canceled HTTP/2 setup took %s", elapsed)
	}
}

func TestConsensusHeaderGuardClosesWithoutSocketDeadline(t *testing.T) {
	t.Parallel()

	local, remote := net.Pipe()
	var deadlineCalls atomic.Uint64
	tracked := &consensusDeadlineTrackingConn{
		Conn:  local,
		calls: &deadlineCalls,
	}
	t.Cleanup(func() {
		_ = tracked.Close()
		_ = remote.Close()
	})
	guard := newConsensusHeaderGuard(tracked, 25*time.Millisecond)
	readDone := make(chan error, 1)
	go func() {
		buffer := make([]byte, 1)
		_, err := remote.Read(buffer)
		readDone <- err
	}()
	select {
	case err := <-readDone:
		if err == nil {
			t.Fatal("header guard closure returned no read error")
		}
	case <-time.After(time.Second):
		t.Fatal("header guard did not close the connection")
	}
	if !guard.timedOut() {
		t.Fatal("header guard did not record timeout")
	}
	if got := deadlineCalls.Load(); got != 0 {
		t.Fatalf("physical socket deadline calls = %d, want 0", got)
	}
}

func TestConsensusHeaderGuardCoversEveryParsedHeader(t *testing.T) {
	t.Parallel()

	local, remote := net.Pipe()
	defer func() {
		_ = local.Close()
		_ = remote.Close()
	}()
	guard := newConsensusHeaderGuard(local, 50*time.Millisecond)
	first := append(
		[]byte(http2.ClientPreface),
		consensusTestHTTP2Frame(
			http2.FrameHeaders,
			http2.FlagHeadersEndHeaders,
			[]byte{0x82},
		)...,
	)
	for _, value := range first {
		guard.observe([]byte{value})
	}
	time.Sleep(75 * time.Millisecond)
	if guard.timedOut() {
		t.Fatal("completed first header later timed out")
	}

	second := consensusTestHTTP2Frame(
		http2.FrameHeaders,
		http2.FlagHeadersEndHeaders,
		[]byte{0x82, 0x84, 0x86, 0x88},
	)
	guard.observe(second[:4])
	readDone := make(chan error, 1)
	go func() {
		buffer := make([]byte, 1)
		_, err := remote.Read(buffer)
		readDone <- err
	}()
	select {
	case err := <-readDone:
		if err == nil {
			t.Fatal("later partial header closure returned no read error")
		}
	case <-time.After(time.Second):
		t.Fatal("later partial header did not time out")
	}
	if !guard.timedOut() {
		t.Fatal("later partial header timeout was not recorded")
	}
}

func TestConsensusLogicalStreamExpiresWithoutProgress(t *testing.T) {
	t.Parallel()

	local := domain.DeviceID("cc1" + strings.Repeat("7", 64))
	remote := domain.DeviceID("cc1" + strings.Repeat("8", 64))
	var bridges consensusStreamBridges
	connection, bridges := newConsensusStreamConn(
		local,
		remote,
		func() {
			_ = bridges.read.Close()
			_ = bridges.write.Close()
		},
	)
	t.Cleanup(func() { _ = connection.Close() })
	connection.armProgressTimeout(25 * time.Millisecond)
	select {
	case <-connection.done:
	case <-time.After(time.Second):
		t.Fatal("idle logical stream did not expire")
	}
}

func TestConsensusSnapshotReaderReauthorizesAfterBlockedRead(t *testing.T) {
	t.Parallel()

	target := domain.DeviceID("cc1" + strings.Repeat("4", 64))
	var authorized atomic.Bool
	authorized.Store(true)
	transport := &ConsensusNetworkTransport{
		authorizeReplication: func(deviceID domain.DeviceID) error {
			if deviceID != target || !authorized.Load() {
				return ErrConsensusReplicationDenied
			}
			return nil
		},
	}
	source := &blockingConsensusReader{
		started: make(chan struct{}),
		release: make(chan struct{}),
	}
	reader := &consensusReplicationReader{
		transport: transport,
		target:    target,
		reader:    source,
	}
	result := make(chan struct {
		count int
		err   error
	}, 1)
	go func() {
		buffer := make([]byte, len("snapshot"))
		count, err := reader.Read(buffer)
		result <- struct {
			count int
			err   error
		}{count: count, err: err}
	}()
	select {
	case <-source.started:
	case <-time.After(time.Second):
		t.Fatal("snapshot reader did not block")
	}
	authorized.Store(false)
	close(source.release)
	select {
	case read := <-result:
		if read.count != 0 ||
			!errors.Is(read.err, ErrConsensusReplicationDenied) {
			t.Fatalf("Read() = (%d, %v)", read.count, read.err)
		}
	case <-time.After(time.Second):
		t.Fatal("snapshot reauthorization did not return")
	}
}

func TestConsensusControlDispatcherIsClosed(t *testing.T) {
	t.Parallel()

	peer := AuthenticatedPeer{
		Plane:    PlaneConsensus,
		DeviceID: domain.DeviceID("cc1" + strings.Repeat("6", 64)),
	}
	var calls atomic.Uint64
	layer := &ConsensusStreamLayer{
		handlers: make(chan struct{}, ConsensusActiveHandlersMax),
		controlHandler: http.HandlerFunc(func(
			writer http.ResponseWriter,
			_ *http.Request,
		) {
			calls.Add(1)
			writer.WriteHeader(http.StatusNoContent)
		}),
	}
	handler := &consensusConnectionHandler{layer: layer, peer: peer}

	allowed := []struct {
		method string
		path   string
	}{
		{http.MethodGet, "/v1/consensus/status"},
		{http.MethodPost, "/v1/consensus/prove"},
		{http.MethodPost, "/v1/credentials/renew"},
		{http.MethodPost, "/v1/credentials/endorse"},
	}
	for _, route := range allowed {
		request := newConsensusControlTestRequest(
			t,
			peer,
			route.method,
			route.path,
		)
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		if response.Code != http.StatusNoContent {
			t.Fatalf("%s %s status = %d", route.method, route.path, response.Code)
		}
	}
	if got := calls.Load(); got != uint64(len(allowed)) {
		t.Fatalf("allowed control handler calls = %d, want %d", got, len(allowed))
	}

	rejected := []struct {
		name   string
		method string
		path   string
		mutate func(*http.Request)
		status int
	}{
		{"content route", http.MethodGet, "/v1/events", nil, http.StatusNotFound},
		{"wrong method", http.MethodPost, "/v1/consensus/status", nil, http.StatusNotFound},
		{"query", http.MethodGet, "/v1/consensus/status?x=1", nil, http.StatusNotFound},
		{
			"unexpected protocol",
			http.MethodGet,
			"/v1/consensus/status",
			func(request *http.Request) {
				request.Header.Set(":protocol", ConsensusRaftProtocol)
			},
			http.StatusNotFound,
		},
		{
			"wrong authority",
			http.MethodGet,
			"/v1/consensus/status",
			func(request *http.Request) { request.Host = "other.peer" },
			http.StatusBadRequest,
		},
	}
	for _, route := range rejected {
		t.Run(route.name, func(t *testing.T) {
			request := newConsensusControlTestRequest(
				t,
				peer,
				route.method,
				route.path,
			)
			if route.mutate != nil {
				route.mutate(request)
			}
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			if response.Code != route.status {
				t.Fatalf("status = %d, want %d", response.Code, route.status)
			}
		})
	}
	if got := calls.Load(); got != uint64(len(allowed)) {
		t.Fatalf("rejected route reached control handler; calls = %d", got)
	}

	for range ConsensusActiveHandlersMax {
		layer.handlers <- struct{}{}
	}
	response := httptest.NewRecorder()
	handler.ServeHTTP(
		response,
		newConsensusControlTestRequest(
			t,
			peer,
			http.MethodGet,
			"/v1/consensus/status",
		),
	)
	if response.Code != http.StatusServiceUnavailable {
		t.Fatalf("handler-capacity status = %d", response.Code)
	}
	for range ConsensusActiveHandlersMax {
		<-layer.handlers
	}
	if got := calls.Load(); got != uint64(len(allowed)) {
		t.Fatalf("capacity refusal reached control handler; calls = %d", got)
	}
}

func testConsensusReplicationAuthorization(t *testing.T) {
	harness := newConsensusHarness(t)
	var authorizationMode atomic.Int32
	var authorizationCalls atomic.Uint64
	var wrongTarget atomic.Bool
	authorizer := func(deviceID domain.DeviceID) error {
		authorizationCalls.Add(1)
		if deviceID != harness.serverID {
			wrongTarget.Store(true)
		}
		switch authorizationMode.Load() {
		case 1:
			return nil
		case 2:
			panic("authorizer panic")
		default:
			return errors.New("leader has not applied membership")
		}
	}
	clientTransport := newConsensusTestNetworkTransport(
		t,
		harness.client,
		harness.clientID,
		authorizer,
	)
	serverTransport := newConsensusTestNetworkTransport(
		t,
		harness.server,
		harness.serverID,
		func(domain.DeviceID) error { return nil },
	)
	defer func() {
		_ = clientTransport.Close()
		_ = serverTransport.Close()
	}()

	received := make(chan string, 16)
	stopResponder := make(chan struct{})
	defer close(stopResponder)
	go respondToConsensusRPCs(serverTransport, received, stopResponder)

	targetID := raft.ServerID(harness.serverID)
	targetAddress := raft.ServerAddress(harness.serverID)
	heartbeat := &raft.AppendEntriesRequest{Term: 1}
	if err := clientTransport.AppendEntries(
		targetID,
		targetAddress,
		heartbeat,
		&raft.AppendEntriesResponse{},
	); err != nil {
		t.Fatalf("ungated heartbeat: %v", err)
	}
	assertConsensusRPCReceived(t, received, "append:0")
	if got := authorizationCalls.Load(); got != 0 {
		t.Fatalf("heartbeat authorization calls = %d, want 0", got)
	}

	entry := &raft.AppendEntriesRequest{
		Term: 1,
		Entries: []*raft.Log{{
			Index: 1,
			Term:  1,
			Type:  raft.LogCommand,
			Data:  []byte("command"),
		}},
	}
	if err := clientTransport.AppendEntries(
		targetID,
		targetAddress,
		entry,
		&raft.AppendEntriesResponse{},
	); !errors.Is(err, ErrConsensusReplicationDenied) {
		t.Fatalf("denied AppendEntries() error = %v", err)
	}
	assertNoConsensusRPC(t, received)

	var commitProbeCalls atomic.Uint64
	clientTransport.authorizeCommitProbe = func(
		deviceID domain.DeviceID,
	) error {
		commitProbeCalls.Add(1)
		if deviceID != harness.serverID {
			wrongTarget.Store(true)
		}
		return nil
	}
	noop := &raft.AppendEntriesRequest{
		Term: 1,
		Entries: []*raft.Log{{
			Index: 1,
			Term:  1,
			Type:  raft.LogNoop,
		}},
	}
	if err := clientTransport.AppendEntries(
		targetID,
		targetAddress,
		noop,
		&raft.AppendEntriesResponse{},
	); err != nil {
		t.Fatalf("commit-probe AppendEntries(): %v", err)
	}
	assertConsensusRPCReceived(t, received, "append:1")
	if got := commitProbeCalls.Load(); got != 1 {
		t.Fatalf("commit-probe authorization calls = %d, want 1", got)
	}
	recovery := &raft.AppendEntriesRequest{
		Term: 1,
		Entries: []*raft.Log{
			{
				Index: 2,
				Term:  1,
				Type:  raft.LogBarrier,
			},
			{
				Index: 3,
				Term:  1,
				Type:  raft.LogNoop,
			},
		},
	}
	if err := clientTransport.AppendEntries(
		targetID,
		targetAddress,
		recovery,
		&raft.AppendEntriesResponse{},
	); err != nil {
		t.Fatalf("barrier commit-recovery AppendEntries(): %v", err)
	}
	assertConsensusRPCReceived(t, received, "append:2")
	if got := commitProbeCalls.Load(); got != 2 {
		t.Fatalf("commit-recovery authorization calls = %d, want 2", got)
	}
	mixedRecovery := &raft.AppendEntriesRequest{
		Term: 1,
		Entries: []*raft.Log{
			{
				Index: 4,
				Term:  1,
				Type:  raft.LogBarrier,
			},
			{
				Index: 5,
				Term:  1,
				Type:  raft.LogCommand,
				Data:  []byte("command"),
			},
		},
	}
	if err := clientTransport.AppendEntries(
		targetID,
		targetAddress,
		mixedRecovery,
		&raft.AppendEntriesResponse{},
	); !errors.Is(err, ErrConsensusReplicationDenied) {
		t.Fatalf("mixed commit-recovery AppendEntries() error = %v", err)
	}
	assertNoConsensusRPC(t, received)
	if got := commitProbeCalls.Load(); got != 2 {
		t.Fatalf("mixed recovery used commit authorization %d times, want 2", got)
	}
	for _, malformedRecovery := range []*raft.AppendEntriesRequest{
		{
			Term: 1,
			Entries: []*raft.Log{{
				Index: 6,
				Term:  1,
				Type:  raft.LogBarrier,
				Data:  []byte("payload"),
			}},
		},
		{
			Term: 1,
			Entries: []*raft.Log{{
				Index:      6,
				Term:       1,
				Type:       raft.LogNoop,
				Extensions: []byte("payload"),
			}},
		},
	} {
		if err := clientTransport.AppendEntries(
			targetID,
			targetAddress,
			malformedRecovery,
			&raft.AppendEntriesResponse{},
		); !errors.Is(err, ErrConsensusReplicationDenied) {
			t.Fatalf("payload-bearing commit recovery error = %v", err)
		}
		assertNoConsensusRPC(t, received)
	}
	if got := commitProbeCalls.Load(); got != 2 {
		t.Fatalf("payload recovery used commit authorization %d times, want 2", got)
	}

	authorizationMode.Store(1)
	if err := clientTransport.AppendEntries(
		targetID,
		targetAddress,
		entry,
		&raft.AppendEntriesResponse{},
	); err != nil {
		t.Fatalf("authorized AppendEntries(): %v", err)
	}
	assertConsensusRPCReceived(t, received, "append:1")

	authorizationMode.Store(0)
	pipeline, err := clientTransport.AppendEntriesPipeline(
		targetID,
		targetAddress,
	)
	if err != nil {
		t.Fatalf("AppendEntriesPipeline(denied setup): %v", err)
	}
	if _, err := pipeline.AppendEntries(
		entry,
		&raft.AppendEntriesResponse{},
	); !errors.Is(err, ErrConsensusReplicationDenied) {
		t.Fatalf("denied pipeline AppendEntries() error = %v", err)
	}
	_ = pipeline.Close()
	assertNoConsensusRPC(t, received)

	pipeline, err = clientTransport.AppendEntriesPipeline(
		targetID,
		targetAddress,
	)
	if err != nil {
		t.Fatalf("AppendEntriesPipeline(commit recovery setup): %v", err)
	}
	if _, err := pipeline.AppendEntries(
		recovery,
		&raft.AppendEntriesResponse{},
	); err != nil {
		t.Fatalf("commit-recovery pipeline AppendEntries(): %v", err)
	}
	select {
	case future := <-pipeline.Consumer():
		if err := future.Error(); err != nil {
			t.Fatalf("commit-recovery pipeline future: %v", err)
		}
	case <-time.After(consensusTestTimeout):
		t.Fatal("commit-recovery pipeline response timed out")
	}
	assertConsensusRPCReceived(t, received, "append:2")
	if got := commitProbeCalls.Load(); got != 3 {
		t.Fatalf("commit-recovery authorization calls = %d, want 3", got)
	}
	_ = pipeline.Close()

	authorizationMode.Store(1)
	pipeline, err = clientTransport.AppendEntriesPipeline(
		targetID,
		targetAddress,
	)
	if err != nil {
		t.Fatalf("AppendEntriesPipeline(authorized setup): %v", err)
	}
	if _, err := pipeline.AppendEntries(
		entry,
		&raft.AppendEntriesResponse{},
	); err != nil {
		t.Fatalf("authorized pipeline AppendEntries(): %v", err)
	}
	select {
	case future := <-pipeline.Consumer():
		if err := future.Error(); err != nil {
			t.Fatalf("pipeline future: %v", err)
		}
	case <-time.After(consensusTestTimeout):
		t.Fatal("pipeline response timed out")
	}
	assertConsensusRPCReceived(t, received, "append:1")
	_ = pipeline.Close()

	snapshot := &raft.InstallSnapshotRequest{
		Term: 1,
		Size: int64(len("snapshot")),
	}
	authorizationMode.Store(0)
	if err := clientTransport.InstallSnapshot(
		targetID,
		targetAddress,
		snapshot,
		&raft.InstallSnapshotResponse{},
		strings.NewReader("snapshot"),
	); !errors.Is(err, ErrConsensusReplicationDenied) {
		t.Fatalf("denied InstallSnapshot() error = %v", err)
	}
	assertNoConsensusRPC(t, received)

	authorizationMode.Store(1)
	if err := clientTransport.InstallSnapshot(
		targetID,
		targetAddress,
		snapshot,
		&raft.InstallSnapshotResponse{},
		strings.NewReader("snapshot"),
	); err != nil {
		t.Fatalf("authorized InstallSnapshot(): %v", err)
	}
	assertConsensusRPCReceived(t, received, "snapshot:snapshot")

	authorizationMode.Store(2)
	if err := clientTransport.AppendEntries(
		targetID,
		targetAddress,
		entry,
		&raft.AppendEntriesResponse{},
	); !errors.Is(err, ErrConsensusReplicationDenied) {
		t.Fatalf("panicking authorizer error = %v", err)
	}
	assertNoConsensusRPC(t, received)
	if wrongTarget.Load() {
		t.Fatal("replication authorizer received the wrong target device")
	}

	wrongAddress := raft.ServerAddress(
		"cc1" + strings.Repeat("5", 64),
	)
	if err := clientTransport.RequestVote(
		targetID,
		wrongAddress,
		&raft.RequestVoteRequest{},
		&raft.RequestVoteResponse{},
	); !errors.Is(err, ErrConsensusRaftTargetMismatch) {
		t.Fatalf("mismatched target error = %v", err)
	}
}

func testConsensusRequestHeaderTimeout(t *testing.T) {
	harness := newConsensusHarness(t)
	harness.server.requestHeaderTimeout = 100 * time.Millisecond
	raw, err := harness.dialer.DialConsensusEndpoint(
		t.Context(),
		netip.MustParseAddrPort("192.0.2.1:47831"),
	)
	if err != nil {
		t.Fatalf("DialConsensusEndpoint(): %v", err)
	}
	config, err := NewClientTLSConfig(ClientTLSOptions{
		Plane:       PlaneConsensus,
		Certificate: harness.client.identityCertificate,
		VerifyIdentityPeer: func(
			certificate IdentityCertificate,
		) error {
			return harness.client.verifyExpected(
				harness.serverID,
				certificate,
			)
		},
	})
	if err != nil {
		_ = raw.Close()
		t.Fatalf("NewClientTLSConfig(): %v", err)
	}
	connection := tls.Client(raw, config)
	if err := connection.HandshakeContext(t.Context()); err != nil {
		_ = connection.Close()
		t.Fatalf("HandshakeContext(): %v", err)
	}
	frame, err := http2.NewFramer(io.Discard, connection).ReadFrame()
	if err != nil {
		_ = connection.Close()
		t.Fatalf("read first HTTP/2 frame: %v", err)
	}
	settings, ok := frame.(*http2.SettingsFrame)
	if !ok {
		_ = connection.Close()
		t.Fatalf("first HTTP/2 frame = %T, want SETTINGS", frame)
	}
	extendedConnect := false
	if err := settings.ForeachSetting(func(setting http2.Setting) error {
		if setting.ID == http2.SettingEnableConnectProtocol &&
			setting.Val == 1 {
			extendedConnect = true
		}
		return nil
	}); err != nil {
		_ = connection.Close()
		t.Fatalf("decode first SETTINGS: %v", err)
	}
	if !extendedConnect {
		_ = connection.Close()
		t.Fatal("first SETTINGS did not enable extended CONNECT")
	}
	readDone := make(chan error, 1)
	go func() {
		_, err := io.Copy(io.Discard, connection)
		readDone <- err
	}()
	select {
	case <-readDone:
	case <-time.After(time.Second):
		_ = connection.Close()
		t.Fatal("stalled HTTP/2 preface was not closed")
	}
	_ = connection.Close()
}

func newConsensusTestNetworkTransport(
	t *testing.T,
	stream *ConsensusStreamLayer,
	localDeviceID domain.DeviceID,
	authorizer ConsensusReplicationAuthorizer,
) *ConsensusNetworkTransport {
	t.Helper()
	transport, err := NewConsensusNetworkTransport(
		ConsensusNetworkTransportOptions{
			Stream:               stream,
			LocalServerID:        raft.ServerID(localDeviceID),
			Timeout:              ConsensusRaftOperationTimeout,
			Logger:               hclog.NewNullLogger(),
			AuthorizeReplication: authorizer,
			AuthorizeCommitProbe: ConsensusCommitProbeAuthorizer(authorizer),
		},
	)
	if err != nil {
		t.Fatalf("NewConsensusNetworkTransport(): %v", err)
	}
	return transport
}

func respondToConsensusRPCs(
	transport *ConsensusNetworkTransport,
	received chan<- string,
	stop <-chan struct{},
) {
	for {
		select {
		case rpc := <-transport.Consumer():
			switch request := rpc.Command.(type) {
			case *raft.AppendEntriesRequest:
				received <- fmt.Sprintf("append:%d", len(request.Entries))
				rpc.Respond(&raft.AppendEntriesResponse{
					Term:    request.Term,
					Success: true,
				}, nil)
			case *raft.InstallSnapshotRequest:
				payload, err := io.ReadAll(rpc.Reader)
				if err != nil {
					rpc.Respond(nil, err)
					continue
				}
				received <- "snapshot:" + string(payload)
				rpc.Respond(&raft.InstallSnapshotResponse{
					Term:    request.Term,
					Success: true,
				}, nil)
			default:
				rpc.Respond(nil, errors.New("unexpected Raft RPC"))
			}
		case <-stop:
			return
		}
	}
}

func assertConsensusRPCReceived(
	t *testing.T,
	received <-chan string,
	expected string,
) {
	t.Helper()
	select {
	case actual := <-received:
		if actual != expected {
			t.Fatalf("received RPC = %q, want %q", actual, expected)
		}
	case <-time.After(consensusTestTimeout):
		t.Fatalf("waiting for RPC %q timed out", expected)
	}
}

func assertNoConsensusRPC(t *testing.T, received <-chan string) {
	t.Helper()
	select {
	case actual := <-received:
		t.Fatalf("denied replication sent RPC %q", actual)
	case <-time.After(50 * time.Millisecond):
	}
}

func newConsensusControlTestRequest(
	t *testing.T,
	peer AuthenticatedPeer,
	method string,
	path string,
) *http.Request {
	t.Helper()
	request, err := http.NewRequest(
		method,
		"https://"+ConsensusRaftAuthority+path,
		strings.NewReader("{}"),
	)
	if err != nil {
		t.Fatalf("http.NewRequest(): %v", err)
	}
	request.ProtoMajor = 2
	request.ProtoMinor = 0
	request.TLS = &tls.ConnectionState{
		HandshakeComplete:  true,
		Version:            tls.VersionTLS13,
		NegotiatedProtocol: ALPNConsensus,
		PeerCertificates:   []*x509.Certificate{{}},
	}
	ctx := context.WithValue(
		request.Context(),
		authenticatedPeerContextKey{},
		&authenticatedPeerContext{
			metadata:    peer,
			reauthorize: func() error { return nil },
		},
	)
	return request.WithContext(ctx)
}

type blockingConsensusReader struct {
	started chan struct{}
	release chan struct{}
}

func (reader *blockingConsensusReader) Read(buffer []byte) (int, error) {
	close(reader.started)
	<-reader.release
	return copy(buffer, "snapshot"), nil
}

func consensusTestHTTP2Frame(
	frameType http2.FrameType,
	flags http2.Flags,
	payload []byte,
) []byte {
	length := len(payload)
	frame := make([]byte, 9+length)
	frame[0] = byte(length >> 16)
	frame[1] = byte(length >> 8)
	frame[2] = byte(length)
	frame[3] = byte(frameType)
	frame[4] = byte(flags)
	frame[8] = 1
	copy(frame[9:], payload)
	return frame
}
