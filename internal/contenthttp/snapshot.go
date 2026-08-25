package contenthttp

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/ijonahch/codecomm/internal/domain"
	"github.com/ijonahch/codecomm/internal/logicalsnapshot"
	"github.com/ijonahch/codecomm/internal/transport"
)

const (
	SnapshotLatestPath       = "/v1/snapshots/latest"
	snapshotPathPrefix       = "/v1/snapshots/"
	snapshotChunkMediaType   = "application/octet-stream"
	snapshotWorkspaceHeader  = "CodeComm-Snapshot-Workspace-ID"
	snapshotGenerationHeader = "CodeComm-Snapshot-Recovery-Generation"
)

var (
	ErrSnapshotNotFound = errors.New(
		"content HTTP: logical snapshot not found",
	)
	ErrSnapshotUnavailable = errors.New(
		"content HTTP: logical snapshot temporarily unavailable",
	)
	ErrInvalidSnapshotScope = errors.New(
		"content HTTP: invalid logical snapshot request scope",
	)
	ErrInvalidSnapshotPage = errors.New(
		"content HTTP: invalid logical snapshot manifest page",
	)
	ErrInvalidSnapshotChunk = errors.New(
		"content HTTP: invalid logical snapshot chunk",
	)
)

// SnapshotService supplies immutable snapshot roots and transfer-scoped parts.
// A Service implementation that also implements SnapshotService enables the
// authenticated snapshot routes on its Server.
type SnapshotService interface {
	LatestSnapshot(context.Context) (logicalsnapshot.Root, error)
	OpenSnapshotTransfer(
		context.Context,
		SnapshotRequestScope,
	) (SnapshotTransfer, error)
}

// SnapshotTransfer pins one exact immutable artifact for the lifetime of one
// authenticated bulk connection. Close must be idempotent.
type SnapshotTransfer interface {
	Scope() SnapshotRequestScope
	SnapshotManifestPage(
		context.Context,
		uint64,
	) (SnapshotManifestPage, error)
	SnapshotChunk(
		context.Context,
		uint64,
	) (SnapshotChunk, error)
	Close() error
}

// SnapshotRequestScope binds an indexed snapshot request to one exact
// lineage and artifact. Services must select storage using the complete
// scope, never artifact ID alone.
type SnapshotRequestScope struct {
	SessionID          domain.UUIDv7
	WorkspaceID        domain.UUIDv4
	RecoveryGeneration uint64
	ArtifactID         string
}

// NewSnapshotRequestScope derives the exact indexed-request scope from root.
func NewSnapshotRequestScope(
	root logicalsnapshot.Root,
) (SnapshotRequestScope, error) {
	input := root.Unsigned().Input()
	scope := SnapshotRequestScope{
		SessionID:          input.SessionID,
		WorkspaceID:        input.WorkspaceID,
		RecoveryGeneration: input.RecoveryGeneration,
		ArtifactID:         input.ArtifactID,
	}
	if len(root.CanonicalBytes()) == 0 || scope.validate() != nil {
		return SnapshotRequestScope{}, ErrInvalidSnapshotScope
	}
	return scope, nil
}

func (scope SnapshotRequestScope) validate() error {
	if !scope.SessionID.Valid() ||
		!scope.WorkspaceID.Valid() ||
		!domain.ValidUnsignedInteger(scope.RecoveryGeneration) ||
		!validSnapshotArtifactID(scope.ArtifactID) {
		return ErrInvalidSnapshotScope
	}
	return nil
}

// SnapshotManifestPage is one canonical descriptor page bound to the exact
// request scope used by its provider.
type SnapshotManifestPage struct {
	scope SnapshotRequestScope
	page  logicalsnapshot.DescriptorPage
	valid bool
}

// NewSnapshotManifestPage binds a canonical page to one request scope.
func NewSnapshotManifestPage(
	scope SnapshotRequestScope,
	page logicalsnapshot.DescriptorPage,
) (SnapshotManifestPage, error) {
	input := page.Input()
	if scope.validate() != nil ||
		len(page.CanonicalBytes()) < 1 ||
		len(page.CanonicalBytes()) >
			logicalsnapshot.MaxDescriptorPageBytes ||
		input.ArtifactID != scope.ArtifactID {
		return SnapshotManifestPage{}, ErrInvalidSnapshotPage
	}
	return SnapshotManifestPage{
		scope: scope,
		page:  page,
		valid: true,
	}, nil
}

// Scope returns the exact lineage and artifact selection.
func (page SnapshotManifestPage) Scope() SnapshotRequestScope {
	if page.validate() != nil {
		return SnapshotRequestScope{}
	}
	return page.scope
}

// Page returns the immutable canonical descriptor page value.
func (page SnapshotManifestPage) Page() logicalsnapshot.DescriptorPage {
	if page.validate() != nil {
		return logicalsnapshot.DescriptorPage{}
	}
	return page.page
}

func (page SnapshotManifestPage) validate() error {
	input := page.page.Input()
	if !page.valid ||
		page.scope.validate() != nil ||
		len(page.page.CanonicalBytes()) < 1 ||
		len(page.page.CanonicalBytes()) >
			logicalsnapshot.MaxDescriptorPageBytes ||
		input.ArtifactID != page.scope.ArtifactID {
		return ErrInvalidSnapshotPage
	}
	return nil
}

// SnapshotChunk is one immutable transmitted chunk bound to its artifact and
// zero-based index.
type SnapshotChunk struct {
	scope      SnapshotRequestScope
	chunkIndex uint64
	content    []byte
	valid      bool
}

// NewSnapshotChunk validates and copies one transmitted snapshot chunk.
func NewSnapshotChunk(
	scope SnapshotRequestScope,
	chunkIndex uint64,
	content []byte,
) (SnapshotChunk, error) {
	if scope.validate() != nil ||
		!domain.ValidUnsignedInteger(chunkIndex) ||
		len(content) < 1 ||
		len(content) > logicalsnapshot.MaxChunkCompressedBytes {
		return SnapshotChunk{}, ErrInvalidSnapshotChunk
	}
	return SnapshotChunk{
		scope:      scope,
		chunkIndex: chunkIndex,
		content:    bytes.Clone(content),
		valid:      true,
	}, nil
}

// ArtifactID returns the artifact bound to this chunk.
func (chunk SnapshotChunk) ArtifactID() string {
	if !chunk.valid {
		return ""
	}
	return chunk.scope.ArtifactID
}

// Scope returns the exact lineage and artifact selection.
func (chunk SnapshotChunk) Scope() SnapshotRequestScope {
	if chunk.validate() != nil {
		return SnapshotRequestScope{}
	}
	return chunk.scope
}

// ChunkIndex returns the zero-based chunk index.
func (chunk SnapshotChunk) ChunkIndex() uint64 {
	if !chunk.valid {
		return 0
	}
	return chunk.chunkIndex
}

// Bytes returns an independent copy of the exact transmitted bytes.
func (chunk SnapshotChunk) Bytes() []byte {
	if chunk.validate() != nil {
		return nil
	}
	return bytes.Clone(chunk.content)
}

// Len returns the transmitted byte length.
func (chunk SnapshotChunk) Len() int {
	if chunk.validate() != nil {
		return 0
	}
	return len(chunk.content)
}

func (chunk SnapshotChunk) validate() error {
	if !chunk.valid ||
		chunk.scope.validate() != nil ||
		!domain.ValidUnsignedInteger(chunk.chunkIndex) ||
		len(chunk.content) < 1 ||
		len(chunk.content) > logicalsnapshot.MaxChunkCompressedBytes {
		return ErrInvalidSnapshotChunk
	}
	return nil
}

func (chunk SnapshotChunk) writeTo(writer io.Writer) error {
	if writer == nil {
		return ErrInvalidSnapshotChunk
	}
	if err := chunk.validate(); err != nil {
		return err
	}
	written, err := writer.Write(chunk.content)
	if err != nil {
		return err
	}
	if written != len(chunk.content) {
		return io.ErrShortWrite
	}
	return nil
}

type snapshotTargetKind uint8

const (
	snapshotTargetLatest snapshotTargetKind = iota + 1
	snapshotTargetManifestPage
	snapshotTargetChunk
)

type snapshotTarget struct {
	kind       snapshotTargetKind
	artifactID string
	index      uint64
}

func (target snapshotTarget) responseLimit() int64 {
	switch target.kind {
	case snapshotTargetLatest:
		return int64(logicalsnapshot.MaxRootBytes)
	case snapshotTargetManifestPage:
		return int64(logicalsnapshot.MaxDescriptorPageBytes)
	case snapshotTargetChunk:
		return int64(logicalsnapshot.MaxChunkCompressedBytes)
	default:
		return 0
	}
}

func (target snapshotTarget) mediaType() string {
	if target.kind == snapshotTargetChunk {
		return snapshotChunkMediaType
	}
	return contentJSONMediaType
}

func snapshotRequestTarget(
	request *http.Request,
) (snapshotTarget, bool) {
	if request == nil ||
		request.URL == nil ||
		!validRequestTarget(request) {
		return snapshotTarget{}, false
	}
	return parseSnapshotTarget(request.URL.Path)
}

func parseSnapshotTarget(path string) (snapshotTarget, bool) {
	if path == SnapshotLatestPath {
		return snapshotTarget{kind: snapshotTargetLatest}, true
	}
	if !strings.HasPrefix(path, snapshotPathPrefix) {
		return snapshotTarget{}, false
	}
	segments := strings.Split(strings.TrimPrefix(path, snapshotPathPrefix), "/")
	if len(segments) != 3 ||
		!validSnapshotArtifactID(segments[0]) {
		return snapshotTarget{}, false
	}
	index, valid := parseSnapshotIndex(segments[2])
	if !valid {
		return snapshotTarget{}, false
	}
	target := snapshotTarget{
		artifactID: segments[0],
		index:      index,
	}
	switch segments[1] {
	case "manifest-pages":
		target.kind = snapshotTargetManifestPage
	case "chunks":
		target.kind = snapshotTargetChunk
	default:
		return snapshotTarget{}, false
	}
	return target, true
}

func parseSnapshotIndex(encoded string) (uint64, bool) {
	if encoded == "" || len(encoded) > 1 && encoded[0] == '0' {
		return 0, false
	}
	for _, character := range encoded {
		if character < '0' || character > '9' {
			return 0, false
		}
	}
	value, err := strconv.ParseUint(encoded, 10, 64)
	return value, err == nil &&
		domain.ValidUnsignedInteger(value) &&
		encoded == strconv.FormatUint(value, 10)
}

func validSnapshotArtifactID(value string) bool {
	if len(value) < 1 ||
		len(value) > 128 ||
		value == "." ||
		value == ".." {
		return false
	}
	for index := range len(value) {
		character := value[index]
		switch {
		case character >= 'a' && character <= 'z',
			character >= 'A' && character <= 'Z',
			character >= '0' && character <= '9',
			character == '.', character == '_', character == ':',
			character == '-':
		default:
			return false
		}
	}
	return true
}

func snapshotIndexedPath(
	artifactID string,
	collection string,
	index uint64,
) (string, bool) {
	if !validSnapshotArtifactID(artifactID) ||
		!domain.ValidUnsignedInteger(index) ||
		(collection != "manifest-pages" && collection != "chunks") {
		return "", false
	}
	path := snapshotPathPrefix + artifactID + "/" + collection + "/" +
		strconv.FormatUint(index, 10)
	_, valid := parseSnapshotTarget(path)
	return path, valid
}

func snapshotRequestScope(
	request *http.Request,
	target snapshotTarget,
	sessionID domain.UUIDv7,
) (SnapshotRequestScope, bool) {
	if request == nil ||
		request.Header == nil ||
		target.kind != snapshotTargetManifestPage &&
			target.kind != snapshotTargetChunk ||
		!sessionID.Valid() {
		return SnapshotRequestScope{}, false
	}
	workspaceValues := request.Header.Values(snapshotWorkspaceHeader)
	generationValues := request.Header.Values(snapshotGenerationHeader)
	if len(workspaceValues) != 1 || len(generationValues) != 1 {
		return SnapshotRequestScope{}, false
	}
	workspaceID, err := domain.ParseUUIDv4(workspaceValues[0])
	if err != nil {
		return SnapshotRequestScope{}, false
	}
	generation, valid := parseSnapshotIndex(generationValues[0])
	if !valid {
		return SnapshotRequestScope{}, false
	}
	scope := SnapshotRequestScope{
		SessionID:          sessionID,
		WorkspaceID:        workspaceID,
		RecoveryGeneration: generation,
		ArtifactID:         target.artifactID,
	}
	return scope, scope.validate() == nil
}

func setSnapshotScopeHeaders(
	header http.Header,
	scope SnapshotRequestScope,
) bool {
	if header == nil || scope.validate() != nil {
		return false
	}
	header.Set(snapshotWorkspaceHeader, string(scope.WorkspaceID))
	header.Set(
		snapshotGenerationHeader,
		strconv.FormatUint(scope.RecoveryGeneration, 10),
	)
	return true
}

func (handler *connectionHandler) snapshotTransferFor(
	ctx context.Context,
	scope SnapshotRequestScope,
) (SnapshotTransfer, error) {
	if handler == nil ||
		handler.server == nil ||
		handler.server.snapshots == nil ||
		ctx == nil ||
		scope.validate() != nil {
		return nil, ErrSnapshotUnavailable
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	handler.snapshotMu.Lock()
	defer handler.snapshotMu.Unlock()
	if handler.snapshotTransfer != nil {
		if handler.snapshotScope != scope ||
			handler.snapshotTransfer.Scope() != scope {
			return nil, ErrInvalidSnapshotScope
		}
		return handler.snapshotTransfer, nil
	}
	transfer, err := handler.server.snapshots.OpenSnapshotTransfer(ctx, scope)
	if err != nil {
		return nil, err
	}
	if transfer == nil || transfer.Scope() != scope {
		if transfer != nil {
			err = transfer.Close()
		}
		return nil, errors.Join(ErrInvalidSnapshotScope, err)
	}
	handler.snapshotTransfer = transfer
	handler.snapshotScope = scope
	handler.snapshotTimer = time.AfterFunc(
		handler.server.snapshotTransferLifetime,
		handler.stopConnection,
	)
	return transfer, nil
}

func (handler *connectionHandler) closeSnapshotTransfer() error {
	if handler == nil {
		return nil
	}
	handler.snapshotMu.Lock()
	transfer := handler.snapshotTransfer
	timer := handler.snapshotTimer
	handler.snapshotTransfer = nil
	handler.snapshotScope = SnapshotRequestScope{}
	handler.snapshotTimer = nil
	handler.snapshotMu.Unlock()

	if timer != nil {
		timer.Stop()
	}
	if transfer == nil {
		return nil
	}
	return transfer.Close()
}

func (handler *connectionHandler) serveSnapshot(
	writer http.ResponseWriter,
	request *http.Request,
	target snapshotTarget,
) {
	if request.Method != http.MethodGet {
		writer.Header().Set("Allow", http.MethodGet)
		writeProblem(writer, http.StatusMethodNotAllowed, problemMethod)
		return
	}
	if !validBodylessRequest(request) {
		writeProblem(writer, http.StatusBadRequest, problemRequestBody)
		return
	}
	if !validNegotiationFor(request.Header, target.mediaType()) {
		writeProblem(writer, http.StatusNotAcceptable, problemNegotiation)
		return
	}
	if target.kind != snapshotTargetChunk {
		select {
		case handler.server.replicationHandlers <- struct{}{}:
			defer func() { <-handler.server.replicationHandlers }()
		default:
			writer.Header().Set("Retry-After", "1")
			writeProblem(
				writer,
				http.StatusServiceUnavailable,
				problemSnapshotUnavailable,
			)
			return
		}
	}

	callContext, cancel := context.WithTimeout(
		request.Context(),
		handler.server.handlerTimeout,
	)
	defer cancel()
	if handler.server.snapshots == nil {
		writeSnapshotProblem(writer, ErrSnapshotUnavailable)
		return
	}

	var (
		scope    SnapshotRequestScope
		transfer SnapshotTransfer
	)
	if target.kind == snapshotTargetManifestPage ||
		target.kind == snapshotTargetChunk {
		var valid bool
		scope, valid = snapshotRequestScope(
			request,
			target,
			handler.peer.SessionID,
		)
		if !valid {
			writeProblem(writer, http.StatusBadRequest, problemSnapshotScope)
			return
		}
		var err error
		transfer, err = handler.snapshotTransferFor(callContext, scope)
		if err != nil {
			if errors.Is(err, ErrInvalidSnapshotScope) {
				handler.closeAfterResponse(writer)
				writeProblem(
					writer,
					http.StatusBadRequest,
					problemSnapshotScope,
				)
				return
			}
			writeSnapshotProblem(writer, err)
			return
		}
	}

	switch target.kind {
	case snapshotTargetLatest:
		root, err := handler.server.snapshots.LatestSnapshot(callContext)
		if err != nil {
			writeSnapshotProblem(writer, err)
			return
		}
		input := root.Unsigned().Input()
		encoded := root.CanonicalBytes()
		if input.SessionID != handler.peer.SessionID ||
			!validSnapshotArtifactID(input.ArtifactID) ||
			len(encoded) < 1 ||
			len(encoded) > logicalsnapshot.MaxRootBytes {
			writeProblem(writer, http.StatusInternalServerError, problemInternal)
			return
		}
		writeJSON(writer, http.StatusOK, contentJSONMediaType, encoded)
	case snapshotTargetManifestPage:
		result, err := transfer.SnapshotManifestPage(
			callContext,
			target.index,
		)
		if err != nil {
			writeSnapshotProblem(writer, err)
			return
		}
		page := result.Page()
		input := page.Input()
		encoded := page.CanonicalBytes()
		if result.validate() != nil ||
			result.Scope() != scope ||
			input.ArtifactID != target.artifactID ||
			input.PageIndex != target.index ||
			len(encoded) < 1 ||
			len(encoded) > logicalsnapshot.MaxDescriptorPageBytes {
			writeProblem(writer, http.StatusInternalServerError, problemInternal)
			return
		}
		writeJSON(writer, http.StatusOK, contentJSONMediaType, encoded)
	case snapshotTargetChunk:
		chunk, err := transfer.SnapshotChunk(
			callContext,
			target.index,
		)
		if err != nil {
			writeSnapshotProblem(writer, err)
			return
		}
		if chunk.validate() != nil ||
			chunk.Scope() != scope ||
			chunk.scope.ArtifactID != target.artifactID ||
			chunk.chunkIndex != target.index {
			writeProblem(writer, http.StatusInternalServerError, problemInternal)
			return
		}
		writeJSONHeader(
			writer,
			http.StatusOK,
			snapshotChunkMediaType,
			len(chunk.content),
		)
		_ = chunk.writeTo(writer)
	default:
		writeProblem(writer, http.StatusNotFound, problemRouteNotFound)
	}
}

func writeSnapshotProblem(writer http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, ErrSnapshotNotFound):
		writeProblem(
			writer,
			http.StatusNotFound,
			problemSnapshotNotFound,
		)
	case errors.Is(err, context.Canceled),
		errors.Is(err, context.DeadlineExceeded),
		errors.Is(err, ErrSnapshotUnavailable):
		writer.Header().Set("Retry-After", "1")
		writeProblem(
			writer,
			http.StatusServiceUnavailable,
			problemSnapshotUnavailable,
		)
	default:
		writeProblem(writer, http.StatusInternalServerError, problemInternal)
	}
}

var (
	problemSnapshotNotFound = problemDefinition{
		code:      "snapshot_not_found",
		title:     "Logical snapshot not found",
		retryable: true,
	}
	problemSnapshotUnavailable = problemDefinition{
		code:      "snapshot_unavailable",
		title:     "Logical snapshot temporarily unavailable",
		retryable: true,
	}
	problemSnapshotScope = problemDefinition{
		code:  "invalid_snapshot_scope",
		title: "Invalid logical snapshot request scope",
	}
)

// LatestSnapshot returns the peer's exact canonical signed logical-snapshot
// root after Session binds this client to the peer's lineage. Root signature
// authorization remains the importer's responsibility.
func (client *Client) LatestSnapshot(
	ctx context.Context,
) (logicalsnapshot.Root, error) {
	if client == nil || ctx == nil {
		return logicalsnapshot.Root{}, ErrInvalidClient
	}
	if err := ctx.Err(); err != nil {
		return logicalsnapshot.Root{}, err
	}
	client.operationMu.Lock()
	defer client.operationMu.Unlock()

	lineage, err := client.replicationLineage()
	if err != nil {
		return logicalsnapshot.Root{}, err
	}
	body, err := client.requestBounded(
		ctx,
		http.MethodGet,
		SnapshotLatestPath,
		nil,
		nil,
		int64(logicalsnapshot.MaxRootBytes),
	)
	if err != nil {
		return logicalsnapshot.Root{}, normalizeClientSnapshotError(err)
	}
	root, err := logicalsnapshot.ParseRoot(body)
	if err != nil {
		client.invalidate()
		return logicalsnapshot.Root{}, fmt.Errorf(
			"%w: parse logical snapshot root: %w",
			ErrResponseProtocol,
			err,
		)
	}
	input := root.Unsigned().Input()
	if input.SessionID != lineage.sessionID ||
		input.WorkspaceID != lineage.workspaceID ||
		input.RecoveryGeneration != lineage.recoveryGeneration {
		client.invalidate()
		return logicalsnapshot.Root{}, ErrLineageMismatch
	}
	if !validSnapshotArtifactID(input.ArtifactID) {
		client.invalidate()
		return logicalsnapshot.Root{}, ErrResponseProtocol
	}
	return root, nil
}

// SnapshotManifestPage rejects page retrieval on a content-control connection.
// Use OpenSnapshotBulkClient with a root fetched on this control client.
func (client *Client) SnapshotManifestPage(
	ctx context.Context,
	_ logicalsnapshot.Root,
	_ uint64,
) (logicalsnapshot.DescriptorPage, error) {
	if client == nil || ctx == nil {
		return logicalsnapshot.DescriptorPage{}, ErrInvalidClient
	}
	if err := ctx.Err(); err != nil {
		return logicalsnapshot.DescriptorPage{}, err
	}
	return logicalsnapshot.DescriptorPage{}, ErrInvalidClient
}

// SnapshotChunk rejects chunk retrieval on a content-control connection.
// Use OpenSnapshotBulkClient with a root fetched on this control client.
func (client *Client) SnapshotChunk(
	ctx context.Context,
	_ logicalsnapshot.Root,
	_ uint64,
) (SnapshotChunk, error) {
	if client == nil || ctx == nil {
		return SnapshotChunk{}, ErrInvalidClient
	}
	if err := ctx.Err(); err != nil {
		return SnapshotChunk{}, err
	}
	return SnapshotChunk{}, ErrInvalidClient
}

// SnapshotBulkClient owns one authenticated content-bulk HTTP/2 connection
// bound to a previously fetched snapshot root. Manifest pages and chunks use
// this same connection; roots, replication, and control routes are absent.
type SnapshotBulkClient struct {
	client *Client
	root   logicalsnapshot.Root
	input  logicalsnapshot.RootInput
	scope  SnapshotRequestScope
}

// OpenSnapshotBulkClient performs a bounded content-plane handshake and binds
// the owned connection to root's exact lineage and artifact. The constructor
// takes ownership of connection on every return path.
func OpenSnapshotBulkClient(
	ctx context.Context,
	connection *tls.Conn,
	expectedDeviceID domain.DeviceID,
	admission *transport.ContentAdmissionRecorder,
	root logicalsnapshot.Root,
) (_ *SnapshotBulkClient, err error) {
	if connection == nil {
		return nil, ErrInvalidClient
	}
	scope, scopeErr := NewSnapshotRequestScope(root)
	if scopeErr != nil {
		_ = connection.Close()
		return nil, ErrInvalidClient
	}
	input := root.Unsigned().Input()
	client, err := openClientForRole(
		ctx,
		connection,
		expectedDeviceID,
		admission,
		contentConnectionBulk,
	)
	if err != nil {
		return nil, err
	}
	if err := client.bindLineage(
		scope.SessionID,
		scope.WorkspaceID,
		scope.RecoveryGeneration,
		expectedDeviceID,
		true,
	); err != nil {
		_ = client.Close()
		return nil, err
	}
	return &SnapshotBulkClient{
		client: client,
		root:   root,
		input:  input,
		scope:  scope,
	}, nil
}

// SnapshotManifestPage returns one bounded canonical descriptor page from the
// root fixed at construction.
func (client *SnapshotBulkClient) SnapshotManifestPage(
	ctx context.Context,
	pageIndex uint64,
) (logicalsnapshot.DescriptorPage, error) {
	if client == nil || client.client == nil || ctx == nil {
		return logicalsnapshot.DescriptorPage{}, ErrInvalidClient
	}
	if err := ctx.Err(); err != nil {
		return logicalsnapshot.DescriptorPage{}, err
	}
	client.client.operationMu.Lock()
	defer client.client.operationMu.Unlock()

	if client.scope.validate() != nil ||
		len(client.root.CanonicalBytes()) == 0 ||
		client.input.ArtifactID != client.scope.ArtifactID ||
		!domain.ValidUnsignedInteger(pageIndex) ||
		pageIndex >= client.input.DescriptorPageCount {
		return logicalsnapshot.DescriptorPage{}, ErrInvalidClient
	}
	target, valid := snapshotIndexedPath(
		client.scope.ArtifactID,
		"manifest-pages",
		pageIndex,
	)
	if !valid {
		return logicalsnapshot.DescriptorPage{}, ErrInvalidClient
	}
	body, err := client.client.requestBounded(
		ctx,
		http.MethodGet,
		target,
		nil,
		func(header http.Header) {
			setSnapshotScopeHeaders(header, client.scope)
		},
		int64(logicalsnapshot.MaxDescriptorPageBytes),
	)
	if err != nil {
		return logicalsnapshot.DescriptorPage{},
			normalizeClientSnapshotError(err)
	}
	page, err := logicalsnapshot.ParseDescriptorPage(body)
	if err != nil {
		client.client.invalidate()
		return logicalsnapshot.DescriptorPage{}, fmt.Errorf(
			"%w: parse logical snapshot descriptor page: %w",
			ErrResponseProtocol,
			err,
		)
	}
	pageInput := page.Input()
	if pageInput.ArtifactID != client.input.ArtifactID ||
		pageInput.PageIndex != pageIndex {
		client.client.invalidate()
		return logicalsnapshot.DescriptorPage{}, ErrResponseProtocol
	}
	return page, nil
}

// SnapshotChunk returns one bounded binary transmitted chunk from the root
// fixed at construction.
func (client *SnapshotBulkClient) SnapshotChunk(
	ctx context.Context,
	chunkIndex uint64,
) (SnapshotChunk, error) {
	if client == nil || client.client == nil || ctx == nil {
		return SnapshotChunk{}, ErrInvalidClient
	}
	if err := ctx.Err(); err != nil {
		return SnapshotChunk{}, err
	}
	client.client.operationMu.Lock()
	defer client.client.operationMu.Unlock()

	if client.scope.validate() != nil ||
		len(client.root.CanonicalBytes()) == 0 ||
		client.input.ArtifactID != client.scope.ArtifactID ||
		!domain.ValidUnsignedInteger(chunkIndex) ||
		chunkIndex >= client.input.ChunkCount {
		return SnapshotChunk{}, ErrInvalidClient
	}
	target, valid := snapshotIndexedPath(
		client.scope.ArtifactID,
		"chunks",
		chunkIndex,
	)
	if !valid {
		return SnapshotChunk{}, ErrInvalidClient
	}
	body, err := client.client.requestBounded(
		ctx,
		http.MethodGet,
		target,
		nil,
		func(header http.Header) {
			setSnapshotScopeHeaders(header, client.scope)
		},
		int64(logicalsnapshot.MaxChunkCompressedBytes),
	)
	if err != nil {
		return SnapshotChunk{}, normalizeClientSnapshotError(err)
	}
	chunk, err := NewSnapshotChunk(client.scope, chunkIndex, body)
	if err != nil {
		client.client.invalidate()
		return SnapshotChunk{}, fmt.Errorf(
			"%w: parse logical snapshot chunk: %w",
			ErrResponseProtocol,
			err,
		)
	}
	return chunk, nil
}

// Close interrupts in-flight chunk retrieval and releases the owned bulk
// connection. Repeated calls are idempotent.
func (client *SnapshotBulkClient) Close() error {
	if client == nil || client.client == nil {
		return ErrInvalidClient
	}
	return client.client.Close()
}

func normalizeClientSnapshotError(err error) error {
	var remote *RemoteError
	if !errors.As(err, &remote) {
		return err
	}
	switch {
	case remote.Code == problemSnapshotNotFound.code &&
		remote.Status == http.StatusNotFound:
		return fmt.Errorf("%w: %w", ErrSnapshotNotFound, err)
	case remote.Code == problemSnapshotUnavailable.code &&
		remote.Status == http.StatusServiceUnavailable:
		return fmt.Errorf("%w: %w", ErrSnapshotUnavailable, err)
	default:
		return err
	}
}
