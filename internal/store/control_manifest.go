package store

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"sort"

	"github.com/ijonahch/codecomm/internal/codec"
	"github.com/ijonahch/codecomm/internal/domain"
	"github.com/ijonahch/codecomm/internal/event"
	"zombiezen.com/go/sqlite"
)

const (
	// InitialControlManifestVersion is the durable version of the empty
	// approved-control-file state.
	InitialControlManifestVersion uint64 = 0

	controlManifestDomain = "codecomm/v1/control-manifest"
)

var (
	ErrInvalidControlFileDecision = errors.New(
		"store: invalid control-file decision",
	)
	ErrControlFileLineageMismatch = errors.New(
		"store: control-file lineage mismatch",
	)
	ErrControlFileProposalNotFound = errors.New(
		"store: control-file proposal not found",
	)
	ErrControlFileProposalStale = errors.New(
		"store: control-file proposal is stale",
	)
	ErrControlFileDecisionConflict = errors.New(
		"store: control-file decision conflicts with durable state",
	)
	ErrControlFileStateIntegrity = errors.New(
		"store: control-file state integrity failure",
	)
	ErrControlManifestVersionExhausted = errors.New(
		"store: control-manifest version exhausted",
	)
)

// ControlFileDecision is the closed local consent state.
type ControlFileDecision string

const (
	ControlFilePending  ControlFileDecision = "pending"
	ControlFileApproved ControlFileDecision = "approved"
	ControlFileDeclined ControlFileDecision = "declined"
)

func (decision ControlFileDecision) valid() bool {
	switch decision {
	case ControlFilePending, ControlFileApproved, ControlFileDeclined:
		return true
	default:
		return false
	}
}

// ControlFileContentRef is a canonical state-directory-relative reference to
// durably cached approved bytes or a delete tombstone.
type ControlFileContentRef string

// Valid reports whether the reference is portable, relative, and traversal
// free. The referenced object is created and verified by the content layer
// before this store transaction.
func (reference ControlFileContentRef) Valid() bool {
	return domain.RepositoryPath(reference).Valid()
}

// ControlFileLineage binds a local operation to one active generation.
type ControlFileLineage struct {
	SessionID          domain.UUIDv7
	WorkspaceID        domain.UUIDv4
	RecoveryGeneration uint64
}

func (lineage ControlFileLineage) validate() error {
	if !lineage.SessionID.Valid() ||
		!lineage.WorkspaceID.Valid() ||
		!domain.ValidUnsignedInteger(lineage.RecoveryGeneration) {
		return ErrInvalidControlFileDecision
	}
	return nil
}

// ControlFileProposalReference is the immutable proposal identity repeated by
// a local reviewer. Repetition prevents an event-ID-only lookup from approving
// content the caller did not review.
type ControlFileProposalReference struct {
	ProposalEventID domain.UUIDv7
	Path            domain.RepositoryPath
	Operation       ControlFileOperation
	ContentDigest   *[sha256.Size]byte
	ChainIndex      uint64
}

func (reference ControlFileProposalReference) validate() error {
	if !reference.ProposalEventID.Valid() ||
		!reference.Path.Valid() ||
		!reference.Operation.valid() ||
		reference.ChainIndex < 1 ||
		!domain.ValidUnsignedInteger(reference.ChainIndex) {
		return ErrInvalidControlFileDecision
	}
	switch reference.Operation {
	case ControlFileUpsert:
		if reference.ContentDigest == nil {
			return ErrInvalidControlFileDecision
		}
	case ControlFileDelete:
		if reference.ContentDigest != nil {
			return ErrInvalidControlFileDecision
		}
	default:
		return ErrInvalidControlFileDecision
	}
	return nil
}

// ControlFileDecisionInput contains the exact lineage, proposal, and canonical
// decision time common to approval and decline.
type ControlFileDecisionInput struct {
	Lineage   ControlFileLineage
	Proposal  ControlFileProposalReference
	DecidedAt domain.Timestamp
}

func (input ControlFileDecisionInput) validate() error {
	if err := input.Lineage.validate(); err != nil {
		return err
	}
	if err := input.Proposal.validate(); err != nil {
		return err
	}
	if !input.DecidedAt.Valid() {
		return ErrInvalidControlFileDecision
	}
	return nil
}

// ControlFileApprovalInput approves one pending proposal after its content or
// tombstone has been durably installed.
type ControlFileApprovalInput struct {
	ControlFileDecisionInput
	ContentStoreRef ControlFileContentRef
}

func (input ControlFileApprovalInput) validate() error {
	if err := input.ControlFileDecisionInput.validate(); err != nil {
		return err
	}
	if !input.ContentStoreRef.Valid() {
		return ErrInvalidControlFileDecision
	}
	return nil
}

// ControlFileDecisionRecord is one durable local decision. ManifestVersion is
// zero for a decline and otherwise names the manifest version at approval.
type ControlFileDecisionRecord struct {
	ProposalEventID domain.UUIDv7
	SessionID       domain.UUIDv7
	Path            domain.RepositoryPath
	Operation       ControlFileOperation
	ContentDigest   *[sha256.Size]byte
	ChainIndex      uint64
	Decision        ControlFileDecision
	ContentStoreRef ControlFileContentRef
	ManifestVersion uint64
	DecidedAt       domain.Timestamp
}

// ControlManifestEntry is one current approved operation.
type ControlManifestEntry struct {
	Path          domain.RepositoryPath
	Operation     ControlFileOperation
	ContentDigest *Digest
}

// ControlManifest is the exact local approved-control-file gate advertised in
// presence and bound into paginated comparisons.
type ControlManifest struct {
	SessionID domain.UUIDv7
	Version   uint64
	Digest    Digest
	PathCount uint64
	Entries   []ControlManifestEntry
}

type controlFileDecisionStage uint8

const controlFileAfterDecisionWrite controlFileDecisionStage = 1

type storedControlFileApproval struct {
	proposal        ControlFileProposalRow
	decision        ControlFileDecision
	contentStoreRef ControlFileContentRef
	manifestVersion uint64
	decidedAt       domain.Timestamp
}

// ControlManifest reads a transactionally stable manifest for the requested
// active generation. Any missing, malformed, or noncanonical local row fails
// closed.
func (state LocalState) ControlManifest(
	ctx context.Context,
	lineage ControlFileLineage,
) (ControlManifest, error) {
	if err := lineage.validate(); err != nil {
		return ControlManifest{}, err
	}
	var manifest ControlManifest
	err := state.withImmediate(ctx, func(conn *sqlite.Conn) error {
		if err := requireControlFileLineage(conn, lineage); err != nil {
			return err
		}
		var err error
		manifest, err = readControlManifest(conn, lineage.SessionID)
		return err
	})
	if err != nil {
		return ControlManifest{}, err
	}
	return cloneControlManifest(manifest), nil
}

// ApproveControlFile atomically records local consent and advances the
// manifest version only if the exact current entry array changes. The bool is
// true only for an exact replay of the durable decision.
func (state LocalState) ApproveControlFile(
	ctx context.Context,
	input ControlFileApprovalInput,
) (ControlFileDecisionRecord, bool, error) {
	if err := input.validate(); err != nil {
		return ControlFileDecisionRecord{}, false, err
	}
	var (
		result    ControlFileDecisionRecord
		duplicate bool
	)
	err := state.withImmediate(ctx, func(conn *sqlite.Conn) error {
		if err := requireControlFileLineage(conn, input.Lineage); err != nil {
			return err
		}
		rows, err := readStoredControlFileApprovals(
			conn,
			input.Lineage.SessionID,
		)
		if err != nil {
			return err
		}
		row, found := findStoredControlFileApproval(
			rows,
			input.Proposal.ProposalEventID,
		)
		if !found {
			return ErrControlFileProposalNotFound
		}
		if !controlFileProposalReferenceMatches(
			row.proposal,
			input.Lineage.SessionID,
			input.Proposal,
		) {
			return ErrControlFileDecisionConflict
		}
		switch row.decision {
		case ControlFileApproved:
			if row.contentStoreRef != input.ContentStoreRef ||
				row.decidedAt != input.DecidedAt {
				return ErrControlFileDecisionConflict
			}
			result = row.decisionRecord()
			duplicate = true
			_, err := deriveControlManifest(input.Lineage.SessionID, rows)
			return err
		case ControlFileDeclined:
			return ErrControlFileDecisionConflict
		case ControlFilePending:
			// Continue below.
		default:
			return ErrControlFileStateIntegrity
		}
		if !isLatestControlFileProposal(rows, row.proposal) {
			return ErrControlFileProposalStale
		}

		before, err := deriveControlManifest(input.Lineage.SessionID, rows)
		if err != nil {
			return err
		}
		current, exists := controlManifestEntryForPath(
			before.Entries,
			row.proposal.Path,
		)
		candidate := manifestEntryFromProposal(row.proposal)
		changed := !exists || !controlManifestEntryEqual(current, candidate)
		version := before.Version
		if changed {
			if version == domain.MaxSafeInteger {
				return ErrControlManifestVersionExhausted
			}
			version++
		}
		if err := execute(
			conn,
			`UPDATE control_file_approvals
			    SET decision = 'approved', content_store_ref = ?2,
			        manifest_version = ?3, decided_at = ?4
			  WHERE proposal_event_id = ?1 AND decision = 'pending';`,
			string(row.proposal.ProposalEventID),
			string(input.ContentStoreRef),
			version,
			string(input.DecidedAt),
		); err != nil {
			return err
		}
		if err := requireOneChangedRow(conn); err != nil {
			return err
		}
		if err := state.store.reachControlFileDecisionStage(
			controlFileAfterDecisionWrite,
		); err != nil {
			return err
		}

		afterRows, err := readStoredControlFileApprovals(
			conn,
			input.Lineage.SessionID,
		)
		if err != nil {
			return err
		}
		after, err := deriveControlManifest(input.Lineage.SessionID, afterRows)
		if err != nil {
			return err
		}
		expectedEntries := before.Entries
		if changed {
			expectedEntries = replaceControlManifestEntry(
				before.Entries,
				candidate,
			)
		}
		if after.Version != version ||
			!controlManifestEntriesEqual(after.Entries, expectedEntries) {
			return ErrControlFileStateIntegrity
		}
		updated, found := findStoredControlFileApproval(
			afterRows,
			row.proposal.ProposalEventID,
		)
		if !found ||
			updated.decision != ControlFileApproved ||
			updated.contentStoreRef != input.ContentStoreRef ||
			updated.decidedAt != input.DecidedAt ||
			updated.manifestVersion != version {
			return ErrControlFileStateIntegrity
		}
		result = updated.decisionRecord()
		return nil
	})
	if err != nil {
		return ControlFileDecisionRecord{}, false, err
	}
	return result, duplicate, nil
}

// DeclineControlFile atomically declines one pending current proposal without
// changing the current manifest. The bool is true only for an exact replay.
func (state LocalState) DeclineControlFile(
	ctx context.Context,
	input ControlFileDecisionInput,
) (ControlFileDecisionRecord, bool, error) {
	if err := input.validate(); err != nil {
		return ControlFileDecisionRecord{}, false, err
	}
	var (
		result    ControlFileDecisionRecord
		duplicate bool
	)
	err := state.withImmediate(ctx, func(conn *sqlite.Conn) error {
		if err := requireControlFileLineage(conn, input.Lineage); err != nil {
			return err
		}
		rows, err := readStoredControlFileApprovals(
			conn,
			input.Lineage.SessionID,
		)
		if err != nil {
			return err
		}
		row, found := findStoredControlFileApproval(
			rows,
			input.Proposal.ProposalEventID,
		)
		if !found {
			return ErrControlFileProposalNotFound
		}
		if !controlFileProposalReferenceMatches(
			row.proposal,
			input.Lineage.SessionID,
			input.Proposal,
		) {
			return ErrControlFileDecisionConflict
		}
		switch row.decision {
		case ControlFileDeclined:
			if row.decidedAt != input.DecidedAt {
				return ErrControlFileDecisionConflict
			}
			result = row.decisionRecord()
			duplicate = true
			_, err := deriveControlManifest(input.Lineage.SessionID, rows)
			return err
		case ControlFileApproved:
			return ErrControlFileDecisionConflict
		case ControlFilePending:
			// Continue below.
		default:
			return ErrControlFileStateIntegrity
		}
		if !isLatestControlFileProposal(rows, row.proposal) {
			return ErrControlFileProposalStale
		}
		before, err := deriveControlManifest(input.Lineage.SessionID, rows)
		if err != nil {
			return err
		}
		if err := execute(
			conn,
			`UPDATE control_file_approvals
			    SET decision = 'declined', decided_at = ?2
			  WHERE proposal_event_id = ?1 AND decision = 'pending';`,
			string(row.proposal.ProposalEventID),
			string(input.DecidedAt),
		); err != nil {
			return err
		}
		if err := requireOneChangedRow(conn); err != nil {
			return err
		}
		if err := state.store.reachControlFileDecisionStage(
			controlFileAfterDecisionWrite,
		); err != nil {
			return err
		}
		afterRows, err := readStoredControlFileApprovals(
			conn,
			input.Lineage.SessionID,
		)
		if err != nil {
			return err
		}
		after, err := deriveControlManifest(input.Lineage.SessionID, afterRows)
		if err != nil {
			return err
		}
		if after.Version != before.Version ||
			after.Digest != before.Digest ||
			!controlManifestEntriesEqual(after.Entries, before.Entries) {
			return ErrControlFileStateIntegrity
		}
		updated, found := findStoredControlFileApproval(
			afterRows,
			row.proposal.ProposalEventID,
		)
		if !found ||
			updated.decision != ControlFileDeclined ||
			updated.decidedAt != input.DecidedAt {
			return ErrControlFileStateIntegrity
		}
		result = updated.decisionRecord()
		return nil
	})
	if err != nil {
		return ControlFileDecisionRecord{}, false, err
	}
	return result, duplicate, nil
}

func (store *Store) reachControlFileDecisionStage(
	stage controlFileDecisionStage,
) error {
	if store.controlFileFailpoint == nil {
		return nil
	}
	return store.controlFileFailpoint(stage)
}

func requireControlFileLineage(
	conn *sqlite.Conn,
	want ControlFileLineage,
) error {
	lineage, err := readLocalLineage(conn)
	if err != nil {
		return err
	}
	if lineage.sessionID != want.SessionID ||
		lineage.workspaceID != want.WorkspaceID ||
		lineage.recoveryGeneration != want.RecoveryGeneration {
		return ErrControlFileLineageMismatch
	}
	return nil
}

func validateAppliedControlFileProjections(
	request ApplyRequest,
	heads ApplyHeads,
	rows []ControlFileProposalRow,
) error {
	proposal := request.Proposal.Proposal()
	if request.Outcome.Status == OutcomeAccepted &&
		proposal.Kind == event.KindControlFileChangeProposed {
		if len(rows) != 1 {
			return fmt.Errorf(
				"%w: accepted control-file event produced %d proposals, want 1",
				ErrInvalidApply,
				len(rows),
			)
		}
		entityID, present := proposal.EntityID.Value()
		row := rows[0]
		if !present ||
			row.ProposalEventID != proposal.EventID ||
			row.SessionID != proposal.SessionID ||
			string(row.Path) != entityID ||
			row.ProposedByDeviceID != proposal.Origin.DeviceID() ||
			row.ChainIndex != heads.ChainIndex {
			return fmt.Errorf(
				"%w: control-file projection does not match accepted event",
				ErrInvalidApply,
			)
		}
		payload, err := controlFileProposalPayload(row)
		if err != nil || !bytes.Equal(payload, proposal.Payload) {
			return fmt.Errorf(
				"%w: control-file projection does not match signed payload",
				ErrInvalidApply,
			)
		}
		return nil
	}
	if len(rows) == 0 {
		return nil
	}
	return fmt.Errorf(
		"%w: control-file projection on event kind %q with outcome %q",
		ErrInvalidApply,
		proposal.Kind,
		request.Outcome.Status,
	)
}

func controlFileProposalPayload(row ControlFileProposalRow) ([]byte, error) {
	var contentDigest *string
	if row.ContentDigest != nil {
		encoded := codec.EncodeBase64URL(row.ContentDigest[:])
		contentDigest = &encoded
	}
	encoded, err := json.Marshal(struct {
		Path          string  `json:"path"`
		Operation     string  `json:"operation"`
		ContentDigest *string `json:"content_digest"`
		ContentSize   uint64  `json:"content_size"`
		Diff          string  `json:"diff"`
	}{
		Path:          string(row.Path),
		Operation:     string(row.Operation),
		ContentDigest: contentDigest,
		ContentSize:   row.ContentSize,
		Diff:          row.Diff,
	})
	if err != nil {
		return nil, err
	}
	return codec.CanonicalizeSignedObject(encoded)
}

func ensurePendingControlFileApprovals(
	conn *sqlite.Conn,
	sessionID domain.UUIDv7,
	rows []ControlFileProposalRow,
) error {
	for index, row := range rows {
		if row.SessionID != sessionID {
			return fmt.Errorf(
				"%w: control-file proposal %d belongs to another session",
				ErrInvalidApply,
				index,
			)
		}
		if err := execute(
			conn,
			`INSERT INTO control_file_approvals(
			    proposal_event_id, session_id, path, operation,
			    content_digest, decision, content_store_ref,
			    manifest_version, decided_at
			) VALUES (?1, ?2, ?3, ?4, ?5, 'pending', NULL, NULL, NULL)
			ON CONFLICT (proposal_event_id) DO NOTHING;`,
			string(row.ProposalEventID),
			string(row.SessionID),
			string(row.Path),
			string(row.Operation),
			nullableDigest(row.ContentDigest),
		); err != nil {
			return fmt.Errorf(
				"store: initialize control-file approval %d: %w",
				index,
				err,
			)
		}
		stored, found, err := readStoredControlFileApproval(
			conn,
			row.ProposalEventID,
		)
		if err != nil {
			return err
		}
		if !found ||
			!controlFileProposalsEqual(stored.proposal, row) ||
			stored.decision != ControlFilePending {
			return ErrControlFileStateIntegrity
		}
	}
	return nil
}

func readControlManifest(
	conn *sqlite.Conn,
	sessionID domain.UUIDv7,
) (ControlManifest, error) {
	rows, err := readStoredControlFileApprovals(conn, sessionID)
	if err != nil {
		return ControlManifest{}, err
	}
	return deriveControlManifest(sessionID, rows)
}

func deriveControlManifest(
	sessionID domain.UUIDv7,
	rows []storedControlFileApproval,
) (ControlManifest, error) {
	if !sessionID.Valid() {
		return ControlManifest{}, ErrControlFileStateIntegrity
	}
	version := InitialControlManifestVersion
	current := make(map[domain.RepositoryPath]storedControlFileApproval)
	for _, row := range rows {
		if row.proposal.SessionID != sessionID || !row.decision.valid() {
			return ControlManifest{}, ErrControlFileStateIntegrity
		}
		if row.decision != ControlFileApproved {
			continue
		}
		if row.manifestVersion < 1 ||
			!domain.ValidUnsignedInteger(row.manifestVersion) {
			return ControlManifest{}, ErrControlFileStateIntegrity
		}
		if row.manifestVersion > version {
			version = row.manifestVersion
		}
		previous, exists := current[row.proposal.Path]
		if !exists ||
			row.manifestVersion > previous.manifestVersion ||
			row.manifestVersion == previous.manifestVersion &&
				row.proposal.ChainIndex > previous.proposal.ChainIndex {
			if exists &&
				row.manifestVersion == previous.manifestVersion &&
				!controlFileProposalsHaveSameManifestEntry(
					row.proposal,
					previous.proposal,
				) {
				return ControlManifest{}, ErrControlFileStateIntegrity
			}
			current[row.proposal.Path] = row
		}
	}

	paths := make([]domain.RepositoryPath, 0, len(current))
	for path := range current {
		paths = append(paths, path)
	}
	sort.Slice(paths, func(left, right int) bool {
		return string(paths[left]) < string(paths[right])
	})
	entries := make([]ControlManifestEntry, 0, len(paths))
	for _, path := range paths {
		entries = append(
			entries,
			manifestEntryFromProposal(current[path].proposal),
		)
	}
	if !domain.ValidUnsignedInteger(uint64(len(entries))) {
		return ControlManifest{}, ErrControlFileStateIntegrity
	}
	_, digest, err := encodeControlManifestEntries(entries)
	if err != nil {
		return ControlManifest{}, err
	}
	return ControlManifest{
		SessionID: sessionID,
		Version:   version,
		Digest:    digest,
		PathCount: uint64(len(entries)),
		Entries:   entries,
	}, nil
}

type controlManifestJSONEntry struct {
	Path          string  `json:"path"`
	Operation     string  `json:"operation"`
	ContentDigest *string `json:"content_digest"`
}

func encodeControlManifestEntries(
	entries []ControlManifestEntry,
) ([]byte, Digest, error) {
	wire := make([]controlManifestJSONEntry, len(entries))
	var previous domain.RepositoryPath
	for index, entry := range entries {
		if !entry.Path.Valid() || !entry.Operation.valid() {
			return nil, Digest{}, ErrControlFileStateIntegrity
		}
		if index > 0 && string(previous) >= string(entry.Path) {
			return nil, Digest{}, ErrControlFileStateIntegrity
		}
		wire[index] = controlManifestJSONEntry{
			Path:      string(entry.Path),
			Operation: string(entry.Operation),
		}
		switch entry.Operation {
		case ControlFileUpsert:
			if entry.ContentDigest == nil {
				return nil, Digest{}, ErrControlFileStateIntegrity
			}
			encoded := codec.EncodeBase64URL(entry.ContentDigest[:])
			wire[index].ContentDigest = &encoded
		case ControlFileDelete:
			if entry.ContentDigest != nil {
				return nil, Digest{}, ErrControlFileStateIntegrity
			}
		default:
			return nil, Digest{}, ErrControlFileStateIntegrity
		}
		previous = entry.Path
	}
	encoded, err := json.Marshal(wire)
	if err != nil {
		return nil, Digest{}, fmt.Errorf(
			"%w: encode control manifest: %v",
			ErrControlFileStateIntegrity,
			err,
		)
	}
	canonical, err := codec.Canonicalize(encoded)
	if err != nil {
		return nil, Digest{}, fmt.Errorf(
			"%w: canonicalize control manifest: %v",
			ErrControlFileStateIntegrity,
			err,
		)
	}
	preimage := make([]byte, 0, len(controlManifestDomain)+1+len(canonical))
	preimage = append(preimage, controlManifestDomain...)
	preimage = append(preimage, 0)
	preimage = append(preimage, canonical...)
	return canonical, Digest(sha256.Sum256(preimage)), nil
}

func readStoredControlFileApprovals(
	conn *sqlite.Conn,
	sessionID domain.UUIDv7,
) ([]storedControlFileApproval, error) {
	var (
		rows   []storedControlFileApproval
		rowErr error
	)
	err := queryArgs(
		conn,
		controlFileApprovalSelect+`
		  WHERE p.session_id = ?1
		  ORDER BY p.chain_index, p.proposal_event_id;`,
		[]any{string(sessionID)},
		func(stmt *sqlite.Stmt) {
			if rowErr != nil {
				return
			}
			row, err := decodeStoredControlFileApproval(stmt)
			if err != nil {
				rowErr = err
				return
			}
			rows = append(rows, row)
		},
	)
	if err != nil {
		return nil, err
	}
	if rowErr != nil {
		return nil, rowErr
	}
	var invalidApprovalCount int64
	if err := queryOneArgs(
		conn,
		`SELECT count(*)
		   FROM control_file_approvals AS a
		   LEFT JOIN control_file_proposals AS p
		     ON p.proposal_event_id = a.proposal_event_id
		  WHERE a.session_id = ?1
		    AND (p.proposal_event_id IS NULL OR p.session_id <> a.session_id);`,
		[]any{string(sessionID)},
		func(stmt *sqlite.Stmt) {
			if stmt.ColumnType(0) != sqlite.TypeInteger {
				invalidApprovalCount = -1
				return
			}
			invalidApprovalCount = stmt.ColumnInt64(0)
		},
	); err != nil {
		return nil, err
	}
	if invalidApprovalCount != 0 {
		return nil, ErrControlFileStateIntegrity
	}
	return rows, nil
}

func readStoredControlFileApproval(
	conn *sqlite.Conn,
	eventID domain.UUIDv7,
) (storedControlFileApproval, bool, error) {
	var (
		result storedControlFileApproval
		count  int
		rowErr error
	)
	err := queryArgs(
		conn,
		controlFileApprovalSelect+`
		  WHERE p.proposal_event_id = ?1;`,
		[]any{string(eventID)},
		func(stmt *sqlite.Stmt) {
			count++
			if count != 1 {
				return
			}
			result, rowErr = decodeStoredControlFileApproval(stmt)
		},
	)
	if err != nil {
		return storedControlFileApproval{}, false, err
	}
	if rowErr != nil || count > 1 {
		if rowErr != nil {
			return storedControlFileApproval{}, false, rowErr
		}
		return storedControlFileApproval{}, false, ErrControlFileStateIntegrity
	}
	return result, count == 1, nil
}

const controlFileApprovalSelect = `
		SELECT p.proposal_event_id, p.session_id, p.path, p.operation,
		       p.content_digest, p.content_size, p.diff,
		       p.proposed_by_device_id, p.chain_index,
		       a.proposal_event_id, a.session_id, a.path, a.operation,
		       a.content_digest, a.decision, a.content_store_ref,
		       a.manifest_version, a.decided_at
		  FROM control_file_proposals AS p
		  LEFT JOIN control_file_approvals AS a
		    ON a.proposal_event_id = p.proposal_event_id`

func decodeStoredControlFileApproval(
	stmt *sqlite.Stmt,
) (storedControlFileApproval, error) {
	requiredTypes := []sqlite.ColumnType{
		sqlite.TypeText,
		sqlite.TypeText,
		sqlite.TypeText,
		sqlite.TypeText,
		sqlite.TypeNull,
		sqlite.TypeInteger,
		sqlite.TypeText,
		sqlite.TypeText,
		sqlite.TypeInteger,
		sqlite.TypeText,
		sqlite.TypeText,
		sqlite.TypeText,
		sqlite.TypeText,
		sqlite.TypeNull,
		sqlite.TypeText,
	}
	for index, want := range requiredTypes {
		if (index == 4 || index == 13) &&
			stmt.ColumnType(index) == sqlite.TypeBlob {
			continue
		}
		if stmt.ColumnType(index) != want {
			return storedControlFileApproval{}, ErrControlFileStateIntegrity
		}
	}
	if stmt.ColumnType(9) == sqlite.TypeNull {
		return storedControlFileApproval{}, ErrControlFileStateIntegrity
	}
	contentDigest, err := controlFileDigestColumn(stmt, 4)
	if err != nil {
		return storedControlFileApproval{}, err
	}
	contentSize := stmt.ColumnInt64(5)
	chainIndex := stmt.ColumnInt64(8)
	if contentSize < 0 || chainIndex < 1 {
		return storedControlFileApproval{}, ErrControlFileStateIntegrity
	}
	proposal := ControlFileProposalRow{
		ProposalEventID:    domain.UUIDv7(stmt.ColumnText(0)),
		SessionID:          domain.UUIDv7(stmt.ColumnText(1)),
		Path:               domain.RepositoryPath(stmt.ColumnText(2)),
		Operation:          ControlFileOperation(stmt.ColumnText(3)),
		ContentDigest:      contentDigest,
		ContentSize:        uint64(contentSize),
		Diff:               stmt.ColumnText(6),
		ProposedByDeviceID: domain.DeviceID(stmt.ColumnText(7)),
		ChainIndex:         uint64(chainIndex),
	}
	if err := proposal.Validate(); err != nil {
		return storedControlFileApproval{}, ErrControlFileStateIntegrity
	}
	approvalDigest, err := controlFileDigestColumn(stmt, 13)
	if err != nil {
		return storedControlFileApproval{}, err
	}
	if stmt.ColumnText(9) != string(proposal.ProposalEventID) ||
		stmt.ColumnText(10) != string(proposal.SessionID) ||
		stmt.ColumnText(11) != string(proposal.Path) ||
		stmt.ColumnText(12) != string(proposal.Operation) ||
		!controlFileDigestPointersEqual(approvalDigest, proposal.ContentDigest) {
		return storedControlFileApproval{}, ErrControlFileStateIntegrity
	}
	result := storedControlFileApproval{
		proposal: proposal,
		decision: ControlFileDecision(stmt.ColumnText(14)),
	}
	if !result.decision.valid() {
		return storedControlFileApproval{}, ErrControlFileStateIntegrity
	}
	switch result.decision {
	case ControlFilePending:
		if stmt.ColumnType(15) != sqlite.TypeNull ||
			stmt.ColumnType(16) != sqlite.TypeNull ||
			stmt.ColumnType(17) != sqlite.TypeNull {
			return storedControlFileApproval{}, ErrControlFileStateIntegrity
		}
	case ControlFileApproved:
		if stmt.ColumnType(15) != sqlite.TypeText ||
			stmt.ColumnType(16) != sqlite.TypeInteger ||
			stmt.ColumnType(17) != sqlite.TypeText {
			return storedControlFileApproval{}, ErrControlFileStateIntegrity
		}
		result.contentStoreRef = ControlFileContentRef(stmt.ColumnText(15))
		version := stmt.ColumnInt64(16)
		result.decidedAt = domain.Timestamp(stmt.ColumnText(17))
		if !result.contentStoreRef.Valid() ||
			version < 1 ||
			!domain.ValidUnsignedInteger(uint64(version)) ||
			!result.decidedAt.Valid() {
			return storedControlFileApproval{}, ErrControlFileStateIntegrity
		}
		result.manifestVersion = uint64(version)
	case ControlFileDeclined:
		if stmt.ColumnType(15) != sqlite.TypeNull ||
			stmt.ColumnType(16) != sqlite.TypeNull ||
			stmt.ColumnType(17) != sqlite.TypeText {
			return storedControlFileApproval{}, ErrControlFileStateIntegrity
		}
		result.decidedAt = domain.Timestamp(stmt.ColumnText(17))
		if !result.decidedAt.Valid() {
			return storedControlFileApproval{}, ErrControlFileStateIntegrity
		}
	default:
		return storedControlFileApproval{}, ErrControlFileStateIntegrity
	}
	return result, nil
}

func controlFileDigestColumn(
	stmt *sqlite.Stmt,
	column int,
) (*[sha256.Size]byte, error) {
	if stmt.ColumnType(column) == sqlite.TypeNull {
		return nil, nil
	}
	if stmt.ColumnType(column) != sqlite.TypeBlob {
		return nil, ErrControlFileStateIntegrity
	}
	value := columnBytes(stmt, column)
	if len(value) != sha256.Size {
		return nil, ErrControlFileStateIntegrity
	}
	var digest [sha256.Size]byte
	copy(digest[:], value)
	return &digest, nil
}

func requireOneChangedRow(conn *sqlite.Conn) error {
	var changes int64
	if err := queryOne(
		conn,
		"SELECT changes();",
		func(stmt *sqlite.Stmt) {
			if stmt.ColumnType(0) != sqlite.TypeInteger {
				changes = -1
				return
			}
			changes = stmt.ColumnInt64(0)
		},
	); err != nil {
		return err
	}
	if changes != 1 {
		return ErrControlFileStateIntegrity
	}
	return nil
}

func findStoredControlFileApproval(
	rows []storedControlFileApproval,
	eventID domain.UUIDv7,
) (storedControlFileApproval, bool) {
	for _, row := range rows {
		if row.proposal.ProposalEventID == eventID {
			return row, true
		}
	}
	return storedControlFileApproval{}, false
}

func isLatestControlFileProposal(
	rows []storedControlFileApproval,
	target ControlFileProposalRow,
) bool {
	for _, row := range rows {
		if row.proposal.Path == target.Path &&
			row.proposal.ChainIndex > target.ChainIndex {
			return false
		}
	}
	return true
}

func controlFileProposalReferenceMatches(
	proposal ControlFileProposalRow,
	sessionID domain.UUIDv7,
	reference ControlFileProposalReference,
) bool {
	return proposal.SessionID == sessionID &&
		proposal.ProposalEventID == reference.ProposalEventID &&
		proposal.Path == reference.Path &&
		proposal.Operation == reference.Operation &&
		controlFileDigestPointersEqual(
			proposal.ContentDigest,
			reference.ContentDigest,
		) &&
		proposal.ChainIndex == reference.ChainIndex
}

func controlFileProposalsEqual(
	left, right ControlFileProposalRow,
) bool {
	return left.ProposalEventID == right.ProposalEventID &&
		left.SessionID == right.SessionID &&
		left.Path == right.Path &&
		left.Operation == right.Operation &&
		controlFileDigestPointersEqual(
			left.ContentDigest,
			right.ContentDigest,
		) &&
		left.ContentSize == right.ContentSize &&
		left.Diff == right.Diff &&
		left.ProposedByDeviceID == right.ProposedByDeviceID &&
		left.ChainIndex == right.ChainIndex
}

func controlFileProposalsHaveSameManifestEntry(
	left, right ControlFileProposalRow,
) bool {
	return left.Path == right.Path &&
		left.Operation == right.Operation &&
		controlFileDigestPointersEqual(
			left.ContentDigest,
			right.ContentDigest,
		)
}

func controlFileDigestPointersEqual(
	left, right *[sha256.Size]byte,
) bool {
	if left == nil || right == nil {
		return left == nil && right == nil
	}
	return *left == *right
}

func manifestEntryFromProposal(
	proposal ControlFileProposalRow,
) ControlManifestEntry {
	entry := ControlManifestEntry{
		Path:      proposal.Path,
		Operation: proposal.Operation,
	}
	if proposal.ContentDigest != nil {
		digest := Digest(*proposal.ContentDigest)
		entry.ContentDigest = &digest
	}
	return entry
}

func controlManifestEntryForPath(
	entries []ControlManifestEntry,
	path domain.RepositoryPath,
) (ControlManifestEntry, bool) {
	index := sort.Search(len(entries), func(index int) bool {
		return string(entries[index].Path) >= string(path)
	})
	if index >= len(entries) || entries[index].Path != path {
		return ControlManifestEntry{}, false
	}
	return entries[index], true
}

func replaceControlManifestEntry(
	entries []ControlManifestEntry,
	replacement ControlManifestEntry,
) []ControlManifestEntry {
	result := cloneControlManifestEntries(entries)
	index := sort.Search(len(result), func(index int) bool {
		return string(result[index].Path) >= string(replacement.Path)
	})
	if index < len(result) && result[index].Path == replacement.Path {
		result[index] = cloneControlManifestEntry(replacement)
		return result
	}
	result = append(result, ControlManifestEntry{})
	copy(result[index+1:], result[index:])
	result[index] = cloneControlManifestEntry(replacement)
	return result
}

func controlManifestEntriesEqual(
	left, right []ControlManifestEntry,
) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if !controlManifestEntryEqual(left[index], right[index]) {
			return false
		}
	}
	return true
}

func controlManifestEntryEqual(
	left, right ControlManifestEntry,
) bool {
	if left.Path != right.Path || left.Operation != right.Operation {
		return false
	}
	if left.ContentDigest == nil || right.ContentDigest == nil {
		return left.ContentDigest == nil && right.ContentDigest == nil
	}
	return *left.ContentDigest == *right.ContentDigest
}

func cloneControlManifest(manifest ControlManifest) ControlManifest {
	manifest.Entries = cloneControlManifestEntries(manifest.Entries)
	return manifest
}

func cloneControlManifestEntries(
	entries []ControlManifestEntry,
) []ControlManifestEntry {
	result := make([]ControlManifestEntry, len(entries))
	for index, entry := range entries {
		result[index] = cloneControlManifestEntry(entry)
	}
	return result
}

func cloneControlManifestEntry(
	entry ControlManifestEntry,
) ControlManifestEntry {
	result := entry
	if entry.ContentDigest != nil {
		digest := *entry.ContentDigest
		result.ContentDigest = &digest
	}
	return result
}

func (row storedControlFileApproval) decisionRecord() ControlFileDecisionRecord {
	result := ControlFileDecisionRecord{
		ProposalEventID: row.proposal.ProposalEventID,
		SessionID:       row.proposal.SessionID,
		Path:            row.proposal.Path,
		Operation:       row.proposal.Operation,
		ChainIndex:      row.proposal.ChainIndex,
		Decision:        row.decision,
		ContentStoreRef: row.contentStoreRef,
		ManifestVersion: row.manifestVersion,
		DecidedAt:       row.decidedAt,
	}
	if row.proposal.ContentDigest != nil {
		digest := *row.proposal.ContentDigest
		result.ContentDigest = &digest
	}
	return result
}
