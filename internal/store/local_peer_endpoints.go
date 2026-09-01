package store

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"sort"
	"time"

	"github.com/ijonahch/codecomm/internal/codec"
	codecommcrypto "github.com/ijonahch/codecomm/internal/crypto"
	"github.com/ijonahch/codecomm/internal/domain"
	"github.com/ijonahch/codecomm/internal/domain/device"
	"github.com/ijonahch/codecomm/internal/domain/policy"
	"zombiezen.com/go/sqlite"
)

const (
	PeerEndpointHintsPerMemberMax  = 16
	PeerEndpointHintsPerSessionMax = 128
	ManualEndpointsPerMemberMax    = 16
	ManualEndpointsPerSessionMax   = 128
	SignedEndpointSetMaxBytes      = 16 << 10

	peerEndpointSetSchemaVersion = 1
	peerEndpointHintTTLIntervals = 8
	peerEndpointGuessTTL         = 7 * 24 * time.Hour
	peerEndpointClockSkew        = 120 * time.Second
	rawDiscoveryEndpointMaxTTL   = 60 * time.Second

	// own_signed is a sequence-counter row, not a dial candidate. A literal
	// TEST-NET address keeps the required host column non-DNS and structurally
	// valid while remaining distinguishable from every published endpoint set.
	ownEndpointSequenceHost = "192.0.2.1"
	ownEndpointSequencePort = uint16(1)
)

var (
	ErrInvalidPeerEndpoint = errors.New(
		"store: invalid local peer endpoint",
	)
	ErrInvalidPeerEndpointSet = errors.New(
		"store: invalid signed peer endpoint set",
	)
	ErrPeerEndpointSequenceRollback = errors.New(
		"store: peer endpoint sequence rollback",
	)
	ErrPeerEndpointSequenceConflict = errors.New(
		"store: peer endpoint sequence reused with different bytes",
	)
	ErrPeerEndpointCapacity = errors.New(
		"store: local peer endpoint capacity exceeded",
	)
	ErrPeerEndpointIntegrity = errors.New(
		"store: local peer endpoint integrity failure",
	)
)

// PeerEndpointSourceKind is the closed set of durable local endpoint sources.
type PeerEndpointSourceKind string

const (
	PeerEndpointOwnSigned          PeerEndpointSourceKind = "own_signed"
	PeerEndpointMemberSigned       PeerEndpointSourceKind = "member_signed"
	PeerEndpointRawDiscovery       PeerEndpointSourceKind = "raw_discovery"
	PeerEndpointAuthenticatedGuess PeerEndpointSourceKind = "authenticated_guess"
	PeerEndpointManual             PeerEndpointSourceKind = "manual"
)

var peerEndpointSourceKinds = [...]PeerEndpointSourceKind{
	PeerEndpointOwnSigned,
	PeerEndpointMemberSigned,
	PeerEndpointRawDiscovery,
	PeerEndpointAuthenticatedGuess,
	PeerEndpointManual,
}

// Valid reports whether kind is a defined V1 endpoint source.
func (kind PeerEndpointSourceKind) Valid() bool {
	switch kind {
	case PeerEndpointOwnSigned,
		PeerEndpointMemberSigned,
		PeerEndpointRawDiscovery,
		PeerEndpointAuthenticatedGuess,
		PeerEndpointManual:
		return true
	default:
		return false
	}
}

// PeerEndpointSourceKinds returns every source kind in stable wire order.
func PeerEndpointSourceKinds() []PeerEndpointSourceKind {
	result := make([]PeerEndpointSourceKind, len(peerEndpointSourceKinds))
	copy(result, peerEndpointSourceKinds[:])
	return result
}

// PeerEndpointRecord is one validated local-only peer_endpoints row.
// EndpointSetJSON is an exact signed JCS object only for a current
// member_signed row. A stale signed-set address has neither JSON nor sequence.
type PeerEndpointRecord struct {
	DeviceID         domain.DeviceID
	SourceKind       PeerEndpointSourceKind
	Endpoint         netip.AddrPort
	EndpointSequence uint64
	EndpointSetJSON  []byte
	ObservedAt       domain.Timestamp
	ExpiresAt        domain.Timestamp
}

// Validate verifies all source-specific persisted invariants.
func (record PeerEndpointRecord) Validate() error {
	return validatePeerEndpointRecord(record)
}

// MemberEndpointSetUpdate reports the effect of a signed-set replacement.
type MemberEndpointSetUpdate uint8

const (
	MemberEndpointSetStored MemberEndpointSetUpdate = iota + 1
	MemberEndpointSetReplaced
	MemberEndpointSetIdempotent
)

type storedPeerEndpoint struct {
	id     int64
	record PeerEndpointRecord
}

type peerEndpointKey struct {
	deviceID   domain.DeviceID
	sourceKind PeerEndpointSourceKind
	endpoint   netip.AddrPort
}

type parsedPeerEndpointSet struct {
	sessionID          domain.UUIDv7
	workspaceID        domain.UUIDv4
	recoveryGeneration uint64
	deviceID           domain.DeviceID
	sequence           uint64
	issuedAt           domain.WholeSecondTimestamp
	expiresAt          domain.WholeSecondTimestamp
	endpoints          []netip.AddrPort
	canonical          []byte
	unsigned           []byte
	signature          []byte
}

type peerEndpointSetWire struct {
	SchemaVersion      uint64             `json:"schema_version"`
	SessionID          string             `json:"session_id"`
	WorkspaceID        string             `json:"workspace_id"`
	RecoveryGeneration uint64             `json:"recovery_generation"`
	DeviceID           string             `json:"device_id"`
	EndpointSequence   uint64             `json:"endpoint_sequence"`
	IssuedAt           string             `json:"issued_at"`
	ExpiresAt          string             `json:"expires_at"`
	Endpoints          []peerEndpointWire `json:"endpoints"`
	Signature          string             `json:"signature"`
}

type peerEndpointWire struct {
	IP   string `json:"ip"`
	Port uint16 `json:"port"`
}

// AllocateOwnEndpointSequence atomically returns and persists
// max(previous+1, now.UnixMilli()). The counter is durable before callers sign
// or publish an endpoint set.
func (state LocalState) AllocateOwnEndpointSequence(
	ctx context.Context,
	localDeviceID domain.DeviceID,
	now domain.Timestamp,
) (uint64, error) {
	if !localDeviceID.Valid() {
		return 0, ErrInvalidPeerEndpoint
	}
	nowTime, err := peerEndpointTime(now)
	if err != nil || nowTime.Before(time.Unix(0, 0)) {
		return 0, ErrInvalidPeerEndpoint
	}
	milliseconds := nowTime.UnixMilli()
	if milliseconds < 0 ||
		uint64(milliseconds) > domain.MaxSafeInteger {
		return 0, ErrInvalidPeerEndpoint
	}

	var next uint64
	err = state.withImmediate(ctx, func(conn *sqlite.Conn) error {
		member, found, err := readStatusMember(conn, localDeviceID)
		if err != nil {
			return err
		}
		if !found || member.Status != device.StatusActive {
			return ErrInvalidPeerEndpoint
		}

		rows, err := readPeerEndpointRowsForSource(
			conn,
			localDeviceID,
			PeerEndpointOwnSigned,
		)
		if err != nil {
			return err
		}
		var previous uint64
		switch len(rows) {
		case 0:
		case 1:
			previous = rows[0].record.EndpointSequence
		default:
			return ErrPeerEndpointIntegrity
		}
		if previous >= domain.MaxSafeInteger {
			return ErrPeerEndpointSequenceRollback
		}
		next = previous + 1
		if current := uint64(milliseconds); current > next {
			next = current
		}
		if next < 1 || !domain.ValidUnsignedInteger(next) {
			return ErrPeerEndpointSequenceRollback
		}

		record := PeerEndpointRecord{
			DeviceID:         localDeviceID,
			SourceKind:       PeerEndpointOwnSigned,
			Endpoint:         ownEndpointSequence(),
			EndpointSequence: next,
			ObservedAt:       now,
		}
		if err := record.Validate(); err != nil {
			return err
		}
		return upsertPeerEndpointRow(conn, record)
	})
	if err != nil {
		return 0, err
	}
	return next, nil
}

// ReplaceMemberSignedEndpointSet authenticates and atomically retains one
// active member's exact signed JCS endpoint set. The current set's addresses
// remain local guesses for seven days after their latest observation.
func (state LocalState) ReplaceMemberSignedEndpointSet(
	ctx context.Context,
	canonicalJSON []byte,
	observedAt domain.Timestamp,
) (MemberEndpointSetUpdate, error) {
	observedTime, err := peerEndpointTime(observedAt)
	if err != nil {
		return 0, ErrInvalidPeerEndpointSet
	}
	parsed, err := parsePeerEndpointSet(canonicalJSON)
	if err != nil {
		return 0, err
	}

	var update MemberEndpointSetUpdate
	err = state.withImmediate(ctx, func(conn *sqlite.Conn) error {
		lineage, err := readLocalLineage(conn)
		if err != nil {
			return err
		}
		if parsed.sessionID != lineage.sessionID ||
			parsed.workspaceID != lineage.workspaceID ||
			parsed.recoveryGeneration != lineage.recoveryGeneration {
			return fmt.Errorf(
				"%w: signed set lineage does not match the active generation",
				ErrInvalidPeerEndpointSet,
			)
		}
		member, found, err := readStatusMember(conn, parsed.deviceID)
		if err != nil {
			return err
		}
		if !found || member.Status != device.StatusActive {
			return fmt.Errorf(
				"%w: signer is not an active member",
				ErrInvalidPeerEndpointSet,
			)
		}
		if err := codecommcrypto.VerifyEd25519(
			member.IdentityPublicKey,
			codec.SignatureEndpointHints,
			parsed.unsigned,
			parsed.signature,
		); err != nil {
			return fmt.Errorf(
				"%w: verify identity signature: %v",
				ErrInvalidPeerEndpointSet,
				err,
			)
		}
		values, err := readPeerEndpointPolicy(conn, lineage.sessionID)
		if err != nil {
			return err
		}
		if err := validatePeerEndpointSetTimes(
			parsed,
			observedTime,
			time.Duration(values.AdvertisementIntervalSeconds)*time.Second,
		); err != nil {
			return err
		}
		if _, err := expireStalePeerEndpointRows(conn, observedTime); err != nil {
			return err
		}

		existing, err := readPeerEndpointRowsForSource(
			conn,
			parsed.deviceID,
			PeerEndpointMemberSigned,
		)
		if err != nil {
			return err
		}
		current, currentFound, err := currentMemberEndpointSet(existing)
		if err != nil {
			return err
		}
		if currentFound {
			switch {
			case parsed.sequence < current.sequence:
				return ErrPeerEndpointSequenceRollback
			case parsed.sequence == current.sequence &&
				!bytes.Equal(parsed.canonical, current.canonical):
				return ErrPeerEndpointSequenceConflict
			case parsed.sequence == current.sequence:
				if err := refreshMemberEndpointRows(
					conn,
					parsed.deviceID,
					observedAt,
				); err != nil {
					return err
				}
				update = MemberEndpointSetIdempotent
				return nil
			}
			update = MemberEndpointSetReplaced
		} else {
			update = MemberEndpointSetStored
		}

		if err := execute(
			conn,
			`DELETE FROM peer_endpoints
			  WHERE device_id = ?1 AND source_kind = 'member_signed';`,
			string(parsed.deviceID),
		); err != nil {
			return err
		}
		guessExpiry, err := peerEndpointGuessExpiry(observedAt)
		if err != nil {
			return err
		}
		for _, endpoint := range parsed.endpoints {
			record := PeerEndpointRecord{
				DeviceID:         parsed.deviceID,
				SourceKind:       PeerEndpointMemberSigned,
				Endpoint:         endpoint,
				EndpointSequence: parsed.sequence,
				EndpointSetJSON:  bytes.Clone(parsed.canonical),
				ObservedAt:       observedAt,
				ExpiresAt:        guessExpiry,
			}
			if err := record.Validate(); err != nil {
				return err
			}
			if err := insertPeerEndpointRow(conn, record); err != nil {
				return err
			}
		}
		return enforcePeerEndpointCaps(conn, nil)
	})
	if err != nil {
		return 0, err
	}
	return update, nil
}

// UpsertRawDiscoveryEndpoint retains a verified datagram source only through
// its whole-second datagram expiry.
func (state LocalState) UpsertRawDiscoveryEndpoint(
	ctx context.Context,
	deviceID domain.DeviceID,
	endpoint netip.AddrPort,
	observedAt domain.Timestamp,
	expiresAt domain.WholeSecondTimestamp,
) error {
	record := PeerEndpointRecord{
		DeviceID:   deviceID,
		SourceKind: PeerEndpointRawDiscovery,
		Endpoint:   endpoint,
		ObservedAt: observedAt,
		ExpiresAt:  domain.Timestamp(expiresAt),
	}
	return state.upsertPeerEndpointCandidate(ctx, record, true)
}

// UpsertAuthenticatedEndpoint retains an exact successful expected-member
// dial destination for seven days after the handshake.
func (state LocalState) UpsertAuthenticatedEndpoint(
	ctx context.Context,
	deviceID domain.DeviceID,
	endpoint netip.AddrPort,
	observedAt domain.Timestamp,
) error {
	expiresAt, err := peerEndpointGuessExpiry(observedAt)
	if err != nil {
		return err
	}
	record := PeerEndpointRecord{
		DeviceID:   deviceID,
		SourceKind: PeerEndpointAuthenticatedGuess,
		Endpoint:   endpoint,
		ObservedAt: observedAt,
		ExpiresAt:  expiresAt,
	}
	return state.upsertPeerEndpointCandidate(ctx, record, true)
}

// UpsertManualEndpoint retains an operator-configured endpoint without an
// expiry. Capacity exhaustion refuses the addition and preserves all rows.
func (state LocalState) UpsertManualEndpoint(
	ctx context.Context,
	deviceID domain.DeviceID,
	endpoint netip.AddrPort,
	observedAt domain.Timestamp,
) error {
	record := PeerEndpointRecord{
		DeviceID:   deviceID,
		SourceKind: PeerEndpointManual,
		Endpoint:   endpoint,
		ObservedAt: observedAt,
	}
	return state.upsertPeerEndpointCandidate(ctx, record, false)
}

// ListManualEndpoints returns every operator-configured endpoint ordered by
// device ID and canonical endpoint address.
func (state LocalState) ListManualEndpoints(
	ctx context.Context,
) ([]PeerEndpointRecord, error) {
	var result []PeerEndpointRecord
	err := state.withImmediate(ctx, func(conn *sqlite.Conn) error {
		rows, err := readAllPeerEndpointRows(conn)
		if err != nil {
			return err
		}
		if err := validatePeerEndpointRowCaps(rows); err != nil {
			return err
		}
		for _, row := range rows {
			if row.record.SourceKind != PeerEndpointManual {
				continue
			}
			result = append(
				result,
				clonePeerEndpointRecord(row.record),
			)
		}
		sort.Slice(result, func(left, right int) bool {
			if result[left].DeviceID != result[right].DeviceID {
				return result[left].DeviceID < result[right].DeviceID
			}
			return comparePeerEndpoints(
				result[left].Endpoint,
				result[right].Endpoint,
			) < 0
		})
		return nil
	})
	if err != nil {
		return nil, err
	}
	return result, nil
}

// RemoveManualEndpoint removes exactly one operator-configured endpoint.
// The boolean reports whether a matching row existed; a miss is idempotent.
func (state LocalState) RemoveManualEndpoint(
	ctx context.Context,
	deviceID domain.DeviceID,
	endpoint netip.AddrPort,
) (bool, error) {
	if !deviceID.Valid() ||
		validatePeerEndpointAddress(endpoint, true) != nil {
		return false, ErrInvalidPeerEndpoint
	}

	removed := false
	err := state.withImmediate(ctx, func(conn *sqlite.Conn) error {
		rows, err := readAllPeerEndpointRows(conn)
		if err != nil {
			return err
		}
		if err := validatePeerEndpointRowCaps(rows); err != nil {
			return err
		}
		found := false
		for _, row := range rows {
			if row.record.DeviceID == deviceID &&
				row.record.SourceKind == PeerEndpointManual &&
				row.record.Endpoint == endpoint {
				found = true
				break
			}
		}
		if !found {
			return nil
		}
		if err := execute(
			conn,
			`DELETE FROM peer_endpoints
			  WHERE device_id = ?1
			    AND source_kind = 'manual'
			    AND transport = 'tcp'
			    AND host = ?2
			    AND port = ?3;`,
			string(deviceID),
			endpoint.Addr().String(),
			uint64(endpoint.Port()),
		); err != nil {
			return err
		}
		var changed int64
		if err := queryOne(
			conn,
			"SELECT changes();",
			func(stmt *sqlite.Stmt) {
				if stmt.ColumnType(0) != sqlite.TypeInteger {
					changed = -1
					return
				}
				changed = stmt.ColumnInt64(0)
			},
		); err != nil {
			return err
		}
		if changed != 1 {
			return ErrPeerEndpointIntegrity
		}
		removed = true
		return nil
	})
	if err != nil {
		return false, err
	}
	return removed, nil
}

func (state LocalState) upsertPeerEndpointCandidate(
	ctx context.Context,
	record PeerEndpointRecord,
	requireActiveMember bool,
) error {
	if record.SourceKind != PeerEndpointRawDiscovery &&
		record.SourceKind != PeerEndpointAuthenticatedGuess &&
		record.SourceKind != PeerEndpointManual {
		return ErrInvalidPeerEndpoint
	}
	if err := record.Validate(); err != nil {
		return err
	}
	observedTime, _ := record.ObservedAt.Time()
	return state.withImmediate(ctx, func(conn *sqlite.Conn) error {
		if requireActiveMember {
			member, found, err := readStatusMember(conn, record.DeviceID)
			if err != nil {
				return err
			}
			if !found || member.Status != device.StatusActive {
				return ErrInvalidPeerEndpoint
			}
		}
		if _, err := expireStalePeerEndpointRows(conn, observedTime); err != nil {
			return err
		}

		key := peerEndpointRecordKey(record)
		exists, err := peerEndpointRowExists(conn, key)
		if err != nil {
			return err
		}
		if record.SourceKind == PeerEndpointManual && !exists {
			if err := checkManualEndpointCapacity(
				conn,
				record.DeviceID,
			); err != nil {
				return err
			}
		}
		if err := upsertPeerEndpointRow(conn, record); err != nil {
			return err
		}
		if record.SourceKind == PeerEndpointManual {
			return validatePeerEndpointCaps(conn)
		}
		if err := enforcePeerEndpointCaps(conn, &key); err != nil {
			return err
		}
		retained, err := peerEndpointRowExists(conn, key)
		if err != nil {
			return err
		}
		if !retained {
			return ErrPeerEndpointCapacity
		}
		return nil
	})
}

// ListPeerEndpointCandidates returns one unexpired row per canonical endpoint,
// preferring member-signed, raw-discovery, authenticated, then manual sources.
func (state LocalState) ListPeerEndpointCandidates(
	ctx context.Context,
	deviceID domain.DeviceID,
	now domain.Timestamp,
) ([]PeerEndpointRecord, error) {
	if !deviceID.Valid() {
		return nil, ErrInvalidPeerEndpoint
	}
	nowTime, err := peerEndpointTime(now)
	if err != nil {
		return nil, ErrInvalidPeerEndpoint
	}
	var result []PeerEndpointRecord
	err = state.withImmediate(ctx, func(conn *sqlite.Conn) error {
		if _, err := expireStalePeerEndpointRows(conn, nowTime); err != nil {
			return err
		}
		if err := validatePeerEndpointCaps(conn); err != nil {
			return err
		}
		rows, err := readPeerEndpointRowsForDevice(conn, deviceID)
		if err != nil {
			return err
		}
		candidates := make([]PeerEndpointRecord, 0, len(rows))
		for _, row := range rows {
			if row.record.SourceKind == PeerEndpointOwnSigned {
				continue
			}
			candidates = append(
				candidates,
				clonePeerEndpointRecord(row.record),
			)
		}
		sort.Slice(candidates, func(left, right int) bool {
			leftPriority := peerEndpointSourcePriority(
				candidates[left].SourceKind,
			)
			rightPriority := peerEndpointSourcePriority(
				candidates[right].SourceKind,
			)
			if leftPriority != rightPriority {
				return leftPriority < rightPriority
			}
			return comparePeerEndpoints(
				candidates[left].Endpoint,
				candidates[right].Endpoint,
			) < 0
		})
		seen := make(map[netip.AddrPort]struct{}, len(candidates))
		for _, candidate := range candidates {
			if _, duplicate := seen[candidate.Endpoint]; duplicate {
				continue
			}
			seen[candidate.Endpoint] = struct{}{}
			result = append(result, candidate)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return result, nil
}

// PurgePeerEndpoints removes all non-own endpoint state for one device.
func (state LocalState) PurgePeerEndpoints(
	ctx context.Context,
	deviceID domain.DeviceID,
) error {
	if !deviceID.Valid() {
		return ErrInvalidPeerEndpoint
	}
	return state.withImmediate(ctx, func(conn *sqlite.Conn) error {
		return execute(
			conn,
			`DELETE FROM peer_endpoints
			  WHERE device_id = ?1 AND source_kind <> 'own_signed';`,
			string(deviceID),
		)
	})
}

// PurgePeerLearnedEndpoints removes a member's signed endpoint set and every
// nonmanual dial guess while preserving explicit operator configuration.
func (state LocalState) PurgePeerLearnedEndpoints(
	ctx context.Context,
	deviceID domain.DeviceID,
) error {
	if !deviceID.Valid() {
		return ErrInvalidPeerEndpoint
	}
	return state.withImmediate(ctx, func(conn *sqlite.Conn) error {
		return execute(
			conn,
			`DELETE FROM peer_endpoints
			  WHERE device_id = ?1
			    AND source_kind IN (
			        'member_signed', 'raw_discovery', 'authenticated_guess'
			    );`,
			string(deviceID),
		)
	})
}

// ExpireStalePeerEndpoints removes expired nonmanual rows and strips expired
// signed objects/high-water marks while retaining their seven-day dial guesses.
func (state LocalState) ExpireStalePeerEndpoints(
	ctx context.Context,
	now domain.Timestamp,
) (int, error) {
	nowTime, err := peerEndpointTime(now)
	if err != nil {
		return 0, ErrInvalidPeerEndpoint
	}
	var affected int
	err = state.withImmediate(ctx, func(conn *sqlite.Conn) error {
		var err error
		affected, err = expireStalePeerEndpointRows(conn, nowTime)
		return err
	})
	if err != nil {
		return 0, err
	}
	return affected, nil
}

func validatePeerEndpointRecord(record PeerEndpointRecord) error {
	if !record.DeviceID.Valid() ||
		!record.SourceKind.Valid() ||
		!record.Endpoint.IsValid() ||
		record.Endpoint.Port() == 0 {
		return ErrInvalidPeerEndpoint
	}
	observedTime, err := peerEndpointTime(record.ObservedAt)
	if err != nil {
		return ErrInvalidPeerEndpoint
	}

	switch record.SourceKind {
	case PeerEndpointOwnSigned:
		if record.Endpoint != ownEndpointSequence() ||
			record.EndpointSequence < 1 ||
			!domain.ValidUnsignedInteger(record.EndpointSequence) ||
			len(record.EndpointSetJSON) != 0 ||
			record.ExpiresAt != "" {
			return ErrInvalidPeerEndpoint
		}
		return nil

	case PeerEndpointMemberSigned:
		if err := validatePeerEndpointAddress(record.Endpoint, false); err != nil {
			return err
		}
		expiryTime, err := peerEndpointTime(record.ExpiresAt)
		if err != nil ||
			!expiryTime.After(observedTime) ||
			expiryTime.Sub(observedTime) != peerEndpointGuessTTL {
			return ErrInvalidPeerEndpoint
		}
		if len(record.EndpointSetJSON) == 0 {
			if record.EndpointSequence != 0 {
				return ErrInvalidPeerEndpoint
			}
			return nil
		}
		parsed, err := parsePeerEndpointSet(record.EndpointSetJSON)
		if err != nil {
			return err
		}
		if record.EndpointSequence != parsed.sequence ||
			record.DeviceID != parsed.deviceID ||
			!peerEndpointSetContains(parsed, record.Endpoint) {
			return ErrInvalidPeerEndpoint
		}
		return nil

	case PeerEndpointRawDiscovery:
		if record.EndpointSequence != 0 ||
			len(record.EndpointSetJSON) != 0 {
			return ErrInvalidPeerEndpoint
		}
		if err := validatePeerEndpointAddress(record.Endpoint, true); err != nil {
			return err
		}
		expiryTime, err := peerEndpointTime(record.ExpiresAt)
		if err != nil ||
			!expiryTime.After(observedTime) ||
			expiryTime.Sub(observedTime) > rawDiscoveryEndpointMaxTTL {
			return ErrInvalidPeerEndpoint
		}
		if !domain.WholeSecondTimestamp(record.ExpiresAt).Valid() {
			return ErrInvalidPeerEndpoint
		}
		return nil

	case PeerEndpointAuthenticatedGuess:
		if record.EndpointSequence != 0 ||
			len(record.EndpointSetJSON) != 0 {
			return ErrInvalidPeerEndpoint
		}
		if err := validatePeerEndpointAddress(record.Endpoint, true); err != nil {
			return err
		}
		expiryTime, err := peerEndpointTime(record.ExpiresAt)
		if err != nil ||
			!expiryTime.After(observedTime) ||
			expiryTime.Sub(observedTime) != peerEndpointGuessTTL {
			return ErrInvalidPeerEndpoint
		}
		return nil

	case PeerEndpointManual:
		if record.EndpointSequence != 0 ||
			len(record.EndpointSetJSON) != 0 ||
			record.ExpiresAt != "" {
			return ErrInvalidPeerEndpoint
		}
		return validatePeerEndpointAddress(record.Endpoint, true)

	default:
		return ErrInvalidPeerEndpoint
	}
}

func validatePeerEndpointAddress(
	endpoint netip.AddrPort,
	allowIPv6LinkLocal bool,
) error {
	if !endpoint.IsValid() || endpoint.Port() == 0 {
		return ErrInvalidPeerEndpoint
	}
	address := endpoint.Addr()
	if !address.IsValid() ||
		address.Is4In6() ||
		address.IsLoopback() ||
		address.IsUnspecified() ||
		address.IsMulticast() ||
		!(address.IsGlobalUnicast() || address.IsLinkLocalUnicast()) {
		return ErrInvalidPeerEndpoint
	}
	if address.Is4() {
		if address.Zone() != "" ||
			address.As4() == [4]byte{255, 255, 255, 255} {
			return ErrInvalidPeerEndpoint
		}
		return nil
	}
	if address.IsLinkLocalUnicast() {
		if !allowIPv6LinkLocal || !validPeerEndpointZone(address.Zone()) {
			return ErrInvalidPeerEndpoint
		}
		return nil
	}
	if address.Zone() != "" {
		return ErrInvalidPeerEndpoint
	}
	return nil
}

func validPeerEndpointZone(zone string) bool {
	if len(zone) < 1 || len(zone) > 64 {
		return false
	}
	for index := 0; index < len(zone); index++ {
		character := zone[index]
		if character >= 'a' && character <= 'z' ||
			character >= 'A' && character <= 'Z' ||
			character >= '0' && character <= '9' ||
			character == '.' ||
			character == '_' ||
			character == '-' {
			continue
		}
		return false
	}
	return true
}

func parsePeerEndpointSet(input []byte) (parsedPeerEndpointSet, error) {
	if len(input) == 0 || len(input) > SignedEndpointSetMaxBytes {
		return parsedPeerEndpointSet{}, ErrInvalidPeerEndpointSet
	}
	canonical, err := codec.CanonicalizeSignedObject(input)
	if err != nil || !bytes.Equal(input, canonical) {
		return parsedPeerEndpointSet{}, fmt.Errorf(
			"%w: noncanonical JSON",
			ErrInvalidPeerEndpointSet,
		)
	}
	unsigned, encodedSignature, err := codec.RemoveCanonicalObjectMember(
		canonical,
		"signature",
	)
	if err != nil {
		return parsedPeerEndpointSet{}, fmt.Errorf(
			"%w: signature member: %v",
			ErrInvalidPeerEndpointSet,
			err,
		)
	}
	var wire peerEndpointSetWire
	if err := decodeClosedPeerEndpointJSON(canonical, &wire); err != nil {
		return parsedPeerEndpointSet{}, fmt.Errorf(
			"%w: decode object: %v",
			ErrInvalidPeerEndpointSet,
			err,
		)
	}
	var signatureText string
	if err := json.Unmarshal(encodedSignature, &signatureText); err != nil ||
		signatureText != wire.Signature {
		return parsedPeerEndpointSet{}, fmt.Errorf(
			"%w: signature member",
			ErrInvalidPeerEndpointSet,
		)
	}
	signature, err := codec.DecodeBase64URLExact(
		signatureText,
		64,
	)
	if err != nil {
		return parsedPeerEndpointSet{}, fmt.Errorf(
			"%w: signature: %v",
			ErrInvalidPeerEndpointSet,
			err,
		)
	}
	if wire.SchemaVersion != peerEndpointSetSchemaVersion ||
		len(wire.Endpoints) < 1 ||
		len(wire.Endpoints) > PeerEndpointHintsPerMemberMax {
		return parsedPeerEndpointSet{}, ErrInvalidPeerEndpointSet
	}
	result := parsedPeerEndpointSet{
		sessionID:          domain.UUIDv7(wire.SessionID),
		workspaceID:        domain.UUIDv4(wire.WorkspaceID),
		recoveryGeneration: wire.RecoveryGeneration,
		deviceID:           domain.DeviceID(wire.DeviceID),
		sequence:           wire.EndpointSequence,
		issuedAt:           domain.WholeSecondTimestamp(wire.IssuedAt),
		expiresAt:          domain.WholeSecondTimestamp(wire.ExpiresAt),
		endpoints:          make([]netip.AddrPort, len(wire.Endpoints)),
		canonical:          bytes.Clone(canonical),
		unsigned:           bytes.Clone(unsigned),
		signature:          bytes.Clone(signature),
	}
	if !result.sessionID.Valid() ||
		!result.workspaceID.Valid() ||
		!domain.ValidUnsignedInteger(result.recoveryGeneration) ||
		!result.deviceID.Valid() ||
		result.sequence < 1 ||
		!domain.ValidUnsignedInteger(result.sequence) ||
		!result.issuedAt.Valid() ||
		!result.expiresAt.Valid() {
		return parsedPeerEndpointSet{}, ErrInvalidPeerEndpointSet
	}
	issuedTime, _ := result.issuedAt.Time()
	expiresTime, _ := result.expiresAt.Time()
	if !expiresTime.After(issuedTime) {
		return parsedPeerEndpointSet{}, ErrInvalidPeerEndpointSet
	}

	for index, endpointWire := range wire.Endpoints {
		address, err := netip.ParseAddr(endpointWire.IP)
		if err != nil ||
			address.String() != endpointWire.IP ||
			address.Zone() != "" {
			return parsedPeerEndpointSet{}, ErrInvalidPeerEndpoint
		}
		endpoint := netip.AddrPortFrom(address, endpointWire.Port)
		if err := validatePeerEndpointAddress(endpoint, false); err != nil {
			return parsedPeerEndpointSet{}, err
		}
		if index > 0 {
			order := comparePeerEndpoints(result.endpoints[index-1], endpoint)
			if order >= 0 {
				return parsedPeerEndpointSet{}, ErrInvalidPeerEndpointSet
			}
		}
		result.endpoints[index] = endpoint
	}
	return result, nil
}

func decodeClosedPeerEndpointJSON(input []byte, target any) error {
	decoder := json.NewDecoder(bytes.NewReader(input))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("trailing JSON value")
		}
		return err
	}
	return nil
}

func validatePeerEndpointSetTimes(
	value parsedPeerEndpointSet,
	now time.Time,
	advertisementInterval time.Duration,
) error {
	if advertisementInterval <
		time.Duration(policy.MinAdvertisementIntervalSeconds)*time.Second ||
		advertisementInterval >
			time.Duration(policy.MaxAdvertisementIntervalSeconds)*time.Second ||
		advertisementInterval%time.Second != 0 {
		return ErrPeerEndpointIntegrity
	}
	issuedAt, _ := value.issuedAt.Time()
	expiresAt, _ := value.expiresAt.Time()
	hintTTL := peerEndpointHintTTLIntervals * advertisementInterval
	if expiresAt.Sub(issuedAt) > hintTTL ||
		issuedAt.After(now.Add(peerEndpointClockSkew)) ||
		!expiresAt.After(now) ||
		expiresAt.After(now.Add(hintTTL+peerEndpointClockSkew)) {
		return ErrInvalidPeerEndpointSet
	}
	return nil
}

func readPeerEndpointPolicy(
	conn *sqlite.Conn,
	sessionID domain.UUIDv7,
) (policy.Values, error) {
	var (
		encoded string
		count   int
	)
	if err := queryArgs(
		conn,
		`SELECT values_json
		   FROM session_policy
		  WHERE session_id = ?1;`,
		[]any{string(sessionID)},
		func(stmt *sqlite.Stmt) {
			count++
			encoded = stmt.ColumnText(0)
		},
	); err != nil {
		return policy.Values{}, err
	}
	if count != 1 {
		return policy.Values{}, ErrPeerEndpointIntegrity
	}
	canonical, err := codec.CanonicalizeSignedObject([]byte(encoded))
	if err != nil || !bytes.Equal(canonical, []byte(encoded)) {
		return policy.Values{}, ErrPeerEndpointIntegrity
	}
	var wire policyValuesJSON
	if err := decodeClosedPeerEndpointJSON(canonical, &wire); err != nil {
		return policy.Values{}, ErrPeerEndpointIntegrity
	}
	values := policy.Values{
		CheckpointEvents:             wire.CheckpointEvents,
		CheckpointIntervalSeconds:    wire.CheckpointIntervalSeconds,
		LeaseMinTTLSeconds:           wire.LeaseMinTTLSeconds,
		LeaseDefaultTTLSeconds:       wire.LeaseDefaultTTLSeconds,
		LeaseMaxTTLSeconds:           wire.LeaseMaxTTLSeconds,
		AgentClaimLimit:              wire.AgentClaimLimit,
		AgentLeaseLimit:              wire.AgentLeaseLimit,
		DeviceClaimLimit:             wire.DeviceClaimLimit,
		DeviceLeaseLimit:             wire.DeviceLeaseLimit,
		AdvertisementIntervalSeconds: wire.AdvertisementIntervalSeconds,
		AuditDepthPerDevicePerEpoch:  wire.AuditDepthPerDevicePerEpoch,
		MaxMemberDevices:             wire.MaxMemberDevices,
		MaxActiveAgentSessions:       wire.MaxActiveAgentSessions,
		ClusterMinApplyLevel:         wire.ClusterMinApplyLevel,
	}
	if values.Validate() != nil {
		return policy.Values{}, ErrPeerEndpointIntegrity
	}
	return values, nil
}

func readPeerEndpointRowsForDevice(
	conn *sqlite.Conn,
	deviceID domain.DeviceID,
) ([]storedPeerEndpoint, error) {
	return readPeerEndpointRows(
		conn,
		`SELECT endpoint_id, device_id, source_kind, endpoint_sequence,
		        transport, host, port, endpoint_set_json, observed_at, expires_at
		   FROM peer_endpoints
		  WHERE device_id = ?1
		  ORDER BY endpoint_id;`,
		[]any{string(deviceID)},
	)
}

func readPeerEndpointRowsForSource(
	conn *sqlite.Conn,
	deviceID domain.DeviceID,
	sourceKind PeerEndpointSourceKind,
) ([]storedPeerEndpoint, error) {
	return readPeerEndpointRows(
		conn,
		`SELECT endpoint_id, device_id, source_kind, endpoint_sequence,
		        transport, host, port, endpoint_set_json, observed_at, expires_at
		   FROM peer_endpoints
		  WHERE device_id = ?1 AND source_kind = ?2
		  ORDER BY endpoint_id;`,
		[]any{string(deviceID), string(sourceKind)},
	)
}

func readAllPeerEndpointRows(
	conn *sqlite.Conn,
) ([]storedPeerEndpoint, error) {
	return readPeerEndpointRows(
		conn,
		`SELECT endpoint_id, device_id, source_kind, endpoint_sequence,
		        transport, host, port, endpoint_set_json, observed_at, expires_at
		   FROM peer_endpoints
		  ORDER BY endpoint_id;`,
		nil,
	)
}

func readPeerEndpointRows(
	conn *sqlite.Conn,
	statement string,
	args []any,
) ([]storedPeerEndpoint, error) {
	var (
		rows   []storedPeerEndpoint
		rowErr error
	)
	err := queryArgs(conn, statement, args, func(stmt *sqlite.Stmt) {
		if rowErr != nil {
			return
		}
		rowID := stmt.ColumnInt64(0)
		transport := stmt.ColumnText(4)
		port := stmt.ColumnInt64(6)
		if rowID < 1 || transport != "tcp" || port < 1 || port > 65535 {
			rowErr = ErrPeerEndpointIntegrity
			return
		}
		host := stmt.ColumnText(5)
		address, err := netip.ParseAddr(host)
		if err != nil || address.String() != host {
			rowErr = ErrPeerEndpointIntegrity
			return
		}
		record := PeerEndpointRecord{
			DeviceID:   domain.DeviceID(stmt.ColumnText(1)),
			SourceKind: PeerEndpointSourceKind(stmt.ColumnText(2)),
			Endpoint: netip.AddrPortFrom(
				address,
				uint16(port),
			),
			ObservedAt: domain.Timestamp(stmt.ColumnText(8)),
		}
		if stmt.ColumnType(3) != sqlite.TypeNull {
			sequence := stmt.ColumnInt64(3)
			if sequence < 1 {
				rowErr = ErrPeerEndpointIntegrity
				return
			}
			record.EndpointSequence = uint64(sequence)
		}
		if stmt.ColumnType(7) != sqlite.TypeNull {
			record.EndpointSetJSON = []byte(stmt.ColumnText(7))
		}
		if stmt.ColumnType(9) != sqlite.TypeNull {
			record.ExpiresAt = domain.Timestamp(stmt.ColumnText(9))
		}
		if err := record.Validate(); err != nil {
			rowErr = fmt.Errorf("%w: %v", ErrPeerEndpointIntegrity, err)
			return
		}
		rows = append(rows, storedPeerEndpoint{
			id:     rowID,
			record: record,
		})
	})
	if err != nil {
		return nil, err
	}
	if rowErr != nil {
		return nil, rowErr
	}
	if err := validateMemberEndpointGroups(rows); err != nil {
		return nil, err
	}
	return rows, nil
}

func validateMemberEndpointGroups(rows []storedPeerEndpoint) error {
	groups := make(map[domain.DeviceID][]storedPeerEndpoint)
	for _, row := range rows {
		if row.record.SourceKind == PeerEndpointMemberSigned {
			groups[row.record.DeviceID] = append(
				groups[row.record.DeviceID],
				row,
			)
		}
	}
	for _, group := range groups {
		if len(group) == 0 {
			continue
		}
		first := group[0].record
		hasCurrentSet := len(first.EndpointSetJSON) != 0
		for _, row := range group[1:] {
			record := row.record
			if (len(record.EndpointSetJSON) != 0) != hasCurrentSet {
				return ErrPeerEndpointIntegrity
			}
			if hasCurrentSet &&
				(record.EndpointSequence != first.EndpointSequence ||
					!bytes.Equal(record.EndpointSetJSON, first.EndpointSetJSON) ||
					record.ObservedAt != first.ObservedAt ||
					record.ExpiresAt != first.ExpiresAt) {
				return ErrPeerEndpointIntegrity
			}
		}
		if !hasCurrentSet {
			continue
		}
		parsed, err := parsePeerEndpointSet(first.EndpointSetJSON)
		if err != nil ||
			parsed.deviceID != first.DeviceID ||
			len(parsed.endpoints) != len(group) {
			return ErrPeerEndpointIntegrity
		}
		endpoints := make([]netip.AddrPort, len(group))
		for index, row := range group {
			endpoints[index] = row.record.Endpoint
		}
		sort.Slice(endpoints, func(left, right int) bool {
			return comparePeerEndpoints(endpoints[left], endpoints[right]) < 0
		})
		for index := range endpoints {
			if endpoints[index] != parsed.endpoints[index] {
				return ErrPeerEndpointIntegrity
			}
		}
	}
	return nil
}

func currentMemberEndpointSet(
	rows []storedPeerEndpoint,
) (parsedPeerEndpointSet, bool, error) {
	if len(rows) == 0 || len(rows[0].record.EndpointSetJSON) == 0 {
		return parsedPeerEndpointSet{}, false, nil
	}
	parsed, err := parsePeerEndpointSet(rows[0].record.EndpointSetJSON)
	if err != nil {
		return parsedPeerEndpointSet{}, false, ErrPeerEndpointIntegrity
	}
	return parsed, true, nil
}

func insertPeerEndpointRow(
	conn *sqlite.Conn,
	record PeerEndpointRecord,
) error {
	return execute(
		conn,
		`INSERT INTO peer_endpoints(
		    device_id, source_kind, endpoint_sequence, transport, host, port,
		    endpoint_set_json, observed_at, expires_at
		) VALUES (?1, ?2, ?3, 'tcp', ?4, ?5, ?6, ?7, ?8);`,
		string(record.DeviceID),
		string(record.SourceKind),
		nullablePeerEndpointSequence(record.EndpointSequence),
		record.Endpoint.Addr().String(),
		uint64(record.Endpoint.Port()),
		nullablePeerEndpointJSON(record.EndpointSetJSON),
		string(record.ObservedAt),
		nullablePeerEndpointTimestamp(record.ExpiresAt),
	)
}

func upsertPeerEndpointRow(
	conn *sqlite.Conn,
	record PeerEndpointRecord,
) error {
	return execute(
		conn,
		`INSERT INTO peer_endpoints(
		    device_id, source_kind, endpoint_sequence, transport, host, port,
		    endpoint_set_json, observed_at, expires_at
		) VALUES (?1, ?2, ?3, 'tcp', ?4, ?5, ?6, ?7, ?8)
		ON CONFLICT(device_id, source_kind, host, port) DO UPDATE SET
		    endpoint_sequence = excluded.endpoint_sequence,
		    endpoint_set_json = excluded.endpoint_set_json,
		    observed_at = excluded.observed_at,
		    expires_at = excluded.expires_at;`,
		string(record.DeviceID),
		string(record.SourceKind),
		nullablePeerEndpointSequence(record.EndpointSequence),
		record.Endpoint.Addr().String(),
		uint64(record.Endpoint.Port()),
		nullablePeerEndpointJSON(record.EndpointSetJSON),
		string(record.ObservedAt),
		nullablePeerEndpointTimestamp(record.ExpiresAt),
	)
}

func refreshMemberEndpointRows(
	conn *sqlite.Conn,
	deviceID domain.DeviceID,
	observedAt domain.Timestamp,
) error {
	rows, err := readPeerEndpointRowsForSource(
		conn,
		deviceID,
		PeerEndpointMemberSigned,
	)
	if err != nil {
		return err
	}
	if len(rows) == 0 || len(rows[0].record.EndpointSetJSON) == 0 {
		return ErrPeerEndpointIntegrity
	}
	currentObserved, _ := rows[0].record.ObservedAt.Time()
	nextObserved, _ := observedAt.Time()
	if !nextObserved.After(currentObserved) {
		return nil
	}
	expiresAt, err := peerEndpointGuessExpiry(observedAt)
	if err != nil {
		return err
	}
	return execute(
		conn,
		`UPDATE peer_endpoints
		    SET observed_at = ?2, expires_at = ?3
		  WHERE device_id = ?1 AND source_kind = 'member_signed';`,
		string(deviceID),
		string(observedAt),
		string(expiresAt),
	)
}

func expireStalePeerEndpointRows(
	conn *sqlite.Conn,
	now time.Time,
) (int, error) {
	rows, err := readAllPeerEndpointRows(conn)
	if err != nil {
		return 0, err
	}
	affected := 0
	expiredMemberSets := make(map[domain.DeviceID]struct{})
	for _, row := range rows {
		record := row.record
		if record.SourceKind == PeerEndpointOwnSigned ||
			record.SourceKind == PeerEndpointManual {
			continue
		}
		expiresAt, _ := record.ExpiresAt.Time()
		if !expiresAt.After(now) {
			if err := execute(
				conn,
				"DELETE FROM peer_endpoints WHERE endpoint_id = ?1;",
				row.id,
			); err != nil {
				return 0, err
			}
			affected++
			continue
		}
		if record.SourceKind != PeerEndpointMemberSigned ||
			len(record.EndpointSetJSON) == 0 {
			continue
		}
		parsed, err := parsePeerEndpointSet(record.EndpointSetJSON)
		if err != nil {
			return 0, ErrPeerEndpointIntegrity
		}
		setExpiry, _ := parsed.expiresAt.Time()
		if !setExpiry.After(now) {
			expiredMemberSets[record.DeviceID] = struct{}{}
		}
	}
	for deviceID := range expiredMemberSets {
		var count int64
		if err := queryOneArgs(
			conn,
			`SELECT count(*)
			   FROM peer_endpoints
			  WHERE device_id = ?1
			    AND source_kind = 'member_signed'
			    AND endpoint_set_json IS NOT NULL;`,
			[]any{string(deviceID)},
			func(stmt *sqlite.Stmt) {
				count = stmt.ColumnInt64(0)
			},
		); err != nil {
			return 0, err
		}
		if count < 1 {
			return 0, ErrPeerEndpointIntegrity
		}
		if err := execute(
			conn,
			`UPDATE peer_endpoints
			    SET endpoint_sequence = NULL, endpoint_set_json = NULL
			  WHERE device_id = ?1 AND source_kind = 'member_signed';`,
			string(deviceID),
		); err != nil {
			return 0, err
		}
		affected += int(count)
	}
	return affected, nil
}

func checkManualEndpointCapacity(
	conn *sqlite.Conn,
	deviceID domain.DeviceID,
) error {
	rows, err := readAllPeerEndpointRows(conn)
	if err != nil {
		return err
	}
	perMember := 0
	perSession := 0
	for _, row := range rows {
		if row.record.SourceKind != PeerEndpointManual {
			continue
		}
		perSession++
		if row.record.DeviceID == deviceID {
			perMember++
		}
	}
	if perMember >= ManualEndpointsPerMemberMax ||
		perSession >= ManualEndpointsPerSessionMax {
		return ErrPeerEndpointCapacity
	}
	return nil
}

func enforcePeerEndpointCaps(
	conn *sqlite.Conn,
	protected *peerEndpointKey,
) error {
	rows, err := readAllPeerEndpointRows(conn)
	if err != nil {
		return err
	}
	byMember := make(map[domain.DeviceID]int)
	sessionCount := 0
	for _, row := range rows {
		if !isNonmanualPeerEndpoint(row.record.SourceKind) {
			continue
		}
		byMember[row.record.DeviceID]++
		sessionCount++
	}

	evictable := make([]storedPeerEndpoint, 0, len(rows))
	for _, row := range rows {
		if !peerEndpointRowEvictable(row.record) {
			continue
		}
		if protected != nil &&
			peerEndpointRecordKey(row.record) == *protected {
			continue
		}
		evictable = append(evictable, row)
	}
	sort.Slice(evictable, func(left, right int) bool {
		return comparePeerEndpointEviction(
			evictable[left],
			evictable[right],
		) < 0
	})
	deleted := make(map[int64]struct{})
	deleteRow := func(row storedPeerEndpoint) error {
		if _, already := deleted[row.id]; already {
			return nil
		}
		if err := execute(
			conn,
			"DELETE FROM peer_endpoints WHERE endpoint_id = ?1;",
			row.id,
		); err != nil {
			return err
		}
		deleted[row.id] = struct{}{}
		byMember[row.record.DeviceID]--
		sessionCount--
		return nil
	}

	deviceIDs := make([]domain.DeviceID, 0, len(byMember))
	for deviceID := range byMember {
		deviceIDs = append(deviceIDs, deviceID)
	}
	sort.Slice(deviceIDs, func(left, right int) bool {
		return deviceIDs[left] < deviceIDs[right]
	})
	for _, deviceID := range deviceIDs {
		for byMember[deviceID] > PeerEndpointHintsPerMemberMax {
			found := false
			for _, candidate := range evictable {
				if candidate.record.DeviceID != deviceID {
					continue
				}
				if _, already := deleted[candidate.id]; already {
					continue
				}
				if err := deleteRow(candidate); err != nil {
					return err
				}
				found = true
				break
			}
			if !found {
				return ErrPeerEndpointCapacity
			}
		}
	}
	for sessionCount > PeerEndpointHintsPerSessionMax {
		found := false
		for _, candidate := range evictable {
			if _, already := deleted[candidate.id]; already {
				continue
			}
			if err := deleteRow(candidate); err != nil {
				return err
			}
			found = true
			break
		}
		if !found {
			return ErrPeerEndpointCapacity
		}
	}
	return validatePeerEndpointCaps(conn)
}

func validatePeerEndpointCaps(conn *sqlite.Conn) error {
	rows, err := readAllPeerEndpointRows(conn)
	if err != nil {
		return err
	}
	return validatePeerEndpointRowCaps(rows)
}

func validatePeerEndpointRowCaps(rows []storedPeerEndpoint) error {
	nonmanualByMember := make(map[domain.DeviceID]int)
	manualByMember := make(map[domain.DeviceID]int)
	nonmanualSession := 0
	manualSession := 0
	for _, row := range rows {
		switch {
		case isNonmanualPeerEndpoint(row.record.SourceKind):
			nonmanualByMember[row.record.DeviceID]++
			nonmanualSession++
		case row.record.SourceKind == PeerEndpointManual:
			manualByMember[row.record.DeviceID]++
			manualSession++
		}
	}
	if nonmanualSession > PeerEndpointHintsPerSessionMax ||
		manualSession > ManualEndpointsPerSessionMax {
		return ErrPeerEndpointCapacity
	}
	for _, count := range nonmanualByMember {
		if count > PeerEndpointHintsPerMemberMax {
			return ErrPeerEndpointCapacity
		}
	}
	for _, count := range manualByMember {
		if count > ManualEndpointsPerMemberMax {
			return ErrPeerEndpointCapacity
		}
	}
	return nil
}

func peerEndpointRowExists(
	conn *sqlite.Conn,
	key peerEndpointKey,
) (bool, error) {
	var count int64
	if err := queryOneArgs(
		conn,
		`SELECT count(*)
		   FROM peer_endpoints
		  WHERE device_id = ?1
		    AND source_kind = ?2
		    AND host = ?3
		    AND port = ?4;`,
		[]any{
			string(key.deviceID),
			string(key.sourceKind),
			key.endpoint.Addr().String(),
			uint64(key.endpoint.Port()),
		},
		func(stmt *sqlite.Stmt) {
			count = stmt.ColumnInt64(0)
		},
	); err != nil {
		return false, err
	}
	if count < 0 || count > 1 {
		return false, ErrPeerEndpointIntegrity
	}
	return count == 1, nil
}

func peerEndpointGuessExpiry(
	observedAt domain.Timestamp,
) (domain.Timestamp, error) {
	observedTime, err := peerEndpointTime(observedAt)
	if err != nil {
		return "", ErrInvalidPeerEndpoint
	}
	expiresAt := domain.Timestamp(
		observedTime.Add(peerEndpointGuessTTL).
			UTC().
			Format(time.RFC3339Nano),
	)
	if !expiresAt.Valid() {
		return "", ErrInvalidPeerEndpoint
	}
	return expiresAt, nil
}

func peerEndpointTime(value domain.Timestamp) (time.Time, error) {
	if !value.Valid() {
		return time.Time{}, ErrInvalidPeerEndpoint
	}
	parsed, err := value.Time()
	if err != nil || parsed.IsZero() {
		return time.Time{}, ErrInvalidPeerEndpoint
	}
	return parsed, nil
}

func peerEndpointSetContains(
	value parsedPeerEndpointSet,
	endpoint netip.AddrPort,
) bool {
	index := sort.Search(len(value.endpoints), func(index int) bool {
		return comparePeerEndpoints(value.endpoints[index], endpoint) >= 0
	})
	return index < len(value.endpoints) &&
		value.endpoints[index] == endpoint
}

func comparePeerEndpoints(left, right netip.AddrPort) int {
	leftAddress := left.Addr()
	rightAddress := right.Addr()
	if leftAddress.Is4() != rightAddress.Is4() {
		if leftAddress.Is4() {
			return -1
		}
		return 1
	}
	if order := bytes.Compare(
		leftAddress.AsSlice(),
		rightAddress.AsSlice(),
	); order != 0 {
		return order
	}
	if leftAddress.Zone() < rightAddress.Zone() {
		return -1
	}
	if leftAddress.Zone() > rightAddress.Zone() {
		return 1
	}
	switch {
	case left.Port() < right.Port():
		return -1
	case left.Port() > right.Port():
		return 1
	default:
		return 0
	}
}

func comparePeerEndpointEviction(
	left, right storedPeerEndpoint,
) int {
	leftTime, _ := left.record.ObservedAt.Time()
	rightTime, _ := right.record.ObservedAt.Time()
	if leftTime.Before(rightTime) {
		return -1
	}
	if leftTime.After(rightTime) {
		return 1
	}
	if left.record.DeviceID < right.record.DeviceID {
		return -1
	}
	if left.record.DeviceID > right.record.DeviceID {
		return 1
	}
	leftPriority := peerEndpointSourcePriority(left.record.SourceKind)
	rightPriority := peerEndpointSourcePriority(right.record.SourceKind)
	if leftPriority < rightPriority {
		return -1
	}
	if leftPriority > rightPriority {
		return 1
	}
	if order := comparePeerEndpoints(
		left.record.Endpoint,
		right.record.Endpoint,
	); order != 0 {
		return order
	}
	switch {
	case left.id < right.id:
		return -1
	case left.id > right.id:
		return 1
	default:
		return 0
	}
}

func peerEndpointSourcePriority(kind PeerEndpointSourceKind) int {
	switch kind {
	case PeerEndpointMemberSigned:
		return 0
	case PeerEndpointRawDiscovery:
		return 1
	case PeerEndpointAuthenticatedGuess:
		return 2
	case PeerEndpointManual:
		return 3
	default:
		return 4
	}
}

func peerEndpointRowEvictable(record PeerEndpointRecord) bool {
	switch record.SourceKind {
	case PeerEndpointRawDiscovery, PeerEndpointAuthenticatedGuess:
		return true
	case PeerEndpointMemberSigned:
		return len(record.EndpointSetJSON) == 0
	default:
		return false
	}
}

func isNonmanualPeerEndpoint(kind PeerEndpointSourceKind) bool {
	return kind == PeerEndpointMemberSigned ||
		kind == PeerEndpointRawDiscovery ||
		kind == PeerEndpointAuthenticatedGuess
}

func peerEndpointRecordKey(record PeerEndpointRecord) peerEndpointKey {
	return peerEndpointKey{
		deviceID:   record.DeviceID,
		sourceKind: record.SourceKind,
		endpoint:   record.Endpoint,
	}
}

func clonePeerEndpointRecord(record PeerEndpointRecord) PeerEndpointRecord {
	record.EndpointSetJSON = bytes.Clone(record.EndpointSetJSON)
	return record
}

func ownEndpointSequence() netip.AddrPort {
	return netip.AddrPortFrom(
		netip.MustParseAddr(ownEndpointSequenceHost),
		ownEndpointSequencePort,
	)
}

func nullablePeerEndpointSequence(value uint64) any {
	if value == 0 {
		return nil
	}
	return value
}

func nullablePeerEndpointJSON(value []byte) any {
	if len(value) == 0 {
		return nil
	}
	return string(value)
}

func nullablePeerEndpointTimestamp(value domain.Timestamp) any {
	if value == "" {
		return nil
	}
	return string(value)
}
