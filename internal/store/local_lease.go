package store

import (
	"context"
	"fmt"
	"math"
	"time"

	"github.com/ijonahch/codecomm/internal/domain"
	"github.com/ijonahch/codecomm/internal/domain/lease"
	"zombiezen.com/go/sqlite"
)

// RearmLeaseDeadlines replaces every local timer with a full TTL measured
// from the current daemon boot. Persisted monotonic values are never reused
// across boots.
func (state LocalState) RearmLeaseDeadlines(
	ctx context.Context,
	originBootID domain.UUIDv7,
	now domain.Timestamp,
	monotonicNowNS int64,
) error {
	if !originBootID.Valid() || !now.Valid() || monotonicNowNS < 0 {
		return ErrInvalidLocalState
	}
	wallNow, err := now.Time()
	if err != nil {
		return ErrInvalidLocalState
	}
	return state.withImmediate(ctx, func(conn *sqlite.Conn) error {
		return rearmLeaseDeadlines(
			conn,
			originBootID,
			wallNow,
			monotonicNowNS,
		)
	})
}

func rearmLeaseDeadlines(
	conn *sqlite.Conn,
	originBootID domain.UUIDv7,
	wallNow time.Time,
	monotonicNowNS int64,
) error {
	if conn == nil ||
		!originBootID.Valid() ||
		monotonicNowNS < 0 {
		return ErrInvalidLocalState
	}
	var (
		records []LeaseDeadlineRecord
		rowErr  error
	)
	err := query(
		conn,
		`SELECT lease_id, entity_version, ttl_seconds
		   FROM leases
		  WHERE status = 'active'
		  ORDER BY lease_id;`,
		func(stmt *sqlite.Stmt) {
			if rowErr != nil {
				return
			}
			version := stmt.ColumnInt64(1)
			ttlSeconds := stmt.ColumnInt64(2)
			if version < 1 ||
				!domain.ValidUnsignedInteger(uint64(version)) ||
				lease.ValidateRequestedTTL(
					ttlSeconds,
					lease.MinTTLSeconds,
					lease.MaxTTLSeconds,
				) != nil ||
				ttlSeconds > math.MaxInt64/int64(time.Second) ||
				monotonicNowNS >
					math.MaxInt64-ttlSeconds*int64(time.Second) {
				rowErr = ErrLocalStateIntegrity
				return
			}
			record := LeaseDeadlineRecord{
				LeaseID:       domain.UUIDv7(stmt.ColumnText(0)),
				EntityVersion: uint64(version),
				OriginBootID:  originBootID,
				MonotonicDeadlineNS: monotonicNowNS +
					ttlSeconds*int64(time.Second),
				DisplayDeadlineAt: domain.Timestamp(
					wallNow.Add(
						time.Duration(ttlSeconds) * time.Second,
					).UTC().Format(time.RFC3339Nano),
				),
			}
			if record.Validate() != nil {
				rowErr = ErrLocalStateIntegrity
				return
			}
			records = append(records, record)
		},
	)
	if err != nil {
		return err
	}
	if rowErr != nil {
		return rowErr
	}
	if err := execute(conn, "DELETE FROM lease_deadlines;"); err != nil {
		return err
	}
	return writeLeaseDeadlines(conn, records, nil)
}

// NextLeaseDeadline returns the earliest active same-boot deadline. Any
// orphaned, stale-boot, or version-mismatched row is an integrity failure.
func (state LocalState) NextLeaseDeadline(
	ctx context.Context,
	originBootID domain.UUIDv7,
) (LeaseDeadlineRecord, bool, error) {
	if !originBootID.Valid() {
		return LeaseDeadlineRecord{}, false, ErrInvalidLocalState
	}
	var (
		record LeaseDeadlineRecord
		found  bool
	)
	err := state.withImmediate(ctx, func(conn *sqlite.Conn) error {
		var invalid int64
		if err := queryOneArgs(
			conn,
			`SELECT
			    (SELECT count(*)
			       FROM lease_deadlines AS d
			       LEFT JOIN leases AS l
			         ON l.lease_id = d.lease_id
			        AND l.entity_version = d.entity_version
			        AND l.status = 'active'
			      WHERE d.origin_boot_id <> ?1 OR l.lease_id IS NULL)
			    +
			    (SELECT count(*)
			       FROM leases AS l
			       LEFT JOIN lease_deadlines AS d
			         ON d.lease_id = l.lease_id
			        AND d.entity_version = l.entity_version
			      WHERE l.status = 'active' AND d.lease_id IS NULL);`,
			[]any{string(originBootID)},
			func(stmt *sqlite.Stmt) {
				invalid = stmt.ColumnInt64(0)
			},
		); err != nil {
			return err
		}
		if invalid != 0 {
			return ErrLocalStateIntegrity
		}
		count := 0
		var rowErr error
		if err := queryArgs(
			conn,
			`SELECT lease_id, entity_version, origin_boot_id,
			        monotonic_deadline_ns, display_deadline_at
			   FROM lease_deadlines
			  ORDER BY monotonic_deadline_ns, lease_id
			  LIMIT 1;`,
			nil,
			func(stmt *sqlite.Stmt) {
				count++
				version := stmt.ColumnInt64(1)
				deadline := stmt.ColumnInt64(3)
				if count != 1 || version < 1 || deadline < 0 {
					rowErr = ErrLocalStateIntegrity
					return
				}
				record = LeaseDeadlineRecord{
					LeaseID:             domain.UUIDv7(stmt.ColumnText(0)),
					EntityVersion:       uint64(version),
					OriginBootID:        domain.UUIDv7(stmt.ColumnText(2)),
					MonotonicDeadlineNS: deadline,
					DisplayDeadlineAt: domain.Timestamp(
						stmt.ColumnText(4),
					),
				}
				found = true
			},
		); err != nil {
			return err
		}
		if rowErr != nil {
			return rowErr
		}
		if found && record.Validate() != nil {
			return fmt.Errorf(
				"%w: invalid lease deadline",
				ErrLocalStateIntegrity,
			)
		}
		return nil
	})
	if err != nil {
		return LeaseDeadlineRecord{}, false, err
	}
	return record, found, nil
}
