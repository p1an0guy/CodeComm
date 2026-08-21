package store

import (
	"context"
	"fmt"
	"sort"

	"github.com/ijonahch/codecomm/internal/domain"
	"zombiezen.com/go/sqlite"
	"zombiezen.com/go/sqlite/sqlitex"
)

// SettledReplicationObservation is the greatest signed server watermark
// retained for one signer and authority version.
type SettledReplicationObservation struct {
	SignerDeviceID           domain.DeviceID
	AuthorityVersion         uint64
	VerifiedResultIndex      uint64
	ServerAppliedResultIndex uint64
	VerifiedAt               domain.Timestamp
}

// SettledReplicationBlocker identifies a signed watermark beyond the local
// verified result head.
type SettledReplicationBlocker struct {
	SignerDeviceID   domain.DeviceID
	AuthorityVersion uint64
	ResultIndex      uint64
}

// SettledReplicationProgress reports the fully verified local head and the
// signed authority observations retained to establish its currency.
type SettledReplicationProgress struct {
	Heads        ApplyHeads
	Observations []SettledReplicationObservation
	Blocker      *SettledReplicationBlocker
}

// SettledReplicationProgress revalidates the complete settled-nonvoter
// evidence chain and derives signed progress observations from that same
// transaction.
func (store *Store) SettledReplicationProgress(
	ctx context.Context,
) (SettledReplicationProgress, error) {
	if store == nil || ctx == nil {
		return SettledReplicationProgress{}, ErrInvalidOptions
	}
	if err := ctx.Err(); err != nil {
		return SettledReplicationProgress{}, err
	}

	store.applyMu.Lock()
	defer store.applyMu.Unlock()

	var progress SettledReplicationProgress
	err := store.withConn(ctx, func(conn *sqlite.Conn) (err error) {
		previousInterrupt := conn.SetInterrupt(ctx.Done())
		defer conn.SetInterrupt(previousInterrupt)
		end, err := sqlitex.ImmediateTransaction(conn)
		if err != nil {
			return err
		}
		defer end(&err)

		state, found, err := readConsensusState(conn)
		if err != nil {
			return err
		}
		if !found {
			return fmt.Errorf(
				"%w: active generation is missing",
				ErrReplicaEvidenceMode,
			)
		}
		settled, found, err := readSettledNonvoterState(conn)
		if err != nil {
			return err
		}
		if !found {
			return ErrReplicaEvidenceMode
		}
		if err := verifyCommitmentHistory(conn, state); err != nil {
			return err
		}
		if err := verifySettledNonvoterEvidence(
			conn,
			state,
			settled,
		); err != nil {
			return err
		}

		type observationKey struct {
			signer    domain.DeviceID
			authority uint64
		}
		observations := make(
			map[observationKey]SettledReplicationObservation,
		)
		cursor := settled.baselineHeads.ResultIndex
		for cursor < state.resultIndex {
			if cursor == domain.MaxSafeInteger {
				return replicationEvidenceError(
					"progress cursor is exhausted",
					nil,
				)
			}
			attestation, found, err :=
				readReplicationAttestationStartingAt(
					conn,
					state,
					cursor+1,
				)
			if err != nil {
				return err
			}
			if !found {
				return replicationEvidenceError(
					"progress attestation is missing",
					nil,
				)
			}
			key := observationKey{
				signer:    attestation.signerDeviceID,
				authority: attestation.authorityVersion,
			}
			candidate := SettledReplicationObservation{
				SignerDeviceID:      attestation.signerDeviceID,
				AuthorityVersion:    attestation.authorityVersion,
				VerifiedResultIndex: attestation.toResultIndex,
				ServerAppliedResultIndex: attestation.
					serverAppliedResultIndex,
				VerifiedAt: attestation.verifiedAt,
			}
			current, exists := observations[key]
			if !exists ||
				candidate.ServerAppliedResultIndex >
					current.ServerAppliedResultIndex ||
				candidate.ServerAppliedResultIndex ==
					current.ServerAppliedResultIndex &&
					candidate.VerifiedResultIndex >
						current.VerifiedResultIndex {
				observations[key] = candidate
			}
			cursor = attestation.toResultIndex
		}
		watermarks, err := readStoredWatermarkObservations(conn)
		if err != nil {
			return err
		}
		for _, watermark := range watermarks {
			key := observationKey{
				signer:    watermark.signerDeviceID,
				authority: watermark.authorityVersion,
			}
			candidate := SettledReplicationObservation{
				SignerDeviceID:      watermark.signerDeviceID,
				AuthorityVersion:    watermark.authorityVersion,
				VerifiedResultIndex: watermark.resultIndex,
				ServerAppliedResultIndex: watermark.
					serverAppliedResultIndex,
				VerifiedAt: watermark.verifiedAt,
			}
			current, exists := observations[key]
			if !exists ||
				candidate.ServerAppliedResultIndex >
					current.ServerAppliedResultIndex ||
				candidate.ServerAppliedResultIndex ==
					current.ServerAppliedResultIndex &&
					candidate.VerifiedResultIndex >
						current.VerifiedResultIndex {
				observations[key] = candidate
			}
		}

		progress.Heads = headsFromConsensus(state)
		progress.Observations = make(
			[]SettledReplicationObservation,
			0,
			len(observations),
		)
		for _, observation := range observations {
			progress.Observations = append(
				progress.Observations,
				observation,
			)
			if observation.ServerAppliedResultIndex <=
				state.resultIndex {
				continue
			}
			candidate := SettledReplicationBlocker{
				SignerDeviceID:   observation.SignerDeviceID,
				AuthorityVersion: observation.AuthorityVersion,
				ResultIndex:      observation.ServerAppliedResultIndex,
			}
			if progress.Blocker == nil ||
				candidate.ResultIndex > progress.Blocker.ResultIndex ||
				candidate.ResultIndex == progress.Blocker.ResultIndex &&
					candidate.AuthorityVersion >
						progress.Blocker.AuthorityVersion ||
				candidate.ResultIndex == progress.Blocker.ResultIndex &&
					candidate.AuthorityVersion ==
						progress.Blocker.AuthorityVersion &&
					candidate.SignerDeviceID <
						progress.Blocker.SignerDeviceID {
				progress.Blocker = &candidate
			}
		}
		sort.Slice(
			progress.Observations,
			func(left, right int) bool {
				if progress.Observations[left].AuthorityVersion !=
					progress.Observations[right].AuthorityVersion {
					return progress.Observations[left].
						AuthorityVersion <
						progress.Observations[right].
							AuthorityVersion
				}
				return progress.Observations[left].SignerDeviceID <
					progress.Observations[right].SignerDeviceID
			},
		)
		return nil
	})
	if err != nil {
		return SettledReplicationProgress{}, err
	}
	return progress, nil
}
