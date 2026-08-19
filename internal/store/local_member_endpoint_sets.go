package store

import (
	"bytes"
	"context"
	"fmt"
	"sort"
	"time"

	"github.com/ijonahch/codecomm/internal/codec"
	codecommcrypto "github.com/ijonahch/codecomm/internal/crypto"
	"github.com/ijonahch/codecomm/internal/domain"
	"github.com/ijonahch/codecomm/internal/domain/device"
	"zombiezen.com/go/sqlite"
)

// MemberSignedEndpointSet is one active member's exact identity-signed JCS
// endpoint-set object.
type MemberSignedEndpointSet struct {
	DeviceID        domain.DeviceID
	EndpointSetJSON []byte
}

// ListMemberSignedEndpointSets returns the latest unexpired exact signed
// endpoint set for each active member in canonical device-ID order.
func (state LocalState) ListMemberSignedEndpointSets(
	ctx context.Context,
	now domain.Timestamp,
) ([]MemberSignedEndpointSet, error) {
	nowTime, err := peerEndpointTime(now)
	if err != nil {
		return nil, ErrInvalidPeerEndpoint
	}

	var result []MemberSignedEndpointSet
	err = state.withImmediate(ctx, func(conn *sqlite.Conn) error {
		if _, err := expireStalePeerEndpointRows(conn, nowTime); err != nil {
			return err
		}
		if err := validatePeerEndpointCaps(conn); err != nil {
			return err
		}
		rows, err := readAllPeerEndpointRows(conn)
		if err != nil {
			return err
		}
		lineage, err := readLocalLineage(conn)
		if err != nil {
			return err
		}
		values, err := readPeerEndpointPolicy(conn, lineage.sessionID)
		if err != nil {
			return err
		}
		advertisementInterval := time.Duration(
			values.AdvertisementIntervalSeconds,
		) * time.Second

		seen := make(map[domain.DeviceID]struct{})
		for _, row := range rows {
			record := row.record
			if record.SourceKind != PeerEndpointMemberSigned ||
				len(record.EndpointSetJSON) == 0 {
				continue
			}
			if _, duplicate := seen[record.DeviceID]; duplicate {
				continue
			}
			seen[record.DeviceID] = struct{}{}

			member, found, err := readStatusMember(conn, record.DeviceID)
			if err != nil {
				return err
			}
			if !found || member.Status != device.StatusActive {
				continue
			}
			parsed, err := parsePeerEndpointSet(record.EndpointSetJSON)
			if err != nil {
				return fmt.Errorf(
					"%w: parse retained member endpoint set: %v",
					ErrPeerEndpointIntegrity,
					err,
				)
			}
			if parsed.sessionID != lineage.sessionID ||
				parsed.workspaceID != lineage.workspaceID ||
				parsed.recoveryGeneration != lineage.recoveryGeneration {
				return fmt.Errorf(
					"%w: retained member endpoint set lineage mismatch",
					ErrPeerEndpointIntegrity,
				)
			}
			if err := validatePeerEndpointSetTimes(
				parsed,
				nowTime,
				advertisementInterval,
			); err != nil {
				return fmt.Errorf(
					"%w: retained member endpoint set time bounds: %v",
					ErrPeerEndpointIntegrity,
					err,
				)
			}
			if err := codecommcrypto.VerifyEd25519(
				member.IdentityPublicKey,
				codec.SignatureEndpointHints,
				parsed.unsigned,
				parsed.signature,
			); err != nil {
				return fmt.Errorf(
					"%w: verify retained member endpoint set: %v",
					ErrPeerEndpointIntegrity,
					err,
				)
			}
			result = append(result, MemberSignedEndpointSet{
				DeviceID:        record.DeviceID,
				EndpointSetJSON: bytes.Clone(record.EndpointSetJSON),
			})
		}
		sort.Slice(result, func(left, right int) bool {
			return result[left].DeviceID < result[right].DeviceID
		})
		return nil
	})
	if err != nil {
		return nil, err
	}
	return result, nil
}
