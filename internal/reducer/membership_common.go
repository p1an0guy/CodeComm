package reducer

import (
	"bytes"
	"fmt"

	"github.com/ijonahch/codecomm/internal/domain"
	"github.com/ijonahch/codecomm/internal/domain/auditcounter"
	"github.com/ijonahch/codecomm/internal/domain/credentialauthority"
	"github.com/ijonahch/codecomm/internal/domain/device"
	"github.com/ijonahch/codecomm/internal/domain/voterset"
)

func (context reductionContext) subjectDeviceID() domain.DeviceID {
	value, _ := context.proposal.EntityID.Value()
	return domain.DeviceID(value)
}

func (context reductionContext) acceptMembership(
	devices []device.Device,
	counters []auditcounter.Counter,
	targets []voterset.Set,
	authorities []credentialauthority.Authority,
	audit *AuditDirective,
) (Outcome, error) {
	deviceChanges := make([]device.Device, len(devices))
	for index, member := range devices {
		if err := member.Validate(); err != nil {
			return Outcome{}, invalidState(
				"reducer produced invalid device %q: %v",
				member.ID,
				err,
			)
		}
		member.IdentityPublicKey = bytes.Clone(member.IdentityPublicKey)
		deviceChanges[index] = member
	}
	for _, counter := range counters {
		if err := counter.Validate(); err != nil {
			return Outcome{}, invalidState(
				"reducer produced invalid audit counter %q: %v",
				counter.DeviceID,
				err,
			)
		}
	}
	for _, target := range targets {
		if err := target.Validate(); err != nil {
			return Outcome{}, invalidState(
				"reducer produced invalid voter target: %v",
				err,
			)
		}
	}
	for _, authority := range authorities {
		if err := authority.Validate(); err != nil {
			return Outcome{}, invalidState(
				"reducer produced invalid credential authority: %v",
				err,
			)
		}
	}
	return Outcome{
		Status: StatusAccepted,
		Code:   CodeAccepted,
		Changes: Changes{
			OriginScopes:        []OriginScope{context.scope},
			AuditCounters:       counters,
			Devices:             deviceChanges,
			VoterSet:            targets,
			CredentialAuthority: authorities,
		},
		Audit: audit,
	}, nil
}

func membershipOperatorOverride(subject string) *AuditDirective {
	return &AuditDirective{
		Class:   AuditOperatorOverride,
		Subject: subject,
	}
}

func deviceMembershipOverride(deviceID domain.DeviceID) *AuditDirective {
	return membershipOperatorOverride(
		fmt.Sprintf("device_membership:%s", deviceID),
	)
}

func voterSetMembershipOverride(sessionID domain.UUIDv7) *AuditDirective {
	return membershipOperatorOverride(
		fmt.Sprintf("voter_set:%s", sessionID),
	)
}

func decodeDeviceIDs(
	object payloadObject,
	field string,
) ([]domain.DeviceID, bool) {
	values, ok := decodeValue[[]string](object, field)
	if !ok {
		return nil, false
	}
	result := make([]domain.DeviceID, len(values))
	for index, value := range values {
		result[index] = domain.DeviceID(value)
	}
	return result, true
}

func activeOwnerCount(
	devices map[domain.DeviceID]device.Device,
	replacement *device.Device,
) int {
	count := 0
	for id, member := range devices {
		if replacement != nil && id == replacement.ID {
			member = *replacement
		}
		if member.Status == device.StatusActive &&
			member.Role == device.RoleOwner {
			count++
		}
	}
	return count
}
