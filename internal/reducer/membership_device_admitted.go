package reducer

import (
	"bytes"
	"crypto/ed25519"

	"github.com/ijonahch/codecomm/internal/codec"
	"github.com/ijonahch/codecomm/internal/domain"
	"github.com/ijonahch/codecomm/internal/domain/auditcounter"
	"github.com/ijonahch/codecomm/internal/domain/device"
)

func reduceMembershipDeviceAdmitted(
	context reductionContext,
) (Outcome, error) {
	payload, code := decodePayload(
		context.proposal.Payload,
		[]string{
			"identity_public_key",
			"role",
			"daemon_version",
			"max_apply_level",
			"initial_epoch_binding",
		},
		nil,
	)
	if code != "" {
		return context.reject(code), nil
	}
	publicKeyText, keyOK := decodeValue[string](
		payload,
		"identity_public_key",
	)
	roleText, roleOK := decodeValue[string](payload, "role")
	daemonVersion, versionOK := decodeValue[string](
		payload,
		"daemon_version",
	)
	maxApplyLevel, levelOK := decodeValue[uint64](
		payload,
		"max_apply_level",
	)
	publicKey, keyErr := codec.DecodeBase64URLExact(
		publicKeyText,
		ed25519.PublicKeySize,
	)
	role := device.Role(roleText)
	if !keyOK || keyErr != nil ||
		!roleOK || !role.Valid() ||
		!versionOK || !levelOK {
		return context.reject(CodeInvalidPayload), nil
	}

	subjectID := context.subjectDeviceID()
	derivedID, err := device.DeriveID(publicKey)
	if err != nil || derivedID != subjectID {
		return context.reject(CodeMembershipSubjectMismatch), nil
	}
	if _, valid := decodeInitialEpochBinding(
		payload["initial_epoch_binding"],
		context.state.sessionID,
		subjectID,
		publicKey,
	); !valid {
		return context.reject(CodeInvalidPayload), nil
	}
	if maxApplyLevel <
		uint64(context.state.sessionPolicy.Values.ClusterMinApplyLevel) {
		return context.reject(CodeClusterApplyLevelUnsupported), nil
	}

	current, exists := context.state.devices[subjectID]
	var operation device.Operation
	var counters []auditcounter.Counter
	var next device.Device
	if !exists {
		if context.proposal.ExpectedEntityVersion != nil {
			return context.reject(CodeExpectedEntityVersion), nil
		}
		operation = device.OperationAdmission
		next = device.Device{
			ID:                subjectID,
			Role:              role,
			IdentityPublicKey: bytes.Clone(publicKey),
			DaemonVersion:     daemonVersion,
			MaxApplyLevel:     maxApplyLevel,
			Status:            device.StatusActive,
			EntityVersion:     1,
		}
		counters = []auditcounter.Counter{{DeviceID: subjectID}}
	} else {
		if current.Status != device.StatusRequiresReadmission {
			return context.reject(CodeEntityAlreadyExists), nil
		}
		expected := context.proposal.ExpectedEntityVersion
		if expected == nil || *expected != current.EntityVersion {
			return context.reject(CodeEntityVersionMismatch), nil
		}
		if current.EntityVersion == domain.MaxSafeInteger {
			return context.reject(CodeEntityVersionExhausted), nil
		}
		if !bytes.Equal(current.IdentityPublicKey, publicKey) {
			return context.reject(CodeInvalidMembershipTransition), nil
		}
		operation = device.OperationReadmission
		next = current
		next.Role = role
		next.DaemonVersion = daemonVersion
		next.MaxApplyLevel = maxApplyLevel
		next.Status = device.StatusActive
		next.EntityVersion++
	}
	activeMembers := int64(0)
	for _, member := range context.state.devices {
		if member.Status == device.StatusActive {
			activeMembers++
		}
	}
	if activeMembers+1 >
		context.state.sessionPolicy.Values.MaxMemberDevices {
		return context.reject(CodeMemberLimitReached), nil
	}
	if err := device.ValidateTransition(operation, currentDevice(exists, current), next); err != nil {
		return context.reject(CodeInvalidPayload), nil
	}
	return context.acceptMembership(
		[]device.Device{next},
		counters,
		nil,
		nil,
		deviceMembershipOverride(subjectID),
	)
}

func currentDevice(exists bool, current device.Device) *device.Device {
	if !exists {
		return nil
	}
	return &current
}
