package reducer

import (
	"github.com/ijonahch/codecomm/internal/domain"
	"github.com/ijonahch/codecomm/internal/domain/device"
)

func reduceMembershipVersionReported(
	context reductionContext,
) (Outcome, error) {
	payload, code := decodePayload(
		context.proposal.Payload,
		[]string{"daemon_version", "max_apply_level"},
		nil,
	)
	if code != "" {
		return context.reject(code), nil
	}
	daemonVersion, versionOK := decodeValue[string](payload, "daemon_version")
	maxApplyLevel, levelOK := decodeValue[uint64](payload, "max_apply_level")
	if !versionOK || !levelOK {
		return context.reject(CodeInvalidPayload), nil
	}

	subjectID := context.subjectDeviceID()
	if subjectID != context.proposal.Origin.DeviceID() {
		return context.reject(CodeMembershipSubjectMismatch), nil
	}
	current := context.device
	if current.ID != subjectID || current.Status != device.StatusActive {
		return Outcome{}, invalidState(
			"active origin device disagrees with version-report subject",
		)
	}
	expected := context.proposal.ExpectedEntityVersion
	if expected == nil || *expected != current.EntityVersion {
		return context.reject(CodeEntityVersionMismatch), nil
	}
	if current.EntityVersion == domain.MaxSafeInteger {
		return context.reject(CodeEntityVersionExhausted), nil
	}
	if maxApplyLevel <
		uint64(context.state.sessionPolicy.Values.ClusterMinApplyLevel) {
		return context.reject(CodeClusterApplyLevelUnsupported), nil
	}

	next := current
	next.DaemonVersion = daemonVersion
	next.MaxApplyLevel = maxApplyLevel
	next.EntityVersion++
	err := device.ValidateTransition(
		device.OperationVersionReport,
		&current,
		next,
	)
	if err != nil {
		if daemonVersion == current.DaemonVersion &&
			maxApplyLevel == current.MaxApplyLevel {
			return context.reject(CodeMembershipReportUnchanged), nil
		}
		return context.reject(CodeInvalidPayload), nil
	}
	return context.acceptMembership(
		[]device.Device{next},
		nil,
		nil,
		nil,
		nil,
	)
}
