package reducer

import (
	"unicode/utf8"

	"github.com/ijonahch/codecomm/internal/domain"
	"github.com/ijonahch/codecomm/internal/domain/auditcounter"
	"github.com/ijonahch/codecomm/internal/domain/device"
)

const (
	CodeAuditSubjectNotFound         Code = "audit_subject_not_found"
	CodeAuditSubjectNotActive        Code = "audit_subject_not_active"
	CodeAuditCredentialEpochMismatch Code = "audit_credential_epoch_mismatch"
	CodeAuditDepthExceeded           Code = "audit_depth_exceeded"
)

func reduceAuditRecorded(context reductionContext) (Outcome, error) {
	counter, directive, code, err := prepareAuditRecorded(context)
	if err != nil {
		return Outcome{}, err
	}
	if code != "" {
		return context.reject(code), nil
	}
	if err := counter.Validate(); err != nil {
		return Outcome{}, invalidState(
			"reducer produced invalid audit counter: %v",
			err,
		)
	}
	return Outcome{
		Status: StatusAccepted,
		Code:   CodeAccepted,
		Changes: Changes{
			OriginScopes:  []OriginScope{context.scope},
			AuditCounters: []auditcounter.Counter{counter},
		},
		RecordedAudit: &directive,
	}, nil
}

// AuditRecordedDirective is the validated explicit rejection-audit payload.
// Event identity, result position, reporter actor, and apply time are supplied
// by the apply layer.
type AuditRecordedDirective struct {
	ReporterDeviceID       domain.DeviceID
	SubjectDeviceID        domain.DeviceID
	SubjectCredentialEpoch uint64
	ActionCode             string
	OutcomeCode            string
	Subject                string
}

func prepareAuditRecorded(
	context reductionContext,
) (
	auditcounter.Counter,
	AuditRecordedDirective,
	Code,
	error,
) {
	payload, code := decodePayload(
		context.proposal.Payload,
		[]string{
			"action",
			"outcome",
			"subject",
			"subject_device_id",
			"subject_credential_epoch",
		},
		nil,
	)
	if code != "" {
		return auditcounter.Counter{}, AuditRecordedDirective{}, code, nil
	}
	action, actionOK := decodeValue[string](payload, "action")
	outcome, outcomeOK := decodeValue[string](payload, "outcome")
	subject, subjectOK := decodeValue[string](payload, "subject")
	subjectDeviceText, deviceOK := decodeValue[string](
		payload,
		"subject_device_id",
	)
	subjectEpoch, epochOK := decodeValue[uint64](
		payload,
		"subject_credential_epoch",
	)
	subjectDeviceID := domain.DeviceID(subjectDeviceText)
	if !actionOK || !outcomeOK || !subjectOK || !deviceOK || !epochOK ||
		!validAuditCode(action) || !validAuditCode(outcome) ||
		len(subject) > 256 || !utf8.ValidString(subject) ||
		!subjectDeviceID.Valid() ||
		!domain.ValidUnsignedInteger(subjectEpoch) {
		return auditcounter.Counter{},
			AuditRecordedDirective{},
			CodeInvalidPayload,
			nil
	}

	member, exists := context.state.devices[subjectDeviceID]
	if !exists {
		return auditcounter.Counter{},
			AuditRecordedDirective{},
			CodeAuditSubjectNotFound,
			nil
	}
	if member.Status != device.StatusActive {
		return auditcounter.Counter{},
			AuditRecordedDirective{},
			CodeAuditSubjectNotActive,
			nil
	}
	counter, exists := context.state.auditCounters[subjectDeviceID]
	if !exists || counter.DeviceID != subjectDeviceID {
		return auditcounter.Counter{},
			AuditRecordedDirective{},
			"",
			invalidState(
				"active audit subject %q has no matching counter",
				subjectDeviceID,
			)
	}
	if counter.CredentialEpoch != subjectEpoch {
		return auditcounter.Counter{},
			AuditRecordedDirective{},
			CodeAuditCredentialEpochMismatch,
			nil
	}
	depth := context.state.sessionPolicy.Values.
		AuditDepthPerDevicePerEpoch
	if depth < 1 ||
		uint64(depth) > auditcounter.MaxAcceptedCount {
		return auditcounter.Counter{},
			AuditRecordedDirective{},
			"",
			invalidState("audit-depth policy is outside the hard bound")
	}
	if counter.AcceptedCount >= uint64(depth) {
		return auditcounter.Counter{},
			AuditRecordedDirective{},
			CodeAuditDepthExceeded,
			nil
	}
	counter.AcceptedCount++
	return counter, AuditRecordedDirective{
		ReporterDeviceID:       context.device.ID,
		SubjectDeviceID:        subjectDeviceID,
		SubjectCredentialEpoch: subjectEpoch,
		ActionCode:             action,
		OutcomeCode:            outcome,
		Subject:                subject,
	}, "", nil
}

func validAuditCode(value string) bool {
	if len(value) < 1 || len(value) > 64 {
		return false
	}
	for index := range len(value) {
		character := value[index]
		if character >= 'A' && character <= 'Z' ||
			character >= 'a' && character <= 'z' ||
			character >= '0' && character <= '9' ||
			character == '.' ||
			character == '_' ||
			character == ':' ||
			character == '-' {
			continue
		}
		return false
	}
	return true
}
