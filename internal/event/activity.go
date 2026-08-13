package event

import (
	"errors"
	"fmt"
	"strings"
	"unicode"
	"unicode/utf8"

	codecommcrypto "github.com/ijonahch/codecomm/internal/crypto"
	"github.com/ijonahch/codecomm/internal/domain"
)

const (
	MaxRationaleSummaryBytes = 2048
	MaxActions               = 64
	MaxActionTargetBytes     = 256
	MaxActionSummaryBytes    = 1024
	MaxActivityDurationMS    = 604_800_000
)

var (
	ErrInvalidAction    = errors.New("event: invalid action")
	ErrInvalidRedaction = errors.New("event: invalid redaction")
)

// SHA256Digest is the fixed-width digest used by action artifact references.
type SHA256Digest = codecommcrypto.SHA256Digest

// CaptureLevel records how an activity report was obtained.
type CaptureLevel string

const (
	CaptureAgentReported  CaptureLevel = "agent_reported"
	CaptureHumanReported  CaptureLevel = "human_reported"
	CaptureDaemonObserved CaptureLevel = "daemon_observed"
)

// Valid reports whether level is in the closed V1 namespace.
func (level CaptureLevel) Valid() bool {
	return level == CaptureAgentReported ||
		level == CaptureHumanReported ||
		level == CaptureDaemonObserved
}

func captureLevelForActor(actor ActorType) CaptureLevel {
	switch actor {
	case ActorAgent:
		return CaptureAgentReported
	case ActorHuman:
		return CaptureHumanReported
	case ActorDaemon:
		return CaptureDaemonObserved
	default:
		return ""
	}
}

// ActionType is a redacted activity operation class.
type ActionType string

const (
	ActionFileRead         ActionType = "file.read"
	ActionFileEdit         ActionType = "file.edit"
	ActionCommandRun       ActionType = "command.run"
	ActionToolCall         ActionType = "tool.call"
	ActionTestRun          ActionType = "test.run"
	ActionDecisionRecorded ActionType = "decision.recorded"
	ActionArtifactCreated  ActionType = "artifact.created"
)

// Valid reports whether actionType is in the closed V1 namespace.
func (actionType ActionType) Valid() bool {
	switch actionType {
	case ActionFileRead,
		ActionFileEdit,
		ActionCommandRun,
		ActionToolCall,
		ActionTestRun,
		ActionDecisionRecorded,
		ActionArtifactCreated:
		return true
	default:
		return false
	}
}

// ActionStatus is the reported result of an activity action.
type ActionStatus string

const (
	ActionAttempted ActionStatus = "attempted"
	ActionSucceeded ActionStatus = "succeeded"
	ActionFailed    ActionStatus = "failed"
	ActionSkipped   ActionStatus = "skipped"
)

// Valid reports whether status is in the closed V1 namespace.
func (status ActionStatus) Valid() bool {
	return status == ActionAttempted ||
		status == ActionSucceeded ||
		status == ActionFailed ||
		status == ActionSkipped
}

// Action is one bounded, redacted activity entry. Raw arguments, environment,
// output, and private reasoning have no fields in this schema.
type Action struct {
	Type           ActionType
	Target         string
	Summary        string
	Status         ActionStatus
	TaskID         *domain.UUIDv7
	ArtifactDigest *SHA256Digest
	StartedAt      *domain.Timestamp
	DurationMS     *uint64
}

// Validate verifies the complete closed action schema.
func (action Action) Validate() error {
	if !action.Type.Valid() {
		return fmt.Errorf("%w: type %q", ErrInvalidAction, action.Type)
	}
	if !validActionTarget(action.Type, action.Target) {
		return fmt.Errorf("%w: target for %q", ErrInvalidAction, action.Type)
	}
	if !validText(action.Summary, 1, MaxActionSummaryBytes, true) {
		return fmt.Errorf("%w: summary", ErrInvalidAction)
	}
	if !action.Status.Valid() {
		return fmt.Errorf("%w: status %q", ErrInvalidAction, action.Status)
	}
	if action.TaskID != nil && !action.TaskID.Valid() {
		return fmt.Errorf("%w: task_id %q", ErrInvalidAction, *action.TaskID)
	}
	if action.StartedAt != nil && !action.StartedAt.Valid() {
		return fmt.Errorf("%w: started_at %q", ErrInvalidAction, *action.StartedAt)
	}
	if action.DurationMS != nil && *action.DurationMS > MaxActivityDurationMS {
		return fmt.Errorf(
			"%w: duration_ms %d exceeds %d",
			ErrInvalidAction,
			*action.DurationMS,
			MaxActivityDurationMS,
		)
	}
	return nil
}

func validActionTarget(actionType ActionType, target string) bool {
	switch actionType {
	case ActionFileRead, ActionFileEdit:
		return domain.RepositoryPath(target).Valid()
	case ActionCommandRun:
		return validASCIIIdentifier(target, 128, "._+-")
	case ActionToolCall:
		return validASCIIIdentifier(target, 128, "._:-")
	case ActionTestRun:
		return validText(target, 1, MaxActionTargetBytes, true)
	case ActionDecisionRecorded:
		return validText(target, 1, 128, true)
	case ActionArtifactCreated:
		return domain.RepositoryPath(target).Valid() || validArtifactClass(target)
	default:
		return false
	}
}

func validASCIIIdentifier(value string, maxBytes int, punctuation string) bool {
	if len(value) < 1 || len(value) > maxBytes || !isASCIIAlphaNumeric(value[0]) {
		return false
	}
	for index := 1; index < len(value); index++ {
		if !isASCIIAlphaNumeric(value[index]) &&
			!strings.ContainsRune(punctuation, rune(value[index])) {
			return false
		}
	}
	return true
}

func validArtifactClass(value string) bool {
	const prefix = "class:"
	if !strings.HasPrefix(value, prefix) {
		return false
	}
	class := value[len(prefix):]
	return validASCIIIdentifier(class, 64, "._-")
}

func isASCIIAlphaNumeric(char byte) bool {
	return char >= 'A' && char <= 'Z' ||
		char >= 'a' && char <= 'z' ||
		char >= '0' && char <= '9'
}

func validText(value string, minBytes, maxBytes int, rejectControls bool) bool {
	if len(value) < minBytes || len(value) > maxBytes || !utf8.ValidString(value) {
		return false
	}
	if rejectControls {
		for _, char := range value {
			if unicode.IsControl(char) {
				return false
			}
		}
	}
	return true
}

// RedactionPolicy is the closed policy identifier carried by V1 events.
type RedactionPolicy string

const RedactionDefault RedactionPolicy = "default"

// RedactionField reports one category omitted before event construction.
type RedactionField string

const (
	RedactionArguments        RedactionField = "arguments"
	RedactionEnvironment      RedactionField = "environment"
	RedactionOutput           RedactionField = "output"
	RedactionPrivateReasoning RedactionField = "private_reasoning"
	RedactionSecret           RedactionField = "secret"
	RedactionSensitiveValue   RedactionField = "sensitive_value"
)

// Valid reports whether field is in the closed V1 namespace.
func (field RedactionField) Valid() bool {
	switch field {
	case RedactionArguments,
		RedactionEnvironment,
		RedactionOutput,
		RedactionPrivateReasoning,
		RedactionSecret,
		RedactionSensitiveValue:
		return true
	default:
		return false
	}
}

// Redaction declares omitted categories without carrying their values.
type Redaction struct {
	Policy        RedactionPolicy
	FieldsRemoved []RedactionField
}

// Validate requires the exact V1 policy and a sorted unique closed subset.
func (redaction Redaction) Validate() error {
	if redaction.Policy != RedactionDefault || redaction.FieldsRemoved == nil {
		return ErrInvalidRedaction
	}
	var previous RedactionField
	for index, field := range redaction.FieldsRemoved {
		if !field.Valid() || index > 0 && field <= previous {
			return fmt.Errorf("%w: fields_removed", ErrInvalidRedaction)
		}
		previous = field
	}
	return nil
}
