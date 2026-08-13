package reducer

import (
	"fmt"

	"github.com/ijonahch/codecomm/internal/domain"
	"github.com/ijonahch/codecomm/internal/domain/plan"
)

func reducePlanCurrentSelected(
	context reductionContext,
) (Outcome, error) {
	payload, code := decodePayload(
		context.proposal.Payload,
		[]string{"plan_revision_id"},
		nil,
	)
	if code != "" {
		return context.reject(code), nil
	}
	revisionText, ok := decodeValue[string](payload, "plan_revision_id")
	if !ok {
		return context.reject(CodeInvalidPayload), nil
	}
	revisionID := domain.UUIDv7(revisionText)
	if !revisionID.Valid() {
		return context.reject(CodeInvalidPayload), nil
	}
	entityText, _ := context.proposal.EntityID.Value()
	if domain.UUIDv7(entityText) != context.state.sessionID {
		return context.reject(CodeSessionBindingMismatch), nil
	}

	current := context.state.planCurrent
	if err := context.state.validateCurrentPlanRow(current); err != nil {
		return Outcome{}, invalidState("current plan: %v", err)
	}
	expected := context.proposal.ExpectedEntityVersion
	if expected == nil || *expected != current.EntityVersion {
		return context.reject(CodeEntityVersionMismatch), nil
	}
	if current.EntityVersion == domain.MaxSafeInteger {
		return context.reject(CodeEntityVersionExhausted), nil
	}
	if _, exists := context.state.planRevisions[revisionID]; !exists {
		return context.reject(CodePlanRevisionNotFound), nil
	}
	if _, err := context.state.validateRetainedPlanRevision(
		revisionID,
	); err != nil {
		return Outcome{}, invalidState("%v", err)
	}

	next := plan.Current{
		SessionID:     current.SessionID,
		RevisionID:    revisionID,
		EntityVersion: current.EntityVersion + 1,
	}
	if err := plan.ValidateTransition(
		plan.OperationSelect,
		current,
		next,
	); err != nil {
		return Outcome{}, invalidState(
			"reducer produced invalid current-plan transition: %v",
			err,
		)
	}
	return context.acceptPlanCurrent(next, planOperatorOverride(current.SessionID))
}

func planOperatorOverride(sessionID domain.UUIDv7) *AuditDirective {
	return &AuditDirective{
		Class:   AuditOperatorOverride,
		Subject: fmt.Sprintf("plan_current:%s", sessionID),
	}
}
