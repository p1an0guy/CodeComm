package reducer

import "github.com/ijonahch/codecomm/internal/domain/publication"

func reducePublicationWithdrawn(
	context reductionContext,
) (Outcome, error) {
	payload, code := decodePayload(
		context.proposal.Payload,
		nil,
		[]string{"reason"},
	)
	if code != "" {
		return context.reject(code), nil
	}
	var reason *string
	if _, present := payload["reason"]; present {
		value, ok := decodeValue[string](payload, "reason")
		if !ok {
			return context.reject(CodeInvalidPayload), nil
		}
		reason = &value
	}
	current, outcome, done, err := loadMutablePublication(context)
	if err != nil || done {
		return outcome, err
	}
	if !publicationWithdrawalAuthorized(context, current) {
		return context.reject(CodePublicationWithdrawalNotAuthorized), nil
	}

	next := clonePublication(current)
	next.State = publication.StateWithdrawn
	next.TerminalSource = publication.TerminalSourceWithdraw
	next.DecisionReason = reason
	next.EntityVersion++
	if err := publication.ValidateTransition(
		publication.OperationWithdraw,
		current,
		next,
	); err != nil {
		if next.Validate() != nil {
			return context.reject(CodeInvalidPayload), nil
		}
		return context.reject(CodeInvalidPublicationTransition), nil
	}
	return context.acceptPublication(next, nil)
}
