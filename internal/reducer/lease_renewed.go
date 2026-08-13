package reducer

import "github.com/ijonahch/codecomm/internal/domain/lease"

func reduceLeaseRenewed(context reductionContext) (Outcome, error) {
	payload, code := decodePayload(
		context.proposal.Payload,
		[]string{"ttl_seconds"},
		nil,
	)
	if code != "" {
		return context.reject(code), nil
	}
	ttl, ok := decodeValue[int64](payload, "ttl_seconds")
	if !ok {
		return context.reject(CodeInvalidPayload), nil
	}

	current, outcome, done, err := loadMutableLease(context)
	if err != nil || done {
		return outcome, err
	}
	if !leaseHeldByOrigin(current, context) {
		return context.reject(CodeLeaseHolderRequired), nil
	}
	if _, code, err := validateLeaseTTL(context, ttl); err != nil {
		return Outcome{}, err
	} else if code != "" {
		return context.reject(code), nil
	}
	if err := lease.ValidateTransition(
		lease.OperationRenew,
		current.Lifecycle(),
		lease.Lifecycle{Status: lease.StatusActive},
	); err != nil {
		return context.reject(CodeInvalidLeaseTransition), nil
	}

	next := current
	next.TTLSeconds = ttl
	next.EntityVersion++
	return context.acceptLease(next, nil)
}
