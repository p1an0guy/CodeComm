package ipc

import "context"

// ClassRouter dispatches a mechanically validated bind to exactly one
// class-specific authority owner.
type ClassRouter struct {
	operator Binder
	agent    Binder
}

// NewClassRouter creates a router with at least one configured class.
func NewClassRouter(operator, agent Binder) (*ClassRouter, error) {
	if operator == nil && agent == nil {
		return nil, ErrBindRejected
	}
	return &ClassRouter{
		operator: operator,
		agent:    agent,
	}, nil
}

// Bind routes by the immutable class selected in the first request.
func (router *ClassRouter) Bind(
	ctx context.Context,
	peer VerifiedPeer,
	request BindRequest,
) (BindResult, error) {
	if router == nil {
		return BindResult{}, ErrBindRejected
	}
	var binder Binder
	switch request.Class {
	case ClassOperator:
		binder = router.operator
	case ClassAgent:
		binder = router.agent
	default:
		return BindResult{}, ErrBindRejected
	}
	if binder == nil {
		return BindResult{}, ErrBindRejected
	}
	return binder.Bind(ctx, peer, request)
}
