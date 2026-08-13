package ipc

import (
	"context"
	"errors"
	"net/http"
	"testing"
)

func TestClassRouterDispatchesExactlyOneConfiguredBinder(t *testing.T) {
	operatorCalls := 0
	agentCalls := 0
	operator := BinderFunc(func(
		context.Context,
		VerifiedPeer,
		BindRequest,
	) (BindResult, error) {
		operatorCalls++
		return NewOperatorBindResult(routerBoundClient{})
	})
	agent := BinderFunc(func(
		context.Context,
		VerifiedPeer,
		BindRequest,
	) (BindResult, error) {
		agentCalls++
		return NewAgentResumeBindResult(routerBoundClient{})
	})
	router, err := NewClassRouter(operator, agent)
	if err != nil {
		t.Fatalf("NewClassRouter(): %v", err)
	}

	for _, class := range []ClientClass{ClassOperator, ClassAgent} {
		request := BindRequest{Class: class}
		result, err := router.Bind(context.Background(), VerifiedPeer{}, request)
		if err != nil {
			t.Fatalf("Bind(%s): %v", class, err)
		}
		if _, _, ok := consumeBindResult(result, class); !ok {
			t.Fatalf("Bind(%s) returned incompatible result", class)
		}
	}
	if operatorCalls != 1 || agentCalls != 1 {
		t.Fatalf(
			"binder calls = operator %d, agent %d; want 1 each",
			operatorCalls,
			agentCalls,
		)
	}
}

func TestClassRouterRejectsMissingBinderAndUnknownClass(t *testing.T) {
	binder := BinderFunc(func(
		context.Context,
		VerifiedPeer,
		BindRequest,
	) (BindResult, error) {
		return BindResult{}, errors.New("must not be called")
	})
	for _, test := range []struct {
		name     string
		operator Binder
		agent    Binder
		class    ClientClass
	}{
		{name: "missing operator", agent: binder, class: ClassOperator},
		{name: "missing agent", operator: binder, class: ClassAgent},
		{
			name:     "unknown class",
			operator: binder,
			agent:    binder,
			class:    ClientClass(99),
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			router, err := NewClassRouter(test.operator, test.agent)
			if err != nil {
				t.Fatalf("NewClassRouter(): %v", err)
			}
			if _, err := router.Bind(
				context.Background(),
				VerifiedPeer{},
				BindRequest{Class: test.class},
			); !errors.Is(err, ErrBindRejected) {
				t.Fatalf("Bind() error = %v, want %v", err, ErrBindRejected)
			}
		})
	}
}

func TestClassRouterRequiresAtLeastOneBinder(t *testing.T) {
	if _, err := NewClassRouter(nil, nil); !errors.Is(
		err,
		ErrBindRejected,
	) {
		t.Fatalf("NewClassRouter(nil, nil) error = %v, want %v", err, ErrBindRejected)
	}
}

type routerBoundClient struct{}

func (routerBoundClient) Handler() http.Handler {
	return http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})
}

func (routerBoundClient) Disconnected(context.Context) {}
