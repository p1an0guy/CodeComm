package main

import (
	"bytes"
	"context"
	"errors"
	"testing"

	"github.com/ijonahch/codecomm/internal/consensus"
	"github.com/ijonahch/codecomm/internal/domain"
	"github.com/ijonahch/codecomm/internal/event"
	"github.com/ijonahch/codecomm/internal/store"
)

type daemonProposalForwarderStub struct {
	calls  int
	target domain.DeviceID
	signed []byte
	result consensus.ForwardedProposalResult
	err    error
}

func (stub *daemonProposalForwarderStub) ForwardProposal(
	_ context.Context,
	target domain.DeviceID,
	signed event.SignedEvent,
) (consensus.ForwardedProposalResult, error) {
	stub.calls++
	stub.target = target
	stub.signed = signed.CanonicalBytes()
	return stub.result, stub.err
}

func TestDaemonProposalForwarderRelayBindsOnceAndDelegatesExactly(t *testing.T) {
	_, privateKey, deviceID := daemonTestInitialState(t)
	defer clear(privateKey)
	signed := daemonTestTaskEvent(t, privateKey, deviceID)
	target := daemonContentTestDeviceID(t, 0xda)
	chainIndex := uint64(1)
	chainHash := store.Digest{1}
	result := consensus.ForwardedProposalResult{
		Outcome: store.CommandOutcome{
			Status: store.OutcomeAccepted,
			Code:   "accepted",
			JSON:   []byte(`{"code":"accepted","status":"accepted"}`),
		},
		ResultIndex: 1,
		ChainIndex:  &chainIndex,
		ChainHash:   &chainHash,
	}
	delegate := &daemonProposalForwarderStub{result: result}
	relay := &daemonProposalForwarderRelay{}

	if _, err := relay.ForwardProposal(
		context.Background(),
		target,
		signed,
	); !errors.Is(err, errDaemonProposalForwarderUnavailable) {
		t.Fatalf("unbound ForwardProposal() error = %v", err)
	}
	if err := relay.set(nil); !errors.Is(
		err,
		errDaemonProposalForwarderUnavailable,
	) {
		t.Fatalf("set(nil) error = %v", err)
	}
	if err := relay.set(delegate); err != nil {
		t.Fatalf("set(delegate): %v", err)
	}
	if err := relay.set(&daemonProposalForwarderStub{}); !errors.Is(
		err,
		errDaemonProposalForwarderUnavailable,
	) {
		t.Fatalf("second set error = %v", err)
	}

	got, err := relay.ForwardProposal(
		context.Background(),
		target,
		signed,
	)
	if err != nil {
		t.Fatalf("ForwardProposal(): %v", err)
	}
	if got.Outcome.Status != result.Outcome.Status ||
		got.Outcome.Code != result.Outcome.Code ||
		!bytes.Equal(got.Outcome.JSON, result.Outcome.JSON) ||
		got.ResultIndex != result.ResultIndex ||
		got.ChainIndex == nil ||
		*got.ChainIndex != chainIndex ||
		got.ChainHash == nil ||
		*got.ChainHash != chainHash ||
		delegate.calls != 1 ||
		delegate.target != target ||
		!bytes.Equal(delegate.signed, signed.CanonicalBytes()) {
		t.Fatalf(
			"delegated result/call = (%+v, %d, %s, %q)",
			got,
			delegate.calls,
			delegate.target,
			delegate.signed,
		)
	}

	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := relay.ForwardProposal(
		canceled,
		target,
		signed,
	); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled ForwardProposal() error = %v", err)
	}
	if delegate.calls != 1 {
		t.Fatal("canceled proposal reached delegate")
	}
}

func TestDaemonProposalForwarderRelayRejectsNilReceiverAndContext(
	t *testing.T,
) {
	var relay *daemonProposalForwarderRelay
	if _, err := relay.ForwardProposal(
		context.Background(),
		"",
		event.SignedEvent{},
	); !errors.Is(err, errDaemonProposalForwarderUnavailable) {
		t.Fatalf("nil relay error = %v", err)
	}
	relay = &daemonProposalForwarderRelay{}
	//lint:ignore SA1012 This test verifies the explicit nil-context contract.
	if _, err := relay.ForwardProposal(nil, "", event.SignedEvent{}); !errors.Is(
		err,
		errDaemonProposalForwarderUnavailable,
	) {
		t.Fatalf("nil context error = %v", err)
	}
}
