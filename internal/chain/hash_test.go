package chain_test

import (
	"errors"
	"testing"

	"github.com/ijonahch/codecomm/internal/chain"
)

func TestLineageGoldenVectors(t *testing.T) {
	t.Parallel()

	genesisBytes := []byte(
		`{"creator_signature":"AQ","recovery_generation":0,"session_id":"018f0000-0000-7000-8000-000000000001"}`,
	)
	genesis, err := chain.GenesisDigest(genesisBytes)
	if err != nil {
		t.Fatalf("GenesisDigest() error = %v", err)
	}
	assertDigest(
		t,
		"genesis",
		genesis,
		"5d5eb1f6cf4c7fd529a2b7b1a90497659a1718036ef3e2e4c3f06665a679e19f",
	)
	if want := manualDomainDigest(
		"codecomm/v1/genesis-digest",
		genesisBytes,
	); genesis != want {
		t.Fatalf("GenesisDigest() = %x, manual preimage = %x", genesis, want)
	}

	initial := chain.Boundary{Genesis: genesis}
	eventSeed, err := chain.EventSeed(initial)
	if err != nil {
		t.Fatalf("EventSeed(initial) error = %v", err)
	}
	assertDigest(
		t,
		"initial event seed",
		eventSeed,
		"088bf877ca057c112f0bffc4f9ef14b7887a249510dc90a2f6ac86322fa35c39",
	)
	if want := manualDomainDigest(
		"codecomm/v1/chain",
		genesis[:],
	); eventSeed != want {
		t.Fatalf("EventSeed(initial) = %x, manual preimage = %x", eventSeed, want)
	}

	resultSeed, err := chain.ResultSeed(initial)
	if err != nil {
		t.Fatalf("ResultSeed(initial) error = %v", err)
	}
	assertDigest(
		t,
		"initial result seed",
		resultSeed,
		"44a8a3c7b58724972a40b4c84747be9af351c7b9cf75dd4d3bbd9b9c4cef2732",
	)
	if want := manualDomainDigest(
		"codecomm/v1/result-chain",
		genesis[:],
	); resultSeed != want {
		t.Fatalf("ResultSeed(initial) = %x, manual preimage = %x", resultSeed, want)
	}

	event := []byte(
		`{"event_id":"018f0000-0000-7000-8000-000000000002","kind":"task.created","origin_signature":"AA","sequence":1}`,
	)
	eventHead, err := chain.AppendEvent(eventSeed, event)
	if err != nil {
		t.Fatalf("AppendEvent() error = %v", err)
	}
	assertDigest(
		t,
		"event append",
		eventHead,
		"87d2ccc07ca198d6b4b06303e79c8524d3356ec85ae66ffd1fc69492f6dde947",
	)
	if want := manualDomainDigest(
		"codecomm/v1/chain",
		eventSeed[:],
		event,
	); eventHead != want {
		t.Fatalf("AppendEvent() = %x, manual preimage = %x", eventHead, want)
	}

	successor := chain.Boundary{
		Genesis:     filledDigest(0x11),
		Generation:  2,
		ChainIndex:  7,
		ResultIndex: 11,
		ChainHash:   filledDigest(0x22),
		ResultHash:  filledDigest(0x33),
	}
	successorEvent, err := chain.EventSeed(successor)
	if err != nil {
		t.Fatalf("EventSeed(successor) error = %v", err)
	}
	assertDigest(
		t,
		"successor event seed",
		successorEvent,
		"f8644437091542fba647b09465158f6faf995b9ce3e2b35ea4ff7642f9f592ed",
	)
	if want := manualBoundarySeed("codecomm/v1/chain", successor); successorEvent != want {
		t.Fatalf("EventSeed(successor) = %x, manual preimage = %x", successorEvent, want)
	}

	successorResult, err := chain.ResultSeed(successor)
	if err != nil {
		t.Fatalf("ResultSeed(successor) error = %v", err)
	}
	assertDigest(
		t,
		"successor result seed",
		successorResult,
		"478c3934845c19c1a92ce70c274e0e402dd6deec190e19a8a9c7423bfbf6b38d",
	)
	if want := manualBoundarySeed(
		"codecomm/v1/result-chain",
		successor,
	); successorResult != want {
		t.Fatalf("ResultSeed(successor) = %x, manual preimage = %x", successorResult, want)
	}

	initialGenesis := filledDigest(0x44)
	initialState := filledDigest(0x55)
	initialAccumulator := chain.AccumulatorSeedInitial(initialGenesis, initialState)
	assertDigest(
		t,
		"initial accumulator seed",
		initialAccumulator,
		"15cacbdff45a41fc0b3932996be8fc09702430a4cf5aff8eba94aedd887ae045",
	)
	if want := manualDomainDigest(
		"codecomm/v1/projection-accumulator",
		initialGenesis[:],
		initialState[:],
	); initialAccumulator != want {
		t.Fatalf(
			"AccumulatorSeedInitial() = %x, manual preimage = %x",
			initialAccumulator,
			want,
		)
	}

	previousAccumulator := filledDigest(0x66)
	successorGenesis := filledDigest(0x77)
	transformedState := filledDigest(0x88)
	successorAccumulator := chain.AccumulatorSeedSuccessor(
		previousAccumulator,
		successorGenesis,
		transformedState,
	)
	assertDigest(
		t,
		"successor accumulator seed",
		successorAccumulator,
		"e46321d3612a6e0fa202c10208cb0d3847b6723e2fc496145a991ed7fbc004a3",
	)
	if want := manualDomainDigest(
		"codecomm/v1/projection-accumulator",
		previousAccumulator[:],
		successorGenesis[:],
		transformedState[:],
	); successorAccumulator != want {
		t.Fatalf(
			"AccumulatorSeedSuccessor() = %x, manual preimage = %x",
			successorAccumulator,
			want,
		)
	}
}

func TestLineageRejectsInvalidInputs(t *testing.T) {
	t.Parallel()

	for _, input := range [][]byte{
		[]byte(`{"z":1,"a":2}`),
		[]byte(`[1,2,3]`),
		[]byte(`{"value":1.5}`),
		nil,
	} {
		if _, err := chain.GenesisDigest(input); !errors.Is(err, chain.ErrInvalidObject) {
			t.Errorf("GenesisDigest(%q) error = %v, want ErrInvalidObject", input, err)
		}
		if _, err := chain.AppendEvent(chain.Digest{}, input); !errors.Is(
			err,
			chain.ErrInvalidObject,
		) {
			t.Errorf("AppendEvent(%q) error = %v, want ErrInvalidObject", input, err)
		}
	}

	tests := []chain.Boundary{
		{Generation: 0, ChainIndex: 1},
		{Generation: 0, ChainHash: filledDigest(1)},
		{Generation: 1, ChainIndex: 2, ResultIndex: 1},
		{Generation: 1},
		{
			Generation: 1,
			ChainHash:  filledDigest(1),
		},
		{
			Generation: 1,
			ResultHash: filledDigest(1),
		},
		{Generation: 1 << 53},
		{
			Generation:  1,
			ChainIndex:  1 << 53,
			ResultIndex: 1 << 53,
			ChainHash:   filledDigest(1),
			ResultHash:  filledDigest(2),
		},
	}
	for _, boundary := range tests {
		if _, err := chain.EventSeed(boundary); !errors.Is(err, chain.ErrInvalidBoundary) {
			t.Errorf("EventSeed(%+v) error = %v, want ErrInvalidBoundary", boundary, err)
		}
		if _, err := chain.ResultSeed(boundary); !errors.Is(err, chain.ErrInvalidBoundary) {
			t.Errorf("ResultSeed(%+v) error = %v, want ErrInvalidBoundary", boundary, err)
		}
	}
}

func manualBoundarySeed(label string, boundary chain.Boundary) chain.Digest {
	return manualDomainDigest(
		label,
		boundary.Genesis[:],
		testUint64(boundary.Generation),
		testUint64(boundary.ChainIndex),
		boundary.ChainHash[:],
		testUint64(boundary.ResultIndex),
		boundary.ResultHash[:],
	)
}
