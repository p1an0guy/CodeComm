package store

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"path/filepath"
	"testing"

	"github.com/ijonahch/codecomm/internal/chain"
	"github.com/ijonahch/codecomm/internal/domain"
	"github.com/ijonahch/codecomm/internal/domain/voterset"
	"github.com/ijonahch/codecomm/internal/replication"
)

func TestExportResultRangeReturnsVerifiedContiguousRecords(t *testing.T) {
	fixture := newResultRangeFixture(t)

	got, found, err := fixture.store.ExportResultRange(
		context.Background(),
		ResultRangeOptions{
			AfterResultIndex: fixture.initial.ResultIndex,
			MaxResults:       MaxResultRangeItems,
			MaxBytes:         MaxResultRangeBytes,
		},
	)
	if err != nil {
		t.Fatalf("ExportResultRange() error = %v", err)
	}
	if !found {
		t.Fatal("ExportResultRange() found = false")
	}
	if got.SessionID != domain.UUIDv7(testSessionID) ||
		got.WorkspaceID != testWorkspaceID ||
		got.RecoveryGeneration != 0 ||
		got.FromResultIndex != fixture.initial.ResultIndex+1 ||
		got.ToResultIndex != fixture.second.Heads.ResultIndex ||
		got.ServerAppliedResultIndex != fixture.second.Heads.ResultIndex {
		t.Fatalf("ExportResultRange() identity/range = %+v", got)
	}
	if got.StartResultHash != fixture.initial.ResultHash ||
		got.EndResultHash != fixture.second.Heads.ResultHash ||
		got.StartChainIndex != fixture.initial.ChainIndex ||
		got.StartChainHash != fixture.initial.ChainHash ||
		got.EndChainIndex != fixture.second.Heads.ChainIndex ||
		got.EndChainHash != fixture.second.Heads.ChainHash {
		t.Fatalf(
			"ExportResultRange() heads = start (%d,%x;%x), end (%d,%x;%x)",
			got.StartChainIndex,
			got.StartChainHash,
			got.StartResultHash,
			got.EndChainIndex,
			got.EndChainHash,
			got.EndResultHash,
		)
	}
	if len(got.Results) != 2 {
		t.Fatalf("len(Results) = %d, want 2", len(got.Results))
	}
	first, err := chain.DecodeResult(got.Results[0])
	if err != nil {
		t.Fatalf("DecodeResult(first): %v", err)
	}
	second, err := chain.DecodeResult(got.Results[1])
	if err != nil {
		t.Fatalf("DecodeResult(second): %v", err)
	}
	if first.ResultIndex != fixture.first.Heads.ResultIndex ||
		first.ChainIndex == nil ||
		*first.ChainIndex != fixture.first.Heads.ChainIndex ||
		second.ResultIndex != fixture.second.Heads.ResultIndex ||
		second.ChainIndex != nil ||
		second.ChainHash != nil {
		t.Fatalf("decoded range = first %+v, second %+v", first, second)
	}
	if got.Authority.VoterSetVersion != 1 ||
		!got.Authority.Contains(fixture.authorityDeviceID) {
		t.Fatalf("range authority = %+v", got.Authority)
	}

	pristine := bytes.Clone(got.Results[0])
	got.Results[0][0] ^= 0xff
	again, found, err := fixture.store.ExportResultRange(
		context.Background(),
		ResultRangeOptions{
			AfterResultIndex: fixture.initial.ResultIndex,
			MaxResults:       MaxResultRangeItems,
			MaxBytes:         MaxResultRangeBytes,
		},
	)
	if err != nil || !found || !bytes.Equal(again.Results[0], pristine) {
		t.Fatalf(
			"ExportResultRange(after caller mutation) = found %t, err %v",
			found,
			err,
		)
	}
}

func TestExportResultRangeStartsAtExactResultCursor(t *testing.T) {
	fixture := newResultRangeFixture(t)

	got, found, err := fixture.store.ExportResultRange(
		context.Background(),
		ResultRangeOptions{
			AfterResultIndex: fixture.first.Heads.ResultIndex,
			MaxResults:       MaxResultRangeItems,
			MaxBytes:         MaxResultRangeBytes,
		},
	)
	if err != nil || !found {
		t.Fatalf("ExportResultRange(after first) = found %t, err %v", found, err)
	}
	if got.FromResultIndex != fixture.second.Heads.ResultIndex ||
		got.ToResultIndex != fixture.second.Heads.ResultIndex ||
		got.StartResultHash != fixture.first.Heads.ResultHash ||
		got.StartChainIndex != fixture.first.Heads.ChainIndex ||
		got.StartChainHash != fixture.first.Heads.ChainHash ||
		got.EndChainIndex != fixture.first.Heads.ChainIndex ||
		got.EndChainHash != fixture.first.Heads.ChainHash ||
		len(got.Results) != 1 {
		t.Fatalf("ExportResultRange(after first) = %+v", got)
	}

	empty, found, err := fixture.store.ExportResultRange(
		context.Background(),
		ResultRangeOptions{
			AfterResultIndex: fixture.second.Heads.ResultIndex,
			MaxResults:       MaxResultRangeItems,
			MaxBytes:         MaxResultRangeBytes,
		},
	)
	if err != nil {
		t.Fatalf("ExportResultRange(at head) error = %v", err)
	}
	if found || len(empty.Results) != 0 {
		t.Fatalf("ExportResultRange(at head) = %+v, true; want zero, false", empty)
	}
}

func TestExportResultRangeBuildsVerifiableSignedBatch(t *testing.T) {
	fixture := newResultRangeFixture(t)
	exported, found, err := fixture.store.ExportResultRange(
		context.Background(),
		ResultRangeOptions{
			AfterResultIndex: fixture.initial.ResultIndex,
			MaxResults:       replication.MaxBatchResults,
			MaxBytes:         replication.MaxBatchExpandedBytes - 2<<10,
		},
	)
	if err != nil || !found {
		t.Fatalf("ExportResultRange() = found %t, err %v", found, err)
	}
	if !exported.Authority.Contains(fixture.authorityDeviceID) {
		t.Fatal("exported end authority does not authorize the signer")
	}
	unsigned, err := replication.NewUnsignedBatch(
		replication.BatchInput{
			FromResultIndex:          exported.FromResultIndex,
			ToResultIndex:            exported.ToResultIndex,
			StartResultHash:          chain.Digest(exported.StartResultHash),
			EndResultHash:            chain.Digest(exported.EndResultHash),
			StartChainIndex:          exported.StartChainIndex,
			StartChainHash:           chain.Digest(exported.StartChainHash),
			EndChainIndex:            exported.EndChainIndex,
			EndChainHash:             chain.Digest(exported.EndChainHash),
			Results:                  exported.Results,
			SessionID:                exported.SessionID,
			WorkspaceID:              exported.WorkspaceID,
			RecoveryGeneration:       exported.RecoveryGeneration,
			ServerDeviceID:           fixture.authorityDeviceID,
			ServerAppliedResultIndex: exported.ServerAppliedResultIndex,
			ServerAuthorityVersion:   exported.Authority.VoterSetVersion,
		},
	)
	if err != nil {
		t.Fatalf("replication.NewUnsignedBatch(): %v", err)
	}
	seed := make([]byte, ed25519.SeedSize)
	for index := range seed {
		seed[index] = byte(index + 1)
	}
	privateKey := ed25519.NewKeyFromSeed(seed)
	batch, err := replication.SignBatch(unsigned, privateKey)
	if err != nil {
		t.Fatalf("replication.SignBatch(): %v", err)
	}
	parsed, err := replication.ParseBatch(batch.CanonicalBytes())
	if err != nil {
		t.Fatalf("replication.ParseBatch(): %v", err)
	}
	if err := replication.VerifyBatch(
		parsed,
		privateKey.Public().(ed25519.PublicKey),
	); err != nil {
		t.Fatalf("replication.VerifyBatch(): %v", err)
	}
}

func TestExportResultRangeHonorsItemAndByteLimits(t *testing.T) {
	fixture := newResultRangeFixture(t)
	options := ResultRangeOptions{
		AfterResultIndex: fixture.initial.ResultIndex,
		MaxResults:       MaxResultRangeItems,
		MaxBytes:         MaxResultRangeBytes,
	}
	all, found, err := fixture.store.ExportResultRange(
		context.Background(),
		options,
	)
	if err != nil || !found {
		t.Fatalf("ExportResultRange(all) = found %t, err %v", found, err)
	}

	options.MaxResults = 1
	one, found, err := fixture.store.ExportResultRange(
		context.Background(),
		options,
	)
	if err != nil || !found || len(one.Results) != 1 ||
		one.ToResultIndex != one.FromResultIndex {
		t.Fatalf("ExportResultRange(one item) = %+v, %t, %v", one, found, err)
	}

	options.MaxResults = MaxResultRangeItems
	options.MaxBytes = 2 + len(all.Results[0])
	one, found, err = fixture.store.ExportResultRange(
		context.Background(),
		options,
	)
	if err != nil || !found || len(one.Results) != 1 {
		t.Fatalf("ExportResultRange(one byte-fit) = %+v, %t, %v", one, found, err)
	}

	options.MaxBytes--
	if _, _, err := fixture.store.ExportResultRange(
		context.Background(),
		options,
	); !errors.Is(err, ErrResultRangeTooLarge) {
		t.Fatalf(
			"ExportResultRange(first too large) error = %v, want ErrResultRangeTooLarge",
			err,
		)
	}
}

func TestExportResultRangeRejectsInvalidCursorAndCorruption(t *testing.T) {
	t.Run("cursor beyond head", func(t *testing.T) {
		fixture := newResultRangeFixture(t)
		_, _, err := fixture.store.ExportResultRange(
			context.Background(),
			ResultRangeOptions{
				AfterResultIndex: fixture.second.Heads.ResultIndex + 1,
				MaxResults:       MaxResultRangeItems,
				MaxBytes:         MaxResultRangeBytes,
			},
		)
		if !errors.Is(err, ErrResultRangeNotCovered) {
			t.Fatalf("error = %v, want ErrResultRangeNotCovered", err)
		}
	})

	t.Run("retained result corruption", func(t *testing.T) {
		fixture := newResultRangeFixture(t)
		commitmentExecute(
			t,
			fixture.store,
			`UPDATE command_results
			    SET result_hash = zeroblob(32)
			  WHERE result_index = ?1;`,
			fixture.first.Heads.ResultIndex,
		)
		_, _, err := fixture.store.ExportResultRange(
			context.Background(),
			ResultRangeOptions{
				AfterResultIndex: fixture.initial.ResultIndex,
				MaxResults:       MaxResultRangeItems,
				MaxBytes:         MaxResultRangeBytes,
			},
		)
		if !errors.Is(err, ErrCommandResultCorrupt) {
			t.Fatalf("error = %v, want ErrCommandResultCorrupt", err)
		}
	})
}

func TestExportResultRangeValidatesOptionsContextAndClosedStore(t *testing.T) {
	fixture := newResultRangeFixture(t)
	valid := ResultRangeOptions{
		AfterResultIndex: fixture.initial.ResultIndex,
		MaxResults:       MaxResultRangeItems,
		MaxBytes:         MaxResultRangeBytes,
	}
	for _, test := range []struct {
		name    string
		options ResultRangeOptions
	}{
		{name: "zero items", options: ResultRangeOptions{MaxBytes: 2}},
		{
			name: "too many items",
			options: ResultRangeOptions{
				MaxResults: MaxResultRangeItems + 1,
				MaxBytes:   2,
			},
		},
		{name: "tiny byte bound", options: ResultRangeOptions{MaxResults: 1, MaxBytes: 1}},
		{
			name: "oversize byte bound",
			options: ResultRangeOptions{
				MaxResults: 1,
				MaxBytes:   MaxResultRangeBytes + 1,
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			if _, _, err := fixture.store.ExportResultRange(
				context.Background(),
				test.options,
			); !errors.Is(err, ErrInvalidOptions) {
				t.Fatalf("error = %v, want ErrInvalidOptions", err)
			}
		})
	}

	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, _, err := fixture.store.ExportResultRange(
		cancelled,
		valid,
	); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled error = %v, want context.Canceled", err)
	}
	if _, _, err := fixture.store.ExportResultRange(
		nil,
		valid,
	); !errors.Is(err, ErrInvalidOptions) {
		t.Fatalf("nil context error = %v, want ErrInvalidOptions", err)
	}
	if err := fixture.store.Close(); err != nil {
		t.Fatalf("Close(): %v", err)
	}
	if _, _, err := fixture.store.ExportResultRange(
		context.Background(),
		valid,
	); !errors.Is(err, ErrClosed) {
		t.Fatalf("closed error = %v, want ErrClosed", err)
	}
}

type resultRangeFixture struct {
	store             *Store
	initial           ApplyHeads
	first             ApplyResult
	second            ApplyResult
	authorityDeviceID domain.DeviceID
}

func newResultRangeFixture(t *testing.T) resultRangeFixture {
	t.Helper()

	firstProposal := testSignedTaskEvent(t, testEventID, 1)
	authorityDeviceID := firstProposal.Proposal().Origin.DeviceID()
	target, err := voterset.New(
		domain.UUIDv7(testSessionID),
		[]domain.DeviceID{authorityDeviceID},
		1,
	)
	if err != nil {
		t.Fatalf("voterset.New(): %v", err)
	}
	state := commitmentInitialState(
		t,
		domain.UUIDv7(testSessionID),
		0,
		ProjectionWrites{
			VoterSet: []voterset.Set{target},
			CredentialAuthority: []CredentialAuthorityRow{{
				SessionID:        domain.UUIDv7(testSessionID),
				VoterDeviceIDs:   []domain.DeviceID{authorityDeviceID},
				VoterSetVersion:  1,
				ActivationSource: CredentialAuthorityGenesis,
			}},
		},
	)
	database := openTestStore(
		t,
		filepath.Join(t.TempDir(), "session", "state.db"),
		nil,
	)
	initial, err := database.Initialize(context.Background(), state)
	if err != nil {
		t.Fatalf("Initialize(): %v", err)
	}
	first, err := database.Apply(
		context.Background(),
		acceptedApplyRequest(t, firstProposal),
	)
	if err != nil {
		t.Fatalf("Apply(first): %v", err)
	}
	secondProposal := testSignedTaskEvent(t, testEventID2, 1)
	second, err := database.Apply(
		context.Background(),
		rejectedApplyRequest(t, secondProposal, first.Heads),
	)
	if err != nil {
		t.Fatalf("Apply(second): %v", err)
	}
	return resultRangeFixture{
		store:             database,
		initial:           initial,
		first:             first,
		second:            second,
		authorityDeviceID: authorityDeviceID,
	}
}
