package consensus

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/ijonahch/codecomm/internal/chain"
	"github.com/ijonahch/codecomm/internal/domain"
	"github.com/ijonahch/codecomm/internal/domain/device"
	"github.com/ijonahch/codecomm/internal/logicalsnapshot"
	"github.com/ijonahch/codecomm/internal/store"
)

func TestFreshDeviceLogicalSnapshotBoundaryVerifierVerifiesInitialCut(
	t *testing.T,
) {
	initial, bootstrap := freshDeviceBootstrapFixture(t)
	frozen := cloneFreshDeviceBootstrapView(bootstrap)
	payload := freshDeviceInitialPayload(bootstrap)
	genesisDigest := freshDeviceGenesisDigest(t, payload.GenesisJSON)

	verifier, err := NewFreshDeviceLogicalSnapshotBoundaryVerifier(
		bootstrap,
		0,
		genesisDigest,
	)
	if err != nil {
		t.Fatalf(
			"NewFreshDeviceLogicalSnapshotBoundaryVerifier(): %v",
			err,
		)
	}

	// The constructor owns its bootstrap memory.
	bootstrap.GenesisJSON[0] ^= 0xff
	bootstrap.ProjectionRows[0].PrimaryKey[0] ^= 0xff
	bootstrap.ProjectionRows[0].Row[0] ^= 0xff

	verified, err := verifier.VerifyInitialBoundary(
		testContext(t),
		payload,
	)
	if err != nil {
		t.Fatalf("VerifyInitialBoundary(): %v", err)
	}
	if verified.SessionID != initial.SessionID ||
		verified.WorkspaceID != initial.WorkspaceID ||
		verified.DigestVersion != initial.DigestVersion ||
		verified.ProjectionSchemaVersion !=
			initial.ProjectionSchemaVersion ||
		!bytes.Equal(verified.GenesisJSON, frozen.GenesisJSON) {
		t.Fatalf("verified initial metadata = %+v", verified)
	}

	target, err := store.Open(
		context.Background(),
		store.Options{
			Path: filepath.Join(t.TempDir(), "target", "state.db"),
		},
	)
	if err != nil {
		t.Fatalf("store.Open(target): %v", err)
	}
	t.Cleanup(func() { _ = target.Close() })
	if _, err := target.Initialize(testContext(t), verified); err != nil {
		t.Fatalf("Initialize(verified): %v", err)
	}
	view, err := target.VerifiedGenerationZeroView(testContext(t))
	if err != nil {
		t.Fatalf("VerifiedGenerationZeroView(target): %v", err)
	}
	if view.Heads != frozen.Heads ||
		view.ProjectionStateDigest != frozen.ProjectionStateDigest ||
		!reflect.DeepEqual(view.ProjectionRows, frozen.ProjectionRows) {
		t.Fatalf(
			"installed initial cut differs:\ngot=%+v\nwant=%+v",
			view,
			frozen,
		)
	}

	verifiedGenesis := bytes.Clone(verified.GenesisJSON)
	payload.GenesisJSON[0] ^= 0xff
	if !bytes.Equal(verified.GenesisJSON, verifiedGenesis) {
		t.Fatal("returned initial genesis aliases payload storage")
	}
}

func TestFreshDeviceLogicalSnapshotBoundaryVerifierRejectsInvalidBootstrap(
	t *testing.T,
) {
	_, valid := freshDeviceBootstrapFixture(t)
	validDigest := freshDeviceGenesisDigest(t, valid.GenesisJSON)

	tests := []struct {
		name   string
		mutate func(*store.StateView)
	}{
		{
			name: "successor generation",
			mutate: func(view *store.StateView) {
				view.RecoveryGeneration = 1
			},
		},
		{
			name: "Raft provenance",
			mutate: func(view *store.StateView) {
				term := uint64(1)
				index := uint64(1)
				view.CurrentTerm = &term
				view.LastRaftAppliedLogIndex = &index
			},
		},
		{
			name: "chain position",
			mutate: func(view *store.StateView) {
				view.Heads.ChainIndex = 1
			},
		},
		{
			name: "result position",
			mutate: func(view *store.StateView) {
				view.Heads.ResultIndex = 1
			},
		},
		{
			name: "previous result head",
			mutate: func(view *store.StateView) {
				view.Heads.PreviousResultHash[0] ^= 0xff
			},
		},
		{
			name: "invalid metadata",
			mutate: func(view *store.StateView) {
				view.SessionID = ""
			},
		},
		{
			name: "projection digest",
			mutate: func(view *store.StateView) {
				view.ProjectionStateDigest[0] ^= 0xff
			},
		},
		{
			name: "event seed",
			mutate: func(view *store.StateView) {
				view.Heads.ChainHash[0] ^= 0xff
			},
		},
		{
			name: "result seed",
			mutate: func(view *store.StateView) {
				view.Heads.ResultHash[0] ^= 0xff
			},
		},
		{
			name: "projection accumulator",
			mutate: func(view *store.StateView) {
				view.Heads.ProjectionAccumulator[0] ^= 0xff
			},
		},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			candidate := cloneFreshDeviceBootstrapView(valid)
			test.mutate(&candidate)
			if _, err := NewFreshDeviceLogicalSnapshotBoundaryVerifier(
				candidate,
				0,
				validDigest,
			); !errors.Is(err, ErrLogicalSnapshotBoundaryUnavailable) {
				t.Fatalf(
					"NewFreshDeviceLogicalSnapshotBoundaryVerifier() error = %v, want boundary unavailable",
					err,
				)
			}
		})
	}

	if _, err := NewFreshDeviceLogicalSnapshotBoundaryVerifier(
		valid,
		domain.MaxSafeInteger+1,
		validDigest,
	); !errors.Is(err, ErrLogicalSnapshotBoundaryUnavailable) {
		t.Fatalf(
			"NewFreshDeviceLogicalSnapshotBoundaryVerifier(unsafe generation) error = %v",
			err,
		)
	}
}

func TestFreshDeviceLogicalSnapshotBoundaryVerifierPinsInitialPayload(
	t *testing.T,
) {
	_, bootstrap := freshDeviceBootstrapFixture(t)
	validPayload := freshDeviceInitialPayload(bootstrap)
	validDigest := freshDeviceGenesisDigest(
		t,
		validPayload.GenesisJSON,
	)

	t.Run("invite digest", func(t *testing.T) {
		wrongDigest := validDigest
		wrongDigest[0] ^= 0xff
		verifier, err := NewFreshDeviceLogicalSnapshotBoundaryVerifier(
			bootstrap,
			0,
			wrongDigest,
		)
		if err != nil {
			t.Fatalf("constructor: %v", err)
		}
		if _, err := verifier.VerifyInitialBoundary(
			testContext(t),
			validPayload,
		); !errors.Is(err, ErrLogicalSnapshotBoundaryUnavailable) {
			t.Fatalf(
				"VerifyInitialBoundary(wrong pin) error = %v",
				err,
			)
		}
	})

	t.Run("genesis bytes", func(t *testing.T) {
		payload := freshDeviceInitialPayload(bootstrap)
		var members map[string]any
		if err := json.Unmarshal(payload.GenesisJSON, &members); err != nil {
			t.Fatalf("json.Unmarshal(genesis): %v", err)
		}
		members["substituted"] = true
		payload.GenesisJSON = canonicalLogicalSnapshotJSON(t, members)
		payloadDigest := freshDeviceGenesisDigest(t, payload.GenesisJSON)
		verifier, err := NewFreshDeviceLogicalSnapshotBoundaryVerifier(
			bootstrap,
			0,
			payloadDigest,
		)
		if err != nil {
			t.Fatalf("constructor: %v", err)
		}
		if _, err := verifier.VerifyInitialBoundary(
			testContext(t),
			payload,
		); !errors.Is(err, ErrLogicalSnapshotBoundaryUnavailable) {
			t.Fatalf(
				"VerifyInitialBoundary(substituted genesis) error = %v",
				err,
			)
		}
	})

	t.Run("boundary transform", func(t *testing.T) {
		payload := freshDeviceInitialPayload(bootstrap)
		payload.BoundaryTransformDigest[0] ^= 0xff
		verifier, err := NewFreshDeviceLogicalSnapshotBoundaryVerifier(
			bootstrap,
			0,
			validDigest,
		)
		if err != nil {
			t.Fatalf("constructor: %v", err)
		}
		if _, err := verifier.VerifyInitialBoundary(
			testContext(t),
			payload,
		); !errors.Is(err, ErrLogicalSnapshotBoundaryUnavailable) {
			t.Fatalf(
				"VerifyInitialBoundary(wrong transform) error = %v",
				err,
			)
		}
	})
}

func TestFreshDeviceLogicalSnapshotBoundaryVerifierTracksActiveRecovery(
	t *testing.T,
) {
	fixture := newLogicalSnapshotRecoveryFixture(t, device.RoleOwner)
	bootstrap, err := fixture.source.VerifiedGenerationZeroView(
		testContext(t),
	)
	if err != nil {
		t.Fatalf("VerifiedGenerationZeroView(): %v", err)
	}
	initialPayload := freshDeviceInitialPayload(bootstrap)
	activeDigest := freshDeviceGenesisDigest(
		t,
		fixture.payload.GenesisJSON,
	)

	t.Run("successor cannot replace initial", func(t *testing.T) {
		verifier, err := NewFreshDeviceLogicalSnapshotBoundaryVerifier(
			bootstrap,
			1,
			activeDigest,
		)
		if err != nil {
			t.Fatalf("constructor: %v", err)
		}
		if _, err := verifier.VerifyInitialBoundary(
			testContext(t),
			fixture.payload,
		); !errors.Is(
			err,
			ErrLogicalSnapshotSuccessorBoundaryUnsupported,
		) {
			t.Fatalf(
				"VerifyInitialBoundary(successor) error = %v",
				err,
			)
		}
	})

	t.Run("verified target and upper bound", func(t *testing.T) {
		verifier, err := NewFreshDeviceLogicalSnapshotBoundaryVerifier(
			bootstrap,
			1,
			activeDigest,
		)
		if err != nil {
			t.Fatalf("constructor: %v", err)
		}
		if _, err := verifier.VerifySuccessorBoundary(
			testContext(t),
			fixture.predecessor,
			fixture.payload,
		); !errors.Is(err, ErrLogicalSnapshotBoundaryUnavailable) {
			t.Fatalf(
				"VerifySuccessorBoundary(before initial) error = %v",
				err,
			)
		}
		if _, err := verifier.VerifyInitialBoundary(
			testContext(t),
			initialPayload,
		); err != nil {
			t.Fatalf("VerifyInitialBoundary(): %v", err)
		}
		successor, err := verifier.VerifySuccessorBoundary(
			testContext(t),
			fixture.predecessor,
			fixture.payload,
		)
		if err != nil {
			t.Fatalf("VerifySuccessorBoundary(): %v", err)
		}
		if successor.RecoveryGeneration != 1 ||
			!bytes.Equal(
				successor.GenesisJSON,
				fixture.payload.GenesisJSON,
			) {
			t.Fatalf("verified successor = %+v", successor)
		}
		if _, err := verifier.VerifySuccessorBoundary(
			testContext(t),
			fixture.predecessor,
			fixture.payload,
		); !errors.Is(
			err,
			ErrLogicalSnapshotSuccessorBoundaryUnsupported,
		) {
			t.Fatalf(
				"VerifySuccessorBoundary(beyond pin) error = %v",
				err,
			)
		}
	})

	t.Run("target digest mismatch", func(t *testing.T) {
		wrongDigest := activeDigest
		wrongDigest[0] ^= 0xff
		verifier, err := NewFreshDeviceLogicalSnapshotBoundaryVerifier(
			bootstrap,
			1,
			wrongDigest,
		)
		if err != nil {
			t.Fatalf("constructor: %v", err)
		}
		if _, err := verifier.VerifyInitialBoundary(
			testContext(t),
			initialPayload,
		); err != nil {
			t.Fatalf("VerifyInitialBoundary(): %v", err)
		}
		if _, err := verifier.VerifySuccessorBoundary(
			testContext(t),
			fixture.predecessor,
			fixture.payload,
		); !errors.Is(
			err,
			ErrLogicalSnapshotSuccessorBoundaryInvalid,
		) {
			t.Fatalf(
				"VerifySuccessorBoundary(wrong target pin) error = %v",
				err,
			)
		}
	})

	t.Run("intermediate generation", func(t *testing.T) {
		unreachedDigest := activeDigest
		unreachedDigest[0] ^= 0xff
		verifier, err := NewFreshDeviceLogicalSnapshotBoundaryVerifier(
			bootstrap,
			2,
			unreachedDigest,
		)
		if err != nil {
			t.Fatalf("constructor: %v", err)
		}
		if _, err := verifier.VerifyInitialBoundary(
			testContext(t),
			initialPayload,
		); err != nil {
			t.Fatalf("VerifyInitialBoundary(): %v", err)
		}
		if _, err := verifier.VerifySuccessorBoundary(
			testContext(t),
			fixture.predecessor,
			fixture.payload,
		); err != nil {
			t.Fatalf(
				"VerifySuccessorBoundary(intermediate): %v",
				err,
			)
		}
		if _, err := verifier.VerifySuccessorBoundary(
			testContext(t),
			fixture.predecessor,
			fixture.payload,
		); !errors.Is(
			err,
			ErrLogicalSnapshotSuccessorBoundaryInvalid,
		) {
			t.Fatalf(
				"VerifySuccessorBoundary(repeated generation) error = %v",
				err,
			)
		}
	})
}

func freshDeviceBootstrapFixture(
	t *testing.T,
) (store.InitialState, store.StateView) {
	t.Helper()
	initial, _, _ := nodeTestInitialState(t)
	database, err := store.Open(
		context.Background(),
		store.Options{
			Path: filepath.Join(t.TempDir(), "bootstrap", "state.db"),
		},
	)
	if err != nil {
		t.Fatalf("store.Open(bootstrap): %v", err)
	}
	t.Cleanup(func() { _ = database.Close() })
	if _, err := database.Initialize(testContext(t), initial); err != nil {
		t.Fatalf("Initialize(bootstrap): %v", err)
	}
	view, err := database.VerifiedGenerationZeroView(testContext(t))
	if err != nil {
		t.Fatalf("VerifiedGenerationZeroView(): %v", err)
	}
	return initial, view
}

func freshDeviceInitialPayload(
	view store.StateView,
) logicalsnapshot.GenesisPayload {
	return logicalsnapshot.GenesisPayload{
		GenesisJSON:             bytes.Clone(view.GenesisJSON),
		BoundaryTransformDigest: chain.Digest(view.ProjectionStateDigest),
	}
}

func freshDeviceGenesisDigest(
	t *testing.T,
	genesisJSON []byte,
) chain.Digest {
	t.Helper()
	digest, err := chain.GenesisDigest(genesisJSON)
	if err != nil {
		t.Fatalf("chain.GenesisDigest(): %v", err)
	}
	return digest
}
