package consensus

import (
	"context"
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"testing"
	"time"

	"github.com/ijonahch/codecomm/internal/store"
)

func TestRaftApplyWaitsForEnqueueGate(t *testing.T) {
	root := t.TempDir()
	initial, identityPrivate, deviceID := nodeTestInitialState(t)
	node, err := OpenSingleNode(context.Background(), SingleNodeOptions{
		ServerID:     deviceID,
		StatePath:    filepath.Join(root, "state", "state.db"),
		ConsensusDir: filepath.Join(root, "consensus"),
		OriginBootID: nodeTestBootID1,
		InitialState: &initial,
		Clock:        nodeTestClock(),
		RaftConfig:   nodeTestRaftConfig(),
	})
	if err != nil {
		t.Fatalf("OpenSingleNode(): %v", err)
	}
	t.Cleanup(func() { _ = node.Close() })
	waitForNodeLeader(t, node)

	guard, err := node.acquireRaftEnqueue(testContext(t))
	if err != nil {
		t.Fatalf("acquireRaftEnqueue(): %v", err)
	}
	signed := nodeTestTaskEvent(
		t,
		identityPrivate,
		deviceID,
		nodeTestBootID1,
		nodeTestEventID1,
		nodeTestTaskID1,
		nodeTestTimestamp1,
		1,
		"serialized apply",
	)
	done := make(chan struct {
		result store.ApplyResult
		err    error
	}, 1)
	applyContext := testContext(t)
	go func() {
		result, applyErr := node.Apply(applyContext, signed)
		done <- struct {
			result store.ApplyResult
			err    error
		}{result: result, err: applyErr}
	}()

	select {
	case result := <-done:
		t.Fatalf("Apply() bypassed enqueue gate: (%#v, %v)", result.result, result.err)
	case <-time.After(100 * time.Millisecond):
	}
	guard.release()

	select {
	case result := <-done:
		if result.err != nil ||
			result.result.Outcome.Status != store.OutcomeAccepted {
			t.Fatalf("Apply() after release = (%#v, %v)", result.result, result.err)
		}
	case <-testContext(t).Done():
		t.Fatal("Apply() did not resume after enqueue gate release")
	}
}

func TestDirectRaftEnqueuesStayInsideAdapters(t *testing.T) {
	t.Parallel()

	const (
		applyAdapter         = "enqueueRaftApply"
		configurationAdapter = "invokeRaftConfigurationChange"
	)
	allowed := map[string]string{
		"Apply":        applyAdapter,
		"AddVoter":     configurationAdapter,
		"AddNonvoter":  configurationAdapter,
		"DemoteVoter":  configurationAdapter,
		"RemoveServer": configurationAdapter,
	}
	forbidden := map[string]struct{}{
		"ApplyLog":   {},
		"AddPeer":    {},
		"RemovePeer": {},
	}
	counts := make(map[string]int, len(allowed))
	forbiddenCounts := make(map[string]int, len(forbidden))
	adapterCallers := map[string]struct {
		function string
		count    int
	}{
		"enqueueRaftApply": {
			function: "apply",
			count:    1,
		},
		"invokeRaftConfigurationChange": {
			function: "changeRaftConfiguration",
			count:    1,
		},
		"changeRaftConfiguration": {
			function: "reconcileVoterSet",
			count:    0,
		},
	}
	adapterCounts := make(map[string]int, len(adapterCallers))
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatalf("Glob(): %v", err)
	}
	for _, path := range files {
		if filepath.Ext(path) != ".go" ||
			len(path) >= len("_test.go") &&
				path[len(path)-len("_test.go"):] == "_test.go" {
			continue
		}
		file, err := parser.ParseFile(
			token.NewFileSet(),
			path,
			nil,
			parser.SkipObjectResolution,
		)
		if err != nil {
			t.Fatalf("ParseFile(%s): %v", path, err)
		}
		for _, declaration := range file.Decls {
			function, ok := declaration.(*ast.FuncDecl)
			if !ok || function.Body == nil {
				continue
			}
			ast.Inspect(function.Body, func(node ast.Node) bool {
				call, ok := node.(*ast.CallExpr)
				if !ok {
					return true
				}
				method, ok := call.Fun.(*ast.SelectorExpr)
				if !ok {
					return true
				}
				if caller, guarded := adapterCallers[method.Sel.Name]; guarded {
					adapterCounts[method.Sel.Name]++
					if function.Name.Name != caller.function {
						t.Errorf(
							"%s: %s called in %s; want %s",
							path,
							method.Sel.Name,
							function.Name.Name,
							caller.function,
						)
					}
				}
				wantFunction, allowedMethod := allowed[method.Sel.Name]
				_, forbiddenMethod := forbidden[method.Sel.Name]
				if !allowedMethod && !forbiddenMethod {
					return true
				}
				receiver, ok := method.X.(*ast.SelectorExpr)
				if !ok || receiver.Sel.Name != "raft" {
					return true
				}
				if forbiddenMethod {
					forbiddenCounts[method.Sel.Name]++
					t.Errorf(
						"%s: forbidden direct node.raft.%s call in %s",
						path,
						method.Sel.Name,
						function.Name.Name,
					)
					return true
				}
				counts[method.Sel.Name]++
				if function.Name.Name != wantFunction {
					t.Errorf(
						"%s: direct node.raft.%s call in %s; want %s",
						path,
						method.Sel.Name,
						function.Name.Name,
						wantFunction,
					)
				}
				return true
			})
		}
	}
	for method := range allowed {
		if counts[method] != 1 {
			t.Errorf("direct node.raft.%s call count = %d, want 1", method, counts[method])
		}
	}
	for method := range forbidden {
		if forbiddenCounts[method] != 0 {
			t.Errorf(
				"forbidden node.raft.%s call count = %d, want 0",
				method,
				forbiddenCounts[method],
			)
		}
	}
	for adapter, caller := range adapterCallers {
		if adapterCounts[adapter] != caller.count {
			t.Errorf(
				"%s call count = %d, want %d",
				adapter,
				adapterCounts[adapter],
				caller.count,
			)
		}
	}
}
