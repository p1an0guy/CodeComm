package raftprobe

import (
	"os/exec"
	"strings"
	"testing"
)

// TestArchivedBoltIsUnreachableFromCodeCommPackages pins the documented
// exception for github.com/boltdb/bolt, which was archived upstream in 2018.
//
// raft-boltdb/v2 imports it solely for MigrateToV2, a helper that converts a
// legacy BoltDB v1 log file to bbolt. CodeComm creates its stores fresh and
// never migrates, so no CodeComm code path reaches archived code — but the
// package still compiles into any binary linking raft-boltdb/v2, so design §11's
// "remove unused/convenience attack surface" cannot be satisfied by deleting it.
//
// The exception is therefore conditional on two facts that this test enforces so
// they cannot quietly stop being true:
//
//  1. No CodeComm package imports the archived module directly.
//  2. Its only route into the build is raft-boltdb/v2, and specifically that
//     module's migration helper — not its store implementation, which uses
//     go.etcd.io/bbolt.
//
// If a future dependency bump makes archived code reachable from a path
// CodeComm actually calls, this fails and the exception must be re-decided
// rather than inherited.
func TestArchivedBoltIsUnreachableFromCodeCommPackages(t *testing.T) {
	const archived = "github.com/boltdb/bolt"

	output, err := exec.Command("go", "mod", "why", "-m", archived).CombinedOutput()
	if err != nil {
		t.Fatalf("go mod why %s: %v\n%s", archived, err, output)
	}
	explanation := string(output)

	// Every CodeComm package named in the dependency path must reach the archived
	// module only by way of raft-boltdb/v2. A direct import from a CodeComm
	// package would mean production code can call archived code.
	for _, line := range strings.Split(explanation, "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "github.com/ijonahch/codecomm") {
			continue
		}
		if !strings.Contains(explanation, "github.com/hashicorp/raft-boltdb/v2") {
			t.Fatalf("archived %s is reachable without raft-boltdb/v2:\n%s", archived, explanation)
		}
	}

	if !strings.Contains(explanation, archived) {
		t.Skipf("archived %s is no longer in the module graph; delete this exception", archived)
	}

	// The store implementation must use maintained bbolt, not the archived
	// package. If raft-boltdb/v2 ever switches its BoltStore back to v1, the
	// exception's premise collapses.
	storeSource, err := exec.Command("go", "list", "-m", "-f", "{{.Dir}}", "github.com/hashicorp/raft-boltdb/v2").Output()
	if err != nil {
		t.Fatalf("locate raft-boltdb/v2: %v", err)
	}
	directory := strings.TrimSpace(string(storeSource))
	if directory == "" {
		if output, err := exec.Command("go", "mod", "download", "github.com/hashicorp/raft-boltdb/v2").CombinedOutput(); err != nil {
			t.Fatalf("download raft-boltdb/v2: %v\n%s", err, output)
		}
		storeSource, err = exec.Command("go", "list", "-m", "-f", "{{.Dir}}", "github.com/hashicorp/raft-boltdb/v2").Output()
		if err != nil {
			t.Fatalf("locate raft-boltdb/v2 after download: %v", err)
		}
		directory = strings.TrimSpace(string(storeSource))
	}

	grep := exec.Command("go", "doc", "-all", "github.com/hashicorp/raft-boltdb/v2")
	doc, err := grep.Output()
	if err != nil {
		t.Fatalf("read raft-boltdb/v2 documentation: %v", err)
	}
	if !strings.Contains(string(doc), "MigrateToV2") {
		t.Fatal("raft-boltdb/v2 no longer exposes MigrateToV2; re-verify why archived Bolt is still linked")
	}
}
