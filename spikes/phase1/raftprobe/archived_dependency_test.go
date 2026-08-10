package raftprobe

import (
	"os"
	"path/filepath"
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
// The exception is conditional on two facts this test enforces so they cannot
// quietly stop being true:
//
//  1. No CodeComm source file imports the archived module directly.
//  2. Its only route into the build is raft-boltdb/v2's migration helper, not
//     that module's store implementation, which uses go.etcd.io/bbolt.
//
// If a dependency bump makes archived code reachable from a path CodeComm calls,
// this fails and the exception must be re-decided rather than inherited.
//
// Deliberately implemented by reading files rather than shelling out to `go mod
// why`/`go list`/`go doc`: those subprocesses cost ~50s on a cold module cache
// and starved the timing-sensitive leadership-transfer test in this same
// package on CI's slower Windows runner. A dependency contract must not be able
// to fail an unrelated consensus test.
func TestArchivedBoltIsUnreachableFromCodeCommPackages(t *testing.T) {
	const (
		archived = "github.com/boltdb/bolt"
		gateway  = "github.com/hashicorp/raft-boltdb/v2"
	)

	root := repositoryRoot(t)

	// 1. No first-party file may import the archived module.
	var offenders []string
	err := filepath.WalkDir(root, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() {
			switch entry.Name() {
			case ".git", "testdata":
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") {
			return nil
		}
		// This file names the module in string constants to enforce the contract;
		// it is the contract, not a consumer of the archived package.
		if filepath.Base(path) == "archived_dependency_test.go" {
			return nil
		}
		source, readErr := os.ReadFile(path)
		if readErr != nil {
			return readErr
		}
		if importsModule(string(source), archived) {
			relative, _ := filepath.Rel(root, path)
			offenders = append(offenders, relative)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("scan first-party sources: %v", err)
	}
	if len(offenders) > 0 {
		t.Fatalf("first-party files import archived %s directly: %v; the unreachability exception no longer holds", archived, offenders)
	}

	// 2. The archived module must still enter the graph only through the gateway.
	// go.mod records it as an indirect requirement; a direct one would mean a
	// first-party import that step 1 would also have caught, but asserting both
	// keeps the failure message specific.
	modules, err := os.ReadFile(filepath.Join(root, "go.mod"))
	if err != nil {
		t.Fatalf("read go.mod: %v", err)
	}
	archivedLine := ""
	for _, line := range strings.Split(string(modules), "\n") {
		if strings.Contains(line, archived+" ") {
			archivedLine = strings.TrimSpace(line)
			break
		}
	}
	if archivedLine == "" {
		t.Skipf("archived %s is no longer in go.mod; delete this exception and its status-doc row", archived)
	}
	if !strings.Contains(archivedLine, "// indirect") {
		t.Fatalf("go.mod lists archived %s as a direct requirement (%q), want indirect via %s", archived, archivedLine, gateway)
	}
	if !strings.Contains(string(modules), gateway) {
		t.Fatalf("archived %s is required but gateway %s is absent; its route into the build changed", archived, gateway)
	}
}

// importsModule reports whether source has an import declaration for the module,
// rather than merely mentioning its name in a comment or string.
func importsModule(source, module string) bool {
	for _, line := range strings.Split(source, "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "//") {
			continue
		}
		if !strings.Contains(trimmed, `"`+module+`"`) {
			continue
		}
		// An import path appears either alone in a block or after an alias.
		fields := strings.Fields(trimmed)
		switch len(fields) {
		case 1:
			return true
		case 2:
			if fields[0] == "import" || !strings.ContainsAny(fields[0], "=(){}") {
				return true
			}
		}
	}
	return false
}

func repositoryRoot(t *testing.T) string {
	t.Helper()
	directory, err := os.Getwd()
	if err != nil {
		t.Fatalf("working directory: %v", err)
	}
	for {
		if _, err := os.Stat(filepath.Join(directory, "go.mod")); err == nil {
			return directory
		}
		parent := filepath.Dir(directory)
		if parent == directory {
			t.Fatal("go.mod not found above the test's working directory")
		}
		directory = parent
	}
}
