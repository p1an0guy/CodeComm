package agent

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/ijonahch/codecomm/internal/domain"
	"github.com/ijonahch/codecomm/internal/store"
)

func TestCreateManagedRootRefusesPreExistingDestination(t *testing.T) {
	harness := newAgentTestHarness(t, nil)
	repository := createManagedRootTestDirectory(t, "repository")
	destination := createManagedRootTestDirectory(t, "pre-existing")
	sentinel := filepath.Join(destination, "user-data")
	if err := os.WriteFile(sentinel, []byte("preserve"), 0o600); err != nil {
		t.Fatal(err)
	}

	_, err := harness.service.CreateManagedRoot(
		context.Background(),
		ManagedRootOptions{
			DestinationPath:           destination,
			RepositoryCommonDirectory: repository,
			Kind:                      store.ManagedRootIsolated,
		},
	)
	if !errors.Is(err, ErrManagedRootDestinationExists) {
		t.Fatalf(
			"CreateManagedRoot(pre-existing) error = %v, want %v",
			err,
			ErrManagedRootDestinationExists,
		)
	}
	content, readErr := os.ReadFile(sentinel)
	if readErr != nil || string(content) != "preserve" {
		t.Fatalf("pre-existing destination changed: %q, %v", content, readErr)
	}
}

func TestCreateManagedRootRefusesPreExistingEmptyDestination(t *testing.T) {
	harness := newAgentTestHarness(t, nil)
	repository := createManagedRootTestDirectory(t, "repository")
	destination := createManagedRootTestDirectory(t, "empty")

	_, err := harness.service.CreateManagedRoot(
		context.Background(),
		ManagedRootOptions{
			DestinationPath:           destination,
			RepositoryCommonDirectory: repository,
			Kind:                      store.ManagedRootShared,
		},
	)
	if !errors.Is(err, ErrManagedRootDestinationExists) {
		t.Fatalf(
			"CreateManagedRoot(empty destination) error = %v, want %v",
			err,
			ErrManagedRootDestinationExists,
		)
	}
	entries, readErr := os.ReadDir(destination)
	if readErr != nil || len(entries) != 0 {
		t.Fatalf(
			"pre-existing empty destination changed: %v, %v",
			entries,
			readErr,
		)
	}
}

func TestNativeDirectoryIdentityCanonicalizesSymlinkAlias(t *testing.T) {
	target := createManagedRootTestDirectory(t, "identity-target")
	alias := filepath.Join(t.TempDir(), "identity-alias")
	if err := os.Symlink(target, alias); err != nil {
		t.Skipf("directory symlinks unavailable: %v", err)
	}

	direct, err := inspectNativeDirectory(target)
	if err != nil {
		t.Fatalf("inspectNativeDirectory(target): %v", err)
	}
	throughAlias, err := inspectNativeDirectory(alias)
	if err != nil {
		t.Fatalf("inspectNativeDirectory(alias): %v", err)
	}
	if direct != throughAlias {
		t.Fatalf(
			"directory identities differ:\ndirect = %#v\nalias  = %#v",
			direct,
			throughAlias,
		)
	}
}

func TestCreateManagedRootRejectsRepositoryAlias(t *testing.T) {
	harness := newAgentTestHarness(t, nil)
	repository := createManagedRootTestDirectory(t, "repository")
	alias := filepath.Join(t.TempDir(), "repository-alias")
	if err := os.Symlink(repository, alias); err != nil {
		t.Skipf("directory symlinks unavailable: %v", err)
	}

	firstDestination := filepath.Join(t.TempDir(), "first-root")
	first, err := harness.service.CreateManagedRoot(
		context.Background(),
		ManagedRootOptions{
			DestinationPath:           firstDestination,
			RepositoryCommonDirectory: repository,
			Kind:                      store.ManagedRootIsolated,
		},
	)
	if err != nil {
		t.Fatalf("CreateManagedRoot(first): %v", err)
	}

	secondDestination := filepath.Join(t.TempDir(), "second-root")
	_, err = harness.service.CreateManagedRoot(
		context.Background(),
		ManagedRootOptions{
			DestinationPath:           secondDestination,
			RepositoryCommonDirectory: alias,
			Kind:                      store.ManagedRootIsolated,
		},
	)
	if !errors.Is(err, store.ErrManagedRootConflict) {
		t.Fatalf(
			"CreateManagedRoot(repository alias) error = %v, want %v",
			err,
			store.ErrManagedRootConflict,
		)
	}
	assertManagedRootTestPathMissing(t, secondDestination)
	if info, statErr := os.Stat(first.CanonicalPath); statErr != nil || !info.IsDir() {
		t.Fatalf("first managed root changed: %#v, %v", info, statErr)
	}
}

func TestCreateManagedRootCleansUpAfterRegistrationFailure(t *testing.T) {
	harness := newAgentTestHarness(t, nil)
	firstRepository := createManagedRootTestDirectory(t, "first-repository")
	first, err := harness.service.CreateManagedRoot(
		context.Background(),
		ManagedRootOptions{
			DestinationPath:           filepath.Join(t.TempDir(), "first-root"),
			RepositoryCommonDirectory: firstRepository,
			Kind:                      store.ManagedRootIsolated,
		},
	)
	if err != nil {
		t.Fatalf("CreateManagedRoot(first): %v", err)
	}

	harness.service.generateID = func() (domain.UUIDv7, error) {
		return first.ManagedRootID, nil
	}
	secondRepository := createManagedRootTestDirectory(t, "second-repository")
	secondDestination := filepath.Join(t.TempDir(), "second-root")
	_, err = harness.service.CreateManagedRoot(
		context.Background(),
		ManagedRootOptions{
			DestinationPath:           secondDestination,
			RepositoryCommonDirectory: secondRepository,
			Kind:                      store.ManagedRootShared,
		},
	)
	if !errors.Is(err, store.ErrManagedRootConflict) {
		t.Fatalf(
			"CreateManagedRoot(duplicate ID) error = %v, want %v",
			err,
			store.ErrManagedRootConflict,
		)
	}
	assertManagedRootTestPathMissing(t, secondDestination)
	if _, statErr := os.Stat(first.CanonicalPath); statErr != nil {
		t.Fatalf("first managed root was removed: %v", statErr)
	}
}

func TestManagedRootCleanupPreservesNonEmptyDirectory(t *testing.T) {
	path := createManagedRootTestDirectory(t, "non-empty-root")
	identity, err := inspectNativeDirectory(path)
	if err != nil {
		t.Fatalf("inspectNativeDirectory(): %v", err)
	}
	sentinel := filepath.Join(path, "concurrent-data")
	if err := os.WriteFile(sentinel, []byte("preserve"), 0o600); err != nil {
		t.Fatal(err)
	}

	err = removeOwnedEmptyDirectory(identity)
	if !errors.Is(err, ErrManagedRootCleanup) {
		t.Fatalf(
			"removeOwnedEmptyDirectory(non-empty) error = %v, want %v",
			err,
			ErrManagedRootCleanup,
		)
	}
	content, readErr := os.ReadFile(sentinel)
	if readErr != nil || string(content) != "preserve" {
		t.Fatalf("non-empty managed root changed: %q, %v", content, readErr)
	}
}

func createManagedRootTestDirectory(t *testing.T, name string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.Mkdir(path, 0o700); err != nil {
		t.Fatal(err)
	}
	return path
}

func assertManagedRootTestPathMissing(t *testing.T, path string) {
	t.Helper()
	if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("path %q still exists or cannot be checked: %v", path, err)
	}
}
