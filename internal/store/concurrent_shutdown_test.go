package store

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"zombiezen.com/go/sqlite"
)

const concurrentStoreShutdownChild = "CODECOMM_TEST_CONCURRENT_STORE_SHUTDOWN_CHILD"

func TestConcurrentIndependentStoreShutdown(t *testing.T) {
	if os.Getenv(concurrentStoreShutdownChild) == "1" {
		runConcurrentIndependentStoreShutdown(t)
		return
	}

	executable, err := os.Executable()
	if err != nil {
		t.Fatalf("locate test executable: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	command := exec.CommandContext(
		ctx,
		executable,
		"-test.run=^TestConcurrentIndependentStoreShutdown$",
		"-test.count=1",
		"-test.timeout=90s",
	)
	command.Env = append(os.Environ(), concurrentStoreShutdownChild+"=1")
	output, err := command.CombinedOutput()
	if ctx.Err() != nil {
		t.Fatalf("concurrent shutdown subprocess: %v\n%s", ctx.Err(), output)
	}
	if err != nil {
		t.Fatalf("concurrent shutdown subprocess: %v\n%s", err, output)
	}
}

func runConcurrentIndependentStoreShutdown(t *testing.T) {
	t.Helper()
	const (
		rounds         = 12
		storesPerRound = 6
	)
	root := t.TempDir()
	template := migratedTestStoreTemplate(t)
	stores := openSeededIndependentStores(
		t,
		root,
		template,
		"initial",
		storesPerRound,
	)
	defer func() {
		_ = closeIndependentStores(stores)
	}()
	for round := range rounds {
		initializeEveryPooledConnection(t, stores)
		paths := seedIndependentStorePaths(
			t,
			root,
			template,
			fmt.Sprintf("round-%02d", round),
			storesPerRound,
		)
		replacements, errs := replaceIndependentStores(stores, paths)
		if len(errs) != 0 {
			closeIndependentStores(replacements)
			t.Fatalf("round %d replace stores: %v", round, errs)
		}
		stores = replacements
	}
	initializeEveryPooledConnection(t, stores)
	if errs := closeIndependentStores(stores); len(errs) != 0 {
		t.Fatalf("close final stores: %v", errs)
	}
	stores = nil
}

func openSeededIndependentStores(
	t *testing.T,
	root string,
	template []byte,
	prefix string,
	count int,
) []*Store {
	t.Helper()
	paths := seedIndependentStorePaths(t, root, template, prefix, count)
	stores := make([]*Store, 0, len(paths))
	for index, path := range paths {
		database, err := Open(context.Background(), Options{Path: path})
		if err != nil {
			closeIndependentStores(stores)
			t.Fatalf("%s open store %d: %v", prefix, index, err)
		}
		stores = append(stores, database)
	}
	return stores
}

func seedIndependentStorePaths(
	t *testing.T,
	root string,
	template []byte,
	prefix string,
	count int,
) []string {
	t.Helper()
	paths := make([]string, count)
	for index := range count {
		path := filepath.Join(
			root,
			fmt.Sprintf("%s-store-%02d", prefix, index),
			"state.db",
		)
		if err := seedTestStore(path, template); err != nil {
			t.Fatalf("%s seed store %d: %v", prefix, index, err)
		}
		paths[index] = path
	}
	return paths
}

type independentStoreOpenResult struct {
	index    int
	database *Store
	err      error
}

func replaceIndependentStores(
	stores []*Store,
	paths []string,
) ([]*Store, []error) {
	start := make(chan struct{})
	errs := make(chan error, len(stores)+len(paths))
	opened := make(chan independentStoreOpenResult, len(paths))
	var group sync.WaitGroup
	for index, database := range stores {
		group.Add(1)
		go func() {
			defer group.Done()
			<-start
			if err := database.Close(); err != nil {
				errs <- fmt.Errorf("close store %d: %w", index, err)
			}
		}()
	}
	for index, path := range paths {
		group.Add(1)
		go func() {
			defer group.Done()
			<-start
			database, err := Open(context.Background(), Options{Path: path})
			opened <- independentStoreOpenResult{
				index:    index,
				database: database,
				err:      err,
			}
		}()
	}
	close(start)
	group.Wait()
	close(opened)
	close(errs)

	replacements := make([]*Store, len(paths))
	var openErrors []error
	for result := range opened {
		if result.err != nil {
			openErrors = append(
				openErrors,
				fmt.Errorf("open store %d: %w", result.index, result.err),
			)
			continue
		}
		replacements[result.index] = result.database
	}
	return replacements, append(openErrors, collectErrors(errs)...)
}

func initializeEveryPooledConnection(t *testing.T, stores []*Store) {
	t.Helper()
	for storeIndex, database := range stores {
		acquired := make(chan error, defaultPoolSize)
		completed := make(chan error, defaultPoolSize)
		release := make(chan struct{})
		for range defaultPoolSize {
			go func() {
				signaled := false
				err := database.withConn(
					context.Background(),
					func(conn *sqlite.Conn) error {
						var schemaObjects int64
						if err := queryOne(
							conn,
							"SELECT count(*) FROM sqlite_schema;",
							func(stmt *sqlite.Stmt) {
								schemaObjects = stmt.ColumnInt64(0)
							},
						); err != nil {
							return err
						}
						if schemaObjects < 1 {
							return fmt.Errorf(
								"sqlite_schema object count = %d",
								schemaObjects,
							)
						}
						signaled = true
						acquired <- nil
						<-release
						return nil
					},
				)
				if !signaled {
					acquired <- err
				}
				completed <- err
			}()
		}
		for connectionIndex := range defaultPoolSize {
			if err := <-acquired; err != nil {
				close(release)
				t.Fatalf(
					"initialize store %d connection %d: %v",
					storeIndex,
					connectionIndex,
					err,
				)
			}
		}
		close(release)
		for connectionIndex := range defaultPoolSize {
			if err := <-completed; err != nil {
				t.Fatalf(
					"release store %d connection %d: %v",
					storeIndex,
					connectionIndex,
					err,
				)
			}
		}
	}
}

func closeIndependentStores(stores []*Store) []error {
	start := make(chan struct{})
	errs := make(chan error, len(stores))
	var group sync.WaitGroup
	for _, database := range stores {
		if database == nil {
			continue
		}
		group.Add(1)
		go func() {
			defer group.Done()
			<-start
			if err := database.Close(); err != nil {
				errs <- err
			}
		}()
	}
	close(start)
	group.Wait()
	close(errs)
	return collectErrors(errs)
}

func collectErrors(errs <-chan error) []error {
	var result []error
	for err := range errs {
		result = append(result, err)
	}
	return result
}
