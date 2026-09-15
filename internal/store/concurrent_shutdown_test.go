package store

import (
	"context"
	"errors"
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

func TestCloseWaitsWithoutBlockingIndependentStoreDependency(t *testing.T) {
	root := t.TempDir()
	stores := openSeededIndependentStores(
		t,
		root,
		migratedTestStoreTemplate(t),
		"lifecycle",
		2,
	)
	defer func() {
		if errs := closeIndependentStores(stores); len(errs) != 0 {
			t.Errorf("cleanup stores: %v", errs)
		}
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	lease, err := sqliteLifecycle.beginOperation(ctx)
	if err != nil {
		t.Fatalf("begin independent-store operation: %v", err)
	}

	entered := make(chan struct{})
	runDependency := make(chan struct{})
	operationDone := make(chan error, 1)
	go func() {
		defer lease.release()
		operationDone <- stores[0].withConnUnderLease(
			ctx,
			lease,
			func(*sqlite.Conn) error {
				close(entered)
				select {
				case <-runDependency:
				case <-ctx.Done():
					return ctx.Err()
				}
				return stores[1].withConnUnderLease(
					ctx,
					lease,
					func(*sqlite.Conn) error { return nil },
				)
			},
		)
	}()
	select {
	case <-entered:
	case <-ctx.Done():
		t.Fatal("independent store operation did not start")
	}

	closeDone := make(chan error, 1)
	go func() {
		closeDone <- stores[1].Close()
	}()
	waitForSQLiteLifecycleExclusiveWaiter(t, ctx, sqliteLifecycle)
	select {
	case err := <-closeDone:
		t.Fatalf("independent close completed during active operation: %v", err)
	default:
	}

	close(runDependency)
	select {
	case err := <-operationDone:
		if err != nil {
			t.Fatalf("dependent independent-store operation: %v", err)
		}
	case <-ctx.Done():
		t.Fatal("dependent operation blocked behind independent close")
	}
	select {
	case err := <-closeDone:
		if err != nil {
			t.Fatalf("independent close: %v", err)
		}
	case <-ctx.Done():
		t.Fatal("independent close did not run after operation release")
	}
	if err := stores[1].withConn(
		ctx,
		func(*sqlite.Conn) error { return nil },
	); !errors.Is(err, ErrClosed) {
		t.Fatalf("operation after independent close = %v, want ErrClosed", err)
	}
}

func TestSQLiteLifecycleActiveGenerationPrecedesQueuedExclusive(t *testing.T) {
	gate := newSQLiteLifecycleGate()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	active, err := gate.beginOperation(ctx)
	if err != nil {
		t.Fatalf("begin active operation: %v", err)
	}
	exclusiveAcquired := make(chan struct{})
	releaseExclusive := make(chan struct{})
	exclusiveDone := make(chan error, 1)
	go func() {
		release, err := gate.beginExclusive(ctx)
		if err != nil {
			exclusiveDone <- err
			return
		}
		close(exclusiveAcquired)
		select {
		case <-releaseExclusive:
		case <-ctx.Done():
		}
		release()
		exclusiveDone <- nil
	}()
	waitForSQLiteLifecycleExclusiveWaiter(t, ctx, gate)

	joined, err := gate.beginOperation(ctx)
	if err != nil {
		t.Fatalf("join active operation generation: %v", err)
	}
	select {
	case <-exclusiveAcquired:
		t.Fatal("queued exclusive interrupted an active operation generation")
	default:
	}
	active.release()
	select {
	case <-exclusiveAcquired:
		t.Fatal("exclusive acquired before the active generation drained")
	default:
	}
	joined.release()

	operationAcquired := make(chan struct{})
	operationDone := make(chan error, 1)
	go func() {
		lease, err := gate.beginOperation(ctx)
		if err != nil {
			operationDone <- err
			return
		}
		close(operationAcquired)
		lease.release()
		operationDone <- nil
	}()

	select {
	case <-exclusiveAcquired:
	case <-operationAcquired:
		t.Fatal("operation entered between generation zero and exclusive grant")
	case <-ctx.Done():
		t.Fatal("queued exclusive was not granted when the generation drained")
	}
	select {
	case <-operationAcquired:
		t.Fatal("later operation acquired while lifecycle work was exclusive")
	default:
	}
	close(releaseExclusive)
	select {
	case err := <-exclusiveDone:
		if err != nil {
			t.Fatalf("exclusive lifecycle work: %v", err)
		}
	case <-ctx.Done():
		t.Fatal("exclusive lifecycle work did not finish")
	}
	select {
	case <-operationAcquired:
	case <-ctx.Done():
		t.Fatal("later operation did not resume after exclusive lifecycle work")
	}
	select {
	case err := <-operationDone:
		if err != nil {
			t.Fatalf("operation after exclusive lifecycle work: %v", err)
		}
	case <-ctx.Done():
		t.Fatal("later operation did not finish")
	}
}

func TestSQLiteLifecycleWaitHonorsContext(t *testing.T) {
	gate := newSQLiteLifecycleGate()
	releaseExclusive, err := gate.beginExclusive(context.Background())
	if err != nil {
		t.Fatalf("begin exclusive lifecycle work: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Millisecond)
	defer cancel()
	if _, err := gate.beginOperation(ctx); !errors.Is(
		err,
		context.DeadlineExceeded,
	) {
		t.Fatalf("operation wait = %v, want context deadline", err)
	}
	releaseExclusive()

	lease, err := gate.beginOperation(context.Background())
	if err != nil {
		t.Fatalf("begin lifecycle operation: %v", err)
	}
	defer lease.release()
	ctx, cancel = context.WithTimeout(context.Background(), 25*time.Millisecond)
	defer cancel()
	if _, err := gate.beginExclusive(ctx); !errors.Is(
		err,
		context.DeadlineExceeded,
	) {
		t.Fatalf("exclusive wait = %v, want context deadline", err)
	}
}

func waitForSQLiteLifecycleExclusiveWaiter(
	t *testing.T,
	ctx context.Context,
	gate *sqliteLifecycleGate,
) {
	t.Helper()
	ticker := time.NewTicker(time.Millisecond)
	defer ticker.Stop()
	for {
		gate.mu.Lock()
		queued := len(gate.exclusiveWaiters) > 0
		gate.mu.Unlock()
		if queued {
			return
		}
		select {
		case <-ticker.C:
		case <-ctx.Done():
			t.Fatal("exclusive lifecycle work did not enter the wait queue")
		}
	}
}

func runConcurrentIndependentStoreShutdown(t *testing.T) {
	t.Helper()
	rounds, storesPerRound := 12, 6
	if raceDetectorEnabled {
		rounds = 3
		storesPerRound = 3
	}
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
