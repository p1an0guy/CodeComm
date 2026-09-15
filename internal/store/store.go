// Package store owns CodeComm's per-workspace SQLite state.
package store

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"sync"
	"sync/atomic"

	"zombiezen.com/go/sqlite"
	"zombiezen.com/go/sqlite/sqlitex"
)

const defaultPoolSize = 4

// sqliteLifecycle prevents connection use from overlapping pool construction
// or teardown in another store. Operations may join an active generation; the
// first transition to zero grants the oldest queued lifecycle waiter before a
// new operation can start. Snapshot installation reuses one explicit operation
// lease while accessing its source and destination stores.
var sqliteLifecycle = newSQLiteLifecycleGate()

type sqliteLifecycleGate struct {
	mu               sync.Mutex
	activeOperations int
	exclusive        bool
	exclusiveWaiters []*sqliteLifecycleExclusiveWaiter
	operationsReady  chan struct{}
}

type sqliteLifecycleExclusiveWaiter struct {
	ready   chan struct{}
	granted bool
}

type sqliteLifecycleLease struct {
	gate     *sqliteLifecycleGate
	released atomic.Bool
}

func newSQLiteLifecycleGate() *sqliteLifecycleGate {
	operationsReady := make(chan struct{})
	close(operationsReady)
	return &sqliteLifecycleGate{operationsReady: operationsReady}
}

func (gate *sqliteLifecycleGate) beginOperation(
	ctx context.Context,
) (*sqliteLifecycleLease, error) {
	if gate == nil {
		return nil, ErrInvalidOptions
	}
	if ctx == nil {
		return nil, fmt.Errorf("%w: nil context", ErrInvalidOptions)
	}
	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		gate.mu.Lock()
		if gate.operationsReady == nil {
			gate.mu.Unlock()
			return nil, ErrInvalidOptions
		}
		if !gate.exclusive {
			if gate.activeOperations == 0 &&
				len(gate.exclusiveWaiters) > 0 {
				gate.grantNextExclusiveLocked()
			} else {
				gate.activeOperations++
				gate.mu.Unlock()
				return &sqliteLifecycleLease{gate: gate}, nil
			}
		}
		operationsReady := gate.operationsReady
		gate.mu.Unlock()
		select {
		case <-operationsReady:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
}

func (lease *sqliteLifecycleLease) release() {
	if lease == nil || lease.gate == nil {
		return
	}
	if !lease.released.CompareAndSwap(false, true) {
		panic("store: SQLite lifecycle lease released more than once")
	}
	lease.gate.endOperation()
}

func (lease *sqliteLifecycleLease) validFor(
	gate *sqliteLifecycleGate,
) bool {
	return lease != nil &&
		lease.gate == gate &&
		!lease.released.Load()
}

func (gate *sqliteLifecycleGate) beginExclusive(
	ctx context.Context,
) (func(), error) {
	if gate == nil {
		return nil, ErrInvalidOptions
	}
	if ctx == nil {
		return nil, fmt.Errorf("%w: nil context", ErrInvalidOptions)
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	waiter := &sqliteLifecycleExclusiveWaiter{ready: make(chan struct{})}
	gate.mu.Lock()
	if gate.operationsReady == nil {
		gate.mu.Unlock()
		return nil, ErrInvalidOptions
	}
	if err := ctx.Err(); err != nil {
		gate.mu.Unlock()
		return nil, err
	}
	gate.exclusiveWaiters = append(gate.exclusiveWaiters, waiter)
	gate.grantNextExclusiveLocked()
	gate.mu.Unlock()

	select {
	case <-waiter.ready:
	case <-ctx.Done():
		gate.mu.Lock()
		if !waiter.granted {
			gate.removeExclusiveWaiterLocked(waiter)
			gate.grantNextExclusiveLocked()
			gate.mu.Unlock()
			return nil, ctx.Err()
		}
		gate.mu.Unlock()
	}

	var releaseOnce sync.Once
	return func() {
		releaseOnce.Do(gate.endExclusive)
	}, nil
}

func (gate *sqliteLifecycleGate) endOperation() {
	gate.mu.Lock()
	defer gate.mu.Unlock()
	if gate.activeOperations <= 0 {
		panic("store: SQLite lifecycle operation count underflow")
	}
	gate.activeOperations--
	if gate.activeOperations == 0 {
		gate.grantNextExclusiveLocked()
	}
}

func (gate *sqliteLifecycleGate) endExclusive() {
	gate.mu.Lock()
	defer gate.mu.Unlock()
	if !gate.exclusive {
		panic("store: SQLite lifecycle exclusive release without ownership")
	}
	if len(gate.exclusiveWaiters) > 0 {
		gate.grantQueuedExclusiveLocked()
		return
	}
	gate.exclusive = false
	close(gate.operationsReady)
}

func (gate *sqliteLifecycleGate) grantNextExclusiveLocked() {
	if gate.exclusive ||
		gate.activeOperations != 0 ||
		len(gate.exclusiveWaiters) == 0 {
		return
	}
	gate.exclusive = true
	gate.operationsReady = make(chan struct{})
	gate.grantQueuedExclusiveLocked()
}

func (gate *sqliteLifecycleGate) grantQueuedExclusiveLocked() {
	waiter := gate.exclusiveWaiters[0]
	copy(gate.exclusiveWaiters, gate.exclusiveWaiters[1:])
	last := len(gate.exclusiveWaiters) - 1
	gate.exclusiveWaiters[last] = nil
	gate.exclusiveWaiters = gate.exclusiveWaiters[:last]
	waiter.granted = true
	close(waiter.ready)
}

func (gate *sqliteLifecycleGate) removeExclusiveWaiterLocked(
	waiter *sqliteLifecycleExclusiveWaiter,
) {
	for index, queued := range gate.exclusiveWaiters {
		if queued != waiter {
			continue
		}
		copy(
			gate.exclusiveWaiters[index:],
			gate.exclusiveWaiters[index+1:],
		)
		last := len(gate.exclusiveWaiters) - 1
		gate.exclusiveWaiters[last] = nil
		gate.exclusiveWaiters = gate.exclusiveWaiters[:last]
		return
	}
}

var (
	ErrInvalidOptions     = errors.New("store: invalid options")
	ErrClosed             = errors.New("store: closed")
	ErrCorrupt            = errors.New("store: corrupt database")
	ErrInsecurePath       = errors.New("store: insecure database path")
	ErrMigrationState     = errors.New("store: invalid migration state")
	ErrMigrationChecksum  = errors.New("store: migration checksum mismatch")
	ErrSchemaTooNew       = errors.New("store: database schema is newer than this binary")
	ErrSQLiteVersion      = errors.New("store: unsupported SQLite version")
	ErrRaftState          = errors.New("store: cannot read Raft state")
	ErrRaftIndexAhead     = errors.New("store: applied SQLite index exceeds Raft log")
	ErrIntegrityCheck     = errors.New("store: integrity check failed")
	ErrUnexpectedRowCount = errors.New("store: unexpected query row count")
	ErrDatabaseExists     = errors.New("store: database already exists")
)

// RaftLog provides the durable last log index used for the startup consistency
// assertion. A nil RaftLog identifies a settled nonvoter without local Raft
// state.
type RaftLog interface {
	LastIndex() (uint64, error)
}

// Options configures one per-workspace store.
type Options struct {
	Path       string
	RaftLog    RaftLog
	RequireNew bool
}

// Store is a concurrency-safe owner for one SQLite connection pool.
type Store struct {
	path string
	pool *sqlitex.Pool

	mu       sync.RWMutex
	closed   bool
	closeErr error

	applyMu           sync.Mutex
	applyFailpoint    func(applyStage) error
	admissionRevision atomic.Uint64
	resultHeadChanges *resultHeadChangeFeed

	controlFileFailpoint func(controlFileDecisionStage) error
}

// Open creates or opens a store, applies checksummed migrations, verifies
// integrity, and checks any local Raft applied index before returning.
func Open(ctx context.Context, options Options) (_ *Store, err error) {
	if ctx == nil {
		return nil, fmt.Errorf("%w: nil context", ErrInvalidOptions)
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if options.Path == "" || !filepath.IsAbs(options.Path) {
		return nil, fmt.Errorf("%w: path must be absolute", ErrInvalidOptions)
	}
	path := filepath.Clean(options.Path)

	releaseLifecycle, err := sqliteLifecycle.beginExclusive(ctx)
	if err != nil {
		return nil, err
	}
	defer releaseLifecycle()
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	created, err := openDatabaseFile(path, syncDirectory)
	if err != nil {
		return nil, err
	}
	if options.RequireNew && !created {
		return nil, ErrDatabaseExists
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	conn, err := sqlite.OpenConn(
		path,
		sqlite.OpenReadWrite|sqlite.OpenPrivateCache,
	)
	if err != nil {
		return nil, normalizeSQLiteError(ctx, "open database", err)
	}
	defer func() {
		if conn == nil {
			return
		}
		if closeErr := conn.Close(); err == nil && closeErr != nil {
			err = normalizeSQLiteError(ctx, "close startup connection", closeErr)
		}
	}()
	conn.SetInterrupt(ctx.Done())
	if err := configureStartupConnection(conn); err != nil {
		return nil, normalizeSQLiteError(ctx, "configure database", err)
	}
	if err := checkIntegrity(conn); err != nil {
		return nil, normalizeSQLiteError(ctx, "check database before migration", err)
	}
	if err := applyMigrations(conn, embeddedMigrations, systemClock); err != nil {
		return nil, normalizeSQLiteError(ctx, "apply migrations", err)
	}
	if err := compactCommandResultStorageIfRequired(conn); err != nil {
		return nil, normalizeSQLiteError(
			ctx,
			"compact migrated command-result storage",
			err,
		)
	}
	if err := checkIntegrity(conn); err != nil {
		return nil, normalizeSQLiteError(ctx, "check database after migration", err)
	}
	if err := assertRaftIndex(conn, options.RaftLog); err != nil {
		return nil, err
	}
	if options.RaftLog != nil {
		if err := ensureRaftEvidenceMode(conn); err != nil {
			return nil, normalizeSQLiteError(
				ctx,
				"verify replica evidence mode",
				err,
			)
		}
	}
	if err := verifyCommittedRaftConfiguration(conn); err != nil {
		return nil, normalizeSQLiteError(
			ctx,
			"verify committed Raft configuration",
			err,
		)
	}
	if err := verifyCommandResultPayloadMetadata(conn); err != nil {
		return nil, normalizeSQLiteError(
			ctx,
			"verify command-result payload metadata",
			err,
		)
	}
	if err := verifyCurrentCommitmentTip(conn); err != nil {
		return nil, normalizeSQLiteError(ctx, "verify commitment tip", err)
	}
	if _, _, _, err := verifyCheckpointCadenceBinding(conn); err != nil &&
		!errors.Is(err, ErrApplyConflict) {
		return nil, normalizeSQLiteError(
			ctx,
			"verify checkpoint cadence",
			err,
		)
	}
	conn.SetInterrupt(nil)
	if err := conn.Close(); err != nil {
		return nil, normalizeSQLiteError(ctx, "close startup connection", err)
	}
	conn = nil

	if err := ctx.Err(); err != nil {
		return nil, err
	}
	pool, err := sqlitex.NewPool(path, sqlitex.PoolOptions{
		Flags:    sqlite.OpenReadWrite | sqlite.OpenPrivateCache,
		PoolSize: defaultPoolSize,
		PrepareConn: func(conn *sqlite.Conn) error {
			return configurePooledConnection(conn)
		},
	})
	if err != nil {
		return nil, normalizeSQLiteError(ctx, "open connection pool", err)
	}
	if err := prepareConnectionPool(ctx, pool); err != nil {
		_ = pool.Close()
		return nil, normalizeSQLiteError(ctx, "prepare connection pool", err)
	}
	store := &Store{
		path:              path,
		pool:              pool,
		resultHeadChanges: newResultHeadChangeFeed(),
	}
	store.admissionRevision.Store(1)
	return store, nil
}

func prepareConnectionPool(ctx context.Context, pool *sqlitex.Pool) error {
	connections := make([]*sqlite.Conn, 0, defaultPoolSize)
	defer func() {
		for _, conn := range connections {
			pool.Put(conn)
		}
	}()
	for range defaultPoolSize {
		if err := ctx.Err(); err != nil {
			return err
		}
		conn, err := pool.Take(ctx)
		if err != nil {
			return err
		}
		connections = append(connections, conn)
	}
	return nil
}

// Path returns the cleaned absolute database path.
func (store *Store) Path() string {
	if store == nil {
		return ""
	}
	return store.path
}

// AdmissionRevision returns a process-local token that changes after every
// committed mutation capable of making an applied peer-admission cut stale.
// The apply lock linearizes the token with the corresponding SQLite commit.
func (store *Store) AdmissionRevision() uint64 {
	if store == nil {
		return 0
	}
	store.applyMu.Lock()
	defer store.applyMu.Unlock()
	return store.admissionRevision.Load()
}

func (store *Store) advanceAdmissionRevision() uint64 {
	return store.admissionRevision.Add(1)
}

// Close interrupts active operations and closes every pooled connection after
// its caller returns it. Repeated and concurrent calls return the same result.
func (store *Store) Close() error {
	if store == nil || store.pool == nil {
		return ErrInvalidOptions
	}
	releaseLifecycle, err := sqliteLifecycle.beginExclusive(
		context.Background(),
	)
	if err != nil {
		return err
	}
	defer releaseLifecycle()
	store.mu.Lock()
	defer store.mu.Unlock()
	if store.closed {
		return store.closeErr
	}
	store.closed = true
	store.resultHeadChanges.close()
	store.closeErr = store.pool.Close()
	if store.closeErr != nil {
		store.closeErr = fmt.Errorf("store: close: %w", store.closeErr)
	}
	return store.closeErr
}

func (store *Store) withConn(
	ctx context.Context,
	fn func(*sqlite.Conn) error,
) error {
	lease, err := sqliteLifecycle.beginOperation(ctx)
	if err != nil {
		return err
	}
	defer lease.release()
	return store.withConnUnderLease(ctx, lease, fn)
}

func (store *Store) withConnUnderLease(
	ctx context.Context,
	lease *sqliteLifecycleLease,
	fn func(*sqlite.Conn) error,
) error {
	if store == nil || store.pool == nil || fn == nil {
		return ErrInvalidOptions
	}
	if !lease.validFor(sqliteLifecycle) {
		return ErrInvalidOptions
	}
	if ctx == nil {
		return fmt.Errorf("%w: nil context", ErrInvalidOptions)
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	store.mu.RLock()
	defer store.mu.RUnlock()
	if store.closed {
		return ErrClosed
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	conn, err := store.pool.Take(ctx)
	if err != nil {
		return normalizeSQLiteError(ctx, "take connection", err)
	}
	defer store.pool.Put(conn)
	if err := fn(conn); err != nil {
		return normalizeSQLiteError(ctx, "database operation", err)
	}
	return nil
}

func assertRaftIndex(conn *sqlite.Conn, raftLog RaftLog) error {
	if raftLog == nil {
		return nil
	}
	lastIndex, err := raftLog.LastIndex()
	if err != nil {
		return fmt.Errorf("%w: %v", ErrRaftState, err)
	}
	var (
		applied int64
		found   bool
	)
	err = query(
		conn,
		"SELECT last_raft_applied_log_index FROM consensus_state WHERE singleton = 1;",
		func(stmt *sqlite.Stmt) {
			found = true
			if stmt.ColumnType(0) != sqlite.TypeNull {
				applied = stmt.ColumnInt64(0)
			}
		},
	)
	if err != nil {
		return normalizeSQLiteError(context.Background(), "read applied Raft index", err)
	}
	if found && applied > 0 && uint64(applied) > lastIndex {
		return fmt.Errorf(
			"%w: SQLite applied %d, Raft last index %d",
			ErrRaftIndexAhead,
			applied,
			lastIndex,
		)
	}
	var configurationIndex int64
	if err := queryOne(
		conn,
		`SELECT coalesce(max(log_index), 0)
		   FROM raft_committed_configuration;`,
		func(stmt *sqlite.Stmt) {
			configurationIndex = stmt.ColumnInt64(0)
		},
	); err != nil {
		return normalizeSQLiteError(
			context.Background(),
			"read committed Raft configuration index",
			err,
		)
	}
	if configurationIndex > 0 &&
		uint64(configurationIndex) > lastIndex {
		return fmt.Errorf(
			"%w: SQLite configuration %d, Raft last index %d",
			ErrRaftIndexAhead,
			configurationIndex,
			lastIndex,
		)
	}
	return nil
}

func normalizeSQLiteError(ctx context.Context, operation string, err error) error {
	if err == nil {
		return nil
	}
	if ctx != nil && ctx.Err() != nil {
		return ctx.Err()
	}
	switch sqlite.ErrCode(err) {
	case sqlite.ResultCorrupt, sqlite.ResultNotADB:
		return fmt.Errorf("%w: %s: %v", ErrCorrupt, operation, err)
	default:
		return fmt.Errorf("store: %s: %w", operation, err)
	}
}
