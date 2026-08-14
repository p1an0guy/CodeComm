# Phase 2 Status

Status: complete; implementation-plan steps 1-11 and Phase 2 delivery gates pass
Last updated: 2026-08-13
Scope: walking skeleton in `docs/IMPLEMENTATION.md` §3.

## Completed

### 1. Domain

`internal/domain` now defines and tests V1 identifiers, timestamps, Git OIDs, paths, numeric
bounds, entities, and pure transitions for tasks, plans, memory, leases, devices, agent sessions,
publications, conflicts, policy, and voter targets.

Persisted-form invariants fail closed. Cross-entity or authority checks that require committed state
remain reducer work: role/actor authorization, entity-version CAS, active membership, task
dependency graph traversal, lease quotas, publication graph/receipt validation, and revocation
subject/authority checks.

### 2. Codec

`internal/codec` now provides bounded RFC 8785 canonicalization under CodeComm's integer-only
I-JSON profile, strict unpadded base64url, the closed V1 Ed25519 domain-label set and
`label || 0x00 || signed_bytes`, plus device-ID derivation and golden vectors. Unsafe integers and
floating-point spellings are rejected before binary64 conversion. Layering tests prevent imports
from higher internal packages.

The full RFC 8785 engine and device-ID vectors, migration checksum, chain/result/projection vectors,
all 36 accepted reducer outcomes, and the complete rejection-code namespace are frozen.

### 3. Crypto and native credential store

`internal/crypto` provides narrow Ed25519 and SHA-256 wrappers with key-consistency checks and
non-aliased outputs. `internal/platform/credentialstore` stores only opaque identity/epoch
references, validates complete private keys, enforces create-only identity semantics, clears
temporary key buffers, propagates cancellation, and reports locked/unavailable/unreadable stores as
non-retryable startup blockers. There is no file, environment, or in-memory identity fallback.

Native providers use the macOS Security framework with a current-application ACL, Linux Secret
Service over the existing local session D-Bus without prompt/autostart/unlock behavior, and Windows
Credential Manager with a SID-scoped mutation mutex. Windows and common Linux providers are
user/session scoped rather than per-application ACLs; design §10 now states that limitation.

Native execution still requires the CI/platform matrix: signed-binary macOS ACL upgrade behavior,
live locked/headless Linux Secret Service cases, and Windows Credential Manager execution. Local
cross-compilation covers Linux and Windows AMD64/ARM64 plus Darwin's no-CGo refusal path.

### 4. Event envelope and registry

`internal/event` defines the complete 36-kind V1 registry, immutable actor/role/CAS/entity/apply-level
metadata, closed activity/redaction schemas, canonical entity IDs, and a signed envelope that retains
the exact bytes replicated through Raft. Local IPC commands use a distinct schema with no identity
fields; any supplied `origin`, including null, is rejected. MCP can mint only agent bindings.
Human/daemon bindings require a daemon-held `LocalAuthority`, and an AST gate prohibits that
capability outside `codecommd`, verified IPC, and the event implementation.

Known field bounds are checked before Ed25519 work. Unknown network members remain byte-for-byte in
the signature preimage and are rejected only after successful verification. Local construction
derives schema/apply level, event/session/workspace binding, capture level, origin, and sequence;
normalizes payload bytes to JCS; enforces actor/CAS/entity contracts; and deep-copies mutable input.
Received actor/CAS/domain violations remain available for deterministic reducer outcomes rather than
being misclassified as transport failures.

### 5. Store

`internal/store` now has a CGo-free `zombiezen.com/go/sqlite` backend, migration 0001, and all 41
documented tables. Open configures WAL, `synchronous=FULL`, foreign keys, a five-second busy timeout,
`trusted_schema=OFF`, and SQLite defensive mode; requires SQLite 3.42 or newer; verifies
checksummed transactional migrations and database integrity; enforces owner-only storage; syncs the
parent after first file creation; and refuses startup when the stored applied index is ahead of the
last Raft log index. Close is concurrent and idempotent.

The first-seen apply transaction writes accepted events and provenance, all 17 digest-covered
projections, command results, activity, audits, checkpoints, lease deadlines, outbox deletion, and
consensus state atomically. Rejections omit accepted-event rows but remain durable. Boundary
failpoints over a complete checkpoint/lease write set verify rollback throughout the transaction,
including sequence-reuse rejection. Accepted checkpoint events and checkpoint rows are now
one-to-one: typed fields, canonical unsigned bytes, authority signature, signed payload, event,
session, workspace, and recovery generation must all agree. Activity presence is bound to accepted
event content. Accepted `audit.recorded` writes exactly one payload-matching `audit_event` row and
cannot also emit the generic accepted-event audit source.

Migration review also corrected origin-sequence uniqueness, UUIDv4-only genesis workspaces, durable
publication preparation metadata, resolved-request bulk retention, safe foreign keys, control
manifest constraints, compact recovery tombstones, and exhausted origin counters. Design §6.2 now
states that origin tuples are unique only among accepted events.

Primary and independent reviews found and fixed two projection hazards: device capability validation
now shares the protocol's signed 31-bit apply-level ceiling with events and policy, and
credential-authority proofs are canonical, voter-tagged, and ordered exactly like the sorted voter
target. Tests write and read every column of all 17 projection tables, exercise all mutable upserts
and immutable duplicate rollbacks, and cover canonical JSON, NULL, BLOB, and boolean storage.

Control proposals are kind- and payload-bound before projection writes. Local approvals bind the
active lineage and exact event/path/operation/digest/index, update a canonical versioned manifest
only when effective state changes, and fail atomically on stale, corrupt, overflowing, or injected
failure paths. Frozen empty/populated vectors, successor installation, historical rollback, and
cross-kind rejection tests close the control-manifest gate.

Raft applications now bind exact event bytes independently of the generation where the immutable
result was first seen, so a legitimate predecessor-result replay survives successor restart.
Changed bytes under an existing event ID fail without writing a Raft binding, watermark, outbox
change, or any other row; close/reopen regressions cover both paths.

### 6. Reducer

`internal/reducer` now re-verifies each signed event against committed membership, consumes origin
sequences at the specified boundary, applies deterministic payload/CAS/authorization precedence,
and returns pure projection changes or stable rejection codes. `NewState` validates authoritative
rows and derives claim, lease, and unresolved-conflict indexes rather than accepting caller-supplied
negative authorization facts; `State.Apply` validates each complete prospective change set before
mutating memory.

The binary reducer ceiling and committed cluster floor are checked before kind dispatch. Unknown
kinds and unsupported levels return no outcome and halt FSM application before sequence, result,
or Raft-watermark advancement. Task claims freeze role, existence/CAS, actionable,
intended-device, then quota precedence. Golden rejection coverage pins every declared wire code and
representative preflight, role, payload, and domain results through their result and accumulator
hashes.

All seven `task.*` kinds enforce transition, ownership, dependency, conflict, reassignment, quota,
and operator-override rules. All three `lease.*` kinds enforce scope grammar, optional existing-task
association, exact-holder renewal, TTL policy, per-agent/device quotas, active-scope intersection,
release authority, CAS, and terminal lifecycle. Expiry leadership is an authenticated ingress
invariant because volatile Raft leadership is not reducer input; replicas still enforce daemon
actor, CAS, and lifecycle. Snapshot and apply tests cover corrupt references, over-limit indexes,
overlaps, immutable-field changes, and atomic rejection.

All three `agent.session.*` kinds enforce first-seen scope creation, generation-wide ID burning,
binding/profile identity, lifecycle authority, active-session limits, and atomic task/lease release
on end. Recovery-carried ended sessions have no predecessor scope and cannot be rebound on either
the original or another device; two independent review rounds found and closed both halves of that
invariant.

Both `plan.*` kinds and `memory.appended` enforce immutable identity, committed task/predecessor
references, owner-only current-pointer CAS, acyclic plan supersession, and single-successor
compatible memory correction chains. `NewState` derives memory occupancy from authoritative rows,
and `State.Apply` validates the complete prospective change set before mutation. Focused tests cover
malformed snapshots, cycles, branches, dangling/corrupt retained references, immutable replacement,
exact text bounds, deterministic payload outcomes, and atomic rollback.
Independent review also closed an unreachable `plan_current` state: a null revision is now valid
only at entity version 1 in the domain model, reducer snapshot, and SQLite constraint.

All seven `membership.*` kinds enforce closed payloads, role/actor authority, subject binding,
entity and voter-target CAS, active-owner continuity, active credential-authority majority, legal
voter-target transitions, and atomic topology validation. Admission verifies the identity-derived
device ID and signed initial epoch binding; readmission preserves identity. Owner recovery verifies
the exact generation/event/subject tuple under the recovery key. Authority activation verifies one
ordered proof per target voter, a common post-promotion checkpoint, and the prior-authority handoff
before replacing the authority row. Exact admission, recovery, checkpoint, activation-proof, and
handoff wire schemas are now explicit in design §5.4.

Independent review closed six boundary defects: activation checkpoints must cover the live
configuration index; reducer outcomes cannot alias committed public keys; `State.Apply` cannot
reinterpret voter revocation as a generic target replacement; generation genesis is the only
version-1 credential authority; event-chain positions cannot exceed result-chain positions; and
audit counts cannot exceed V1's hard per-epoch ceiling. Snapshot, constructed-change, tamper,
boundary, and atomicity tests cover each invariant. Deterministic precedence tests also pin
duplicate/readmission classification before member-cap rejection and malformed repeated device IDs
before subject mismatch.

`policy.changed` decodes exactly the complete 14-key mutable V1 policy object and rejects missing,
unknown, null, mistyped, immutable, out-of-range, or relationally invalid values. Only a human owner
with the current session-policy CAS may replace it. Reductions cannot lower member, active-agent,
per-agent/device claim, or per-agent/device lease caps below replicated use; apply-level raises are
monotonic and require every active device's committed capability. `NewState` enforces the same
member/capability invariants, while `State.Apply` validates the complete prospective policy and row
set before mutating either the policy or origin sequence. Tests cover every named immutable V1 key,
all live-use cap families, exact-use inclusive boundaries, inactive-device capability exclusion,
and atomic rollback. Independent review found and closed one compatibility gap by pinning
current-use rejection ahead of unsupported-capability rejection when both apply.

All four `publication.*` and all three `workspace.conflict.*` kinds enforce immutable proposal
identity, bounded staging evidence, author/task/root/path authority, review separation and override,
canonical-ref CAS, ancestry and supersession rules, deterministic conflict identity, terminal
transitions, and atomic task/conflict bookkeeping. Snapshot validation reconstructs publication
graphs and conflict gates from retained rows; tests cover malformed receipts, lineage cycles,
conflicting terminal writes, path authorization, deterministic IDs, and apply rollback.

`credential.authorized` enforces subject membership/role, per-session/device epoch continuity,
key/binding uniqueness, fixed validity and overlap clamps, exact activated-authority version,
sorted active-majority endorsements, and atomic audit-counter reset. Its in-memory key now matches
SQLite's `(session_id, device_id, epoch)` key, so recovery may retain predecessor epoch 1 while the
successor independently starts at epoch 1. Current counters constrain only current-session rows;
all retained streams remain contiguous and signature-valid. Historical authority membership is
trusted only after verified replay/snapshot chains, handoffs, and accumulator evidence, because the
singleton current authority projection cannot reconstruct old quorums. Valid 3- and 5-voter tests
cover exact majority, under-quorum, and revocation with a surviving majority.

`activity.recorded` supports taskless and task-linked records; activity for every accepted kind is
derived centrally from signed rationale/actions. `control_file.change_proposed` is append-only,
digest/size/operation/path bound, recovery-aware, and included in snapshot/apply validation.
`audit.recorded` validates active subject/latest epoch/depth and emits one typed audit directive plus
one counter increment, with no unrelated mutation. `consensus.checkpoint` verifies the closed
authority-signed object, then classifies stale local positions deterministically and integrity-halts
on same-position head or accumulator divergence before persistence.

Every one of the 36 registered V1 kinds now traverses central dispatch. Accepted events advance the
event chain exactly once, every first-seen outcome advances the result position, explicit audits and
checkpoints remain typed, and chain/result capacity exhaustion is a terminal operational error
rather than an impossible durable rejection. A registry-to-dispatch test prevents a future kind
from being added without reducer coverage.

### 7. Chain and projection commitments

`internal/chain` now owns SQLite-independent genesis, event-chain, result-chain, and projection
commitments. Golden vectors freeze generation-zero/successor seeds, accepted links, the exact
six-field command-result JCS object, mutation ordering/length framing, empty and populated
projection-state digests, and all fixed domain labels. Successor seeds retain dense positions while
changing each generation-scoped head.

The V1 projection registry closes every logical row over the exact 17-table field set, including
nullability, JSON array/object shape, booleans, nonnegative exact integers, and fixed-length
base64url binary values. Missing, extra, mistyped, noncanonical, invalid-UTF-8, wrong-key, duplicate,
or no-op mutations fail before hashing. The canonical mutation assembler has a 32 MiB integrity
ceiling and accepts the worst-case 64-claim/256-lease session-end cascade, which exceeds the generic
4 MiB JSON limit.

Store initialization now requires an explicit generation-zero boundary and atomically records its
full logical-state digest and all three seeds. Successor installation preserves event/result
positions, replaces covered projections atomically, and binds the prior genesis, both predecessor
heads, predecessor accumulator, digest versions, post-transform state digest, and signature
encodings to the persisted successor record. Recovery-layer cryptographic and semantic genesis
verification remains the caller's prerequisite; the store independently rejects any typed/signed
commitment disagreement.

`Apply` computes event/result hashes, persists the exact canonical projection mutations, and advances
the accumulator inside the same transaction as projections, the Raft-command ledger, and watermark.
Exact duplicates verify durable event/result links before returning the original outcome; equal-index
crash replay and predecessor-generation retry cannot regress the watermark. A duplicate declaring a
future generation is rejected without writes; an earlier-generation replay is bound to the active
application generation. Changed bytes return `idempotency_conflict`. Startup verifies genesis,
anchored links, every ledger/result binding, first-seen order, monotonic terms, and the boundary
state digest/accumulator before opening the pool.

Regressions cover tampered genesis/result/event/head/predecessor links, boundary rollback, exact
logical codecs, insertion order, WAL checkpoint, `VACUUM`, actual rowid reuse, arbitrary rowid
rewrites, excluded tables, and concurrent/race/shuffled execution. Full-state scans are serialized
with apply and run in one SQLite transaction, preventing mixed-snapshot digests.

### 8. Consensus

`internal/consensus` now runs a real one-voter `hashicorp/raft` node over loopback with the
production `raft-boltdb` stable/log store, private snapshot directory, and real SQLite FSM. It
bootstraps only the exact local voter, survives bootstrap interruption, reconciles an ephemeral
loopback address after restart, waits for an apply barrier before reporting readiness, and drains
committed applies before closing either durable store.

The FSM re-verifies exact Raft bytes under committed membership, reconstructs reducer state, applies
deterministic reduction, maps every projection/audit/checkpoint/lease-timer directive, and commits
through `Store.Apply`. Same-event proposal flights coalesce; changed bytes for a reserved or
committed event ID fail without entering Raft. Joined callers and durable retries return the
original outcome with duplicate status.

Startup verifies topology, snapshot metadata/content, full commitment history, historical cuts,
Raft-command bindings, and contiguous log/snapshot coverage before starting Raft. Missing
snapshots, log gaps, substituted commands, malformed configurations, and SQLite/Raft disagreement
fail closed; library startup panics at this boundary become errors. Any committed-command, lookup,
persistence, history, or snapshot-integrity failure latches one fatal FSM error and stops consensus.

Canonical snapshot anchor v2 binds session/generation, term/applied index, both chain heads,
projection accumulator and state digest, schema versions, and a bounded contiguous non-command Raft
tail. Phase 2 refuses restore because the anchor contains no transferable SQLite state; Phase 3 must
add verified logical restore plus adapter-bound `raft_snapshot_installs` baseline evidence before
accepting `InstallSnapshot`; an installed prefix never fabricates source command provenance.
Adversarial tests cover
restart/replay, all-log compaction, concurrent collision, canceled callers, close races, old or
tampered anchors, historical projection rewind, corrupt ledgers, missing coverage, and fatal halts.

### 9. Local IPC

`internal/ipc` now provides authenticated local endpoints and strict HTTP/1.1 framing without
loopback TCP. Unix listeners require an owner-owned `0700` directory, create a `0600` socket,
remove only a same-owner stale socket, verify both peers with `SO_PEERCRED` or
`LOCAL_PEERCRED`/`LOCAL_PEERPID`, and avoid deleting a replaced path. Windows listeners use a
protected current-SID owner/DACL, go-winio's pinned remote-client rejection, client/server PID
queries, identification-level dialing, applied-descriptor verification, and a dedicated locked
thread for impersonation-token SID checks and fail-closed reversion.

The server enforces the fixed 128-connection, 64-handler, 32 KiB-header, 1 MiB-JSON, 10-second
header, and 120-second body/idle ceilings. It rejects transfer encoding, duplicate or ambiguous
framing, non-JSON POSTs, HTTP versions/methods outside the closed profile, and pre-sent pipelined
bytes before any binder or handler side effect. The literal first request is
`POST /local/v1/bind`; protocol, client instance, session, workspace, class, and agent-proof shape
are validated before the daemon binder runs. The resulting handler and operator/agent class are
pinned for the connection, a second bind closes it, and disconnect notification occurs exactly
once. A silent pre-bind peer gets only the 10-second header budget and releases its global
connection slot; the 120-second idle budget begins only after a successful bind.

IPC treats `agent_proof` as one bounded JSON object; `internal/agent` alone interprets its closed
launch/resume union and constructs agent authority. Transport cannot manufacture an actor.

### 10. Agent lifecycle and MCP

`internal/agent` now owns durable managed-root and launch registration, one-use selector
reservation, exact start-proposal recovery, launch settlement/acknowledgement, and context-bound
resume commitments. A launch exposes no operations until `agent.session.started` commits and the
adapter acknowledges its 256-bit capability; only its domain-separated digest persists. Binds fix
client/session/workspace/root/profile for one connection and receive an injected daemon lifecycle
binding rather than constructing privileged authority.

Managed-root creation refuses every pre-existing destination, records canonical native filesystem
identities for both the new root and trusted Git common directory, and rejects aliases through
durable repository-identity uniqueness. Failed registration removes only the same still-empty
directory CodeComm created; replacements and concurrent content are preserved.

The local outbox reserves signed proposals and origin sequences transactionally, forwards one
proposal per origin, returns exact duplicate outcomes, and recovers pending queues after restart.
Request cancellation interrupts every blocking launch/resume bind operation without stopping the
service. Per-origin workers retire after observing an empty durable queue and remove only their own
map entry under the wake lock, preventing both goroutine leaks and lost wakeups.
Recovery removes unreserved launches, marks locally owned live sessions disconnected, and applies
the 90-second reap; resume and reap share one entity-version CAS. Typed, bounded store reads validate
agent/task rows, reject noncanonical SQLite JSON arrays, and build each core context from one
transactional commitment cut.

Recovery rearms every active lease to a full TTL against the new boot's monotonic clock; persisted
monotonic values are never reused. Only the current leader proposes expiry with the lease's exact
entity-version CAS. Tests pin wall-clock-jump and event-volume immunity, renewal races, follower
silence, restart rearming, and corrupt timer refusal. Background reconciliation failures latch on
`Service.FatalError`, which `codecommd` monitors as terminal.

`internal/mcp` uses `github.com/modelcontextprotocol/go-sdk/mcp` v1.6.0. `Serve` is stdio-only and
retains one authenticated Unix-socket/named-pipe connection; it hard-codes agent class, accepts
exactly one launch selector or resume capability, performs the launch acknowledgement, serializes
requests without HTTP pipelining, bounds responses, and rejects ambiguous framing, unknown headers,
noncanonical bodies, lineage mismatches, and malformed daemon output.

The Phase 2 allowlist is `agent.session.get`, `context.get`, `task.list`, `task.create`, and
`task.claim`. Input/output schemas are closed and bounded; no tool accepts origin, actor, device,
agent-session, root, host-path, command, or executable fields. Mutations generate adapter-local
UUIDv7 request/entity IDs, map only to the matching daemon operation, and expose deterministic
accepted/rejected outcomes without converting domain rejection into a transport error.

One vertical test launches three distinct Codex/Claude combinations through real local IPC and
official SDK transports. Two agents race on one task, exactly one claim commits, all three observe
the winner through MCP, `context.get` remains binding-specific, and a third agent creates a task
that another immediately observes.

### 11. Status TUI and executable skeleton

`internal/status` and `internal/ui` provide a typed, bounded status snapshot, strict read-only
operator IPC, and a responsive Bubble Tea view of local identity, consensus/quorum, applied heads,
active agents, and tasks. Reads combine one transactional durable cut with validated runtime Raft
state. The client rebinds after daemon restart, including after an intervening failed dial; the TUI
retains stale data, reports unavailability, sanitizes terminal text, and refreshes without blocking
input. Golden renders cover 40-, 80-, and 120-column terminals.

`cmd/codecommd --foreground` now composes required native identity loading, single-node
Raft/SQLite, agent recovery, operator/agent IPC routing, fatal-node monitoring, and ordered
shutdown. `cmd/codecomm` exposes `status` JSON and the status TUI. Both take explicit endpoint and
lineage arguments for the walking skeleton; workspace locking, registry resolution, detached
process management, and on-demand startup remain the later `supervisor` phase.

MCP clients retain only their in-memory resume capability and automatically rebind after a local
daemon endpoint restart using serialized exact-request replay and bounded exponential jittered
backoff. A real integration test proves the same agent-session and working-root identities survive
the restart. A subprocess test kills `codecommd` with `SIGKILL` twice and verifies unchanged event
and result heads, projection accumulator, state digest, and logical rows after each recovery.

The frozen reducer registry now contains one accepted-path fixture for every registered V1 kind.
Each fixture records canonical signed input, complete prior logical rows and coherent replayed
event/result/accumulator heads, deterministic outcome and projection mutations, result hash, and
resulting accumulator. Registry completeness and explicit regeneration gates prevent silent drift.

## Evidence

Current verification:

```text
go test -count=1 ./...
go test -race -count=1 ./internal/mcp ./internal/store ./internal/agent ./internal/ui
go vet ./...
go run honnef.co/go/tools/cmd/staticcheck@v0.7.0 ./...
go mod tidy -diff
go mod verify
gofmt -l cmd internal
git diff --check
CGO_ENABLED=0 GOOS={linux,windows,darwin} GOARCH={amd64,arm64} go test -exec=true ./...
```

All pass; the full suite includes real loopback Raft, production local IPC, and the three-client MCP
race, endpoint restart/resume, and process-kill recovery. Test binaries compile with CGo disabled
for Linux, Windows, and Darwin on AMD64 and ARM64. Linux/Windows native credential-store behavior
still requires their CI runners as noted in step 3.

Independent store pools are not scheduled concurrently inside one test process: both the pinned and
current modernc stacks showed allocator/binding corruption under that artificial shape, while V1
runs one store per daemon process. Concurrent use and close of one production-sized pool remain
normal- and race-tested. Reassess the driver before any future multi-store process architecture.

## Next

Proceed to Phase 3. Supervisor and registry lifecycle remain outside Phase 2 scope.

## Self-Review

1. **§2.5 invariants:** origin identity is daemon-derived, signed bytes are canonical and immutable,
   and credential storage fails closed without fallback; no consensus or durability claim is weakened.
2. **Reducer purity:** reducers perform no I/O and read no clock or local leadership state; role,
   sequence continuity, CAS, authorization, and domain decisions use committed state only.
3. **Frozen commitments:** V1 canonical, schema, chain/result/projection, signed event/outcome, and
   accumulator fixtures are frozen only after every registered kind passed the walking skeleton.
4. **Bounds:** envelope, local body, action count/text/duration, identifiers, canonical JSON,
   signatures, and credential keys have boundary and one-past-boundary coverage.
5. **Failing-first evidence:** actor escalation, client-supplied origin, null/unknown fields,
   signature-before-extension ordering, pre-signature bounds, CAS/entity mismatches, aliasing,
   credential fallback, and native-provider failure paths have focused regressions.
6. **Consensus safety:** only committed command bytes enter reduction; startup, replay, snapshots,
   history, and ledger mismatches fail closed; readiness and shutdown cross explicit apply barriers.
7. **IPC authority:** kernel peer identity and endpoint session/workspace are checked before a
   binder runs; transport accepts no actor/device/agent identity and pins one returned handler.
8. **MCP authority:** the adapter is stdio-only, binds one agent proof over local IPC, exposes five
   closed tools, and cannot reach operator authority or supply actor/session/root identity.
9. **Executable recovery:** foreground composition fails closed on identity or lineage mismatch;
   daemon restart preserves commitments, agents resume with the same binding, and operator status
   reconnects after endpoint loss.
