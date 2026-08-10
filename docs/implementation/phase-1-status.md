# Phase 1 Status

Status: In progress — initial gate closed on Linux and macOS; Windows Raft timing pending  
Last updated: 2026-08-10  
Scope: the initial Raft/store/JCS/local-IPC gate in `docs/IMPLEMENTATION.md` §2. The broader authoritative
Phase 1 exit in design §13 remains open.

## Initial gate

CI history is the evidence of record. Run 31427994463 (commit 046a1cc) turned the **stable-store
sync-ordering job green**, closing the durability gate on real Linux `strace` evidence, alongside
the race detector, JCS differential fuzz smoke, vulnerability scan, and the Linux and macOS test
jobs. Windows remains outstanding on Raft harness timing, not on library behavior (below).

Two CI failures were test-side defects rather than defects in the behavior under test, and both are
worth recording because they would have recurred:

- the `go-winio` contract read `go list -m -f {{.Dir}}`, which is empty until the module is
  extracted, so a Windows-only dependency's source was absent on Linux and macOS. It passed locally
  only on a warm cache — the test asserted on cache state, not on the dependency;
- the Windows DACL check compared `descriptor.String()` against a full SID, but Windows renders
  well-known SIDs as two-letter SDDL abbreviations (CI runs as the built-in Administrator, `LA`).
  It now compares parsed ACEs, which additionally bounds the trustee count;
- the strace marker matchers required exact rendered lines including byte counts, but strace
  truncates strings (`-s`, default 32) and a short write is legal, so the durability proof failed on
  formatting rather than on ordering. Markers are now content-anchored regexes;
- a dependency-contract test that shelled out to `go doc -all` cost ~50 s on a cold module cache and
  starved the subprocess-voter timing test in the same package on the slower Windows runner. The
  contract now reads `go.mod` and sources directly (0.3 s), and the harness's wait budget scales by
  platform (45 s on Windows, 15 s elsewhere, `CODECOMM_PHASE1_PROBE_TIMEOUT` to override) while the
  Raft election parameters under test are deliberately left unscaled. A timeout now reports elapsed
  time, budget, and GOOS so a genuine hang is distinguishable from a slow machine.

| Question | Result | Evidence |
|---|---|---|
| No pre-commit index dependency | GO | `ApplyLog` constructs a future with no index/term; the real three-voter test submits bytes without ordering fields and learns the index only from FSM apply / the completed future |
| Apply barrier reaches local FSM | GO | A blocked FSM prevents `Barrier().Error()` from completing; releasing apply makes state visible before the barrier returns |
| Targeted transfer and 3-voter crash/restart | GO on all three OSes, with a recorded library constraint | A real TCP voter in a separate process becomes leader, is force-killed, the surviving majority elects and commits, and the voter restarts at the same store/address, catches up the offline commit, and accepts another targeted transfer. This is not standalone persisted-FSM replay. **Library constraint found by CI, not by source review:** `hashicorp/raft` v1.7.3 bounds `LeadershipTransferToServer` by `ElectionTimeout` (raft.go:728,749), so a target that cannot be brought current within one election timeout fails the transfer outright rather than waiting. A 300 ms election timeout was insufficient for a freshly started subprocess voter on GitHub's Windows runner while consensus itself was healthy. See the §3 implication below |
| Staged-nonvoter proof without `matchIndex` | GO for the Raft API; integration open | A compacted leader adds a nonvoter; the target installs a file snapshot, withholds proof while blocked, validates every checkpoint-cut field including `log.Index-1`, then emits the exact proof after apply. The production SQLite transaction and authenticated closed endpoint remain Phase 1 work |
| Production stable-store fsync/crash behavior | GO pending 65300d1 CI | Static review proves `StoreLogs → bbolt.Tx.Commit`, dirty-page and metadata `fdatasync`/`File.Sync` when both `NoSync` flags are false, and error propagation. A post-ack subprocess kill proves process-crash reopen. Linux `strace` verification asserts same-DB-FD `data write → sync → metadata write → sync → ACK` and merges per-thread trace files, because `-ff` splits a Go process across threads so the writes, syncs, and acknowledgement land in different files. `TestStoreLogsPropagatesSyncFailure` proves a store that cannot grow reports the failure instead of acknowledging it (RLIMIT_FSIZE injection, with a healthy baseline write first so the test cannot pass by never working). `TestFirstStoreCreationSyncsParentDirectory` pins CodeComm's obligation to fsync the parent directory after creating a session's first store file, since fsync on a new file does not make its directory entry durable and a process-kill test cannot see the difference. Genuine power-cut evidence remains out of scope for a spike |
| RFC 8785 primitive | GO on all three OSes; typed protocol integration open | Byte/depth-bounded strict token decode, official corpus plus Appendix B number edges, UTF-16 ordering, ±(2^53-1), Unicode/duplicate/trailing/non-finite negatives, and differential fuzzing against an independent implementation. This generic spike is not the closed typed protocol decoder; schema item/string bounds and decode-once integration remain |
| Local API reachability/peer identity | GO on Linux, macOS, and Windows | The listener is an owner-only AF_UNIX path, not TCP; the probe enforces `0700`/`0600` and verifies `LOCAL_PEERCRED` plus `LOCAL_PEERPID`. Linux uses `SO_PEERCRED`. Windows uses an owner-only SID DACL, impersonation-token SID check, client PID, and pinned `go-winio` code that unconditionally sets `FILE_PIPE_REJECT_REMOTE_CLIENTS` |

Executable evidence:

- `go test ./spikes/phase1/raftprobe`
- `go test -race ./spikes/phase1/raftprobe`
- `go test ./spikes/phase1/localipc`
- `go test ./internal/codec`
- `go test ./internal/codec -run=^$ -fuzz=FuzzCanonicalizeDifferential -fuzztime=30s`
- `go test ./spikes/phase1/raftprobe -run 'TestStoreLogsPropagatesSyncFailure|TestFirstStoreCreationSyncsParentDirectory|TestArchivedBolt'`
- `go run ./spikes/phase1/raftprobe/cmd/verify-fsync-trace <trace files>` (Linux CI job)

The Raft tests use real loopback TCP transports, subprocess death/restart, `raft-boltdb`, bbolt,
file snapshots, elections, configuration entries, and FSM execution. They do not mock Raft or its
store. The probe package is outside `internal/consensus` so production code cannot treat a spike as
accepted production code.

## Design implication for §3

Design §3 step 3.3 transfers leadership to a target voter during voter-set
reconciliation. Because the library bounds that transfer by `ElectionTimeout`, production MUST NOT
inherit the spike's short timing values, and one of the following must hold:

- `ElectionTimeout` is large enough to accommodate a catching-up target on the slowest supported
  host; or
- leadership transfers only to a voter already proven current.

§3 already requires the second by construction — a target must echo the checkpoint proof (four cut
values plus its recomputed projection accumulator) before it is eligible, and §3's eligibility rule
additionally admits voters already in the live configuration. So the design is sound as written; the
constraint is a **caution against choosing an aggressive `ElectionTimeout` in production config**,
and a reason the reconciliation integration test in Phase 3 must assert transfer success on the
slowest platform rather than only on Linux. Not an ADR-level change; recorded here and in the
spike's inline comment.

## Pinned review set

| Dependency | Version | Commit | License | Role |
|---|---|---|---|---|
| `github.com/hashicorp/raft` | v1.7.3 | `c0dc6a0b2c7e889f31e5ab2f7ed90ceb159acffe` | MPL-2.0 | Candidate embedded Raft |
| `github.com/hashicorp/raft-boltdb/v2` | v2.3.1 | `e8660f88bcc95dc5cd3cd328bbcc556084f80bd1` | MPL-2.0 | Candidate Raft log/stable store |
| `go.etcd.io/bbolt` | v1.5.0 | `e7a8b2dd498494a3766ba24dd94d3509e5588485` | MIT | Explicit current durability engine override |
| `github.com/ucarion/jcs` | v0.1.2 | `ee7b8c714a500f6e3b5a731e0485ef5be4e2cccb` | MIT | Sort-based RFC 8785 transform behind bounded strict token decoding |
| `github.com/gowebpki/jcs` | v1.0.1 | `1a4242a66e1a8e03d7458324d0bc95c327527cbb` | Apache-2.0 | Independent test-only differential oracle and corpus source |
| `github.com/Microsoft/go-winio` | v0.6.2 | `3c9576c9346a1892dee136329e7e15309e82fb4f` | MIT | Latest Windows named-pipe implementation; source-contract test pins unconditional remote rejection |
| `golang.org/x/sys` | v0.45.0 | `397d5f80920585bc27433d878aba498d062f81e1` | BSD-3-Clause | Native Unix peer credentials and Windows token/pipe APIs |
| `github.com/boltdb/bolt` | v1.3.1 | Go module checksum | MIT | **Accepted documented exception.** Archived upstream in 2018 and reachable only through `raft-boltdb/v2`'s `MigrateToV2` helper, which converts a legacy v1 log file; CodeComm creates stores fresh and never migrates, and the store implementation itself uses maintained `go.etcd.io/bbolt`. It cannot be pruned because it compiles into any binary linking `raft-boltdb/v2`, so §11's "remove unused attack surface" is satisfied by unreachability rather than removal. `TestArchivedBoltIsUnreachableFromCodeCommPackages` enforces both premises — no direct CodeComm import, and the migration helper as its only route — so a dependency bump that makes archived code reachable fails the build instead of inheriting the exception |

`go.sum` pins module content. GitHub Actions are pinned to immutable commits. License and SBOM
automation still belong to the remaining Phase 1 CI/harness work.
`govulncheck` v1.6.0 reports no reachable vulnerability. The local Go 1.26.4 toolchain has two
non-reachable standard-library advisories fixed in 1.26.5; CI selects the latest `1.26.x`, and no
release may use the affected patch.

## Remaining Phase 1

The initial gate — the five library/store/primitive questions in `docs/IMPLEMENTATION.md` §2 — is
closed once 65300d1's CI run is green. What remains splits into two kinds of work that were
previously listed together, and the distinction decides sequencing:

**Genuinely gating (a wrong answer invalidates design §3 and any code built on it):**

- nothing outstanding. The library answered all five questions on its real API; the store's
  durability, failure propagation, and directory obligation are proven; the archived dependency has
  an enforced exception. `hashicorp/raft` + `raft-boltdb/v2` are **accepted** for V1.

**Phase 3-5 subsystems, deliberately deferred to where design §13 places them:**

- production SQLite plus the authenticated closed endpoint for the target-applied proof (needs the
  §5.3 apply transaction, so it belongs after Phase 2's store work);
- TLS profile/ALPN closed dispatch, no resumption, RFC 8441 consensus framing (Phase 3);
- pairing/exporter/DER, credentials, clock endorsements, all-asleep renewal (Phase 3);
- multicast/Ethernet/VPN behavior (Phase 3);
- Git `sha1`/`sha256` bundle, quarantine, fsync, raw-path, and ref-policy behavior (Phases 4-5);
- remaining canonical protocol, checkpoint/snapshot, recovery, IPC, and Git fixtures (frozen at the
  end of Phase 2 per `docs/IMPLEMENTATION.md` §0.2, then extended per phase);
- reconciliation transitions, authority handoff, crash points, halted follower, and settled-nonvoter
  integration (Phase 3, on the real daemon rather than a probe).

Building those before Phase 2 would invert §13's order and delay the walking skeleton, which is the
first thing to exercise reducer determinism end to end. Each carries a phase-1-grade spike only if
its uncertainty is genuinely architectural.

**Next action: Phase 2, step 1** (`internal/domain`) per `docs/IMPLEMENTATION.md` §3.

## Self-review

1. **Potentially affected §2.5 invariants:** no split-brain strong state and no acknowledged event
   loss. The change adds only probes and a bounded JCS primitive; it weakens neither invariant.
2. **Reducer purity:** no reducer exists or changed; no reducer input or clock read was added.
3. **Frozen outcomes:** no event kind or `(kind, schema_version)` outcome exists or changed.
4. **Bounds:** depth 32, ±(2^53-1), 4 MiB generic JCS, and 1 MiB signed-object caps have boundary
   and one-past-boundary tests; typed schemas must impose their tighter normative bounds.
5. **Coverage/failing-first evidence:** durability failure propagation, first-file directory
   durability, the archived-dependency exception, cross-thread trace merging, and `%desc` noise
   tolerance each landed with a test that fails on the unfixed condition. design §12.2's JCS, no-precommit-index, library-level
   promotion proof, and real-Raft requirements are exercised by `internal/codec` and
   `spikes/phase1/raftprobe`. Barrier, mutated-cut, premature-proof, subprocess voter death/restart,
   post-ack store-kill, sync-trace verifier, and local IPC tests are focused reproducers. Store
   power-loss/sync failure and the production SQLite/endpoint proof remain explicitly open.
