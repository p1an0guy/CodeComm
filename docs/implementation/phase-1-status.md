# Phase 1 Status

Status: In progress  
Last updated: 2026-08-10  
Scope: the initial Raft/store/JCS/local-IPC gate in `docs/IMPLEMENTATION.md` §2. The broader authoritative
Phase 1 exit in design §13 remains open.

## Initial gate

The local macOS run supports the results below. The stable-store decision remains open, and every
GO becomes cross-platform evidence only after the checked-in Linux/macOS/Windows CI matrix passes.

| Question | Result | Evidence |
|---|---|---|
| No pre-commit index dependency | GO | `ApplyLog` constructs a future with no index/term; the real three-voter test submits bytes without ordering fields and learns the index only from FSM apply / the completed future |
| Apply barrier reaches local FSM | GO | A blocked FSM prevents `Barrier().Error()` from completing; releasing apply makes state visible before the barrier returns |
| Targeted transfer and 3-voter crash/restart | GO locally | A real TCP voter in a separate process becomes leader, is force-killed, the surviving majority elects and commits, and the voter restarts at the same store/address, catches up the offline commit, and accepts another targeted transfer. This is not standalone persisted-FSM replay |
| Staged-nonvoter proof without `matchIndex` | GO for the Raft API; integration open | A compacted leader adds a nonvoter; the target installs a file snapshot, withholds proof while blocked, validates every checkpoint-cut field including `log.Index-1`, then emits the exact proof after apply. The production SQLite transaction and authenticated closed endpoint remain Phase 1 work |
| Production stable-store fsync/crash behavior | OPEN | Static review proves `StoreLogs → bbolt.Tx.Commit`, dirty-page and metadata `fdatasync`/`File.Sync` when both `NoSync` flags are false, and error propagation. A post-ack subprocess kill proves process-crash reopen. Checked-in Linux `strace` verification requires same-DB-FD `data pwrite → sync → metadata pwrite → sync → ACK`; native CI has not run. Sync-failure/power-cut evidence, first-file directory durability, and the archived Bolt dependency remain |
| RFC 8785 primitive | GO locally; typed protocol integration open | Byte/depth-bounded strict token decode, official corpus plus Appendix B number edges, UTF-16 ordering, ±(2^53-1), Unicode/duplicate/trailing/non-finite negatives, and differential fuzzing against an independent implementation. This generic spike is not the closed typed protocol decoder; schema item/string bounds and decode-once integration remain |
| Local API reachability/peer identity | GO on macOS; native CI pending | The listener is an owner-only AF_UNIX path, not TCP; the probe enforces `0700`/`0600` and verifies `LOCAL_PEERCRED` plus `LOCAL_PEERPID`. Linux uses `SO_PEERCRED`. Windows uses an owner-only SID DACL, impersonation-token SID check, client PID, and pinned `go-winio` code that unconditionally sets `FILE_PIPE_REJECT_REMOTE_CLIENTS` |

Executable evidence:

- `go test ./spikes/phase1/raftprobe`
- `go test -race ./spikes/phase1/raftprobe`
- `go test ./spikes/phase1/localipc`
- `go test ./internal/codec`
- `go test ./internal/codec -run=^$ -fuzz=FuzzCanonicalizeDifferential -fuzztime=30s`

The Raft tests use real loopback TCP transports, subprocess death/restart, `raft-boltdb`, bbolt,
file snapshots, elections, configuration entries, and FSM execution. They do not mock Raft or its
store. The probe package is outside `internal/consensus` so production code cannot treat a spike as
accepted production code.

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
| `github.com/boltdb/bolt` | v1.3.1 | Go module checksum | MIT | Archived transitive import used only by `raft-boltdb/v2`'s optional V1 migration function; CodeComm never calls it, but its compiled dependency is an unresolved maintenance exception |

`go.sum` pins module content. GitHub Actions are pinned to immutable commits. License and SBOM
automation still belong to the remaining Phase 1 CI/harness work.
`govulncheck` v1.6.0 reports no reachable vulnerability. The local Go 1.26.4 toolchain has two
non-reachable standard-library advisories fixed in 1.26.5; CI selects the latest `1.26.x`, and no
release may use the affected patch.

## Remaining Phase 1

This initial gate does not complete design §13. Before Phase 2 daemon work, Phase 1 must still prove:

- stable-store sync observation/failure propagation, first-file parent-directory durability,
  power-cut evidence, and resolution of the archived Bolt dependency;
- production SQLite plus authenticated closed-endpoint integration for the target-applied proof;
- native CI results, including Linux/Windows runtime IPC checks;
- TLS profile/ALPN closed dispatch, no resumption, and RFC 8441 consensus framing;
- pairing/exporter/DER, credentials, clock endorsements, and all-asleep renewal;
- multicast/Ethernet/VPN behavior;
- Git `sha1`/`sha256` bundle, quarantine, fsync, raw-path, and ref-policy behavior;
- remaining canonical protocol, checkpoint/snapshot, recovery, IPC, and Git fixtures;
- reconciliation transitions, authority handoff, crash points, halted follower, and settled-nonvoter
  evidence required by the authoritative Phase 1 exit.

No production daemon or `internal/consensus` implementation starts until those gates close.

## Self-review

1. **Potentially affected §2.5 invariants:** no split-brain strong state and no acknowledged event
   loss. The change adds only probes and a bounded JCS primitive; it weakens neither invariant.
2. **Reducer purity:** no reducer exists or changed; no reducer input or clock read was added.
3. **Frozen outcomes:** no event kind or `(kind, schema_version)` outcome exists or changed.
4. **Bounds:** depth 32, ±(2^53-1), 4 MiB generic JCS, and 1 MiB signed-object caps have boundary
   and one-past-boundary tests; typed schemas must impose their tighter normative bounds.
5. **Coverage/failing-first evidence:** design §12.2's JCS, no-precommit-index, library-level
   promotion proof, and real-Raft requirements are exercised by `internal/codec` and
   `spikes/phase1/raftprobe`. Barrier, mutated-cut, premature-proof, subprocess voter death/restart,
   post-ack store-kill, sync-trace verifier, and local IPC tests are focused reproducers. Store
   power-loss/sync failure and the production SQLite/endpoint proof remain explicitly open.
