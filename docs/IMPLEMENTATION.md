# CodeComm V1 Implementation Plan

Companion to `docs/design/` rev 0.14. The design says *what* and *why*; §13 says in what order and
what proves done. This says **how to start**, and only covers what the design deliberately leaves
open: package layout, build order within a phase, and the decisions that must be made once and then
never re-litigated.

Owner: ijonahch (solo). Every change touching cryptography, identity, credentials, consensus,
reducers, migrations, path handling, or process execution runs the five-item self-review checklist in
part 00's front matter. That checklist is the review gate; it is not optional and it is written on
the change, not remembered.

---

## 0. Ground rules

1. **Phase 1 gates everything.** It is a spike whose output is a go/no-go on the candidate Raft
   library. Do not write daemon code against `hashicorp/raft` before §3's five capability questions
   are answered on the real API. If any fails, the library is replaced and §3 changes — which
   invalidates work built on it.
2. **Fixtures freeze late.** §12.2 freezes canonical encoding, the DDL, event fixtures, and the
   projection accumulator preimage as immutable golden fixtures. Freezing is a one-way door:
   unwinding means a `digest_version` bump plus a migration. Freeze at the *end* of phase 2, after
   the walking skeleton has exercised every kind once.
3. **Reducers are the crown jewels.** The frozen-reducer rule (§5.5) means a wrong outcome for a
   released `(kind, schema_version)` can never be corrected in place — only a new kind or version.
   Reducer code gets the checklist every time, no exceptions.
4. **Nothing in a reducer reads a clock, the filesystem, a peer, or local config.** Only committed
   state, the current proposal, and chain heads. This is the single easiest way to corrupt every
   replica, and the projection accumulator will catch it only after the fact.
5. **Write the failing test first.** §12.1 requires it. For reducers, "failing first" means the
   golden fixture exists and fails before the reducer does.

---

## 1. Package layout

One decision, made now, because §12.5's import-cycle and layering lint enforces whatever is chosen.
Dependencies point downward only; no package imports a package above it.

```
cmd/
  codecomm/              CLI + TUI entrypoint
  codecommd/             session daemon entrypoint
  codecomm-supervisor/   per-user supervisor entrypoint

internal/
  domain/          entities, enums, bounds, state machines. NO I/O, no imports below.
    task/ plan/ memory/ lease/ device/ agentsession/ publication/ conflict/ policy/ voterset/
  codec/           JCS canonicalization, base64url, domain-separated signing input, digests
  crypto/          Ed25519 + SHA-256 wrappers, credential-store adapters (per-OS)
  event/           envelope, origin construction, signing/verification, kind registry
  reducer/         one file per kind. Pure: (committed state, proposal) -> outcome. No I/O.
  chain/           event chain, result chain, checkpoints, projection accumulator
  store/           SQLite: schema, migrations, apply transaction, projections, backup
  consensus/       Raft node, FSM adapter, voter-set reconciliation, recovery
  transport/       TLS 1.3, two-plane cert profiles, mTLS verification, REST/SSE, HTTP/2
  discovery/       multicast advertise/receive, endpoint hints, bounded source state
  pairing/         invite, exporter-bound proof, SAS
  credential/      epoch lifecycle, clamps, clock endorsements
  gitplumbing/     system-Git invocation, bare store, sparse drafts, refs, bundles, quarantine
  publication/     staging receipts, canonical ref CAS, materialization
  agent/           agent-session lifecycle, launch registry, managed roots, resume
  mcp/             stdio MCP server, closed tool schemas
  ipc/             Unix socket / named pipe, peer-credential verification, origin binding
  supervisor/      registry, on-demand start/stop, process detachment
  ui/              TUI views, state rendering, monochrome-safe styling
  platform/        per-OS: credential store, service integration, FS quirks, firewall
  testharness/     §12.3 harness — a V1 deliverable, not test scaffolding
```

**Layering, strictly enforced:** `domain` and `codec` import nothing internal. `reducer` imports
`domain` + `codec` + `event` only — never `store`, `consensus`, or anything with I/O. That constraint
is what makes reducers testable as pure functions and is the structural reason they stay
deterministic; if `reducer` ever needs `store`, the design has been misread.

`platform` is imported by leaves only, never by `domain` or `reducer`.

---

## 2. Phase 1 — the spike (do this first, alone)

Output is a written go/no-go, not code that ships. Five questions on the real library API:

| # | Question | Why it gates | If it fails |
|---|---|---|---|
| 1 | Does any path need a log index **before** commitment? | §5.2 rests on ordering metadata being unsigned local provenance | Replace library |
| 2 | Can a leader complete an **apply barrier** and know it applied through it? | §3 step 2 reads target + config after a barrier | Replace library |
| 3 | Is **targeted leadership transfer** available? | §3 step 3.3 transfers to a named device | Replace library |
| 4 | Can a staged nonvoter produce the **checkpoint proof** (four values + recomputed accumulator) without leader-side match-index access? | Promotion safety; §3 says phase 1 MUST replace the library if not | Replace library |
| 5 | Does the production stable store fsync as claimed under crash? | "No acknowledged event loss" | Replace store |

Also in phase 1, independent of the library:

- JCS canonicalization byte-identical on Linux/macOS/Windows in CI, against RFC 8785 vectors —
  this is the foundation every signature rests on, and cross-platform drift here is silent.
- A differential JCS fuzzer against a reference implementation.
- Prove local APIs are unreachable from another host.
- 3-voter crash/election spike.

**Exit:** all five answered on the real API, JCS golden fixtures byte-identical across three OSes,
local APIs proven unreachable. Write the answers down; they are ADR material.

Current evidence and open gates: [`docs/implementation/phase-1-status.md`](implementation/phase-1-status.md).

---

## 3. Phase 2 — walking skeleton, in this order

One device, one session, single-voter Raft, two MCP clients, a task claimed by one and observed by
the other. Build bottom-up so each layer is testable before the next exists.

1. **`domain`** — entities, enums, bounds, the §6.3 state machine as a pure transition table.
   Table-driven tests: every legal edge accepted, every absent edge rejected, terminal states admit
   no outgoing edge.
2. **`codec`** — JCS, base64url, `signed_input = label || 0x00 || signed_bytes`. Freeze the RFC 8785
   vectors and the `device_id` derivation vectors here.
3. **`crypto`** + `platform` credential store — including the refuse-to-start path when the store is
   locked or unreadable. That refusal is not a crash and must not be retried on backoff.
4. **`event`** — envelope, kind registry, and **`origin` construction from the IPC binding**. Write
   the negative tests now: a client-supplied `origin` is a schema rejection, and an MCP-bound
   connection cannot assert `actor_type: human`. This is the enforcement point for every
   operator-only guarantee in the document; if it is added late it will be added wrong.
5. **`store`** — schema, migration 0001, the §5.3 step-7 apply transaction with its complete
   enumerated write set, `synchronous=FULL`, and the startup assertion
   `applied_index ≤ last Raft log index`.
6. **`reducer`** — one kind at a time, in dependency order: `task.*` → `activity.recorded` →
   `lease.*` → `agent.session.*` → `plan.*`/`memory.*` → `membership.*`/`policy.changed` →
   `control_file.change_proposed` → `publication.*`/`workspace.conflict.*` →
   `credential.authorized`/`consensus.checkpoint`/`audit.recorded`.
   Each kind lands with its golden reducer-outcome fixture: (prior state, input) → outcome, rejection
   code, resulting accumulator.
7. **`chain`** — event chain, result chain, checkpoints, projection accumulator. Assert immunity to
   vacuum, rowid reuse, and insertion order.
8. **`consensus`** — single-voter Raft + FSM adapter. Real Raft, real SQLite; §12.2 forbids mocking
   either when testing their behavior.
9. **`ipc`** — socket/pipe with peer-credential verification (`SO_PEERCRED`/`LOCAL_PEERCRED`, or an
   explicit named-pipe DACL), mode `0600` in an owner-only directory.
10. **`agent`** + **`mcp`** — launch registry, managed roots, closed tool schemas, per-connection
    binding.
11. **`ui`** — minimum status view.

**Exit:** skeleton runs; three concurrent MCP clients hold distinct agent sessions; a local task race
produces exactly one winner; a `SIGKILL`ed daemon recovers with an unchanged accumulator; every §5.4
kind round-trips through a golden fixture. **Then freeze the fixture set.**

---

## 4. Phases 3–6

These follow §13 directly and need no elaboration here beyond build order within each:

- **Phase 3 (secure mesh):** `discovery` → `pairing` → `credential` → `transport` (consensus plane
  first, since it never expires and everything else recovers through it) → 3-voter cluster →
  voter-set reconciliation → revocation. Must exit proving a minority commits nothing, self-promotes
  nothing, and authorizes no credential — the fail-closed half, not just the happy path.
- **Phase 4 (bootstrap):** `gitplumbing` bundle path, no-checkout clone, isolated Git config
  (including `core.hooksPath`, `init.templateDir`, `GIT_CONFIG_*`, `core.fsmonitor`,
  `protectNTFS`/`protectHFS`), preflight.
- **Phase 5 (object/ref mesh):** bare store → sparse drafts → `publication` staging → canonical ref
  CAS → materialization → conflicts → `repo include`. The opt-in inclusion consent flow is the
  newest, least-reviewed design in the document; treat it as security-critical.
- **Phase 6 (hardening):** installers, native E2E, backup/export, `state recover`, `state scrub`.

---

## 5. Standing risks to watch while building

- **Solo review.** No second reader on consensus, credential, and reducer paths. The mechanical gates
  and frozen fixtures are the compensating control; they only work if the checklist is actually
  written each time.
- **System Git is a runtime dependency.** Resolve it once at daemon start to an absolute path, record
  it, version-verify, re-verify on change. Never resolve `git` from `PATH` per invocation.
- **Staging receipts are unverifiable attestations.** One dishonest voter in a 3-voter session can
  defeat the staging quorum. Detection is post-hoc refetch; build that refetch, don't skip it.
- **Opt-in draft inclusion can leak a secret irreversibly.** Revocation ends authorization, not
  possession.
- **OQ2 (scale) is still open** and closes at phase 3's first real benchmarks. §11.2 values may move;
  no mechanism should.
