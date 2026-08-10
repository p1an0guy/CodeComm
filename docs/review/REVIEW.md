# CodeComm `design.md` rev 0.6 — design review

Complete. Seven lenses (security/crypto, distributed correctness, cold-reader clarity,
implementation readiness, internal consistency, external technology facts, simplicity-vs-best-
practice) plus a completeness critic, each followed by an adversarial verifier that re-read the doc
and tried to refute the findings. 5 findings were rejected outright as already covered or factually
wrong; nearly every "blocker" was downgraded on verification. What follows survived that.

Raw data: `final-review-raw.json` (45 findings with verifier reasoning), `review-state.json`
(earlier pass). Scripts: `codecomm-review-final.js`.

## The three questions you asked

**Is it self-contained?** **Partly.** The mechanism layer is exceptionally so — an engineer can read
§3-§9 and understand topology, consensus usage, credential lifecycle, sync containment, and failure
behavior with no outside context. The product layer is absent. There is no problem statement, no
motivation, no user model, and no end-to-end narrative. A reader finishes knowing precisely how a
task transition is committed and never learning **what a task is or who it is for**.

**Is it correct and secure?** **Partly.** No confirmed exploitable hole. One mechanism as specified
cannot be built on the stack the doc mandates (below). The security layer is *under-specified rather
than wrong* — no signature suite, hash, canonical encoding, or domain separation is named anywhere;
the only algorithm in 1010 lines is SHA-256 at line 572, for Git bundles.

**Ready for an implementation plan?** **Yes, with caveats.** Phase 1 (spikes, threat model, ADRs,
Raft review, native CI) can start today essentially as written — answering open items is its job.
Phases 2-3 cannot be planned until the eight must-fixes below are closed.

## Must-fix before an implementation plan

Ranked by what would actually hurt the project most.

**1. The product itself is unspecified.** The entire application domain is eight bullets (429-437).
There is not one field of a task, plan revision, memory record, or lease anywhere: no title, size
bounds, priority, dependency relations, acceptance criteria, plan-to-task linkage, memory record
shape, or lease glob syntax. `payload: {}` and `actions: []` are opaque, the V1 `kind` namespace is
never enumerated though §5.3 deterministically rejects unknown kinds, and `context.{json,md}` — the
primary agent-facing payload — has no schema, size bound, or refresh trigger. Ten wire fields
(`credential_epoch`, `advertising_key_digest`, `advertisement_nonce`, `committed_membership_index`,
`schema_version`, `entity_id`, `expected_entity_version`, `hlc`, `actor_type`,
`previous_entry_hash`) appear exactly once each, inside JSON examples, untyped and unbounded. Two
§2.1 goals (activity, acknowledgements) have no table; `credential_authorizations` — the state every
mTLS handshake validates against — has no persistence home at all.
*Why it's first:* every reducer, projection, MCP schema, TUI view, and golden fixture derives from
this. §12.2 mandates unit coverage of "task/plan states" for entities that are never specified. The
implementation-ready surface is inverted — the commodity layers are deep, the differentiated product
is a sketch.
*Fix:* §6.0 domain model (typed schema per entity, bounds, relations, reducer-validated vs display)
and §5.4 event-kind registry (every V1 kind with payload schema, `actor_type`/`capture_level` enums,
`expected_entity_version` base and create-event rule).

**2. Canonical serialization, digests, and domain separation are unspecified.** No signature scheme,
hash, canonical encoding, or per-context domain label anywhere. `device_id` is "Hash of long-lived
device public key" (152) with no hash, encoding, or truncation — and it is the identifier every
authorization decision keys on. "Canonical" appears six times, never bound to a named encoding. The
same identity key signs six structurally different objects (genesis, discovery datagram, invite/key
binding, origin proposal, leader consensus block, snapshot digest) with no domain tag — the textbook
precondition for cross-protocol signature confusion, and one line per context to close.
*Why:* line 818 makes cross-platform signature stability and immutable golden fixtures a **merge
gate**. Those fixtures cannot be authored from these definitions, so the gate is inert from day one
and two OS builds may disagree on signed bytes.
*Fix:* §4.0 crypto primitives — one named canonical encoding for signed bytes (e.g. RFC 8785 JCS
over the §5.2 JSON, with 296's binary encoding declared a transport wrapper only), digest text
encoding, exact `device_id` derivation, `previous_entry_hash` chain input, one ASCII domain label per
context. Suite selection stays in ADR-003, named as a phase-1 exit item.

**3. The leader cannot pre-assign and sign `(term, log_index, previous_entry_hash)` on the mandated
Raft libraries.** Lines 301-304 and step 3 (356) require assigning and signing ordering metadata
*before* proposing to Raft. `hashicorp/raft`'s `Apply`/`ApplyLog` and `etcd/raft`'s `Propose` both
take a sealed payload and assign term/index internally, with **no reservation API**. The only
workaround is serializing every proposal against `LastIndex()+1`, which races leader no-op and
configuration entries and forecloses the pipelining the line 889 benchmarks assume. Separately the
chain's domain is self-contradictory: `previous_entry_hash` sits in the leader-signed block (336),
but line 367 says rejected commands and config entries consume indices so accepted-event indices
have gaps — if the chain covers all Raft entries, a nonvoter receiving only accepted events (371)
can never recompute it; if it covers accepted events only, the leader cannot compute it at propose
time because acceptance is decided at apply (358-362). Chain continuity is also missing from the
step 5 recheck list even though line 373 makes the snapshot chain digest load-bearing for joiners.
*Not a safety hole:* lines 88 and 303-305 make quorum commitment plus deterministic apply
authoritative, so a signed-but-uncommitted entry never becomes history.
*Fix:* drop leader pre-assignment from the signed proposal; let Raft own ordering; derive the chain
at apply over accepted events only (`chain_n = H(domain_label || chain_{n-1} || canonical_event_n)`
with stated hash and `chain_version`); keep observed `(term, log_index)` as unsigned provenance. If a
leader attestation is wanted, make it a separate post-apply committed checkpoint over
`(term, applied_index, chain_digest)` — expressible on standard APIs. Add chain continuity to step 5.

**4. Daemon-to-session cardinality is contradictory.** Lines 12/43 say one daemon per *user*. Line
654-655 specifies a per-*workspace* lock preventing "two local daemons" — presupposing several. Line
533 pins one sidecar per *session*. All state lives under a workspace-relative `.codecomm/` with
exactly one `session.json`, `state.db`, and `consensus/`, so the on-disk schema is single-session.
The MCP process reaches the daemon through "a Unix socket or Windows named pipe" — singular, with no
addressing scheme for choosing among several.
*Why:* a developer working on two repositories at once is the ordinary case. This determines the
process model, the IPC namespace every client uses, port and multicast-advertiser counts per host,
and the meaning of the §14 targets. Unresolved, the first three components built will each assume
something different.
*Fix:* state it in §3's component table — recommend daemon-per-(user, session) with a per-user
registry directory and client selection by `--session` or workspace-root ancestry — then reconcile
12/43 with 654-655 and 533, and scope the 2-8 device / 32-agent caps to a named unit.

**5. The user model is never stated — one person with several devices, or several people?** There is
no user, person, or principal identity anywhere. The identifier table has device, session, workspace,
agent-profile, agent-session, and event IDs — no human. Roles are granted to *devices*. Yet both
models are silently assumed: multi-human at 223-224 ("Both users compare and confirm..." is not a
ceremony if one person does both halves), 183 ("cannot be self-granted" is vacuous if one human owns
every device), and 686 (workspace readability is only a threat between distinct people);
single-human at 12/43 ("per-user daemon"), 442 ("same-user process"), and 688 (compromised local
account out of scope). §15 has no question on this.
*Why:* this one decision determines whether the role model needs a user layer or is over-built,
whether two-sided SAS confirmation is a real control or theater, whether the audit log has a purpose,
and whether at-rest encryption is optional or mandatory. Roughly a third of the mechanisms in §4,
§8.4, and §10 are priced for the multi-human case while the narrative voice is single-human.
*Fix:* §2.0 user model with a named primary and a named excluded persona. File as Open Question 0,
due before phase 1 exits.

**6. No ownership release or operator override — a liveness defect reachable by an agent exiting.**
Line 496 says session expiry "ends the session, releases leases" — *leases* are released, task claims
are not. Ownership is `(device_id, agent_session_id)` and `agent_session_id` is never reused, so a
task in `claimed`/`in_progress`/`blocked` whose agent ended is permanently owned by an identity that
can never return, and the compare-and-set reducer rejects everyone else. The whole mutation surface
is one-directional: no unclaim, reassign, `lease.release`, memory tombstone, or plan rollback in MCP;
no `agent stop`, `task unclaim|reassign|cancel`, or voluntary `peer leave` in the CLI. The failure
table covers 21 infrastructure failures and zero human-intervention scenarios.
*Why:* triggered by the most common event in the system — a process exiting. Risk 7 already concedes
agents may ignore the workflow, which makes override required, not optional. A coordination tool
whose only human verbs are "start more work" is missing the half operators use most.
*Fix:* §6.3 ownership release and operator override; claims return to `ready` on committed
session-end; owner/editor force-release and reassign as committed audited events; the missing CLI
verbs with MCP exclusions stated explicitly. Also replace the 431/498 state *chains* with edge lists
(they omit every real edge — no return from `blocked`, no release from `claimed`) and mark
`sync_blocked` an orthogonal flag gating `-> done`, not a state.

**7. No runtime rule for a committed entry a replica cannot apply, and "projection digest" is
undefined.** Nothing states what a replica does on encountering a committed entry whose kind, field,
or reducer branch it doesn't implement — line 292-294's "unknown required capabilities fail closed"
is scoped to *wire messages* and cannot apply to an already-committed entry. No version-skew window,
and no rule freezing reducer semantics per schema version: a v1.1 daemon that "fixes" a transition
accepts at index N what v1.0 stored as a rejection, diverging both permanently while both believe
they are deterministic. Meanwhile "projection digest" — the harness pass/fail criterion at 834-836 —
appears exactly once, with no tables, row ordering, encoding, hash, or definition of "eligible".
SQLite page hashes are nondeterministic across vacuum and rowid reuse; unordered `SELECT` isn't
stable.
*Why:* the one bug class that silently destroys the correctness story, triggering on the first real
upgrade because nothing stops a user updating one laptop. The doc's own divergence detector is the
undefined digest, so it cannot be implemented. Compensating controls (783's compatibility gate, 848's
cross-version scenario) are test-time only.
*Fix:* normative §5.3 addition — per-command minimum-apply-version or feature gate, with a replica
that cannot deterministically apply **halting** rather than substituting a local rejection; the
supported skew window; new reducer semantics ship dark behind a committed capability-enable entry;
a §6.2 invariant that reducer behavior for an existing `(kind, schema_version)` MUST NOT change,
added to line 783's non-mergeable list. Define the digest as an ordered fold over named tables, rows
canonically encoded and sorted by primary key, with `digest_version` and a named hash.

**8. Endpoint churn and suspend/resume have no treatment, and they interact with the 30-minute
epoch.** §2.2 covers which networks work, never a network *changing*. Nothing specifies how a peer's
address updates, whether address changes are committed events, or how tunnels re-establish after DHCP
renewal, Wi-Fi→Ethernet, VPN reconnect, or suspend. "Sleep/wake" appears once, as a test-matrix item.
Multicast advertisement is `MAY` at an unnumbered interval, so it isn't reliable re-discovery, and
the manual fallback is a human action. No failure row for address change, suspend, or interface loss.
*The sharp part:* a laptop closed for 40 minutes wakes with expired credentials and, if quorum is
unreachable, into the renewal-only path with no session data — and neither §4.5 nor §9 mentions
suspend.
*Fix:* endpoint-churn subsection, three failure rows, required behavior for waking expired with
quorum unreachable, plus justifying and parameterizing the 30-minute epoch as committed genesis
policy with a pre-expiry countdown state.

## Notable should-fixes

Full list of 14 in `final-review-raw.json`. The ones I'd not skip:

- **§14 is unfalsifiable.** Latency targets name no measurement endpoints ("coordination visibility
  p95 <500 ms" — from what event to what, at what load, on what topology?). Line 946 ("Targets
  require benchmark validation before commitment") withdraws the section's normative force so nothing
  can fail. No §12.5 gate cites a §14 number; the benchmark list tracks dimensions §14 doesn't
  mention while omitting every latency target it states. Lines 939-944 are restated §2.4 invariants.
  No resource budgets at all (CPU, RSS, `.codecomm/` growth, battery).
- **§2.4 invariants are insufficient for the §2.1 goals.** Missing: durability ("no acknowledged
  event loss" appears only as a §14 bullet despite 363-364 specifying the exact mechanism),
  idempotent resumption, identity uniqueness/non-reuse, and **content confidentiality** — nothing
  states that workspace content, secrets, or activity never leave the authorized set.
- **§11's ~40 "release criteria" have no verifying gate.** Many are mechanically checkable (acyclic
  deps, no panic on peer input, bounded queues, no secrets in argv/logs, no ignored errors in
  security paths) but §12.5 enforces none of them. Convert the checkable subset into named gates with
  tools; state the rest as review-checklist items so the word "criterion" means something.
- **Line 139 is factually wrong.** "No two-device configuration can preserve strict writes after
  either device fails" is false given line 135 — a one-voter config has quorum 1 and survives losing
  the nonvoter. True only of *two voters*. Also "strict" is used once where "strong" is used nine
  times.
- **`recover-quorum` is one clause**, and one case has no path at all: line 181 makes recovery
  owner-only, so **an editor-only survivor set reads as permanently unrecoverable**. Also unstated:
  offline single-device operation (required, since by then nothing can connect), survivor
  re-admission, and how the successor epoch links to the immutable genesis record (168-170 defines no
  successor). Scenario 17 stops at "fail closed".
- **Discovery has no receiver-side replay rules.** `advertisement_nonce`/`expires_at` are declared
  with no nonce cache scope, bound, or TTL, no future horizon, no skew allowance, and no
  no-trusted-clock behavior despite link-local operation being supported. A naive unbounded nonce set
  is itself a memory-exhaustion target from one unauthenticated LAN host. And the omission list at
  207-208 reads as a completed privacy analysis while still broadcasting a plaintext `session_id`
  stable for the whole collaboration — a cross-network linkability beacon.
- **Identity-key lifecycle has no procedures:** whether revoked/superseded public keys are retained
  so past signatures stay verifiable (302-305 rests history verifiability on them), whether excluding
  private keys from backup is deliberate, the lost/reinstalled-device path, and daemon behavior when
  no credential store is available or unlocked (headless Linux, no D-Bus, locked keyring at boot).
- **Missing constants**, one consolidated pass: multicast group and port (absent entirely),
  clock-skew allowance (named at 445, valued nowhere, while the leader's clock is a trusted input to
  lease expiry), disconnect grace, invite TTL and outstanding-invite cap, nonce cache size,
  `idempotency_keys` retention, and every version floor — line 726 literally reads "system Git with
  minimum version" in a doc that forbids shipping placeholders (770-771).

## Corrections to my earlier report

Verification overturned several things I told you yesterday:

- **Extended CONNECT is fine.** I flagged Go's RFC 8441 support as the top external risk. I checked
  `x/net/http2` myself: the server advertises `SETTINGS_ENABLE_CONNECT_PROTOCOL` and accepts
  `:protocol` by default; the client sends it via `req.Header[":protocol"]` and waits for the peer's
  first SETTINGS frame. §5.1 line 271 and §8.1 stand. Two implementation notes worth a line in the
  doc: the setting must arrive in the peer's *first* SETTINGS frame, and `http2.Server`/`Transport`
  must be wired explicitly since `net/http`'s automatic path doesn't expose it.
- **The HTTP/2 throughput concern was rejected.** Its premise — bulk sync sharing a connection with
  control/SSE — is not what the doc says: line 539 opens a per-pair tunnel, 538 gives each pair a
  distinct connector, 252 treats control and sync tunnels separately. Line 890 already benchmarks
  tunneled Syncthing.
- **The quorum-loss "contradiction" was wrong.** Lines 550 and 941 are about *leader* loss, which
  the doc deliberately separates from quorum loss in adjacent failure rows (663 vs 665). Nothing is
  falsified, and the 30-minute coupling is stated in at least six places rather than hidden. The
  cold-reader verifier was right and I was wrong to carry the conflict forward. What survives is the
  narrow recovery gap above.
- **The leader-signature "two valid entries at one index" attack was refuted** by lines 88 and
  303-305. The finding survives on feasibility and chain-domain grounds instead.
- **Git divergence downgraded to minor:** content travels as working-tree bytes with per-path
  digests, so a receiver verifies and renders a diff without resolving `base_commit` as a git object.
  §8.3 should still state the consequence (receiver HEAD lags, `git status` shows synced content as
  local change).

## Judgement calls — your decision, not defects

- **Don't retro-fit RFC 2119 keywords document-wide.** Fixing line 8 (cite RFC 2119/8174, add
  `MUST NOT` which is used five times) is a one-line edit worth making. Adding ceremony to hundreds
  of bullets under headings already reading "Required controls:" would fight the document's greatest
  strength. Reject the broader version of this ask.
- **Property-based / formal testing is strengthening, not a gap.** §12 already gets much of that
  assurance via cross-replica digest equality, snapshot-plus-replay equivalence, real SQLite and real
  three-voter Raft, boundary fault injection, and continuous decode fuzzing. If you add only one
  thing, make it **seeded deterministic replay** — a nightly chaos failure recurring once in 200 runs
  is unactionable without it.
- **V1 scope cuts.** Defensible: drop `hlc` from the signed canonical event (line 344 already demotes
  it to display and 443 bars reducers from consulting clocks, so it buys nothing while carrying
  canonical-encoding and cross-platform signature-stability obligations); ship 1 and 3 voters with 5
  deferred. Not recommended: swapping the per-entry leader signature for only a periodic checkpoint
  changes the verification property rather than preserving it cheaply — a single exported event stops
  being independently verifiable. Either way §13 needs an explicit deferred-past-V1 list.
- **At-rest posture.** FDE can't be enforced but it *can* be detected and reported. Worth enumerating
  the cleartext copies CodeComm creates outside the workspace (bootstrap staging holding a full git
  bundle, conflict snapshots, the sidecar's prior-version store, `state.db`/WAL, `consensus/`) and
  adding an FDE check to `status`/`doctor`.

## What this document does unusually well

Accurate signal, not flattery — these are worth preserving through any rewrite:

- **The §2.4 invariant table** states negative safety properties each paired with a named enforcement
  mechanism ("No DB diffs on wire | Typed events/snapshots only; received SQL is inert data"). Most
  designs list positive aspirations. Stating what MUST NOT happen and where it's prevented is what
  makes §§5, 8, and 12 auditable.
- **The Syncthing containment design (533-544)** is careful engineering, not boilerplate: per-pair
  local connector, a tunnel that can only forward to the receiver's own session-bound loopback
  sidecar, "No caller chooses a destination", Syncthing's own TLS retained inside, and an explicit
  disable list. The "managed sidecar becomes an open proxy" threat was clearly reasoned about and
  closed.
- **The commit pipeline (352-369)** gets the details that usually go wrong: event, rejection,
  idempotency result, projection, and applied index in *one* SQLite transaction; invalid commands
  store the same structured rejection on every replica rather than diverging; index gaps stated
  explicitly; leader prevalidation explicitly declared non-authoritative; both signatures on
  long-lived identity keys rather than rotating transport keys so history stays verifiable.
- **The refusal to sync `.git/`, SQLite pages/WAL, or changesets (377-381)** comes with the actual
  reasoning — leaks unrelated and deleted data, bypasses domain authorization, couples peers to
  page/schema history — and is promoted to an ADR rather than left implicit.
- **§12** is stronger than most shipped systems: "Do not mock SQLite or Raft when testing their
  behavior", the harness as a V1 deliverable, faults injected at the Raft/SQLite boundaries,
  cross-replica digest equality after quiescence, immutable golden fixtures with historical migration
  replay, and leaking test artifacts as a release blocker.
- **Honesty about its own limits:** leases "cannot stop a same-user process from editing a path",
  "Signatures prove provenance, not content safety", "MCP cannot observe every native action",
  "CodeComm never claims arbitrary offline writes are mergeable". Risk 1 concedes provenance cannot
  replace sandboxing.
- **Density.** ~1000 lines carry a decided position on platforms, topology, consensus, transport,
  discovery, pairing, credential rotation, persistence, file sync, agent integration, testing, and
  delivery with almost no filler. That compression is a real asset — and also why the terminology
  collisions and example-only wire fields matter more here than they would in a verbose document.

## Shortest path to implementation-ready

Full 21-item ordered list in `final-review-raw.json`. The first six, in order:

1. §2.0 user model — one paragraph, named primary and excluded persona. Everything else depends on it.
2. Fix daemon/session cardinality in §3, reconciling 12/43 with 654-655 and 533.
3. §6.0 domain model — the single largest missing artifact; unblocks the kind registry, MCP schemas,
   TUI, and every fixture.
4. §5.4 event-kind registry plus a field table for the ten example-only wire fields.
5. §4.0 crypto primitives — canonical encoding, `device_id` derivation, chain input, domain labels.
6. Rewrite the §5.2 `consensus` block and §5.3 step 3 per must-fix 3, and validate against the real
   candidate Raft library in the phase-1 three-voter spike.
