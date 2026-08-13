# CodeComm V1 Design — Part 02: Architecture and Consensus

Part 2 of 14. Contents: §3 Architecture, §3.1 quorum recovery, §3.2 process cardinality, §3.3 multi-session isolation.
Section map, review status, and reading order: [README.md](README.md)

Authoritative revision 0.14; maintained only in this split set.

Normative terms follow RFC 2119/8174; declarative requirements and table rows headed "MUST" or
"Required" are equally normative.

---

## 3. Architecture

The mesh below is one session. Each member device runs one daemon for this workspace, and all
authorized pairs connect directly.

```text
         direct CodeComm mTLS mesh + replicated Raft control plane

  +----------------+     +----------------+     +----------------+
  | device A       |<--->| device B       |<--->| device C       |
  | daemon + DB    |<--->| daemon + DB    |<--->| daemon + DB    |
  | Raft voter     |     | Raft voter     |     | Raft voter     |
  | Git object svc |     | Git object svc |     | Git object svc |
  +-------+--------+     +-------+--------+     +-------+--------+
          |                      |                      |
      local IPC              local IPC              local IPC
       TUI/MCP                TUI/MCP                TUI/MCP
```

Within one device, the supervisor fans out to one daemon per joined workspace, isolated
per §3.3.

```text
  device A, one OS user
  +-------------------------------------------------+
  | codecomm-supervisor   (launchd/systemd/Task)    |
  |   daemon registry + on-demand start/stop        |
  +---------+---------------------------+-----------+
            |                           |
   codecommd(workspace A)      codecommd(workspace B)
    socket A, port A            socket B, port B
    Raft A, Git store           Raft B, Git store
    .codecomm/ in A             .codecomm/ in B
            |                           |
     TUI/CLI/MCP for A           TUI/CLI/MCP for B
```

| Component | Responsibility |
|---|---|
| `codecomm-supervisor` | One per device and OS user; the registered service. Owns the daemon registry, starts/stops session daemons, holds no session state |
| `codecommd` | One per (device, workspace). Local state, Raft, peer API, pairing, Git object/ref exchange, recovery |
| `codecomm` | TUI and scriptable CLI; talks only to a local daemon normally |
| MCP adapter | One local stdio process and unique agent session per client instance |
| Raft library | Election, replicated log, safe membership changes, snapshots |
| Git adapter | System Git plumbing, quarantined bundle import, CodeComm ref policy, worktree/draft/publication operations |

The session creator is only the bootstrap member; after admission, members learn the
committed roster and connect directly.

Raft orders only durable shared state: task/lease transitions, current-plan selection, shared
memory, membership/roles/voters/revocation, credential-key authorizations, and durable audit
events. Ephemeral presence, ordinary reads, Git artifacts, catch-up reads, and repository bytes do not
traverse the leader.

Application role (`owner`, `editor`) and consensus role (`voter`, `nonvoter`) are
separate. Voter count MUST be 1, 3, or 5 **at rest**; a reconfiguration may transit any
count up to the eight-device session cap while old voters are retained until the new target is
ready (voter-set transitions, below):

| Voters | Tolerates | Use |
|---|---|---|
| 1 | no voter loss; all strong state on one device | Development, or a session whose other devices are all nonvoters |
| 3 | one unavailable voter | Recommended default |
| 5 | two unavailable voters | Larger or less reliable sessions |

A joining device is admitted as a **nonvoter**. Promotion to voter is an explicit owner
action (`membership.voter_set_changed`, §5.4), never automatic. While fewer than three
voters are configured, every client MUST show a persistent degraded-tolerance indicator
naming what a single loss would cost. A one-voter session survives losing any nonvoter,
since quorum is 1. No two-**voter** configuration survives either voter failing (quorum
2), so a two-device session should be one voter plus one nonvoter.

"Up-to-date" is mode-specific. A current-generation live-configuration member is current when its
Raft FSM has applied through the committed index it reports. A settled application nonvoter is
current when its verified result head equals the greatest current-authority signed watermark it has
observed, with contiguous §5.3 attestations through that head; it has no synthetic Raft applied
index. Either mode also requires a current content credential and no integrity/version halt.
Eligibility names which mode/evidence was checked and becomes `unknown` when a higher reachable
authority watermark cannot be ruled out. A Git bootstrap source MUST additionally hold and verify
the canonical commit. Only an active authority member at the checkpoint cut may generate a logical
snapshot (§5.3). A normal unresolved merge conflict does not make a replica stale.

If quorum survives a permanent voter loss, it removes or replaces that voter without
re-pairing existing members. A minority MUST NOT self-promote. After a removal with no
replacement the session rests at the next lower legal count (5→3, 3→1), never even.

**Voter-set transitions.** The candidate library (§11) offers only **single-server**
configuration changes — `AddVoter`, `AddNonvoter`, `DemoteVoter`, `RemoveServer`, each
committing its own configuration entry — and provides no joint-consensus API and no way to
commit an application entry and a configuration change as one entry. V1 therefore MUST NOT
claim either. Instead, a voter change is a **committed intent plus a driven reconciliation**:

1. `membership.voter_set_changed` commits the **resulting voter set** — the full target
   membership, not a per-device delta. This is the authoritative record, and it is a single
   application event, so it is atomic in the only sense that matters to reducers: every replica
   moves from one legal target to the next at one index.

   The voter set is therefore its own **versioned entity**, not a field scattered across device
   rows: `voter_set` is a §6.2 table holding the current target and a `voter_set_version`, whose
   `entity_id` is the `session_id` (§4.2) and whose version is the CAS token. Making it an
   entity is what makes the CAS expressible at all — the §5.2 envelope carries exactly one
   `expected_entity_version`, so a set-valued transition needs a set-valued entity to name.
   `membership.device_revoked` always carries `expected_voter_set_version` alongside the envelope's
   device version; a mismatch on **either** token is a deterministic rejection. When the subject is a
   target voter, the event mutates both entities: its resulting target excludes the subject and the
   voter-set version increments. When the subject is not a target voter, the payload target MUST
   byte-equal the current target and the voter-set row/version do not change. Validation still needs
   the second token: without it, a revocation concurrent with `voter_set_changed` could accept a
   target computed from a set that no longer exists. Avoiding an identical-target version increment
   also avoids a needless credential-authority handoff.
   Reducers additionally require `voter_set[]` to be sorted, unique, 1/3/5 entries, and composed
   only of active admitted devices. A revocation target MUST exclude the subject and every
   already-revoked device.
2. Reconciliation starts only on the current leader over the consensus plane (§4.6). The
   leader first completes the library's barrier operation and waits until its local state machine
   has applied through that barrier; it then reads membership, target, and live configuration.
   A halted or no-longer-leader daemon issues no configuration call. This prevents a newly
   elected leader from reconciling toward a stale locally applied target.
3. The leader runs this state machine, one completed library future at a time:

   1. Add every target device absent from the live configuration as a **nonvoter**, in ascending
      `device_id` order. After `AddNonvoter` completes, force a fresh `consensus.checkpoint` and
      capture its event ID, committed log index, covered event/result chain heads, projection
      accumulator, digest version, and projection schema version (§5.2.1). Before promotion, prove that
      this staging replica applied
      that exact checkpoint. The proof MAY come from a maintained public leader-side
      replication-progress API. The required fallback is a consensus-plane-authenticated response
      emitted by the target's FSM only after the checkpoint event and its SQLite transaction apply;
      it echoes the captured tuple and the target's stored accumulator comparison for that checkpoint.
      The leader compares it byte-for-byte with its committed checkpoint; a generic `Barrier`,
      last-contact time, or self-reported numeric index alone is insufficient. The accumulator detects a
      deterministic-state mismatch; it is not a cryptographic proof of execution, so this mechanism
      relies on §2.4's crash-fault/non-Byzantine member assumption. Installing a snapshot and
      replaying its tail necessarily precede applying the checkpoint, so the proof covers both
      paths. If the candidate library cannot run the staging FSM or expose the checkpoint's
      committed index, phase 1 MUST replace it with a maintained library that can; promotion has no
      weaker fallback. An unavailable or lagging target remains a nonvoter and never enlarges quorum
      prematurely.
   2. Let `V` be live voters and `T` the latest applied target. Promote every caught-up member of
      `T \ V`, in ascending `device_id` order, **before removing any old voter**. Retaining the old
      set is intentional: content-credential and checkpoint authority remains the last activated
      voter set until the replacement is proven, so alternating promotion/removal could strand that
      authority below a majority midway through a disjoint replacement. The transient union is
      bounded by the eight-device session cap; every newly promoted server has already passed step
      3.1, so growing quorum does not count an unavailable target prematurely.
   3. Once `T ⊆ V`, if the authority has not already activated this target version, force a fresh
      checkpoint and collect a signed activation proof from **every**
      member of `T`. Each proof binds the session, target and current authority versions, exact
      sorted `T`, live configuration index, and checkpoint tuple under
      `codecomm/v1/voter-activation-proof`, and is emitted only after that device has applied the
      checkpoint and locally observes itself as a voter. One active member of the current
      credential authority then signs the complete proof set under
      `codecomm/v1/voter-authority-handoff`. The leader commits
      `membership.voter_set_activated`; its reducer validates the current target, prior-authority
      signer, every target proof, and both version compare-and-sets, then atomically replaces the
      `credential_authority` row (§§4.6, 6.1). A crash or target change invalidates the proofs and
      restarts this step. This post-promotion handoff is the trust bridge by which an offline replica
      verifies that a new batch/checkpoint signer descends from its previously trusted authority
      (§5.3).
   4. Remove only a voter outside `T` for which the post-removal configuration has a quorum of
      currently reachable, active voters. Prefer revoked voters, then unreachable extras, then
      ascending `device_id`; this removes a lost voter before a reachable helper in a 3→1
      transition. Never remove the current leader. If it is outside `T`, first transfer leadership
      with the library's targeted transfer API to the lowest-`device_id` **eligible** target voter;
      the new leader resumes from step 2. This deterministic choice needs no per-follower
      `matchIndex`.

      A target voter is **eligible** if it proved the staging checkpoint of step 3.1, or if it was
      already a voter in the live configuration when reconciliation began. The second case is
      required for termination: proofs are generated only for devices staged by `AddNonvoter`, so
      an existing voter that is also in `T` has none, and without this clause a transition whose
      leader is outside `T` and whose sole target was never staged would have no legal move — the
      leader may not remove itself and could not transfer. An existing voter's participation in
      the live configuration's commit quorum is already evidence of currency, so the leader
      requires only that its last-contact is current and that a fresh barrier completes; if that
      barrier does not complete, the transition stalls per the rule below rather than transferring
      to an unverified voter.
   5. Remove obsolete staging nonvoters after all target voters are promoted. Stable state is
      exactly `T` as voters, `T` as the activated credential authority, and no staging server.

   Every call carries the freshly observed configuration index as `prevIndex`. After its future
   resolves, the daemon re-runs the barrier, re-reads target and configuration, and recomputes from
   step 1; a changed target, failed compare, crash, or leadership loss therefore leaves no cursor to
   repair. The only durable inputs are the committed target and library configuration.

   **Reconciliation requires content-plane and object availability.** Configuration changes move
   both consensus quorum and the devices expected to retain canonical objects. Before each library
   call, the leader therefore rechecks that every voter counted toward the post-change quorum has a
   current content credential (§4.6), and that a majority of the target `T` has signed canonical-
   coverage receipts for the exact current `(voter_set_version, canonical_ref_version,
   commit_oid)` (§8.1). It MUST NOT remove an old voter until that coverage exists. A concurrent
   canonical advance invalidates the check and requires fresh receipts before the next call.

   The leader re-stages and retries rather than weakening either gate. Credential authorization
   continues to use the **previously activated authority**, not an unproven target, until step 3
   commits; therefore an unavailable target cannot make the credentials needed to repair that
   transition impossible to renew. Coverage is re-derived from signed receipts and immutable
   objects. An unavailable target or missing canonical object leaves reconciliation visibly stalled
   and preserves both the old live configuration and old credential authority.

The consequence to state plainly: between intent commit and reconciliation completion the committed
application target, activated credential authority, and live Raft configuration may all differ.
`voter_reconcile_deadline` is an alert threshold, not a protocol time bound: an unavailable target,
failed handoff or leadership transfer, or loss of a post-change quorum can leave the cluster
reconciling indefinitely. It keeps the target, never rolls back or guesses a different set, retries
after topology or leadership changes, and requires §3.1 recovery if the live configuration
permanently loses quorum. §5.5's frozen-reducer rule is unaffected because reducers read only the
committed target and authority rows.

**Revocation demotes, and does not depend on winning a race.** If the subject is a target voter,
`membership.device_revoked` atomically commits a legal target excluding it; if it is already a
nonvoter, the target and its version remain unchanged. Either way, a revoked device is absent from
every later target. Because the live Raft configuration may lag, the design MUST NOT rest any
security property on the revoked device having left it. Every peer instead refuses the device on
**applied application membership** at *connection admission* on both planes (§4.6), a local check
needing no reconciliation. A refused connection never reaches vote exchange, so vote granting has no
separate membership rule and per §4.6 must not gain one. If revoking a voter would leave an even or
illegal count, the resulting target settles at the next lower legal count and never at two voters.

The sole member of a one-device voter target cannot be revoked in one step: applying revocation
would make the only process able to reconcile refuse its own consensus connection. The reducer
therefore rejects `membership.device_revoked` while the subject is the sole current target voter.
More generally, revocation is rejected if the active members left in the current
`credential_authority` would no longer form its majority; the owner must first activate a replacement
target. This prevents a sequence of individually valid revocations from removing the clock witnesses
needed to renew content credentials while reconciliation is still in flight.
An owner first targets and fully reconciles a trusted replacement, then revokes the old device. If
the sole voter is already compromised or lost, §3.1 recovery is the only safe path; the design does
not pretend an atomic availability-preserving revocation exists in that topology.

### 3.1 Recovery from permanent quorum loss

Recovery is offline and single-device: the tool acquires the workspace lock, stops the old daemon,
opens no listener, and communicates with no peer. Other survivors may still be physically reachable;
they do not participate and later use readmission pairing. The recovering identity MUST be an `active` member in the
verified predecessor projection and match the locally available installation key. An active `owner`
authorizes with that identity; an active `editor` requires the **recovery key** — a keypair whose
public half genesis binds and whose private half is exported once at `host`. The key cannot select an
arbitrary successor: revoked, `requires_readmission`, absent, and never-admitted identities remain
ineligible even with it. Its issuance requires confirmation of off-device storage and states both
this power and its separate owner-restoration power (§4.3). If no eligible active identity survives,
or every eligible owner identity and the recovery key are lost, the session is unrecoverable.

`codecomm cluster recover-quorum` then:

1. Fully recomputes both chains, the projection accumulator, deterministic outcomes, and full
   projection-state digest from genesis (§§5.2.1, 5.6), and verifies every authority handoff plus the
   latest checkpoint at its cut. A Raft survivor additionally proves its
   `last_raft_applied_log_index` against matching stable-store/snapshot state. A settled nonvoter
   instead proves contiguous authority-signed batch/checkpoint attestations from genesis or a trusted
   checkpoint through its result head; it cannot claim Raft provenance. A pre-checkpoint session is
   recoverable only with complete Raft evidence or signed batch coverage from genesis. Recovery
   refuses a broken chain, missing attestation range, unverified authority transition, or replay
   disagreement, and carries forward every verified result/idempotency row.

   **Durability limit, stated plainly.** The recovering device is a survivor of a lost
   majority, so it may be behind entries the old majority committed and acknowledged. Those
   entries are unrecoverable from this device, and recovery therefore **does not** preserve
   the "No acknowledged event loss" invariant (§2.5) — it is the one operation exempt from
   it, which is why it demands explicit operator authorization. Recovery reports its
   nullable `last_raft_applied_log_index`, `result_index`/hash, `chain_index`/hash, accumulator, and
   evidence mode/coverage so the operator can compare every survivor. Choose the greatest verified
   `result_index` that also holds the selected canonical commit; a Raft index is supporting evidence,
   never the primary rank, because settled nonvoters legitimately lack one. Never rank by
   `chain_index` alone because rejected commands advance only the result chain.
   Conflicting order or a same-position hash mismatch requires `state scrub` and blocks recovery. A missing
   canonical object stops recovery and names its staging-receipt holders; if no copy survives,
   selecting the latest locally complete ancestor requires a second explicit repository-data-loss
   confirmation and is recorded in the successor genesis.
2. Requires the recovering active identity's signature in every case and a distinct recovery-
   authorization signature: the same identity signs under the recovery domain when it is an
   `owner`; the predecessor recovery key signs when it is an `editor`.
3. Presents the members not being carried forward and requires explicit confirmation.
4. Generates a fresh recovery key, requires the same off-device-storage confirmation as `host`, and
   writes the dual-signed **successor genesis record**. It binds the same `workspace_id`, a new
   `session_id`, incremented
   `recovery_generation`, prior-genesis digest, new recovery public key, selected canonical
   commit/object format, predecessor event/result/accumulator heads, and the post-transform
   projection-state digest. The predecessor recovery key remains only as historical verification
   material and grants no authority in the successor.

   Let `successor_body` be that complete closed record with both
   `recovering_identity_signature` and `quorum_recovery_signature` absent. The recovering active
   identity always signs those exact JCS bytes under `codecomm/v1/genesis`, proving possession of the
   predecessor-enrolled installation key. A second signature over the same bytes under
   `codecomm/v1/quorum-recovery` supplies recovery authority: the same identity signs when its
   predecessor role is `owner`; the predecessor recovery key signs when it is `editor`. Both
   signatures, signer kinds, canonical selection, and any repository-data-loss confirmation are in
   the final record. No signature transfers to another candidate, key, commit, predecessor head, or
   successor generation.

   The complete record uses these exact store-checked commitment fields:
   `predecessor_genesis_digest`, `predecessor_chain_index`, `predecessor_chain_hash`,
   `predecessor_result_index`, `predecessor_result_hash`,
   `predecessor_projection_accumulator`, `post_transform_state_digest`, `digest_version`, and
   `projection_schema_version`. Digests/hashes are unpadded base64url 32-byte values; both
   authorization signatures are unpadded base64url 64-byte values. Recovery verifies both
   signatures and all genesis semantics before storage; the boundary transaction independently
   rejects any disagreement between these signed fields and the predecessor heads, installed
   projections, or active digest versions.
5. Applies one fixed recovery transform before accepting new events:
   - preserve accepted events/results, immutable plans/memory/control-file proposals, tasks,
     conflicts, enrolled public keys, and publication history; select the confirmed canonical commit;
     convert every `proposed`/`approved` publication to `withdrawn` with
     `terminal_source = recovery` and fixed recovery reason because its author binding and receipts
     cannot authorize successor work;
   - recompute every applied publication's `canonical_lineage_member` against the selected
     canonical first-parent ancestry. A repository-data-loss rollback marks excluded historical
     applies false so they cease to pin objects unless an unresolved conflict still references them;
   - retain prior credential authorizations only as historical rows under the old `session_id`;
     the successor has no authorization until epoch 1 is committed;
   - mark every non-recovering previously active device `requires_readmission`, leave revoked devices
     revoked, and make the recovering device the sole active `owner`;
   - create successor `voter_set` and `credential_authority` rows at version 1 for that device, with
     `activation_source = genesis`; remap copied current-plan/policy rows to the new `session_id`;
   - reset `audit_counters` to successor epoch 0/count 0 and drop every predecessor `origin_scopes`
     row;
   - end every nonterminal old agent session and release its claims/leases with `recovery`; retire
     every old draft stream without advertising it in the successor, while keeping currently retained
     immutable snapshots under local historical retention refs; and
   - clear resume capabilities, invites, endpoint hints, replication cursors/acks, outbox entries,
     agent-launch registrations, local request/challenge/counter rows, lease timers,
     transfer/quarantine state, and pre-proposal staging pins not required by a preserved
     publication, canonical ref, conflict, or retained draft. Verified predecessor replication
     attestations remain historical recovery evidence.

   Every carried mutable projection row becomes the successor baseline with `entity_version = 1`;
   this reset is safe because CAS identity is scoped by the new `session_id`, and no old request,
   capability, or cursor survives. Immutable rows retain their IDs. Local control-file decisions and
   workspace bytes remain local and are neither authority nor part of the transform. The canonical
   field/value ordering and reset rules are fixture-frozen; the successor genesis binds their full
   projection-state digest before visibility.

The successor event/result chains and projection accumulator continue rather than restart:
`chain_seed(successor)` and `result_seed(successor)` commit to both predecessor heads and the
successor genesis (§5.2.1), while both dense indices keep increasing. The successor genesis itself
is retained in `genesis_records` and projects one recovery audit row; it is a signed chain boundary,
not a synthetic domain event.

Survivors rejoin through §4.5's explicit **readmission** pairing, including the authentication-string
comparison and conditional same-key admission of their retained `requires_readmission` row. Prior
enrolment alone confers no successor authorization; prior keys remain for historical verification.
A minority that merely *believes* the majority
is gone MUST NOT run this; recovery requires the deliberate operator action above. A
recovered session that later meets a surviving member of the old lineage detects the
mismatched `recovery_generation` and refuses to interoperate.

Nothing technically prevents two partitions that each hold an owner device or the recovery key
from both running recovery, and they would produce the **same** `recovery_generation`, so a
generation comparison alone would not catch it. The successor genesis therefore binds the
predecessor's final verified event **and result** heads, the recovering `device_id`, the new
`session_id`, and the new recovery public key. Peers compare the complete signed successor-genesis
digest; any mismatch for one workspace/generation is a refusal to interoperate. Sibling successors
are therefore mutually incompatible and visibly so, naming both recovering devices, rather than
silently merging divergent histories.

### 3.2 Process and session cardinality

One device runs one supervisor per OS user and **one `codecommd` per joined workspace**. A device
MAY participate in several active sessions concurrently; each gets its own daemon process, Raft
node, HTTPS port, Git repository binding, and `.codecomm/` directory. A workspace has exactly one
active session generation, while §3.1 recovery may give the same `workspace_id` a lineage of
successive `session_id`s. "Session daemon" and "workspace daemon" both mean the daemon for that
workspace's active generation.

Two OS users on one physical machine each get an independent supervisor, registry, state root,
credential-store identity, `device_id`, and session cap. A session admits each installation
separately. CodeComm never copies a private identity key across OS-account boundaries or requires a
system service merely to make a physical machine look like one principal (§2.1, §4.2).

The supervisor is the only component registered with `launchd`, `systemd --user`, or Task
Scheduler (§9); it is installed once per user and does not depend on any workspace
existing. It maintains a durable registry of joined workspaces in the platform-standard
per-user state location, never inside a workspace. Each entry records `workspace_id`,
`session_id`, one canonical primary anchor root and repository identity, and last-known socket path
and HTTPS port, plus the live PID
while its daemon runs. Entries outlive their daemon so a session can be listed and
restarted while stopped; an entry whose PID is dead is marked stopped at supervisor start
or on the next failed client connection, and its socket path and port are never reused
without revalidation. Registry files are owner-only.

At host/join/adopt, the supervisor resolves symlinks/junctions, records the native filesystem object
identity of the anchor and Git common directory (Unix device/inode; Windows volume/file ID), and
compares paths using native canonical case rules. One `workspace_id` has one anchor, and one
repository identity cannot back two registry entries. Aliases, symlinks, junctions, case variants,
or copied markers therefore cannot start a second daemon. CodeComm-created managed worktrees are
registered beneath that same entry and may select the daemon, but are never independent anchors.
Moving an anchor is an explicit stopped-daemon operation that revalidates repository identity and
updates the registry atomically.

Clients select a daemon in this order: an explicit `--session` or `--workspace` flag; the
nearest ancestor directory of the working directory containing `.codecomm/`; a sole
registry entry; otherwise fail listing every registered candidate. Once a workspace is
selected, a stopped daemon is started on demand through the supervisor. The MCP adapter
uses its launch registration's already selected daemon and binds for its lifetime, so an agent's actor identity
cannot migrate between sessions.

The per-workspace OS lock (§9) and registry identity checks jointly prevent two daemons owning one
workspace or repository through path aliases. Long-lived
device identity is **per installation and shared across its sessions** (§4.2); credential
epochs, roles, and voter status are per session, and the §4.6 epoch binding includes
`session_id`, so one identity key backs several independent epoch streams. Losing one
daemon does not affect another; the supervisor restarts it with capped backoff and
surfaces repeated failure as a blocker rather than looping.

The 2-8 device and 32-agent limits of §2.2, and the 100k-file and 2 GiB workspace targets,
are all **per session**. V1 caps concurrent sessions per device at four; each adds a daemon, a
listening port, and one multicast
advertiser per selected interface. §14 states resource budgets per daemon and for the
per-device aggregate at that cap.

### 3.3 Multi-session isolation on one device

Sessions on one device share only the device identity key and the supervisor.
They MUST NOT share a socket, port, Git ref namespace, artifact quarantine, database, Raft store, or
`.codecomm/` directory, and no daemon opens another session's state. A client or agent bound to
one session cannot observe, address, or mutate another.

One device may advertise several sessions from one source address on one interface. A
receiver MUST match the `session_id` of an inbound discovery datagram (§4.4) against its
own session and silently ignore any mismatch. Such a datagram is not an error, is not
rate-limit-accounted against the sender, and MUST NOT be treated as a credential
violation.
