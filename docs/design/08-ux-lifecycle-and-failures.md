# CodeComm V1 Design — Part 09: UX, Lifecycle, and Failure Behavior

Part 9 of 14. Contents: §9 TUI/CLI surface, supervisor lifecycle, and the required-behavior failure table.
Section map, review status, and reading order: [README.md](README.md)

Authoritative revision 0.14; maintained only in this split set.

Normative terms follow RFC 2119/8174; declarative requirements and table rows headed "MUST" or
"Required" are equally normative.

---

## 9. UX, Lifecycle, and Failures

TUI views: session/leader/quorum, peers/roles/direct links, agents by device, tasks, plan
history, activity/provenance, repository/drafts/conflicts, and security reviews. Preparing, pending,
committed, applied, stale, merge-conflicted, object-lagging, local-only, offline, expiring,
expired, halted, reconciling, readmission-required, and ref-tampered states
MUST be visually distinct and distinguishable without color (§16). `expiring` carries a countdown
to credential expiry, `halted` names the version required to resume (§5.5), and `reconciling`
names a voter-set transit whose live Raft configuration has not yet reached the committed target
past `voter_reconcile_deadline` (§3). `halted` and a peer's `object-lagging`/`local-only` are
**self-reported**, exactly like `reconciling`: halt is a per-replica apply-time condition that is
never committed, so from another device a halted peer is indistinguishable from slow or offline, and
only the halted device can name the version it requires. Every peer-derived state is therefore
labelled "as of last contact", and a peer with no current contact shows `unknown` rather than
`healthy`. `reconciling` is derivable only by a member of the live Raft
configuration; a settled application nonvoter receives no configuration entries (§5.3), so its
client shows the committed target and labels reconciliation status as voter-reported rather than
implying local observation. Same-labeled
agents remain separate by shortened session ID. Repository status also names
`git-storage-over-quota`, incomplete draft history, `ref-tampered`, and an unsafe managed root; none
is collapsed into generic offline or conflict state.

Representative CLI:

```text
codecomm host|join|tui|status
codecomm agent list|launch|stop
codecomm task add|list|show|update|ready|withdraw
codecomm task force-release|reassign|cancel
codecomm lease list|force-release
codecomm plan show|propose|select
codecomm memory add
codecomm activity add
codecomm conflicts list|show|resolve|force-resolve
codecomm draft list|inspect|pin|unpin|restore|materialize|prune
codecomm control-files review|propose
codecomm peer invite create|list|revoke
codecomm peer role|owner-recover|revoke|endpoint add|list|remove
codecomm cluster status|set-voters|transfer-leadership|recover-quorum
codecomm policy show|set
codecomm publication list|show|review|apply|reject|withdraw
codecomm state scrub|recover
codecomm export events|audit
codecomm backup create|verify
codecomm repo status|doctor|integrate|worktree|include|exclude
codecomm mcp serve
codecomm shell
codecomm daemon start|stop|status
codecomm sessions list|leave
codecomm supervisor install|uninstall|start|stop|status
codecomm audit list|export
codecomm support-bundle
codecomm config show|validate
```

`membership.device_admitted` has no verb of its own: an owner commits it implicitly by completing
`peer invite create` and the §4.5 pairing exchange. Every other §5.4 kind whose `Actor` is `human`
has an explicit verb above, which is required because `human`-only means unreachable over MCP.

Every command except `sessions list`, `supervisor *`, `config *`, and `host`/`join` operates on one
selected session, resolved by `--session`/`--workspace`, then working-directory ancestry,
then a sole registry entry (§3.2). `sessions list` prints each registry entry — workspace
root, `session_id`, daemon state, and port — and queries each running daemon for quorum
health, blank for stopped sessions.

`sessions leave` **MUST refuse** when the local `device_id` is in the committed `voter_set`,
naming the owner action required first (`cluster set-voters` to demote it), and offering `--force`
only after calculating the actual post-loss condition. If the remaining live voters retain quorum,
the warning says the session continues degraded but membership/configuration do not change
automatically; an owner must explicitly replace or remove this voter. If the deletion loses quorum,
the warning says strong state and renewal stop and names §3.1 recovery. The command MUST separately
confirm before deleting session state, naming the Raft log and database, loss of this §3.1 recovery
candidate, and any sole canonical-object copy (§8.1); it erases the retained epoch key (§4.4). A
still-active member that retained its installation identity but deleted session state rejoins under
its existing `device_id` only through §4.5's owner-issued, SAS-confirmed rebootstrap mode; it is not
re-admitted and workspace markers never restore trust.

Otherwise `sessions leave` is a local operation: it stops the session daemon, removes the registry
entry, and optionally deletes `.codecomm/`, leaving the workspace files in place. It does
**not** alter committed membership — that device remains indistinguishable from an offline member
until an owner revokes it (§4.3).

Install the **supervisor** visibly and reversibly as a per-user `launchd`, `systemd --user`,
or Windows scheduled-task/user-service integration; it is the only registered service, and
supervisor-started session daemons are **detached into their own process scope**, not left as
supervisor children: under `systemd --user` the default `KillMode` tears down a unit's whole cgroup
and a launchd job's children live in its job scope, so without detachment — a transient scope or a
per-daemon job — the "running daemons continue" and "restart reconciles the registry against live
PIDs" rows below would be false on two of three platforms.

Both process kinds retain a foreground mode for development. A foreground `codecommd` takes
the same per-workspace OS lock and writes the same registry entry as a supervised one,
marking it foreground and externally managed, so clients resolve to it normally and the
supervisor will neither adopt nor restart it. This is what the §9 rule against starting a
daemon "behind the supervisor's back" means: a client MUST NOT spawn a daemon itself, while
an operator explicitly running one in the foreground is expected and visible. If no
supervisor is installed, foreground daemons still work and `sessions list` reads the
registry directly. The per-workspace OS lock prevents two daemons owning the same
session state directory, Git quarantine, or ref namespace; the lock, not the registry, is the
authority. Four rules make that precise: a starting daemon MUST acquire the lock **before** writing
its registry entry and MUST exit reporting the holder's PID on failure; a lock whose owning process
is gone is reclaimed only after an explicit liveness check, since `flock` releases on death but
Windows needs a stated staleness rule; a crashed foreground daemon's entry is marked stopped and MAY
then be started supervised, since the foreground marking describes the previous run rather than a
permanent claim; and `codecomm daemon start` is defined as a *request to the supervisor*, with
foreground operation reachable only by running `codecommd --foreground` directly — which is what
keeps it distinct from the prohibited client-spawns-daemon path.

| Failure | Required behavior |
|---|---|
| Exact duplicate request | Verify and return the chained committed result without re-evaluation |
| Same `event_id`, different proposal | Return `idempotency_conflict`; preserve the original result and both chain heads |
| Same local `(client_instance_id, request_id)`, different command | Return `local_idempotency_conflict`; preserve the original request digest, event ID, publication preparation or signed proposal, and result |
| Publication preparation interrupted | Resume the same durable request, proposal event ID, immutable metadata, artifact, and collected receipts; never rebuild it from a changed working root. A committed failed attempt requires a new request and cannot lend receipts to it (§§5.1, 7.2) |
| Unsigned publication preparation abandoned or author session ends | Tombstone its local request/event/publication IDs, release local queue/artifact capacity, and return `publication_preparation_abandoned` on retry. Send no early-release message; remote pins age out by the committed result window (§§5.1, 7.2) |
| Owner-recovery challenge expires | Terminally tombstone that request and return `challenge_expired`; never extend or finalize it. A new request ID starts a new five-minute challenge |
| Duplicate agent ID | Reject and audit |
| Agent launch interrupted, replayed, or consumed concurrently | Resume only the exact pending start after daemon/vendor crash. Exactly one consumer reserves the one-use selector; rejection consumes it and burns the agent ID, while replay after acceptance cannot create another session (§§5.1, 7.2) |
| Direct vendor launch or pre-existing root selected | Refuse the bind and name `codecomm agent launch`; model/vendor input cannot choose session metadata or a host path (§7.2) |
| Agent disconnect | Owning daemon commits `disconnected` with stored `resume_state`; valid local resume and grace reaping race on one session CAS, so resume restores exactly that state or end releases claims/leases (§§6.1, 6.4) |
| Task owned by an ended agent session | Reducer returns it to `ready` with `last_release_reason = session_ended` on the committed session-end event |
| Runaway agent still heartbeating | Operator `agent stop` is local; its eventual session-end event and any separate force-release events project directly to audit when accepted (§§5.4, 6.4) |
| Abandoned worktree | Surfaced as a blocker with its owning session and base commit; publication refused until an operator releases or reassigns |
| Concurrent claim | Consensus commits one winner |
| Leader loss | Elect; direct reads/Git transfers continue |
| Election | Queue strong proposals; expose transient state |
| Quorum loss | Queue strong work; content links continue only to credential expiry; the consensus plane stays reachable but cannot authorize a renewal without a voter majority (§4.6) |
| Voter restart | Replay Raft, idempotently apply SQLite, rejoin follower |
| Expired content credential | Close content connections; obtain a quorum-authorized replacement on consensus, then reopen with it. Make-before-break applies only to on-time overlap before expiry (§4.6) |
| All content credentials expired after sleep | Ordinary election on the identity-authenticated consensus plane; the majority authorizes fresh epochs and content links reopen with no operator action and no distinct cold-start mode (§4.6) |
| Every content credential expired and a voter majority version-halted, but one reachable voter can apply the log | That voter leads on the non-expiring consensus plane with halted voters' votes counting toward quorum (§4.6); fresh content credentials commit; halted voters resume automatically on upgrade |
| No reachable voter able to apply the log far enough to lead | Surface the §5.5 version blocker naming the release required. Upgrading a voter resolves it; §3.1 recovery MUST NOT be offered, since state is intact and merely unapplied. This — not a halted majority as such — is the unrecoverable case |
| Voter reconciliation stalls | Preserve the committed target, prior activated credential authority, and current live configuration; never roll back, skip catch-up, or choose another voter set. Existing credentials keep renewing through the prior authority. Surface the blocking device/step after `voter_reconcile_deadline`, retry on topology or leadership change, and require §3.1 recovery only if the live configuration permanently loses quorum |
| Revoked device attempts to reconnect | A peer that applied revocation refuses every ALPN; quorum remains configuration-derived. A stale peer may exchange votes, but a nonleader sends no state and an elected leader applies membership before replicating to any voter or staging nonvoter (§4.6) |
| Revocation | All informed peers close consensus, content, and Git access and stop serving the device; the revoked device erases its retained epoch key and stops advertising (§4.4) |
| Git interruption/digest/object/manifest failure | Resume by artifact digest/offset or discard quarantine and audit; never update a ref from partial/unverified data, a malformed sparse container, or a manifest/tree mismatch |
| Git child hang/crash | Kill on deadline, retain verified objects, clean quarantine, and retry with capped backoff |
| Reserved CodeComm ref is missing, unexpected, or externally changed | Enter `ref-tampered`, preserve the external value, and block materialization/publication until explicit repair; never overwrite after an expected-old-OID CAS failure (§8.1) |
| Managed-root mutation requested with a pending/live/resumable agent | Refuse with the registration/agent IDs; never invalidate an agent's filesystem view. After all bindings end, verify the guard and perform the operation while the root is unavailable (§§7.2, 8.2) |
| Pending-command or Git-transfer queue full | Return structured retryable backpressure before minting an event/sequence or starting a child; reads and accepted work continue, and admission resumes as the queue drains (§11.2) |
| Peer handler/stream/connection ceiling reached | Refuse or reset only the excess request with a retryable limit code; preserve control capacity separately from bulk transfer and allocate no unbounded wait queue (§§5.1, 11.2) |
| Disk full/permission loss | Stop affected acknowledgements/writes, retain files, expose the exact Raft/SQLite/Git/control-store blocker |
| Stale publication/merge conflict | Preserve immutable commits/drafts; require explicit rebase or reviewed merge publication |
| Control-file change | Hold local proposal for approval; validate explicit upsert/delete semantics, reject an oversized upsert before fetch, and discard exact-size/digest mismatches. CodeComm-invoked operations in a healthy managed root keep control paths excluded and restore only local approvals; arbitrary same-account Git is a visible bypass (§8.4) |
| Control manifest version or digest changes during peer pagination | Return `stale_control_manifest`; discard that comparison and restart from the new presence summary. Every request/cursor binds both values, so restoring an older local version with different approved rows cannot combine two states (§5.1) |
| DB corruption | Preserve evidence and immediately stop campaigning, acknowledgements, and writes; the corrupt node never edits membership itself. Healthy owners remove/replace a voter through normal CAS. `state recover` builds a fresh DB from a verified Raft/result-stream export or backup; it may extract old events/results only read-only after SQLite integrity, signatures, full verification of both chains, and deterministic replay, never trusting them blindly. Otherwise re-bootstrap as a fresh replica |
| Unappliable committed entry | Halt before that entry without advancing `last_raft_applied_log_index`; serve prior reads; expose required version; resume after upgrade (§5.5) |
| Projection-accumulator or same-position chain-head mismatch within one recovery generation at a checkpoint | Integrity-halt before recording a rejection or advancing apply; preserve evidence and alarm. `state recover` creates a fresh DB from verified result history or an authority-signed checkpoint snapshot plus contiguous tail, recomputes every outcome/row/digest, and atomically swaps only after verification. It never copies raw SQLite state. §3.1 is not offered (§§5.2.1, 5.6) |
| Full projection-state mismatch during snapshot, export, recovery, or scrub | Integrity-halt and rebuild as above; an untouched corrupt row need not change the incremental checkpoint accumulator, so a full-state boundary never trusts the accumulator alone (§5.6) |
| Version too old to join | Refuse to join rather than joining and halting |
| Host suspend and resume | On wake, re-resolve interfaces, re-advertise at once, re-dial peers with capped backoff; renew credentials immediately if expired (§2.3) |
| Local address change or interface loss | Drop connections bound to the vanished address, re-advertise, re-dial; membership unchanged |
| Wake with expired epoch and no quorum | Distinct visible state: local reads and work continue, the consensus plane keeps retrying, content and Git traffic remain closed, strong proposals queue, and renewal succeeds automatically once a majority returns (§4.6) |
| Stale endpoint hint | Treat it as a local guess only through `endpoint_guess_ttl_seconds`, dial only over a selected-interface route, fail fast, then fall back to multicast or a manual endpoint |
| Endpoint set sequence regresses after local-state restore | Reject it while the prior set is valid; discovery/manual routing remains available, and expiry clears the ephemeral high-water mark so a fresh signed set recovers without membership change (§4.4) |
| Endpoint retention cap reached | Replace the member's prior signed set atomically, then expire/evict oldest stale guesses; refuse a manual addition at its separate per-member/session cap and preserve configured endpoints (§§2.3, 4.4, 11.2) |
| Permanent voter loss with quorum | Safe remove/replace |
| Permanent quorum loss | Select the greatest verified `result_index` with complete canonical data using Raft evidence or contiguous signed nonvoter attestations. An eligible owner identity, or editor identity plus recovery key, creates the successor; nonterminal publications withdraw, rolled-back applies release lineage pins, draft streams retire, and survivors return only through explicit readmission (§3.1) |
| Permanent quorum loss with no eligible active predecessor identity | Recovery is unavailable: the key cannot promote a revoked, readmission-required, absent, or never-admitted identity. With an active editor but no recovery key, the session is likewise unrecoverable |
| Recovered session meets an old-lineage or sibling successor | Old generations mismatch directly; same-generation siblings differ in their complete signed successor-genesis digest. Refuse to interoperate and name both recovering devices rather than merge histories (§3.1) |
| Session daemon crash | Supervisor restarts with capped backoff; other sessions unaffected; repeated failure surfaces a blocker instead of looping |
| Supervisor crash | Running daemons continue; clients keep using registry entries; restart reconciles the registry against live PIDs |
| Stale registry entry | Entry whose PID is dead is marked stopped at supervisor start or on failed client connection; socket path and port are revalidated before reuse |
| Supervisor absent when a client resolves a session | Client reports that the supervisor is not installed or running, with the command to start it; it MUST NOT start a session daemon behind the supervisor's back |
| Workspace directory moved or deleted | Daemon stops and the entry is marked unreachable, a state distinct from stopped: the workspace root no longer exists, so the session requires explicit re-selection or rejoin rather than restart |
| Concurrent-session cap reached | Refuse the new session with the current list; never evict a running one |
| Session would rest at one voter | `host`/`join` prompt for voter placement, recommending the machine likelier to stay reachable and naming what the other loses while it sleeps; an operator MAY decline (§1, OQ3) |
| `repo include` pattern is blanket, spans directory levels, or names a control file | Refuse, naming the offending pattern; control files are never includable because that would route around §8.4 per-device approval |
| `repo include` matches a secret-shaped path | Preview lists it, a second differently-worded confirmation is required, and the prompt states that every member device will read it and that inclusion cannot be undone for replicated data (§8.1) |
| Revocation proposed concurrently with a voter-set change | Rejected on a stale `expected_voter_set_version` rather than committing a target computed from a superseded set; the owner re-proposes against the current version (§3) |
| Active nonvoter revoked | Validate the current voter-set CAS and exact unchanged target, revoke access, and leave `voter_set_version`, credential authority, and reconciliation state unchanged (§3) |
| Revocation targets the sole current voter | Deterministically reject; fully reconcile a replacement first, or use explicit §3.1 recovery if the sole voter is lost/compromised |
| Role change or revocation would remove the last active owner | Deterministically reject. Promote another owner first; if the sole owner identity is lost while quorum survives, an active editor uses `peer owner-recover` with the offline recovery key (§4.3) |
| Sole owner identity and recovery key both lost | Existing coordination may continue, but governance cannot be restored; surface an unrecoverable blocker rather than offering self-grant or quorum recovery without authorization |
| Revocation would leave fewer than a majority of the activated credential authority active | Deterministically reject; activate the replacement voter target first, then revoke (§3) |
| Refusing a revoked live-config voter costs quorum | Security wins over availability: the peer stays refused and the session follows the stalled-reconciliation path, surfacing the blocker; §3.1 only if the live configuration permanently loses quorum (§4.6) |
| Task claimed on a device that never returns | Owner `task force-release` returns it to unassigned `ready`, or `task reassign` re-targets it; both audited. Session-end release does not cover this, since no session-end event will ever be proposed (§6.4) |
| Reassignment intent naming a since-revoked device | The task stays `ready` and visibly blocked, never silently delegated; an owner clears or re-targets the intent via the `ready → ready` override edge (§6.3) |
| Credential store locked, unavailable, or unreadable by this OS user | Daemon refuses to start with a distinct actionable error and MUST NOT mint a second identity or fall back to a file, env var, or in-memory key. This is **not** a crash: the supervisor MUST NOT retry it on backoff, and surfaces it as a blocker naming the unlock action (§4.2, §3.2) |
| Invite TTL expiry, three failed proofs, or SAS mismatch | Invite is voided with no retry; a failed proof does not consume the invite but increments its durable failure counter; a crash after consumption leaves it consumed, so the joiner requests a fresh invite (§4.5) |
| Outstanding-invite cap reached on a device | Refuse to issue, listing that device's outstanding invites; the cap is per issuer, not per session (§4.5) |
| Bootstrap preflight rejection | Case/Unicode collision, Windows-reserved name, escaping symlink, or count/size limit is reported per path and requires resolution or explicit exclusion before the clone proceeds; nothing partial is written (§8.2) |
| Bootstrap interrupted | Resume by digest and offset, or restart cleanly; a partial ref is never exposed and staging artifacts are deleted (§8.2) |
| Catch-up result batch fails verification | Reject the batch, do not advance either cursor, and retry elsewhere; the signer is trusted only after scratch replay establishes that it is active in the authority at the batch end. A signed progress regression is an audited integrity blocker (§5.3) |
| Large catch-up | A full verified checkpoint snapshot may accelerate replay, but V1 retains command results and never treats a snapshot as permission to skip unverified history (§5.3) |
| Checkpoint append interleaved after capture | Deterministic `stale_checkpoint` result and retry; distinct from a same-position hash/digest mismatch, which integrity-halts (§5.2.1) |
| Initial publication cannot assemble a staging-receipt majority | Remains a durable local `preparing` attempt with no signed/replicated event and names unreachable target voters; target change recollects receipts for the same reserved proposal event, or the author abandons it (§§5.1, 7.2) |
| Approved publication cannot assemble fresh apply receipts | Stays `approved` with a visible blocker naming unreachable current-target voters; canonical does not move, and holders may issue fresh receipts from protected pins (§7.2) |
| Voter change lacks canonical coverage on the target majority | Keep the old live configuration, show `object-coverage-degraded`, fetch/validate/sign receipts, and resume only for the same canonical version (§§3, 8.1) |
| Publication repeatedly loses the canonical CAS | Rejection leaves the publication unchanged; the initiating daemon counts stale lineage attempts locally and shows `starving` past the threshold. Reject or withdraw the stale publication before creating its superseding publication/review; no replicated rejection counter is mutated (§7.2) |
| Conflict whose resolution can never be staged | Owner `conflicts force-resolve` clears the completion gate, recording that it was cleared without a merge publication; without it a task could only be `cancelled`, i.e. mandatory data loss (§6.4) |
| Ref advertisement rollback, gap, or wrong prior OID | Reject equal/lower sequence. For exactly-next, reject a wrong prior OID; for a forward gap, verify the independent sparse snapshot, advance with an explicit missing-history marker, and never claim continuity (§8.1) |
| Draft restore target differs from the manifest base | Preserve both versions and surface a per-path conflict; never overwrite/delete silently. Materialization occurs only in an isolated managed worktree, and the sparse container is never raw-cherry-picked or merged (§8.1) |
| Git storage quota or draft/publication-staging pin cap reached | Safely prune eligible history/artifacts, expired/rejected pre-proposal pins, applied pins already covered by local canonical ancestry, and unreferenced rejected/withdrawn pins under the bare-store mutex; otherwise refuse growth and preserve canonical, nonterminal/unresolved-conflict, unexpired-staging, live-draft-head, and explicit-pin reachability (§8.1) |
| Git quota configured below current use | Start normally in `git-storage-over-quota`; permit reads, export/deletion, and safe pruning/GC, but no quota-growing operation. Never evict protected data or reject daemon startup solely for overage (§8.1) |
| Operator Git GC removes an object a peer's ref needs | Report `object-lagging` and refetch from a receipt holder; never fast-forward a ref from unverified data (§8.1) |
| Sole durable copy of a canonical object on this device | `sessions leave` and uninstall refuse without an explicit override naming the object (§8.1, §10.1) |
| Voter force-leaves without prior demotion | Never alter membership or the Raft configuration implicitly. If remaining voters retain quorum, show degraded tolerance until an owner commits and reconciles a replacement/removal; otherwise strong writes and renewal stop and §3.1 recovery is required (§§3, 9) |
| Clock skew beyond the allowance | Voters refuse credential-time endorsements and peers refuse content certificates; `status`/`repo doctor` report suspected skew distinctly from expiry (§2.3, §4.6) |
| Multicast blocked with no manual endpoint configured | Distinct from a stale hint: report that discovery is unavailable and name `peer endpoint add` as the required action (§2.3) |
| Ambiguous session selection | Refuse, exit non-zero, and list every registered candidate with root, `session_id`, and state; never guess and never pick the most recent (§3.2) |
| Workspace/repository path aliases an existing registry entry | Resolve native filesystem and Git-common-directory identities, select the existing entry, or reject a conflicting adoption; never start a second daemon through a symlink, junction, case variant, or copied marker (§3.2) |
| Workspace marker names another session, endpoint, or state path | Treat it as an untrusted mismatch and refuse; only the owner-only supervisor registry may resolve an IPC endpoint (§§5.1, 6.2) |
| Authenticated member request exceeds a depth or rate limit | Structured refusal, audited per §5.4's two-tier rule; unauthenticated discovery and handshake floods follow their intentional silent-drop/local-aggregate rules (§§4.4, 10) |
| Invalid or insecure local configuration | Reject the entire file before side effects, name the key/source/error, and suggest `config validate`; never fall back to partial/default security settings (§11) |
| Unsupported Git, SQLite, or OS version | Refuse to start naming detected and required versions (§11.1) |
| Missing canonical object during §3.1 recovery | Recovery stops and names the staging-receipt holders; if no copy survives, selecting the latest locally complete ancestor requires a second explicit repository-data-loss confirmation recorded in the successor genesis (§3.1) |
| Minority believes the majority is gone | Recovery requires an active owner's identity or an active editor's identity plus recovery key; two partitions that recover produce mutually incompatible successors and name both recovering devices (§3.1) |
| TLS ticket/resumption or 0-RTT offered | Refuse; V1 performs a full certificate handshake and current admission checks on every connection (§4.6) |
| Active member lost local session state | Rebootstrap only after the device is absent from both voter target and live Raft configuration; otherwise fully remove it first or use §3.1 after quorum loss. After verified import, its daemon reaps old local agent sessions before accepting new ones (§4.5) |
| Settled nonvoter backup or restore | Use a verified logical checkpoint/snapshot plus contiguous signed attestations through the result head; never claim or synthesize a Raft applied position. A Raft participant instead requires a matching Raft snapshot and SQLite backup (§6.2) |

An accepted event means voter-majority durability, not application by every peer. A publication
additionally proves durable objects on a voter-target majority, while each member's local object/ref
materialization may lag. Report those states separately.
