# CodeComm V1 Design — Part 10: Security and Privacy

Part 10 of 14. Contents: §10 threat model and controls, §10.1 at rest, audit, retention, removal.
Section map, review status, and reading order: [README.md](README.md)

Authoritative revision 0.14; maintained only in this split set.

Normative terms follow RFC 2119/8174; declarative requirements and table rows headed "MUST" or
"Required" are equally normative.

---

## 10. Security and Privacy

Assume hostile LAN, spoofed/replayed discovery, unauthorized API/pair attempts, lost/compromised
former members, malicious paths/content, prompt injection, tampered dependencies, secret-bearing
telemetry, and workspace readability by authorized owner/editors.

Per §2.1, an authorized member is in scope as an adversary in the following forms:

| Authorized-member threat | Control |
|---|---|
| Member floods proposals by fanning out to every peer | Per-receiver rate limits are a first-line filter only: proposals may enter through any member, so N peers each admit their own quota and forward, and the leader — the one node that cannot fan out its work — sees the sum. §11.2's `leader_ingress_rate_per_device` is the actual bound, applied on the leader after forwarding and before `raft.Apply`. Because the limit is local and uncommitted, the refusal is a transport-level response and never a committed outcome |
| Careless or subverted member floods events, claims, or leases | Committed per-device/per-agent caps bound active claims and leases, including the session-end cascade. Activity is append-only, so it cannot honestly have an “unacknowledged” reducer depth; event/byte bounds and receiver/leader rates contain it, and §16 records residual authorized-member disk exhaustion. Time-relative limits stay outside reducers (§6.3) |
| Member proposes malformed or unauthorized mutations | Deterministic recheck of role, schema, actor binding, and expected version on every replica (§5.3 step 5) |
| Member escalates its own role or voter status | Grants are committed and audited; ordinary grants are owner-only. The sole exception is a recovery-key-signed event that promotes only its submitting active editor and still needs Raft quorum (§4.3) |
| Member signs an endpoint set naming another host | The object is attributable but not treated as address ownership: literal/special-address and count/byte checks run first, dials require a selected-interface route and bounded backoff, and no application byte is sent unless the expected member identity completes TLS (§4.4). A malicious member can still induce bounded ClientHello traffic to an allowed routed literal (§16) |
| Member's device is lost or stolen | Committed revocation closes consensus and content access at admission on applied membership; a peer that never observes it stops serving content within 1800 s plus the §11.2 clock bound, i.e. up to ~32 minutes (§4.6) |
| Member reads workspace or history it should not have seen | Not a control boundary: admission is the decision (§2.1). Withholding data requires revoking the device and rotating affected external secrets out of band; CodeComm provides no external-secret rotation primitive |

**A compromised local OS account is out of scope, and that exclusion is broader than it looks.**
Every mechanism that authorizes a *local* caller lives inside that boundary: the IPC peer check
(§5.1), the OS credential store holding the identity signing key — unlocked for the logged-in
session on macOS and Linux, so any process at that UID signs as the device — `control_file_approvals`
(§8.4, the only per-device consent boundary), and the whole MCP and agent surface. A compromised OS
account is therefore full and indefinite impersonation of that member device, including owner
actions if it holds `owner`. Because §10.1 provides no key rotation within a `device_id`, the sole
remedy is revocation and re-pairing as a new identity; and because every event the attacker signed
is validly signed and permanently retained, there is no primitive to bound *when* the compromise
began — the design has no "events from device D after `chain_index` N are suspect" concept. V1
therefore treats the OS account as the trust root, and credential-store enrolment MUST use
per-application ACL scoping where the platform offers it (Keychain ACL, Windows Credential Manager
scoping) so a different process at the same UID is not automatic. §16 carries this as a risk.
The same limitation applies without a full account compromise when a coding agent is allowed to
launch arbitrary local processes: MCP cannot select `operator`, but an approved shell command can
invoke the human CLI under the same UID. Client sandbox and command-approval policy, not CodeComm
IPC, is the boundary for that path; the product MUST state this rather than imply OS-level agent
isolation.

Also out of the V1 boundary: revocation of data a member already
downloaded, which is unrecoverable once fetched; a malicious authorized **voter** deliberately violating the consensus protocol (§2.4 excludes
Byzantine tolerance) — an exclusion that extends to voter-signed result batches, checkpoints,
durability receipts, and ancestry attestations. For example, at 3 voters one dishonest voter plus
one honest one can produce a receipt majority for objects only one device holds, defeating §2.5's
"no canonical pointer without durable objects". Cross-checks and post-apply refetch detect some lies
but cannot prevent them; a receipt holder that cannot serve what it attested is an audited integrity
blocker (§8.1). Confidentiality among mutually all-reading owners/editors is also excluded (§2.1).

Required controls:

- TLS 1.3 mTLS, pinned invite identity/genesis, exporter-bound one-use invite proof, two-sided SAS
  confirmation, rate limits, and replay/idempotency protection. V1 has no short-code mode; any
  future one requires a separately specified and audited PAKE (§4.5).
- Stable device identity, quorum-authorized ephemeral keys, bounded stale
  partition lifetime, committed revocation, safe voter changes.
- Voter target and credential authority are separate: every replacement voter proves checkpoint
  application/promotion and the prior authority signs the handoff before credentials, checkpoints,
  or catch-up trust switch; a stalled target leaves the old authority usable (§3).
- Plane-specific ALPN dispatch: identity-authenticated consensus carries only guarded Raft and its
  four closed control endpoints, never repository bytes or ordinary content APIs; epoch-mTLS content
  expires in 30 minutes; pairing is isolated pre-membership. Quorum clock endorsements make
  late renewal possible without trusting one leader's wall clock; no future-key stockpile; only an
  applied leader replicates to active live-configuration voters/staging nonvoters. TLS tickets,
  PSK resumption, and 0-RTT are disabled so every connection reruns admission (§4.6).
- Daemon-constructed event `origin` blocks, so operator-only verbs are unreachable from the MCP
  socket by construction rather than by convention (§5.2, §7.1).
- One-use launch registrations fix session, client/profile, concurrency mode, and a canonical
  daemon-managed root before vendor start; selectors cannot choose host paths or create a second
  agent after reservation/consumption (§§5.1, 7.2).
- Publication authority: every path in the bounded introduced-history union has a held path lease,
  task/root binding matches, and the daemon alone builds from the opaque bound root. Agent review
  requires another device; an explicit local human review is permitted and labeled (§7.2).
- Two-tier audit: accepted events and retained committed rejections project directly; bounded
  `audit.recorded` events cover active-member request rejections with no retained result; all
  other/excess attempts aggregate locally (§5.4).
- Origin signatures, separate apply-time event/result chains, authority-signed checkpoints, and
  Raft commitment; no remote SQL/DB changesets.
- Owner/editor least privilege; admission is the only data boundary (§2.1).
- Last-owner removal is rejected; the offline recovery key can restore only its submitting active
  editor while quorum exists, or authorize that same active editor as a §3.1 recovery candidate after
  quorum loss. It cannot revive or replace an ineligible identity.
- Local-only MCP/IPC with Unix peer UID/socket mode or Windows named-pipe ACL.
- Absolute verified MCP executable; no remote execution or permission changes.
- Provenance-labeled bounded remote text; ANSI/OSC/control-character escaping.
- Per-device approval for agent instructions/hooks/MCP/ignore policy.
- Session-bound bare Git store; read-only allowlisted `upload-pack`; no `receive-pack`, user-owned
  refs, arbitrary repository paths/OIDs, checkout, or workspace writes over the peer API.
- Exclusive `refs/codecomm/**` inventory plus expected-old-OID CAS for every final bare-store and
  user-repository ref write; external mutation blocks as `ref-tampered` and is never overwritten.
- Quarantined bounded bundles, digest and graph/metadata verification, no shell, and
  hooks/helpers/filters/alternates/submodule/LFS network disabled.
- Canonical path/symlink containment and file/request/queue/DB quotas, including the committed 1 MiB
  control-file artifact limit and exact size/digest verification before local approval writes.
- Committed depth limits plus local rate limiting, per the table row above.
- Redaction before persistence/replication; restrictive/rate-limited local logs;
  no telemetry in V1 — there is no opt-in mechanism, destination, or payload, and adding one would require an ADR (§17).
- Identity and epoch-key material in platform credential protection (Keychain, Secret Service-
  compatible storage, or Windows Credential Manager/DPAPI-backed storage); temporary sensitive
  artifacts expire securely. Per-application ACLs are used where available but are not treated as
  protection from a compromised OS account.
- Signed/checksummed releases, SBOM, dependency/license/vulnerability review,
  exact executable firewall rules, and explicit Windows firewall consent.

### 10.1 At rest, audit, retention, and removal

CodeComm does not encrypt data at rest in V1 and relies on full-disk encryption. What
that leaves in the clear, including copies of repository content **outside** the
workspace:

- `state.db` and its WAL, holding all coordination history;
- `consensus/`, the Raft log and snapshots;
- `.codecomm/contexts/<agent_session_id>.{json,md}`, regenerated per-agent workspace projections
  containing bounded tasks, memory, activity, peer, and repository state;
- `tmp/` during bootstrap, which briefly holds a complete Git bundle of the repository;
- `<per-user state>/codecomm/sessions/<workspace_id>/git/`, the session bare store, quarantines, publication artifacts, and retained draft
  objects; `.git/objects` and `refs/codecomm/**` may also retain content deleted from a working tree;
- `control/`, the locally approved control-file bytes and delete tombstones needed to preserve that
  decision across Git operations;
- `conflicts/` temporary merge-resolution worktrees/snapshots;
- redacted logs and any support bundle.

Identity and live epoch private keys are the exception: they live in the OS credential store, never
in either tree (§§4.2, 4.6). FDE cannot be enforced from userspace, so `status` and `repo doctor`
MUST report volume encryption for the workspace and per-user state as one of three states —
`encrypted`, `not encrypted`, or `undetermined` — and first-run MUST warn on the latter two,
naming the platform reason. Three states rather than two because a binary is not achievable:
Windows `GetProtectionStatus` requires elevation that §2.2 forbids the daemon to hold, and Linux
dm-crypt detection misreports fscrypt, eCryptfs, ZFS-native, and LVM-on-LUKS nesting. The check
also mitigates only offline device theft: at runtime the volume is mounted and decrypted, so it
does nothing for the OS-account boundary above, and a green result MUST NOT be presented as
protection it is not. Database encryption and its key
management are deferred.

**Identity key lifecycle.** Revoked and superseded identity public keys are retained
indefinitely in `devices`, since §5.2 rests history verifiability on them: revocation ends
authorization, never verifiability. Identity private keys are outside backup and export
(§6.2). A device whose credential store is lost or whose OS is reinstalled has lost that
identity permanently; it re-pairs as a **new** `device_id` and an owner replaces its voter
slot (§3). There is no key rotation within a `device_id` (§4.1).

**Recovery key lifecycle.** `host` generates an Ed25519 recovery keypair, stores only its public key
in genesis, exports the private seed exactly once, and requires confirmation of off-device storage.
CodeComm retains no private copy. Key input uses TUI/no-echo stdin and never enters argv,
environment, event payload, log, crash report, or support bundle. Possession plus control of an
active editor identity can restore that editor to owner while quorum exists (§4.3) or make it the
successor after quorum loss (§3.1); revoked, readmission-required, absent, and never-admitted
identities remain ineligible. The creation prompt states both powers. For owner restoration, the CLI
signs a daemon-reserved local challenge and sends only the public authorization signature (§5.1). A
successor rotates the key.

**Audit.** Every accepted domain event and first-seen committed rejection projects its auditable
fields into `audit_events`; neither emits a duplicate `audit.recorded`. Explicit `audit.recorded`
events cover only active-member request rejections lacking both an accepted event and retained
command result, capped per subject device and latest committed credential epoch. Their origin is
the reporting device, so the view shows reporter and subject and does not present the report as
independent evidence. Excess, unknown, unauthenticated, revoked, and stale-epoch attempts remain
bounded local aggregates (§5.4). The audit view includes membership/voter changes, owner recovery,
revocations, credential authorizations, operator overrides, quorum recovery, and bounded
member-attributable rejections.
Committed source events inherit chain tamper-evidence (§5.2.1). Any member may read the audit log
(§2.1).
`codecomm audit list|export` exposes it, with export producing a signed range whose complete event
and result chains are verifiable per §5.2.1. A §3.1 recovery boundary contributes one audit row
derived from its signed successor genesis rather than a fabricated domain event.

**Retention.** Coordination history — including every `actions[]` entry and
`rationale_summary` — is retained for the **session's lifetime**. These fields live inside
signed, chain-covered events (§5.2.1), so they cannot be pruned without either breaking chain
verification or introducing a second event form; V1 does neither. Pruning an activity
*projection* reclaims space but deletes nothing sensitive, and this document does not claim
otherwise.

The only way to shed activity history is to export, end the session, and start another (§2.2).
SQLite WAL checkpointing and Raft log compaction after a verified FSM snapshot are physical storage
maintenance and MUST NOT prune `events` or `command_results`. The UI offers audit/event export before
deleting an old session. Logical payload compaction is a later revision, not V1.
Compact local request/challenge tombstones likewise remain for the active generation to prevent an
old local retry becoming a new mutation; they retain IDs/digests/codes, not artifacts or duplicate
event bodies (§6.2).

Git history has a separate local quota (§8.1): unpinned drafts, applied publication refs already
covered by local canonical first-parent ancestry, and rejected/withdrawn refs with no unresolved
conflict may be unreferenced before explicit bare-store GC under the import/GC mutex. Canonical,
nonterminal/unresolved-conflict, live-draft-head, unexpired staging, and explicit-pin reachability is
never quota-evicted; new growth stops instead, including when configuration is lowered below current
use.

**Removal.** `sessions leave` is local (§9). Uninstall removes the supervisor registration,
registry, and per-user state, and MUST prompt separately before removing `.codecomm/`
directories, identity keys, or CodeComm-owned Git refs, naming what is about to be destroyed and
that it is unrecoverable. It never deletes user refs or runs Git GC in the user's repository. `codecomm
support-bundle` produces a redacted archive under the same redaction rules as retained
diagnostics (§12.5), and states what it included.

Signatures prove provenance, not content safety.
