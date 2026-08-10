# CodeComm V1 Design

Status: Draft for review  
Date: 2026-08-05  
Revision: 0.10  
Owner: *unassigned — set before review*  
Reviewers: *unassigned*  
Audience: Engineering, with product review of §§2, 15, 16  

`MUST`, `MUST NOT`, `SHOULD`, and `MAY` are normative as defined in RFC 2119 and RFC 8174.
Requirements also appear as declarative statements and as table rows; a row in a table headed
"MUST" or "Required" carries the same force as the keyword.

Revision history: 0.10 replaces live working-tree replication with Git-native object/ref
exchange, immutable draft snapshots, and quorum-staged canonical publications; it also makes
lease expiry time-driven, persists reassignment targets and version reports, gives merge
conflicts deterministic identities, and defines a Raft catch-up proof available without
leader-side match-index access. 0.9 specified apply-gated voter reconciliation; 0.8 restored
30-minute credentials with quorum-gated cold-start rekey; 0.7 was the initial full draft.

## 1. Problem and Approach

Coding agents such as Codex and Claude Code work well on one machine. The moment work spans two
— a laptop and a desktop, or two people's laptops — there is no shared coordination layer:
no shared task list, no record of which agent is editing which files, and no synchronized repository
state. Agents duplicate each other's work, overwrite each other's files, or sit idle. Every existing
answer routes through a hosted service — GitHub, or a SaaS control plane — which many settings
cannot use and none should need for machines sitting on the same network.

CodeComm is a local-first TUI/CLI and local daemon that coordinates coding agents across the same
or different devices and synchronizes repository state, with **no hosted relay and no data leaving
the authorized devices**. It is for a small group — 2-8 devices, owned by one person or several
(§2.1) — collaborating on one workspace over a LAN, direct Ethernet, or a user-provided VPN.

Concretely, the smallest useful session:

1. On laptop A, `codecomm host` in a Git repository starts a session and prints a one-use invite.
2. On laptop B, `codecomm join` with that invite pairs the two devices; both operators confirm the
   same authentication string (§4.5), and B bootstraps the repository over the direct link (§8.2).
3. Agent A1 claims task 7; agent B1's `context.get` immediately shows the claim and A1's path lease,
   so B1 picks task 9 instead of colliding (§6).
4. A1 finishes on an isolated worktree and publishes a reviewed commit. Its objects are staged on
   a voter quorum before one committed compare-and-set advances the canonical CodeComm ref; B
   fetches that immutable commit without any remote process changing B's `HEAD`, index, branch, or
   working tree (§§7.2, 8).

Nothing touches the cloud. Direct transfer survives leader loss; strong writes survive a peer loss
only while the configured voter quorum does (§§3, 9).

### 1.1 Alternatives considered

| Instead of | Rejected because |
|---|---|
| A CRDT or last-writer-wins task store (no consensus) | The goal is exactly one winner for a task claim (§2.2); with LWW two agents can both "win" and burn effort on one task, which is worse than a brief queue. Raft buys a single agreed order for the small set of strong decisions |
| A single designated coordinator device | It is the permanent routing/availability dependency §2.5 forbids; losing it loses the session, whereas a replaceable Raft leader (§3) does not |
| A hosted relay or Git host as the hub | Defeats the one hard constraint — no data through a third party — and needs connectivity CodeComm explicitly does not assume (§2.3) |
| One shared database over the network | Leaks unrelated and deleted rows, couples every peer to one schema, and bypasses domain authorization (§5.3); per-device SQLite with logical replication avoids all three |
| Live working-tree replication (including Syncthing) | A checkout, reset, stash, or clean operation becomes an unbounded remote edit while peers' `HEAD` and indexes remain unrelated; conflict copies cannot preserve uncontended deletes. Git-native immutable objects and namespaced refs retain concurrent work without mutating a peer's workspace (§8) |

Raft and per-device SQLite are heavier than a toy would use; §16 records the residual risk against
the correctness the alternatives cannot provide. Repository transfer delegates object construction,
validation, and graph traversal to system Git rather than implementing a file-sync engine.

### 1.2 Decision summary

Member devices may belong to one person or to several; a device is the unit of identity and
trust (§2.1).

| Area | V1 decision |
|---|---|
| Platforms | Native Windows, macOS, and Linux |
| Principal | The device; no user or account identity |
| Processes | Per-user supervisor service plus one session daemon per joined workspace |
| Connectivity | Direct LAN, Ethernet, or user-provided VPN; no hosted relay |
| Topology | Direct authenticated peer mesh; no permanent coordinator or data hub |
| Strong state | Maintained embedded Raft; replaceable leader; 1/3/5 voters |
| Discovery | UDP multicast plus manual endpoint/invite fallback |
| Pairing | One-use high-entropy invite and two-sided transcript confirmation |
| Transport | TLS 1.3 mTLS; 30-minute quorum-authorized session keys plus a restricted identity-authenticated cold-start rekey plane |
| Coordination | Signed logical events, deterministic reducers, local SQLite |
| Repository data | Git bundles/objects and source-owned namespaced refs over direct mTLS; no remote working-tree mutation |
| Bootstrap | Verified Git bundle from any up-to-date owner/editor peer (§3) |
| Agents | Local stdio MCP for Codex and Claude Code; many instances per device |
| Isolation | Per-agent Git worktrees by default; shared root is explicit opt-in |
| Licensing | CodeComm under a permissive OSS license; system Git is invoked, not redistributed |

The elected Raft leader orders strong mutations but carries no ordinary REST, Git, presence, or
repository traffic; losing it causes a brief election while direct peer traffic continues. Without a
voter majority, strong mutations and new credential authorizations MUST pause, while local work
and direct Git transfer among reachable peers continue only until current credentials expire (§3).

## 2. Scope and Invariants

### 2.1 Participants and trust model

A **member** is a device, and `device_id` is the only principal. Application roles,
credentials, revocation, and audit attribution all bind to a device. CodeComm has no
user or account identity.

Devices in one session MAY belong to one person or to several. No mechanism branches on
ownership: transport, consensus, repository transfer, roles, revocation, and agent coordination treat
every authorized device identically, and CodeComm never records who operates a device.
Each member runs one daemon for this workspace (§3.2) and MAY run many concurrent agent
sessions against it. Ownership affects only who performs a human step: at the pairing
confirmation of §4.5 step 6, two operators compare the authentication string out of
band, or one operator compares it across their own two screens. CodeComm MUST require
it in both cases.

Members trust each other enough to share a workspace, but not unconditionally. Two
consequences are normative:

- **There is no confidentiality boundary between members.** Every member replicates the full
  event stream and may fetch every shared Git object, so any member can read the entire workspace and all
  coordination history. Withholding data from a device means not admitting it, or revoking it
  and rotating the affected secrets. V1 has no read-only role: a filtered replication path that
  still chain-verifies (§5.2.1) is a subsystem V1 does not build, and a role promising privacy
  it could not deliver would be worse than none.
- Role and voter grants MUST NOT be self-issued; every grant is committed and audited.

Roles are per device, not per operator: a hardened workstation MAY hold `owner` while a
travel laptop holds `editor`. Per-device revocation is the primitive; there is no
"remove this person" operation.

In-scope adversaries include an authorized but careless, curious, or subverted member,
and a former member that attempts to *regain* access after revocation. What a former
member already downloaded is outside the boundary — revocation ends authorization, not
possession (§10). Untrusted or public participants are out of scope: admission is an
explicit owner decision, never automatic. A compromised local OS account is also
outside the V1 boundary.

### 2.2 Goals

V1 MUST:

- run as a terminal client, one per-user supervisor service, and one long-lived session daemon
  per joined workspace (§3.2), all under the invoking OS user account, never as a system
  service;
- discover, pair, authenticate, revoke, and reconnect devices securely;
- coordinate 2-8 member devices, owned by one or several people (§2.1), and up to 32
  concurrent agent instances;
- assign every collaboration, device, agent run, event, and workspace a distinct durable
  identity;
- replicate ordered plans, tasks, memory, leases, activity, and acknowledgements;
- support multiple Codex, Claude Code, or mixed instances on every device;
- preserve one winner for strong task/lease claims while quorum exists;
- bootstrap with Git; exchange canonical commits and eligible dirty/untracked work as immutable,
  source-namespaced draft snapshots (§8);
- preserve concurrent edits as commits or draft refs for explicit review/merge, without remotely
  mutating a member's `HEAD`, index, user refs, or working tree;
- resume idempotently after process, network, or device interruption;
- expose local MCP, CLI/JSON, TUI, and owner-restricted local IPC; and
- operate without GitHub or another hosted service on a directly routable network.

Initial targets are 100,000 files, 2 GiB per workspace, 100 MiB per file, and session-lifetime
coordination history with export before compaction. Sessions MAY use two devices, but
automatic strong-state failover requires three voters; a lone survivor queues strong mutations
until quorum returns.

### 2.3 Network constraints

Multicast normally does not cross routers, VLANs, VPNs, or client-isolated Wi-Fi. A manual IP
helps only when unicast routing exists. Eduroam-like networks may block all peer traffic;
supported fallbacks are switched/direct Ethernet or a user-provided VPN such as WireGuard or
Tailscale. `localhost` is never a cross-device transport. CodeComm binds only selected
non-loopback LAN/VPN interfaces and supports IPv4/IPv6 link-local use without DHCP.

Churn — sleep, Wi-Fi to Ethernet, DHCP renewal, VPN reconnect — is the normal case:

- Endpoints are **gossip, never committed state.** The roster carries endpoint hints
  (§5.1) with a TTL of one advertisement interval times eight; a hint older than its TTL
  is a starting guess only. Membership never changes because an address changed.
- On local address change, interface appearance or disappearance, or wake from suspend,
  a daemon MUST re-resolve its selected interfaces, re-advertise immediately rather than
  waiting for its next jittered interval, drop connections bound to a vanished local
  address, and re-dial every authorized peer with capped exponential backoff and jitter.
  Git transfers re-establish the same way (§8.1).
- Reconnection is idempotent and never loses durable work: queued events remain queued,
  replication resumes from durable cursors, and bounded Git artifacts resume by digest and offset.
- **Wake with an expired epoch.** A device suspended past its credential expiry MUST
  enter the rekey plane immediately (§4.6). If a voter majority is reachable, even when
  every reachable voter's session credential has expired, the voters re-form quorum,
  authorize fresh credentials, and reopen the ordinary mesh without operator action. If
  no majority is reachable, local work and reads continue against already-applied state;
  rekey discovery and identity-authenticated attempts continue, but ordinary peer,
  workspace, and Git traffic remain closed and strong proposals queue.

### 2.4 Non-goals

- GUI, Internet discovery, NAT traversal, or a CodeComm relay.
- Strong-write availability without Raft quorum.
- Byzantine tolerance against malicious authorized voters.
- Real-time character collaboration or automatic arbitrary merge.
- Copying `.git/` filesystem state, or synchronizing SQLite files/pages/WAL or another mutable
  shared DB. Git objects and CodeComm-owned refs move only through validated Git plumbing (§8).
- Remote shell/tool execution, remote agent launch, or replayed commands.
- Capturing private chain-of-thought.
- Reimplementing Git object transfer/merge, Raft, PAKE, signatures, TLS, or cryptography.

### 2.5 Critical invariants

Each row states a property that MUST hold, where it is enforced, and its proof: a bare number
is a §12.3 core scenario, a §-reference is a §12.2 or §12.4 test, and "—" marks a structural
property asserted by construction. A change that weakens any row requires an ADR (§11).

| Invariant | Enforcement | Proof |
|---|---|---|
| No permanent routing node | Every authorized pair connects directly | 1 |
| No split-brain strong state | Only quorum-committed Raft entries are accepted | 6, 7 |
| No replica divergence | Frozen reducers; halt rather than apply what a peer may have applied differently; digest compared at every checkpoint (§5.5, §5.6) | 9 |
| No acknowledged event loss | Event, chain, idempotency result, projection, and applied index commit in one durable SQLite transaction (§5.3) | 10, 21 |
| Idempotent resumption | Committed-but-unapplied entries replay identically after crash; duplicate IDs return the committed result | 10 |
| No identity reuse | `agent_session_id` and `event_id` are unique and never reused; the origin-scope sequence of §4.2 is unique | §12.2 |
| No orphaned ownership | Session end releases claims and leases deterministically; operators can always override (§6.4) | 5 |
| No remote agent control | MCP is local stdio; peer API has no execution primitive | — |
| No shared coordination DB | Each daemon owns local SQLite and applies logical events | §12.2 |
| No DB diffs on wire | Typed events/snapshots only; received SQL is inert data | §12.4 |
| No remote workspace mutation | Peer APIs can import validated Git objects and update only CodeComm-owned refs; no checkout, index write, user-ref update, `receive-pack`, or caller-selected repository path exists | 1, 15 |
| No silent file winner | Draft/publication commits are immutable; canonical advancement is CAS-ordered and merge conflicts are explicit | 15 |
| No canonical pointer without durable objects | `publication.applied` requires validated staging receipts from a current voter-target majority before its dual CAS | 15, 21 |
| No agent identity spoofing | Actor identity comes from the bound local MCP connection | §12.2 |
| No private reasoning capture | Store rationale summaries and redacted activity only | — |
| No silent control-file propagation | Per-device approval after bootstrap | 16 |
| No insecure minority renewal | Credential authorization requires quorum; a minority never self-promotes (§3.1) | 7, 20 |
| Revocation excludes from every later voter target | `membership.device_revoked` commits a resulting voter set without the device, CAS'd on `voter_set_version`; access is denied at admission on applied membership, never on the lagging Raft configuration (§3) | 14, §12.2 |
| Consensus authority is the Raft configuration alone | Quorum size and vote counting derive only from the committed configuration; applied application membership gates access, never majority arithmetic (§3, §4.6) | 6, 7, §12.2 |
| No rekey-plane write escalation | Dedicated ALPN and closed message enum; the only committable outcome is one `credential.authorized`; no ordinary API, Git/artifact, workspace, or agent surface (§4.6) | 7, 13, §12.4 |
| No committed data to a peer before an election | Inbound pre-election traffic is identity handshake, vote exchange, and an opaque credential status only; entries and snapshots flow solely from an elected leader that has applied its membership index (§4.6) | 13, 14, §12.2 |
| Content stays in the authorized set | Workspace files, secrets, and activity never leave admitted member devices; no telemetry by default | — |

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
separate. Voter count MUST be 1, 3, or 5 **at rest**; even counts are rejected as a
settled configuration, though a reconfiguration transits them (voter-set transitions,
below):

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

"Up-to-date", where it gates eligibility (bootstrap source §8.2, snapshot server §5.3),
means applied index equals the committed index the member reports, with a current credential and
no unresolved conflicts; a Git bootstrap source MUST also hold and verify the canonical commit.

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
   `membership.device_revoked` mutates two entities at once, the device and the voter set, so it
   is the one kind carrying a second explicit token, `expected_voter_set_version`, alongside the
   envelope's device version; a mismatch on **either** is a deterministic rejection. Without
   that, a revocation proposed concurrently with a `voter_set_changed` could commit a target
   computed from a set that no longer exists, silently reinstating or dropping a voter.
   Reducers additionally require `voter_set[]` to be sorted, unique, 1/3/5 entries, and composed
   only of active admitted devices. A revocation target MUST exclude the subject and every
   already-revoked device.
2. Reconciliation starts only on the current leader over ordinary epoch-mTLS transport. The
   leader first completes the library's barrier operation and waits until its local state machine
   has applied through that barrier; it then reads membership, target, and live configuration.
   A halted or no-longer-leader daemon issues no configuration call. This prevents a newly
   elected leader from reconciling toward a stale locally applied target.
3. The leader runs this state machine, one completed library future at a time:

   1. Add every target device absent from the live configuration as a **nonvoter**, in ascending
      `device_id` order. After `AddNonvoter` completes, force a fresh `consensus.checkpoint` and
      capture its event ID, committed log index, chain index, and chain hash. Before promotion,
      prove that this staging replica applied that exact checkpoint. The proof MAY come from a
      maintained public leader-side replication-progress API. The required fallback is an
      epoch-mTLS-authenticated response from the target, generated only after its FSM applies the
      checkpoint, echoing those four values from its durable local state. The leader compares the
      response byte-for-byte with its committed checkpoint; a generic `Barrier`, last-contact time,
      or self-reported numeric index alone is insufficient. Installing a snapshot and replaying its
      tail necessarily precede applying the checkpoint, so the proof covers both paths. Raft's
      non-Byzantine member assumption applies (§2.4). If the candidate library cannot run the
      staging FSM or expose the checkpoint's committed index, phase 1 MUST replace it with a
      maintained library that can; promotion has no weaker fallback. An unavailable or lagging
      target remains a nonvoter and never enlarges quorum prematurely.
   2. Let `V` be live voters and `T` the latest applied target. If `V ∩ T` is empty, promote the
      lowest-ID caught-up target nonvoter first. Otherwise, when `|V| > |T|`, remove an extra voter
      before promoting another; when `|V| ≤ |T|`, promote the lowest-ID caught-up missing target.
      For a like-for-like replacement, promotion precedes the paired removal. Thus voter count never exceeds
      `max(starting count, target count) + 1`, never reaches zero, and converges through the
      unavoidable even configurations.
   3. Remove only a voter outside `T` for which the post-removal configuration has a quorum of
      currently reachable, active voters. Prefer revoked voters, then unreachable extras, then
      ascending `device_id`; this removes a lost voter before a reachable helper in a 3→1
      transition. Never remove the current leader. If it is outside `T`, first transfer leadership
      with the library's targeted transfer API to the lowest-`device_id` target voter that has
      proved the latest checkpoint above; the new leader resumes from step 2. This deterministic
      choice needs no per-follower `matchIndex`.
   4. Remove obsolete staging nonvoters after all target voters are promoted. Stable state is
      exactly `T` as voters and no staging server.

   Every call carries the freshly observed configuration index as `prevIndex`. After its future
   resolves, the daemon re-runs the barrier, re-reads target and configuration, and recomputes from
   step 1; a changed target, failed compare, crash, or leadership loss therefore leaves no cursor to
   repair. The only durable inputs are the committed target and library configuration.

   **Reconciliation is suspended on the rekey plane.** A leader elected while quorum still
   depends on a rekey connection (§4.6) MUST NOT issue configuration calls, even if the target
   and live configuration disagree. §4.6 freezes every proposal except `credential.authorized`
   precisely so quorum does not move underneath a cold start, and a configuration change moves
   quorum. The leader defers the gap until ordinary transport is restored, then reconciles
   normally — which is safe because the gap is re-derived from observable state, so deferring
   costs nothing but time.

The consequence to state plainly: between intent commit and reconciliation completion the committed
application target and the live Raft configuration **disagree**, so voter changes are
eventually consistent with their intent. `voter_reconcile_deadline` is an alert threshold, not a
protocol time bound: an unavailable target, failed leadership transfer, or loss of a post-change
quorum can leave the cluster reconciling indefinitely. It keeps the target, never rolls back or
guesses a different set, retries after topology or leadership changes, and requires §3.1 recovery
if the live configuration permanently loses quorum. §5.5's frozen-reducer rule is unaffected,
since reducers only ever read the committed target.

**Revocation demotes, and does not depend on winning a race.** `membership.device_revoked`
commits a `voter_set_changed` target excluding the device as part of the same event, so a
revoked device is never a member of any subsequently committed target. Because the live Raft
configuration lags per the window above, the design MUST NOT rest any security property on the
revoked device having already left the Raft configuration. What actually bounds it is that every
peer refuses the device on **applied application membership** at *connection admission* —
ordinary transport (§4.6) and rekey admission (§4.6) — which is a local check needing no
reconciliation. Admission is the only surface: a peer that refuses the connection never reaches
a vote exchange, so nothing needs to special-case vote-granting itself, and per §4.6 nothing
may. If revoking a voter would leave an even or illegal count, the committed target
settles at the next lower legal count, so a revocation never rests the cluster at two voters.

### 3.1 Recovery from permanent quorum loss

Recovery is offline and single-device: credentials have expired (§4.6) and no peer is
reachable. It is authorized by a surviving `owner` device or by the **recovery key** — a
keypair whose public half the genesis record binds and whose private half is exported
once at `host`, which requires the operator to confirm off-device storage. The key
covers the no-surviving-owner case, where grants are not self-issued (§2.1). Losing
every owner device and the recovery key leaves the session unrecoverable, stated at
`host` when the key is issued.

`codecomm cluster recover-quorum` then:

1. Verifies the local committed state by recomputing chain continuity from genesis
   (§5.2.1), and verifies the most recent `consensus.checkpoint` signature if any
   checkpoint exists. A session with no checkpoint yet is still recoverable, since the
   chain is verifiable from genesis; recovery refuses only on a chain that fails to
   verify. It carries forward every locally committed and chain-verified entry.

   **Durability limit, stated plainly.** The recovering device is a survivor of a lost
   majority, so it may be behind entries the old majority committed and acknowledged. Those
   entries are unrecoverable from this device, and recovery therefore **does not** preserve
   the "No acknowledged event loss" invariant (§2.5) — it is the one operation exempt from
   it, which is why it demands explicit operator authorization. Recovery reports its
   `chain_index` and applied index so the operator can compare against any other survivor
   and choose the most advanced device to recover from. Prefer recovering on the survivor
   with the highest verified `chain_index` that also holds the canonical commit. A missing
   canonical object stops recovery and names its staging-receipt holders; if no copy survives,
   selecting the latest locally complete ancestor requires a second explicit repository-data-loss
   confirmation and is recorded in the successor genesis.
2. Requires owner-device authority or a signature from the recovery key.
3. Presents the members not being carried forward and requires explicit confirmation.
4. Writes a **successor genesis record** that binds the same `workspace_id`, a new
   `session_id`, an incremented `recovery_generation`, the digest of the prior genesis
   record, selected canonical commit/object format, and the verified `(chain_index, chain_hash)` it resumes from. The successor
   chain continues rather than restarting: its first accepted event chains from
   `chain_seed(successor)` (§5.2.1), which commits to the predecessor's final verified
   hash, so `chain_index` keeps increasing across generations and the whole lineage stays
   auditable.
5. Admits the recovering device as sole `owner` and sole voter, and marks every other
   prior member as requiring re-admission.

Survivors rejoin by **normal pairing** (§4.5), including the authentication-string
comparison; prior enrolment does not carry across a recovery generation. Prior identity
keys stay enrolled for historical signature verification (§4.2) but confer no
authorization in the successor session. A minority that merely *believes* the majority
is gone MUST NOT run this; recovery requires the deliberate operator action above. A
recovered session that later meets a surviving member of the old lineage detects the
mismatched `recovery_generation` and refuses to interoperate.

### 3.2 Process and session cardinality

One device runs one supervisor per OS user and **one `codecommd` per joined workspace**. A device
MAY participate in several sessions concurrently; each gets its own daemon process, Raft node,
HTTPS port, Git repository binding, and `.codecomm/` directory. Session and workspace are bound 1:1 by
the genesis record (§4.2), so "session daemon" and "workspace daemon" name the same process.

Two OS users on one machine each get their own supervisor, registry, and session cap, and
share the device identity: `device_id` is per device, so both present the same principal
and a session admits the machine once, consuming one member slot (§4.2). Where the OS
credential store is per-user, the identity key material is enrolled once and made
readable to the owning user only; a second OS user that cannot read it MUST refuse to
start rather than mint a second identity for the same machine.

The supervisor is the only component registered with `launchd`, `systemd --user`, or Task
Scheduler (§9); it is installed once per user and does not depend on any workspace
existing. It maintains a durable registry of joined workspaces in the platform-standard
per-user state location, never inside a workspace. Each entry records `workspace_id`,
`session_id`, workspace root, and last-known socket path and HTTPS port, plus the live PID
while its daemon runs. Entries outlive their daemon so a session can be listed and
restarted while stopped; an entry whose PID is dead is marked stopped at supervisor start
or on the next failed client connection, and its socket path and port are never reused
without revalidation. Registry files are owner-only.

Clients select a daemon in this order: an explicit `--session` or `--workspace` flag; the
nearest ancestor directory of the working directory containing `.codecomm/`; a sole
registry entry; otherwise fail listing every registered candidate. Once a workspace is
selected, a stopped daemon is started on demand through the supervisor. The MCP adapter
resolves identically at startup and binds for its lifetime, so an agent's actor identity
cannot migrate between sessions.

The per-workspace OS lock (§9) prevents two daemons owning one `.codecomm/`. Long-lived
device identity is **per device and shared across every session** (§4.2); credential
epochs, roles, and voter status are per session, and the §4.6 epoch binding includes
`session_id`, so one identity key backs several independent epoch streams. Losing one
daemon does not affect another; the supervisor restarts it with capped backoff and
surfaces repeated failure as a blocker rather than looping.

The 2-8 device and 32-agent limits of §2.2, and the 100k-file and 2 GiB workspace targets,
are all **per session**. Concurrent sessions per device are capped (default 4,
configurable); each adds a daemon, a listening port, and one multicast
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

## 4. Identity, Discovery, and Authentication

### 4.1 Cryptographic primitives

These values are frozen by the golden fixtures of §12.2, which make canonical encoding and
cross-platform signature stability a merge gate. ADR-003 records the selection and any future
migration; CodeComm implements none of these primitives itself (§2.4).

| Purpose | V1 choice |
|---|---|
| Signatures | Ed25519 (RFC 8032), 32-byte public key, 64-byte signature |
| Digests | SHA-256 |
| Canonical form for signing | RFC 8785 JSON Canonicalization Scheme (JCS) |
| Binary fields in JSON, including digests carried as values | unpadded base64url (RFC 4648 §5) |
| Digests in identifiers and display (`device_id`, UI) | lowercase hex, full length, never truncated |
| Integers in a hash preimage | 8-byte big-endian, each field length-framed |
| Key agreement, record encryption | none of CodeComm's own; TLS 1.3 provides it (§4.6) |

`signed_bytes` for any object is `JCS(object minus its own signature field)`. JCS fixes
UTF-8, lexicographic key order over UTF-16 code units, no insignificant whitespace, and
canonical number form. Every field inside a signed object MUST be a string, a JSON
integer in the safe range, a boolean, `null`, an array, or an object — **floating-point
values are prohibited in signed fields**. Durations and sizes are integers with the unit
in the field name; timestamps are RFC 3339 strings.

Unknown fields are never stripped before verification: a verifier canonicalizes and
verifies exactly the bytes it received, so an object carrying an unrecognized field
still verifies, and §5.1's capability rules then decide whether it is acceptable. The
negotiated binary encoding and compression of §5.1 are a transport wrapper only; they
never alter `signed_bytes` (§5.3).

`device_id = "cc1" || lowercase_hex(SHA-256(raw 32-byte Ed25519 public key))`, full 64
hex characters, no truncation; comparison is over the whole string. A `device_id` is a
commitment to one public key, so enrolling a new key produces a new device identity
(§4.2).

Every signature is over a domain-separated input:

```text
signed_input = domain_label || 0x00 || signed_bytes
```

`domain_label` is one of these exact ASCII strings; the `0x00` separator cannot occur
inside a label:

| Label | Signed object |
|---|---|
| `codecomm/v1/genesis` | Immutable genesis record |
| `codecomm/v1/discovery` | Multicast advertisement datagram |
| `codecomm/v1/invite` | Invite bundle issued by an owner |
| `codecomm/v1/invite-proof` | Joiner's proof of invite possession |
| `codecomm/v1/credential-binding` | Ephemeral TLS key / session / device / epoch binding |
| `codecomm/v1/rekey-handshake` | Cold-start rekey nonce/exporter proof (§4.6) |
| `codecomm/v1/event-origin` | Origin's domain proposal |
| `codecomm/v1/checkpoint` | Committed chain checkpoint (§5.2.1) |
| `codecomm/v1/batch` | Served catch-up batch (§5.3) |
| `codecomm/v1/snapshot` | Signed logical snapshot |
| `codecomm/v1/git-ref-advertisement` | Source-owned draft/publication ref advertisement (§8.1) |
| `codecomm/v1/git-stage-receipt` | Voter proof of durable validated publication objects (§7.2) |
| `codecomm/v1/sas-transcript` | Pairing authentication-string transcript |

The `v1` component is the primitive-suite version, carried in the genesis protocol policy
and independent of `schema_version`. Changing any primitive requires a new suite version
and a new set of labels; a member MUST reject an object whose label names a suite it does
not implement.

### 4.2 Identifiers

| ID | Meaning |
|---|---|
| `device_id` | `cc1` + hex SHA-256 of the Ed25519 identity public key (§4.1); one per device, shared across all its sessions |
| `session_id` | UUIDv7 for one session; bound 1:1 to `workspace_id` by the genesis record |
| `workspace_id` | Random UUID for the logical workspace; one daemon per joined workspace (§3.2) |
| `agent_profile_id` | Optional stable persona/configuration ID |
| `agent_session_id` | Never-reused UUIDv7 for one running agent instance |
| `event_id` | Origin-generated UUIDv7 |
| `origin_sequence` | Monotonic sequence within one *origin scope*: the `agent_session_id` for `agent` events, and the `(device_id, daemon boot id)` pair for `human` and `daemon` events, which carry a null `agent_session_id`. Uniqueness is over `(device_id, agent_session_id_or_boot_id, origin_sequence)` |
| `entity_id` | The identity of the entity an event mutates, typed per family: UUIDv7 for `task.*`, `plan.*`, `memory.*`, `lease.*`, `agent.session.*`, and `publication.*`; deterministic `ccf1` conflict digest for `workspace.conflict.*` (§8.3); `device_id` for `membership.*` and `credential.*`, except `membership.voter_set_changed`, which uses `session_id` (§3); `session_id` for `policy.changed`; canonical workspace-relative path for `control_file.change_proposed`; null for `consensus.checkpoint` and `audit.recorded`. The fixed form lets a reducer parse it before the payload |
| `log_index` | Committed Raft log index; event indices may have gaps |

Every agent event carries `(session_id, device_id, agent_session_id)`. `agent_session_id` MUST
come from secure daemon randomness, never PID, label, path, or vendor display ID. A directory
name is display-only; `workspace_id` is authoritative. Long-lived private keys MUST stay in the
OS credential store, outside the workspace. If no provider is available or the store is locked —
a headless Linux host with no D-Bus session, or an unattended boot before first unlock — the
daemon MUST refuse to start with a distinct, actionable error. It MUST NOT fall back to a file,
an environment variable, or an in-memory-only key (§3.2).

The bootstrap device signs an immutable genesis record binding `session_id`, `workspace_id`,
`recovery_generation` (0 at creation), `recovery_public_key` (§3.1), the primitive suite version
(§4.1), Git object format, initial canonical commit, protocol policy, and initial membership. The
canonical row of §6.1 is initialized from that commit on every replica. Protocol policy is the set of values every
member must agree on: `credential_epoch_seconds`, `credential_overlap_seconds`, and
`credential_renewal_lead_seconds` (§4.6),
`checkpoint_events` and `checkpoint_interval` (§5.2.1), `digest_version` (§5.6), admission depth
limits (§10), lease minimum/default/maximum TTL (§6.1), the multicast group and advertisement
interval (§4.4), and `cluster_min_version` (§5.5). §11.2 is the authoritative list of which
constants are committed. Endpoint hint
TTL is derived from the committed advertisement interval, not separately committed. Everything else
is local configuration, and changing a mutable committed value requires a `policy.changed` event
(§5.4). The 30-minute epoch, two-minute overlap, and five-minute renewal lead are fixed in V1;
changing any of them requires a new protocol policy version and ADR, and a V1
`policy.changed` reducer MUST reject it.

Subsequent trust changes require committed membership events. There is no transferable session
CA key. A successor genesis record is written only by quorum recovery (§3.1) and chain-links to
its predecessor, so genesis is immutable within a `recovery_generation` and auditable across
generations.

### 4.3 Roles

| Capability | Owner | Editor |
|---|---:|---:|
| Read coordination | Yes | Yes |
| Receive/send shared Git objects | Yes | Yes |
| Claim/update tasks | Yes | Yes |
| Propose plan/memory | Yes | Yes |
| Make plan current | Yes | No |
| Force-release own task (§6.4) | Yes | Yes |
| Reassign or cancel (§6.4) | Yes | No |
| Invite, change roles/voters, revoke, change policy | Yes | No |

Role/voter changes are signed, committed, audited, and cannot be self-granted. Credential roles
MUST match current committed membership.

### 4.4 Discovery

Each session daemon MUST multicast a signed, versioned datagram on every selected
interface at the §11.2 advertisement interval, and immediately on start, wake, and
address change (§2.3). A device joined to several sessions emits one advertisement
stream per session, and receivers filter by `session_id` (§3.3). Group address,
interval, TTL, and size limit are in §11.2.

```json
{
  "magic": "codecomm",
  "protocol": 1,
  "session_id": "uuid",
  "https_port": 47831,
  "credential_epoch": 42,
  "advertising_key_digest": "base64url",
  "transport_mode": "session",
  "committed_membership_index": 1048,
  "pairing_open": true,
  "advertisement_nonce": "base64url",
  "expires_at": "RFC3339",
  "signature": "base64url"
}
```

The source address is only an endpoint hint. Datagrams contain no workspace, device, or
operator names, paths, stable identity fingerprints, secrets, tasks, or activity. They
do broadcast `session_id`, `credential_epoch`, `transport_mode`,
`committed_membership_index`, and `pairing_open` in the clear — an accepted residual
disclosure of a session's existence, credential state, pairing state, and commit volume,
linkable across time by anyone on the same segment. `pairing_open` is false except while an
invite is outstanding.

With `transport_mode = session`, the current authorized epoch key signs the packet and its
digest MUST match a currently valid committed credential. An expired daemon instead emits
`transport_mode = rekey`, signed by its latest authorized epoch key even though that
authorization is expired. A receiver verifies the signature against the retained
authorization but treats the source address only as a hint for the §4.6 rekey plane; it
MUST NOT open an ordinary connection or revive the expired credential. The daemon retains only
the latest epoch private key after expiry, solely for this advertisement, and MUST erase it as
soon as a replacement authorization activates, on applying its own revocation, or on leaving the
session (§9) — whichever comes first. A revoked device therefore stops advertising rather than
continuing to publish a signed `rekey` hint peers would have to evaluate and discard. Before
pairing either signature is informational.

Receiver rules for this unauthenticated input:

- Check cheap fields before any signature work: `magic`, `protocol`, size, then
  `session_id` (§3.3), then nonce, then signature.
- Reject a datagram whose `expires_at` is more than 60 s in the future or already past,
  using the local clock. Like certificate validity, this is a liveness-only wall-clock
  decision — never committed state.
- Keep a bounded nonce cache, at most 256 entries per source address with a 5-minute
  TTL, evicting oldest-first. A repeated `(source, nonce)` is dropped.
- Rate-limit inbound datagrams per source address; exceeding it drops silently rather
  than logging per packet.

Manual member endpoints and full invite bundles are mandatory fallbacks.
Discovery MUST NOT pair, alter membership, import Git objects, update refs, or write workspace files.

### 4.5 Pairing

1. An owner on any healthy member creates a one-use invite with a 15-minute TTL. At
   most 8 invites may be outstanding per session; `codecomm peer invite list|revoke`
   shows and cancels them.
2. The invite contains protocol and session IDs, a 128-bit secret from a CSPRNG, the
   inviter's identity fingerprint, the signed genesis digest, and endpoint hints.
3. The joiner pins the inviter identity from the invite; multicast cannot override it.
4. TLS verifies the inviter's long-lived identity against that pinned fingerprint and
   verifies the genesis binding.
5. The joiner proves the invite secret **without transmitting it**: it sends
   `HMAC-SHA-256(secret, "codecomm/v1/invite-proof" || 0x00 || transcript_hash)` where
   `transcript_hash` covers the TLS exporter value for this connection, both identity
   public keys, `session_id`, and the invite ID. Channel binding to the exporter makes a
   proof captured on one connection useless on another.
6. The inviter marks the invite consumed **durably, before sending its response**. Proof
   failures are rate-limited and audited; three failures void the invite.
7. The operator of each device compares and confirms a short authentication string: the
   first 5 decimal digit-groups of `SHA-256("codecomm/v1/sas-transcript" || 0x00 ||
   transcript_hash)`, rendered as 5 groups of 4 digits. Both sides display the same value;
   either side declining voids the invite. There is exactly one attempt, no retry.
8. The inviter proposes membership; admission starts only after quorum commit.
9. The joiner receives membership proof, roster, and first credential authorization,
   then opens direct peer connections.

Secrets MUST enter through TUI or no-echo stdin, never argv, environment, URL, log,
crash report, or shell history. If a short numeric code is offered instead of a full
invite, it MUST use an audited PAKE such as SPAKE2+, expire within five minutes, and
be rate-limited. Unverified TLS plus a six-digit password is prohibited.

### 4.6 Rotating transport credentials

Stable identity establishes membership. A quorum-authorized ephemeral key authenticates the
ordinary **session transport** carrying REST/SSE, Git artifacts, and normal Raft traffic.
Its V1 lifetime is fixed at **1800 seconds (30 minutes)**. A peer that applies revocation
closes every connection immediately; a stale partition that does not observe revocation
loses ordinary access when the credential expires, subject only to the ±120 s verifier skew.

An active member begins renewal 300 s before expiry. The replacement activates 120 s before
the old credential expires, allowing make-before-break connection replacement; the old
credential's own expiry is never extended. At most the current and immediately next epoch
may be authorized. CodeComm MUST NOT pre-authorize a stockpile of future keys or accept an
expired key for ordinary traffic. Impending expiry is visible with a countdown (§9).

The rotation procedure:

1. The member generates a new ephemeral key.
2. Its long-lived identity signs the binding of that public key to `session_id`,
   `device_id`, and its next epoch number, under `codecomm/v1/credential-binding`.
3. Any voter forwards the request to the leader.
4. **The leader assigns validity; the requester never states it.** Raft commits an
   authorization object containing every field a peer needs to verify use of that key
   without contacting anyone:

   | Field | Meaning |
   |---|---|
   | `subject_device_id` | The device this authorizes |
   | `epoch_public_key` | The full Ed25519 public key, not only its digest |
   | `key_digest` | SHA-256 of `epoch_public_key`, the value advertised in discovery (§4.4) |
   | `epoch` | The subject's epoch number, per device |
   | `role` | Taken from committed membership, not from the request |
   | `issued_at` | Leader's clock when the authorization is proposed |
   | `not_before`, `validity` | Activation time and fixed 1800 s lifetime |
   | `binding_signature` | The requester's identity signature over `(epoch_public_key, session_id, device_id, epoch)` under `codecomm/v1/credential-binding` |

   Carrying `epoch_public_key` rather than only its digest is what makes discovery
   verifiable: a receiver resolves `advertising_key_digest` to this committed object and
   already holds the key needed to check the datagram signature. Every reducer clamps the
   object against committed state alone, reading no local clock: `epoch` MUST be exactly
   the subject's current epoch plus one; `validity` MUST equal
   `credential_epoch_seconds`; for a successor authorization, `issued_at` MUST be no
   earlier than
   `prior.not_before + prior.validity - credential_renewal_lead_seconds`;
   `not_before` MUST equal `issued_at` for the first authorization and otherwise
   `max(issued_at, prior.not_before + prior.validity - credential_overlap_seconds)`;
   `key_digest` MUST equal SHA-256 of `epoch_public_key` and MUST NOT match any prior
   authorization for that device; `binding_signature` MUST verify against the subject's
   enrolled identity key; and `role` MUST equal current committed membership. Failing any
   clamp is a deterministic rejection on every replica. `issued_at` is a committed leader
   attestation used only in that formula and for display; no reducer reads a wall clock.
5. The member presents a self-signed TLS 1.3 certificate whose profile is fixed: subject
   public key is `epoch_public_key`; the subject CN and a SAN URI carry
   `codecomm:<session_id>/<device_id>`; `notBefore`/`notAfter` mirror `not_before` and
   `not_before + validity`; and one critical CodeComm extension carries
   `(session_id, device_id, epoch, authorization chain_index)`. No CA, no chain, no other
   extension is honored.
6. A peer accepts the certificate only after it has applied the authorization's
   `chain_index`, and after confirming: active committed membership for
   `subject_device_id`, the role it expects, `key_digest` matching the presented key, and
   the certificate fields agreeing with the committed object. Expiry is checked against the
   verifier's local clock with a **±120 s skew allowance**, applied only at connection
   setup; it is a liveness decision, never committed state, so no reducer depends on it
   (§6.3). A peer that has not yet applied the authorizing index MUST refuse the connection
   and retry rather than accept on faith.

`credential_epoch` is **per device**, not session-global. There is no leader certificate or
shared CA key. Before rollover, establish replacement control, Raft, and Git connections,
then drain the old ones; every connection has an absolute lifetime ending at its
certificate's `notAfter`. Never reuse keys.

**Cold-start rekey plane.** Expiry removes session-transport authority, not enrolled
membership. To avoid an all-devices-asleep deadlock, every daemon exposes a second TLS 1.3
mTLS mode on the same listener under the dedicated ALPN `codecomm-rekey/1`. It authenticates
the committed long-lived device identities rather than epoch keys:

- Each side presents a self-signed identity certificate whose SPKI contains the enrolled
  Ed25519 key from which `device_id` is derived (§4.1), and whose critical extension binds
  `session_id`, `recovery_generation`, `device_id`, and the rekey ALPN. Verification pins
  that exact key to locally committed membership and rejects a locally revoked member, a
  different session or generation, Web PKI roots, and every other ALPN. X.509 time validity
  grants no authority on this ALPN; freshness comes from the proof below.
- Each side then proves freshness by signing
  `(nonce, TLS exporter, session_id, recovery_generation, device_id)` under
  `codecomm/v1/rekey-handshake`. Nonces are 128-bit CSPRNG values, single-use, and
  rate-limited per source and claimed device. Possession of an expired epoch key alone is
  insufficient.
- Any active member may submit its next credential binding and receive an
  `authorized` result carrying **exactly two values**: the committed authorization
  `chain_index` and the leader's `not_before`. Both are values the requester needs to build the
  §4.6 step-5 certificate for its own key, and neither reveals committed content; without them a
  nonvoter could not construct a usable certificate at all, since it receives no Raft traffic and
  no event endpoint here. Every other outcome is the opaque `pending` or `refused`. Voters may
  additionally carry the embedded Raft library's election and replication traffic needed to elect a
  leader and commit `credential.authorized`. While quorum depends on any rekey connection, the
  leader MUST queue every new proposal except `credential.authorized`.
- **Which "voter" this means.** Connection admission checks only applied application membership:
  an active member is admitted and a revoked member is refused. The target voter set does **not**
  gate consensus traffic. Election and replication eligibility come only from the receiver's live
  Raft configuration: an active target-demoted device continues voting until `RemoveServer`
  commits, while a target-promoted device does not carry consensus traffic until `AddVoter`
  commits. Otherwise a target/configuration disagreement could reject a voter the live quorum
  still requires and deadlock cold-start rekey. A revoked device remains refused even if the live
  configuration still names it; security wins over availability, and if that removes quorum the
  session follows the stalled-reconciliation/§3.1 path.
- **No committed data before a leader exists.** The rule is **directional**: it constrains what
  flows *to* a peer, not what a peer may submit. Pre-election, a peer may send its own credential
  binding and receive a status — that is the plane's entire purpose and it discloses nothing,
  since the requester authored the payload. Pre-election that status can only ever be `pending`
  or `refused`, both opaque, because `authorized` requires a commit and a commit requires a
  leader. What a peer MUST NOT *receive* pre-election is any committed state:
  - **Pre-election** inbound traffic is confined to identity handshakes, the vote exchange
    (`RequestVote` and its reply, carrying only term, candidate ID, and last-log index/term),
    and that opaque status. It MUST carry **no committed log entries, no snapshot bytes, and no
    committed event payloads**. A device that never gets past this stage learns only that a
    session exists and how far its peers' logs reach.
  - **Post-election** replication — `AppendEntries` with entries, and `InstallSnapshot` — is
    sent **only by the elected leader**, and only to devices configured **as voters** in the
    leader's committed Raft configuration whose subject is also active in the leader's applied membership. A
    follower MUST NOT serve log entries or snapshots to a peer on this plane; the sole
    direction data flows is leader→follower.

  This closes the case where a stale voter holding post-revocation entries replays them to the
  revoked device: that peer is not the leader, and a non-leader sends no entries. A revoked
  device admitted by a stale peer can still trade votes with it, which reveals nothing beyond
  log extents, and cannot be brought current except by an elected leader. **One residual window
  is real and stated rather than papered over:** log completeness guarantees an elected leader
  *holds* the revocation entry, but the gate above is the leader's *applied* membership, and a
  leader starts replicating on election before it has applied its backlog. A leader MUST
  therefore apply through its committed membership index before replicating to any peer on this
  plane, which is the same catch-up it already owes before forwarding `credential.authorized`.
- The ALPN exposes no ordinary REST/SSE, event or snapshot *endpoint*, Git/bootstrap,
  presence, workspace, artifact transfer, MCP, agent, membership, policy, or generic
  Raft-proposal surface. A nonvoter never receives Raft traffic on it. Dispatch is a closed
  message enum, not a path supplied by the caller.
- **The library's internal snapshot transfer is part of that enum.** A voter that slept long
  enough for its peers to compact past its last index cannot be caught up by
  `AppendEntries` alone, so a rekey-plane election can leave a leader that must run
  `InstallSnapshot` before it can commit anything — including the first
  `credential.authorized`. Excluding it would deadlock exactly the cold start this plane
  exists to solve. It is therefore carried, under the post-election leader-only rule above: it
  is the internal consensus snapshot, distinct from the §5.3 logical snapshot *endpoint*,
  which stays unreachable here. §12.2 tests it directly, on a cluster whose logs have actually
  been compacted rather than one that merely could be.
- **What the restriction does and does not buy.** It bounds *write authority* and *API
  surface*: the only state a peer can cause to change is one `credential.authorized`. For a
  device that is still an **active** member, it does **not** make history confidential — an
  elected leader will bring it current, and those entries are the events: task content,
  activity, rationale, control-file diffs. That is not an escalation, since §2.1 gives every
  member the full event stream anyway. For a **revoked** device the leader-only rule above is
  what withholds history, and it holds as soon as any legitimately elected leader has applied
  the revocation. The properties the plane preserves are therefore: no write authority beyond
  one credential, no read surface beyond what current membership entitles the peer to, and no
  replication at all from a non-leader.
- Admission and authorization are separately gated, because on cold start no leader exists
  yet and the election is the thing being bootstrapped — a rule requiring a leader before
  anyone may speak would never terminate. Two distinct checks:
  - **At handshake, pre-election:** each side admits the peer against its **own latest
    applied** membership, failing closed on any device it has already seen revoked and on a
    mismatched `session_id` or `recovery_generation`. No leader is consulted. Consensus messages
    are separately accepted only when the peer is a voter in the receiver's live Raft
    configuration. This is deliberately the weaker check: a revoked device can still be admitted
    by a peer that has not yet applied its revocation. Because pre-election traffic carries no
    entries, that admission discloses nothing.
  - **Before proposing or forwarding `credential.authorized`:** the forwarding voter MUST
    have caught up to the elected leader's committed membership index and MUST confirm the
    subject is active there. This is the authoritative check, and it is what the 30-minute
    bound rests on.

  A revoked device therefore may complete a handshake and exchange votes with a stale peer, but
  it receives no log entries or snapshot from a non-leader, and obtaining a fresh credential
  requires a voter majority whose leader-confirmed membership still lists it as active. No
  quorum means no renewal, and no stale minority can authorize an epoch.
- Election participation is gated without changing consensus arithmetic. A participant refuses to
  *establish or keep* a rekey connection to a device its applied membership shows as revoked. For
  an active peer, it passes election or replication messages only when the receiver's live Raft
  configuration grants that peer voter status. A live-config nonvoter is still admitted — the
  plane is its only renewal path — but its connection carries only its credential request.

  **Quorum is whatever the committed Raft configuration says, and nothing else.** A daemon MUST
  NOT alter vote-granting logic, quorum size, or majority counting based on applied application
  membership. Doing so would let two replicas halted at different indices (§5.5) compute
  different quorums for the same term — a split-brain of the safety argument itself, and far
  worse than the stale-admission case it would be trying to fix. Application membership gates
  *who a peer will talk to*; the library's committed configuration decides *what constitutes a
  majority*. The two are deliberately different mechanisms, and where they disagree, the
  configuration wins for consensus and membership wins for access.

When a voter majority wakes with every session credential expired, its members discover
`rekey` hints, mutually authenticate, elect/catch up through the restricted transport,
commit fresh credentials one device at a time, reconnect normal Raft over epoch mTLS, and
close the rekey connections. A one-voter cluster performs the same authorization through
its local quorum. Nonvoters renew through a fresh voter afterward. This is ordinary
reconnection, not §3.1 quorum recovery, and requires no operator confirmation.

**Version-halted voters.** A voter halted per §5.5 cannot campaign, so a majority halted on
the same version boundary cannot elect a leader, and with every credential also expired the
rekey plane would have no way to commit `credential.authorized`. Two rules keep that from
bricking the session. First, a halted voter MAY still grant rekey-plane election **votes** and
keep **accepting** `AppendEntries` — it receives entries, it never serves them, per the
leader-only rule above — exactly as on the ordinary plane, so a single up-to-date voter that can satisfy
every entry may become leader with halted voters counting toward its quorum — which follows
directly from quorum deriving from the committed configuration rather than from each replica's
applied membership, since a halted replica's membership is by definition stale. Second, if no
reachable voter can apply the log far enough to lead — a genuinely halted majority — the
session is **not** self-recoverable: it surfaces the §5.5 version blocker naming the release
required, and the remedy is upgrading a voter, not §3.1 recovery, since committed state is
intact and nothing has diverged. Recovery under §3.1 MUST NOT be offered for this case, because
it would discard entries that are merely unapplied rather than lost.

Pairing and rekey are the only pre-session-authentication network surfaces. All ordinary
post-pairing traffic uses epoch TLS 1.3 mTLS. Plain HTTP is limited to owner-restricted local
IPC or explicit development-only loopback wiring.

## 5. Control Protocol and Event Model

### 5.1 Transport

The ordinary application protocol is versioned REST over HTTP/2 HTTPS plus SSE. Strong
proposals may enter through any member; followers forward only the proposal to the leader.
Raft uses its maintained framed transport in a dedicated epoch-mTLS channel, with only the
§4.6 restricted rekey fallback. The Raft stream is not an agent-facing API.

| Method/path | Purpose |
|---|---|
| `GET /v1/session` | Capabilities/session metadata |
| `GET /v1/peers` | Committed roster and endpoint hints |
| `GET /v1/consensus/status` | Local term, leader, quorum, applied index |
| `GET /v1/consensus/catchup-proof/{checkpoint_event_id}` | Staging replica's authenticated durable application proof used only for §3 promotion |
| `POST /v1/pairing/{request,confirm}` | Pairing |
| `POST /v1/credentials/renew` | Propose epoch authorization on ordinary mTLS while current, or as the sole application operation inside the `codecomm-rekey/1` closed dispatcher after §4.6 identity proof |
| `POST /v1/events` | Propose idempotent event |
| `GET /v1/events?after=N` | Committed catch-up; `N` is a `chain_index` and the response is the §5.3 batch object |
| `GET /v1/events/stream` | SSE watermark/event notification |
| `GET /v1/snapshots/latest` | Signed logical snapshot |
| `POST /v1/agent-sessions/presence` | Ephemeral device-bound presence |
| `POST /v1/acks` | Durable applied watermark |
| `POST/GET /v1/bootstrap/git-bundles[/id]` | Verified bootstrap artifact |
| `GET/POST /v1/git/upload-pack` | Read-only Git protocol v2 for allowlisted CodeComm refs; never `receive-pack` |
| `PUT/GET /v1/git/artifacts/{sha256}` | Resumable bounded publication/draft bundle staging and retrieval |
| `GET /v1/git/refs` | Signed source-owned draft/publication ref advertisement and local availability |
| `GET /v1/conflicts` | Committed merge-conflict records |

The catch-up-proof endpoint accepts only the current leader authenticated on ordinary transport,
only while the receiver is a staging nonvoter, and only for a committed checkpoint it has applied;
it returns the fixed §3 tuple, not a caller-selected status query.

All messages use explicit schema/capability versions, bounded pagination and sizes,
structured problem responses, and idempotency keys for mutations. Unknown required
capabilities fail closed. Git bundles use `application/octet-stream` plus digest/size/expiry.
Every Git endpoint is bound to the selected session repository; callers cannot provide a path,
run arbitrary Git, write user refs, or invoke `receive-pack`.
Canonical event batches MAY use negotiated binary encoding and gzip/zstd, with compressed and
expanded limits enforced before allocation.

### 5.2 Events

An origin signs a canonical domain proposal (§4.1) with its enrolled device identity key,
never a rotating transport key, so history stays verifiable across credential epochs. The
leader prevalidates and proposes the proposal **unchanged** to Raft. Raft commitment plus
deterministic state-machine validation, not the signature alone, produce an accepted event.

Ordering metadata is **not signed by the leader and not part of the proposal**. The
embedded Raft libraries of §11 seal the payload and assign term and index internally,
exposing no index-reservation API, so the leader cannot know an entry's index before
commitment. Every replica records the observed `(term, log_index)` as **unsigned local
provenance** when it applies the entry; ordering integrity comes from Raft itself plus
the chain below.

```json
{
  "schema_version": 1,
  "min_apply_version": 1,
  "event_id": "uuidv7",
  "session_id": "uuid",
  "workspace_id": "uuid",
  "origin": {
    "device_id": "cc1<64 hex>",
    "actor_type": "agent",
    "agent_profile_id": null,
    "agent_session_id": "uuidv7",
    "origin_sequence": 42
  },
  "created_at": "RFC3339Nano",
  "hlc": "opaque bounded string",
  "kind": "task.updated",
  "entity_id": "uuid | device_id | session_id | null (§4.2)",
  "expected_entity_version": 7,
  "rationale_summary": "bounded visible rationale",
  "capture_level": "agent_reported",
  "actions": [],
  "payload": {},
  "redaction": {"policy": "default", "fields_removed": []},
  "origin_signature": "base64url"
}
```

That object, minus `origin_signature`, is exactly what the origin signs under the
`codecomm/v1/event-origin` label, and exactly what is replicated; a peer can verify
authorship without any consensus context.

On applying an accepted event, each replica additionally stores local provenance,
which is **never signed, never replicated, and never part of `signed_bytes`**:

```json
{
  "term": 17,
  "log_index": 1048,
  "leader_device_id": "cc1<hex>",
  "applied_at": "RFC3339Nano",
  "chain_index": 903,
  "chain_hash": "base64url"
}
```

`log_index` defines order. `created_at` and `hlc` are attestations of what the origin
claimed, not trusted time: they aid display and diagnosis, and a reducer MUST NOT derive
any decision from them (§6.3).

Agent-originated events require the bound agent session; `human` and `daemon` events use
null. `human` means a person acting through the local TUI, CLI, or IPC, `daemon` the
daemon acting on its own initiative; both attribute solely to `device_id` (§2.1).

Actions MAY record `file.read/edit`, `command.run`, `tool.call`, `test.run`, `decision.recorded`,
and `artifact.created`, with relative paths, digests, redacted summaries, status, timing, task,
and actor. Raw terminal streams, environment, secrets, private reasoning, and sensitive
arguments are excluded by default.

#### 5.2.1 Event chain and checkpoints

The chain is defined over **accepted events only**, in accepted order, and is derived
independently by every replica at apply time. It is never computed by the leader
before commitment and never transmitted inside an event:

```text
chain_seed(gen 0) = SHA-256("codecomm/v1/chain" || 0x00 || digest(genesis_0))
chain_seed(gen k)  = SHA-256("codecomm/v1/chain" || 0x00 || digest(genesis_k)
                      || u64be(k) || final_chain_hash(gen k-1))
chain_n            = SHA-256("codecomm/v1/chain" || 0x00 || chain_{n-1}
                      || JCS(accepted_event_n including origin_signature))
chain_index        = n, counting accepted events from 1 across all generations
```

`digest(genesis_k)` is the digest of generation k's own genesis record — the successor record for
k>0 — and `final_chain_hash(gen k-1)` is the last verified hash carried forward by recovery.
Seeding from a genesis digest rather than `session_id` is what lets a successor generation (§3.1),
whose `session_id` differs, continue its predecessor's chain: `chain_index` never restarts and the
lineage verifies end to end.

Rejected commands and Raft configuration entries consume Raft indices (§5.3) but are
**not** chain members, so `chain_index` advances densely while `log_index` has gaps. A
nonvoter that receives only accepted events in bounded signed batches (§5.3) can
therefore reproduce the chain exactly.

Chain continuity is a validation step: on applying an accepted event, a replica computes
`chain_n` from its own `chain_{n-1}` and stores it. On importing a batch or snapshot it
MUST recompute the chain across every event it receives and reject the transfer if the
result disagrees with the sender's stated digest.

Periodically — every `checkpoint_events` accepted events or `checkpoint_interval`,
whichever comes first, both committed genesis policy — the current leader proposes a
`consensus.checkpoint` event **after** applying, carrying `(term, applied_log_index,
chain_index, chain_hash, projection_digest, digest_version)` signed under
`codecomm/v1/checkpoint` with its identity key. Proposing after apply means the leader
knows every value it signs, so this is expressible on the §11 library APIs. A checkpoint
is an ordinary committed event: it is itself a chain member, every replica validates it
against its own chain state, and a checkpoint that disagrees is a structured rejection
and an audited divergence alarm (§5.3).

Verifying an exported range needs the events plus the next checkpoint at or after them:
recompute the chain across the range, confirm each `origin_signature`, and confirm the
checkpoint signature and the chain hash it commits to. A single event in isolation
proves authorship but not position; snapshots (§5.3) carry a chain digest for the same
purpose.

### 5.3 Commit and replication

1. Origin submits unique ID, origin sequence, and expected entity version.
2. Receiver performs bounded structural checks, enforces its local request-rate limits
   (§10), and forwards if not leader.
3. Leader prevalidates the complete command, then proposes the **byte-identical** signed
   proposal to Raft, adding nothing to it.
4. Raft durably replicates the command to a voter majority.
5. Every state machine applies it in index order and deterministically rechecks membership,
   signatures and their domain labels, actor binding, authorization, schema and capability
   support, sequence, transition, expected version, admission depth limits, and chain
   continuity against prior committed state.
6. A valid command emits/stores the accepted event, extends the chain, and updates
   projections; an invalid or stale command stores the same structured rejection on every
   replica and does **not** extend the chain.
7. SQLite commits event/rejection, chain state, idempotency result, projection, and applied
   index in one transaction.
8. The caller receives the committed result; duplicate IDs return that result.

A leader MAY pre-reject an obviously stale command but MUST NOT treat prevalidation as the
authoritative state transition; two replicas that disagree about validity is a divergence,
not a tie for the leader to break.

Settled application nonvoters and catch-up clients use the batch contract below, durable cursors,
and SSE high-watermarks. A target temporarily placed in the live Raft configuration by
`AddNonvoter` is the sole exception: it receives ordinary-plane Raft replication until promoted or
removed so it can produce §3's target-applied checkpoint proof.

**Catch-up batch contract.** `GET /v1/events?after=N` takes `N` as a **`chain_index`**, never a
`log_index`: the chain is dense over accepted events (§5.2.1) while `log_index` gaps, so only
`chain_index` is a usable cursor. The response is a batch object, canonically encoded per §4.1:

| Field | Meaning |
|---|---|
| `from_chain_index`, `to_chain_index` | Inclusive range actually served, which MAY be shorter than requested |
| `events[]` | Accepted events, in chain order, byte-identical to their signed form |
| `end_chain_hash` | The chain hash after the last included event |
| `enclosing_checkpoint` | The first committed `consensus.checkpoint` at or after `to_chain_index`, with its signature, when one exists |
| `server_device_id`, `server_applied_chain_index` | The serving member and how far it had applied |
| `batch_signature` | The serving member's identity signature over the batch under `codecomm/v1/batch` |

The **serving member signs the batch with its identity key** (not a transport key), which attests
only "I served these bytes" — it is not authority. Authority comes from each event's own
`origin_signature` plus the receiver recomputing the chain across the batch and matching
`end_chain_hash`, then verifying `enclosing_checkpoint` against committed membership. That is the
post-commit ordering proof: a batch cannot reorder, omit, or insert an event without breaking the
recomputed chain, and a served range is only trusted as *committed* once a checkpoint at or after
it verifies. A receiver MUST reject a batch that fails any of these checks and MUST NOT advance
its cursor.

Cursors are durable per `(peer, session)` and hold the last verified `chain_index` and
`chain_hash`. A cursor whose `chain_index` precedes the server's earliest retained event gets a
`cursor_too_old` problem response, and the receiver MUST fall back to a snapshot plus tail rather
than skipping the gap. Batches are bounded by §11.2's batch size.

Any up-to-date voter may serve a signed logical snapshot
containing schema version, term, applied `log_index`, `chain_index`, `chain_hash`, the most
recent committed checkpoint with its signature, and domain rows. The receiver verifies the
checkpoint signature against committed membership, imports transactionally, then replays
later committed events and recomputes the chain forward from the snapshot's `chain_hash`. A
snapshot whose stated chain state does not match its own rows is rejected.

Wire replication MUST NOT contain SQL, SQLite pages/WAL/SHM, DB patches, Session Extension
changesets, or driver logs. Transport encoding/compression never changes either signed
canonical form. Workspace files and Git artifacts are separate data planes.

### 5.4 Event kinds

This table is the complete V1 `kind` namespace and the authority for what may be committed at
`schema_version` 1; a kind absent from it is rejected deterministically by every replica
(§5.3). Entities and their fields are in §6.1.

`CAS` means the event MUST carry `expected_entity_version` and is rejected on mismatch. `Role`
is the minimum application role, checked against committed membership at apply time, never
against the proposer's claim. `Payload` names the fields beyond the §5.2 envelope; every
payload is a JSON object, bounded, with unknown fields rejected at `schema_version` 1.

`Actor` is the `actor_type` (§5.2) permitted to propose the kind. `agent` proposes for its own
bound session; `human` is an operator through the TUI or CLI; `daemon` is the local daemon acting
on its own initiative, and `daemon (leader)` marks a kind only the current leader's daemon proposes.

| Kind | Role | Actor | CAS | Payload |
|---|---|---|---|---|
| `task.created` | editor | agent, human | no | `title`, `body?`, `priority`, `labels?`, `blocked_by?` |
| `task.updated` | editor | agent, human | yes | any of `title`, `body`, `priority`, `labels`, `blocked_by` |
| `task.state_changed` | editor | agent, human | yes | `to_state`, `reason?`; legal edges only, self-owned unless human (§6.3) |
| `task.claimed` | editor | agent | yes | none; actor from binding; an `intended_device_id`, when set, MUST equal the actor's device and is cleared by the successful claim |
| `task.released` | editor | agent, human, daemon | yes | `release_reason` ∈ {`voluntary`, `session_ended`, `forced`}; `voluntary` is agent, `session_ended` daemon, `forced` human |
| `task.reassigned` | owner | human | yes | active `to_device_id`; releases the current holder, persists that device as the one-shot intended claimant, and leaves the task `ready` (§6.4) |
| `task.cancelled` | owner | human | yes | any non-terminal task to `cancelled` |
| `workspace.conflict.detected` | editor | daemon | no | `publication_id`, `merge_base`, `canonical_commit`, `candidate_commit`, sorted `paths[]`; `entity_id` is the deterministic `conflict_id` (§8.3) |
| `workspace.conflict.resolved` | editor | agent, human | yes | `resolution_publication_id`; it must be applied and list this conflict as staging-verified (§8.3) |
| `publication.proposed` | editor | agent | no | `task_id?`, `base_commit`, `commit_oid`, `parent_oids[]`, `tree_oid`, sorted `paths[]`, `artifact_digest`, `resolves_conflict_ids[]?`, current-voter-set staging receipts (§7.2) |
| `publication.reviewed` | editor | agent, human | yes | `verdict`; never the author's own session |
| `publication.applied` | editor | agent, human | yes | `expected_canonical_ref_version`, current-voter-set staging receipts; atomically advances the replicated canonical ref (§7.2) |
| `publication.rejected` | editor | agent, human | yes | `reason?` |
| `plan.revision_proposed` | editor | agent, human | no | `title`, `body`, `task_ids?`, `supersedes?` |
| `plan.current_selected` | owner | human | yes | `plan_revision_id`; CAS on the current pointer |
| `memory.appended` | editor | agent, human | no | `scope`, `task_id?`, `key`, `body`, `supersedes?` |
| `lease.acquired` | editor | agent | no | `scope`, `task_id?`, `path_globs?`, `ttl_seconds` within committed min/max |
| `lease.renewed` | editor | agent | yes | `ttl_seconds` within committed min/max |
| `lease.released` | editor | agent, human, daemon | yes | `release_reason` ∈ {`voluntary`, `session_ended`, `forced`, `expired`}; `expired` is proposed only by the current leader, `session_ended` by a daemon, `voluntary` by the holder, and `forced` by a human |
| `agent.session.started` | editor | agent | no | `client_kind`, `agent_profile_id?`, `working_root_digest` |
| `agent.session.state_changed` | editor | agent | yes | `to_state`; live states of §7.2 |
| `agent.session.ended` | editor | agent, daemon | no | `end_reason`; releases claims and leases (§6.4); expiry and daemon-loss reaping are daemon-proposed |
| `membership.device_admitted` | owner | human | yes | `device_id`, identity public key, `role`, `daemon_version` |
| `membership.version_reported` | any member | daemon | yes | `daemon_version`; actor may update only its own active device row and emits only when the value changes |
| `membership.role_changed` | owner | human | yes | `device_id`, `role` |
| `membership.device_revoked` | owner | human | yes | `device_id`, `reason?`, the resulting `voter_set[]` excluding it, and `expected_voter_set_version`; CAS on **both** that and the envelope's device version — the one kind mutating two entities (§3) |
| `membership.voter_set_changed` | owner | human | yes | `voter_set[]`, the full resulting set; `entity_id` is `session_id` and CAS is on `voter_set_version`; count 1/3/5 at rest; reconciled to Raft by the leader (§3) |
| `policy.changed` | owner | human | yes | changed mutable genesis-policy keys and values (§4.2); V1 rejects epoch/overlap/renewal-lead changes |
| `credential.authorized` | any member | daemon (leader) | no | `subject_device_id`, `epoch_public_key`, `key_digest`, `epoch`, authorized `role`, `issued_at`, `not_before`, `validity`, and the requester's identity signature over its binding (§4.6) |
| `control_file.change_proposed` | editor | agent, human | no | path, digest, bounded diff (§8.4) |
| `consensus.checkpoint` | — | daemon (leader) | no | `term`, `applied_log_index`, `chain_index`, `chain_hash`, `projection_digest`, `digest_version`, and `leader_signature` over those fields under `codecomm/v1/checkpoint` (§5.2.1, §5.6) |
| `audit.recorded` | — | daemon | no | `action`, `subject`, `outcome` |

The `Actor` column is authoritative for who may propose each kind; a proposal from any other
`actor_type` is rejected deterministically. Operator overrides (`task.reassigned`, `task.cancelled`,
`plan.current_selected`, `policy.changed`, owner-controlled membership changes, and the `forced` case of
`task.released` / `lease.released`) are `human` only, which keeps them off the MCP surface (§6.4,
§7.1). The daemon reaps a dead or expired session by proposing that session's `agent.session.ended`
and the `session_ended` releases that follow; the leader's daemon proposes `credential.authorized`
and `consensus.checkpoint`. `membership.version_reported` is the sole self-service membership
mutation: actor binding fixes its device and it cannot alter role, status, identity, or voter set.
`credential.authorized` has no minimum application role because every
member must rotate keys (§4.6); its clamp instead requires the authorized
`role` to equal committed membership.

Two enums are fixed at `schema_version` 1:

- `actor_type`: `agent`, `human`, `daemon`.
- `capture_level`: `agent_reported` (the agent's own account), `hook_observed` (captured by a
  consented local hook, §7.3), `daemon_observed` (the daemon saw it directly). It records *how*
  an action was learned and never implies the report is complete (§16 risk 8).

`expected_entity_version` starts at 1 on create. Create-kind events carry no
`expected_entity_version`; uniqueness of the new `entity_id` prevents a duplicate, and a
replayed create returns the original committed result by `event_id` (§5.3).

### 5.5 Version skew and frozen reducers

Devices upgrade independently, so two daemon versions will share a cluster. Three rules
prevent silent divergence.

**Frozen reducers.** The outcome of applying a given `(kind, schema_version)` MUST NOT
change once released. Fixing or extending behavior requires a **new kind** or a new
`schema_version`, never a redefinition of an existing pair. This is on the non-mergeable
list of §12.1.

**Halt rather than diverge.** Each committed event carries `min_apply_version` in its
envelope (§5.2), the lowest daemon version that can apply it deterministically. A
replica that does not satisfy an entry's `min_apply_version`, or that meets an unknown
`kind`, unknown required payload field, or any input it cannot apply deterministically,
MUST:

- stop applying at that index and **not** advance its applied index;
- never substitute a local rejection for an entry another replica may have accepted —
  a rejection is a committed outcome, not a fallback;
- continue serving reads of everything already applied, and remain a **non-campaigning
  follower**: it keeps accepting `AppendEntries` so it does not stall the leader's commit
  index, but MUST NOT start or win an election while halted — a halted voter that became
  leader could not apply, so it MUST decline `RequestVote` candidacy for itself and
  surrender leadership if it holds it. It still votes for other candidates, so a halted
  voter does not by itself deny quorum;
- surface a distinct blocker state naming the version required, in the TUI, `status`,
  and readiness reporting (§11);
- resume from the same index automatically once upgraded, with no manual repair.

§5.1's fail-closed capability negotiation covers *request* time only; the entry here is
already committed.

**Supported skew.** A cluster supports at most one release step: N and N-1 may
interoperate. Committed genesis policy carries a cluster-level `cluster_min_version` (§4.2), distinct
from any single event's `min_apply_version`; a daemon MUST refuse to join a cluster whose
`cluster_min_version` it cannot satisfy rather than joining and halting on the first entry.
`cluster_min_version` changes only by a committed `policy.changed` event (§5.4), which an owner
MAY propose once every active committed member's persisted `daemon_version` is at least the new
value. Admission records the initial value; after an upgrade or downgrade, the daemon MUST commit
`membership.version_reported` before accepting agent work or proposing any other mutation.
Presence is deliberately irrelevant: every reducer evaluates the raise from the same `devices`
rows. A binary below the already committed minimum refuses to start the session and therefore
cannot report a downgrade. Raising the minimum is explicit and audited, never a side effect of an
upgrade.

Each event kind's authoritative minimum is the `min_apply_version` its emitter stamps, fixed per
`(kind, schema_version)` by the frozen-reducer rule above: the same pair always carries the same
value, so two emitters cannot disagree about what a kind requires.
Emitting a kind or field some committed member cannot apply is therefore a release-gate
question, covered by the compatibility coverage §12.1 requires.

### 5.6 Projection digest

The digest is how replicas prove they agree. It is computed over projections only —
never over SQLite pages, free lists, or rowids, which are not deterministic across
vacuum and reuse history.

```text
row_bytes    = JCS(row as an object with its declared field order)
table_digest = SHA-256 over row_bytes of every row, ordered by primary key ascending
digest       = SHA-256("codecomm/v1/projection" || 0x00
                      || u64be(digest_version) || u64be(schema_version)
                      || each 32-byte table_digest in the fixed order below)
```

`u64be` is the 8-byte big-endian integer encoding of §4.1; each `table_digest` is a fixed
32 bytes, so the preimage is unambiguous without further separators.

Every table in §6.2 is classified. Covered, in this exact order: `tasks`,
`plan_revisions`, `plan_current`, `memory_records`, `leases`, `devices`, `voter_set`,
`agent_sessions`, `canonical_refs`, `credential_authorizations`, `publications`,
`control_file_proposals`, and `merge_conflicts` — all committed replicated domain state whose
divergence must be caught.
`voter_set` is the committed target of §3, never the library's live configuration — that lives in
the Raft stable store under `consensus/`, is not a projection at all, and so is outside the digest
by construction; two replicas mid-reconciliation legitimately differ there while agreeing on this
table. The
proposal is covered; the local approval decision is not (§8.4). Excluded, with reason: `events`
and `chain_checkpoints` (the chain covers them,
§5.2.1); `event_provenance`, `consensus_state`, `replication_cursors`, `peer_acks`,
`lease_deadlines`, `git_artifacts`, `outbox`, and `idempotency_keys` (local or
timing-dependent, legitimately differ between
replicas); `activity` and `audit_events` (append-only local projections of events already covered by the
chain, so they need not match byte-for-byte); `schema_migrations` and `control_file_approvals`
(local by design,
§8.4 — replicating an approval would defeat per-device consent). Every field of a covered table is
included in its declared order (§6.1); no covered table has a local-only column. Adding a
covered table, removing one, or changing the fixed order requires a new `digest_version`,
independent of `schema_version` — **once released**, exactly as §5.5 scopes frozen reducers.
Composing the initial V1 set is not a bump: `digest_version` 1 is the first released value, so
edits to this list before V1 ships leave it at 1.

Two replicas are **comparable** when they share `digest_version` and `schema_version`.
Comparable replicas at the same `chain_index` MUST produce an identical digest; that is
the §12.3 assertion. Replicas differing in either
version MUST NOT be compared.

Each `consensus.checkpoint` (§5.2.1) carries the leader's digest at that `chain_index`;
every comparable replica compares its own on apply, and a mismatch is a fail-closed
condition: stop applying, preserve evidence, raise an alarm, and require explicit
operator recovery, as for DB corruption (§9). A replica MUST NOT attempt to self-repair
by copying the leader's state.

## 6. Persistence and Coordination Semantics

### 6.1 Domain model

Every entity below is replicated as signed events (§5.2) and projected locally. Each
carries `entity_version`, a monotonic counter starting at 1 on create and incremented by
each accepted mutation; mutating events carry `expected_entity_version` and are rejected
deterministically on mismatch (§5.3). Bounds are normative and validated by reducers on
every replica. All strings are UTF-8 with bounds in bytes.

**Task** — the unit of claimable work.

| Field | Type | Notes |
|---|---|---|
| `task_id` | UUIDv7 | Origin-generated |
| `title` | string, 1-200 | Required; single line, control characters rejected |
| `body` | string, ≤8192 | Optional; untrusted display text (§7.3) |
| `state` | enum | §6.3 state machine |
| `priority` | integer 0-3 | 0 highest; ordering hint only, never an authorization |
| `blocked_by` | [`task_id`], ≤16 | Hard prerequisites; cycles rejected |
| `labels` | [string ≤32], ≤16 | Free-form, deduplicated, sorted on apply |
| `owner_device_id` | `device_id`? | Set on claim, cleared on release |
| `owner_agent_session_id` | `agent_session_id`? | Set with `owner_device_id`; both null or both set |
| `intended_device_id` | `device_id`? | One-shot reassignment target; only that device may claim, and a successful claim clears it |
| `entity_version` | integer ≥1 | Compare-and-set token |
| `created_at`, `updated_at` | RFC 3339 | Display only; never read by a reducer |

`blocks` is **derived**, never stored: it is the reverse index of `blocked_by`. A task is
*actionable*, also derived, when `state = ready`, no unresolved merge conflict references it,
and every `blocked_by` task is `done`; it is claimable by a given device only when
`intended_device_id` is null or names that device. Dependency edges MUST form a directed acyclic graph; a
reducer that would introduce a cycle rejects the event, identically on every replica.
`blocked_by` MUST reference tasks in the same session and MUST NOT reference the task
itself.

**Plan revision** — an immutable proposal for how work is organized.

| Field | Type | Notes |
|---|---|---|
| `plan_revision_id` | UUIDv7 | Immutable once accepted |
| `supersedes` | `plan_revision_id`? | The revision this was drafted against |
| `title` | string, 1-200 | Required |
| `body` | string, ≤65536 | Markdown; untrusted display text |
| `task_ids` | [`task_id`], ≤512 | Tasks this revision organizes; membership only, no ordering authority |
| `proposed_by_device_id` | `device_id` | Committed, not self-asserted |
| `created_at` | RFC 3339 | Display only |

Revisions are append-only and never mutated, so they carry no `entity_version`. Exactly
one revision per session is *current*, named by a separate committed pointer holding
`(plan_revision_id, entity_version)`; selecting a new current revision is a
compare-and-set against that pointer.

**Memory record** — durable shared context.

| Field | Type | Notes |
|---|---|---|
| `memory_id` | UUIDv7 | Immutable |
| `scope` | enum: `session`, `task` | Determines whether `task_id` is required |
| `task_id` | `task_id`? | Required when `scope = task`, else null |
| `key` | string, 1-128 | Namespacing hint; not unique |
| `body` | string, ≤16384 | Untrusted display text |
| `supersedes` | `memory_id`? | Forms a chain, never a cycle |
| `created_at` | RFC 3339 | Display only |

Append-only: a correction is a new record superseding the old. A record MUST NOT
supersede one that is already superseded, keeping supersession a chain, not a tree.

**Lease** — an advisory, expiring reservation.

| Field | Type | Notes |
|---|---|---|
| `lease_id` | UUIDv7 | Immutable |
| `holder_device_id` | `device_id` | From the committed actor binding |
| `holder_agent_session_id` | `agent_session_id` | Released when that session ends (§6.4) |
| `scope` | enum: `task`, `path` | |
| `task_id` | `task_id`? | Required when `scope = task` |
| `path_globs` | [string ≤512], ≤32 | Required when `scope = path`; workspace-relative, canonicalized, no traversal or absolute paths (§8.4) |
| `ttl_seconds` | integer | Requested lifetime within committed minimum/maximum; resets on accepted renewal |
| `entity_version` | integer ≥1 | |

Expiry is an ordinary CAS-protected `lease.released(expired)` event; the wall clock schedules its
proposal but never runs inside a reducer (§6.3). Leases are advisory and cannot stop another
process running as the same OS user from editing a path (§7.2).

**Activity record** — what an agent reports doing. Bounded, append-only, and projected
from events rather than separately mutable: `(kind, task_id?, actions[],
rationale_summary, capture_level, redaction)` as carried in the §5.2 envelope.
High-frequency presence is ephemeral and never durable (§7.2).

**Device** — a member, projected from `membership.*`.

| Field | Type | Notes |
|---|---|---|
| `device_id` | string | §4.1 |
| `role` | enum: `owner`, `editor` | Current committed role |
| `voter` | boolean | Derived view of membership in the `voter_set` target, kept for convenient per-device reads; the set is authoritative and CAS'd, this is not (§3) |
| `identity_public_key` | bytes | Ed25519; retained after revocation for verification (§4.2) |
| `daemon_version` | version | Last committed self-report; admission initializes it and §5.5 gates minimum-version changes on it |
| `status` | enum: `active`, `revoked` | Revoked keys are retained, not deleted |
| `entity_version` | integer ≥1 | |

**Agent session** — a running agent instance, projected from `agent.session.*`.

| Field | Type | Notes |
|---|---|---|
| `agent_session_id` | UUIDv7 | Never reused (§4.2) |
| `device_id` | `device_id` | Owning device |
| `client_kind` | enum: `codex`, `claude`, `other` | |
| `agent_profile_id` | string? | Optional stable persona |
| `state` | enum | Live states of §7.2 |
| `working_root_digest` | string | Digest of the working root at start |
| `entity_version` | integer ≥1 | |

**Canonical ref** — the replicated repository pointer, initialized to the verified bootstrap
commit. V1 has one row and never maps it directly to a user's branch.

| Field | Type | Notes |
|---|---|---|
| `ref_name` | string | Fixed `refs/codecomm/canonical`; row key, never a user ref |
| `commit_oid` | algorithm-tagged Git OID | Commit selected by the latest applied publication |
| `entity_version` | integer ≥1 | Second CAS token carried by `publication.applied` (§7.2) |

**Merge conflict** — a committed record of an immutable Git merge result.

| Field | Type | Notes |
|---|---|---|
| `conflict_id` | string | Deterministic `ccf1` digest defined in §8.3 |
| `publication_id` | UUIDv7 | Candidate publication; determines task and author |
| `merge_base`, `canonical_commit`, `candidate_commit` | Git OIDs | Immutable conflict tuple |
| `paths` | [canonical path], ≤2048 | Sorted, unique conflicting paths |
| `status` | enum: `unresolved`, `resolved` | |
| `resolution_publication_id` | UUIDv7? | Applied merge publication containing both tips |
| `entity_version` | integer ≥1 | CAS token for resolution |

**Voter set** — the committed consensus target, projected from `membership.voter_set_changed` and
`membership.device_revoked`. One row per session, so `session_id` is both `entity_id` and primary
key (§4.2).

| Field | Type | Notes |
|---|---|---|
| `session_id` | string | §4.2; the sole row's key |
| `voter_device_ids` | array of string | The committed target, sorted ascending so the digest is order-independent of proposal order; length 1, 3, or 5 at rest (§3) |
| `voter_set_version` | integer ≥1 | CAS token; `membership.device_revoked` carries it as `expected_voter_set_version` (§3, §5.4) |

This entity is the target, never the Raft library's live configuration. That configuration lives
in the library's own stable store under `consensus/` (§6.2), is not a projection, and is not
digest-covered — two replicas mid-reconciliation legitimately hold different live configurations
while agreeing on this row (§3, §5.6).

Field order in each table above is the canonical order for the projection digest (§5.6). The
covered tables §5.6 lists that have no entity above — `credential_authorizations` and
`control_file_proposals` — take their declared order from the §6.2 DDL,
which §6.2 makes a phase-2 deliverable; that DDL is the canonical order for them.

### 6.2 Local state

```text
.codecomm/
  session.json       non-secret local metadata
  state.db           daemon-owned SQLite/WAL projections and events
  consensus/         production Raft stable store/snapshots for voters
  context.{json,md}  atomic generated read-only context
  inbox/             optional immutable write-then-rename submissions
  git/               resumable artifacts, quarantine, draft metadata
  conflicts/         local merge-resolution worktrees/snapshots
  logs/ run/ tmp/    redacted logs, IPC metadata, bootstrap staging
```

There is one `.codecomm/` per joined workspace, owned by that workspace's daemon (§3.2).
It is local-only and added to `.git/info/exclude` by default;
changing tracked `.gitignore` requires consent.

State that must outlive or span workspaces lives outside every workspace, in
platform-standard owner-only locations. Only `config.*` and `identity/` are shared by
session daemons; the registry belongs to the supervisor (§3.3):

```text
<per-user config>/codecomm/
  config.*                 device-wide typed configuration        (shared)
<per-user state>/codecomm/
  identity/                device identity reference; private key in OS store (shared)
  registry/                supervisor registry, one entry per joined workspace (§3.2)
  logs/                    supervisor logs
```

Long-lived private keys stay in the OS credential store, never in either tree. Only the owning
`codecommd` opens its `state.db` or `.codecomm/git` quarantine; CLI/TUI/MCP/hooks use local IPC.

| Table | Holds |
|---|---|
| `schema_migrations` | Applied migration numbers and checksums |
| `consensus_state` | Applied index, term, current `chain_index`/`chain_hash` |
| `events` | Accepted events exactly as signed (§5.2) |
| `event_provenance` | Unsigned local `(term, log_index, applied_at, chain_index, chain_hash)`, kept apart from `events` |
| `chain_checkpoints` | Committed checkpoints with leader signature and digest (§5.2.1) |
| `idempotency_keys` | Committed result per request key, retained per §11.2 |
| `devices` | Membership, role, enrolled identity keys including revoked and superseded ones (§4.2) |
| `voter_set` | The committed voter target and its `voter_set_version` CAS token; one row per session (§3) |
| `credential_authorizations` | Committed epoch authorizations every mTLS handshake validates against (§4.6) |
| `agent_sessions` | Agent session rows, state, binding, grouped by device |
| `tasks`, `plan_revisions`, `plan_current`, `memory_records`, `leases` | §6.1 projections; `plan_current` is the single CAS pointer |
| `canonical_refs` | Replicated CodeComm canonical Git pointer and CAS version (§§6.1, 7.2) |
| `activity` | Projected activity records (§6.1), bounded; a local projection of event content, not an independent record (§10.1) |
| `peer_acks` | Durable per-peer applied watermarks |
| `lease_deadlines` | **Local only**: leader scheduling hints keyed by lease/version; never replicated or digest-covered |
| `control_file_proposals` | Committed proposals, replicated (§8.4) |
| `control_file_approvals` | **Local only**: this device's approval decisions. Never replicated, never digest-covered, never committed |
| `publications` | §7.2 publication entities; digest-covered |
| `merge_conflicts` | Deterministic conflict tuples and resolution state from `workspace.conflict.*` |
| `git_artifacts` | **Local only**: resumable bundle offsets, verification/import state, source, and retention |
| `replication_cursors`, `outbox` | Catch-up cursors keyed by peer; outbox holds proposals awaiting forward, drained in insertion order by the owning daemon and deleted once committed or rejected |
| `audit_events` | Audited actions (§16) |

Queryable identity/kind/version/status/time fields are typed and indexed; versioned
payloads use the §4.1 canonical encoding. Network input never becomes SQL; trusted SQL uses
prepared statements. V1 DDL and migration 0001 are a phase-2 deliverable, frozen thereafter
as golden fixtures (§12.2).

SQLite MUST enable WAL, foreign keys, a 5 s busy timeout (§11.2), supported defensive settings,
and full durability for accepted state. Event/projection/idempotency/outbox/applied-index
changes commit atomically. `(event_id)` and the origin-scope sequence of §4.2 are
unique. Committed but unapplied Raft entries replay idempotently after crash. Checkpointing and
transactional checksummed migrations are daemon-controlled; irreversible migration requires
verified backup.

Use the Raft library's production stable store, not a custom log. Backup/export uses
SQLite online backup plus a matching verified Raft snapshot/applied index. Never
ordinary-copy active DB/WAL files. Startup after unclean exit performs recovery/integrity
checks; corruption preserves evidence, stops writes, and offers verified restore or event
reconstruction.

Generated context is non-authoritative, provenance-labeled untrusted data. Inbox files are
immutable, uniquely named, atomically renamed, and deduplicated by event ID.

### 6.3 Coordination semantics

Task states are a graph. Every legal edge is listed; any transition absent from this
table is rejected deterministically on every replica. The `Who` column narrows the
`task.state_changed` role floor (§5.4) per edge; "owner override" edges are the operator
verbs of §6.4, distinct from the `holder` performing a voluntary transition.

| From | To | Who | Notes |
|---|---|---|---|
| — | `backlog` | owner, editor | Create |
| `backlog` | `ready` | owner, editor | Declares it workable |
| `ready` | `backlog` | owner, editor | Withdraw from consideration |
| `ready` | `claimed` | owner, editor | Compare-and-set; exactly one winner |
| `claimed` | `in_progress` | holder | Work started |
| `claimed` | `ready` | holder, or owner override | Voluntary or forced release (§6.4) |
| `in_progress` | `blocked` | holder | Requires `reason` |
| `in_progress` | `ready` | holder, or owner override | Release mid-work |
| `in_progress` | `done` | holder | Refused while an unresolved merge conflict references the task |
| `blocked` | `in_progress` | holder | Unblocked, resume |
| `blocked` | `ready` | holder, or owner override | Hand back instead of resuming |
| any non-terminal | `cancelled` | owner | Terminal; abandons the work |
| `done` | — | — | Terminal |

`done` and `cancelled` are terminal: no edge leaves them. Reviving abandoned work means
creating a new task, optionally labelled to point at the old one. A claim sets
`owner_device_id` and `owner_agent_session_id` together and clears a matching
`intended_device_id`; any release clears both owner fields. A claim from another device while an
intent is set is a deterministic rejection. Reassignment validates that the target is active at
apply time. If that device is later revoked before claiming, the intent remains visibly blocked
until an owner reassigns it or force-releases it; revocation never silently delegates work.

Other entities:

- Plans: immutable revisions plus one compare-and-set current pointer; editors propose,
  owners select (§6.1).
- Memory: append-only records with supersession chains.
- Leases: advisory task or path reservations released by an expiry event.
- Views (derived, never stored): peers/agents, activity, actionable tasks,
  repository/conflicts, and replica watermarks.

Strong task and lease claims are compare-and-set operations in the replicated state
machine, producing one winner. The local daemon serializes same-device requests, but they
remain pending until consensus commits.

No reducer reads a wall clock. On applying `lease.acquired` or `lease.renewed`, every daemon stores
a local, non-digest-covered deadline of its apply time plus the committed, bounded `ttl_seconds`.
Only the current leader schedules it. When the deadline passes, the leader proposes
`lease.released(expired)` with the lease version observed when the timer was armed. A renewal and
expiry therefore race through the same CAS: whichever commits first advances the version and the
other is rejected identically everywhere. Event traffic cannot accelerate expiry, and an idle
session still expires it.

After restart or election, a leader reconstructs timers from its persisted local deadline; a
snapshot import lacking one sets it to local now plus the full `ttl_seconds`. Clock skew or
leader/topology turnover may delay this advisory expiry but cannot release it before that leader's
local deadline. The TUI exposes such a reconstructed deadline. The committed release, not the
timer or timestamp, is authoritative.
Session-end release and operator override remain immediate committed paths.
An agent heartbeat only proves local liveness; its daemon coalesces renewals and proposes one no
earlier than the final third of the current TTL. Heartbeats themselves remain ephemeral.

A majority partition may commit and renew credentials. A minority may edit locally, queue
events, and exchange Git objects directly only while credentials remain valid. On healing, event
IDs deduplicate, the committed log converges, immutable device refs retain concurrent work, and
stale publications require an explicit rebase or merge. CodeComm never claims arbitrary offline
writes are automatically mergeable.

### 6.4 Ownership release and operator override

Because `agent_session_id` is never reused (§4.2), a claim held by an ended agent session
would otherwise be owned forever by an identity that can never return. Two mechanisms
prevent that.

**Automatic release on session end.** A session ends by proposing `agent.session.ended`: the
agent proposes its own clean shutdown, and the daemon reaps a session lost to expiry or daemon
death by proposing that session's end (§5.4). When the event applies, the reducer releases
everything that session held, in the same transaction:

- every task owned by that `agent_session_id` returns to `ready`, with `owner_device_id`
  and `owner_agent_session_id` cleared and `release_reason = session_ended`;
- every lease held by that session is released;
- `blocked_by` and committed merge-conflict records are untouched, since neither is ownership.

The release is deterministic on every replica, driven by a committed event rather than a
local timer.

**Operator override.** For cases session end does not cover — a runaway agent still
heartbeating, an abandoned worktree, a task claimed on a device that is gone for good — an
operator uses the CLI verbs below (§9), each mapping to a committed, audited, expected-version
event of §5.4. All are `human` actor, so none is reachable over MCP (§7.1).

| CLI operation | Event (§5.4) | Effect |
|---|---|---|
| `task force-release` | `task.released` (`forced`) | Returns a claimed, in-progress, or intended task to unassigned `ready`, clearing owners and `intended_device_id`; owner, or editor for its own held task |
| `task reassign` | `task.reassigned` | Force-releases, persists one active `to_device_id`, and leaves the task `ready`; only that device can win the next claim, which clears the intent; owner only |
| `task cancel` | `task.cancelled` | Moves any non-terminal task to `cancelled`; owner only |
| `lease force-release` | `lease.released` (`forced`) | Releases another session's lease |
| `agent stop` | none | Local request to a local agent session to end; the local daemon only, never a committed event and never a peer (§2.5) |

Every override records the acting `device_id` and lands in `audit_events`, so a forced
release is always distinguishable from a voluntary one. None of these are exposed over MCP
(§7.1): an agent may release *its own* claims and leases, but overriding another session's
ownership is an operator action available only through the TUI and CLI.

## 7. Agent Sessions and Integration

### 7.1 Local-only MCP

`codecomm mcp serve` is one stdio MCP process per Codex/Claude instance. It opens no TCP
listener and reaches one owner-restricted session daemon through a Unix socket or Windows
named pipe, resolved once at startup by the §3.2 selection rules and bound for the process
lifetime. Five local clients produce five distinct `agent_session_id`s even if names/types
match. Clients attached to different sessions on one device cannot observe or address each
other. A remote peer cannot open MCP, invoke a tool, add a tool, launch/stop/resume an
agent, or weaken client sandbox, network, filesystem, or approval policy.

The MCP surface is limited to typed coordination operations:

```text
agent.session.get/list   context.get       task.list/claim/update
task.state_change        task.release      plan.get/propose
memory.append            activity.append   repo.status
conflict.list/resolve    lease.acquire/renew/release
```

`task.state_change` moves a task the calling session owns along a legal edge of §6.3 (start,
block, unblock, done); it cannot cancel or reassign, which are operator-only (§6.4). `task.release`
and `lease.release` act **only on the calling session's own** holdings; the actor comes from the
IPC binding and cannot be named as an argument. The override verbs of
§6.4 — `task.force_release`, `task.reassign`, `task.cancel`, `lease.force_release`,
`agent.stop` — are absent from MCP. No tool accepts an executable, shell command, arbitrary
path/URL/script, or actor ID. Mutations validate strict schemas, bounds, roles, and
expected versions. The CLI exposes equivalent JSON operations; `context.md` is read-only
fallback.

Configure clients through supported user-local mechanisms using an absolute, verified
CodeComm path, never synchronized project launchers. Codex setup is equivalent to:

```text
codex mcp add codecomm -- <absolute-codecomm-executable> mcp serve
```

Use explicit MCP tool allowlists and write approval. Claude configuration is a versioned
adapter. MCP instructions require context refresh, peer-agent review, task claim, path
lease, version recheck, concise result, and stop on conflict; they begin by declaring
remote text untrusted.

### 7.2 Agent lifecycle and same-device concurrency

Registration binds a fresh agent ID to session, device, workspace, IPC connection, client
metadata, and working root. The daemon returns an in-memory resume capability, never
argv/env/file/log. Heartbeats refresh presence and make held leases eligible for the coalesced
renewal rule of §6.3. Disconnect enters a 90 s grace period
(§11.2); resume requires the capability; expiry commits `agent.session.ended`, which
releases both leases and task claims (§6.4) and forbids ID reuse.

`starting -> idle -> claimed -> working -> blocked -> disconnected -> ended` is the usual
path, not the only one. `disconnected` returns to its prior state on successful resume;
`ended` is terminal and its ID is never reused. Any state may go directly to `ended` on
expiry, `agent.stop`, or daemon loss, triggering the release of §6.4.

The adapter, not model text, attaches all actor IDs. Durable events record start,
meaningful transitions, and end; high-frequency presence is bounded/ephemeral. All local
instances attached to the same session share that session's daemon and DB, but retain
separate claims, leases, origin sequences, activity, and rows grouped by device.

Writable concurrency modes:

- **Isolated worktree (default):** create one Git worktree per launched agent outside the user's
  primary working tree, then publish an immutable reviewed commit.
- **Shared root (opt-in):** require disjoint advisory path leases and visibly label risk.
  Same-user processes can bypass leases; identity does not provide filesystem isolation.

**Publication** is a replicated proposal to advance the CodeComm canonical ref.

| Field | Type | Notes |
|---|---|---|
| `publication_id` | UUIDv7 | Immutable |
| `task_id` | `task_id`? | Task this completes, if any |
| `author_device_id`, `author_agent_session_id` | ids | From the committed actor binding |
| `base_commit`, `commit_oid`, `tree_oid` | algorithm-tagged Git OIDs | Exact immutable graph transition |
| `parent_oids` | [Git OID], ≤16 | Exact commit parents, needed for conflict-resolution validation |
| `paths` | [canonical path], ≤2048 | Sorted, unique paths changed from `base_commit` |
| `artifact_digest` | SHA-256 | Exact bounded Git bundle staged for this publication |
| `resolves_conflict_ids` | [`conflict_id`], ≤64 | Conflicts whose two tips staging voters verified are ancestors of `commit_oid` |
| `staging_receipts` | [signed receipt], ≤5 | Validated set for one `voter_set_version`, sorted by voter `device_id`; replaced by the apply-time set |
| `state` | enum: `proposed`, `approved`, `applied`, `rejected` | |
| `entity_version` | integer ≥1 | |

Before proposal, the author daemon creates a bounded bundle for `base_commit..commit_oid`.
A receiving target voter downloads it to quarantine, verifies artifact digest/size and
`git bundle verify`, imports with hooks, filters, helpers, alternates, submodules, and LFS network
disabled, runs connectivity/object checks, and confirms the commit, tree, parents, and
`git diff --name-only` paths exactly match the metadata. For every declared resolved conflict it
also verifies both committed tips are ancestors of `commit_oid`. It then pins the objects under
`refs/codecomm/publications/<publication_id>`, durably records them, and signs
`(session_id, workspace_id, voter_set_version, publication_metadata_digest, voter_device_id)`
under `codecomm/v1/git-stage-receipt`. The metadata digest is SHA-256 over the JCS object
containing exactly `publication_id`, `task_id`, `author_device_id`,
`author_agent_session_id`, `base_commit`, `commit_oid`, `tree_oid`, `parent_oids`, `paths`,
`artifact_digest`, and `resolves_conflict_ids`. It excludes receipts, state, and `entity_version`,
avoiding a recursive preimage. A receipt is issued only after durable import and remains valid
while the publication is non-terminal.

`publication.proposed` and `publication.applied` each require valid receipts from a majority of
the **current committed voter target**, with its exact `voter_set_version`, distinct active target
voters, and matching metadata. This makes committed content available wherever the configured
fault tolerance can survive. A target change requires new receipts; old-version receipts grant no
quorum credit. A one-voter session necessarily has one durable voter copy and no content failover,
matching its consensus tolerance.

`publication.reviewed` records approval or rejection; the author's agent session cannot review
its own publication. `publication.applied` succeeds only when the publication is approved,
`base_commit` equals the replicated canonical `commit_oid`, and both the publication version and
`expected_canonical_ref_version` match. One reducer transaction marks the publication applied and
advances `canonical_refs`; a mismatch is a structured stale rejection that leaves the proposal
intact for explicit rebase/merge or rejection. No verification races a changing working tree.

After applying the event, each local reconciler fetches missing objects from any receipt holder,
revalidates them, and runs compare-and-set `git update-ref refs/codecomm/canonical <new> <old>`.
The SQLite canonical projection is authoritative; an unavailable object leaves the local Git ref
visibly `object-lagging` until retrieval succeeds. CodeComm never updates `HEAD`, the index, a
user branch, or a working tree. An agent MUST NOT publish another session's worktree, and a
publication changing a §8.4 control file is rejected in favor of that approval flow.

### 7.3 Generated context

`context.get` and the `context.{json,md}` fallback are the only view an agent has of
its peers. Both render the same fields; `context.md` is a human- and fallback-readable
projection of `context.json` with control characters escaped. Content is derived
entirely from committed state plus local status — a projection, never an authority.

| Group | Fields |
|---|---|
| Session | `session_id`, `workspace_id`, own `device_id` and role, leader, quorum state, applied vs committed index, `chain_index` |
| Self | own `agent_session_id`, state, claimed tasks, held leases |
| Peers | per device: role, online, its agent sessions with state, claims, and leases, grouped by device |
| Work | actionable tasks (§6.1) with `task_id`, title, priority, `blocked_by` and their states; own tasks in any state |
| Plan | current `plan_revision_id`, title, and its `task_ids` |
| Memory | most recent non-superseded records in scope, newest first |
| Repository | canonical commit and local object/ref lag; own and peer draft refs; unresolved merge conflicts |
| Provenance | for every peer-authored string: origin `device_id`, role, `agent_session_id`, `chain_index` |

Bounds are normative: at most 200 tasks, 50 memory records, 100 activity entries, 8 devices
× 32 agent sessions, and a hard 256 KiB total, truncating oldest-first within each group and
stating explicitly in the payload that truncation occurred. Context is regenerated on
applied-index change, agent session state change, conflict change, and on demand, coalesced
so a burst of events produces one regeneration. `context.json` is written atomically by
write-then-rename.

Signed peer text proves provenance, not safety. Adapters keep remote text in bounded
structured data, escape terminal and control characters, never turn it into server
instructions or tool definitions, and never reduce local approvals. Every string in context
that originated on another device carries the provenance fields above.

MCP cannot observe every native action. Agents SHOULD report intent, rationale summary,
decisions, affected files, tools, redacted commands, tests, and results. Optional vendor
hooks require local consent, fixed executable, local IPC, pre-persistence redaction, and
explicit `capture_level`; disabling hooks does not disable coordination.

## 8. Workspace and Git Synchronization

### 8.1 Direct Git object/ref mesh

CodeComm exchanges immutable Git objects and CodeComm-owned refs directly between authorized
peers; no transfer traverses the Raft leader. Each daemon maintains a session-bound bare store
under `.codecomm/git/` containing only shared objects and these namespaces:

| Ref | Meaning |
|---|---|
| `refs/codecomm/canonical` | Local materialization of the replicated canonical pointer (§7.2) |
| `refs/codecomm/publications/<publication_id>` | Pinned validated publication commit |
| `refs/codecomm/drafts/<device_id>/<agent-or-root-id>` | Monotonic source-owned pointer to the latest immutable dirty/untracked snapshot |
| `refs/codecomm/remotes/<device_id>/drafts/<agent-or-root-id>` | A receiver's tracking copy; never advertised as its own work |

The peer API serves this bare store only, never the user's `.git`. It runs allowlisted
`upload-pack` protocol-v2 plumbing and resumable bundle transfer with direct argv, a sanitized
environment, bounded processes/bytes/time, backpressure, and epoch mTLS. It exposes no
`receive-pack`, arbitrary command, repository path, user ref, alternates, or unadvertised-object-ID
surface. Incoming bundles enter a per-session quarantine and are verified before atomic import.
Revocation closes transfer immediately; leader loss does not affect surviving-peer exchange.

Eligible dirty and untracked work is shared as a **draft snapshot**, never as remote filesystem
mutation. After a bounded debounce, and on explicit checkpoint/publish/shutdown, the daemon uses a
temporary index seeded from the worktree's `HEAD`, adds only §8.4-eligible paths with filters and
hooks disabled, then invokes `write-tree`/`commit-tree`. It does not touch the real index, `HEAD`,
user refs, or files. The resulting source-namespaced ref advertisement binds workspace, source
device/agent, base, prior and new snapshot OIDs, path manifest, monotonic sequence, and artifact
digest under `codecomm/v1/git-ref-advertisement`. A peer verifies that the authenticated source
owns the namespace and compare-and-set advances only the remote-tracking ref above; rollback,
sequence gaps, and a wrong prior OID are refused and reconciled by fetching the missing chain.
Peers MAY relay the unchanged source-signed advertisement and verified artifact, but never
re-sign or rename it as their work; consumers verify the original source while treating the
serving peer only as a byte source.

Drafts are not strong state and never advance canonical. Status says `replicated` only after one
other active member durably imports the snapshot; otherwise it says `local-only` and retries.
Retention keeps §11.2's latest-snapshot floor plus explicitly pinned drafts on both source and
receivers, so checkout, stash, reset, clean, branch switch, or deletion cannot erase a recently
replicated version. A clean branch switch creates no dirty snapshot and no mass transfer. Inspect,
pin, restore, cherry-pick, merge, or discard is explicit; no received draft is checked out
automatically.

### 8.2 Initial Git bootstrap

Hosting requires a Git repository with a reachable commit. `git init` or an initial commit requires
explicit consent. Destination handling is: matching `workspace_id` resumes; the same name with a
different/no identity requires preview and adopt/merge; a different name offers
`<cwd>/<workspace-name>`; non-empty content is never overwritten without preview/confirmation.

Bootstrap:

1. Select an up-to-date owner/editor source (§3). It captures eligible dirty/untracked state as
   one immutable draft before freezing the manifest.
2. Source creates a bounded bundle containing the canonical commit, selected CodeComm refs, and
   that draft, with SHA-256, size, object format, source identity, and expiry.
3. Joiner downloads resumably over mTLS, verifies digest/size, runs `git bundle verify`, and clones
   with direct argv and isolated configuration.
4. Hooks, recursive submodules, credential helpers, external filters, alternates, and automatic
   Git LFS network access remain disabled. Seed the session bare store from the verified bundle.
5. The primary working tree stays at canonical. The source draft is visible for explicit
   inspect/apply; it is never overlaid automatically. Review control files before launching agents
   or shells, then enable direct peer exchange and delete expired staging artifacts.

Preflight shows identities, destination, refs, sizes, ignore policy, submodule/LFS limits, and
rejects or requires resolution for case/Unicode collisions, Windows-reserved/invalid names,
escaping symlinks, and file count/size limits. After join, the CLI may `chdir` and launch a child
TUI/shell but cannot change its parent shell.

### 8.3 Canonical advancement and conflicts

The replicated `canonical_refs` row, not any member's branch, is shared truth. A publication
advances it only through §7.2's reviewed, quorum-staged dual CAS. Local materialization updates
only `refs/codecomm/canonical`; users and agents explicitly rebase, merge, cherry-pick, or create a
worktree from it. A checkout, stash, reset, or branch operation therefore affects only its origin.

A stale publication is not silently merged. An explicit rebase/merge attempt runs system Git in an
isolated temporary worktree. If it conflicts, the daemon sorts and canonicalizes Git's conflicting
paths and derives:

```text
conflict_id = "ccf1" || lowercase_hex(SHA-256(JCS({
  "workspace_id": workspace_id,
  "publication_id": publication_id,
  "merge_base": merge_base,
  "canonical_commit": canonical_commit,
  "candidate_commit": candidate_commit,
  "paths": sorted_unique_paths
})))
```

Any daemon may propose `workspace.conflict.detected`; identical merge inputs produce the same ID.
If that row already exists with the exact tuple, reducers return deterministic `already_detected`
without another row; the same ID with different fields is a fail-closed integrity error. The
publication's task and author session derive their blocked view from the unresolved row, and a
referenced task cannot become `done`. No separate per-device conflict flag or daemon-selected ID
exists.

Resolution creates and reviews a new publication declaring the conflict ID. Staging voters verify
that both conflicting tips are ancestors of the resolution commit and bind that fact into their
metadata-digest receipts. After it applies, `workspace.conflict.resolved` CAS-links that
publication; reducers verify its committed declaration and receipt quorum rather than consulting a
local object store. CodeComm shows base/ours/theirs, paths, and resolution publication, but never
chooses a side or silently deletes an immutable draft/publication ref.

### 8.4 Ignore rules and control files

**Control files** configure agent behavior and are the only paths requiring per-device approval.
Always exclude `.git/`, `.codecomm/`, staging paths, non-regular files, selected caches/build
outputs, and configured credentials from drafts. Exclude `.env*`, private keys, cloud credentials,
and signing material by default; opt-in requires preview/warning. `.codecommignore` is
authoritative; `.gitignore` import is optional because semantics differ.

Automatic drafts and ordinary publications exclude:

- `**/AGENTS.md`, `**/AGENTS.override.md`, `**/CLAUDE.md`;
- `.codex/**`, `.claude/**`;
- ignore-policy sources; and
- agent hooks, MCP config, and local command-policy files.

Changes use signed bounded `control_file.change_proposed` events carrying path, proposed content
digest, and bounded diff. The proposal is committed; approval is local in
`control_file_approvals`, never replicated or digest-covered, so one device cannot consent for
another (§2.5). Approval atomically writes digest-verified content locally and records the decision;
decline leaves the file untouched. A stale digest requires re-proposal. Native notifications plus
periodic scan monitor only this set. The TUI shows local current/proposed digests and warns when
authorized peers report differing control/ignore-policy digests without revealing local approval
decisions.

Portable guarantees cover regular content and executable intent where supported, not ownership,
ACLs, ADS, xattrs, or exact timestamps. Submodules and LFS require explicit separately
authenticated setup; no publication or draft triggers their network clients.

## 9. UX, Lifecycle, and Failures

TUI views: session/leader/quorum, peers/roles/direct links, agents by device, tasks, plan
history, activity/provenance, repository/drafts/conflicts, and security reviews. Pending,
committed, applied, stale, merge-conflicted, object-lagging, local-only, offline, expiring,
expired, halted, and reconciling states
MUST be visually distinct and distinguishable without color (§16). `expiring` carries a countdown
to credential expiry, `halted` names the version required to resume (§5.5), and `reconciling`
names a voter-set transit whose live Raft configuration has not yet reached the committed target
past `voter_reconcile_deadline` (§3). `reconciling` is derivable only by a member of the live Raft
configuration; a settled application nonvoter receives no configuration entries (§5.3), so its
client shows the committed target and labels reconciliation status as voter-reported rather than
implying local observation. Same-labeled
agents remain separate by shortened session ID.

Representative CLI:

```text
codecomm host|join|tui|status
codecomm agent list|launch|stop|publish
codecomm task add|list|claim|start|block|unblock|done
codecomm task release|force-release|reassign|cancel
codecomm lease list|release|force-release
codecomm plan show|propose
codecomm memory add
codecomm conflicts
codecomm draft list|inspect|restore|prune
codecomm control-files review
codecomm peer revoke
codecomm cluster status|transfer-leadership|recover-quorum
codecomm repo status|doctor
codecomm mcp serve
codecomm shell
codecomm daemon start|stop|status
codecomm sessions list|leave
codecomm supervisor install|uninstall|start|stop|status
codecomm audit list|export
codecomm support-bundle
```

Every command except `sessions list`, `supervisor *`, and `host`/`join` operates on one
selected session, resolved by `--session`/`--workspace`, then working-directory ancestry,
then a sole registry entry (§3.2). `sessions list` prints each registry entry — workspace
root, `session_id`, daemon state, and port — and queries each running daemon for quorum
health, blank for stopped sessions.

`sessions leave` is a local operation: it stops the session daemon, removes the registry
entry, and optionally deletes `.codecomm/`, leaving the workspace files in place. It does
**not** alter committed membership — that device remains a member until an owner revokes it
(§4.3) — and the TUI labels a left-but-not-revoked session as such.

Install the **supervisor** visibly and reversibly as a per-user `launchd`, `systemd --user`,
or Windows scheduled-task/user-service integration; it is the only registered service, and
supervisor-started session daemons are its children.

Both process kinds retain a foreground mode for development. A foreground `codecommd` takes
the same per-workspace OS lock and writes the same registry entry as a supervised one,
marking it foreground and externally managed, so clients resolve to it normally and the
supervisor will neither adopt nor restart it. This is what the §9 rule against starting a
daemon "behind the supervisor's back" means: a client MUST NOT spawn a daemon itself, while
an operator explicitly running one in the foreground is expected and visible. If no
supervisor is installed, foreground daemons still work and `sessions list` reads the
registry directly. The per-workspace OS lock prevents two daemons owning the same
`.codecomm/` or Git quarantine/ref namespace; the lock, not the registry, is the authority.

| Failure | Required behavior |
|---|---|
| Duplicate request | Return committed idempotent result |
| Duplicate agent ID | Reject and audit |
| Agent disconnect | Grace, then end the session and release its leases and task claims (§6.4) |
| Task owned by an ended agent session | Reducer returns it to `ready` with `release_reason = session_ended` on the committed session-end event |
| Runaway agent still heartbeating | Operator `agent stop` locally, or `task force-release` plus `lease force-release`; both audited |
| Abandoned worktree | Surfaced as a blocker with its owning session and base commit; publication refused until an operator releases or reassigns |
| Concurrent claim | Consensus commits one winner |
| Leader loss | Elect; direct reads/Git transfers continue |
| Election | Queue strong proposals; expose transient state |
| Quorum loss | Queue strong work; ordinary links continue only to credential expiry; the rekey plane cannot renew without a voter majority |
| Voter restart | Replay Raft, idempotently apply SQLite, rejoin follower |
| Expired credential | Close ordinary sessions; advertise `rekey`; identity-authenticate and obtain a quorum-authorized replacement (§4.6) |
| All voter credentials expired after sleep | Reachable voter majority re-forms through the restricted rekey transport, authorizes fresh epochs, and restores normal Raft without operator action |
| Every credential expired and a voter majority version-halted | No leader can be elected: surface the §5.5 version blocker naming the release required. Upgrading a voter resolves it; §3.1 recovery MUST NOT be offered, since state is intact and merely unapplied |
| Voter reconciliation stalls | Preserve the committed target and current live configuration; never roll back, skip catch-up, or choose another voter set. Surface the blocking device/step after `voter_reconcile_deadline`, retry on topology or leadership change, and require §3.1 recovery only if the live configuration has permanently lost quorum |
| Revoked device attempts rekey | Any peer that has applied the revocation refuses the handshake and therefore never exchanges votes with it; quorum arithmetic itself is untouched and stays derived from the committed configuration (§3). A not-yet-applied peer may admit it, but sends it no entries or snapshot, and renewal still requires a leader-confirmed active membership (§4.6) |
| Revocation | All informed peers close ordinary/rekey/Git access and stop serving the device |
| Git interruption/digest/object failure | Resume by artifact digest/offset or discard quarantine and audit; never update a ref from partial/unverified data |
| Git child hang/crash | Kill on deadline, retain verified objects, clean quarantine, and retry with capped backoff |
| Disk full/permission loss | Stop acknowledgements, retain files, expose blocker |
| Stale publication/merge conflict | Preserve immutable commits/drafts; require explicit rebase or reviewed merge publication |
| Control-file change | Hold local proposal for approval |
| DB corruption | Preserve evidence; stop writes; restore/reconstruct |
| Unappliable committed entry | Halt at that index without advancing applied index; serve prior reads; expose required version; resume after upgrade (§5.5) |
| Projection digest mismatch at a checkpoint | Fail closed: stop applying, preserve evidence, alarm, require operator recovery; never self-repair from the leader (§5.6) |
| Version too old to join | Refuse to join rather than joining and halting |
| Host suspend and resume | On wake, re-resolve interfaces, re-advertise at once, re-dial peers with capped backoff; renew credentials immediately if expired (§2.3) |
| Local address change or interface loss | Drop connections bound to the vanished address, re-advertise, re-dial; membership unchanged |
| Wake with expired epoch and no quorum | Distinct visible state: local reads/work and rekey attempts continue, ordinary peer/Git traffic remains closed, strong proposals queue, and renewal retries on connectivity change |
| Stale endpoint hint | Treated as a guess: dial, fail fast, fall back to multicast, then to a manual endpoint |
| Permanent voter loss with quorum | Safe remove/replace |
| Permanent quorum loss | Offline single-device recovery authorized by an owner device or the recovery key; successor genesis; survivors re-pair (§3.1) |
| Permanent quorum loss with no surviving owner device | Recovery key authorizes; without it the session is unrecoverable, as stated at creation |
| Recovered session meets a survivor of the old lineage | Mismatched `recovery_generation` detected; refuse to interoperate rather than merge histories |
| Session daemon crash | Supervisor restarts with capped backoff; other sessions unaffected; repeated failure surfaces a blocker instead of looping |
| Supervisor crash | Running daemons continue; clients keep using registry entries; restart reconciles the registry against live PIDs |
| Stale registry entry | Entry whose PID is dead is marked stopped at supervisor start or on failed client connection; socket path and port are revalidated before reuse |
| Supervisor absent when a client resolves a session | Client reports that the supervisor is not installed or running, with the command to start it; it MUST NOT start a session daemon behind the supervisor's back |
| Workspace directory moved or deleted | Daemon stops and the entry is marked unreachable, a state distinct from stopped: the workspace root no longer exists, so the session requires explicit re-selection or rejoin rather than restart |
| Concurrent-session cap reached | Refuse the new session with the current list; never evict a running one |

An accepted event means voter-majority durability, not application by every peer. A publication
additionally proves durable objects on a voter-target majority, while each member's local object/ref
materialization may lag. Report those states separately.

## 10. Security and Privacy

Assume hostile LAN, spoofed/replayed discovery, unauthorized API/pair attempts, lost/compromised
former members, malicious paths/content, prompt injection, tampered dependencies, secret-bearing
telemetry, and workspace readability by authorized owner/editors.

Per §2.1, an authorized member is in scope as an adversary in the following forms:

| Authorized-member threat | Control |
|---|---|
| Careless or subverted member floods events, claims, or leases | Committed per-device and per-agent-session **depth** limits (in-flight claims, held leases, unacknowledged activity) are counters over committed state, rechecked deterministically by every reducer at §5.3 step 5 without consulting a clock; exceeding one is a structured rejection. **Rate** limiting is not a reducer concern, since a rate is time-relative and reducers never read wall clocks (§6.3): each receiver enforces request rates locally before forwarding a proposal, and the refusal is a transport-level response, audited, never a silent drop |
| Member proposes malformed or unauthorized mutations | Deterministic recheck of role, schema, actor binding, and expected version on every replica (§5.3 step 5) |
| Member escalates its own role or voter status | Grants are never self-issued; committed, audited, owner-only (§4.3) |
| Member's device is lost or stolen | Committed revocation closes ordinary and rekey access (§4.6) |
| Member reads workspace or history it should not have seen | Not a control boundary: admission is the decision (§2.1). Withholding data requires revoking and rotating |

Out of the V1 boundary: a compromised local OS account; revocation of data a member already
downloaded, which is unrecoverable once fetched; a malicious authorized **voter**
deliberately violating the consensus protocol (§2.4 excludes Byzantine tolerance); and
confidentiality among owners and editors, who are mutually all-reading by design (§2.1).

Required controls:

- TLS 1.3 mTLS, pinned invite identity/genesis, two-sided confirmation, one-use
  secrets, PAKE for short codes, rate limits, replay/idempotency protection.
- Stable device identity, quorum-authorized ephemeral keys, bounded stale
  partition lifetime, committed revocation, safe voter changes.
- Dedicated identity-authenticated rekey ALPN bound to session and recovery generation,
  with a closed message enum, no ordinary data surface, no pre-authorized key stockpile,
  no data before an election, leader-only replication, and quorum still required for every
  replacement credential.
- Origin signatures, an apply-time event chain, signed leader checkpoints, and Raft
  commitment; no remote SQL/DB changesets.
- Owner/editor least privilege; admission is the only data boundary (§2.1).
- Local-only MCP/IPC with Unix peer UID/socket mode or Windows named-pipe ACL.
- Absolute verified MCP executable; no remote execution or permission changes.
- Provenance-labeled bounded remote text; ANSI/OSC/control-character escaping.
- Per-device approval for agent instructions/hooks/MCP/ignore policy.
- Session-bound bare Git store; read-only allowlisted `upload-pack`; no `receive-pack`, user refs,
  arbitrary repository paths/OIDs, checkout, or workspace writes over the peer API.
- Quarantined bounded bundles, digest and graph/metadata verification, no shell, and
  hooks/helpers/filters/alternates/submodule/LFS network disabled.
- Canonical path/symlink containment and file/request/queue/DB quotas.
- Committed depth limits plus local rate limiting, per the table row above.
- Redaction before persistence/replication; restrictive/rate-limited local logs;
  no telemetry by default.
- Identity keys in Keychain, Secret Service-compatible storage, or Windows
  Credential Manager; temporary sensitive artifacts expire securely.
- Signed/checksummed releases, SBOM, dependency/license/vulnerability review,
  exact executable firewall rules, and explicit Windows firewall consent.

### 10.1 At rest, audit, retention, and removal

CodeComm does not encrypt data at rest in V1 and relies on full-disk encryption. What
that leaves in the clear, including copies of repository content **outside** the
workspace:

- `state.db` and its WAL, holding all coordination history;
- `consensus/`, the Raft log and snapshots;
- `tmp/` during bootstrap, which briefly holds a complete Git bundle of the repository;
- `.codecomm/git/`, the session bare store, quarantines, publication artifacts, and retained draft
  objects; `.git/objects` and `refs/codecomm/**` may also retain content deleted from a working tree;
- `conflicts/` temporary merge-resolution worktrees/snapshots;
- redacted logs and any support bundle.

Identity private keys are the exception: they live in the OS credential store, never in
either tree (§4.2). FDE cannot be enforced from userspace, so `status` and `repo doctor`
MUST detect and report whether the volumes holding the workspace and per-user state are
encrypted, and first-run MUST warn when they are not. Database encryption and its key
management are deferred.

**Identity key lifecycle.** Revoked and superseded identity public keys are retained
indefinitely in `devices`, since §5.2 rests history verifiability on them: revocation ends
authorization, never verifiability. Identity private keys are outside backup and export
(§6.2). A device whose credential store is lost or whose OS is reinstalled has lost that
identity permanently; it re-pairs as a **new** `device_id` and an owner replaces its voter
slot (§3). There is no key rotation within a `device_id` (§4.1).

**Audit.** `audit_events` records, at minimum: membership, role, and voter changes;
revocations; credential authorizations; operator overrides (§6.4);
quorum recovery; and every rejected authorization attempt. Entries are committed events and
inherit the chain's tamper-evidence (§5.2.1). Any member may read the audit log (§2.1).
`codecomm audit list|export` exposes it, with export producing a signed range verifiable
per §5.2.1.

**Retention.** Coordination history — including every `actions[]` entry and
`rationale_summary` — is retained for the **session's lifetime**. These fields live inside
signed, chain-covered events (§5.2.1), so they cannot be pruned without either breaking chain
verification or introducing a second event form; V1 does neither. Pruning an activity
*projection* reclaims space but deletes nothing sensitive, and this document does not claim
otherwise.

The only way to shed activity history is to export and start a new session (§2.2). An operator
who needs a shorter horizon should scope sessions accordingly. `codecomm audit export` and event
export MUST be offered before any destructive compaction. Chain-preserving payload compaction is
a candidate for a later revision, not V1.

**Removal.** `sessions leave` is local (§9). Uninstall removes the supervisor registration,
registry, and per-user state, and MUST prompt separately before removing `.codecomm/`
directories, identity keys, or CodeComm-owned Git refs, naming what is about to be destroyed and
that it is unrecoverable. It never deletes user refs or runs Git GC automatically. `codecomm
support-bundle` produces a redacted archive under the same redaction rules as retained
diagnostics (§12.5), and states what it included.

Signatures prove provenance, not content safety.

## 11. Implementation and Production Engineering

Go is the default due to networking/TLS, deployment, cross-compilation, concurrency, and
ecosystem fit. Candidate dependencies, after maintenance/license/security review:

- Bubble Tea-equivalent TUI, `net/http` TLS 1.3, maintained SQLite driver;
- maintained embedded Raft plus production stable store;
- maintained MCP SDK;
- stdlib `crypto/ed25519` and `crypto/sha256`; a reviewed RFC 8785 JCS canonicalizer, or a
  small audited in-tree implementation, since the test vectors are fixed and the primitive
  is frozen by §12.2 fixtures;
- system Git;
- Unix sockets, Windows named pipes, native credential-store adapters.

Rust/Tokio/Axum/Ratatui/SQLite is viable if team expertise justifies additional delivery
cost. Do not implement cryptography, PAKE, consensus, a Git object database, or a merge engine.

### 11.1 Supported versions

| Component | Floor | Why this floor |
|---|---|---|
| Go | 1.24 | Current support window and required standard-library security fixes |
| Git | 2.38 | Bundle v3, protocol v2, stable `bundle verify`, `merge-tree`, and mature `worktree`/plumbing |
| SQLite | 3.42 | `PRAGMA optimize`, defensive settings, stable WAL behavior |
| Windows | 10 21H2 / Server 2022 | Named-pipe ACL and Credential Manager behavior assumed here |
| macOS | 13 | Keychain and APFS behavior assumed here |
| Linux | glibc 2.31 or musl 1.2, kernel 5.10 | Secret Service, `SO_PEERCRED`, `systemd --user` |
| Codex CLI, Claude Code | the two most recent minor releases of each, restated per CodeComm release | MCP surfaces move faster than this doc |

`git bundle`'s SHA-256 *object format* is **not** required: §8.2's SHA-256 is the artifact
digest CodeComm computes over the bundle file, independent of the repository's object
format. On an unsupported version CodeComm refuses to start with the detected and required
versions named, except for Codex and Claude Code, where an unsupported client is admitted
with a visible warning.

### 11.2 Constants

Values every member must agree on are committed genesis policy (§4.2) and appear in the left
column. The rest are local configuration with these defaults.

| Constant | Value | Scope |
|---|---|---|
| `credential_epoch_seconds` | 1800; fixed in V1 | Committed |
| `credential_overlap_seconds` | 120; fixed in V1 | Committed |
| `credential_renewal_lead_seconds` | 300; fixed in V1 | Committed |
| `checkpoint_events` / `checkpoint_interval` | 500 events / 5 min | Committed |
| `lease_min_ttl_seconds` / `lease_default_ttl_seconds` / `lease_max_ttl_seconds` | 30 / 900 / 3600 | Committed |
| Admission depth per agent session: in-flight claims / held leases / unacknowledged activity | 8 / 32 / 256 | Committed |
| `digest_version` | 1 | Committed |
| `cluster_min_version` | the release that created the session | Committed |
| Multicast group | `239.192.71.31:47831` (IPv4), `ff12::c0de:c031` port 47831 (IPv6) | Committed |
| Advertisement interval | 20 s, jitter ±25%, TTL/hop-limit 1, ≤1200 bytes | Committed |
| Endpoint hint TTL | 8 × advertisement interval | Derived |
| `voter_reconcile_deadline` | 30 s; an unfinished voter-set transit past this surfaces the `reconciling` state (§3, §9) | Local |
| HTTPS port | 47831 default, configurable; per session, so concurrent sessions take the next free port | Local |
| Invite TTL / outstanding cap | 15 min / 8 | Local at issue |
| Discovery `expires_at` window | ≤60 s future | Local |
| Certificate expiry skew allowance | ±120 s, connection setup only | Local |
| Discovery nonce cache | 256 per source, 5 min TTL | Local |
| Agent heartbeat / disconnect grace | 10 s / 90 s | Local |
| Draft debounce / minimum snapshot interval | 2 s / 5 s | Local |
| Draft retention floor | latest 100 snapshots per source; explicitly pinned drafts exempt | Local minimum |
| Concurrent sessions per device | 4 | Local |
| Max event size / batch / decompressed | 256 KiB / 4 MiB / 64 MiB | Local, enforced before allocation |
| Generated context cap | 256 KiB (§7.3) | Local |
| `idempotency_keys` retention | 24 h, and never less than 10× the max client retry window | Local |
| SQLite busy timeout | 5 s | Local |
| Reconnect backoff | 250 ms base, ×2, cap 30 s, ±25% jitter | Local |
| Log retention | 7 days or 100 MiB per session, whichever first | Local |

Committed values are set at `host` from these defaults and cannot be changed by a
single member afterward; changing one requires an owner-proposed committed policy
event.

Production quality is a release criterion:

- Maintain explicit domain/consensus/transport/storage/repository/agent/UI/platform boundaries and
  acyclic dependencies.
- Decode untrusted input once into bounded typed versioned structures; avoid untyped
  business data, reflection-driven logic, and string protocols.
- Validate every external value/transition. Return stable structured errors with causal
  context; peer/repository/input errors MUST NOT panic the daemon.
- Propagate deadlines/cancellation through network, DB, Git, child processes, and
  shutdown. Bound queues, tasks/goroutines, bodies, expansion, retries, connections, caches,
  and child resources.
- Use backpressure; never silently drop durable work. Retry only transient errors with
  capped exponential backoff and jitter.
- Make startup/shutdown idempotent and crash-safe: drain accepted work, close listeners,
  persist/checkpoint, reap children, and recover every boundary.
- Use atomic replacement, explicit modes/ACLs, canonical paths, symlink checks, required
  directory durability, direct argv, and sanitized child environments.
- Keep config typed/versioned/validated/secure by default. Insecure test/dev wiring MUST be
  constructor/build-only, visibly reported, never remotely enabled, and absent from releases
  when it weakens security.
- Use redacting secret types; exclude secrets from URLs/argv/logs, minimize lifetime/copies,
  and erase mutable buffers where meaningful.
- Emit structured rate-limited logs and bounded metrics for correlation IDs, queues, quorum,
  replication/object lag, Git child failures, and DB latency without source content. Distinguish
  liveness, readiness, quorum, peer, and repository health.
- Make migrations/wire changes checksummed, replayable, crash-safe, fixture tested, and
  reversible or guarded by verified backup/rollback boundary.
- Pin dependencies/lock metadata, verify signatures/checksums, generate SBOM, review
  licenses, scan vulnerabilities, remove unused/convenience attack surface, and support
  signed reproducible packaging/rollback.
- Require formatting, lint/static analysis, race detection where available, parser fuzzing,
  and no ignored errors in security/durability/process/network paths. Every suppression
  needs reason, owner, and review.
- Document public interfaces, invariants, lock/order rules, failure/recovery, security
  assumptions, and operator runbooks. Material changes require ADR and compatibility review.
- Require focused review for crypto, identity/auth, consensus, migrations, paths, process
  execution, and updates. No critical path ships with placeholder behavior, unowned TODO,
  fail-open flag, skipped test, or platform-disabled security/durability.
- Implement native Windows/macOS/Linux adapters and tests; do not fake parity by weakening
  the hardest platform.

## 12. Regression and Test Strategy

### 12.1 Policy and tiers

Every bug fix starts with a failing reproducer at the lowest meaningful layer; the permanent
test MUST fail on unfixed code. Security fixes include exploit and nearby negative cases.
Random tests record seed/trace. Flaky quarantine requires owner, issue, reason, and near
expiry. Protocol, migration, reducer, consensus, or security changes cannot merge without
compatibility coverage. Redefining the outcome of an already-released
`(kind, schema_version)` pair cannot merge at all (§5.5). Fixtures use no production keys,
repositories, or activity.

| Tier | Gate |
|---|---|
| Unit | Every commit |
| Component, contract, integration | Every PR |
| Native system matrix | Main/nightly and release |
| Fuzz, fault, performance, soak | Nightly |
| Signed multi-device acceptance | Release candidate |

Production components expose constructor/test-build seams for clocks, secure randomness,
network/fault proxy, Raft transport/store faults, filesystem/disk, process/Git,
credential store, and SQLite failpoints. Production wiring always uses real secure
implementations. Every daemon test uses isolated config/workspace/DB/credentials/ports/
Git store/quarantine, an isolated supervisor registry root, and never user configuration or the real
per-user state location.

### 12.2 Unit, component, and compatibility coverage

Required unit/component subjects:

- JCS canonicalization against the RFC 8785 test vectors; rejection of floating-point values
  in signed fields; verification of an object carrying an unknown field; rejection of a
  correct signature presented under the wrong domain label; `device_id` derivation vectors;
  identical signed bytes and signatures for the same object on Linux, macOS, and Windows;
- task/plan states; signatures/auth/idempotency; canonical encoding/compression;
- event kinds: every §5.4 kind accepted with a minimal valid payload; an unknown kind
  rejected identically on all replicas; a payload with an unknown field rejected at
  `schema_version` 1; each kind rejected when proposed by an insufficient role or a
  disallowed `actor_type`; CAS kinds rejected without `expected_entity_version`; create
  kinds rejected when one is supplied;
- generated context: every §7.3 group present, bounds enforced with truncation declared in
  the payload, `context.md` rendering the same fields as `context.json`, peer-authored
  strings carrying provenance, control characters escaped, and atomic replacement never
  exposing a partial file;
- snapshot plus replay equivalence and deterministic projection rebuild;
- projection digest (§5.6): identical on comparable replicas at the same `chain_index`;
  unchanged by a vacuum, a rowid reuse, or a differing insertion order; changed by any
  covered-field change; unaffected by an excluded table; a deliberately corrupted row
  detected at the next checkpoint and failing closed rather than self-repairing;
- version skew: every §5.5 halt rule, plus that a halted replica never stores a local rejection
  for an entry a newer replica accepted, and a too-old daemon refuses to join; a
  `cluster_min_version` raise reads only committed device reports, rejects while any active report
  is old, and produces the same verdict with contradictory ephemeral presence on every replica;
  upgrade/downgrade reports are self-device-only and a binary below the committed minimum cannot
  report or serve;
- catch-up batches (§5.3): a reordered, omitted, inserted, or mutated event breaks the
  recomputed chain and the batch is rejected with the cursor unmoved; a batch signed by a
  non-member is rejected; `cursor_too_old` forces snapshot-plus-tail rather than a silent gap;
  `after=N` is interpreted as `chain_index`;
- successor chain (§3.1): a recovered generation's first event chains from the predecessor's
  final hash, `chain_index` does not restart, and the lineage verifies across the boundary;
- credential objects (§4.6): a peer verifies a discovery datagram using `epoch_public_key` from
  the committed authorization alone; a certificate whose fields disagree with the committed
  object is refused; a peer that has not applied the authorizing index refuses and retries;
- publications (§7.2): quarantine rejects a bad bundle digest, missing prerequisite, malformed
  graph, metadata/path mismatch, wrong signer or voter-set version, duplicate signer, and a
  below-majority receipt set; the metadata digest changes with every immutable proposal field but
  not receipts, state, or `entity_version`; a voter receipt is issued only after durable import;
  concurrent applies on one canonical version produce one winner; canonical CAS and publication
  state update atomically; a target-set change invalidates old quorum credit; local ref
  reconciliation never touches `HEAD`, index, working tree, or user refs; an agent cannot publish
  another session's worktree or review its own;
- control-file approval (§8.4): approving on one device never propagates, the approval row is
  absent from every replicated table and from the digest, and applying writes the verified
  content atomically into a path that remains excluded from drafts and publications;
- halted voter (§5.5): does not campaign, surrenders leadership if held, still votes for others,
  and does not stall the leader's commit index;
- chain construction (§5.2.1): identical `chain_hash` on every replica at the same
  `chain_index`; `chain_index` densely counting accepted events while `log_index` gaps over
  rejections and configuration entries; a nonvoter fed only accepted events reproducing the
  voters' chain exactly; rejection of a batch or snapshot whose recomputed chain disagrees
  with its stated digest; checkpoint signature verified against committed membership; a
  checkpoint disagreeing with local chain state raising a divergence alarm rather than being
  applied;
- proof that no signed proposal contains ordering metadata, and that a replica never
  requires a pre-commit index from the Raft library (§5.2);
- ID generation/binding/non-reuse; agent grace/lease/origin isolation;
- ownership release (§6.4): a task claimed by a session that then ends returns to `ready` with
  `release_reason = session_ended` on every replica and is then claimable by another agent;
  reassignment persists `intended_device_id`, rejects a claim from every other device, clears the
  intent on the target's successful claim, and remains visibly blocked if the target is revoked;
  force-release clears owners and intent; all overrides are audited and reject a non-owner caller;
  MCP exposes no override verb; an unresolved merge conflict refuses `in_progress -> done`;
- lease expiry (§6.3): an idle session expires a lease by wall time; arbitrarily high event volume
  does not accelerate it; renewal-before-expiry and expiry-before-renewal each produce one CAS
  winner; an old timer cannot release the renewed version; leader restart/election reconstructs
  deadlines, and a snapshot-imported lease uses the conservative local fallback;
- task graph: every edge in the §6.3 table accepted, every absent edge rejected identically
  on all replicas; terminal states admit no outgoing edge; dependency cycles rejected,
  including a cycle that only closes when two concurrently proposed edges are both applied;
- simultaneous claims/path overlaps; actor-argument spoof rejection;
- admission depth limits (§10): a member exceeding one is throttled and audited rather than
  dropped, every replica reaches the same verdict, and one noisy member cannot starve
  another;
- credential epochs/revocation; membership/voter/old-term validation;
- credential clamps (§4.6): an epoch other than current+1, a validity other than 1800 s,
  an `issued_at` before the five-minute renewal window, an incorrect deterministic
  `not_before`, a reused key digest, or a role above committed membership is rejected by
  every reducer even when the leader forwards it; the old credential expires on its
  original schedule despite overlap and more than one future authorization cannot be
  stockpiled;
- pairing (§4.5): an invite proof replayed on a second connection fails channel binding; a
  crash between consumption and response leaves the invite consumed; three proof failures
  void it; the outstanding-invite cap and TTL are enforced; SAS mismatch voids the invite
  with no retry; both sides derive the same SAS from the transcript;
- rekey plane (§4.6): both nonce/exporter proofs bind session and recovery generation;
  wrong-key, cross-session, cross-generation, replayed, expired-epoch-only, and revoked
  proofs fail; requests are rate-limited per source and claimed device; a responder catches
  up membership before forwarding; a nonvoter cannot open Raft yet still renews, receiving only
  the authorization `chain_index` and `not_before`; and every ordinary REST/SSE, §5.3 logical
  snapshot *endpoint*, Git/artifact, membership, policy, and agent operation is
  structurally unreachable under the rekey ALPN — the library's internal `InstallSnapshot`
  being the one deliberate exception (§4.6);
- rekey admission versus authorization (§4.6): a revoked device is admitted by a peer that
  has not applied its revocation, yet still cannot obtain a credential because the forwarding
  voter's leader-confirmed membership excludes it; once a majority has applied the revocation
  it cannot reach enough peers to win an election; the two checks are proven to be separately
  enforced rather than one standing in for the other;
- rekey target/configuration disagreement (§3, §4.6): an active device removed from the target
  but still present in the live Raft configuration can exchange votes and restore quorum after all
  credentials expire; an active target addition cannot carry consensus traffic before `AddVoter`;
  a revoked live-config voter is refused and the resulting quorum loss fails closed;
- rekey plane data confinement (§4.6): a stale voter that holds post-revocation entries and
  admits a revoked device sends it **no** log entries and no snapshot, proven by asserting on
  the bytes exchanged pre-election; a non-leader never replicates; and a compacted-log voter
  is caught up by `InstallSnapshot` **only** after an election and only from the leader, on a
  cluster whose logs were genuinely compacted past the sleeper's last index;
- quorum authority (§3): a cluster with two replicas halted at different indices (§5.5) and a
  third current computes one identical quorum size from the committed configuration; a replica
  whose applied membership differs is proven not to alter vote counting;
- voter-set reconciliation (§3): `membership.device_revoked` and `membership.voter_set_changed`
  commit a sorted, unique, active-only legal resulting set on every replica; a newly elected
  leader performs an apply barrier before reading it; additions enter as nonvoters and reach a
  post-add checkpoint before promotion; both a library progress API and the authenticated target
  apply-proof path are exercised, while a generic barrier/index claim is rejected; snapshot install
  plus tail precedes the proof; `{A}→{B}` promotes B and transfers leadership before
  removing A; `{A,B,C}→{A}` with C unreachable removes C before B; every call uses fresh
  `prevIndex`; a crash mid-sequence is completed from target and configuration alone; a stalled
  transition never rolls back or promotes an uncaught-up voter; a leader depending on rekey issues
  no configuration call until ordinary transport returns;
- voter-set CAS (§3, §5.4): `voter_set_changed` is rejected on a stale `voter_set_version`, and a
  `device_revoked` proposed concurrently with a `voter_set_changed` is rejected on a stale
  `expected_voter_set_version` rather than committing a target computed from a superseded set;
  both replicas reach the same verdict; the per-device `voter` view always agrees with the
  committed set;
- rekey leader apply gate (§4.6): a leader that has been elected but has not yet applied through
  its committed membership index replicates **nothing** on the rekey plane, so a device revoked
  in that unapplied backlog receives no entries even from the legitimate leader;
- version-halt interaction (§5.5, §4.6): a halted voter still grants rekey votes and keeps
  accepting `AppendEntries` — never serving entries, per the leader-only rule — so one
  up-to-date voter can lead; a fully halted majority with expired credentials
  surfaces the version blocker and does **not** offer §3.1 recovery;
- expired epoch key lifecycle (§4.4): the retained key is erased when a replacement activates,
  on applying own revocation, and on leaving the session; a revoked device stops advertising;
- discovery receiver rules (§4.4): cheap checks precede signature work, a future or expired
  `expires_at` is rejected, the nonce cache is bounded per source and evicts oldest-first, a
  repeated nonce is dropped, a sibling session's datagram is ignored without penalty, and
  a valid `rekey` advertisement signed by the latest expired epoch key is only an endpoint
  hint and never authenticates an ordinary connection;
- control files, terminal sanitization, redaction, cross-platform paths;
- deterministic conflicts (§8.3): independent daemons derive one `conflict_id` for the same tuple;
  duplicate detection is idempotent, changed fields under one ID fail closed, task blocking is
  derived once, and only an applied publication with staging-verified ancestry can resolve it;
- Git argv/environment, bare-store/ref allowlists, quarantine, bundle/draft/publication metadata,
  and proof that checkout/reset/stash/clean/branch switching on one peer never mutates another;
- real SQLite WAL/transactions/checkpoint/migration/backup/corruption/recovery;
- real three-voter Raft election/replication/membership/snapshot/replay.

Do not mock SQLite or Raft when testing their behavior. Immutable golden fixtures cover
§4.1-canonical events/batches/signatures, voters/credentials, rekey identity certificates
and nonce/exporter proofs, snapshots, REST/capabilities, MCP schemas/instructions,
control-file proposals, Git metadata, and every released DB schema. Prove previous protocol
interop, unknown optional/required behavior, cross-platform signature stability, all
historical migrations, migration+replay digest, snapshot+tail equivalence, and recoverable
failed migration. Fixture changes require explicit protocol/schema review.

### 12.3 Integration harness

`internal/testharness` is a V1 deliverable. It launches supervisors with isolated registries,
1/3/5 voters, nonvoters, current/retained prior daemons, devices joined to several workspaces
at once, many simulated Codex/Claude clients, and real Git
repos/worktrees, fault proxy, and isolated fake native stores where native behavior is not
under test.

Faults: partitions, latency, duplication, truncation; leader/voter/peer crashes at
Raft/SQLite boundaries; connection closure; skew/clock jumps/30-minute rollover; disk full,
permission, short write, rename failure; Git child crash/hang, truncated artifact and quarantine
failure; dropped agent heartbeats;
host suspend and resume; local address change and interface disappearance; one or every
voter waking after multiple expired epochs, with and without a reachable majority.

After quiescence, **comparable** replicas — same `digest_version` and `schema_version`
(§5.6) — at the same `chain_index` MUST have equal projection digests. Replicas of differing
versions are compared only on the version-independent subset their shared `schema_version`
defines, and a mixed-version cluster MUST additionally show that the older replica either
applied every entry identically or halted cleanly at a `min_apply_version` it could not
satisfy (§5.5). All replicas MUST have valid SQLite, unique IDs/sequences, expected listener
exposure, and no leaked child/port/temp root. Security cases require audit events and
artifact scans for invite/credential leakage.

Core scenarios:

1. Pair and verified Git bootstrap; source dirty/untracked content arrives as an inspectable draft
   while the joiner's canonical working tree, index, `HEAD`, and user refs remain unchanged.
2. Multiple same-device Codex-only, Claude-only, and mixed sessions.
3. Local/remote task races; one winner; overlapping/non-overlapping worktrees.
4. Shared-root lease conflicts/warnings; idle and high-event-rate expiry, renewal/expiry CAS races,
   leader timer reconstruction, adapter resume, and ID non-reuse.
5. Kill an agent mid-task: its claim and leases release automatically, another agent claims
   the same task, and operator force-release plus reassign works on a task whose owning
   device never returns; every non-target device is refused before the named device claims.
6. Isolate one of three voters: majority commits, minority queues, then converges.
7. Prove minority cannot commit, self-promote, or renew credentials.
8. Drop/duplicate/delay/truncate catch-up; resume cursor; equal projection.
9. Current/previous version and schema replication; snapshot-at-`N` plus tail; a
   v1.0 follower in a v1.1-led cluster halts safely at an entry it cannot apply,
   reports a version blocker, and converges after upgrade rather than diverging; a minimum-version
   raise uses committed reports and is unaffected by contradictory presence.
10. Crash after Raft commit before SQLite apply; idempotent replay.
11. Restart during Git bootstrap, artifact quarantine/import, and ref reconciliation; recover
    deterministically without exposing a partial ref.
12. Rotate 30-minute credentials make-before-break during active control/Git transfer and a forced
    leader election; old connections close at their original expiry and no transfer loses
    acknowledged data.
13. Suspend a device past its epoch and change its address while asleep, then wake it:
    it advertises `rekey`, re-dials, renews, and converges with no operator action. Then
    suspend every voter overnight for multiple epochs and wake a majority with no valid
    session credential: they mutually authenticate on the rekey ALPN, elect/catch up,
    authorize fresh epochs, and restore ordinary Raft. Repeat with only a minority awake:
    no credential or ordinary traffic is authorized, local reads still work, and recovery
    occurs automatically when enough voters return.
14. Revoke during artifact transfer and rekey attempts; every peer that has applied it closes
    ordinary, Git, and rekey access; a stale peer that admits the device still sends it no entries or
    snapshot; the committed voter target excludes it and the leader reconciles the live
    configuration; and a stale minority cannot renew the former member.
15. Run checkout, stash, reset, clean, and branch switches while peers hold divergent work; no
    operation mutates a peer. Replicate and restore drafts, race two publications from one base to one
    canonical winner, derive one conflict row from duplicate detectors, and resolve it through a
    reviewed ancestry-verified publication without losing either side.
16. Hold control-file changes for independent local approval.
17. Kill leader during transfer between survivors; transfer continues and a new
    leader resumes strong commits.
18. Remove a permanently lost voter, add a caught-up replacement, and retain existing trust;
    exercise `{A}→{B}`, a 3→1 removal with one unreachable extra, leader transfer, crash after
    every configuration step, target change mid-transit, and an indefinitely stalled transit.
19. Lose quorum; fail closed; let every credential expire; then recover offline —
    once authorized by a surviving owner device, and once by the recovery key with no
    owner device present — and re-pair survivors into the successor generation.
20. Prove a recovered session and a survivor of the prior generation refuse to
    interoperate, and that a minority cannot run recovery without operator
    authorization.
21. Exhaust Raft/SQLite/Git-artifact disk; no acknowledged event or publication loss and no ref
    update without durable verified objects.

Same-device regression additionally proves hundreds of unique **agent** sessions within one
CodeComm session, identical labels remain distinct, no actor/origin cross-talk, correct
grouped presence/claims/leases, local visibility without network, worktree ownership,
shared-root honesty, and 32-agent responsiveness.

Multi-session regression proves, on one device with two or more joined workspaces: correct
daemon selection by flag, by working-directory ancestry, and by sole-registry-entry fallback,
with an explicit failure listing candidates when ambiguous; no shared state, port, socket, or
Git store/quarantine/ref namespace between sessions; one device identity key reused across sessions while
credential epochs and roles stay independent; a killed session daemon restarting without
disturbing its sibling; supervisor restart reconciling a registry containing one live and one
dead entry; refusal to start a second daemon for one workspace; the concurrent-session cap
refusing rather than evicting; and an MCP client remaining bound to its resolved session for
its lifetime.

### 12.4 Security, platform, and longevity

Security tests cover spoofed discovery/genesis, invite replay/guessing/leakage,
expired/revoked/stale credentials, rekey ALPN confusion or ordinary-API access, stale
minority rekey, identity-proof replay, stale leaders/unauthorized voters, forged and
replayed checkpoints, a tampered event inside an otherwise valid exported range, a chain
segment spliced from a different session, cross-context signature reuse under the wrong
domain label, cross-session Git store/ref/receipt confusion, network reachability of local APIs,
actor/resume spoofing, remote agent control attempts, `receive-pack`/user-ref/arbitrary-OID
requests, malicious control files, tampered bundles/binaries/updates, shell metacharacters,
hooks/helpers/filters/alternates/submodules/LFS,
traversal/symlink/Windows names, forged/replayed/oversized events, decompression bombs, inert
SQL/page/WAL payloads, secrets, and terminal escapes.

Continuously fuzz discovery, invites, event/batch/snapshot decoding, paths, ignore rules, MCP
args, REST, Git ref advertisements/staging receipts/artifact manifests, ordinary and rekey
certificate extensions, and the closed rekey dispatcher; retain minimized crashes. CI runs
secret/dependency/license/SBOM/static scans
and verifies artifacts after signing.

Native tests use Linux case-sensitive FS, default macOS APFS plus one case-sensitive volume,
and native Windows NTFS/named pipes/Credential Manager/Task Scheduler/Firewall on supported
x86-64/ARM64. Cover service lifecycle, IPC ACL, credential store, firewall, multicast
interfaces, Ethernet/VPN, Git, path limits, sleep/wake, and reboot. PRs use MCP
simulators; nightly/release smoke supported installed Codex/Claude versions. TUI golden/PTY
tests cover narrow/normal/wide terminals, long IDs, hostile control characters, `NO_COLOR`,
and a monochrome profile proving every state at §9 is distinguishable without color.

Benchmarks track event/transaction/projection throughput, catch-up at 1/10k/1M events, one
session at 8 devices/32 agents/100k files/2 GiB, one device at the concurrent-session cap
running that many daemons and Git stores at once, bootstrap/publication/draft bundles, and large
TUI histories by commit/OS. Material regression requires review. Seeded nightly soak/chaos
spans many credential epochs, elections, voter changes, artifact resumes, agent churn,
checkpoints, drafts, publications, and restarts.

### 12.5 Gates

Every PR: format/lint/static/dependency policy, unit/component, race detection,
contract/golden/migration, bounded multi-daemon, same-device multi-agent, security regression,
and critical-module coverage floors without unexplained decrease.

The mechanically checkable part of §11's production-quality criterion maps to named gates:

| §11 requirement | Enforcing gate |
|---|---|
| Explicit boundaries, acyclic dependencies | Import-cycle and layering lint |
| No ignored errors on security/durability/process/network paths | `errcheck`-class lint, no blanket suppressions |
| Deadlines and cancellation propagated | `lostcancel`-class lint plus a context-propagation test at each boundary |
| Peer, repository, or input errors never panic the daemon | Panic-boundary test driven by the existing fuzz corpus |
| Every bound has a configured value | Conformance test asserting each §11.2 constant is set and within range |
| No secrets in URLs, argv, env, or logs | Artifact scan over logs, crash reports, and process metadata |
| Insecure dev wiring absent from releases | Build-tag check that no release artifact contains it |

The judgement-based remainder of §11 — naming, altitude, documentation quality — is a review
checklist item, not a gate.

Nightly/main: full native matrix, fuzz, fault, performance, and soak.

Release: all OS/architecture packages; upgrades from supported DB/protocol versions;
install/reboot/join/revoke/elect/replace-voter/recover-quorum/uninstall/rollback; physical or
VM Ethernet/VPN multi-device run including all voters waking with expired credentials;
Codex/Claude smoke; SBOM/dependency/signature verification; zero unresolved critical/high
security or data-loss failures. Retained diagnostics MUST be redacted; leaking test artifacts
block release.

## 13. Delivery

1. **Security/dependency spikes:** threat model/ADRs; Raft/library/store review and 3-voter
   crash/election spike; prove the maintained Raft transport can switch to the restricted
   identity-authenticated rekey path without custom consensus, and prove §3's target-applied
   checkpoint fallback without a public `matchIndex`; mTLS
   pairing, revocation, 30-minute rotation, and all-voters-expired cold start;
   multicast/Ethernet/VPN on all OSes; system-Git bundle/protocol-v2/quarantine/ref-policy spike;
   prove local APIs unreachable; establish native CI/harness.
2. **Local coordination:** daemon/SQLite/reducers/local API/TUI; agent registry, MCP/CLI
   adapters, worktrees, control-file review; permanent local multi-agent and DB recovery
   tests.
3. **Secure mesh:** discovery/pairing/membership/roles/revocation; direct mTLS, SSE/resume;
   Raft replication/election/voter changes; 30-minute quorum credentials and restricted rekey
   transport.
4. **Git bootstrap:** bounded bundle transfer/verification/clone, immutable dirty/untracked draft,
   progress/cancel/expiry/recovery, cross-platform preflight.
5. **Git object/ref mesh:** session bare stores, read-only upload-pack, drafts, quorum-staged
   publications, canonical-ref CAS, deterministic merge conflicts, retention, and revocation.
6. **Hardening:** optional activity hooks, signed installers/services, native
   E2E/security/performance, backup/export/compaction, voter/quorum recovery.

Every phase retains foreground development mode and automated gates. No phase adds custom
consensus, crypto, Git-object, or merge engines. Every phase MUST also close the open questions §15
assigns to it before it exits.

Phase 2 is the **walking skeleton**: one device, one session, a real single-voter Raft per §3,
real SQLite, two MCP clients, and a task claimed by one and observed by the other. It
exercises the whole vertical — event, consensus, reducer, projection, context, adapter — and
every later phase widens it rather than replacing a layer.

Exit criteria as demonstrable facts:

| Phase | Exits when |
|---|---|
| 1 | The real Raft library needs no pre-commit event index (§5.2); reconciliation proves targeted transfer, single-server changes, and the target-applied checkpoint fallback without public per-follower progress, including snapshot catch-up, `{A}→{B}`, unreachable-voter 3→1, crash at every step, and all-expired rekey during target/configuration disagreement; inability to prove the fallback selects another maintained library before exit; a 3-voter spike survives crash/election; Git quarantine/ref policy and JCS/signature fixtures pass on all OSes; local APIs are remotely unreachable |
| 2 | The walking skeleton runs; three concurrent MCP clients hold distinct `agent_session_id`s; local task and lease races produce one winner; idle/busy lease expiry and intended-device claims pass; a `SIGKILL`ed daemon recovers with an unchanged projection digest; every §5.4 kind round-trips; OQ1 is closed |
| 3 | Two devices pair with SAS confirmation and no manual endpoint entry; a 3-voter cluster elects, replicates, and changes voters; 30-minute credentials rotate under load without dropping links; after every voter sleeps through multiple epochs, a waking majority restores ordinary Raft through rekey; a revoked device is refused within §14's target; OQ2 is closed |
| 4 | A joiner bootstraps from a verified bundle over mTLS; dirty/untracked work arrives only as an immutable draft; interrupted transfer resumes; the joiner's index, `HEAD`, user refs, and working tree remain untouched |
| 5 | Eight devices exchange drafts and publication objects directly; a voter-target majority stages each applied publication; concurrent canonical CAS has one winner; branch/reset/stash operations remain local; duplicate conflict detectors converge and a reviewed merge resolves the conflict; revocation stops object access |
| 6 | Signed installers on all three OSes; the §14 targets are confirmed or revised with recorded evidence; backup, export, and quorum recovery are exercised end to end including the recovery-key path |

## 14. Service Targets

Each latency target names its start point, end point, and enforcing gate. Workload is one
session at 3 voters, 8 devices, 32 agents, 100k files, and 2 GiB on a quiet gigabit LAN unless
stated.

| Metric | From | To | Target | Gate |
|---|---|---|---|---|
| Coordination visibility | `POST /v1/events` accepted at the origin | that event applied and visible in a peer's `context.get` | p95 <500 ms | Nightly performance |
| Same-device visibility | MCP call accepted | visible to another agent on the same daemon | p95 <100 ms | Per-PR multi-agent |
| Draft visibility | eligible last write closed on the origin | immutable draft ref and verified 1 MiB object available on one peer | p95 <10 s | Nightly performance |
| Canonical materialization | `publication.applied` committed | verified object and `refs/codecomm/canonical` updated on a reachable peer | p95 <2 s | Nightly performance |
| Reconnect after brief drop | link restored | control and Git transfer available | p95 <5 s | Nightly fault |
| Leader replacement | leader process killed | new leader committing | p95 <5 s | Nightly fault |
| Revocation effect | `membership.device_revoked` committed | revoked device rejected on ordinary and rekey planes by every peer that applied it | <5 s | Per-PR security |
| Single-device wake recovery | expired member resumes while a current voter quorum is reachable | ordinary credential renewed and peer/Git links restored | p95 <15 s | Nightly fault |
| All-expired cold start | last voter needed for majority resumes after every voter exceeded multiple epochs | fresh credentials issued and normal Raft commits again | p95 <30 s | Nightly fault |
| Catch-up | nonvoter starts 10k events behind | applied index equals committed | p95 <30 s | Nightly performance |

Resource budgets, at two scopes because §3.2 allows several session daemons per device:

| Budget | Ceiling |
|---|---|
| Idle session daemon RSS | 150 MiB |
| Idle session daemon CPU | <1% of one core |
| Device at the concurrent-session cap | 800 MiB RSS and <4% of one core total |
| Supervisor | 30 MiB RSS, <0.1% CPU; it holds no session state |
| Coordination state growth (`state.db` + `consensus/`, excluding Git objects/artifacts) | ≤50 MiB per 10,000 committed events before compaction |

These values are provisional until the phase-3 benchmarks in §12.4 confirm or revise them with
recorded evidence; each MUST be confirmed or revised before phase 6, and a revision requires
review. They are not advisory in the meantime: a regression against the current recorded value
fails its gate.

The following are invariants, not targets, and live in §2.5: no acknowledged event loss, commits
continuing after one voter loss with three voters, surviving-peer transfers continuing through
leader loss, exactly one winner for concurrent strong claims, no duplicate or reused active
agent IDs, no silent conflict loss, and no remotely reachable MCP or write-capable Git endpoint.

## 15. Open Questions

Each question names an owner, the phase gate by which it MUST be closed, and what changes under
each answer. Anything §1 or §2.2 decides is not listed here.

**OQ1 — Activity privacy.** Are tool and command names, paths, status, and redacted summaries
sufficient, with no raw arguments or output? *Owner:* security reviewer. *Close by:* end of
phase 2, before the activity projection is frozen as a fixture. *If sufficient:* §5.2's
exclusion list is final. *If not:* an opt-in higher `capture_level` with its own consent and
redaction rules, never on by default.

**OQ2 — Scale.** Are 2-8 devices, 100k files, 2 GiB per workspace, and 100 MiB per file — all
per session (§3.2) — representative, and is a 4-session per-device cap right? *Owner:* product.
*Close by:* end of phase 3, when the §14 benchmarks first produce real numbers. *Either way:*
§11.2 values change but no mechanism does.

Resolved during review: plan authority is owner-only selection with editor proposal (§4.3,
§6.1); a configurable knob would have to be committed genesis policy or reducers would disagree.
Repository synchronization is Git-native only: working-tree replication was rejected because
ordinary branch/reset/stash operations become destructive remote edits; §8's immutable drafts
retain eligible dirty/untracked work without that hazard.

## 16. Key Risks

1. Authorized source/docs can influence agents; provenance/control paths cannot replace sandbox
   and approvals.
2. Strong writes/renewal require quorum; two devices cannot tolerate one loss.
3. Incorrect Raft transport/store/snapshot/membership/apply integration can violate safety
   despite using a mature library. The phase-1 spike MUST confirm on the real library API that
   no code path needs a pre-commit event index (§5.2), and that reconciliation can prove a target
   applied the post-add checkpoint and transfer leadership as §3 requires; failure forces a
   library change, never an inferred catch-up state.
4. The long-lived-identity rekey listener is deliberately narrow but security-critical:
   ALPN confusion, stale membership, or an overbroad dispatcher could bypass epoch expiry.
5. Eight devices can concurrently fetch from seven peers per session; bound Git children,
   connections, bundle sizes, pack CPU, disk amplification, and aggregate load at the
   concurrent-session cap.
6. Publication events and Git objects are separate durability planes; receipt verification,
   retention pins, quarantine import, and ref reconciliation must prevent a committed canonical
   pointer from becoming unavailable or exposing unverified content.
7. Filesystem case, Unicode, Windows names, symlinks, permissions, and path limits can block
   repositories.
8. MCP cannot observe all actions; agents may ignore workflow; `capture_level` and adapter
   ergonomics must remain honest.
9. Telemetry can leak secrets; collect narrowly and redact before persistence.
10. Git LFS/submodules/filters/alternate stores exceed plain-bundle semantics.
11. Shared-root agents can bypass leases; immutable drafts preserve but do not prevent conflicting
    edits, so canonical publication still requires reviewed ordering and explicit merge.

## 17. ADR Backlog

- ADR-001: Direct mTLS mesh and replaceable Raft leader.
- ADR-002: Origin-signed append-only events, deterministic projections, and an apply-time event
  chain with periodic committed leader checkpoints; ordering metadata is unsigned local
  provenance.
- ADR-003: Ed25519 signatures, SHA-256 digests, RFC 8785 JCS canonical form, and per-context
  domain separation; stable identity plus quorum-authorized rotating TLS keys with a committed
  V1 epoch length of 30 minutes and two-minute make-before-break overlap.
- ADR-004: Multicast discovery with manual fallback.
- ADR-005: REST/SSE plus internal Raft and bounded Git artifact/upload-pack endpoints.
- ADR-006: Workspace identity independent of directory name.
- ADR-007: Never copy `.git/` state or remotely mutate a working tree; use validated Git plumbing
  and CodeComm-owned refs.
- ADR-008: Direct Git object/ref mesh with immutable source-namespaced draft snapshots.
- ADR-009: Rationale summaries, not chain-of-thought.
- ADR-010: No V1 relay; Ethernet/user VPN fallback.
- ADR-026: Endpoint hints are gossip with a TTL, never committed state; churn and suspend/resume
  are first-class recovery paths.
- ADR-011: Verified Git bundle bootstrap.
- ADR-012: Local stdio MCP for Codex and Claude Code.
- ADR-013: Per-device approval for control files.
- ADR-014: Native Windows V1 support.
- ADR-015: Direct rotating mTLS authorization for Git object/ref transfer.
- ADR-016: Unique agent sessions and isolated worktrees.
- ADR-017: Per-session SQLite, one database per joined workspace, with logical replication.
- ADR-018: Event batches/snapshots, never SQLite diffs.
- ADR-024: Frozen reducers per `(kind, schema_version)`; halt rather than diverge on an
  unappliable committed entry; N-1 supported skew.
- ADR-025: Normative projection digest over declared tables, with divergence detection at
  committed checkpoints.
- ADR-019: Permanent regression harness and release gates.
- ADR-020: Maintained embedded Raft and production stable store.
- ADR-021: Production engineering requirements are release criteria.
- ADR-028: Named version floors and a single constants table splitting committed policy from
  local configuration.
- ADR-029: Measurable service targets with named endpoints and enforcing gates; resource budgets
  at daemon and device scope.
- ADR-030: Owner and editor roles only; no read-only role in V1, and no confidentiality
  boundary between members.
- ADR-031: Signed catch-up batch contract with `chain_index` cursors and checkpoint-anchored
  ordering proof.
- ADR-032: Quorum-staged publication bundles plus an atomic replicated canonical-ref CAS; local
  Git ref materialization is asynchronous and never touches user state.
- ADR-033: 30-minute session credentials plus an identity-authenticated, quorum-gated
  cold-start rekey plane; admission and authorization are separately gated; pre-election traffic
  carries no data and only an elected leader replicates.
- ADR-034: Voter changes as a committed resulting-voter-set intent driven by idempotent
  ordered single-server reconciliation; active application membership gates connection access,
  while the live Raft configuration alone gates consensus traffic and quorum; promotion requires
  a target-applied post-add checkpoint proof, not an inferred match index.
- ADR-035: Lease wall time schedules a versioned committed release; reducers never read clocks or
  infer elapsed time from event volume.
- ADR-036: Daemon versions are committed device state; cluster minimum raises never read presence.
- ADR-037: Reassignment persists a one-shot intended device, and merge-conflict identity is a
  deterministic digest of immutable Git inputs.
- ADR-027: Offline quorum recovery with a successor genesis record, an offline recovery key, and
  re-pairing of survivors.
- ADR-022: Device as sole principal; no user or account identity.
- ADR-023: Per-user supervisor service plus one session daemon per joined workspace.

## 18. References

Protocol and format:

- RFC 2119 / RFC 8174, requirement keywords: <https://www.rfc-editor.org/rfc/rfc8174>
- RFC 8785, JSON Canonicalization Scheme: <https://www.rfc-editor.org/rfc/rfc8785>
- RFC 8032, Ed25519: <https://www.rfc-editor.org/rfc/rfc8032>
- RFC 9562, UUID v7: <https://www.rfc-editor.org/rfc/rfc9562>
- RFC 8446, TLS 1.3: <https://www.rfc-editor.org/rfc/rfc8446>
- SPAKE2+: <https://www.rfc-editor.org/rfc/rfc9383>

Dependencies:

- Raft paper: <https://raft.github.io/raft.pdf>
- `hashicorp/raft`, the candidate library: <https://github.com/hashicorp/raft>
- Git bundles: <https://git-scm.com/docs/git-bundle>
- Git protocol v2: <https://git-scm.com/docs/protocol-v2>
- Git `upload-pack`: <https://git-scm.com/docs/git-upload-pack>
- Git `update-ref`: <https://git-scm.com/docs/git-update-ref>
- Git `commit-tree`: <https://git-scm.com/docs/git-commit-tree>
- Git `merge-tree`: <https://git-scm.com/docs/git-merge-tree>
- Git worktrees: <https://git-scm.com/docs/git-worktree>

Agent integration:

- Model Context Protocol: <https://modelcontextprotocol.io/specification>
- Codex MCP: <https://developers.openai.com/codex/mcp>
- Codex `AGENTS.md`: <https://agents.md>
- Claude Code MCP configuration: <https://docs.claude.com/en/docs/claude-code/mcp>
