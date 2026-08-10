# CodeComm V1 Design — Part 01: Overview, Problem, and Scope

Part 1 of 14. Contents: Front matter, §1 Problem and Approach, §2 Scope and Invariants.
Section map, review status, and reading order: [README.md](README.md)

Authoritative revision 0.14; maintained only in this split set.

---

# CodeComm V1 Design

Status: Accepted for implementation  
Date: 2026-08-10  
Revision: 0.14  
Owner: ijonahch (solo maintainer)  
Reviewers: none — solo project; §11's "focused review" requirement is discharged by the
self-review checklist below rather than by a second person  
Audience: Engineering  

**Self-review checklist** (replaces second-person review where §11 and §12.1 require "focused
review", and where §2.5 requires an ADR to weaken an invariant). Before merging a change that
touches cryptography, identity, credentials, consensus, reducers, migrations, path handling, or
process execution, the owner MUST, in writing on the change:

1. name the invariant(s) in §2.5 the change could weaken, and either show it does not or write the
   ADR;
2. confirm the change adds no reducer input outside committed state, and reads no wall clock in a
   reducer;
3. confirm any new `(kind, schema_version)` outcome is new rather than a redefinition (§5.5);
4. confirm every new bound has a normative value in its owning schema or §11.2 and a conformance
   assertion (§12.5);
5. state which §12.2/§12.3 test covers the change, and link the failing-first reproducer.

A change that cannot satisfy all five does not merge. This is weaker than a second reader and is
recorded as such: §16 carries it as a risk.

Normative terms follow RFC 2119/8174; declarative requirements and table rows headed "MUST" or
"Required" are equally normative.

Revision history: 0.14 closes the split-set correctness audit: canonical protocol scalars and
genesis signatures; mode-specific Raft/nonvoter evidence; one-use agent launch and canonical managed
roots; per-agent contexts; closed reducer/action/audit rules; recovery withdrawal, retention, and
readmission; exclusive CodeComm refs with expected-old-OID CAS; and matching tests/ADRs. 0.13
established dual event/result chains, activated credential authority, signed catch-up/snapshot trust,
strict local IPC, and unpruned logical history. 0.12 closed the split-document protocol audit. 0.11
selected identity-authenticated consensus plus 30-minute content credentials, Git-native sync,
publication authority, deterministic conflicts, two-device posture, activity privacy, and draft
inclusion. 0.10 introduced Git-native objects/refs, time-driven leases, persisted reassignment and
version reports, deterministic conflicts, and target-applied voter catch-up. Revisions 0.7–0.9 were
the initial design and early credential/reconciliation work; §17 retains the decision history.

## 1. Problem and Approach

Coding agents such as Codex and Claude Code work well on one machine. The moment work spans two
— a laptop and a desktop, or two people's laptops — there is no shared coordination layer:
no shared task list, no record of which agent is editing which files, and no synchronized repository
state. Agents duplicate each other's work, overwrite each other's files, or sit idle. Every existing
answer routes through a hosted service — GitHub, or a SaaS control plane — which many settings
cannot use and none should need for machines sitting on the same network.

CodeComm is a local-first TUI/CLI and local daemon that coordinates coding agents across the same
or different devices and synchronizes repository state, with **no hosted relay and no data leaving
the authorized devices in plaintext**. CodeComm contacts no service of its own; network
intermediaries, including an operator-selected VPN relay, may still observe encrypted traffic
metadata (§2.3). It is for a small group — 2-8 devices, owned by one person or several
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

CodeComm itself contacts no cloud service. Direct transfer survives leader loss; strong writes
survive a peer loss only while the configured voter quorum does (§§3, 9).

**Two devices are supported, with a stated limit and a placement prompt.** A joining device is admitted as a nonvoter (§3), so
this session has one voter — laptop A — and quorum is 1. Every strong mutation (task claim,
state change, lease, plan selection) and every content-credential authorization therefore
requires laptop A to be reachable: with A's lid closed, B can read and work locally but commits
nothing, and its content links close when its credential expires. That is the normal condition
for a laptop-and-desktop pair, not an incident. **Three voters is the minimum for a session that
tolerates one device being away**, and every client MUST show a persistent degraded-tolerance
indicator below that (§3). A two-device session is supported and useful for one operator working
across two machines in the same session; it is not a highly available one.

Because the limitation bites only when the voter is unreachable, `host` and `join` MUST prompt for
voter placement whenever a session would rest at one voter, recommending the machine likelier to
stay awake and reachable — typically a desktop over a laptop — and stating in one line what the
other machine loses while the voter sleeps. An operator MAY decline and keep the default. This turns
the common failure into a rare one without adding a mechanism (§9, OQ3 resolved).

### 1.1 Alternatives considered

| Instead of | Rejected because |
|---|---|
| A CRDT or last-writer-wins task store (no consensus) | The goal is exactly one winner for a task claim (§2.2); with LWW two agents can both "win" and burn effort on one task, which is worse than a brief queue. Raft buys a single agreed order for the small set of strong decisions |
| A single designated coordinator device | For any session at 3 or 5 voters it is the permanent routing/availability dependency §2.5 forbids: losing it loses the session, whereas a replaceable Raft leader (§3) does not. A **1-voter** session deliberately accepts the same single-device dependency for strong state and content durability, with §3.1 as its recovery path; §2.5's invariant is about routing, and voter count is what sets strong-state tolerance |
| A hosted relay or Git host as the hub | Defeats the one hard constraint — no data through a third party — and needs connectivity CodeComm explicitly does not assume (§2.3) |
| One shared database over the network | Leaks unrelated and deleted rows, couples every peer to one schema, and bypasses domain authorization (§5.3); per-device SQLite with logical replication avoids all three |
| Live working-tree replication (including Syncthing) | Syncing `.git/` is unsafe (§2.4), so only the working tree could be replicated — which leaves each peer's `HEAD` and index unrelated to the arriving files, making an ordinary `checkout`, `reset`, `stash`, or `clean` an unbounded remote edit. Delete-vs-edit races resolve by resurrection or silent loss rather than a conflict copy. Git-native immutable objects and namespaced refs retain concurrent work without mutating a peer's workspace (§8) |
| Expiring credentials on the consensus plane too | A consensus channel whose authentication expires cannot recover itself: with every device asleep past expiry there is no authenticated path on which to elect a leader and authorize replacements. Answering that with a second restricted listener cost an ALPN, a closed dispatcher, a pre-election data-confinement argument, and a snapshot carve-out, and still produced an unrecoverable-lockout and a proposal-freeze defect. Identity-authenticated consensus plus epoch-bounded content keeps the only property expiry actually bought — a bounded stale-partition window on content — because revocation was always enforced at admission, not by expiry (§4.6, ADR-039) |
| Long-lived credentials on the content plane too | A peer partitioned away when an owner revoked a member would serve it repository content indefinitely. The fixed 1800 s epoch bounds that window without depending on the revocation reaching that peer (§4.6) |

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
| Transport | TLS 1.3 mTLS with plane-specific ALPNs: consensus authenticated by long-lived device identity (never expires), content by 30-minute quorum-authorized epoch keys (§4.6) |
| Coordination | Signed logical events, deterministic reducers, local SQLite |
| Repository data | Git bundles/objects and source-owned namespaced refs over direct mTLS; no remote working-tree mutation |
| Bootstrap | Verified Git bundle from any up-to-date owner/editor peer (§3) |
| Agents | Local stdio MCP for Codex and Claude Code; many instances per device |
| Isolation | Per-agent Git worktrees by default; shared root is explicit opt-in |
| Licensing | Apache-2.0; system Git is invoked, not redistributed |

The elected Raft leader orders strong mutations but carries no ordinary REST, Git, presence, or
repository traffic; losing it causes a brief election while direct peer traffic continues. Without a
voter majority, strong mutations and new content-credential authorizations MUST pause, while local
work and direct Git transfer among reachable peers continue only until current content credentials
expire (§3). The consensus plane itself does not expire, so a cluster can always re-elect and
re-authorize once a majority is reachable (§4.6).

## 2. Scope and Invariants

### 2.1 Participants and trust model

A **member device** is one CodeComm installation under one OS account, and `device_id` is its only
principal. Two OS accounts on one physical computer are separate member devices because a
per-user service cannot safely share private key material across that boundary (§3.2). Application
roles, credentials, revocation, and audit attribution all bind to a device. CodeComm has no user or
account identity.

Devices in one session MAY belong to one person or to several. No mechanism branches on
ownership: transport, consensus, repository transfer, roles, revocation, and agent coordination treat
every authorized device identically. CodeComm's own identity, authorization, and audit records
name only devices; it never collects operator identity. Git commit `author`/`committer` fields are
an exception it does not control: they are user-authored repository content, CodeComm neither
strips nor normalizes them nor relies on them for authorization, and they will identify operators
by name and email to every member (§7.2).
Each member runs one daemon for this workspace (§3.2) and MAY run many concurrent agent
sessions against it. Ownership affects only who performs a human step: at the pairing
confirmation of §4.5 step 7, two operators compare the authentication string out of
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
- Ordinary role/voter grants require an owner; the genesis-bound recovery key may restore only its
  submitting active editor to owner (§4.3). Every grant is committed and audited.

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
- replicate ordered plans, tasks, memory, leases, and activity, and exchange durable per-peer
  acknowledgement watermarks;
- support multiple Codex, Claude Code, or mixed instances on every device;
- preserve one winner for strong task/lease claims while quorum exists;
- bootstrap with Git; exchange canonical commits and eligible dirty/untracked work as immutable,
  source-namespaced draft snapshots (§8);
- preserve concurrent edits as commits or draft refs for explicit review/merge, without remotely
  mutating a member's `HEAD`, index, user refs, or working tree;
- resume idempotently after process, network, or device interruption;
- expose local MCP, CLI/JSON, TUI, and owner-restricted local IPC; and
- operate without GitHub or another hosted service on a directly routable network.

Initial targets are 100,000 files, 2 GiB per workspace, 100 MiB per file, and unpruned
session-lifetime coordination history in V1. Sessions MAY use two devices, but
automatic strong-state failover requires three voters. A two-device session is 1 voter + 1
nonvoter, so the **voter** alone retains quorum and continues committing while the nonvoter queues
every strong mutation until the voter is reachable; permanent loss of the voter requires §3.1
recovery. §1 states the consequence for the smallest session.

### 2.3 Network constraints

Multicast normally does not cross routers, VLANs, VPNs, or client-isolated Wi-Fi. A manual IP
helps only when unicast routing exists. Eduroam-like networks may block all peer traffic;
supported fallbacks are switched/direct Ethernet or a user-provided VPN such as WireGuard or
Tailscale. A user-provided overlay VPN sits outside CodeComm's trust boundary, and some
(Tailscale) use a hosted coordination service and may relay end-to-end-encrypted traffic through
third-party infrastructure. CodeComm's constraint is that *CodeComm* operates no relay and sends
no plaintext or metadata to any service of its own; an operator choosing such a VPN accepts that
provider's exposure. WireGuard between fixed endpoints, or switched/direct Ethernet, avoids it
entirely. `localhost` is never a cross-device transport. CodeComm binds only selected
non-loopback LAN/VPN interfaces and supports IPv4/IPv6 link-local use without DHCP.

Three environmental preconditions are normative because mechanisms elsewhere depend on them:

- **IPv6 link-local endpoints are interface-scoped.** Zone identifiers are host-local, so a
  link-local address MUST NOT be gossiped as a usable endpoint hint; a receiver derives the zone
  from the interface a discovery datagram arrived on (§4.4), and a manual endpoint on a
  link-local address MUST carry a locally valid zone. Multicast join is per selected interface.
- **Voters MUST be fully pairwise reachable.** Raft requires the voter majority to be mutually
  reachable, and a partially connected voter set — common with client isolation or asymmetric
  firewall rules on exactly the fallbacks above — manifests as repeated elections with no stable
  leader. `repo doctor` MUST report per-pair reachability so an operator can find a one-way path.
- **Device clocks MUST agree within the §11.2 skew allowance.** CodeComm does not synchronize
  time and relies on the platform time service. A device with a badly wrong clock has every
  content certificate refused in both directions, which presents identically to credential
  expiry, so `status` and `repo doctor` MUST detect suspected peer skew and report it as a
  distinct condition (§4.6).

Churn — sleep, Wi-Fi to Ethernet, DHCP renewal, VPN reconnect — is the normal case:

- Endpoints are **gossip, never committed state.** `GET /v1/peers` carries the latest exact
  target-signed set (§4.4), valid for at most eight advertisement intervals. Expired sets are no
  longer relayed; their addresses and successfully authenticated prior destinations are only local
  guesses for §11.2's seven-day guess TTL. Raw discovery guesses expire with their datagram.
  Nonmanual guesses share §11.2's per-member/session cap and evict expired then oldest entries;
  manual endpoints persist until removal, have separate caps, and refuse additions rather than
  replacing operator configuration. Every source, including manual and stale guesses, is dialed only
  when the OS route leaves on a currently selected interface. Membership never changes because an
  address changed.
- On local address change, interface appearance or disappearance, or wake from suspend,
  a daemon MUST re-resolve its selected interfaces, re-advertise immediately rather than
  waiting for its next jittered interval, drop connections bound to a vanished local
  address, and re-dial every authorized peer with capped exponential backoff and jitter.
  Git transfers re-establish the same way (§8.1).
- Reconnection is idempotent and never loses durable work: queued events remain queued,
  replication resumes from durable cursors, and bounded Git artifacts resume by digest and offset.
- **Wake with an expired epoch.** A device suspended past its content-credential expiry
  reaches the consensus plane immediately on wake, because that plane is authenticated by
  long-lived device identity and never expires (§4.6). If a voter majority is reachable,
  the voters elect, authorize fresh credentials, and reopen the content mesh without
  operator action — however long every device slept. If no majority is reachable, local
  work and reads continue against already-applied state and renewal retries on every
  connectivity change, but content traffic stays closed and strong proposals queue.

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
is a §12.3 core scenario, a §-reference is a named test or gate elsewhere in §12 or §13, and "—" marks a structural
property asserted by construction. A change that weakens any row requires an ADR (§17).

| Invariant | Enforcement | Proof |
|---|---|---|
| No permanent routing node | Every authorized pair can connect directly; relaying a target-signed endpoint set is opportunistic and no node is required for any pair, so no transfer traverses the Raft leader | 17, §13 phase 5 |
| No split-brain strong state | Only quorum-committed Raft entries are accepted | 6, 7 |
| No replica divergence | Frozen reducers; halt rather than apply what a peer may have applied differently; digest compared at every checkpoint (§5.5, §5.6) | 9, 25 |
| No acknowledged event loss, except under §3.1 recovery | Voter-majority Raft commit, then event/result chains, idempotency row, projection, and `last_raft_applied_log_index` in one durable SQLite transaction (§5.3). §3.1 offline quorum recovery is the **sole exemption**: a lone survivor may lack entries the lost majority committed, which is why it demands explicit operator authorization | 10, 21 |
| Idempotent resumption | Committed-but-unapplied entries replay identically after crash; exact duplicate IDs verify and return the chained result, while changed bytes under one ID fail closed (§5.2.1) | 10, §12.2 |
| No identity reuse | `agent_session_id` and `event_id` are unique and never reused; the origin-scope sequence of §4.2 is unique | §12.2 |
| No orphaned ownership | Session end releases claims and leases deterministically; operators can always override (§6.4) | 5 |
| No accidental governance orphan | Ordinary role/revocation events leave one active owner; the offline recovery key can restore its submitting active editor while quorum exists (§4.3) | 19, §12.2 |
| No remote agent control | MCP is local stdio; peer API has no execution primitive | §12.4 |
| No shared coordination DB | Each daemon owns local SQLite and applies logical events | §12.3 multi-session |
| No DB diffs on wire | Typed events/snapshots only; received SQL is inert data | §12.4 |
| No remote workspace mutation | Peer APIs can import validated Git objects and update only reserved CodeComm-owned refs through expected-old-OID CAS; no checkout, index write, user-owned-ref update, `receive-pack`, or caller-selected repository path exists | 1, 15 |
| No silent file winner | Draft/publication commits are immutable; canonical advancement is CAS-ordered and merge conflicts are explicit | 15 |
| No canonical pointer without durable objects | `publication.applied` requires validated staging receipts from a current voter-target majority before its dual CAS; each receipt binds the accepted publication's original proposal event | 15, 21 |
| No agent identity spoofing | A one-use launch registration fixes session, client/profile, mode, and a daemon-validated managed root before vendor start; the daemon constructs every event's `origin` from the accepted binding, rejects client-supplied identity fields, and pins MCP to `actor_type: agent` (§§5.1, 7.1) | 2, 22, §12.4 |
| No private reasoning capture | Store only bounded origin-attributed rationale/action summaries under the closed redaction schema; V1 installs no vendor activity hooks (§§5.2, 7.3) | §12.2 |
| No silent control-file propagation | Bootstrap and CodeComm-managed worktrees withhold control paths; each later upsert/delete requires per-device approval (§8.4) | 1, 16 |
| No insecure minority renewal | Credential authorization requires quorum; a minority never self-promotes (§4.6) | 7, 20 |
| No unproven-target renewal lockout | Credential/checkpoint authority switches only after every target voter proves promotion and a prior authority signs the handoff; a stalled target leaves the old authority usable (§§3, 4.6) | 18, §12.2 |
| Revocation excludes from every later voter target | `membership.device_revoked` validates the current voter-set CAS and a resulting target without the device; revoking a target voter advances that target/version, while revoking a nonvoter leaves both unchanged. Access is denied at admission on applied membership, never on the lagging Raft configuration (§3) | 14, §12.2 |
| Consensus authority is the Raft configuration alone | Quorum size and vote counting derive only from the committed configuration; applied application membership gates access, never majority arithmetic (§3, §4.6) | 6, 7, §12.2 |
| Consensus plane is closed to repository and ordinary content APIs | An identity-authenticated connection reaches only guarded Raft election/replication/snapshots and four §4.6 endpoints: renew, endorse, closed consensus proof, and status. It reaches no content-plane REST/SSE, Git, artifact, workspace, agent, or membership-proposal surface; Raft may carry signed coordination events and logical snapshots only under the applied-leader and live-configuration gates | §12.2, §12.4 |
| Only an elected leader replicates | `AppendEntries` with entries and `InstallSnapshot` are sent solely by the current leader, to active voters or staging nonvoters in its live committed Raft configuration, after it has applied through its committed membership index (§4.6) | 13, 14, §12.2 |
| No publication beyond held authority | `publication.proposed` is rejected unless the bounded union of every introduced commit-edge path is covered by an active path lease held by the author and its opaque `working_root_id` matches the bound agent-session row; the daemon, not the client, constructs the artifact from that bound root. Agent approval requires another device; a local human may explicitly review (§7.2) | 23, §12.2 |
| Plaintext content stays in the authorized set | CodeComm sends workspace files, secrets, and activity only inside authenticated end-to-end member connections; no telemetry in V1. Operator-selected network intermediaries may observe ciphertext metadata (§2.3) | 24, §12.4 |
