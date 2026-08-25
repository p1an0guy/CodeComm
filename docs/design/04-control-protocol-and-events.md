# CodeComm V1 Design — Part 05: Control Protocol and Event Model

Part 5 of 14. Contents: §5 transport, events, event chain, commit/replication, event kinds, version skew, projection commitments.
Section map, review status, and reading order: [README.md](README.md)

Authoritative revision 0.14; maintained only in this split set.

Normative terms follow RFC 2119/8174; declarative requirements and table rows headed "MUST" or
"Required" are equally normative.

---

## 5. Control Protocol and Event Model

### 5.1 Transport

Peer application traffic is versioned HTTP/2 plus SSE over TLS. The custom ALPN selects an explicit
HTTP/2 client/server; implementations MUST NOT rely on Web-PKI `h2` auto-configuration. Strong
proposals may enter through any member; followers forward only the proposal. The maintained Raft
framed transport runs unchanged inside an RFC 8441 extended CONNECT stream on the non-expiring
consensus plane (§4.6), with `:protocol = codecomm-raft` and
`:path = /v1/consensus/raft`. The explicit HTTP/2 stack advertises
`SETTINGS_ENABLE_CONNECT_PROTOCOL = 1` in its first SETTINGS frame. The adapter supplies a
`net.Conn`-equivalent byte stream; CodeComm neither parses nor reimplements Raft messages. Phase 1
must prove flow control, cancellation, half-close, bounded concurrent streams, connection reuse,
and rejection of missing/wrong pseudo-headers.

| Method/path | Purpose |
|---|---|
| `GET /v1/session` | Capabilities/session metadata |
| `GET /v1/peers` | Committed roster plus each latest valid exact target-signed endpoint set |
| `GET /v1/consensus/status` | Local term, leader, quorum, and nullable `last_raft_applied_log_index` |
| `POST /v1/consensus/prove` | Closed `staging_apply`, `checkpoint_sign`, `target_activation`, or `authority_handoff` proof requested by the current leader (§§3, 5.2.1) |
| `CONNECT /v1/consensus/raft` | Maintained Raft framed transport with `:protocol = codecomm-raft`; consensus ALPN and live-configuration peers only |
| `POST /v1/pairing/{request,confirm}` | Pairing; pairing ALPN only |
| `POST /v1/credentials/renew` | Submit an epoch-key binding; consensus ALPN only (§4.6) |
| `POST /v1/credentials/endorse` | Voter clock endorsement requested by the leader; consensus ALPN only (§4.6) |
| `POST /v1/events` | Propose idempotent event |
| `GET /v1/events?after=N` | Paginated accepted-event history/export; `N` is a `chain_index` |
| `GET /v1/replication?after_result=M` | Authoritative catch-up; `M` is a `result_index` and the response is the §5.3 result batch |
| `GET /v1/replication/acknowledgement?at_result=M` | Authority-signed proof that the server's current verified result head is exactly `M` |
| `GET /v1/events/stream` | SSE result/event high-watermark notification |
| `GET /v1/snapshots/latest`, `/v1/snapshots/{id}/manifest-pages/{n}`, and `/v1/snapshots/{id}/chunks/{n}` | Signed logical-snapshot root, bounded descriptor pages, and resumable chunks |
| `POST /v1/agent-sessions/presence` | Ephemeral device-bound presence plus a compact local control-manifest summary |
| `GET /v1/control-files/digests?manifest_version=V&manifest_digest=D&cursor=C` | Stable paginated paths/digests for that exact local control manifest |
| `POST /v1/acks` | Durable applied watermark |
| `POST/GET /v1/bootstrap/git-bundles[/id]` | Verified bootstrap artifact |
| `GET/POST /v1/git/upload-pack` | Read-only Git protocol v2 for allowlisted CodeComm refs; never `receive-pack` |
| `PUT/GET /v1/git/artifacts/{sha256}` | Resumable bounded publication/draft bundle staging and retrieval |
| `GET /v1/git/refs` | Signed source-owned draft/publication ref advertisement and local availability |
| `GET /v1/conflicts` | Committed merge-conflict records |

The consensus-proof endpoint accepts only the current leader authenticated on the consensus plane
(§4.6). Its closed mode fixes the subject and response: staging apply proof requires the receiver
to be the named staging nonvoter; checkpoint signing requires an active authority member whose
stored tuple exactly matches the capture; target activation requires the named promoted target
voter; authority handoff requires an active current-authority member. Every mode binds one
leader-supplied tuple after local verification and returns no caller-selected status query.

All messages use explicit schema/capability versions, §11.2's page/body/header/handler ceilings, and
structured problem responses. Lists use opaque stable cursors and at most 256 items; byte bounds may
shorten a page. SSE carries only a coalesced latest result/event high-watermark plus keepalives, not
an unbounded event queue. Artifact, snapshot-chunk, and upload-pack streams use their endpoint
limits and no-progress timer. Bulk content uses dedicated content-bulk connections and cannot
consume the content-control connection's stream slots. Every authenticated non-bulk request consumes
the receiver's per-device control-rate budget; `POST /v1/events` also consumes its lower proposal
budget, and the leader independently applies its post-forwarding ingress budget (§11.2). For
`POST /v1/events`, `Idempotency-Key` MUST equal the signed `event_id`; the
committed command result is retained for the session lifetime, so replay cannot become a new
command after a timer. A byte-identical proposal under that ID returns the original result; the same
ID with a different proposal digest returns `idempotency_conflict` and never overwrites the first
row. An initial submission omits `CodeComm-Proposal-Hop`. A follower forwards it once with that
header exactly `1`; a receiver of `1` applies only while leader and otherwise returns retryable
unavailability, never forwarding again. The marker is authenticated hop metadata, not authorization;
the signed origin and proposal remain byte-identical. Other artifact mutations are idempotent by
artifact digest and offset.
Unknown required capabilities fail closed. Git bundles use `application/octet-stream` plus
digest/size/expiry.
Every Git endpoint is bound to the selected session repository; callers cannot provide a path,
run arbitrary Git, write user refs, or invoke `receive-pack`.
Canonical event batches MAY use negotiated binary encoding and gzip/zstd, with compressed and
expanded limits enforced before allocation.

Presence carries only `(control_manifest_version, control_manifest_digest, control_path_count)`,
not an unbounded path map. The digest is
`SHA-256("codecomm/v1/control-manifest" || 0x00 || JCS(entries))`, where `entries` is the array of
closed `(path, operation, content_digest)` objects sorted by canonical path and `delete` uses a null
digest. `entries` is derived only from durable current **approved**
`control_file_approvals` rows, including approved delete tombstones; pending/declined proposals and
unapproved or drifted live-root bytes never enter it. The durable local monotonic version changes
whenever that exact array changes. Every page request supplies the exact version and digest from
presence; the opaque cursor binds both plus its next position, and each response repeats both. If
either no longer equals current state — including reuse of an older version after local restore —
the daemon returns `stale_control_manifest` and the caller restarts from presence. Generic item/body
limits may shorten a page. This is ephemeral evidence of per-device divergence, never consent or
reducer input (§8.4).

Pairing routes exist only on the pairing ALPN; the four consensus control routes and Raft CONNECT
exist only on the consensus ALPN; every other peer route requires a current content credential and
active applied membership. Reducers remain authoritative for event roles. The OpenAPI 3.1 document and generated
JSON Schemas are release artifacts and golden fixtures; handlers and SDKs derive from the same typed
operation registry rather than duplicating hand-written request models.

Transport failures use `application/problem+json` with fixed fields
`{type, title, status, code, correlation_id, retryable, detail?}`. `detail` is local display text and
never part of a replicated result. Codes distinguish schema/auth/role, stale version,
idempotency conflict, no leader/quorum, rate/size limits, unavailable artifact, and storage
failure. A committed command returns its canonical result object even when that result is a domain
rejection; callers never infer commitment from an HTTP status alone.

`POST /v1/acks` derives the sender from content mTLS and accepts one closed watermark:
`(session_id, recovery_generation, ack_sequence, last_raft_applied_log_index?, chain_index,
chain_hash, result_index, result_hash, canonical_ref_version, canonical_object_available)`.
`last_raft_applied_log_index` is null until this store has applied a Raft FSM entry and advances only
through actual FSM application; importing a result batch or logical snapshot never fabricates it.
`ack_sequence` and non-null positions are durable and monotonic per sender; the same sequence with
another body or the same position with another hash is an integrity alarm, and a regression is
rejected and audited. Availability may change for the exact canonical version and is ordered by
`ack_sequence`. Acknowledgements are durable local evidence, not replicated authority.

**Local IPC.** Release builds expose no loopback TCP API. CLI, TUI, and MCP use strict HTTP/1.1
with §11.2's bounded connections, handlers, framing deadlines, and JSON bodies over one owner-only
byte stream: a Unix-domain socket in the platform
per-user runtime directory or a Windows named pipe. The owner-only supervisor registry supplies the
endpoint; `.codecomm/` is an untrusted workspace hint and cannot select a socket or state path
(§§3.2, 6.2). Unix directories are mode `0700`, sockets `0600`, and the server verifies peer UID.
Windows pipes use the current user SID in the DACL, `PIPE_REJECT_REMOTE_CLIENTS`, and an
impersonation-token SID check. The supervisor has a separate endpoint and operation set.

The first request on a local connection is `POST /local/v1/bind` with
`local_protocol_version`, `client_instance_id`, selected session/workspace IDs, and one closed
client class: `operator` or `agent`. The server independently verifies the endpoint's session and
peer identity, then pins the connection for its lifetime:

- `operator` maps to `actor_type: human` and can reach only the CLI/TUI operation allowlist;
- `operator` omits `agent_proof`; `agent` requires exactly one closed proof object,
  `{"launch_selector":"..."}` or `{"resume_capability":"..."}`. A new bind uses only the one-use
  selector created by `codecomm agent launch`; resume presents the §7.2 capability and restores
  that exact session.

`codecomm agent launch` first creates a durable local registration fixing session/workspace,
immutable `client_kind`/profile, concurrency mode, and a daemon-validated managed-root handle. It
then launches the selected vendor with a non-secret, never-reused selector inherited by its
`codecomm mcp serve` child. The bind cannot provide or override those fields. The daemon atomically
reserves the registration, mints `agent_session_id`/`working_root_id`, and proposes the exact
`agent.session.started`; tools remain closed and no resume capability is returned until that event
commits. A crash/rebind with the same selector resumes the pending exact start; another consumer
loses the reservation. Rejection consumes the registration and burns the start ID, while acceptance
marks it consumed. An unregistered selector, an independently started adapter, or a pre-existing
user root is refused. Shared-root mode may register several launches against one managed root.

No local request carries `actor_type`, `origin`, `device_id`, `agent_session_id`, client/profile
metadata, concurrency mode, root path/ID, private signing keys, or raw recovery-key material. A
closed operation may carry a detached public
authorization signature that its event kind explicitly requires, such as
`membership.owner_recovered`; a signature is payload data, not private signing material.
Connections do not change class and HTTP pipelining is disabled, making disconnect lifecycle and
actor binding unambiguous. Mutations use
`POST /local/v1/commands` with a closed operation name, UUIDv7 `request_id`, expected version where
required, and typed payload. Before mapping or signing a new mutation, the daemon enforces
§11.2's per-origin and per-session unresolved-command ceilings; saturation returns retryable
`local_backpressure` without allocating an event ID or sequence. Before forwarding, one local transaction advances the bound origin
counter and stores `(client_instance_id, request_id)`, the canonical request digest, one
daemon-minted `event_id`, and the exact signed proposal. An exact retry returns its pending or final result; changed request bytes
under the same key return `local_idempotency_conflict`. A crash can therefore resend only the
original proposal. The daemon forwards at most one unresolved proposal per origin scope and drains
later durable mappings in sequence order (§5.2); this is protocol ordering, not a global mutation
lock. Reads use bounded `/local/v1/query/*` operations. Client/daemon protocol mismatch fails before
binding and names the compatible release range. Raw HTTP framing, operation schemas, error codes,
binding transitions, and CLI/MCP mappings are frozen contract fixtures in phase 1.

`publication.propose` is the sole mutation that needs durable preparation before its proposal can be
signed. After the same queue check, the daemon first atomically reserves the request mapping and
`event_id`, builds and durably records one immutable publication/artifact whose
`proposal_event_id = event_id`, then obtains §7.2 receipts over that metadata. Exact retries resume
that preparation and event ID; changed request bytes conflict, and later working-root changes do not
rewrite the attempt. Only after a current-target majority is present does one transaction allocate
the origin sequence and persist the exact signed proposal. From then on the ordinary forwarding
contract applies. Preparation counts toward the unresolved-command cap but reserves no origin
sequence and does not block later signed commands in that scope; when ready, it takes the then-next
sequence. A failed or stale committed attempt requires a new request, event, and publication ID; its
receipts cannot authorize that successor.

Before signing, the author or owning daemon on terminal agent end may abandon a preparation locally.
The request mapping becomes a generation-lifetime tombstone for that event/publication ID, returns
`publication_preparation_abandoned` on retry, releases local artifacts/queue capacity, and can never
be signed. No network "release" is sent: remote staging holders keep their pins until the
subtraction-based receipt window expires, so cancellation cannot make still-valid receipts point at
deleted objects.

`peer owner-recover` is the sole two-step local mutation because its offline-key signature covers
the daemon-minted event ID. On an operator-bound connection,
`POST /local/v1/owner-recovery/challenge` atomically reserves `(client_instance_id, request_id)`, one
`event_id`, the bound local subject device, current session/generation, and caller-supplied expected
device version, then returns the exact JCS authorization object. At most one unexpired challenge may
exist per device. The CLI reads the recovery seed by no-echo input, signs that object locally under
`codecomm/v1/owner-recovery`, erases the mutable key buffer, and submits only the signature to
`POST /local/v1/owner-recovery/finalize`. Finalize verifies the reserved tuple and signature, then
atomically allocates the origin sequence and stores the exact origin-signed proposal before
forwarding under the ordinary retry contract. An exact retry returns the same challenge/proposal/
result; changed fields or signature, another client binding, and abandoned/stale reservations
cannot mint another event. Finalize must persist the proposal before §11.2's five-minute challenge
deadline; expiry terminally tombstones that request, and a retry returns `challenge_expired` rather
than extending it. A new request ID is required. Once finalized in time, ordinary command retry and
quorum-wait semantics apply even after the deadline. The MCP adapter cannot reach either operation.

The shipped `mcp serve` adapter hard-codes its class and exposes no argument that selects
`operator`. This is a boundary against remote/model access through that adapter, not against
arbitrary native code already running as the trusted OS account; same-UID impersonation remains the
explicit §10 exclusion.

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
  "min_apply_level": 1,
  "event_id": "uuidv7",
  "session_id": "uuid",
  "workspace_id": "uuid",
  "origin": {
    "device_id": "cc1<64 hex>",
    "actor_type": "agent",
    "agent_profile_id": null,
    "agent_session_id": "uuidv7",
    "origin_boot_id": null,
    "origin_sequence": 42
  },
  "created_at": "RFC3339Nano",
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

**The daemon is the sole constructor of `origin`.** A local command/bind body from MCP, CLI, TUI, or
another IPC caller MUST NOT supply any `origin` field; doing so is a local schema rejection before
event construction. The signed proposal sent to `POST /v1/events` necessarily contains the completed
block, which network receivers validate rather than reject. MCP uses `actor_type: agent`, its bound
profile/session, and null `origin_boot_id`; TUI/CLI uses `human`, null profile/session, and the
daemon's signed never-reused `origin_boot_id`; daemon initiative uses the same boot scope with
`daemon`. Sequences are monotonic within that signed scope (§4.2), so restart cannot collide with an
earlier human/daemon event.

This rule is load-bearing and cannot be replaced by reducer validation. `human` and `agent`
events originating on one device are signed by the **same** device identity key, so no replica can
distinguish them cryptographically: a reducer can reject an `actor_type` it can see is
inconsistent (an `agent` event naming no live bound session) but can never detect a forged
`human`. Every "operator-only, therefore off the MCP surface" guarantee in §5.4, §6.4, and §7.1
rests entirely on this construction rule — without it, any MCP client could assert
`actor_type: human` and obtain the whole override set including `policy.changed` and owner-only
membership kinds. §5.3 step 5 rechecks only the half that is checkable; the authoritative
enforcement is local and at the IPC boundary. Every override additionally records its originating
IPC channel in `audit_events` (§10.1).

Each origin scope is strictly sequential. Except for an exact duplicate `event_id`, the reducer
requires `origin_sequence = last_sequence + 1`; the first sequence is 1.
`agent.session.started` creates its agent scope and requires sequence 1, while a daemon boot's first
valid human/daemon command creates the shared boot scope. Once signature, session, scope, and the
expected next sequence validate, that sequence is consumed even if later role/CAS/domain checks
reject the command; otherwise one ordinary rejection would strand every later request from that
scope. A gap/reuse rejection consumes nothing. The digest-covered `origin_scopes` projection records
the last consumed sequence (§6.1). To prevent transport reordering from burning a gap, a local
daemon forwards at most one unresolved command per scope; other local commands remain durably
queued. Exact retries use their existing mapping and do not consume another sequence.

On applying an accepted event, each replica additionally stores local provenance,
which is **never signed, never replicated, and never part of `signed_bytes`**:

```json
{
  "term": 17,
  "log_index": 1048,
  "applied_at": "RFC3339Nano",
  "chain_index": 903,
  "chain_hash": "base64url"
}
```

`event_provenance` is written only when the local Raft FSM applies the entry. A settled nonvoter that
imports the same accepted event through a verified result batch stores no invented term/log index;
its commitment evidence is §5.3's replication attestation. `log_index` defines Raft order where
present. `created_at` is an attestation of what the origin claimed, not trusted time: it aids display
and diagnosis, and a reducer MUST NOT derive any decision from it (§6.3).

Agent-originated events require the bound committed agent session and origin scope, and
`origin.agent_profile_id` MUST equal that session's immutable profile, including null. The exception
is `agent.session.started`: it requires `origin.agent_session_id = entity_id`, no existing
session/scope row, sequence 1, and uses `origin.agent_profile_id` to create the immutable profile. A
start's actor, prohibited CAS, entity/session equality, and sequence-1 contract validate before
scope creation; failure consumes nothing. After those structural checks, a first-seen start consumes
sequence 1 and creates the scope even if a later role, payload, cap, or domain check rejects; that
rejected `agent_session_id` is generation-wide burned and a later launch mints a new ID. An orphan
burned scope therefore remains at sequence 1, and another device cannot reuse its ID in that
generation. Only an accepted start creates the agent-session entity. Remote reducers can verify
active membership, IDs, and every post-start profile match; trusted local construction proves a
launch bind existed. A successor generation retains `ended(recovery)` session rows but no predecessor
scopes (§3.1); those retained IDs remain burned and MUST NOT acquire a new scope.
`human` and `daemon` events require the boot scope and a null agent session. `human` means a person
acting through local TUI/CLI/IPC; `daemon` means local daemon initiative. Both attribute solely to
`device_id` (§2.1).

Envelope bounds are reducer-enforced: `rationale_summary` is 0–2048 UTF-8 bytes and `actions` has at
most 64 entries. `redaction` is required and closed: `policy` is exactly `default` at schema version
1, and `fields_removed` is a sorted unique subset of
{`arguments`, `environment`, `output`, `private_reasoning`, `secret`, `sensitive_value`}. These names
report omitted categories, never values. Each action is a closed object:
`type` ∈ {`file.read`, `file.edit`, `command.run`, `tool.call`, `test.run`, `decision.recorded`,
`artifact.created`}; `target` has a closed type-specific grammar. `file.*` uses a canonical
repository path. `command.run` is 1–128 ASCII bytes matching
`[A-Za-z0-9][A-Za-z0-9._+-]*`, a reported executable basename with no path or arguments.
`tool.call` is a 1–128-byte ASCII identifier matching
`[A-Za-z0-9][A-Za-z0-9._:-]*`, not a lookup in local tool state. `test.run` is a 1–256-byte
single-line UTF-8 suite/test name; `decision.recorded` is a 1–128-byte single-line UTF-8 topic.
`artifact.created` is a canonical repository path or
`class:[A-Za-z0-9][A-Za-z0-9._-]{0,63}` for a non-repository artifact. UTF-8 forms reject controls;
ASCII forms reject every byte outside their grammar. `summary` is 1–1024 bytes; `status` ∈
{`attempted`, `succeeded`, `failed`, `skipped`}; optional `task_id`, 32-byte SHA-256
`artifact_digest`, RFC 3339 `started_at`, and integer `duration_ms` in
`0..activity_duration_max_ms`.
Array order is report order. Raw arguments, terminal streams, output, environment, secrets, private
reasoning, and sensitive values are prohibited before signing. `activity.recorded` carries a
standalone report and requires a nonempty `rationale_summary` or at least one action; redaction names
alone are not substantive. Other events may carry the same bounded activity alongside their
mutation. `capture_level` must match origin exactly: `agent_reported` for `agent`,
`human_reported` for `human`, and `daemon_observed` for `daemon`. Receiving a report does not make it
daemon-observed; that value is only for operations/results directly generated at a daemon boundary.
Every canonical repository path is at most 512 UTF-8 bytes (§8.4). Each event `paths[]` array is
also bounded by the JCS-encoded-array ceiling `event_path_array_max_bytes` (§11.2), in addition to
its item-count bound, so a legal path count cannot exceed `max_event_bytes`.

#### 5.2.1 Event chain and checkpoints

Two independent apply-time chains serve different purposes. The **event chain** is the compact
domain/audit history of accepted events. The **result chain** preserves the first committed outcome
for every `event_id`, including deterministic rejections, so idempotency survives snapshots,
restarts, and reconstruction. Neither is computed before Raft commitment or transmitted inside the
origin-signed proposal.

```text
chain_seed(gen 0) = SHA-256("codecomm/v1/chain" || 0x00 || digest(genesis_0))
chain_seed(gen k)  = SHA-256("codecomm/v1/chain" || 0x00 || digest(genesis_k)
                      || u64be(k) || u64be(final_chain_index(gen k-1))
                      || final_chain_hash(gen k-1)
                      || u64be(final_result_index(gen k-1))
                      || final_result_hash(gen k-1))
chain_n            = SHA-256("codecomm/v1/chain" || 0x00 || chain_{n-1}
                      || JCS(accepted_event_n including origin_signature))
chain_index        = n, counting accepted events from 1 across all generations

result_seed(gen 0) = SHA-256("codecomm/v1/result-chain" || 0x00 || digest(genesis_0))
result_seed(gen k)  = SHA-256("codecomm/v1/result-chain" || 0x00 || digest(genesis_k)
                       || u64be(k) || u64be(final_chain_index(gen k-1))
                       || final_chain_hash(gen k-1)
                       || u64be(final_result_index(gen k-1))
                       || final_result_hash(gen k-1))
result_n            = SHA-256("codecomm/v1/result-chain" || 0x00 || result_{n-1}
                       || JCS(command_result_n))
result_index        = n, counting first-seen committed event IDs across all generations
```

`digest(genesis_k)` is exactly §4.2's domain-separated digest of generation k's complete signed
genesis record — the successor record for k>0. Each successor binds both verified predecessor heads. Seeding from genesis rather than
`session_id` lets a successor generation (§3.1), whose `session_id` differs, continue the lineage:
neither dense index restarts. Successor creation makes each new seed the **current boundary head at
the unchanged dense position**; the predecessor's last row retains its old hash. A head tuple is
therefore `(session_id, recovery_generation, index, hash)`, and same-position mismatch rules compare
only within one generation.

Rejected commands and Raft configuration entries consume Raft indices (§5.3) but are
**not event-chain members**, so `chain_index` advances only on acceptance while `log_index` has
gaps. Every first-seen command, accepted or rejected, advances `result_index`; an exact duplicate
and an ID collision do not. `command_result_n` is a closed JCS object containing
`result_index`, the exact signed proposal, its SHA-256 digest, canonical outcome, and the accepted
`(chain_index, chain_hash)` or nulls. It excludes the separately stored `previous_result_hash` and
`result_hash`, avoiding a recursive preimage. Canonical outcomes contain only stable status/code and
bounded typed fields; localized prose is generated later.

The V1 object has exactly these six members and representations:

```json
{"chain_hash":null,"chain_index":null,"outcome":{},"proposal":{},"proposal_digest":"base64url","result_index":1}
```

`proposal` is the complete signed event object embedded as JSON, `proposal_digest` is unpadded
base64url SHA-256 of its exact JCS bytes, and `outcome` is the embedded canonical outcome object.
An accepted result replaces both nulls with its positive integer event-chain position and unpadded
base64url 32-byte hash; a rejection leaves both null. No storage-only column enters this preimage.

On first apply, a replica computes the applicable event link, then the result link, in the same
transaction. An exact duplicate first checks proposal-digest equality and recomputes that row's own
link before returning it; a changed proposal is `idempotency_conflict`, while a broken row is a
local integrity halt. This O(1) check catches corruption in the result being relied upon but does
not pretend to authenticate all predecessors. Snapshot creation/import, event or audit export,
§3.1 recovery, `state recover`, and `state scrub` MUST recompute both complete chains through their
cut and compare the anchored heads. Incremental checkpoints compare stored heads only; they do not
rescan unbounded history.

Ingress returns `idempotency_conflict` before Raft when an existing `event_id` has changed bytes. If
such a collision nevertheless appears in a committed log, the FSM halts before that entry: it does
not write a second result, a Raft-command binding, or an applied watermark.

Periodically — after `checkpoint_events` accepted events or `checkpoint_interval_seconds` seconds,
whichever comes first — the leader serializes checkpoint capture with proposal/configuration appends, completes a
Raft barrier, applies through it, and captures the state **immediately before the checkpoint
command**:
`(session_id, workspace_id, recovery_generation, authority_voter_set_version, signer_device_id,
term, covered_applied_log_index, covered_chain_index, covered_chain_hash, covered_result_index,
covered_result_hash, projection_accumulator, digest_version, projection_schema_version)`. An active
device in the current committed
`credential_authority` set whose local state matches that tuple signs it under
`codecomm/v1/checkpoint`; the leader places that signed object unchanged in a
`consensus.checkpoint` event constructed from its daemon IPC binding.
This signer need not be the leader, which keeps portable checkpoint authority verifiable from
committed state during voter replacement.
The payload has exactly the fourteen tuple members above plus `authority_signature`; that signature
is excluded from its own preimage and is strict unpadded base64url for 64 bytes.

At apply, an entry whose term or `log_index - 1` differs from the covered tuple is a deterministic
`stale_checkpoint` result and the leader retries; no index reservation is needed. If the positions
match but a local chain head or projection accumulator differs, that replica has diverged: it halts
without storing a rejection, extending either chain, or advancing
`last_raft_applied_log_index`. Healthy
replicas accept the checkpoint, then append the checkpoint event at
`covered_chain_index + 1` and its command result at `covered_result_index + 1`; it changes no domain
projection, but consuming its origin sequence is a protocol-projection mutation (§5.6).

An exported range is position-verifiable only when it includes a trusted starting head (genesis or
prior checkpoint), every intervening result record and accepted event without a gap, and a later
authority-valid checkpoint covering the range. Merely attaching a later checkpoint without its
intervening records proves nothing. A lone event proves origin, not committed position.

### 5.3 Commit and replication

1. The origin daemon atomically mints the event ID/next bound sequence and signs the canonical
   command, including an expected entity version when required.
2. Receiver performs bounded structural checks, enforces its local request-rate limits
   (§10), and forwards if not leader.
3. Leader prevalidates the complete command, then proposes the **byte-identical** signed
   proposal to Raft, adding nothing to it.
4. Raft durably replicates the command to a voter majority.
5. Every state machine applies in index order. It first looks up `event_id`: an exact proposal
   duplicate verifies and returns the chained row without re-evaluation; a changed proposal under
   that ID returns `idempotency_conflict`. A first-seen command rechecks schema/apply support,
   membership, signature/domain/session/scope binding, and expected origin sequence. A valid next
   sequence is consumed before deterministic role, entity existence/CAS, transition, depth, and
   remaining kind-specific checks;
   a gap/reuse is itself a rejection and consumes nothing (§5.2).
6. An accepted command stores the event, extends the event chain, and applies its domain mutations.
   A rejected first-seen command stores the same canonical outcome on every healthy replica and does
   not extend the event chain; it may still have advanced `origin_scopes`. Either outcome appends one
   command result, extends the result chain, and extends §5.6's projection accumulator over the
   exact protocol/domain before/after rows. A local checkpoint/head/accumulator mismatch is an
   integrity halt before any of those writes.
7. SQLite commits the accepted event or rejection, both chain heads, projection accumulator,
   affected protocol/domain rows, durable `command_results`, audit view, and
   `last_raft_applied_log_index` in one transaction.
8. The caller receives that committed result. Exact duplicate IDs return it for the session
   lineage's lifetime; ID collisions never replace it.

Pre-Raft rejection is limited to bounded transport facts independent of mutable committed state:
malformed schema/encoding, invalid signature or session binding, size/rate limit, or unavailable
leader/storage. It returns a retryable or terminal transport problem as appropriate, creates no
`command_results` row, and advances neither chain. It never authorizes event-ID reuse: a local request
retains its exact mapped proposal, and a remote origin retries the same signed ID. Role, CAS,
transition, depth, and every other domain decision MUST enter Raft; no caller may observe an
uncommitted domain outcome.

Settled application nonvoters and catch-up clients use the result-batch contract below, durable cursors,
and SSE high-watermarks. A target temporarily placed in the live Raft configuration by
`AddNonvoter` is the sole exception: it receives ordinary-plane Raft replication until promoted or
removed so it can produce §3's target-applied checkpoint proof.

**Catch-up batch contract.** `GET /v1/replication?after_result=M` takes a dense `result_index`.
The identity signature is the commitment attestation under V1's non-Byzantine-voter assumption
(§2.4, §10), and any peer may relay the bytes unchanged. The canonical response contains:

| Field | Meaning |
|---|---|
| `from_result_index`, `to_result_index` | Exactly `M+1` through the last included first-seen result; count equals `results.length` |
| `start_result_hash`, `end_result_hash` | Receiver's expected result head at `M`, and recomputed head |
| `start_chain_index/hash`, `end_chain_index/hash` | Accepted-event cursor before and after replay |
| `start_projection_accumulator`, `end_projection_accumulator` | Exact projection-accumulator heads before and after replay |
| `start_projection_state_digest`, `end_projection_state_digest` | Full covered projection-state digests at both cuts |
| `results[]` | Contiguous canonical command-result records, each carrying its exact proposal and accepted chain tuple or nulls |
| `session_id`, `workspace_id`, `recovery_generation` | Explicit replay/confusion binding |
| `server_device_id`, `server_applied_result_index`, `server_authority_version` | Signer and attested progress/authority at the batch end |
| `batch_signature` | Voter identity signature over every preceding field under `codecomm/v1/batch` |

The receiver requires every starting chain/projection commitment to equal its durable cursor, then scratch-replays every
proposal, outcome, projection transition, event/result link, checkpoint, and authority handoff
without mutating durable state. The signer must be an active member of the authority in effect at
`to_result_index`; when that differs from the receiver's starting authority, the contiguous results
MUST contain every intervening accepted `membership.voter_set_activated`, and the receiver validates
the complete handoff chain before treating the batch signature as authorized. A batch cannot stop
before its signer becomes authorized. If the byte bound prevents reaching such a point, the server
returns `snapshot_required` and offers a checkpoint cut at or after that activation. Any gap, count
mismatch, insertion, mutation, reorder, outcome mismatch, wrong ending chain, accumulator, or state
digest, unauthorized signer, or invalid handoff rejects the whole batch with both cursors unchanged.
Origin signatures alone prove authorship, not commitment.

An accepted batch commits its imported results/projections/heads and one local
`replication_attestations` row atomically. That row stores every signed envelope field, signature,
signer/authority, and covered result/chain range except `results[]`; those exact records are
reconstructed by `result_index` from immutable `command_results` when the signed JCS object is
reverified. Missing, changed, overlapping-inconsistent, or noncontiguous coverage is an integrity
failure. Batch import never advances `last_raft_applied_log_index` and creates no
`event_provenance`.

A server returns a replication acknowledgement only when `at_result` exactly equals its current
verified head and it is active in the authority at that cut. The canonical signed object binds its
kind, lineage, signer and authority version, complete result/event/projection heads, full
projection-state digest, and server result watermark; peers may relay the bytes unchanged. A
receiver verifies the signer at the exact cut and requires every head to equal its local verified
state before retaining the observation. Retention is historical evidence, not reachability: only a
response received directly from an authenticated peer whose identity equals the signer is live
freshness evidence. Relayed responses, process restart, or connection loss cannot establish
`current`, while a retained higher watermark still proves the receiver is `behind`. `current`
requires direct live observations at the exact local cut from every member of the current
authority; otherwise currency is `unknown` unless signed evidence proves `behind`.

A short batch is allowed but not proof of completeness. `server_applied_result_index` is signed;
receivers compare it with peer acknowledgement watermarks and other authority members, continue
while any known watermark is higher, query two when reachable, and audit a signed regression. A
one-voter session necessarily trusts its sole authority. Cursors persist both chain heads plus
`(peer, session_id, recovery_generation, authority_version)`. V1 retains all result records, so a
server MUST NOT silently skip an old cursor; it may offer a verified snapshot as an acceleration,
never as permission to omit history. Batch byte limits are in §11.2.

A settled application nonvoter is caught up when its verified result head equals the greatest
current-generation authority-signed watermark it has learned and no current authority peer reports
a higher one. This is distinct from Raft currency and is always labeled with the observation set;
an unreachable authority can make completeness unknown, never falsely current.

A logical snapshot is generated only at a committed checkpoint cut and signed by an active,
up-to-date member of the authority **in effect at that cut**. If no reachable member of the current
authority is authorized at the selected cut, the leader first commits a fresh checkpoint. The
signed root binds the session/workspace/generation, checkpoint event and complete covered tuple,
authority version/signer, `digest_version`, `projection_schema_version`, projection accumulator,
full projection-state digest (§5.6), content encoding, exact expanded/compressed byte totals,
record/page/chunk counts, expanded artifact digest, and final descriptor-page hash under
`codecomm/v1/snapshot`. The artifact contains the genesis lineage and authority handoffs, every
command result and accepted event through the cut, exact covered rows, and checkpoint
object/signature. Activity and audit views are rebuilt rather than trusted. A receiver verifies both
chains, handoffs/checkpoints, deterministic outcomes, accumulator, exact rows/state digest, and
schema compatibility before one transactional import, then applies only a contiguous result tail.
A later state cannot borrow an older checkpoint; absent a compatible snapshot, replay starts from an
older one or genesis.

Snapshot import retains the signed root, authority-valid checkpoint, and covered range as a trusted
checkpoint attestation. Every settled nonvoter MUST retain contiguous attestation coverage from
genesis or its latest retained trusted checkpoint through its local result head. Pre-checkpoint
batch attestations may be pruned only after a later authority-valid checkpoint covers their range
and local recomputation through that cut matches its heads, accumulator, and full state digest.
This standalone import never advances a Raft watermark. When the same artifact is carried by
`InstallSnapshot`, the snapshot-store adapter additionally binds its non-payload Raft metadata and
the replacement transaction records §6.2's local install baseline; only that verified path may
establish a Raft command watermark without per-command apply bindings for the compacted prefix.

Snapshot history is potentially session-sized and MUST NOT be allocated as one request or in-memory
object. The expanded artifact is a fixed record stream: each record is
`u16be(type_len) || ASCII(type) || u64be(payload_len) || JCS(payload)`. Order is all genesis records
by generation; then, for each `result_index`, one `result` followed by one or more
`result_mutation_chunk` records; all accepted events by `chain_index`; §5.6 rows by
table/primary-key; and the checkpoint. A result binds its exact mutation-encoding byte length,
SHA-256, and chunk count. Continuations carry deterministic consecutive slices of at most 2 MiB,
base64url-wrapped in JCS; every nonfinal slice is exactly 2 MiB. This represents the full 32 MiB
legal mutation ceiling without exceeding the record or compressed-chunk bound, including
incompressible identity encoding. Chunks end only between records. `artifact_digest` hashes the
exact expanded stream; each descriptor's `sha256` hashes the exact transmitted compressed chunk
bytes. The signed root names one encoding from `identity`, `gzip`, or `zstd`; encoding changes
therefore produce a different manifest even when expanded state is equal.

V1 record payloads are closed JCS objects:

| Type | Exact payload members |
|---|---|
| `genesis` | `boundary_transform_digest` (base64url SHA-256), `genesis` (exact canonical signed object), `recovery_authorization` (exact object or null) |
| `result` | `mutation_bytes`, `mutation_chunk_count`, `mutation_sha256` (base64url SHA-256), `result` (exact six-field §5.2.1 object) |
| `result_mutation_chunk` | `chunk_index` (zero-based within the result), `data` (base64url raw mutation-encoding slice), `result_index` |
| `event` | `chain_hash` (base64url SHA-256), `chain_index`, `proposal` (exact canonical signed proposal) |
| `projection` | `primary_key` (canonical key array), `row` (canonical logical row), `table` |
| `checkpoint` | `checkpoint_event_id`, `payload` (exact §5.2.1 checkpoint object plus authority signature) |

Descriptor pages are JCS objects containing `artifact_id`, zero-based `page_index`,
`previous_page_hash`, and a nonempty ordered descriptor slice
`(chunk_index, compressed_length, expanded_length, sha256)`. Chunk indices are contiguous from zero
across pages; duplicate, missing, empty-interior, or out-of-range descriptors reject the artifact.
With a 32-byte zero seed and UTF-8 artifact-ID bytes,
`page_hash_i = SHA-256("codecomm/v1/snapshot-page-chain" || 0x00 || len64(artifact_id) ||
artifact_id || u64be(i) || page_hash_(i-1) || JCS(descriptors))`. The receiver resumes
pages from its durable verified page head and trusts the descriptor stream only when page/chunk
counts, byte sums, and final hash match the signed root. Each root, page, and chunk independently
obeys §11.2's preallocation limits; the root also obeys §11.2's aggregate byte, record, chunk,
page, and generation ceilings before any indexed fetch. Before opening bulk transfer, the receiver
requires the root signer to equal the authenticated serving peer, verifies its identity signature
from applied membership, rejects a signer outside the matching applied authority, and applies the
smaller daemon receive quota in §11.2; a later authority version remains subject to full handoff
verification during replay. Parts are fetched idempotently by artifact ID/index. The receiver
writes pages/chunks to quarantine, verifies compressed bytes before bounded streaming decompression,
then verifies expanded lengths, record count/order, and full artifact digest before replay. Partial
artifacts are resumable and never visible as state; no request or allocation grows with history.

Wire replication MUST NOT contain SQL, SQLite pages/WAL/SHM, DB patches, Session Extension
changesets, or driver logs. Transport encoding/compression never changes either signed
canonical form. Workspace files and Git artifacts are separate data planes.

### 5.4 Event kinds

This table is the complete V1 `kind` namespace and the authority for what may be emitted at
`schema_version` 1. Local/leader ingress rejects a kind absent from the binary registry before Raft;
a replica that nevertheless encounters one in a committed entry halts before that entry under
§5.5 and writes no rejection. Entities and their fields are in §6.1.

`CAS: yes` means the event MUST carry `expected_entity_version` and is rejected on mismatch;
`conditional` uses the kind-specific tokens stated below. `Role` is the minimum application role, checked against
committed membership at apply time, never
against the proposer's claim. `Payload` names the fields beyond the §5.2 envelope; every
payload is a JSON object, bounded, with unknown fields rejected at `schema_version` 1.

`Actor` is the `actor_type` (§5.2) permitted to propose the kind. `agent` proposes for its own
bound session; `human` is an operator through the TUI or CLI; `daemon` is the local daemon acting
on its own initiative, and `daemon (leader)` marks a kind only the current leader's daemon proposes.

| Kind | Role | Actor | CAS | Payload |
|---|---|---|---|---|
| `task.created` | editor | agent, human | no | `title`, `body?`, `priority`, `labels?`, `blocked_by?` |
| `task.updated` | editor | agent, human | yes | any of `title`, `body`, `priority`, `labels`, `blocked_by`; an agent may update only its held task or an unowned task |
| `task.state_changed` | editor | agent, human | yes | `to_state`, `reason?`; `reason` is required iff entering `blocked` and prohibited otherwise. Agents may traverse only held-task work edges (`claimed→in_progress`, `in_progress→blocked`, `in_progress→done`, `blocked→in_progress`); humans only unowned `backlog↔ready`. Release, reassignment, and cancellation use dedicated kinds (§6.3) |
| `task.claimed` | editor | agent | yes | none; task must be actionable and claimable by the actor's device; actor comes from binding and a successful claim clears `intended_device_id` |
| `task.released` | editor | agent, human | yes | `release_reason` ∈ {`voluntary`, `forced`}; voluntary only by holder, forced by owner or an editor for its own device (§6.4) |
| `task.reassigned` | owner | human | yes | active `to_device_id`; releases the current holder, persists that device as the one-shot intended claimant, and leaves the task `ready` (§6.4) |
| `task.cancelled` | owner | human | yes | any non-terminal task to `cancelled` |
| `workspace.conflict.detected` | editor | daemon | no | `publication_id`, `merge_kind`, `replay_commit_oid?`, sorted `merge_base_oids[]`, `canonical_commit`, `candidate_commit`, sorted `paths[]`; deterministic `conflict_id` excludes detector output (§8.3) |
| `workspace.conflict.force_resolved` | owner | human | yes | `reason`; clears the completion gate with **no** resolution publication, for a conflict whose resolution can never be staged. Recorded as an operator override in `audit_events`; without it such a task could only be `cancelled`, i.e. mandatory data loss (§6.4) |
| `workspace.conflict.resolved` | editor | agent, human | yes | `resolution_publication_id`; it must be applied and list this conflict as staging-verified (§8.3) |
| `publication.proposed` | editor | agent | no | `task_id?`, terminal rejected/withdrawn `supersedes_publication_id?`, immutable Git metadata including `proposal_event_id = event_id`, `author_device_id = origin.device_id`, `author_agent_session_id = origin.agent_session_id`, sorted union-of-introduced-history `paths[]`, `artifact_digest`, `working_root_id`, `resolves_conflict_ids[]?`, and fresh current-target receipts carrying `staged_result_index`. The tip's first parent is `base_commit`; every path needs an active path lease; task/root bindings and bounded graph validation must match (§7.2) |
| `publication.reviewed` | editor | agent, human | yes | `verdict` ∈ {`approve`, `reject`}; an agent reviewer MUST be on another device, while an explicit human review may occur on any member device and is labeled self-review when local (§7.2) |
| `publication.applied` | editor | agent, human | yes | `expected_canonical_ref_version`, fresh current-target staging receipts; atomically advances the replicated canonical ref (§7.2) |
| `publication.withdrawn` | editor | agent, human | yes | `reason?`; an agent may withdraw only its own publication; a human owner may withdraw any, while an editor may withdraw only one authored on its device (§7.2) |
| `plan.revision_proposed` | editor | agent, human | no | `title`, `body`, `task_ids?`, `supersedes?` |
| `plan.current_selected` | owner | human | yes | `plan_revision_id`; CAS on the current pointer |
| `memory.appended` | editor | agent, human | no | `scope`, `task_id?`, `key`, `body`, `supersedes?` |
| `activity.recorded` | editor | agent, human, daemon | no | `task_id?`; bounded envelope has nonempty actions or rationale and actor-matching capture level; `entity_id = null` |
| `lease.acquired` | editor | agent | no | `scope`, `task_id?`, `path_globs?`, `ttl_seconds` within committed min/max; path scope requires 1–32 patterns, task scope prohibits them and requires the actor to hold that task |
| `lease.renewed` | editor | agent | yes | `ttl_seconds` within committed min/max |
| `lease.released` | editor | agent, human, daemon (leader) | yes | `release_reason` ∈ {`voluntary`, `forced`, `expired`}; holder, authorized human override, or leader expiry respectively |
| `agent.session.started` | editor | agent | no | `client_kind`, opaque daemon-minted `working_root_id`; profile is derived from `origin.agent_profile_id` |
| `agent.session.state_changed` | editor | agent, daemon | yes | `to_state`; an agent reports its own connected live state; only its owning daemon enters `disconnected` or restores the stored `resume_state` after local capability validation (§§6.1, 7.2) |
| `agent.session.ended` | editor | agent, daemon | yes | `end_reason`: agent only `clean`; owning daemon only `disconnect_timeout`, `operator`, or `crash_reap`; `recovery` is boundary-transform-only. Atomically releases every claim/lease (§6.4); resume/reap CAS has one winner |
| `membership.device_admitted` | owner | human | conditional | identity key, role, `daemon_version`, `max_apply_level`, initial epoch binding; expected version is absent for a new row or invite-bound to the same-key `requires_readmission` row after recovery |
| `membership.version_reported` | any member | daemon | yes | ASCII SemVer `daemon_version` (≤64 bytes), `max_apply_level`; actor updates only its own active row and emits only on change |
| `membership.role_changed` | owner | human | yes | `device_id`, `role`; cannot remove the last active owner |
| `membership.owner_recovered` | — | human | yes | `recovery_authorization`; origin/subject must be the same active editor; recovery-key signature over session/generation, event/subject IDs, and expected version; sets only that device's role to owner (§4.3) |
| `membership.device_revoked` | owner | human | yes | subject, `reason` (1–1024 bytes), resulting voter target, and `expected_voter_set_version`; both CAS tokens always validate. A target-voter revocation advances a legal target excluding it; a nonvoter revocation requires the unchanged target and does not increment its version. Cannot remove the last active owner or sole target voter, and active members remaining in the current credential authority must still form its majority (§3) |
| `membership.voter_set_changed` | owner | human | yes | `voter_set[]`, the full resulting set; `entity_id` is `session_id` and CAS is on `voter_set_version`; count 1/3/5 at rest; reconciled to Raft by the leader (§3) |
| `membership.voter_set_activated` | — | daemon | conditional | target/current-authority versions, exact target, every target's checkpoint/config proof, and prior-authority handoff; updates only `credential_authority` after all target voters are promoted (§3) |
| `policy.changed` | owner | human | yes | allowlisted mutable policy keys only (§4.2); `entity_id = session_id`; the resulting policy must satisfy §11.2 hard ranges/current-use guards; immutable credential, primitive/digest, byte/activity/dependency-bound, control-path-policy, publication graph/parent/receipt-window, multicast-group/port, and merge-input values are rejected |
| `credential.authorized` | any member | daemon (leader-scheduled) | no | key/binding, role, endorsed times, exact `authority_voter_set_version`, and sorted authority-majority `clock_endorsements[]` (§4.6) |
| `control_file.change_proposed` | editor | agent, human | no | path, `operation` (`upsert` or `delete`), operation-valid digest/size, and ≤64 KiB diff (§8.4) |
| `consensus.checkpoint` | — | daemon (leader-scheduled) | no | session/generation and authority signer/version; covered log/event/result tuples; projection accumulator/version/schema; authority signature (§5.2.1, §5.6) |
| `audit.recorded` | — | daemon | no | stable ASCII `action`/`outcome` codes (≤64 bytes each), redacted `subject` (≤256), `subject_device_id`, and `subject_credential_epoch`; only for bounded member-attributable request rejections with no accepted event or retained command result (below) |

The `Actor` column is authoritative for who may propose each kind; a proposal from any other
`actor_type` is rejected deterministically. Operator overrides (`task.reassigned`, `task.cancelled`, `plan.current_selected`, `policy.changed`,
`workspace.conflict.force_resolved`, owner-controlled membership changes, and the `forced` case of
`task.released` / `lease.released`) are `human` only, which keeps them off the MCP surface (§6.4,
§7.1). The daemon reaps a dead or expired session with one CAS-protected
`agent.session.ended`; its reducer performs bounded atomic releases, so no follow-up release events
can be lost. The leader schedules credential authorization, voter activation, and checkpoints;
reducers validate their signed endorsements/proofs rather than trusting the operational
`leader-scheduled` annotation as event data.
`membership.version_reported` is the sole ordinary self-service membership
mutation: actor binding fixes its device and it cannot alter role, status, identity, or voter set.
`membership.owner_recovered` is the sole break-glass exception: it requires a valid
`codecomm/v1/owner-recovery` signature from the genesis-bound recovery key over
`(session_id, recovery_generation, event_id, subject_device_id, expected_entity_version)`, and the
subject MUST be the active editor submitting the event. The payload carries the closed
`recovery_authorization` object and signature produced by §5.1's local challenge; the private key is
entered through no-echo local input and never enters the event, daemon, argv, environment, or
network.
`credential.authorized` has no minimum application role because every
member must rotate keys (§4.6); its clamp instead requires the authorized
`role` to equal committed membership.
Whenever a payload repeats the subject already encoded by `entity_id` (`device_id`, `session_id`, or
control path), equality is mandatory; schemas SHOULD omit the duplicate where the operation does not
need it. Every otherwise-unbounded free-form `reason` in this namespace is 1–1024 UTF-8 bytes.

**Membership wire schemas.** The following are the closed schema-version-1 payloads. Binary values
are strict unpadded base64url; public keys, digests, and signatures are exactly 32, 32, and 64 bytes.
All integers are JCS-safe nonnegative integers, and `max_apply_level` is in `1..2^31-1`.

- `membership.device_admitted` has exactly `identity_public_key`, `role`, `daemon_version`,
  `max_apply_level`, and `initial_epoch_binding`. The binding has exactly `epoch` (1),
  `epoch_public_key`, `key_digest`, and `binding_signature`; its digest is SHA-256 of the epoch key.
  The signature is by `identity_public_key` under `codecomm/v1/credential-binding` over
  `JCS({device_id, epoch, epoch_public_key, session_id})`. Admission validates the binding; the
  scheduler carries it into the first `credential.authorized`, whose reducer independently validates
  the complete binding. Admission creates no extra projection row.
- `membership.version_reported` has exactly `daemon_version` and `max_apply_level`.
  `membership.role_changed` has exactly `device_id` and `role`; a role equal to the committed role
  is rejected rather than version-bumped.
- `membership.owner_recovered` has exactly `recovery_authorization`. That object has exactly
  `session_id`, `recovery_generation`, `event_id`, `subject_device_id`,
  `expected_entity_version`, and `signature`. `signature` is excluded from its own preimage and is
  made by the generation's recovery key under `codecomm/v1/owner-recovery` over the JCS object of
  the other five fields.
- `membership.device_revoked` has exactly `device_id`, `reason`, `voter_set`, and
  `expected_voter_set_version`. A target-voter result is the next smaller legal count, is a strict
  subset of the prior target, and excludes the subject; it may not introduce a voter. A nonvoter
  result is byte-identical to the prior sorted target. Active and `requires_readmission` subjects
  may be revoked; revoked or absent subjects may not. `membership.voter_set_changed` has exactly
  `voter_set`. An identical target is rejected rather than version-bumped.

`membership.voter_set_activated` has exactly `target_voter_set_version`,
`expected_authority_voter_set_version`, `voter_set`, `activation_checkpoint_event_id`,
`activation_proofs`, `prior_authority_signer`, and `prior_authority_handoff`. Proofs are sorted in
the exact `voter_set` order, one per voter. Each proof is a complete canonical object with exactly:

```text
session_id, workspace_id, recovery_generation,
target_voter_set_version, current_authority_voter_set_version, voter_set,
voter_device_id, live_configuration_index, checkpoint_event_id,
checkpoint, checkpoint_signature, voter_signature
```

`checkpoint` is the exact unsigned §5.2.1 object with:

```text
session_id, workspace_id, recovery_generation,
authority_voter_set_version, signer_device_id, term,
covered_applied_log_index, covered_chain_index, covered_chain_hash,
covered_result_index, covered_result_hash, projection_accumulator,
digest_version, projection_schema_version
```

`checkpoint_signature` verifies that object under `codecomm/v1/checkpoint` by its active
current-authority signer. `voter_signature` is excluded from its own preimage and verifies the
remaining proof object under `codecomm/v1/voter-activation-proof` by `voter_device_id`. Every proof
must carry the same target/current-authority versions, sorted target, configuration index,
checkpoint event ID, checkpoint bytes, and checkpoint signature. The checkpoint's authority version
must equal the expected current authority, and its `covered_applied_log_index` must be greater than
or equal to the common `live_configuration_index`, proving the checkpoint follows promotion.

The prior-authority handoff preimage is
`JCS({session_id, workspace_id, recovery_generation, target_voter_set_version,
expected_authority_voter_set_version, voter_set, activation_checkpoint_event_id,
activation_proofs, prior_authority_signer})`, where `activation_proofs` contains the complete
voter-signed objects above. `prior_authority_handoff` is excluded and verifies under
`codecomm/v1/voter-authority-handoff` by an active member of the expected current authority. An
already-activated target is rejected. These exact exclusions make persisted proof bytes sufficient
for offline handoff-chain verification.

**Audit does not duplicate retained outcomes.** Every accepted domain event and every first-seen
committed domain rejection projects its auditable fields directly into local `audit_events`.
`audit.recorded` exists only for an authenticated active member request that was rejected before it
obtained either an accepted event or a retained `command_results` row, such as an invalid
non-event API mutation. A conforming reporter checks the counter before proposing it; when no quorum
or capacity remains, it updates only the local aggregate. Thus one reporter observation gets at most
one durable source through its local idempotency mapping. Independent peers may legitimately observe
and report the same request; those are distinct attributed observations, not duplicates to collapse.

For `audit.recorded`, `subject_device_id` names the rejected request's authenticated member, not the
reporting daemon, and `subject_credential_epoch` MUST equal that device's latest committed epoch.
Its closed payload is exactly `action`, `outcome`, `subject`, `subject_device_id`, and
`subject_credential_epoch`; the first two use the stable ASCII code grammar and bounds above.
The event origin names the reporting daemon and the audit view MUST show both reporter and subject:
subject attribution is that member daemon's signed observation, not independent proof. This is
acceptable only under V1's non-Byzantine-member protocol assumption and grants no authority.
The digest-covered `audit_counters` row for that device stores the current epoch and accepted count;
`credential.authorized` advances the epoch and resets the count, while an accepted audit increments
it. The reducer rejects beyond §11.2's `audit_depth_per_device_per_epoch`. Excess attempts become one
bounded, rate-limited local aggregate with source, action, first/last seen, and count. Unknown,
unauthenticated, revoked, or stale-epoch sources always use that aggregate. No reducer scans retained
history to enforce a depth. The cap bounds accepted audit events, not the general authorized-member
result-chain exhaustion risk in §16. §4.4 applies the same local rule to discovery.

Two enums are fixed at `schema_version` 1:

- `actor_type`: `agent`, `human`, `daemon`.
- `capture_level`: `agent_reported`, `human_reported`, or `daemon_observed`, with the exact
  actor mapping and direct-observation rule of §5.2. It records *how* an action was learned and never
  implies completeness (§16 risk 12).

A newly created entity starts at version 1. Create events carry no `expected_entity_version`;
mutations carry the current version. `membership.device_admitted` is conditional:
absent expectation creates a never-enrolled device, while §3.1 readmission requires the owner
invite-bound `requires_readmission` row version and exact retained identity key.
`membership.voter_set_activated` is also conditional:
it CASes the authority version carried in its payload and the current target version rather than a
caller-owned entity version. Replaying an exact command returns its durable original result by
`event_id`; changed bytes under that ID are an idempotency conflict (§5.3).

### 5.5 Version skew and frozen reducers

Devices upgrade independently, so two daemon releases may share a cluster.

**Frozen reducers.** The outcome of a released `(kind, schema_version)` pair MUST NOT change. A fix
or extension needs a new kind or schema version, never reinterpretation. This is non-mergeable
under §12.1.

**Apply levels.** Product versions are SemVer strings for operators; reducer compatibility uses a
monotonic integer. Each binary declares `max_apply_level`; each event carries the fixed
`min_apply_level` for its `(kind, schema_version)`. The leader MUST NOT propose an event whose level
exceeds committed `cluster_min_apply_level`; this envelope check precedes kind dispatch, so an older
leader can reject a not-yet-enabled kind without applying it. Raising the floor is therefore the
feature-enable operation, not merely a startup warning.

A replica below the committed floor, or facing an unknown kind/required input at or below a floor it
claimed to support, MUST stop before the entry, leave `last_raft_applied_log_index` unchanged, and
never substitute a local rejection for an outcome a newer replica accepted. It latches the required
level, serves prior local reads, and shuts down its Raft instance; it neither campaigns, votes,
accepts replication, nor serves consensus HTTP routes while halted. A halted leader may attempt one
bounded transfer first, but safety and progress MUST NOT depend on success. The committed
configuration still defines quorum, so a compatible majority may continue and any smaller set fails
closed until enough voters upgrade. Upgrade restarts from persisted Raft state and resumes before
the blocked entry. Version halt alone never permits §3.1 recovery.

Genesis carries `cluster_min_apply_level`. A daemon below it refuses to join/start that session.
An owner may raise it through `policy.changed` only after every active `devices` row reports a
sufficient `max_apply_level`. Admission initializes `(daemon_version, max_apply_level)`;
a changed binary commits `membership.version_reported` before agent work or another mutation.
Presence is irrelevant, and the reducer reads only committed device rows. A binary below the
committed floor cannot start merely to report a downgrade.

The supported product-release skew is N/N-1, subject to apply levels. A member with an expired
content credential renews on the consensus plane before reporting; halted daemons expose no
consensus route and provide no clock endorsement (§4.6). The event emitter stamps the one
authoritative level frozen for
its pair, so emitters cannot disagree. Compatibility tests must prove every event an N-1 member may
receive either applies identically or halts cleanly.

### 5.6 Projection commitments

Two commitments avoid both an unbounded checkpoint scan and false confidence in cached SQLite
bytes:

- **Projection accumulator:** incrementally commits every deterministic protocol/domain mutation and
  is compared at each checkpoint. It detects reducer divergence in O(changed rows).
- **Projection-state digest:** scans exact current logical rows. Genesis/recovery, logical-snapshot
  creation/import, backup/export, `state recover`, and `state scrub` MUST compute it; ordinary
  checkpoints do not. It independently detects an untouched corrupt row.

For first-seen result `r`, form a JCS array of every changed covered row:

```text
mutation = {"table": table_name,
            "primary_key": [typed PK components],
            "before": exact covered row object or null,
            "after":  exact covered row object or null}
mutation_bytes_r = JCS(mutations sorted by fixed table order, then canonical PK bytes)

accumulator_r = SHA-256("codecomm/v1/projection-accumulator" || 0x00
                  || accumulator_(r-1) || u64be(result_index_r) || result_hash_r
                  || len64(mutation_bytes_r) || mutation_bytes_r)
```

The result hash binds proposal and outcome; mutations bind resulting state. A domain rejection may
contain only an `origin_scopes` mutation, while a gap/reuse rejection has an empty array. Exact
duplicates advance neither result chain nor accumulator. Boundary seeds are:

```text
accumulator_seed_0 = SHA-256("codecomm/v1/projection-accumulator" || 0x00
                       || digest(genesis_0) || initial_state_digest)
accumulator_seed_k = SHA-256("codecomm/v1/projection-accumulator" || 0x00
                       || predecessor_accumulator || digest(genesis_k)
                       || post_transform_state_digest)
```

All appended values are 32 bytes. A successor changes the accumulator head at the unchanged result
position; the result index does not restart. Accumulator heads, like chain heads, are compared only
within one session/generation tuple.

`genesis_records.boundary_transform_digest` stores `initial_state_digest` for generation 0 and
`post_transform_state_digest` for every successor. It is always the full projection-state digest at
that generation boundary.

The full state digest covers logical rows, never pages, rowids, DDL order, insertion order, or free
lists. JCS orders object keys; exact covered-column membership is nevertheless frozen.

```text
pk_bytes     = JCS([typed primary-key components])
row_bytes    = JCS(object containing exactly the table's covered columns)
row_digest   = SHA-256("codecomm/v1/projection-row" || 0x00
                      || len64(table_name) || table_name
                      || len64(pk_bytes) || pk_bytes
                      || len64(row_bytes) || row_bytes)
table_digest = SHA-256("codecomm/v1/projection-table" || 0x00
                      || len64(table_name) || table_name || u64be(row_count)
                      || each row_digest in canonical PK order)
state_digest = SHA-256("codecomm/v1/projection-state" || 0x00
                      || u64be(digest_version) || u64be(projection_schema_version)
                      || each table_digest in fixed table order)
```

`len64`/`u64be` are unsigned 8-byte big-endian; names are UTF-8. Canonical PK order compares unsigned
bytes of `pk_bytes`, and no PK component is null.

Covered tables, in order: `origin_scopes`, `audit_counters`, `tasks`, `plan_revisions`,
`plan_current`, `memory_records`, `leases`, `devices`, `voter_set`, `credential_authority`,
`agent_sessions`, `canonical_refs`, `credential_authorizations`, `publications`,
`control_file_proposals`, `merge_conflicts`, and `session_policy`. They contain only committed
replicated fields. The voter target and deliberately lagging credential authority are separate;
Raft's live configuration and local control-file approvals are not covered.

Excluded: signed `genesis_records`; chain-backed `events`, `chain_checkpoints`, and
`command_results`; local/support `event_provenance`, `consensus_state`, `replication_cursors`,
`replication_attestations`, `peer_acks`, `lease_deadlines`, `agent_resume_tokens`, `agent_launches`,
`managed_roots`, `git_artifacts`, `outbox`, `local_requests`, `owner_recovery_challenges`,
`peer_endpoints`, and
`origin_counters`; derived `activity`/`audit_events`; and local
`schema_migrations`/`control_file_approvals`. A reducer reads only covered state plus the exact
current proposal and chain heads; there is no retained-history or local-state exception.

Changing a covered table/column/order, mutation encoding, PK encoding, or canonical value encoding
requires new `digest_version` and `projection_schema_version`; excluded-storage migrations do not.
Comparable replicas share `(session_id, recovery_generation, result_index, digest_version,
projection_schema_version)` and MUST have equal accumulators. A mismatch halts apply, preserves
evidence, and requires §9 recovery. Full-state mismatch at a trust boundary does the same; repair
replays verified results into a fresh store and never copies another replica's SQLite bytes.
