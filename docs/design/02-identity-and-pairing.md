# CodeComm V1 Design — Part 03: Identity, Discovery, and Pairing

Part 3 of 14. Contents: §4 intro, §4.1 primitives, §4.2 identifiers, §4.3 roles, §4.4 discovery, §4.5 pairing.
Section map, review status, and reading order: [README.md](README.md)

Authoritative revision 0.14; maintained only in this split set.

Normative terms follow RFC 2119/8174; declarative requirements and table rows headed "MUST" or
"Required" are equally normative.

---

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
| Explicit binary integers outside JCS | unsigned 8-byte big-endian; variable-length byte strings are length-framed as their defining section states |
| Key agreement, record encryption | none of CodeComm's own; TLS 1.3 provides it (§4.6) |

`signed_bytes` for a singly signed object is `JCS(object minus its signature field)`. The sole V1
multi-signature exception is successor genesis: both `recovering_identity_signature` and
`quorum_recovery_signature` cover the same `JCS(record minus both signature fields)`, under their
respective §3.1 labels. JCS fixes UTF-8, lexicographic key order over UTF-16 code units, no
insignificant whitespace, and canonical number form. Every signed field MUST be a string, a JSON
integer in `[-(2^53-1), 2^53-1]`, a boolean, `null`, an array, or an object; floating-point values
are prohibited. Durations and sizes are integers with units in field names.

Timestamp text is canonical UTC RFC 3339: uppercase `T`/`Z`, no numeric offset, and seconds
`00..59`. Whole-second fields are exactly `YYYY-MM-DDTHH:MM:SSZ`. Fractional fields omit the
fraction when zero; otherwise they carry 1–9 digits with no trailing zero before `Z`. Credential
validity uses whole seconds because X.509 cannot preserve fractions; event/display times may use the
fractional form. Semantically equivalent noncanonical text is rejected before signing or
verification.

The pre-JCS decoder is strict: it rejects duplicate object member names, invalid UTF-8 or surrogate
sequences, trailing data, non-integer JSON numbers, and nesting deeper than 32 before allocating a
typed object. It never parses through a generic map and re-serializes later. Byte, item, and string
bounds are checked during decode, before signature verification.

Unknown fields are never stripped before verification: a verifier canonicalizes and
verifies exactly the bytes it received, so an object carrying an unrecognized field
still verifies, and §5.1's capability rules then decide whether it is acceptable. The
negotiated binary encoding and compression of §5.1 are a transport wrapper only; they
never alter `signed_bytes` (§5.3).

`device_id = "cc1" || lowercase_hex(SHA-256(raw 32-byte Ed25519 public key))`, full 64
hex characters, no truncation; comparison is over the whole string. A `device_id` is a
commitment to one public key, so enrolling a new key produces a new device identity
(§4.2).

Signed objects and pairing transcripts use the exact ASCII domain labels below. Ed25519 rows sign:

```text
signed_input = domain_label || 0x00 || signed_bytes
```

Only Ed25519 rows share the `signed_input` construction. Each HMAC or digest row uses the exact
section-defined preimage named below; none inherits a generic `transcript_hash` suffix. They are not
signatures. The `0x00` separator cannot occur inside a label.

| Label | Construction | Protected object or input |
|---|---|---|
| `codecomm/v1/genesis` | Ed25519 | Immutable genesis record |
| `codecomm/v1/genesis-digest` | SHA-256 | Complete signed genesis record |
| `codecomm/v1/discovery` | Ed25519 | Multicast advertisement datagram |
| `codecomm/v1/endpoint-hints` | Ed25519 | Member's bounded source-owned endpoint set |
| `codecomm/v1/invite` | Ed25519 | Invite bundle issued by an owner |
| `codecomm/v1/invite-proof` | HMAC-SHA-256 | Joiner's exporter-bound invite-possession proof |
| `codecomm/v1/credential-binding` | Ed25519 | Ephemeral TLS key / session / device / epoch binding |
| `codecomm/v1/credential-time-endorsement` | Ed25519 | Voter endorsement of a credential binding and proposed `issued_at` (§4.6) |
| `codecomm/v1/voter-activation-proof` | Ed25519 | Target voter's applied-checkpoint/configuration proof (§3) |
| `codecomm/v1/voter-authority-handoff` | Ed25519 | Prior authority's activation of the proven target (§3) |
| `codecomm/v1/event-origin` | Ed25519 | Origin's domain proposal |
| `codecomm/v1/checkpoint` | Ed25519 | Committed chain checkpoint (§5.2.1) |
| `codecomm/v1/batch` | Ed25519 | Served catch-up batch (§5.3) |
| `codecomm/v1/snapshot` | Ed25519 | Logical snapshot |
| `codecomm/v1/snapshot-page-chain` | SHA-256 | Bounded logical-snapshot descriptor pages (§5.3) |
| `codecomm/v1/git-ref-advertisement` | Ed25519 | Source-owned draft/publication ref advertisement (§8.1) |
| `codecomm/v1/git-stage-receipt` | Ed25519 | Voter proof of durable validated publication objects (§7.2) |
| `codecomm/v1/git-canonical-coverage` | Ed25519 | Target-voter proof of durable canonical objects (§8.1) |
| `codecomm/v1/owner-recovery` | Ed25519 | Break-glass owner restoration while quorum still exists (§4.3) |
| `codecomm/v1/quorum-recovery` | Ed25519 | Offline quorum-recovery authorization (§3.1) |
| `codecomm/v1/chain` | SHA-256 | Accepted-event chain (§5.2.1) |
| `codecomm/v1/result-chain` | SHA-256 | Durable command-result chain (§5.2.1) |
| `codecomm/v1/projection-accumulator` | SHA-256 | Incremental deterministic projection-mutation commitment (§5.6) |
| `codecomm/v1/projection-row` | SHA-256 | One logical row in a full projection-state digest (§5.6) |
| `codecomm/v1/projection-table` | SHA-256 | One table in a full projection-state digest (§5.6) |
| `codecomm/v1/projection-state` | SHA-256 | Full projection-state digest at a trust boundary (§5.6) |
| `codecomm/v1/publication-metadata` | SHA-256 | Immutable publication metadata covered by staging receipts (§7.2) |
| `codecomm/v1/conflict-id` | SHA-256 | Immutable merge-conflict identity input (§8.3) |
| `codecomm/v1/draft-manifest` | SHA-256 | Canonical sparse draft-change manifest (§8.1) |
| `codecomm/v1/control-manifest` | SHA-256 | Ephemeral per-device control-file digest manifest (§§5.1, 8.4) |
| `codecomm/v1/agent-resume` | SHA-256 | Local agent-resume capability commitment (§7.2) |
| `codecomm/v1/pairing-transcript` | SHA-256 | Exact TLS-exporter-bound pairing transcript (§4.5) |
| `codecomm/v1/sas-transcript` | SHA-256 | Pairing authentication-string transcript |

The `v1` component is the primitive-suite version, carried in the genesis protocol policy
and independent of `schema_version`. Changing any primitive requires a new suite version
and a new set of labels; a member MUST reject an object whose label names a suite it does
not implement.

### 4.2 Identifiers

| ID | Meaning |
|---|---|
| `device_id` | `cc1` + hex SHA-256 of the Ed25519 identity public key (§4.1); one per OS-account installation, shared across its sessions |
| `session_id` | UUIDv7 for one active recovery generation; a successor generation gets a new ID (§3.1) |
| `workspace_id` | CSPRNG UUIDv4 for the logical workspace lineage; one active daemon per joined workspace (§3.2) |
| `agent_profile_id` | Optional stable persona/configuration ID |
| `agent_session_id` | Never-reused UUIDv7 for one running agent instance |
| `event_id` | Never-reused UUIDv7 minted by the origin daemon for one canonical local command (§5.1) |
| `origin_boot_id` | Never-reused UUIDv7 minted at daemon start; required for `human`/`daemon` events and null for `agent` events |
| `origin_sequence` | Monotonic sequence within one origin scope: `agent_session_id` for `agent`, `origin_boot_id` for `human`/`daemon`. Uniqueness is over `(device_id, agent_session_id_or_origin_boot_id, origin_sequence)`; the scope ID is always present in the signed `origin` block |
| `entity_id` | Typed mutation identity: UUIDv7 for `task.*`, `plan.revision_proposed`, `memory.*`, `lease.*`, `agent.session.*`, and `publication.*`; deterministic `ccf1` for `workspace.conflict.*` (§8.3); `device_id` for device-scoped `membership.*` and `credential.*`; `session_id` for `membership.voter_set_changed`, `membership.voter_set_activated`, `plan.current_selected`, and `policy.changed`; canonical workspace-relative path for `control_file.change_proposed`; null for `activity.recorded`, `consensus.checkpoint`, and `audit.recorded`. The fixed form lets a reducer parse it before the payload |
| `log_index` | Committed Raft log index; event indices may have gaps |
| `chain_index`, `result_index` | Dense accepted-event and first-seen-command positions, respectively (§5.2.1) |

Every UUID uses RFC 9562 lowercase canonical `8-4-4-4-12` text, without braces, URN prefix, or
alternate encoding. `workspace_id` is UUIDv4; every protocol field declared UUIDv7 — including
session, agent session, event, boot, task, plan revision, memory, lease, publication, local request,
client instance, working-root, invite, and draft-stream IDs — is a never-reused UUIDv7.
Algorithm-tagged Git OIDs are exactly lowercase `sha1:<40 lowercase hex>` or
`sha256:<64 lowercase hex>`, matching the genesis object format; abbreviations and untagged OIDs are
rejected. The one exception is §8.1's ref-safe `snapshot_id`, which is the matching raw lowercase
hex.

Every agent event carries `(session_id, device_id, agent_session_id)`. `agent_session_id` MUST
come from secure daemon randomness, never PID, label, path, or vendor display ID. A directory
name is display-only; `workspace_id` is authoritative. Long-lived private keys MUST stay in the
OS credential store, outside the workspace. Content-epoch private keys use the same protected store
and are erased per §4.6. If no provider is available or the store is locked — a headless Linux host
with no D-Bus session, or an unattended boot before first unlock — the daemon MUST refuse to start
with a distinct, actionable error. It MUST NOT fall back to a workspace file, environment variable,
or in-memory-only long-lived identity (§3.2).

The bootstrap device signs an immutable genesis record binding `session_id`, `workspace_id`,
`recovery_generation` (0 at creation), `recovery_public_key` (§3.1),
`primitive_suite_version = 1`, `protocol_policy_version = 1`, Git object format, initial canonical
commit, protocol policy, initial membership, voter target, and matching initial credential
authority. The
canonical row of §6.1 is initialized from that commit on every replica. Protocol policy is the set of values every
member must agree on: `credential_epoch_seconds`, `credential_overlap_seconds`, and
`credential_renewal_lead_seconds` (§4.6),
`checkpoint_events` and `checkpoint_interval_seconds` (§5.2.1), `digest_version`,
`projection_schema_version`, event/result chain versions, `primitive_suite_version`,
`protocol_policy_version`, maximum signed-JSON nesting depth,
`max_event_bytes` and `event_path_array_max_bytes` (§5), `control_file_max_bytes`,
`control_file_diff_max_bytes`, and `control_path_policy_version` (§8.4), admission
depth limits per member device per session and per agent session (§10),
`task_dependency_walk_max` (§6.1), `activity_duration_max_ms` (§5.2), lease
minimum/default/maximum TTL, `agent_claim_limit`, `agent_lease_limit`, `device_claim_limit`, and
`device_lease_limit` (§6.1), the
multicast group and advertisement interval (§4.4), `merge_inputs_version` and the pinned merge
configuration it names (§8.3), `audit_depth_per_device_per_epoch` (§5.4),
`publication_receipt_window_results`, `publication_introduced_commit_max`,
`publication_changed_edge_max`, and `publication_parent_max` (§7.2), maximum member devices and active agent sessions per
session (§2.2), and
`cluster_min_apply_level` (§5.5). §11.2 is the authoritative list of which
constants are committed. Endpoint hint
TTL is derived from the committed advertisement interval, not separately committed. Everything else
is local configuration. V1's mutable `policy.changed` allowlist is
`checkpoint_events`, `checkpoint_interval_seconds`, the three `lease_*_ttl_seconds` values,
`agent_claim_limit`, `agent_lease_limit`, `device_claim_limit`, `device_lease_limit`,
`advertisement_interval_seconds`, `audit_depth_per_device_per_epoch`,
`max_member_devices`, `max_active_agent_sessions`, and
`cluster_min_apply_level`. Genesis and updates satisfy §11.2's immutable hard ranges, relations, and
current-use guards. Credential timing, primitive/protocol-policy/digest versions, chain versions, signed-JSON depth,
event/path/control-file/activity bounds, `control_path_policy_version`, multicast groups/port, merge
inputs, task-dependency and publication graph/parent bounds, and the publication-receipt window are immutable in V1; changing one requires a new
protocol-policy version and ADR, and the V1 reducer rejects it.

Every reference to a genesis digest means exactly:

```text
genesis_digest = SHA-256("codecomm/v1/genesis-digest" || 0x00
                         || JCS(complete genesis record including signatures))
```

Generation 0 has its `creator_signature`; a successor has both §3.1 authorization signatures over
the same signature-free body. Invites,
successor links, chain seeds, and sibling-successor comparison use this digest.

Subsequent trust changes require committed membership events. There is no transferable session
CA key. A successor genesis record is written only by quorum recovery (§3.1), rotates the recovery
key, and chain-links to its predecessor, so genesis is immutable within a `recovery_generation` and
auditable across generations.

### 4.3 Roles

| Capability | Owner | Editor |
|---|---:|---:|
| Read coordination | Yes | Yes |
| Receive/send shared Git objects | Yes | Yes |
| Claim/update tasks | Yes | Yes |
| Propose plan/memory | Yes | Yes |
| Make plan current | Yes | No |
| Force-release own-device task or lease (§6.4) | Yes | Yes |
| Force-release another device, reassign, or cancel (§6.4) | Yes | No |
| Invite, change roles/voters, revoke, change policy | Yes | No |

Role/voter changes are signed, committed, audited, and cannot be self-granted. Credential roles
MUST match current committed membership. An ordinary role change or revocation MUST leave at least
one active owner. If the sole owner identity is lost while Raft quorum survives, an operator on an
active editor device may use the offline recovery key through the dedicated
`membership.owner_recovered` event (§5.4); this restores only that local device to `owner`, rotates
no other authority, and still requires normal quorum commitment. If both the sole owner identity and
recovery key are lost, governance is unrecoverable even though existing strong writes may continue.

### 4.4 Discovery

Each session daemon MUST multicast a signed, versioned datagram on every selected
interface, and immediately on start, wake, and address change (§2.3). Its multicast base cadence is
`min(advertisement_interval_seconds, 48)` seconds with independently sampled uniform ±25% jitter;
each datagram expires 60 seconds after the whole-second UTC emission time. The configured interval,
not this cadence clamp, continues to derive endpoint-set TTL. This keeps every allowed 5–300 second
policy value usable without creating routine gaps in short-lived discovery hints. A device joined to
several sessions emits one advertisement stream per session, and receivers filter by `session_id`
(§3.3). Group address, interval, TTL, and size limit are in §11.2.

```json
{
  "magic": "codecomm",
  "protocol": 1,
  "session_id": "uuid",
  "https_port": 47831,
  "credential_epoch": 42,
  "advertising_key_digest": "base64url",
  "advertisement_nonce": "base64url",
  "expires_at": "RFC3339",
  "signature": "base64url"
}
```

`advertising_key_digest` is exactly 32 bytes, `advertisement_nonce` is a fresh 16-byte CSPRNG value
per datagram, and all binary fields use §4.1 encoding. During overlap the sender uses the greatest
epoch whose `not_before` has arrived; before that instant it keeps advertising with the prior active
key. After all authorizations expire it uses the greatest retained epoch only as the signed endpoint
hint described below.

The source address is only an endpoint hint. Datagrams contain no workspace, device, or
operator names, paths, stable identity fingerprints, secrets, tasks, or activity. They do
broadcast `session_id` and `credential_epoch` in the clear — an accepted residual disclosure of a
session's existence and credential state, linkable across time by anyone on the same segment.

The current authorized epoch key signs the packet and its digest MUST match a committed
credential authorization the receiver has applied. A daemon whose content credential has expired
signs with its latest authorized epoch key even though that authorization has lapsed; a receiver
verifies the signature against the retained authorization and treats the source address as an
endpoint hint only — it MUST NOT open a content connection or revive the expired credential, and
reaches the daemon on the consensus plane instead (§4.6). The daemon retains only the latest epoch
private key after expiry, solely for this advertisement, and MUST erase it as soon as a
replacement authorization activates, on applying its own revocation, or on leaving the session
(§9) — whichever comes first. A device stops advertising only when it applies its own revocation;
until then it may be stale. Any peer that has applied that revocation immediately discards its
datagrams, endpoint set, and nonmanual dial guesses and refuses new retention. Before pairing the
signature is informational.

An authenticated member also publishes this closed identity-signed object under
`codecomm/v1/endpoint-hints`; its own response from `GET /v1/peers` always includes it. The response
carries the exact JCS bytes as one opaque base64url value, and peers may relay only that value, never
a parsed/re-serialized object:

```json
{
  "schema_version": 1,
  "session_id": "uuid",
  "workspace_id": "uuid",
  "recovery_generation": 0,
  "device_id": "cc1<64 hex>",
  "endpoint_sequence": 1786123456789,
  "issued_at": "RFC3339",
  "expires_at": "RFC3339",
  "endpoints": [{"ip": "192.0.2.4", "port": 47831}],
  "signature": "base64url"
}
```

The source sets `endpoint_sequence = max(previous + 1, current Unix milliseconds)` and persists it
before publication; it must remain a JCS-safe integer. This normally survives a restored older local
counter without making wall time an authority. `issued_at`/`expires_at` use whole seconds and their
positive difference is at most the current derived endpoint-hint TTL (eight advertisement
intervals). A receiver additionally requires
`issued_at <= local_now + credential_clock_skew_seconds`,
`expires_at > local_now`, and `expires_at <= local_now + endpoint_hint_ttl_seconds +
credential_clock_skew_seconds`. These are local liveness checks, never reducer input.

`endpoints` is nonempty, unique, and sorted by address family, raw address bytes, then port, with at
most §11.2's per-member count. IPv4 uses canonical dotted decimal; IPv6 uses lowercase RFC 5952
without brackets or a zone. Ports are 1-65535. The source may name only an exact unicast address and
listener port on a selected LAN/VPN interface; loopback, unspecified, multicast, broadcast,
IPv4-mapped IPv6, and IPv6 link-local addresses are forbidden. Hostnames are forbidden, so endpoint
handling performs no DNS lookup.

Receivers verify the byte bound, schema, active membership, identity/signature, session/workspace/
generation, time window, sequence, address grammar, ordering, and endpoint caps before retention.
For one member, a greater sequence atomically replaces the prior valid object; the same sequence and
bytes is idempotent, the same sequence with different bytes is an integrity alarm, and a lower
sequence is rejected while the retained object is valid. Expiry removes the relayed object and its
high-water mark, so loss/rebootstrap of the source's local counter can delay acceptance only until
the prior set expires. Its addresses may remain local dial guesses only until
`endpoint_guess_ttl_seconds` after their latest local observation; they are never relayed as current.
Revocation or generation change purges the object and all nonmanual guesses for that member
immediately.

The raw UDP source is an unverified guess that expires with its advertisement and is never relayed.
For IPv6 link-local it retains the receiving selected-interface zone locally. A successful
target-authenticated dial may retain only the exact destination IP, local zone when required, and
known listener port that were dialed, never the connection's ephemeral source port; it expires after
`endpoint_guess_ttl_seconds` from the latest successful expected-member handshake unless refreshed.
A signed set is attributed routing input, not proof that its
signer owns the named IP: every dial sends no application bytes until the expected member identity
authenticates, requires the OS-selected route to leave on a configured interface, uses the per-peer
backoff, and records success only after that handshake. The four endpoint sources are a current
signed set, a raw discovery source, a successfully authenticated destination, and explicit local
manual configuration; no other network input becomes a dial target.

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
- **Bound the number of tracked sources.** UDP source addresses are trivially spoofable and the
  nonce cache is consulted before any signature work, so per-source state is allocable by
  unauthenticated input at no cost to an attacker. A daemon MUST cap distinct tracked sources at
  §11.2's `discovery_tracked_sources_max`, evicting the oldest source wholesale, and MUST enforce
  §11.2's aggregate memory ceiling for discovery state. Reaching either cap is a rate-limited
  local log line, never a per-packet one.

Manual member endpoints use literal IP and port, but unlike signed sets MAY use IPv6 link-local only
with a locally valid selected-interface zone (for example `[fe80::1%en0]:47831`). They persist until
operator removal, obey separate caps, never relay, and do not bypass the selected-route check. Full
invite bundles remain mandatory trust input; an endpoint alone never pairs a device.
Discovery MUST NOT pair, alter membership, import Git objects, update refs, or write workspace files.

### 4.5 Pairing

1. An owner on any healthy member creates a one-use invite with a 15-minute TTL. At most 8
   invites may be outstanding **per issuing device**; `codecomm peer invite list|revoke` shows and
   cancels them. The cap is per issuer, not per session, because invite issuance and consumption
   are local state — there is no `invite.*` event kind and the cluster learns of an invite only
   when the joiner is proposed for membership at step 8 — so two owners can legitimately hold 8
   each. §11.2 classifies it `Local at issue` accordingly.
2. The inviter identity-signs a closed invite under `codecomm/v1/invite`: invite/protocol/session
   IDs, recovery generation, creation/expiry, a 128-bit CSPRNG secret, inviter identity,
   signed-genesis digest, one mode (`new`, `rebootstrap`, or `readmission`), and at most §11.2's
   endpoint-hint count. `new` carries no subject; the other modes carry the exact existing
   `device_id`, and `readmission` also carries its expected entity version. The encoded invite and
   each pairing request/response obey the pairing-message byte limit.
3. The joiner pins the inviter identity from the invite; multicast cannot override it. In `new`
   mode it generates a long-lived installation identity; `rebootstrap` and `readmission` instead
   load the invite-named enrolled identity and fail if that key is unavailable. Every mode
   generates its initial content-epoch key before connecting.
4. Pairing uses only ALPN `codecomm-pairing/1` (§4.6). TLS verifies the inviter's long-lived
   identity against the pinned fingerprint and genesis binding; the joiner presents its
   self-signed identity certificate, proving possession of that key even though it is not yet a
   member. The pairing dispatcher accepts identity-key certificates only under these pairing rules.
   The unadmitted joiner fails consensus membership admission; after admission, the same identity
   certificate profile is valid on consensus. Identity certificates always fail content-plane
   verification, and pairing paths are absent from both member-plane dispatchers.
5. The joiner proves the invite secret **without transmitting it**. Both sides obtain exactly 32
   bytes from the TLS 1.3 exporter with ASCII label `EXPORTER-CodeComm-Pairing-v1` and empty context.
   Let `invite_digest = SHA-256(JCS(complete signed invite including its signature))`, and let
   `inviter_key` and `joiner_key` be the raw 32-byte identity keys in role order. Then:

   ```text
   transcript_hash = SHA-256("codecomm/v1/pairing-transcript" || 0x00
                       || len64(exporter) || exporter
                       || len64(inviter_key) || inviter_key
                       || len64(joiner_key) || joiner_key
                       || len64(invite_digest) || invite_digest
                       || len64(canonical_request_core) || canonical_request_core)
   proof = HMAC-SHA-256(secret,
             "codecomm/v1/invite-proof" || 0x00 || transcript_hash)
   ```

   `len64` is §5.6's unsigned big-endian length. The joiner sends only `proof`; equality is
   constant-time. Exact exporter label/context, role ordering, and framing are fixtures. Channel
   binding makes a proof captured on one connection useless on another.
6. The inviter marks the invite consumed **durably, before sending its response**, and only on
   a **valid** proof — a failed proof does not consume the invite but increments a durable failure
   counter. Proof failures are rate-limited and enter the bounded local unauthenticated aggregate,
   never `audit.recorded`; three failures void the invite. A crash
   after consumption and before the response leaves the invite consumed. An exact request may
   recover a lost response only on the still-open exporter-bound TLS channel; a new connection or
   daemon restart requires a fresh invite.
7. The operator of each device compares and confirms a short authentication string derived
   from `sas = SHA-256("codecomm/v1/sas-transcript" || 0x00 || transcript_hash)`. The rendering is
   normative because two implementations that differ produce mismatched strings and every pairing
   fails: take the **first 10 bytes** of `sas` in wire order, read them as five consecutive
   **big-endian `uint16`** values, reduce each modulo 10000, and render each as exactly 4 decimal
   digits zero-padded, joined by spaces. §12.2 freezes a golden vector. Both sides display the
   same value; either side declining voids the invite. There is exactly one attempt, no retry. The
   inviter's confirmation is an operator-bound local command that displays and binds the exact
   joiner identity, role, version, and initial epoch-key binding; it is the human authorization from
   which the daemon constructs step 8's event origin (§5.2), not a later unattended daemon action.
   Two approvals durably move the attempt to `finalizing`, not `confirmed`; remote polling reports
   that distinction. Restart retries the exact idempotent finalizer. Durable success records local
   completion and returns `confirmed`; a durable authoritative rejection revokes the attempt,
   returns `revoked`, and requires a fresh invite. Transient errors remain `finalizing`.
8. In `new` mode that local confirmation creates `membership.device_admitted` for an absent identity.
   In `readmission` mode it creates the same event against the named `requires_readmission` row and
   invite-bound expected version; the reducer requires the same enrolled key, then updates role and
   version report and sets `status = active`. `rebootstrap` skips admission. Any admission starts only
   after quorum commit, and its durable local request mapping makes an interrupted wait retry the
   exact event.
9. The admitted joiner reaches the consensus plane with its identity certificate. The leader obtains
   the §4.6 voter clock endorsements, commits the first credential authorization, and returns it with
   membership proof and roster; only then does the joiner open content-plane peer connections. If
   this final step is interrupted, it is safely retryable with the admitted identity and does not
   require a fresh invite.

Immediately before consuming a valid proof, the inviter transactionally rechecks that the issuer is
still an active owner and that the mode-specific subject preconditions still hold. `new` requires an
absent identity. `rebootstrap` requires the exact active enrolled identity and role, the next content
epoch, and exclusion from both the committed voter target and live Raft configuration. `readmission`
requires the exact `requires_readmission` identity/version and the same voter exclusions. The live
configuration check holds the reconciliation exclusion through invite consumption; a check followed
by an unlocked race is insufficient.

On startup the daemon abandons crash-stranded `preparing` invites, expires stale invite/SAS rows,
resumes every `finalizing` attempt, and drains durable native-secret deletion work. The same expiry
and deletion maintenance continues while running with bounded exponential retry. Failed-proof rows
exist only while their invite remains outstanding and are deleted atomically on consumption or any
terminal transition. A proof with a reused `attempt_id` but changed bound input still consumes the
failure budget. Successor-generation installation revokes every unfinished predecessor attempt and
never retries its finalizer in the successor lineage.

An active settled nonvoter that retained its installation identity but deleted local session state
uses closed **rebootstrap** mode. The inviter verifies the named active row and presented key,
performs the same exporter proof/SAS, and skips admission. A device still named by the voter target
or live Raft configuration cannot safely recreate an empty stable store under that server ID: while
quorum survives, an owner first targets and fully reconciles its removal; after quorum loss, only
§3.1 applies.

After §3.1 recovery, every non-recovering survivor uses closed **readmission** mode. The owner invite
names its retained `requires_readmission` identity and expected version; the same key, exporter
proof, and two-sided SAS are mandatory. Conditional `membership.device_admitted` reactivates that
row without creating a new identity, and a stale version, changed key, active/absent row, or revoked
row rejects. A readmitted device starts as an application nonvoter; later voter promotion follows
§3. Readmission is therefore distinct from active-member rebootstrap, which skips admission.

The confirmed response supplies pinned genesis/membership state needed to reach consensus, renew a
content credential, and fetch a verified logical snapshot and Git bootstrap. Before accepting a new
local agent, a rebootstrap daemon commits `agent.session.ended(crash_reap)` for each nonterminal
session formerly owned by that device; §3.1 already ended predecessor sessions for readmission.
Lost resume capabilities never revive either set. Workspace markers or unauthenticated peers cannot
bootstrap trust.

Secrets MUST enter through TUI or no-echo stdin, never argv, environment, URL, log,
crash report, or shell history. V1's shareable code is the full 128-bit invite; it does not offer a
short numeric code. A future short-code mode requires a separately specified and audited PAKE such
as SPAKE2+; unverified TLS plus a six-digit password is prohibited.
