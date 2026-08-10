export const meta = {
  name: 'design-doc-review',
  description: 'Multi-dimension review of the CodeComm design doc: correctness, security, distributed-systems safety, cold-reader clarity, implementation readiness, and overlooked best practices',
  phases: [
    { title: 'Review', detail: '7 independent lenses over docs/design.md' },
    { title: 'Verify', detail: 'skeptical re-check of each lens findings against the actual text' },
    { title: 'Critic', detail: 'what did every lens miss?' },
    { title: 'Synthesize', detail: 'merge, dedupe, rank' },
  ],
}

const DOC = '/Users/ijonahch/Dev/CodeComm/docs/design.md'

const COMMON = `
You are reviewing a GREENFIELD design document at ${DOC}. Read the ENTIRE file first (it is ~1010 lines).

Context on the author's goals (from the author):
- The doc must clearly describe what this project will be WITH NO OTHER CONTEXT NEEDED.
- It must be correct and secure.
- It must contain enough context to move on to an implementation plan.
- No best practice may be silently skipped "for simplicity/easiness".

CRITICAL DISCIPLINE - this document is extremely terse and information-dense. Many things that look
missing ARE actually covered somewhere else in the doc in a single clause. Before you report anything
as "missing" or "unspecified", you MUST grep the whole file for the relevant keywords and confirm it
is genuinely absent. Cite exact line numbers and quote the text you are reacting to. A false
"you forgot X" finding is worse than no finding, because it wastes the author's time.

Report ONLY substantive findings. Do not report style/wording preferences unless they create real
ambiguity for an implementer. Do not pad the list. Quality over quantity: 4 sharp findings beat
20 mushy ones.

Severity definitions:
- blocker: implementation cannot safely start, or the design as written is wrong/insecure.
- major: will cause rework, a security gap, or a real ambiguity an implementer would guess wrong on.
- minor: real but cheap to fix.
- nit: cosmetic/consistency.

Do NOT modify the file. Read-only review.
`

const FINDINGS_SCHEMA = {
  type: 'object',
  properties: {
    findings: {
      type: 'array',
      items: {
        type: 'object',
        properties: {
          id: { type: 'string', description: 'short kebab-case slug unique within your lens' },
          title: { type: 'string', description: 'one line, <=90 chars' },
          severity: { type: 'string', enum: ['blocker', 'major', 'minor', 'nit'] },
          lines: { type: 'string', description: 'line numbers or ranges in design.md, e.g. "231-233" or "34, 665"' },
          quote: { type: 'string', description: 'the exact doc text you are reacting to (may be empty if the finding is an omission)' },
          problem: { type: 'string', description: 'what is wrong / unclear / missing. Be specific and technical.' },
          why_it_matters: { type: 'string', description: 'concrete consequence: what breaks, or what an implementer would get wrong' },
          recommendation: { type: 'string', description: 'the specific fix or the specific sentence/section to add' },
        },
        required: ['id', 'title', 'severity', 'lines', 'problem', 'why_it_matters', 'recommendation'],
      },
    },
  },
  required: ['findings'],
}

const VERDICT_SCHEMA = {
  type: 'object',
  properties: {
    verdicts: {
      type: 'array',
      items: {
        type: 'object',
        properties: {
          id: { type: 'string' },
          verdict: { type: 'string', enum: ['CONFIRMED', 'WEAKENED', 'REJECTED'] },
          reason: { type: 'string', description: 'why. If REJECTED, cite the line number where the doc already handles it.' },
          corrected_severity: { type: 'string', enum: ['blocker', 'major', 'minor', 'nit'] },
          corrected_problem: { type: 'string', description: 'tightened restatement of the problem if the original overreached; else repeat it' },
          corrected_recommendation: { type: 'string' },
        },
        required: ['id', 'verdict', 'reason', 'corrected_severity', 'corrected_problem', 'corrected_recommendation'],
      },
    },
  },
  required: ['verdicts'],
}

const LENSES = [
  {
    key: 'security-crypto',
    prompt: `${COMMON}

YOUR LENS: security, cryptography, identity, and trust establishment.

Scrutinize in depth:
- Section 4 (identity, discovery, pairing, rotating credentials) line by line. Is the pairing
  ceremony (4.4) actually sound? Does step ordering prevent MITM? Is the "short authentication
  string" derivation specified enough to be safe (transcript binding, SAS length, entropy)?
- The invite: 128-bit secret, one-use, short-lived - but is the proof-of-invite mechanism specified?
  Is the invite secret used as a bearer token over a TLS channel the joiner cannot yet verify?
  Compare with the claim in step 3 of 4.4 that the joiner pins the inviter identity.
- 4.5 credential rotation: 30-minute epochs, quorum-committed key authorizations. Look for
  bootstrapping/circularity problems, replay of old authorizations, epoch rollback, the
  "renewal-only handshake" (does it create an unauthenticated pre-auth surface? is it DoS-able?),
  and whether revocation is actually enforceable against a partitioned peer.
- 4.3 discovery: signed multicast datagram. Is the signature meaningful pre-pairing? Replay
  protection via advertisement_nonce + expires_at - is that specified enough? Any information
  leak in the advertised fields (session_id, credential_epoch, committed_membership_index,
  pairing_open)? Amplification/DoS via multicast?
- Section 10: is the threat model complete and honest? What adversary classes are missing?
  Consider: malicious/curious authorized editor, compromised agent process, compromised
  Syncthing sidecar, hostile repository content, a former member who kept files, denial of
  service by an authorized member, local unprivileged process on the same host.
- The CONNECT tunnel (8.1) as a confused-deputy / SSRF surface.
- Secret handling: invite secrets, Syncthing API key, resume capability, identity keys.
- Anything where the doc says "MUST" but gives no enforceable mechanism.

Also try the gates-mcp scan_text tool on the document content if available (load it with
ToolSearch query "select:mcp__gates-mcp__scan_text") and report any genuine findings it surfaces -
ignore false positives from example JSON/placeholder strings, and say so rather than padding.

Be a real cryptographic/security reviewer: name the attack, the preconditions, and the impact.`,
  },
  {
    key: 'distributed-correctness',
    prompt: `${COMMON}

YOUR LENS: distributed systems correctness and safety. This is the highest-risk area of the design.

Scrutinize in depth:
- Section 3 + 5.3 + 6.2. Raft integration: leader ordering, joint consensus voter changes,
  snapshots, the interaction between Raft commitment and "deterministic state-machine validation".
- The dual-signature scheme in 5.2: origin signature + LEADER signature over consensus metadata.
  Is a per-entry leader signature actually coherent with Raft? What happens on leader change,
  log truncation of uncommitted entries, or a signed-but-later-overwritten entry? Does
  previous_entry_hash form a chain that can survive Raft log truncation? Is this a real
  requirement or an unimplementable one?
- Lines 34-35 and 665: "Without a voter majority, strong mutations and new credential
  authorizations MUST pause... while local work and direct sync among reachable peers continue
  only until current credentials expire." Trace the failure mode: a 3-voter cluster loses quorum;
  30 minutes later ALL credentials expire and no one can renew. Is the resulting total shutdown
  intended, stated clearly, and acceptable? Is there any escape hatch? Is the 30-minute rotation
  interval coupled to availability in a way the doc does not acknowledge?
- Leases (6.2, lines 442-446): "Lease deadlines are committed values; reducers never consult local
  wall clocks. The leader proposes renew/expire commands." Is this consistent? Where does the
  passage of time enter a deterministic reducer? Is "bounded clock-skew allowance" defined
  anywhere with a number?
- Single-voter to three-voter growth path. Section 2.1 lines 60-61 say sessions MAY use two devices.
  What is the voter membership as devices 2..8 join? Who decides? Is it automatic? What happens
  to a 1-voter session when the voter dies?
- Idempotency and exactly-once: origin_sequence, event_id uniqueness, the outbox table,
  "duplicate IDs return that result" - is the idempotency key lifetime/GC specified? What happens
  when idempotency records are compacted?
- The hlc field is present but line 344 says wall time/HLC are display-only. Then why is it in the
  signed payload? Is it validated? Unvalidated timestamps in signed data.
- Catch-up/snapshot path for nonvoters, replication_cursors, SSE watermarks, and the claim that
  eligible replicas at the same committed index have EQUAL projection digests (line 836).
  What breaks determinism in practice (map iteration order, floats, locale, time, schema version
  skew between daemons at different releases)? Section 12.3 scenario 8 replicates across versions -
  can projections be digest-equal across different daemon versions?
- Compaction (line 59, "session-lifetime coordination history with export before compaction"):
  is compaction actually designed? How does it interact with the hash chain, snapshots, and
  late-joining/long-offline peers?
- Two-device sessions and the interaction with the owner/editor Syncthing mesh.

Name the specific interleaving or failure sequence that breaks each invariant you challenge.`,
  },
  {
    key: 'cold-reader',
    prompt: `${COMMON}

YOUR LENS: the cold reader. The author's stated bar is that this doc "clearly describes what this
project will be, with no other context needed." Test that bar hard.

Read the doc as a competent senior engineer who has NEVER heard of this project, and answer honestly:
- After reading section 1, do you know what problem this solves and for whom? Is there a problem
  statement, motivation, or "why does this exist" anywhere? Is there a single concrete end-to-end
  usage narrative (user does X, sees Y)?
- Is there any worked example of the actual value proposition: two coding agents on two laptops
  collaborating? What does the user literally type, see, and get?
- Which terms are used before/without definition? Build a list. Candidates to check (verify each
  against the text before claiming): "collaboration", "session" vs "workspace" vs "collaboration",
  "strong state"/"strong mutations"/"strong claims", "trust epoch" vs "credential_epoch",
  "canonical synchronized tree", "sidecar", "connector", "eligible", "up-to-date peer",
  "control files"/"agent-control files", "capture_level", "projection", "reducer", "watermark",
  "sync_blocked", "publish"/"proposal" in 7.2, "genesis record", "voter"/"nonvoter",
  "epoch key"/"advertising key", "inbox", "context.md". Which of these would an implementer
  or a new team member guess wrong?
- Does the doc explain WHY key choices were made, or only WHAT was chosen? Where would a reader
  say "this seems over-engineered, why Raft at all for 2-8 personal devices?" - is that
  justified anywhere? Is the alternative (e.g. simpler CRDT/last-writer-wins, or a single
  designated coordinator) considered and rejected on the record?
- Audience mismatch: line 6 says the audience is "Product and engineering". Is any part of this
  readable by a product reader? Is there a section they can actually use?
- Missing conventional design-doc sections entirely: problem statement, user personas/scenarios,
  requirements traceability, alternatives considered, glossary, diagrams beyond the one ASCII box,
  sequence diagrams for pairing/bootstrap/task-claim, data model diagram, dependency/ownership,
  cost, timeline, success metrics vs the "Service Targets".
- Note where extreme terseness has crossed into actual ambiguity - quote the specific sentence
  and give the two or more readings an implementer could take.

Be concrete. For each gap, say what to add and roughly where.`,
  },
  {
    key: 'impl-readiness',
    prompt: `${COMMON}

YOUR LENS: implementation readiness. Question to answer: could a team start an implementation plan
from this doc alone, and where would they immediately block?

Work through what an implementer must know and check whether the doc supplies it:
- REST API (5.1 table): are request/response bodies, status codes, error taxonomy, auth
  requirements per endpoint, pagination parameters, and size limits specified anywhere? Only the
  event envelope has a schema. What about pairing, credentials/renew, snapshots, presence, acks,
  bootstrap bundles, sync/config, sync/status, conflicts?
- The local IPC protocol (CLI/TUI/MCP to daemon): named in many places, never specified. Framing?
  Schema? Versioning? Is it the same REST surface over a socket, or something else? Auth model?
- MCP tool surface (7.1, lines 466-470): tool names are listed but no argument or result schemas,
  no error semantics, no pagination, no versioning story for the "versioned adapter".
- The SQLite schema: table names are listed (lines 403-409) but no columns, keys, indexes, or
  migration numbering. Is that adequate to start? What is the minimum missing?
- Config: no configuration file format, location, precedence, or reload semantics anywhere.
  Verify before claiming.
- Concrete numbers that are absent but needed: clock-skew allowance, grace period for agent
  disconnect, heartbeat interval, lease default/max TTL, SSE reconnect/backoff, rate-limit
  values, invite TTL (5 min is stated for numeric codes only - what about the invite bundle?),
  max event size, max batch size, max decompressed size, quotas, connection caps, tunnel byte
  rates, retry caps, log retention, port selection (47831 appears once in an example - is it the
  default? is it configurable? IANA-registered?). Build the list of every "bounded"/"rate-limited"
  /"capped" that has no number, but report it as ONE consolidated finding, not thirty.
- Repository/package layout: only internal/testharness is named (line 824). Is module structure,
  binary layout (codecomm plus codecommd - one binary or two?), or build tooling specified? Line 117
  and 647-651 suggest both; is that consistent?
- Cross-cutting decisions an implementation plan needs: minimum Go version, minimum Git version
  ("with minimum version" but no number), pinned Syncthing version, supported OS versions,
  supported Codex/Claude Code versions.
- Sequencing: is section 13 (Delivery) actually decomposable into an implementation plan? Are
  there hidden dependencies between phases? Does phase 1 have exit criteria? Are the phases
  sized at all (no estimates, no team size)?
- What is the smallest thing that could be built and demoed? Is a walking-skeleton/MVP path
  identifiable from the doc, or does phase 2 already require most of the system?

Then state a clear verdict: is the doc sufficient for an implementation plan, sufficient-with-gaps,
or not sufficient - and name the specific top blockers.`,
  },
  {
    key: 'consistency',
    prompt: `${COMMON}

YOUR LENS: internal consistency, factual/arithmetic correctness, and proofreading. Be pedantic and
exhaustive here; this is the one lens where completeness matters more than severity.

Check every one of these against the text:
- Arithmetic: line 546 "at most 28 pairs for eight devices" (verify n(n-1)/2 for 8). Line 968
  repeats 28. Are these consistent with "owner/editor full mesh" when observers are excluded?
  Lines 58-59 targets. Line 45 "2-8 devices and up to 32 concurrent agent instances" vs line 864
  "32-session responsiveness" vs 7.1 "many instances per device".
- Contradictions between the summary table (section 1), the invariants table (2.4), the body, the
  failure table (section 9), Service Targets (14), Risks (16), and the ADR list (17). Every ADR should
  correspond to a decision actually made in the body; every major body decision should have an ADR
  or a reason it doesn't.
- Open Questions (15) vs decisions already made in the body. Specifically: Q1 ongoing Git vs
  8.3 line 594; Q2 plan authority vs 4.2 line 180 "No by default" and 6.2 line 434; Q3
  activity privacy vs 5.2 lines 348-350; Q4 scale vs 2.1 line 58; Q5 sidecar distribution vs
  8.1 line 532 and 8.4 line 624. Is an "open question" that the body already answers a defect?
  Which way should it be resolved?
- Line 8 says MUST/SHOULD/MAY are normative but the doc does not reference RFC 2119, and uses
  MUST/SHOULD inconsistently (many requirements are stated in bare declarative prose). Sample
  and quantify rather than asserting.
- Terminology drift: "credential_epoch" vs "trust epoch" vs "new-epoch recovery"; "session" vs
  "collaboration"; "member" vs "peer" vs "device"; "strong" as an undefined adjective;
  "eligible"; "control file" vs "agent-control file" vs "protected path"; "sidecar" vs
  "connector"; codecommd vs daemon vs "local daemon".
- Identifiers: 4.1 defines device_id, session_id, workspace_id, agent_profile_id,
  agent_session_id, event_id, origin_sequence, log_index. Are all of them used later? Are any
  identifiers used later that are NOT defined (e.g. entity_id, expected_entity_version, term,
  leader_device_id, credential_epoch, committed_membership_index, advertising_key_digest,
  advertisement_nonce, schema_version)? Is device_id "hash of long-lived device public key" -
  which hash? truncated? encoding?
- The JSON examples: are they internally valid JSON? Do field names in 4.3 and 5.2 match how
  they are described in prose? Is the hlc value a placeholder or a format?
  Is created_at RFC3339Nano vs RFC3339 used consistently? Is base64url specified for every
  binary field? Are the signature scopes described in lines 342-343 unambiguous (canonical
  serialization format is never named - verify)?
- The task state machine on line 431: backlog to ready to claimed to in_progress to blocked to
  done is written as a linear chain. Is that the real graph? Can you go blocked to in_progress?
  claimed to backlog? Compare with the CLI verbs on line 641 (add|claim|start|block|done) and
  the agent lifecycle on line 498. Is sync_blocked (line 599) a task state, a flag, or both?
- Section numbering, table formatting, markdown correctness, trailing-space line breaks (lines
  3-7), broken/duplicated cross-references, the section 18 reference URLs (do they look right? is the
  Codex MCP/AGENTS.md URL plausible? is there a missing reference for Syncthing, MCP spec,
  SPAKE2+/RFC, RFC 2119, RFC 8441 CONNECT, UUIDv7/RFC 9562, hashicorp/raft?).
- Anything in sections 11/12 that is a requirement on the TEAM rather than the SYSTEM and is therefore
  in the wrong document (is that a problem? say so if it dilutes the design).
- Missing document metadata: no author/owner, no reviewers, no changelog for revision 0.6, no
  status/approval workflow, no link to a repo or tracking item.

Group micro-issues (typos, formatting) into single consolidated findings. Report substantive
contradictions individually.`,
  },
  {
    key: 'external-facts',
    prompt: `${COMMON}

YOUR LENS: fact-check every external/technical claim about third-party technology. The design leans
hard on other people's software; a wrong assumption here invalidates a whole section.

Verify (use your knowledge; if WebFetch/WebSearch is available via ToolSearch, use it for anything
you are less than confident about, and mark each verdict with your confidence):
- SYNCTHING (8.1, 8.3, 8.4): Can Syncthing's sync listener be bound to loopback only while
  still connecting OUT to a local connector via a static device address? What is the actual
  config surface (options such as localAnnounceEnabled, globalAnnounceEnabled, relaysEnabled,
  natEnabled, listenAddresses, GUI address/apikey, autoAcceptFolders, introducer, crashReporting,
  urAccepted, and whether self-update is a setting or a build tag)? Does Syncthing support
  staggered versioning storing versions OUTSIDE the folder? Are the .sync-conflict files the
  actual conflict mechanism, and is the doc's claim that conflict copies are "authoritative" and
  reliably created correct? Does Syncthing have an ignore file (.stignore) whose semantics differ
  from gitignore as the doc claims (lines 608-609)? Can Syncthing sync executable bits but not
  permissions/ownership (line 622)? Is 100k files / 2 GiB / 100 MiB per file within normal
  Syncthing operating range? Is running one sidecar PER SESSION with an isolated home realistic
  (resource cost, ports)? Is Syncthing's license (MPL-2.0) compatible with bundling (15 Q5)?
- HTTP/2 EXTENDED CONNECT (5.1 line 271, 8.1): is RFC 8441 extended CONNECT usable from Go's
  net/http server and client today? Does Go's HTTP/2 support ENABLE_CONNECT_PROTOCOL and the
  protocol pseudo-header, or would this need h2c/manual framing, or plain CONNECT over HTTP/1.1,
  or some other tunneling approach? This is a load-bearing claim for the entire file-sync data
  plane - be precise about what is and is not supported in the standard library and in
  golang.org/x/net/http2.
- GIT (8.2): does git bundle support the SHA-256 object format, and does git bundle verify
  do what the doc implies? Can you clone from a bundle that contains selected refs and have a
  usable working tree? Is "disable hooks, recursive submodules, external credential helpers/
  filters, automatic Git LFS downloads" achievable via documented config/env (name the actual
  knobs: core.hooksPath, GIT_CONFIG_GLOBAL, GIT_CONFIG_NOSYSTEM, protocol.allow,
  credential.helper, GIT_LFS_SKIP_SMUDGE, transfer.fsckObjects, --no-recurse-submodules)?
  Is the doc's claim that a bundle needs "a reachable commit" and that git init requires consent
  coherent? Do git worktrees interact correctly with a working tree that Syncthing is mutating?
- RAFT (3, 11, 12.2): what maintained embedded Go Raft libraries exist and do they provide
  joint consensus / safe membership change, a production stable store, snapshots, and pluggable
  transport? Be specific and honest about which library actually supports joint consensus
  (line 133) vs single-server membership changes - this is a real distinction and the doc asserts
  the library provides it. Does the leader-signature-per-entry design (5.2) fit any of these
  libraries' APIs, or does it require the application to wrap entries itself?
- MCP (7.1): is stdio MCP the right/current transport model, is "codex mcp add NAME -- CMD"
  the real Codex CLI syntax, is there a documented per-tool allowlist and write-approval
  mechanism in Codex and Claude Code, and are AGENTS.md, CLAUDE.md, .codex/ and .claude/
  the correct control-file paths (lines 613-616)? Is AGENTS.override.md a real thing? Are the
  section 18 reference URLs correct/live?
- STANDARDS: UUIDv7 status (RFC 9562), SPAKE2+ status and whether audited implementations exist
  in Go, TLS 1.3 plus self-signed cert with custom extensions carrying "the identity signature and
  authorization index" (line 245) - is putting that in an X.509 extension the right/practical
  mechanism vs a channel-binding/application-layer proof? Multicast TTL 1 plus 1200-byte datagram
  reasonableness; is port 47831 registered/conflicting; does UDP multicast work on macOS/Windows
  per-interface as assumed (line 70, line 885)?
- PLATFORM: Windows named-pipe ACLs, launchd/systemd --user/Windows scheduled task for a
  per-user daemon, Windows firewall consent prompts, Unix socket peer-UID checks (SO_PEERCRED on
  Linux vs LOCAL_PEERCRED/getpeereid on macOS - is there a portability gap the doc glosses?),
  Keychain/Secret Service/Credential Manager from Go without CGO.

For each claim: state the doc's claim, the actual fact, whether they agree, and if not, the impact
on the design. Only report DISAGREEMENTS or claims that are true-but-load-bearing-and-risky.`,
  },
  {
    key: 'simplicity-tradeoffs',
    prompt: `${COMMON}

YOUR LENS: the author explicitly asked - "make sure no best practices are overlooked for
simplicity/easiness sake". Find both directions of that failure.

(A) Places where the doc chose the easy path and quietly dropped a best practice. Look for:
- Hedge words that hide an unmade decision or a dropped requirement: "MAY later", "if included",
  "optional", "by default" (with no non-default path defined), "where supported", "where platform
  controls allow", "equivalent to", "-equivalent", "such as", "candidate", "separately",
  "not assumed". Grep for these and evaluate each one: is it a legitimate scoping decision or a
  hole? Specifically check lines 554-555, 594, 622-623, 713-715, 719-730.
- At-rest encryption punted to "require full-disk encryption" (lines 713-715): is that acceptable
  given the DB holds coordination history, and given identity keys are in the OS keystore but
  the SQLite DB, logs, conflict snapshots, git worktrees, and .codecomm/tmp are not?
- Long-lived device identity keys: is there ANY rotation, expiry, compromise-recovery, or backup
  story for them? What happens when a user reinstalls the OS or loses a laptop?
- Audit: an audit_events table exists, but is the audit log tamper-evident, exportable, retained,
  or reviewable? Who can read it?
- Backup/restore/DR: 6.1 mentions SQLite online backup plus Raft snapshot, but is there an operator
  runbook, a tested restore path, or a defined RPO/RTO? Is identity/credential backup addressed?
- Observability: section 11 lists metrics/logs but there is no defined SLO/alerting, no crash
  reporting (deliberately? telemetry is off by default), no support-bundle/diagnostics command
  besides sync doctor. Is "no telemetry by default" going to make field debugging impossible?
- Upgrade/downgrade: "reviewed CodeComm releases with compatibility/rollback tests" - is there a
  version-skew policy for a mesh where devices upgrade independently? What is the supported
  skew window? Can a v1.1 daemon and a v1.0 daemon share a Raft cluster and a schema? Section 12.2
  claims "previous protocol interop" - with what N-1 policy?
- Missing entirely (verify before claiming): licensing/OSS posture, data retention/privacy policy
  (this captures human and agent activity), accessibility of the TUI, i18n, user
  documentation, error message quality, first-run UX, uninstall/data removal, multi-user (non-
  same-user) scenarios, what happens with an untrusted co-worker's device.
- Testing: section 12 is unusually strong. Find what it still omits - e.g. property-based or
  model-based testing, or a formal (TLA+/Stateright) model for the consensus plus credential state
  machine, given section 16 risk 3 says incorrect Raft integration can violate safety. Is
  deterministic simulation testing considered? Is there any coverage number, or only
  "coverage floors"?

(B) The opposite failure - places where the design is MORE complex than the stated goals require,
where complexity itself is the risk. Be willing to say so plainly. Candidates to evaluate:
- Raft plus joint consensus plus per-entry leader signatures plus hash chain plus HLC plus
  snapshots plus logical replication plus idempotency plus outbox, for a 2-8 personal-device tool.
- 30-minute quorum-authorized TLS key rotation, on top of stable identity mTLS.
- A per-session Syncthing sidecar tunneled through HTTP/2 extended CONNECT rather than letting
  Syncthing do its own (already end-to-end encrypted, already NAT/discovery-capable) transport.
- Both an event log AND projections AND snapshots AND a git-bundle bootstrap AND Syncthing.
- Whether V1 scope can plausibly ship, and what you would cut to get a credible V1.
For each, give the honest cost/benefit and a concrete simplification, or state clearly why the
complexity is justified. The author wants to hear this, not be flattered.`,
  },
]

phase('Review')

const perLens = await pipeline(
  LENSES,
  (lens) => agent(lens.prompt, { label: `review:${lens.key}`, phase: 'Review', schema: FINDINGS_SCHEMA, effort: 'xhigh' }),
  (result, lens) => {
    if (!result || !result.findings || result.findings.length === 0) return { lens: lens.key, findings: [] }
    return agent(
      `You are a SKEPTICAL verifier. Another reviewer produced findings about the design document at
${DOC} under the lens "${lens.key}". Your job is to REFUTE them. Default to REJECTED when the
finding is not clearly supported.

Read the ENTIRE document yourself first. Then for each finding below:
1. If it claims something is MISSING or UNSPECIFIED: search the whole file for every relevant
   keyword and synonym. If the doc addresses it anywhere - even in one terse clause in a different
   section, a table row, an invariant, a risk, an ADR, or a test scenario - mark it REJECTED and
   cite the line number that covers it.
2. If it claims something is WRONG or INSECURE: check the actual quoted text and decide whether the
   reviewer misread the terse phrasing. Consider whether a competent implementer would actually be
   misled. Consider whether the doc's own section 15 Open Questions or section 16 Key Risks already
   acknowledge it (if it is already acknowledged there, that is usually WEAKENED-to-nit, not
   CONFIRMED - unless the acknowledgement itself is the defect).
3. If it claims an external technology fact: judge whether the claim is actually true. Reject
   confidently-stated but wrong technical assertions.
4. Judge severity honestly. Reviewers inflate. A missing number for a "bounded" limit in a design
   doc is a minor, not a blocker. A design that cannot work as written is a blocker.
5. WEAKENED means the core observation is real but the reviewer overstated scope or severity -
   give the tightened version in corrected_problem.

Findings to verify:
${JSON.stringify(result.findings, null, 2)}

Return one verdict per finding id. Do not invent new findings.`,
      { label: `verify:${lens.key}`, phase: 'Verify', schema: VERDICT_SCHEMA, effort: 'xhigh' }
    ).then((v) => ({ lens: lens.key, findings: result.findings, verdicts: (v && v.verdicts) || [] }))
  }
)

const surviving = []
let rejectedCount = 0
for (const r of perLens.filter(Boolean)) {
  const byId = {}
  for (const v of r.verdicts || []) byId[v.id] = v
  for (const f of r.findings || []) {
    const v = byId[f.id]
    if (!v) { surviving.push({ ...f, lens: r.lens, verdict: 'UNVERIFIED' }); continue }
    if (v.verdict === 'REJECTED') { rejectedCount++; continue }
    surviving.push({
      ...f,
      lens: r.lens,
      verdict: v.verdict,
      severity: v.corrected_severity || f.severity,
      problem: v.corrected_problem || f.problem,
      recommendation: v.corrected_recommendation || f.recommendation,
      verifier_note: v.reason,
    })
  }
}

log(`${surviving.length} findings survived verification; ${rejectedCount} rejected as already covered or wrong`)

phase('Critic')

const critic = await agent(
  `You are a completeness critic. Read the design document at ${DOC} in full.

Seven review lenses (security/crypto, distributed correctness, cold-reader clarity, implementation
readiness, internal consistency, external technology facts, simplicity-vs-best-practice) already
produced these VERIFIED findings:

${JSON.stringify(surviving.map((f) => ({ lens: f.lens, severity: f.severity, title: f.title, lines: f.lines })), null, 2)}

Your job: what did ALL of them miss? Think about whole sections or whole concerns that received no
attention. Consider: sections 2.2, 2.3, 9, 13 and 14 specifically; the document's own structure and
ordering; whether the stated invariants are actually sufficient to guarantee the stated goals;
whether the Service Targets (14) are measurable and tied to anything; whether the 2.1 goals map to
sections that deliver them; whether anything in the doc is internally unfalsifiable; and the
single most important question the author has not asked themselves about this project.

Report only genuinely NEW findings not present in the list above. It is completely acceptable to
return few findings, or an empty list, if coverage was good - say so rather than padding.`,
  { label: 'critic:completeness', phase: 'Critic', schema: FINDINGS_SCHEMA, effort: 'xhigh' }
)

const criticFindings = ((critic && critic.findings) || []).map((f) => ({ ...f, lens: 'completeness-critic', verdict: 'UNVERIFIED' }))

phase('Synthesize')

const all = surviving.concat(criticFindings)

const synth = await agent(
  `You are the lead reviewer writing the final verdict on the design document at ${DOC}.
Read the document yourself first so your synthesis is grounded.

Here are all verified findings from seven lenses plus a completeness critic:

${JSON.stringify(all, null, 2)}

Produce a synthesis:
1. Deduplicate and merge findings that are the same underlying issue seen from different lenses.
   Merge aggressively - the author should see one entry per real issue.
2. Rank by what would actually hurt the project most, not by lens.
3. Separate them into: (a) must-fix before an implementation plan, (b) should-fix in the doc,
   (c) worth noting / author's judgement call.
4. Answer these three questions directly and decisively:
   - Is the doc self-contained (describes what the project is with no other context)? Yes/No/Partly,
     and the single biggest gap.
   - Is it correct and secure as written? Name the most serious technical defect.
   - Is it sufficient to move to an implementation plan? Yes/No/Yes-with-caveats, and the specific
     prerequisites.
5. Call out what the document does UNUSUALLY WELL - be specific and honest, the author deserves
   accurate signal, not flattery.
6. Give the shortest ordered list of concrete edits that would move this doc from where it is to
   implementation-ready.

Be direct and technical. No hedging, no filler.`,
  {
    label: 'synthesize',
    phase: 'Synthesize',
    effort: 'xhigh',
    schema: {
      type: 'object',
      properties: {
        must_fix: {
          type: 'array',
          items: {
            type: 'object',
            properties: {
              title: { type: 'string' },
              lines: { type: 'string' },
              problem: { type: 'string' },
              why_it_matters: { type: 'string' },
              fix: { type: 'string' },
              lenses: { type: 'array', items: { type: 'string' } },
            },
            required: ['title', 'lines', 'problem', 'why_it_matters', 'fix'],
          },
        },
        should_fix: {
          type: 'array',
          items: {
            type: 'object',
            properties: {
              title: { type: 'string' },
              lines: { type: 'string' },
              problem: { type: 'string' },
              fix: { type: 'string' },
            },
            required: ['title', 'lines', 'problem', 'fix'],
          },
        },
        judgement_calls: {
          type: 'array',
          items: {
            type: 'object',
            properties: {
              title: { type: 'string' },
              lines: { type: 'string' },
              note: { type: 'string' },
            },
            required: ['title', 'note'],
          },
        },
        self_contained: { type: 'object', properties: { verdict: { type: 'string' }, biggest_gap: { type: 'string' } }, required: ['verdict', 'biggest_gap'] },
        correct_and_secure: { type: 'object', properties: { verdict: { type: 'string' }, most_serious_defect: { type: 'string' } }, required: ['verdict', 'most_serious_defect'] },
        ready_for_impl_plan: { type: 'object', properties: { verdict: { type: 'string' }, prerequisites: { type: 'array', items: { type: 'string' } } }, required: ['verdict', 'prerequisites'] },
        done_well: { type: 'array', items: { type: 'string' } },
        ordered_edits: { type: 'array', items: { type: 'string' } },
      },
      required: ['must_fix', 'should_fix', 'judgement_calls', 'self_contained', 'correct_and_secure', 'ready_for_impl_plan', 'done_well', 'ordered_edits'],
    },
  }
)

return {
  stats: { surviving: surviving.length, rejected: rejectedCount, critic_new: criticFindings.length },
  synthesis: synth,
  all_findings: all,
}
