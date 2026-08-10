export const meta = {
  name: 'design-doc-review-final',
  description: 'Final CodeComm design review pass: three remaining lenses, catch-up verification of two prior lenses, completeness critic, and synthesis',
  phases: [
    { title: 'Review', detail: '3 remaining lenses over docs/design.md' },
    { title: 'Verify', detail: 'skeptical re-check against the actual text' },
    { title: 'Critic', detail: 'what did every lens miss?' },
    { title: 'Synthesize', detail: 'merge, dedupe, rank, final verdict' },
  ],
}

const DOC = '/Users/ijonahch/Dev/CodeComm/docs/design.md'

const COMMON = `
Review the GREENFIELD design document at ${DOC}. Read the ENTIRE file first (~1010 lines).

The author's bar:
- The doc must describe what this project will be with NO other context needed.
- It must be correct and secure.
- It must contain enough context to move to an implementation plan.
- No best practice may be silently skipped for simplicity/easiness.

DISCIPLINE: the doc is extremely terse. Many things that look missing ARE covered in one clause
elsewhere. Before reporting anything as missing, grep the file for the relevant keywords and
synonyms and confirm genuine absence. Cite exact line numbers. A false "you forgot X" wastes the
author's time.

Be efficient: budget at most ~15 tool calls, then write your findings. Do not exhaustively grep
every synonym; prioritize the highest-value checks. Report 4-10 sharp findings, not 20 mushy ones.

Severity: blocker = cannot safely start implementation, or design as written is wrong/insecure.
major = real rework/security gap/ambiguity an implementer would guess wrong on. minor = real but
cheap. nit = cosmetic.

Read-only. Do not modify the file.
`

const FINDINGS_SCHEMA = {
  type: 'object',
  properties: {
    findings: {
      type: 'array',
      items: {
        type: 'object',
        properties: {
          id: { type: 'string' },
          title: { type: 'string' },
          severity: { type: 'string', enum: ['blocker', 'major', 'minor', 'nit'] },
          lines: { type: 'string' },
          problem: { type: 'string' },
          why_it_matters: { type: 'string' },
          recommendation: { type: 'string' },
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
          reason: { type: 'string' },
          corrected_severity: { type: 'string', enum: ['blocker', 'major', 'minor', 'nit'] },
          corrected_problem: { type: 'string' },
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

LENS: security, cryptography, identity, trust establishment.

Priorities:
- Section 4.4 pairing ceremony: is the step ordering MITM-safe? Is the invite secret a bearer token
  presented over a TLS channel the joiner cannot yet verify, or is the inviter identity pinned
  first (step 3-4)? Is the "short authentication string" derivation specified enough (transcript
  binding, length, entropy)? Is the invite proof mechanism specified at all?
- Section 4.5 credential rotation: circularity/bootstrapping problems, replay of old
  authorizations, epoch rollback, and the "renewal-only handshake" as a pre-auth attack surface.
  Is revocation enforceable against a partitioned peer, and does the doc admit the actual bound?
- Section 4.3 discovery: is the signature meaningful pre-pairing? Is replay protection via
  advertisement_nonce + expires_at specified enough to implement? Information leaked by
  session_id / credential_epoch / committed_membership_index / pairing_open. Multicast DoS.
- Section 8.1 CONNECT tunnel as a confused-deputy/SSRF surface: who chooses the destination, and
  is the "can forward only to its own session-bound loopback sidecar" claim enforceable?
- Section 10 threat model completeness: which adversary classes are missing? Specifically consider
  a malicious-but-authorized editor, a compromised agent process, a compromised sidecar, and
  denial of service by an authorized member.
- Secret handling: invite secret, Syncthing API key, the in-memory "resume capability", identity keys.
- Any place the doc says MUST with no enforceable mechanism behind it.

Name the attack, its preconditions, and its impact.`,
  },
  {
    key: 'consistency',
    prompt: `${COMMON}

LENS: internal consistency, arithmetic/factual correctness, proofreading. Completeness matters more
than severity here, but group micro-issues into single consolidated findings.

Check:
- Arithmetic: line 546 and line 968 both claim "at most 28 pairs for eight devices" - verify
  n(n-1)/2 for n=8, and whether it is consistent with an owner/editor-only mesh that excludes
  observers. Line 45 "2-8 devices and up to 32 concurrent agent instances" vs line 864
  "32-session responsiveness".
- Section 15 Open Questions vs decisions already made in the body: Q1 vs line 594; Q2 vs line 180
  and line 434; Q3 vs lines 348-350; Q4 vs line 58; Q5 vs line 532 and line 624. An open question
  the body already answers is a defect - say which way to resolve each.
- Contradictions across the section 1 summary table, section 2.4 invariants, the body, the
  section 9 failure table, section 14 targets, section 16 risks, and the section 17 ADR list.
  Does every ADR match a decision actually made in the body, and vice versa?
- Line 8 declares MUST/SHOULD/MAY normative but cites no RFC 2119, and most requirements are bare
  declarative prose. Quantify with a rough count rather than asserting.
- Terminology drift: credential_epoch vs trust epoch; session vs collaboration; member vs peer vs
  device; "strong" as an undefined adjective; "eligible"; control file vs agent-control file vs
  protected path; sidecar vs connector.
- Identifiers: are entity_id, expected_entity_version, credential_epoch, advertising_key_digest,
  advertisement_nonce, committed_membership_index, schema_version used but never defined in 4.1?
  Is device_id's hash algorithm/truncation/encoding specified?
- The JSON examples (lines 191-205, 307-340): valid JSON? Do prose descriptions match field names?
  Is the canonical serialization format for signing ever named (lines 342-343)? RFC3339 vs
  RFC3339Nano consistency.
- Line 431 task states written as a linear chain - is that the real graph? Can blocked return to
  in_progress? Compare CLI verbs on line 641 and the agent lifecycle on line 498. Is sync_blocked
  (line 599) a state or a flag?
- Section 18 references: are they adequate? Which load-bearing dependencies have no reference
  (Syncthing, MCP spec, SPAKE2+, RFC 2119, RFC 8441, UUIDv7/RFC 9562, the Raft library)?
- Document metadata: author/owner, reviewers, changelog for revision 0.6, approval workflow.
- Do sections 11 and 12 place requirements on the TEAM rather than the SYSTEM, and does that
  dilute the design doc?`,
  },
  {
    key: 'external-facts',
    prompt: `${COMMON}

LENS: fact-check claims about third-party technology. A wrong assumption here invalidates a section.
Use your knowledge; use WebSearch/WebFetch (load via ToolSearch) only for the 2-3 claims you are
least confident about. Mark each verdict with your confidence. Report only DISAGREEMENTS or
claims that are true-but-load-bearing-and-risky.

Highest priority - these are load-bearing:
1. HTTP/2 extended CONNECT (line 271, section 8.1). Is RFC 8441 extended CONNECT actually
   usable from Go's net/http server and client, or golang.org/x/net/http2? Does Go support
   ENABLE_CONNECT_PROTOCOL and the :protocol pseudo-header? If not, what would the team actually
   have to do, and does that change the design? Be precise - the entire file-sync data plane
   depends on this.
2. Raft (line 133, line 723): which maintained embedded Go Raft libraries exist, and which
   actually implement JOINT CONSENSUS versus single-server membership changes? The doc asserts the
   library provides a "safe joint-consensus procedure" - is that true of the obvious candidate
   (hashicorp/raft) or of any of them? Does the per-entry leader-signature design fit their APIs?
3. Syncthing (section 8.1, 8.3, 8.4): can the sync listener bind loopback-only while still
   dialing out to a local connector via a static device address? Name the real config knobs for
   disabling global/local discovery, relays, NAT, introducer, auto-accept, usage reporting, and
   self-update. Does staggered versioning support storing versions OUTSIDE the folder? Are
   .sync-conflict-* files the real conflict mechanism, and is "conflict copies are authoritative"
   accurate (i.e. are they always created, or can a version be lost)? Does .stignore differ from
   .gitignore as line 608-609 claims? Executable bit but not permissions (line 622)? Is one
   sidecar per session with an isolated home realistic? Is MPL-2.0 compatible with bundling?
4. Git (section 8.2): does git bundle support SHA-256 object format, and does git bundle verify do
   what the doc implies? Name the actual knobs for disabling hooks, submodule recursion, credential
   helpers, filters, and LFS smudge. Do git worktrees behave correctly when Syncthing is mutating
   a working tree?
5. MCP/Codex/Claude Code (section 7.1, section 18): is "codex mcp add NAME -- CMD" the real syntax?
   Do per-tool allowlists and write approval exist as documented features? Are AGENTS.md,
   CLAUDE.md, .codex/, .claude/ the right control-file paths, and is AGENTS.override.md real?
   Are the two learn.chatgpt.com reference URLs plausible/correct?
6. Standards/platform: putting "the identity signature and authorization index" in X.509 extensions
   of a self-signed cert (line 245) - practical, or better as an application-layer/channel-binding
   proof? SPAKE2+ audited Go implementations. Port 47831 registration/conflict. Per-interface UDP
   multicast on macOS/Windows. Unix peer-UID checks (SO_PEERCRED vs LOCAL_PEERCRED/getpeereid).
   OS credential stores from Go without CGO.

For each: state the doc's claim, the actual fact, agreement yes/no, and the design impact.`,
  },
]


const PRIOR_UNVERIFIED = [
 {
  "lens": "distributed-correctness",
  "findings": [
   {
    "id": "DS-01",
    "title": "Per-entry leader signature over (term, log_index, previous_entry_hash) is not implementable on Raft and creates two validly-signed entries at one index",
    "severity": "blocker",
    "lines": "301-305, 331-344, 356, 367-369, 373, 727, 966",
    "problem": "Lines 301-304 and step 3 (line 356) place metadata assignment and leader signing BEFORE the Raft propose: \"The leader prevalidates, assigns ordering metadata, and signs the proposal hash plus that metadata\", then \"proposes it to Raft\". Three distinct defects follow.\n\n(a) Truncation forks the signed chain. Leader L1 (term 17) assigns log_index 1048, previous_entry_hash = H(entry@1047), signs, appends locally, replicates to follower F1 only, then partitions before commit. L2 wins term 18, truncates 1048, and appends a different command at 1048 with its own previous_entry_hash and its own valid leader_signature. Two entries now exist that are indistinguishable by signature validity, carry the same log_index, and root different chains. F1 persisted the first. Nothing in the doc states that the chain is defined only over committed entries, that verifiers MUST reject a leader-signed entry absent from the committed log, or that (term, index) rather than index is the chain position. Line 373 makes this load-bearing: snapshots carry a \"chain digest\" a joiner is expected to trust.\n\n(b) The chain's domain is self-contradictory. Line 367 says rejected commands and Raft configuration entries consume indices \"so accepted event indices may have gaps\". If previous_entry_hash chains Raft entries, then config entries and rejections need hashes too, and a nonvoter receiving only accepted events in \"bounded signed batches\" (line 371) can never recompute the chain across the gaps. If it chains accepted events only, the leader cannot compute previous_entry_hash at propose time, because whether the immediately preceding entry was accepted or rejected is decided only by the deterministic apply in step 5 (lines 358-362), which happens after commit. The leader would have to serialize propose -> commit -> apply -> propose for every single event, forbidding all Raft pipelining. That constraint is nowhere stated and would gut throughput against the line 889 benchmarks.\n\n(c) Mainstream embedded Raft libraries do not expose the assigned index to the proposer before commit (hashicorp/raft `Apply(data)` and etcd/raft `Propose(data)` both assign term/index internally after the payload is sealed). Line 727 selects a \"maintained embedded Raft\" library; there is no API on which a payload can contain a signature over its own term/index/predecessor hash. Line 966 lists incorrect Raft integration as a risk but does not confront this feasibility problem.\n\n(d) The chain is signed but never verified. Step 5's deterministic recheck list (lines 358-360) is \"membership, signatures, actor binding, authorization, schema, sequence, transition, and expected version\" - previous_entry_hash / chain continuity is absent.",
    "why_it_matters": "This is the central integrity mechanism of the coordination plane and invariant \"No split-brain strong state\" (line 88) leans on it. As written an implementer must invent the chain domain, will discover mid-implementation that the chosen Raft library cannot supply pre-commit indices, and will either fork the library, serialize all proposals, or quietly drop the leader signature - a large architectural rework. Meanwhile a divergent, validly-signed phantom entry at a reused index is exactly the artifact an audit or snapshot verifier would accept.",
    "recommendation": "Decouple the hash chain from Raft ordering. Recommended: (1) drop leader-assigned term/log_index/previous_entry_hash from the signed proposal entirely; let Raft own ordering, and have every replica derive `log_index` deterministically at apply. (2) Define the chain over ACCEPTED events only, computed deterministically by every state machine at apply time as chain_n = H(domain_sep || chain_{n-1} || canonical_accepted_event_n), with SHA-256 and an explicit chain_version; no leader signature over it. (3) Record the observed (term, log_index) as unsigned local provenance. (4) If a leader attestation is genuinely wanted, make it a separate periodic committed checkpoint command signed over (term, applied_index, chain_digest) proposed AFTER apply - that is expressible on standard APIs and cannot fork. (5) Add chain continuity to the step 5 recheck list, and state that snapshot chain digests are the trust anchor plus who verifies them. (6) State explicitly that entries not present in the committed log are never events and MUST NOT be served, stored as history, or verified."
   },
   {
    "id": "DS-02",
    "title": "\"Equal projection digests\" is undefined and contradicts cross-version replication; no rule freezes reducer semantics per schema version",
    "severity": "blocker",
    "lines": "834-836, 848, 24, 404-409, 805, 819",
    "problem": "Line 834-836: \"eligible replicas at the same committed index MUST have equal projection digests\". The term \"projection digest\" appears only here; it is never defined - not the covered tables, not row ordering, not the canonical per-row encoding, not the hash, not what \"eligible\" excludes. An implementer will guess (SQLite page hash - nondeterministic due to vacuum/free lists/rowid reuse; or naive `SELECT *` order - unordered in SQLite).\n\nWorse, scenario 8 (line 848) replicates across \"Current/previous version and schema\" daemons, and line 404 lists `schema_migrations`. Two releases with different projection columns cannot produce equal digests under any reasonable definition, so scenario 8 and the line 836 harness assertion are mutually unsatisfiable as written.\n\nMost importantly, the doc never states the invariant that makes deterministic replication safe across releases: that the reducer outcome for a given (event kind, schema_version) is FROZEN forever. Concrete divergence: v1.0 reducer for `task.updated` treats a `blocked -> done` transition as invalid (line 431 lists blocked before done); v1.1 \"fixes\" it to allow it. Device A on v1.0 stores a structured rejection at index 1048, device B on v1.1 stores an accepted event and a changed task row. Both are \"deterministic\", both applied index 1048, and the replicas have silently and permanently diverged with no detection because line 836 only fires in the harness, not in production. Line 819's \"migration+replay digest\" fixture hints at the concern but states no invariant.",
    "why_it_matters": "Divergent state machines in a system whose whole premise is \"deterministic reducers\" (line 24) and \"one winner for strong claims\" (line 50) means two devices disagree about who owns a task while both believe they are committed and correct. There is no production-time divergence detector. This must be settled before any reducer is written, because it constrains how every future behavior change ships.",
    "recommendation": "(1) Define the digest normatively: an ordered fold over a fixed set of projection tables, each row canonically encoded (explicit field order, canonical payload encoding as at line 408), rows sorted by primary key, with a `digest_version` and SHA-256. (2) State the frozen-reducer invariant: reducer behavior for an existing (kind, schema_version) MUST NOT change; changed semantics require a NEW event kind or a new schema_version accepted only after a committed capability gate. Add this to line 783's non-mergeable list. (3) Split the harness assertion: replicas at the same index and same digest_version MUST match exactly; cross-version replicas MUST match on a declared version-independent core subset. (4) Add periodic committed digest checkpoints and a production divergence alarm (line 754-756 already collects metrics) plus a defined fail-closed response, rather than relying on nightly tests."
   },
   {
    "id": "DS-03",
    "title": "Quorum loss silently kills ALL peer connectivity within 30 minutes, contradicting two stated guarantees, and the recovery path for credential-expired survivors is undefined",
    "severity": "blocker",
    "lines": "34-35, 61, 135-137, 142-144, 244-259, 448, 550, 646, 665, 676, 941",
    "problem": "The coupling is stated only in two subordinate clauses - \"continue only until current credentials expire\" (line 35) and \"only while credentials remain valid\" (line 448) - and its magnitude is never spelled out. Trace a 3-voter cluster {A,B,C} where B and C are permanently lost: A (and any nonvoter D, E) keep working. At epoch boundary (<=30 min, line 23/236), every member needs a new authorization; line 243 requires a Raft commit, line 97 makes it a hard invariant, line 665 says renewal stops. So within 30 minutes ALL mTLS credentials in the session expire, line 667 closes all sessions, and two perfectly healthy, mutually reachable editors D and E can no longer control-connect or run the Syncthing CONNECT tunnel (line 289) - file sync between them stops even though nothing is wrong with either device or the network. The same fate hits an ENTIRE session whose lone voter (line 135) dies.\n\nThis directly falsifies two unqualified statements: line 550 \"Leader failure does not affect tunnels between surviving peers\" and Service Target line 941 \"Surviving-peer file transfers continue during leader loss\" - both true only inside the residual epoch window.\n\nThe recovery path is then undefined. Line 142-144 requires \"explicit owner-approved recovery into a new trust epoch from the last verified committed state\" and line 646 exposes `recover-quorum`, but the doc never says: whether the owner device can perform it with zero peer connectivity (it must, since by then nothing can connect); whether the non-owner survivors D and E must re-pair through section 4.4 (line 141's \"without re-pairing existing members\" is scoped only to the quorum-survives case); how a survivor learns the new trust epoch when it cannot open any authenticated channel; or what happens if the OWNER device is one of the lost ones (lines 174-181 make invite/role/voter changes owner-only, so an editor-only survivor set appears to be permanently unrecoverable).",
    "why_it_matters": "This is the last-resort availability path for a system explicitly targeting flaky LAN/VPN environments (2.2) and 2-device sessions (line 60). As written, an ordinary event - one of three laptops closes its lid and one loses Wi-Fi - degrades in 30 minutes from \"strong writes queue\" to \"total session outage including file sync\", and the doc's own guarantees say otherwise. An implementer cannot build `recover-quorum` without inventing the re-admission and owner-absent policy, and each guess produces a different security posture.",
    "recommendation": "(1) State the consequence plainly in section 1 and in the line 665 failure row: \"quorum loss degrades to complete loss of all peer connectivity within one credential epoch (<=30 min), including direct file sync between healthy peers.\" (2) Qualify lines 550 and 941 with \"within the current credential epoch\". (3) Specify the recovery procedure end to end: who may initiate it when the owner is lost (e.g. a committed break-glass recovery authorization, or an offline-verifiable owner recovery key held per line 708), whether it is performed offline on one device, how survivors are re-admitted (re-pair with two-sided confirmation vs. transcript-signed epoch-bump proof), and how the new epoch's genesis links to the old (line 168-170's genesis record has no successor concept). (4) Add an explicit availability-vs-security decision record justifying the epoch length against the outage it induces, and if a longer degraded-mode credential is acceptable, define it (e.g. an owner-approved, role-restricted, sync-only extended credential) rather than leaving 30 minutes as a hidden availability cliff. (5) Add a harness scenario: lose quorum, let ALL credentials expire, then recover - scenario 17 (line 858) stops at \"fail closed\" and never exercises the post-expiry state."
   },
   {
    "id": "DS-04",
    "title": "Credential expiry - the sole bound on stale-partition access - is enforced against unsynchronized local wall clocks with no skew allowance",
    "severity": "major",
    "lines": "243-255, 320, 335, 445, 869",
    "problem": "Line 244 commits an authorization \"containing key digest, role, epoch, issue time, and expiry\", and line 254-255 rests the security argument on it: \"An isolated stale partition cannot authorize another epoch, bounding stale access by the current credential expiry.\" But the enforcement in line 246-248 is a peer checking that committed expiry - a wall-clock instant - against its OWN local clock. No skew allowance, clock-source requirement, or sanity bound is specified anywhere; \"bounded clock-skew allowance\" appears once (line 445) about leases, with no number, and section 2.2 assumes networks with no DHCP or Internet, so NTP may be unavailable.\n\nTwo concrete failures. (a) Slow clock extends the security bound: revoked-then-partitioned device R holds an epoch-42 credential expiring at T. Peer P's clock is 20 minutes slow (suspend/resume drift on the line 886 sleep/wake path is a listed test case). P keeps accepting R's mTLS connections for 20 minutes past T - and P has not observed the revocation (line 253 is explicitly \"on peers that observe it\"), so the documented stale-access bound is silently exceeded. (b) Fast clock causes spurious total outage: a member whose clock jumps 10 minutes ahead rejects every peer's currently-valid credential and cannot present its own, self-isolating even with full connectivity.",
    "why_it_matters": "Line 254-255 is the doc's answer to \"what stops a stale or ex-member from acting\", and section 10 line 694-695 lists \"bounded stale partition lifetime\" as a required control. That bound is only as good as the clocks, and the doc neither bounds them nor bounds the damage. Skew is also a first-class harness fault (line 830 \"skew/rollover\"), so the tests will hit undefined behavior.",
    "recommendation": "Specify the time model for credential validation: (1) a maximum acceptable skew (e.g. 60 s) applied asymmetrically - never leniently past expiry (reject at expiry, no grace) and leniently at issue time (accept notBefore - skew) so a fast clock cannot self-isolate; (2) require monotonic-clock anchoring for connection lifetime caps (line 251) so a wall-clock jump cannot extend a live session; (3) require peers to detect and surface gross skew (compare committed `sequenced_at` on applied entries against local time) as a health signal per line 756, and fail closed on skew above a stated threshold; (4) state that revocation, not expiry, is the primary control and expiry is only the backstop for peers that have not observed revocation, and give the resulting worst-case stale-access window explicitly as epoch + skew."
   },
   {
    "id": "DS-05",
    "title": "Lease expiry has no time source when there is no leader, the skew allowance has no number, and two independent expiry paths are unreconciled",
    "severity": "major",
    "lines": "436, 442-445, 495-496, 664, 794, 830",
    "problem": "Lines 443-445 are internally consistent but incomplete: \"Lease deadlines are committed values; reducers never consult local wall clocks. The leader proposes renew/expire commands, and a new leader observes the bounded clock-skew allowance before expiring inherited leases.\" Three gaps.\n\n(a) Time only enters via the leader, so during any leaderless interval NO lease can expire. Interleaving: agent X on device A holds a path lease with deadline T; A crashes; the leader also crashes at T-1s; election plus a lost voter means the cluster is leaderless or quorum-less (line 664/665 queue strong proposals) for minutes to indefinitely. Agent Y on device B cannot acquire the path lease for the entire outage because the expire command cannot be proposed. This is unstated; line 442's \"leases warn and reduce overlap\" is the only mitigation and it is advisory.\n\n(b) \"the bounded clock-skew allowance\" has no value anywhere in the document (confirmed: `skew` appears only at 445, 794, 830), and the leader's local clock is a trusted input to a mutual-exclusion decision with no requirement that it be monotonic-anchored or sanity-checked. A leader whose clock is 10 minutes fast expires a live agent's lease, and in shared-root mode (line 512-514) that puts two agents on the same paths.\n\n(c) Two independent expiry paths are never reconciled. Line 495-496: agent disconnect grace \"expiry ends the session, releases leases\" - that is the AGENT'S host daemon acting on ITS local clock, proposing a release. The committed lease deadline (line 443) is the LEADER acting on its clock. If the agent's daemon is partitioned from the leader, both paths fire; if the agent reconnects with its resume capability inside grace but the leader already expired the lease, the agent resumes believing it holds a lease it no longer holds. Ordering and the authoritative outcome are unspecified.",
    "why_it_matters": "Leases are the only concurrency control in shared-root mode and the only overlap signal in worktree mode; the shared-root risk is already acknowledged at line 977. An implementer must invent the skew number and the leaderless-expiry policy, and the resume-vs-expire race is exactly the kind of bug the line 844 harness scenario (\"adapter resume/expiry/ID non-reuse\") will surface as nondeterministic.",
    "recommendation": "(1) Give the clock-skew allowance a number and a home (e.g. lease_skew_allowance = 60 s, committed in the genesis policy at line 168 so all members agree). (2) State plainly that leases cannot expire while the cluster has no leader or no quorum, that the resulting hold time is unbounded, and what the UI/agent behavior is (surface \"lease expiry stalled - no quorum\" and block, or document that acquisition fails closed). (3) Require the leader's expiry decision to use a monotonic-anchored clock and to skip expiry if its own clock moved discontinuously. (4) Define precedence between grace-period release and committed deadline expiry (recommend: the committed log is authoritative; a resumed agent MUST recheck lease ownership at the applied index before acting, and resume never revives an expired lease). (5) Add a harness fault for \"leaderless across a lease deadline\"."
   },
   {
    "id": "DS-06",
    "title": "Voter membership policy is unspecified: who becomes a voter as devices join, whether 2/4-voter configs exist, and the target count after removing a lost voter",
    "severity": "major",
    "lines": "20, 60-61, 131-144, 181, 630-634, 857",
    "problem": "The doc constrains voter counts (line 20 \"1/3/5 voters\"; lines 133-137 prefer odd) and says owners may change voters (line 181, 183), but never states the POLICY. Unanswered, each with a different implementation:\n\n(a) As devices 2..8 join (line 46), does anyone become a voter automatically? Line 225-227 admission commits \"membership\" with no voter decision. A session that starts as 1 voter (line 135) and grows to 8 devices plausibly stays at 1 voter forever - a silent single point of failure where the death of that one device kills the whole session including file sync (see DS-03). Nothing requires the TUI to warn; line 630-634 lists a quorum view but no \"1 voter, no tolerance\" alert, and there is no prompt to promote at the third join.\n\n(b) Is 2 voters reachable? Line 20's \"1/3/5\" implies no, but line 60 explicitly permits two-device sessions, and section 3 never says whether the second device joins as nonvoter (correct) or voter. If 2 voters are allowed, quorum is 2 and either device failing halts strong writes - the same outcome as 1 voter but with strictly worse liveness, since the 1-voter case at least keeps working while its voter lives.\n\n(c) Line 141 and scenario 16 (line 857): \"If quorum survives a permanent voter loss, it removes/replaces that voter\". Removing C from {A,B,C} leaves 2 voters - not in {1,3,5}. Does the cluster sit at 2, demote to 1, or is removal forbidden until a replacement is available? \"removes/replaces\" reads as either. The choice materially changes availability: sitting at 2 means the next single failure loses quorum permanently; demoting to 1 keeps writes alive on the survivor but abandons split-brain protection guarantees users were told they had.\n\n(d) Which device gets promoted to replace a lost voter, and on what eligibility criteria (up-to-date applied index? role? uptime?) - relevant because line 372's \"any up-to-date voter\" already implies an up-to-dateness notion that is never defined.",
    "why_it_matters": "Voter set composition determines every availability property the doc promises (lines 32-33, 940) and gates the DS-03 outage. An implementer will guess - most likely \"nonvoter by default, manual promotion\" - and ship a product where the common 3-device session silently has one voter and no fault tolerance despite the doc recommending three. Scenario 16 cannot be written without answering (c).",
    "recommendation": "Add a short normative voter-policy subsection to section 3: default consensus role on admission (recommend nonvoter); an explicit rule for reaching 3 voters (recommend: on the third device's admission, prompt the owner to promote two peers, and require the TUI to display a persistent degraded-tolerance warning until voters >= 3); state whether even voter counts are permitted at all and, if transiently permitted during joint consensus, that they MUST NOT be a resting state; define the resting configuration after permanent voter removal, including whether demotion to 1 voter is allowed and what warning it raises; define \"up-to-date\" (applied index within N of the committed index) as the promotion and snapshot-service eligibility criterion; and state whether a 1-voter session is allowed to accept additional devices at all given the total-session-loss exposure."
   },
   {
    "id": "DS-07",
    "title": "Compaction is one clause: no retention floor, no cursor-too-old behavior, no coordination with Raft snapshots, and no chain anchor for post-compaction history",
    "severity": "major",
    "lines": "59, 281, 363-364, 371-376, 404, 415, 420, 927",
    "problem": "Compaction is mentioned twice - \"session-lifetime coordination history with export before compaction\" (line 59) and \"backup/export/compaction\" (line 927) - and never specified. The consequences reach several defined mechanisms.\n\n(a) Catch-up below the floor is undefined. `GET /v1/events?after=N` (line 281) plus \"durable cursors\" (line 372) is the nonvoter/offline path. A nonvoter offline for a week returns with cursor N below the retained event floor. Line 372-374 offers a snapshot fallback but there is no defined error/signal for \"cursor too old\", no requirement that the server detect it rather than silently return a batch starting above N (which would leave a permanent hole in that replica's events table and break the line 836 digest equality), and no rule that a client MUST switch to snapshot-import on that signal.\n\n(b) Raft log truncation and CodeComm's logical event retention are separate and uncoordinated. Line 391/420 uses the library's snapshot store; line 404's `events` table is CodeComm's. Nothing states that the logical event floor MUST be at or below the Raft snapshot index, or what happens when they disagree.\n\n(c) The hash chain (line 336) and \"chain digest\" (line 373) lose their root. After compaction, no replica can verify continuity from the genesis record (line 168) to the present, and the doc never designates the signed snapshot as the new trust anchor or says who must countersign it (line 372's \"any up-to-date voter\" signing a snapshot is a single-device attestation for state that previously required quorum).\n\n(d) `idempotency_keys` (line 404) has no TTL or GC rule, so it grows for the session lifetime; conversely if it is GC'd or compacted, a retried non-versioned mutation can double-apply. Note the partial mitigation: line 414's unique `(device_id, agent_session_id, origin_sequence)` does dedupe agent-originated retries, and line 324's `expected_entity_version` catches versioned ones - but `memory.append` (line 435, append-only), `activity.append`, and `POST /v1/acks` (line 285) are neither, so duplicates land after key loss.",
    "why_it_matters": "Long-offline rejoin (line 53 \"resume idempotently\") and 1M-event catch-up (line 889) are both promised. Silent event holes are precisely the failure the line 836 harness assertion is meant to catch, and it will catch it only if a test happens to compact - no scenario in 12.3 does. Compaction also interacts with every verification story in the doc, so leaving it to phase 6 (line 927) invites a retrofit through the persistence and replication layers.",
    "recommendation": "Add a retention subsection to section 6: define the retained event floor and who advances it (recommend: only via a committed compaction command carrying the new floor and the snapshot digest, so all replicas agree); require floor <= Raft snapshot index; define a `cursor_too_old` structured problem response (line 293) and require clients to fall back to `GET /v1/snapshots/latest` plus tail; declare the signed snapshot's chain digest the trust anchor for pre-floor history and state the required countersignature policy (recommend quorum-committed digest checkpoints per DS-02 rather than a single voter's signature); give `idempotency_keys` an explicit retention that is provably longer than the maximum client retry window, and state which event kinds rely on the origin-sequence uniqueness constraint instead; add harness scenarios for compaction-then-rejoin and compaction-then-snapshot-verify."
   },
   {
    "id": "DS-08",
    "title": "`hlc` and `created_at` are inside the signed body but declared display-only with no validation rule, and no HLC update rule exists",
    "severity": "minor",
    "lines": "320-321, 335, 344, 358-360, 369, 630",
    "problem": "`created_at` and `hlc` are covered by the origin signature (line 342) but line 344 says \"wall time/HLC aid display and diagnosis only\", and the step 5 deterministic recheck list (lines 358-360) does not include them. So they are signed, replicated, durable, unvalidated, and rendered. An authorized-but-misconfigured or hostile origin sets `created_at` to year 2199 or a negative-looking offset; the activity/provenance TUI view (line 630) and the generated `context.{json,md}` (line 393) - which agents read - order or label history by it, so one device can permanently skew what every human and agent believes the sequence of work was, with no rejection and no audit signal.\n\nAlso, the `hlc` field has no defined semantics at all: no update rule (the defining property of a hybrid logical clock is that receivers advance their clock on receipt), no encoding, and no consumer. As specified it is dead weight that is nonetheless signed and stored.\n\nNote the trap the doc has not addressed: this cannot simply be validated by the leader, because step 5's recheck must be deterministic on every replica and the leader's clock is not a deterministic input. A leader-only bound is explicitly non-authoritative per line 369.",
    "why_it_matters": "Cheap to fix, but signed-and-unvalidated fields are how forged-event tests (line 873 \"forged/replayed/oversized events\") turn into ambiguity, and misleading provenance directly undermines section 7.3's premise that provenance display is a real control. Leaving `hlc` undefined also means five implementers produce five encodings that all appear in golden fixtures (line 814).",
    "recommendation": "Either (a) drop `hlc` from V1 and say `log_index` is the only ordering, keeping `created_at` as an explicitly unvalidated origin claim that the UI MUST label as such and MUST NOT sort by (sort by log_index); or (b) define it properly: encoding, the receive-side advance rule, and a deterministic bound checked at apply against committed values - e.g. reject if `created_at` is more than a committed `max_created_at_drift` outside [previous accepted event's `sequenced_at` - drift, this entry's `sequenced_at` + drift], which is deterministic because `sequenced_at` is committed. Add the chosen rule to the step 5 recheck list and a negative fixture."
   },
   {
    "id": "DS-09",
    "title": "Leader pre-rejection is unreplicated and not recorded, so the same retry can yield different outcomes across leaders",
    "severity": "minor",
    "lines": "362, 368-369, 659, 293",
    "problem": "Line 368 permits the leader to \"pre-reject an obviously stale command\", while line 362 requires that a committed invalid command \"stores the same structured rejection on every replica\". A pre-rejection is neither committed nor stored, and in particular is not recorded in `idempotency_keys` (line 363-364). Interleaving: client submits idempotency key K; leader L1 pre-rejects it and the response is lost in the network; L1 fails; the client retries K to L2, whose applied state has advanced past the staleness condition, so L2 proposes and commits K as accepted. The client's first attempt reported a rejection for a command that is now in the log and applied. Line 659's \"Duplicate request | Return committed idempotent result\" cannot fire because the first attempt left no committed record. Symmetrically, a client that treats a pre-rejection as terminal may abandon a task claim that a different leader would have accepted, and the audit trail (line 128 \"durable audit events\") contains no trace of the rejection the operator saw in the UI.",
    "why_it_matters": "Small blast radius, but it makes the client contract nondeterministic in exactly the leader-churn scenarios the harness stresses (scenarios 11 and 15, lines 851 and 855-856), and it will present as an unreproducible \"the CLI said rejected but the task is claimed\" bug.",
    "recommendation": "State that pre-rejection is a non-authoritative, retryable optimization: it MUST use a distinct problem type marked retryable (line 293's structured problem responses), MUST NOT consume or record the idempotency key, MUST NOT emit a durable audit event, and clients MUST retry it against the current leader rather than treating it as terminal. Restrict pre-rejection to conditions that are monotone in applied index (so a later leader cannot reverse them) or drop the optimization from V1."
   }
  ]
 },
 {
  "lens": "simplicity-tradeoffs",
  "findings": [
   {
    "id": "F1",
    "title": "Mixed-version daemons in one Raft cluster contradict the deterministic-reducer requirement; no skew policy exists",
    "severity": "blocker",
    "lines": "359-362, 834-835, 848, 904, 292-294",
    "problem": "Line 361-362 requires that *every* state machine apply each committed command \"in index order and deterministically recheck ... schema, sequence, transition\" and that \"an invalid or stale command stores the same structured rejection on every replica.\" Line 834-835 makes this a test gate: replicas at the same committed index MUST have equal projection digests. But devices in a personal mesh upgrade independently, and the doc never states a supported skew policy. The only related text is test-side: line 825 (\"current/retained prior daemons\" in the harness), line 848 (\"Current/previous version and schema replication\"), and line 904 (\"upgrades from supported DB/protocol versions\"). None of these define the rule. The failure is structural, not incidental: line 292-294's \"Unknown required capabilities fail closed\" is a *request-time* mechanism and cannot apply to an already-committed Raft entry. A v1.1 leader commits a new event kind or a changed reducer branch; a v1.0 follower must apply that same index and will either reject it (while v1.1 accepted it) or apply it differently. Either way the projection digests diverge and the invariant at line 88 (\"Only quorum-committed Raft entries are accepted\") no longer implies a single agreed state.",
    "why_it_matters": "This is the one class of bug that silently destroys the correctness story the whole design rests on, and it will happen on the first real upgrade because nothing prevents a user from updating one laptop. It is unfixable after the fact: divergent projections are only detectable if you happen to compare digests, and the recovery path (line 143, new trust epoch from last verified committed state) is the heaviest one in the doc.",
    "recommendation": "Add a normative subsection stating: (a) a `min_apply_version` / feature-gate field on every Raft command, so a replica that cannot deterministically apply an entry halts and refuses to advance its applied index rather than diverging; (b) an explicit N-1 support window with a rule that new reducer semantics are introduced dark and only activated by a committed `capability.enabled` entry once all committed members report a version that supports it; (c) a cluster-wide minimum-version field in the committed membership so an upgraded device can refuse to lead until gating is satisfied; (d) an integration scenario asserting that a v1.0 follower in a v1.1-led cluster halts safely and reports a version blocker in the TUI, rather than producing an unequal projection digest. Also add a test that mixed-version projection digests are compared, not just same-version ones."
   },
   {
    "id": "F2",
    "title": "Post-bootstrap Git history diverges permanently; worktree publication depends on an unresolved Open Question",
    "severity": "blocker",
    "lines": "507-511, 591-595, 950-951, 26",
    "problem": "Line 507-511 makes isolated worktrees the *default* concurrency mode and specifies that an agent publishes \"a reviewed proposal containing base commit, paths, digests, and patch/commit metadata into the canonical synchronized tree.\" Line 591-593 states `.git/` is never synchronized, \"Syncthing moves working-tree content, not refs, indexes, locks, or objects; a commit does not move peer refs.\" Line 594 then hedges the entire resolution: \"Ongoing commit/ref exchange, *if included*, MUST use an authenticated bare remote or incremental bundles\" \u2014 and line 950-951 lists it as Open Question 1. The two positions are incompatible. If ongoing ref exchange is excluded, then any commit made on device A after bootstrap creates an object that exists nowhere else; the `base_commit` in A's next published proposal (line 509) references an object B cannot resolve, so B can neither verify the digest chain nor render a diff. Worse, B's synchronized working tree now contains A's post-commit content while B's index/HEAD still point at the bootstrap commit, so `git status` on B shows the whole delta as uncommitted, and a commit on B forks history irrecoverably. Nothing in section 8.3 detects or reports this.",
    "why_it_matters": "The default agent isolation mode cannot be implemented without answering Open Question 1, and the answer changes section 8.2, 8.3, the role table, and delivery phases 4 and 5. An implementer will guess \"working-tree-only\" (the cheaper reading of line 594), ship it, and discover that the flagship feature \u2014 multiple agents on isolated worktrees publishing reviewed proposals \u2014 has no working verification path.",
    "recommendation": "Resolve Open Question 1 in the doc before implementation and pick the ref-exchange option, since the default worktree mode requires it. Concretely: define a `POST /v1/git/incremental-bundles` (or an authenticated bare remote inside the existing mTLS tunnel) that ships objects for any `base_commit` referenced by a published proposal, plus a normative rule that a proposal event is not renderable/approvable until the receiver has the referenced base commit, with an explicit `git_base_missing` blocker state in the TUI. Also state what happens to divergent local histories (who rebases, and whether CodeComm ever runs a merge \u2014 line 77 says it never auto-merges)."
   },
   {
    "id": "F3",
    "title": "Long-lived device identity keys have no lifecycle: no rotation, no expiry, no re-enrollment, no backup, and revoked keys are not stated to be retained for history verification",
    "severity": "major",
    "lines": "163-165, 302-305, 419-420, 668, 707-709, 857",
    "problem": "Line 164-165 puts long-lived private keys in the OS credential store and line 148-149 derives `device_id` from that key's hash. Line 302-305 makes those same keys the root of history verifiability (\"Both signatures use enrolled device identity keys, not rotating transport keys, so history remains verifiable\"). Grepping the whole file for rotation/expiry/reinstall/compromise language confirms every hit is about the *30-minute transport* keys (lines 235-255) or about voter membership (line 141-144, 857) \u2014 nothing about the identity key itself. Four concrete holes: (1) No identity rotation or expiry. A key valid for the life of the project is the opposite of the policy applied to transport keys, and the doc never argues why. (2) No compromise recovery beyond revoking the device (line 668) \u2014 but revocation destroys the device_id, and since device_id *is* the key hash, the same physical machine returns as a stranger with no continuity of its task/lease/authorship history. (3) OS reinstall or credential-store loss is unaddressed: the key is gone, so the device must re-pair as a new identity, its Raft voter slot must be removed and replaced (line 857 covers the mechanics but not the trigger), and its history is orphaned. (4) The backup story at line 419-420 covers SQLite plus a matching Raft snapshot only \u2014 identity keys and credentials are explicitly excluded from backup and the doc does not say whether that is deliberate.",
    "why_it_matters": "Every trust decision in the system chains to this key, and the doc gives it less operational care than the keys it rotates every 30 minutes. Reinstalling an OS or replacing a laptop is a routine event for a 2-8 personal-device tool, and today it silently costs the user their authorship continuity and a voter slot with no documented procedure.",
    "recommendation": "Add a short subsection to 4.1 covering: (a) identity key rotation as a committed `device.identity.rotated` event that binds old_key -> new_key with a signature from the old key, preserving a stable logical `member_id` distinct from `device_id` so history stays attributable across rotations; (b) an explicit statement that revoked and rotated-out public keys are retained forever in the `devices` table for historical signature verification, and that revocation removes authorization but not verifiability; (c) a documented \"lost/reinstalled device\" runbook that re-pairs a new identity, links it to the prior member_id via an owner-approved committed event, and removes/replaces the voter; (d) an explicit decision that identity private keys are deliberately not backed up (with the consequence spelled out), or a defined escrow/export."
   },
   {
    "id": "F4",
    "title": "30-minute quorum-authorized TLS rotation: benefit is narrow, the availability cost is a hard offline cliff, and the doc never argues the tradeoff or the interval",
    "severity": "major",
    "lines": "23, 235-255, 447-448, 664-665, 940-941",
    "problem": "The only property this buys over stable-identity mTLS plus committed revocation is stated at line 253-255: it bounds how long an isolated/revoked device retains access to the current credential expiry. That is real, but it is the *only* benefit, and the cost is not reconciled with the availability promises elsewhere. Line 665 stops credential renewal on quorum loss; line 35 and line 448 say direct sync continues \"only until current credentials expire.\" So within at most 30 minutes of losing quorum, *all* peer traffic between perfectly healthy, mutually-authenticated devices stops \u2014 which directly undercuts line 664 (\"Leader loss: direct reads/sync continue\"), line 550 (\"Leader failure does not affect tunnels between surviving peers\"), and service target line 941 (\"Surviving-peer file transfers continue during leader loss\"). Those statements are true for a brief election and false for a partition lasting half an hour. The doc also never justifies 30 minutes specifically, never makes it configurable, and never says what the user sees as the cliff approaches.",
    "why_it_matters": "For a personal 2-8 device tool, a partition lasting more than 30 minutes is ordinary (a laptop on a hotel network, a device asleep, one of three voters at home). The design converts a partial outage into a total one, and an implementer reading lines 664/941 will build UX that promises continuity the credential layer will revoke.",
    "recommendation": "Either (a) keep rotation but lengthen and parameterize the epoch \u2014 a committed policy value with a default in the hours, plus a normative rule that renewal is attempted continuously and that impending credential expiry surfaces as a distinct TUI/CLI state with a countdown well before the cliff; or (b) drop per-epoch rotation and get the same bounded-staleness property from long-lived mTLS certificates plus a committed revocation list with a short freshness requirement enforced at connection setup, which fails soft (peers keep working, they just cannot admit changes) instead of hard. Whichever is chosen, add an explicit paragraph reconciling the chosen behavior with lines 664, 550, and 941, and change target 941 to state the window over which it holds."
   },
   {
    "id": "F5",
    "title": "Discovery datagram's stated privacy properties are not delivered by its own schema",
    "severity": "major",
    "lines": "191-213, 684",
    "problem": "Line 206-208 claims \"Datagrams contain no workspace/device/user names, paths, stable identity fingerprints, secrets, tasks, or activity,\" and line 684 declares a hostile LAN as the threat model. But the schema on lines 193-204 broadcasts, unencrypted and unauthenticated-to-observers: a stable `session_id` that persists for the entire collaboration, a monotonic `committed_membership_index` (1048), a monotonic `credential_epoch` (42), and an `advertising_key_digest` that is stable for a whole epoch. A passive observer on the LAN can therefore link all of the user's devices to one collaboration, follow them across networks by session_id, count and time every membership change, and infer session age and activity from the two monotonic counters. `pairing_open: true` additionally advertises exactly when the session is accepting a joiner \u2014 the highest-value moment for an attacker to attempt invite guessing (line 232's rate limits are the only mitigation).",
    "why_it_matters": "The doc makes a specific privacy claim that its own message format contradicts, so a reviewer or implementer will believe discovery is privacy-preserving and will not fix it. On a shared office or conference LAN \u2014 the exact environment section 2.2 targets \u2014 this is a persistent device-linkage beacon.",
    "recommendation": "Replace the plaintext `session_id` with a per-epoch rotating tag, e.g. `HMAC(current_epoch_key, session_id || epoch)`, which existing members can recognize and strangers cannot correlate across epochs. Drop `committed_membership_index` and `credential_epoch` from the datagram (a peer can learn both over mTLS after connecting) or coarsen them. Gate `pairing_open` so it is only advertised while an invite is actually outstanding, and restate lines 206-208 to say precisely what a passive observer can learn rather than implying it is nothing."
   },
   {
    "id": "F6",
    "title": "Section 12 has no property-based, model-based, or deterministic-simulation testing, despite risk 3 naming Raft integration as a safety hazard",
    "severity": "major",
    "lines": "775-820, 823-864, 967-968",
    "problem": "Section 16 risk 3 (lines 967-968) states that \"Incorrect Raft transport/store/snapshot/membership/apply integration can violate safety despite using a mature library\" \u2014 i.e. the author already knows the hardest bugs are in emergent multi-node state, not in units. Section 12 answers this exclusively with example-based tests: an enumerated scenario list (lines 840-859), a named fault list (lines 829-832), golden fixtures (lines 813-820), and seeded soak/chaos (lines 892-894). Grepping for property/model/linearizability/TLA/simulation/shrink finds nothing; the only relevant hit is line 781, \"Random tests record seed/trace,\" which is a hygiene rule, not a technique. Missing specifically: (a) property-based tests over reducers (apply-order determinism, replay/snapshot equivalence at line 804 is asserted as a subject but with fixed fixtures, and CAS/lease/version-conflict properties over generated command sequences); (b) a deterministic simulation mode with a virtual clock and controlled scheduling so a multi-node safety violation is reproducible from a seed rather than caught once in a nightly soak; (c) a linearizability/history checker on the strong-claim path so \"exactly one winner\" (line 942) is validated against generated concurrent histories, not the four hand-written races in scenarios 3, 5, 6.",
    "why_it_matters": "Enumerated scenarios only find the interleavings someone imagined. The safety violations risk 3 warns about live in the interleavings nobody imagined, and a nightly chaos run that fails once every 200 runs without a deterministic replay is effectively unactionable. The rest of section 12 is unusually strong, which makes this the conspicuous gap.",
    "recommendation": "Add to 12.2 a property-based suite over reducers and canonical encoding (roundtrip, order-determinism, idempotent-replay, and CAS-single-winner as generated properties with shrinking), and to 12.3 a deterministic simulation mode: virtual clock, seeded deterministic scheduler over the existing fault-proxy and failpoint seams (lines 794-797 already provide the seams), so any harness failure is replayable from a seed in CI. Add a linearizability checker over generated concurrent task/lease claim histories. If a TLA+/Stateright model of the credential-epoch and membership state machine is out of scope for V1, say so explicitly and name what compensates."
   },
   {
    "id": "F7",
    "title": "Bulk Syncthing traffic multiplexed over HTTP/2 CONNECT is a throughput hazard the performance targets do not account for",
    "severity": "major",
    "lines": "267-272, 289, 538-544, 890, 935",
    "problem": "Line 267 puts the application protocol on HTTP/2, line 271 tunnels Syncthing via \"HTTP/2 extended CONNECT\", and line 289 defines `CONNECT /v1/sync/tunnel`. The design intent (lines 538-544, invariant line 92) is sound \u2014 one authenticated port, one identity system, revocation kills sync instantly, no second pairing UX, no extra firewall rules. But HTTP/2 imposes per-stream and per-connection flow-control windows and connection-level head-of-line blocking, which are well known to cap bulk transfer throughput unless windows are explicitly tuned, and here the bulk data (2 GiB workspaces, 100 MiB files per line 58) shares a connection with the control plane's SSE streams and REST calls. The doc benchmarks \"tunneled Syncthing\" (line 890) and sets a p95 <2 s stable-file-visibility target (line 935) without acknowledging this coupling, specifying window sizes, or stating whether tunnels get a dedicated connection. It also adds a second full TLS layer over Syncthing's own TLS (line 543), doubling encryption cost on the bulk path.",
    "why_it_matters": "If measured throughput comes in low, the fix is architectural, not a tuning knob \u2014 you have to move the tunnel off the control connection \u2014 and that lands after the sync, revocation, and tunnel-authorization work is built on top of it. Cheap to decide now, expensive to discover in phase 5.",
    "recommendation": "Keep the tunnel-through-CodeComm decision, but specify that sync tunnels use a *separate* mTLS connection negotiated by ALPN (or at minimum a dedicated HTTP/2 connection never shared with control/SSE traffic), with explicit initial window and frame-size requirements and a documented target throughput floor. Add an explicit note under ADR-015 (line 996) recording the double-encryption cost and why it is accepted, and add a benchmark comparing tunneled versus direct-Syncthing throughput so the overhead is a measured number rather than an assumption."
   },
   {
    "id": "F8",
    "title": "Concrete V1 scope cuts: several mechanisms carry full cost for a property the design already gets elsewhere",
    "severity": "major",
    "lines": "20, 60-61, 136-137, 328, 331-338, 344, 392-393, 402-403",
    "problem": "Taking the author's lens seriously in the other direction: most of the machinery here is justified (Raft for single-winner claims; log plus snapshot are inherent to Raft, not a separate mechanism; the git bundle exists precisely because `.git/` never syncs; Syncthing for files; outbox and idempotency for crash safety). Three items are not carrying their weight for a 2-8 personal-device tool. (1) `hlc` (line 328) is a signed, canonical, per-event field, yet line 344 says \"wall time/HLC aid display and diagnosis only\" and line 444 forbids reducers from consulting clocks \u2014 a full HLC subsystem plus its canonical-encoding, fixture, and cross-platform-stability obligations, for tooltips that `created_at` plus `log_index` already serve. (2) `leader_signature` per entry (line 337) buys offline verifiability of an exported history by a party that does not trust the local DB \u2014 but `previous_entry_hash` (line 336) already chains entries, so a signature over a periodic checkpoint of the chain head yields the same guarantee at a tiny fraction of the per-event signing cost on the leader's critical path. (3) five voters (line 20, 136-137) is a configuration whose only V1 value is tolerating two simultaneous losses in a mesh capped at eight devices; it multiplies the joint-consensus, harness, and benchmark matrix. Separately, `inbox/` (line 392-393) is a third event-ingress path, already marked \"optional\", duplicating `POST /v1/events` and the MCP/CLI surface.",
    "why_it_matters": "The author asked whether V1 can plausibly ship. As written it is a very large V1, and these four items are pure surface area: each one adds canonical-format obligations, golden fixtures, harness scenarios, and security review load without adding a property the design lacks.",
    "recommendation": "For V1: drop `hlc` from the signed event (keep `created_at` plus `log_index`) and add it later if diagnosis actually demands it; replace the per-entry `leader_signature` with the existing hash chain plus a signed periodic chain-head checkpoint, stating the exact verification property retained; support 1 and 3 voters only and defer 5; cut `inbox/` entirely. Keep unchanged: Raft with joint consensus, the single signed-event/deterministic-reducer plane, projections, snapshots, idempotency and outbox, verified git-bundle bootstrap, Syncthing, isolated worktrees, local-only stdio MCP, and stable-identity mTLS. Add a short paragraph to section 13 stating what is explicitly deferred past V1, so scope is visible rather than implied."
   },
   {
    "id": "F9",
    "title": "At-rest posture asserts a requirement it cannot enforce and does not enumerate what sits in the clear",
    "severity": "minor",
    "lines": "713-715, 387-395, 601, 908",
    "problem": "Line 713-715 says \"At-rest encryption is not assumed. Require full-disk encryption; add DB encryption/key management separately if coordination history is more sensitive than source.\" Owning the tradeoff is the right instinct, but as written it is a requirement on the user with no verification, no first-run check, and no failure behavior \u2014 nothing anywhere in the doc detects or reports that FDE is off. It also does not enumerate the cleartext surface it is covering, which is larger than \"the DB\": `logs/` redacted logs, `run/`, and `tmp/` bootstrap staging (line 395 \u2014 staging holds a full verified git bundle of the repository), `conflicts/` resolution snapshots (line 394), and the sidecar's staggered version history of prior file versions stored outside the repository (line 601). \"Require full-disk encryption\" reads as satisfied when in fact several new plaintext copies of workspace content are being created outside the workspace.",
    "why_it_matters": "The author explicitly asked whether this is an owned tradeoff or a silent gap. It is currently half-owned: the decision is stated, the scope and the enforcement are not, so a reader cannot tell what they are accepting.",
    "recommendation": "Rewrite lines 713-715 to (a) enumerate every cleartext artifact CodeComm creates outside the workspace \u2014 `state.db` and WAL, `consensus/`, `logs/`, `conflicts/` snapshots, `tmp/` bootstrap staging including full git bundles, and sidecar version history \u2014 and note that these are new plaintext copies of repository content; (b) add a normative first-run and `codecomm status`/`doctor` check that reports FDE state per platform and surfaces a visible warning when it is off; (c) require that `tmp/` staging and expired temporary artifacts are removed promptly (line 582 covers the success path only) and that sidecar version retention is bounded and configurable."
   },
   {
    "id": "F10",
    "title": "Audit log, activity retention, and data removal have no defined surface, policy, or lifecycle",
    "severity": "minor",
    "lines": "58-59, 128, 406, 630, 637-651, 906, 707",
    "problem": "`audit_events` exists as a table (line 406) and audit entries are Raft-ordered (line 128), so they inherit the hash chain and leader signatures \u2014 tamper-evidence is genuinely covered. What is absent, confirmed by grep: (1) no query surface \u2014 the CLI list (lines 637-651) has no `codecomm audit` verb, and the TUI's \"security reviews\" view (line 630) is not stated to be the audit log; (2) no definition of which events are auditable, so an implementer cannot populate the table; (3) no retention policy for captured human and agent activity beyond line 58-59's \"session-lifetime coordination history with export before compaction\" \u2014 no statement of how long an ended session's activity, rationale summaries, and file-path records persist, and no way to delete or further redact them after the fact; (4) uninstall is a release-gate test item (line 906) but the doc never says what uninstall removes \u2014 identity keys, `state.db`, the sidecar home, versioned file copies, or nothing; (5) with telemetry off by default (line 707) there is no support-bundle or diagnostics-export path, only `codecomm sync doctor` (line 647); (6) TUI accessibility is untreated \u2014 line 886-887 covers terminal widths, long IDs, and hostile control characters, but not NO_COLOR, color-blind-safe status encoding, or non-color-only state signalling, while line 632 requires six states be \"distinct\"; (7) licensing hits at lines 710, 760, and 878 are all *dependency* license review \u2014 CodeComm's own license and OSS-distribution posture is absent, which also matters for Open Question 5's proposal to bundle Syncthing binaries (line 958).",
    "why_it_matters": "Individually cheap, collectively these are the difference between a design that can be implemented and one where each implementer invents a different answer. The retention and uninstall gaps in particular are user-visible commitments about a tool that durably records everything a human and their agents did to a codebase.",
    "recommendation": "Add a short section covering: the enumerated set of audited actions plus `codecomm audit list|export` and an explicit statement that the audit log's tamper-evidence derives from the Raft chain and per-entry signature; a retention policy with a default window for ended-session activity and a `codecomm session purge` path; a normative statement of exactly what uninstall removes and what it deliberately leaves; a `codecomm support-bundle` that produces a redacted, user-reviewable diagnostics archive (reusing the line 908 redaction rule); a TUI accessibility requirement that all six states at line 632 are distinguishable without color, honoring NO_COLOR; and one line naming CodeComm's own license and how it interacts with the bundling choice in Open Question 5."
   }
  ]
 }
];

const PRIOR_VERIFIED_SUMMARY = [
 {
  "lens": "cold-reader",
  "severity": "major",
  "title": "No problem statement, motivation, or why-this-exists anywhere",
  "lines": "10-14, 39-56"
 },
 {
  "lens": "cold-reader",
  "severity": "major",
  "title": "Generated context is the primary agent-facing payload and its content is never specified",
  "lines": "394, 425, 467, 475"
 },
 {
  "lens": "cold-reader",
  "severity": "minor",
  "title": "No alternatives-considered section: Raft/Syncthing/mesh asserted, never defended",
  "lines": "20, 30-35, 133-144"
 },
 {
  "lens": "cold-reader",
  "severity": "minor",
  "title": "No glossary; 'eligible' has three meanings and 'epoch' is overloaded between trust generation and credential counter",
  "lines": "20, 26, 143, 197"
 },
 {
  "lens": "cold-reader",
  "severity": "minor",
  "title": "inbox/ is a second event-submission path with no stated authorization",
  "lines": "393, 426-427"
 },
 {
  "lens": "cold-reader",
  "severity": "minor",
  "title": "No end-to-end usage narrative",
  "lines": "635-651"
 },
 {
  "lens": "cold-reader",
  "severity": "minor",
  "title": "Line 6 claims a Product audience no section serves; no success metrics",
  "lines": "6, 911-946"
 },
 {
  "lens": "cold-reader",
  "severity": "minor",
  "title": "Voter assignment policy on join unspecified; 'odd preferred' is non-normative",
  "lines": "60-61, 133-137"
 },
 {
  "lens": "impl-readiness",
  "severity": "major",
  "title": "No event kind registry; canonical serialization and signature/digest primitives never named",
  "lines": "322, 346-347"
 },
 {
  "lens": "impl-readiness",
  "severity": "minor",
  "title": "No version floors at all (Go, Git, Syncthing, OS, Codex/Claude); line 726 is a literal placeholder",
  "lines": "719-730"
 },
 {
  "lens": "impl-readiness",
  "severity": "minor",
  "title": "Multicast group address and port appear nowhere; clock-skew allowance and disconnect grace period unvalued",
  "lines": "188-196, 444-445, 495"
 },
 {
  "lens": "impl-readiness",
  "severity": "minor",
  "title": "16 REST endpoints, one schema: no bodies, status codes, problem-type registry, or pagination params",
  "lines": "275-297"
 },
 {
  "lens": "impl-readiness",
  "severity": "minor",
  "title": "Local IPC: operation paths, error envelope, and resume-capability wire form unspecified",
  "lines": "458-475"
 },
 {
  "lens": "impl-readiness",
  "severity": "minor",
  "title": "outbox and replication_cursors have no stated contract",
  "lines": "403-417"
 },
 {
  "lens": "impl-readiness",
  "severity": "minor",
  "title": "Is worktree publication agent-invocable? Line 510 implies yes, no publish tool exists",
  "lines": "464-475, 510, 639"
 },
 {
  "lens": "impl-readiness",
  "severity": "minor",
  "title": "No configuration model; genesis 'protocol policy' contents never enumerated",
  "lines": "168-169, 401"
 },
 {
  "lens": "impl-readiness",
  "severity": "minor",
  "title": "No phase exit criteria, no named walking skeleton",
  "lines": "911-930"
 }
];

phase('Review')

const newLensWork = pipeline(
  LENSES,
  (lens) => agent(lens.prompt, { label: `review:${lens.key}`, phase: 'Review', schema: FINDINGS_SCHEMA, effort: 'high' }),
  (result, lens) => {
    if (!result || !result.findings || result.findings.length === 0) return { lens: lens.key, findings: [], verdicts: [] }
    return agent(
      `You are a SKEPTICAL verifier. Another reviewer produced findings about ${DOC} under the lens
"${lens.key}". Your job is to REFUTE them. Default to REJECTED when a finding is not clearly supported.

Read the document. Then for each finding:
1. If it claims something is MISSING: search the whole file for every relevant keyword and synonym.
   If the doc addresses it anywhere - even one terse clause in another section, a table row, an
   invariant, a risk, an ADR, or a test scenario - mark REJECTED and cite the covering line number.
2. If it claims something is WRONG or INSECURE: re-read the quoted text and decide whether the
   reviewer misread terse phrasing, and whether a competent implementer would actually be misled.
   If section 15 (Open Questions) or section 16 (Key Risks) already acknowledges it, that is usually
   WEAKENED-to-minor rather than CONFIRMED - unless the acknowledgement itself is the defect.
3. If it asserts an external technology fact, judge whether the fact is actually true. Reject
   confident but wrong assertions.
4. Judge severity honestly - reviewers inflate. A missing number for a "bounded" limit in a design
   doc is minor, not blocker. A design that cannot work as written is a blocker.
5. WEAKENED = the core observation is real but overstated; give the tightened version.

Be efficient: at most ~12 tool calls, then return verdicts.

Findings:
${JSON.stringify(result.findings, null, 2)}

One verdict per finding id. Invent nothing new.`,
      { label: `verify:${lens.key}`, phase: 'Verify', schema: VERDICT_SCHEMA, effort: 'high' }
    ).then((v) => ({ lens: lens.key, findings: result.findings, verdicts: (v && v.verdicts) || [] }))
  }
)

const catchUpWork = parallel(PRIOR_UNVERIFIED.map((job) => () =>
  agent(
    `You are a SKEPTICAL verifier. A previous reviewer produced findings about ${DOC} under the lens
"${job.lens}". These findings have NEVER been verified and several are rated "blocker". Your job is
to REFUTE them. Default to REJECTED when a finding is not clearly supported by the text.

Read the ENTIRE document first (~1010 lines). Then for each finding:
1. If it claims something is MISSING: search the file for every relevant keyword and synonym. If the
   doc addresses it anywhere - even one terse clause in another section, a table row, an invariant,
   a risk, an ADR, or a test scenario - mark REJECTED and cite the covering line number.
2. If it claims the design is WRONG, UNIMPLEMENTABLE, or INSECURE: this is where you must be
   hardest. Re-read the cited lines. Decide whether the reviewer misread terse phrasing or invented
   a constraint the doc never imposes. For any claim about what a third-party library's API permits
   (e.g. that hashicorp/raft or etcd/raft cannot expose a pre-commit log index to the proposer),
   judge whether that is actually true - and say so plainly if the reviewer is right, since a real
   feasibility defect is the most valuable finding in the review.
3. If section 15 (Open Questions) or section 16 (Key Risks) already acknowledges the issue, that is
   usually WEAKENED-to-minor rather than CONFIRMED - unless the acknowledgement itself is the defect.
4. Judge severity honestly - reviewers inflate. blocker means the design as written cannot work or
   is insecure, or implementation genuinely cannot safely start. A missing number for a "bounded"
   limit is minor.
5. WEAKENED = core observation real but overstated; give the tightened version.

Be efficient: at most ~18 tool calls, then return verdicts.

Findings to verify:
${JSON.stringify(job.findings, null, 2)}

One verdict per finding id. Invent nothing new.`,
    { label: `verify-prior:${job.lens}`, phase: 'Verify', schema: VERDICT_SCHEMA, effort: 'high' }
  ).then((v) => ({ lens: job.lens, findings: job.findings, verdicts: (v && v.verdicts) || [] }))
))

const [newResults, catchUpResults] = await Promise.all([newLensWork, catchUpWork])

const surviving = []
let rejected = 0
for (const r of [...newResults, ...catchUpResults].filter(Boolean)) {
  const byId = {}
  for (const v of r.verdicts || []) byId[v.id] = v
  for (const f of r.findings || []) {
    const v = byId[f.id]
    if (v && v.verdict === 'REJECTED') { rejected++; continue }
    surviving.push({
      ...f,
      lens: r.lens,
      verdict: v ? v.verdict : 'UNVERIFIED',
      severity: (v && v.corrected_severity) || f.severity,
      problem: (v && v.corrected_problem) || f.problem,
      recommendation: (v && v.corrected_recommendation) || f.recommendation,
      verifier_note: v ? v.reason : '',
    })
  }
}

log(`${surviving.length} findings survived verification; ${rejected} rejected`)

phase('Critic')

const allKnown = [...surviving.map((f) => ({ lens: f.lens, severity: f.severity, title: f.title, lines: f.lines })), ...PRIOR_VERIFIED_SUMMARY]

const critic = await agent(
  `You are a completeness critic. Read the design document at ${DOC} in full (~1010 lines).

Seven review lenses (security/crypto, distributed correctness, cold-reader clarity, implementation
readiness, internal consistency, external technology facts, simplicity-vs-best-practice) already
produced these findings:

${JSON.stringify(allKnown, null, 2)}

What did ALL of them miss? Consider: sections 2.2, 2.3, 9, 13 and 14 specifically, which got little
attention; the document's own structure and ordering; whether the stated invariants in 2.4 are
actually sufficient to guarantee the goals in 2.1; whether the Service Targets in 14 are measurable
and tied to anything; whether every 2.1 goal maps to a section that delivers it; whether anything in
the doc is unfalsifiable as written; and the single most important question the author has not asked
themselves about this project.

Be efficient: at most ~15 tool calls. Report only genuinely NEW findings not in the list above. It
is completely acceptable to return few or zero findings if coverage was good - say so rather than
padding.`,
  { label: 'critic:completeness', phase: 'Critic', schema: FINDINGS_SCHEMA, effort: 'high' }
)

const criticFindings = ((critic && critic.findings) || []).map((f) => ({ ...f, lens: 'completeness-critic', verdict: 'UNVERIFIED' }))

phase('Synthesize')

const forSynth = [...surviving, ...criticFindings]

const synth = await agent(
  `You are the lead reviewer writing the final verdict on the design document at ${DOC}.
Read the document yourself first so your synthesis is grounded. Be efficient: ~12 tool calls.

Findings verified in THIS pass (security/crypto, consistency, external-facts, plus catch-up
verification of distributed-correctness and simplicity-tradeoffs), plus new critic findings:

${JSON.stringify(forSynth, null, 2)}

Findings verified in an EARLIER pass (cold-reader and implementation-readiness lenses), already
post-verification, which you must fold into the same ranking:

${JSON.stringify(PRIOR_VERIFIED_SUMMARY, null, 2)}

Produce a synthesis:
1. Deduplicate and merge aggressively - one entry per real underlying issue, even when several
   lenses saw it. Note which lenses converged on it.
2. Rank by what would actually hurt the project most, not by lens or severity label.
3. Split into: must-fix before an implementation plan; should-fix in the doc; author's judgement call.
4. Answer three questions decisively:
   - Is the doc self-contained (describes what the project is with no other context)? Yes/No/Partly,
     plus the single biggest gap.
   - Is it correct and secure as written? Name the most serious technical defect.
   - Is it sufficient to move to an implementation plan? Yes/No/Yes-with-caveats, plus specific
     prerequisites.
5. Call out what the document does UNUSUALLY WELL - specific and honest, not flattery.
6. Give the shortest ordered list of concrete edits that moves this doc to implementation-ready.

Be direct and technical. No hedging, no filler.`,
  {
    label: 'synthesize',
    phase: 'Synthesize',
    effort: 'high',
    schema: {
      type: 'object',
      properties: {
        must_fix: { type: 'array', items: { type: 'object', properties: {
          title: { type: 'string' }, lines: { type: 'string' }, problem: { type: 'string' },
          why_it_matters: { type: 'string' }, fix: { type: 'string' },
          lenses: { type: 'array', items: { type: 'string' } } },
          required: ['title', 'lines', 'problem', 'why_it_matters', 'fix'] } },
        should_fix: { type: 'array', items: { type: 'object', properties: {
          title: { type: 'string' }, lines: { type: 'string' }, problem: { type: 'string' },
          fix: { type: 'string' } }, required: ['title', 'lines', 'problem', 'fix'] } },
        judgement_calls: { type: 'array', items: { type: 'object', properties: {
          title: { type: 'string' }, lines: { type: 'string' }, note: { type: 'string' } },
          required: ['title', 'note'] } },
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

return { stats: { surviving: surviving.length, rejected, critic_new: criticFindings.length }, synthesis: synth, all_findings: forSynth }
