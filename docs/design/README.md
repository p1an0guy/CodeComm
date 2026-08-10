# CodeComm V1 Design — Reading Guide

The accepted revision 0.14 design is split into 14 authoritative, independently reviewable parts.
It originated in the archived revision 0.10 monolith and is maintained only here. Section numbers are
preserved, so every `§x.y` cross-reference resolves through this map. `docs/design.md` is now only a
pointer; the frozen monolith is `docs/archive/design-rev-0.10.md`.

## Section map

| Part | File | Sections | Lines |
|---|---|---|---|
| 00 | [Overview, Problem, and Scope](00-overview-and-scope.md) | Front matter, §1, §1.1–1.2, §2, §2.1–2.5 | 321 |
| 01 | [Architecture and Consensus](01-architecture-and-consensus.md) | §3, §3.1–3.3 | 425 |
| 02 | [Identity, Discovery, and Pairing](02-identity-and-pairing.md) | §4, §4.1–4.5 | 444 |
| 03 | [Transport Credentials](03-transport-credentials.md) | §4.6 | 261 |
| 04 | [Control Protocol and Event Model](04-control-protocol-and-events.md) | §5, §5.1–5.6, §5.2.1 | 799 |
| 05 | [Persistence and Coordination Semantics](05-persistence-and-coordination.md) | §6, §6.1–6.4 | 581 |
| 06 | [Agent Sessions and MCP Integration](06-agents-and-mcp.md) | §7, §7.1–7.3 | 392 |
| 07 | [Repository Synchronization](07-git-synchronization.md) | §8, §8.1–8.4 | 467 |
| 08 | [UX, Lifecycle, and Failure Behavior](08-ux-lifecycle-and-failures.md) | §9 | 227 |
| 09 | [Security and Privacy](09-security-and-privacy.md) | §10, §10.1 | 205 |
| 10 | [Implementation, Versions, and Constants](10-implementation-and-constants.md) | §11, §11.1–11.2 | 227 |
| 11 | [Regression and Test Strategy](11-test-strategy.md) | §12, §12.1–12.5 | 813 |
| 12 | [Delivery, Targets, Open Questions, Risks](12-delivery-targets-and-open-questions.md) | §13, §14, §15, §16 | 191 |
| 13 | [ADR Backlog and References](13-adr-backlog-and-references.md) | §17, §18 | 363 |

## Where to find a section

§1 → 00 · §2 → 00 · §3 → 01 · §4.1–4.5 → 02 · §4.6 → 03 · §5 → 04 · §6 → 05 · §7 → 06 ·
§8 → 07 · §9 → 08 · §10 → 09 · §11 → 10 · §12 → 11 · §13–16 → 12 · §17–18 → 13

## Reading order by audience

**Product / approval:** 00, then 12 (§15 open questions, §16 risks). Approving the design means
approving these two.

**Security review:** 02 → 03 → 09, then 07 (repository data plane) and 06 (agent surface).
Part 03 is the highest-risk single document.

**Implementation:** 04 → 05 are the normative protocol core and should be frozen first; 10 holds
the constants both depend on.

**Consensus correctness:** 01 → 03 → 04. Voter reconciliation (01) and credential authorization
(03) are coupled through quorum; read them together.

## Load-bearing cross-part couplings

These pairs cannot be reviewed in isolation:

- **01 ↔ 03** — voter-set reconciliation defers while any post-change quorum voter lacks a content
  credential; consensus eligibility derives from the live Raft configuration that 01 reconciles,
  while access derives from applied membership.
- **04 ↔ 05** — §5.4's event kinds and §6.1's entities must agree field-for-field; §5.6's
  digest coverage list must match §6.2's table list.
- **04 ↔ 10** — §5's committed policy values are enumerated in §11.2.
- **07 ↔ 06** — publication (§7.2) is the mechanism by which agent work reaches the canonical
  ref (§8).
- **11 → all** — §12.2's coverage list cites nearly every other part; changes elsewhere
  invalidate entries here.

## Status

Revision 0.14 is accepted for implementation. Owner: `ijonahch`; this solo project uses part 00's
written self-review gate. Superseded decisions remain annotated in §17. The revision 0.10 monolith is
archived for history and is non-authoritative.
