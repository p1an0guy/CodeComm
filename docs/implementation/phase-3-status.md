# Phase 3 Status

Status: in progress; secure daemon mesh, discovery, pairing admission/rebootstrap, content
credentials, endpoint and proposal relay, voter reconciliation, and revocation are
production-composed; Phase 3 exit gate remains open
Last updated: 2026-09-02
Scope: secure mesh in `docs/IMPLEMENTATION.md` §4 and design §13.

## Completed

- Discovery datagrams, bounded receiver state, selected-interface multicast I/O, endpoint-set
  signing/cache rules, pairing wire protocol, exporter-bound HTTP/2 pairing service, identity and
  content certificate profiles, ALPN isolation, admission limits, and native pairing persistence
  are implemented and unit/integration tested.
- The non-expiring identity-mTLS consensus plane carries unmodified HashiCorp Raft framing over
  RFC 8441. Admission uses applied membership; replication uses live configuration. Certificate,
  session, generation, expected-peer, route, and control-mode mismatches fail closed.
- Three real voters elect, replicate, recover after cold restart, reject divergent state, and
  preserve exact SQLite/Raft commitments. The mesh harness can sever established connections, not
  only future dials.
- Canonical-coverage receipt contracts and the no-bypass configuration gate are implemented.
  Verified fixture providers permit integration changes; an absent production Git provider blocks
  changes.
- Voter reconciliation implements staged nonvoters, exact checkpoint proofs, promotion, signed
  target activation and authority handoff, leadership transfer, revoked/unreachable-first removal,
  crash resumption, and status reporting.
- A committed isolated-minority test proves it cannot apply a proposal, authorize a credential,
  reconcile or self-promote, while the majority commits and both sides converge after healing.
- Human-only durable commands and CLI surfaces implement `cluster set-voters` and `peer revoke`.
  Both retain reviewed CAS values, sign through the boot-scoped operator origin, survive restart,
  and are reducer-authorized. Revocation resolves its subject through an exact committed-member
  query, including retained devices outside the bounded status roster.
- `codecommd` now opens a device-addressed mesh node, issues its generation-bound identity
  certificate, binds selected non-loopback listeners, uses selected-source static routes, serves
  authenticated consensus ingress, and owns peer/local/worker shutdown as one lifecycle.
- Selected-interface discovery, raw-hint persistence, signed endpoint publication/relay,
  authenticated-destination retention, expiry, rollback refusal, and route reconciliation are
  composed. Multicast loss degrades and retries without disabling manual routes, pairing, or
  content; committed cadence changes update the running service and signed-set TTL.
- Invite create/list/revoke, exporter-bound pairing ingress, durable proof/SAS state, local
  confirmation, admission finalization, and restart recovery are composed. CLI confirmations bind
  the complete immutable review subject and explicit declines are durable. Durable invite/attempt
  history is capped at 256 entries with deterministic oldest-first pruning that preserves active,
  finalizing, and pending-secret-deletion rows.
- `codecomm join --state ABSOLUTE_PATH` now completes fresh-device pairing, committed-membership
  proof, credential authorization, and verified settled-nonvoter snapshot installation. It follows
  identity-signed leader redirects when an invite comes from a follower, pins lineage/member/
  signer/credential cuts, and reopens the installed store before deleting its journal. A durable
  nonsecret journal, native key storage, process lock, destination-ownership phase, and exact
  baseline verification make every post-approval boundary retryable or fail closed; approval alone
  never implies admission. Invite and confirmation input is bounded, cancellable, and no-echo where
  secret. Windows rejects remote/reparse-backed state and untrusted DACLs and flushes directory
  metadata where supported.
- Join and daemon startup now contend on the same owner-only `<state>.join.lock`. The daemon acquires
  it before opening identity or workspace state and retains it through shutdown; contention reports
  a best-effort holder PID and clean shutdown clears it. The OS lock is authoritative after a crash;
  stale metadata cannot block recovery through PID reuse. Unix and Windows reject unsafe
  files/volumes and hard-linked SQLite aliases; cross-process tests retain interoperability with the
  prior lock primitives.
- Targeted `rebootstrap` retains the exact installation identity, skips a second admission, requires
  an unused destination, and abandons an ambiguous post-confirmation resume in favor of a fresh
  invite. Snapshot installation atomically writes a local crash gate bound to lineage, retained
  device, snapshot attestation, and installation time; join completion requires that exact marker,
  while `new` and `readmission` reject one.
- Settled startup validates the rebootstrap marker, withholds ingress/IPC until direct exact-cut
  observations from every current credential authority make replica currency `current`, then
  synchronously commits `agent.session.ended(crash_reap)` for every imported nonterminal session
  owned by the retained device. Before marker clear it fences all imports, revalidates `current`,
  and rescans; a tail arriving after the first reap forces another cycle. Multi-session interruption
  and authority-committed commands awaiting local import survive SQLite reopen. Snapshot fallback
  atomically rebinds the gate to the newer verified attestation; later membership changes do not
  prevent exact marker clear before ordinary recovery.
- `readmission` join accepts an unused destination or a verified predecessor workspace exactly one
  recovery generation behind. A verified successor snapshot may replace a legitimate Raft
  predecessor only across that generation transition; same-generation Raft-to-settled conversion
  fails closed.
- Production readmission coverage synthesizes only the Phase 6 recovery command's successor
  payload, proves it through the generation-zero and successor-boundary verifiers, then exercises
  real TLS/SAS pairing, conditional admission, credential authorization, snapshot transfer,
  Raft-predecessor replacement, settled startup, and reopen with the retained identity. This
  production predecessor has no post-initial commands; a separate verified-install test covers a
  nonempty Raft command ledger.
- Quorum clock endorsement, leader authorization/forwarding, protected epoch-key storage,
  make-before-break certificate selection, renewal retry, content mTLS, `/v1/session`, `/v1/peers`,
  and direct endpoint-set exchange are composed. Applied revocation closes established access,
  rejects fresh access, purges learned routes, and erases local epoch keys. Authenticated inbound
  and outbound consensus connectivity plus selected-interface changes interrupt bounded renewal
  backoff; failed or unauthenticated attempts do not.
- Content mTLS now serves strict `POST /v1/events`. Followers forward byte-identical signed
  proposals once to their observed active leader; leader ingress is independently rate-limited per
  signed origin, explicit hop metadata prevents recursive forwarding, delayed local Raft apply
  cannot trigger hot re-forwarding, and each six-field response is compared with the exact local
  result/event-chain positions after replication. Disconnect, GOAWAY, rollover, draining, and
  capacity failures remain retryable without weakening malformed-response checks; explicit
  per-connection graceful shutdown sends GOAWAY even after response headers flush, lets the final
  active response finish, and prevents a superseded connection from occupying an idle ingress slot.
- The six-field command-result record now has a strict canonical decoder. Immutable result-batch
  values bind every envelope field under `codecomm/v1/batch`, verify both dense chains and signer
  identity, and enforce the 256-record/64 MiB expanded limits. SQLite exports bounded ranges only
  after replaying the retained generation, checks both starting and ending heads in one snapshot,
  and reconstructs the credential authority at the exact end position. Strict
  `GET /v1/replication?after_result=M` serving signs only pages ending where the server identity is
  both active and authorized, returns `snapshot_required` when a bounded page cannot reach such a
  cut, and streams under a single global large-response slot. The client preserves direct or
  relayed signed bytes; signer-key and active-authority trust is intentionally deferred until
  scratch replay reaches the batch end.
- Settled nonvoters now have an explicit evidence mode and a Raft-free runtime owner. Receiver
  scratch replay verifies origin signatures, deterministic accepted/rejected outcomes, projection
  mutations, both chains, the accumulator, terminal authority, and the batch signature before one
  atomic import. Imports retain contiguous signed attestations and per-relay cursors, rebuild local
  activity/audit/checkpoint/lease rows, publish admission only after commit, survive reopen, and
  never create event/Raft provenance or advance the frozen Raft watermark. Transaction failpoints,
  cancellation, coherent projection-history tampering, failed replay, relayed-signer separation,
  and race tests preserve both cursors and the complete prior cut. Signed starting/ending
  accumulator and full-state digests bind durable projection evidence, and startup revalidates the
  pre-transition Raft ledger. Each fetch revalidates local evidence before comparing the remote
  lineage; coherent local rewrites latch fatal state, revoke already-issued local-state
  capabilities, and stop admission/writes. Transient store failures remain retryable and scratch
  replay observes cancellation between bounded records. Identity-signed equal-cursor
  acknowledgements bind the complete verified cut, persist separately from contiguous batch
  attestations, and are reverified on reopen. Durable observations can prove `behind`, but only
  exact-cut observations received directly from their authenticated signer establish `current`;
  relayed signatures are historical evidence only, and disconnect or restart returns currency to
  `unknown`.
- Daemon startup now selects Raft or settled mode from verified durable evidence. A settled daemon
  opens no Raft state, renews credentials over identity mTLS, keeps content links alive at equal
  cursors, forwards local and initial-hop proposals to current authority peers, imports bounded
  signed tails through one serialized gate, and exposes status plus durable owner mutations through
  local IPC. Mutations queue while authority is unavailable and resolve only after their exact
  signed result imports. Status labels live topology and reconciliation unknown rather than
  presenting the frozen pre-transition Raft configuration as current; replica currency remains
  unknown without direct live exact-cut observations from the complete current authority.
- Late-wake content bootstrap validates identity-plane status with the same captured credential
  clock used for certificate selection and verification. The provisional authorization remains
  peer-pinned and outbound-only; ingress still requires applied membership and authorization.
- Logical-snapshot roots, descriptor-page chains, record framing, semantic payload codecs, and the
  streaming record-order validator are implemented. The validator checks complete successor
  genesis lineage, both chains, accepted-event identity, projection accumulator/state, and the
  terminal signed checkpoint. Result mutations use deterministic 2 MiB continuation records, so
  valid encodings above the 4 MiB chunk ceiling remain representable without a history-sized
  allocation. This structural pass deliberately does not replace the import layer's authority,
  signature, or deterministic reducer-replay checks. Identity artifact construction greedily
  streams record-aligned bounded chunks to a caller-owned sink while committing exact byte totals,
  record/chunk counts, and artifact/chunk SHA-256 digests. Store export now verifies the selected
  current checkpoint, exact Raft or settled evidence, signer authority, complete history, and full
  projection state from one stable read cut. Historical state reconstruction uses file-backed
  SQLite temporary storage rather than a history-sized Go allocation. The composition layer spools
  the exact expanded artifact, builds bounded descriptor pages, semantically replays the spool, and
  invokes the identity signer only after every structural commitment passes.
- Content mTLS serves exact canonical snapshot roots and descriptor pages plus immutable binary
  chunks under lineage-and-artifact-scoped routes. Clients enforce canonical targets, media types,
  declared and actual lengths, root/page/chunk bounds, artifact continuity, structured errors, and
  separate bulk-connection capacity. Roots and descriptor pages share the control-plane global
  large-response slot with replication; chunks use independently bounded bulk connection/stream
  capacity. A fresh connection serializes role registration before reauthorization, so concurrent
  bulk streams cannot bypass the one-stream gate.
- Snapshot receive is two-pass and file-backed. The first pass authenticates the descriptor chain,
  chunks, expanded bytes, record order, and root commitments before trusted boundary policy runs.
  The second verifies genesis/recovery boundaries, origin and checkpoint signatures, frozen-reducer
  outcomes, exact mutations, both chains, accumulators, and projection state while rebuilding a new
  SQLite quarantine one bounded command transaction at a time. Failed stages are closed and removed;
  a successful stage is immutable and root-bound.
- A verified quarantine can atomically initialize or forward-replace a destination and enter
  settled-nonvoter mode without inventing Raft provenance. Installation rechecks source and
  destination history, signed checkpoints, derived views, control decisions, local audit bindings,
  recovery lineage, lease reconstruction, and foreign keys; it preserves only verified predecessor
  attestations and stable recovery observation times. Explicit scrub/export and replacement
  revalidate every historical snapshot/batch signature, checkpoint, signer identity and authority
  transition, immutable head/accumulator endpoint, state-digest continuity, range, and inventory;
  bounded startup revalidates the active evidence chain and current commitment tip. Orphaned,
  duplicate, altered, or cross-lineage evidence fails closed.
- Initialization and valid generation-zero legacy upgrades retain the exact genesis projection
  baseline before any non-invertible recovery; an already-recovered legacy store lacking it refuses
  migration transactionally. Migration checksums bind SQL plus each versioned Go hook's identity and
  CI-verified source fingerprint; future migrations require an explicit reversibility classification
  or verified backup gate. Snapshot repositories and caches use trusted-root operations that reject
  links/reparse points in every managed path component and keep cleanup contained under races,
  including runtime Windows-junction coverage. They enforce owner-only directories, fsync inventory
  changes, cap artifacts at 256 MiB/4,096 chunks/one page, bound builds to five minutes, and check
  cleanup capacity before forcing another checkpoint.
- Settled catch-up automatically handles `snapshot_required`: it fetches an authority-valid latest
  root over control mTLS, resumes root-bound pages/chunks from a bounded durable cache, verifies and
  installs the quarantine, then continues the contiguous signed tail. A five-device production
  composition covers authority replacement, stale-cursor fallback, post-snapshot tail import, and
  cold restart.
- Raft `InstallSnapshot` now carries the same signed logical state in a metadata-bound frame.
  Receivers verify and stage it before atomically replacing SQLite, retain exact local install
  provenance without fabricating per-command bindings, resume post-snapshot replication, survive
  restart, and become promotion-eligible. Finalized-but-unbound inbound files are quarantined on
  startup; exact retries rebind only identical evidence. Ineligible signers and already-compacted
  baselines decline snapshot creation without halting the FSM.
- Production-composition tests start three daemons through `runDaemon`, form a real TCP/mTLS
  cluster, establish and relay content state, rotate all credentials from epoch 1 to 2 under active
  HTTP/2 traffic, submit a task through a captured follower, complete two-sided SAS admission,
  authorize the admitted member's content credential, revoke it through local operator IPC, verify
  established and fresh content denial without target/authority drift, and restart a follower.
  They then stop every voter past expiry, prove one awake voter elects and authorizes nothing, prove
  two voters restore quorum and epoch 3, catch up the third, restore content traffic, re-open every
  store, and verify commitment history. The same production path rebootstraps an active retained
  nonvoter through owner-targeted SAS pairing, commits a second retained-device session after the
  installed snapshot, then proves the stale tail reaches exact current currency and both sessions
  are durably crash-reaped before IPC. It also proves no second admission or membership-version
  drift, clears the marker, and creates no Raft state.
- The settled production path now also runs the documented two-device mode after a 3-to-1 authority
  handoff. With the sole voter offline and both content credentials expired, the owner nonvoter
  remains readable, exposes no leader or strong-write authority, and durably queues a reviewed
  revocation. Returning the voter renews both peers over identity mTLS, commits the command,
  preserves voter-target and authority version while revoking the active nonvoter, imports the
  exact signed result, resolves the outbox, restores content, and converges a subsequent task.
- Fresh two-device admission prompts the inviter to keep the current voter, move the sole-voter
  target to the joined device, or defer. The prompt recommends the device likelier to remain awake,
  states the exact degraded consequence, and binds a move to a fresh voter-set CAS. The guided
  `cluster set-voters` fallback is independently callable, and every TUI status with fewer than
  three known live or durable target voters carries the persistent no-loss-tolerated warning.
- `peer endpoint add|list|remove` manages bounded device-local literal routes over owner-only IPC.
  Add requires an active expected peer, all mutations preserve source isolation and fail closed on
  malformed/cap-exceeding state, and each successful change immediately reconciles the live route
  table and triggers reconnect recovery. Peer identity remains pinned before application traffic.
- Operator status reports multicast as disabled, locally available, or degraded, with selected
  addresses and the manual-endpoint count. Degraded errors are bounded and control-free; the TUI
  names `peer endpoint add` as the recovery action without weakening peer authentication.
- Selected-interface identity now survives DHCP/VPN address churn. A two-second reconciler
  re-resolves address slots, atomically replaces listener generations, withdraws stale endpoint
  sets before route work, closes inbound and outbound connections bound to removed generations,
  remaps explicit manual sources, limits multicast to listener-backed families, and immediately
  re-advertises. Total address or bind loss leaves no published endpoint, selected route, or stale
  multicast delegate; unchanged refresh recovers an exhausted listener and later address return.
- CI runs the security-critical mesh tests in-process with cross-package coverage and enforces a
  45% `consensus` + `transport` floor. The ordinary Linux/macOS/Windows and race jobs retain the
  subprocess and daemon-composition tests.

## Open Exit Gates

- Fresh `new`, identity-preserving `rebootstrap`, and post-recovery `readmission` joins are
  production-composed. Readmission is covered from a verifier-approved synthesized successor;
  production `codecomm cluster recover-quorum` and its full recovery/readmission E2E belong to
  Phase 6 and are not Phase 3 exit requirements.
- Result export, serving, scratch replay/import, terminal authority authorization, durable batch
  evidence, mode-aware startup, and peer fetch/catch-up orchestration are implemented.
  Snapshot artifact transport, two-pass quarantine replay, and standalone settled installation are
  implemented, including automatic fallback selection and tail resumption. Removal needs the
  reciprocal verified freeze before restarting in settled mode; it may not relabel imported
  results as local Raft provenance.
- Phase boundary, not a Phase 3 gate: Phase 4 supplies the production local-Git
  canonical-coverage provider. Phase 3 requires verified fixture repositories and fail-closed
  production behavior; without that provider, voter changes stop at `object-coverage-degraded`.
- Multi-activation catch-up, SSE, divergence recovery, and the remaining Phase 3
  fault/performance matrix are outstanding. Final §14 benchmark confirmation remains a Phase 6
  exit gate.

Phase 3 exit requires its secure-mesh paths to be production-composed, the canonical-coverage gate
to be proven with verified fixture repositories and fail closed in production, and committed proof
that a minority commits nothing, self-promotes nothing, and authorizes no credential. The Phase 4
production local-Git provider and Phase 6 quorum recovery are not exit requirements. The Phase 3
test gaps above remain open.

## Evidence

Primary tests:

- `TestDaemonProductionMeshComposition`
- `TestDaemonProductionReadmissionComposition`
- `TestDecisionApprovedResumeRequiresCommittedAdmission`
- `TestDecisionApprovedRebootstrapResumeRequiresFreshInvite`
- `TestOpenJoinDestinationRecordsExclusiveOwnershipBeforeReuse`
- `TestJoinLockExcludesAnotherProcessHandle`
- `TestJoinerRealTLSPairingHTTPFlow`
- `TestReadmissionDestinationRequiresExactPredecessorLineage`
- `TestJoinCompletionRequiresModeSpecificRebootstrapMarker`
- `TestCrashReapEndsAllImportedSessionsBeforeRecovery`
- `TestCrashReapResumesPartialMultiSessionWorkAfterRestart`
- `TestInspectDaemonRebootstrapInstallBindsLineageAndDevice`
- `TestRebootstrapRecoveryWaitsForCurrentReplica`
- `TestRecoverSettledAgentStateRetriesEveryCrashBoundary`
- `TestRecoverSettledAgentStateResumesPartialMultiSessionCrashReap`
- `TestRecoverSettledAgentStateRefreshesSnapshotFallbackMarker`
- `TestRecoverSettledAgentStateRejectsInvalidFinalMarker`
- `TestRecoverSettledAgentStateReapsTailArrivingBeforeFence`
- `TestDaemonSettledReplicationFenceExcludesImportPass`
- `TestJoinAndWorkspaceLockMutuallyExclude`
- `TestAcquireReclaimsLockAfterOwnerProcessDies`
- `TestAcquireInteroperatesWithLegacyOwnerProcess`
- `TestLegacyUnixLockInteroperability` / `TestLegacyWindowsLockInteroperability`
- `TestOpenRejectsHardLinkedDatabase`
- `TestDaemonGracefulShutdownClosesConsensusAndLocalWorkers`
- `TestVerifiedLogicalSnapshotStageAtomicallyMarksRebootstrap`
- `TestVerifiedLogicalSnapshotStageRejectsRebootstrapForAuthority`
- `TestVerifiedLogicalSnapshotStageInstallsSuccessorOverRaftPredecessor`
- `TestVerifiedLogicalSnapshotStageRejectsSameGenerationRaftConversion`
- `TestRebootstrapInstallMarkerClearRequiresExactBinding`
- `TestRebootstrapInstallMarkerRejectsCorrelatedStateCorruption`
- `TestRebootstrapInstallMarkerCanClearAfterMembershipChanges`
- `TestInstallStandaloneLogicalSnapshotPreservesRebootstrapMarker`
- `TestMigration0009AddsEmptyRebootstrapCrashGate`
- `TestSecureThreeVoterConsensusMesh`
- `TestSecureThreeVoterColdCommitRecovery`
- `TestSecureMeshCompactedSnapshotCatchupAndPromotion`
- `TestSecureMeshVoterReconciliationTransitions`
- `TestSecureMeshIsolatedMinorityCannotEscalate`
- `TestSecureMeshFollowerForwardsOnlyToObservedLeader`
- `TestSecureMeshTopologyPartitionClosesEstablishedConnections`
- `TestOpenNodeUsesInjectedDeviceAddressedTransport`
- `TestInspectDaemonMeshState*`
- `TestSettledReplicaImportsAndReopensAuthorityHandoff`
- `TestSettledReplicaCoherentLocalRewriteLatchesFatalState`
- `TestDaemonSettledAutomaticLogicalSnapshotFallbackPersistsAcrossRestart`
- `TestDaemonSettledNonvoterReplicatesAcrossAuthorityHandoffAndRestart`
- `TestDaemonContentPeerBootstrapInstallsAuthorityVerifiedLaterEpoch`
- `TestGuidedVoterPlacementBindsChoiceToFreshCAS`
- `TestGuidedVoterPlacementRequiresOwnerAndStableTwoDeviceTopology`
- `TestPeerInviteCLIEndToEnd`
- `TestPeerEndpointCLIAddListFilterAndRemoveJSON`
- `TestOperatorClientManagesManualEndpoints`
- `TestDaemonDiscoveryManualEndpointChangeReconcilesRoutesImmediately`
- `TestDaemonDiscoveryRefreshRebindsAndWithdrawsOnInterfaceLoss`
- `TestDaemonDiscoveryRefreshBindFailureWithdrawsUntilRecovery`
- `TestDaemonDiscoveryRefreshRebindsSameAddressAfterInterfaceReplacement`
- `TestDaemonPeerListenerSet*`
- `TestConsensusRouteTableSelectedAddressRefreshClosesTrackedConnections`
- `TestIngressClosesOnlyConnectionsBoundToVanishedAddress`
- `TestOpenSelectedMulticastJoinsOnlyListenerFamilies`
- `TestManualEndpointManagementFailsClosedOnCorruption`
- `TestOperatorStatusIncludesLocalNetworkState`
- `TestDaemonOperatorStatusSourceReportsNetworkModes`
- `TestModelRendersMulticastDegradedRecoveryAction`
- `TestSnapshotClientRoundTripBindsRootAndArtifact`
- `TestVerifyAndStageLogicalSnapshotReplaysRealReducerHistory`
- `TestInstallStandaloneLogicalSnapshotSuccessorPreservesPredecessorAttestationPrefix`
- `TestFSMSemanticRaftSnapshotCaptureAndRestoreUsesCommandWatermark`

Run:

```text
go test -p 2 -parallel 2 -timeout 20m ./...
go test -race -p 1 -parallel 2 -timeout 20m ./...
go vet ./...
go run honnef.co/go/tools/cmd/staticcheck@v0.7.0 ./...
```

## Self-Review

1. **Consensus safety:** bootstrap is allowed only before any committed configuration or applied
   Raft entry. Mature voters and nonvoters reopen from durable state; minority operations fail
   without changing logs, projections, authority, or configuration.
2. **Revocation:** authorization reads applied membership, never lagging configuration. Revocation
   commits the exact resulting target and CAS values; reconciliation prioritizes revoked voters.
3. **Key handling:** identity private keys remain native-store-owned, are cloned only into bounded
   signer/TLS owners, and temporary copies are cleared. TLS 1.3 disables resumption and cross-plane
   certificate use.
4. **Bounds:** routes, listeners, connections, streams, bodies, headers, sources, nonces, retries,
   and status views retain explicit ceilings. Unknown routes, peers, capabilities, and unavailable
   providers fail closed.
5. **Recovery interruption:** exact-current authority observations precede rebootstrap cleanup; the
   import fence plus marker contract keep sessions inaccessible until every crash reap commits.
   Crashes during multi-session reap, before clear, or before ordinary recovery retry the gate.
6. **Coverage:** real Raft, SQLite, TCP, mTLS, HTTP/2, process restart, live connection loss,
   revocation, reconciliation, minority behavior, and production-composed rebootstrap are exercised
   without mocking their behavior. Full production quorum-recovery/readmission E2E is deferred to
   Phase 6.
