# CodeComm V1 Design — Part 04: Transport Credentials

Part 4 of 14. Contents: §4.6 Transport credentials — the identity-authenticated consensus plane
and the quorum-authorized epoch-credential content plane.
Section map, review status, and reading order: [README.md](README.md)

Authoritative revision 0.14; maintained only in this split set.

Normative terms follow RFC 2119/8174; declarative requirements and table rows headed "MUST" or
"Required" are equally normative.

---

### 4.6 Transport credentials

CodeComm has two member network planes, authenticated differently and deliberately so. Both are TLS
1.3 mTLS on one selected port; an exact ALPN selects the certificate profile before HTTP or Raft
bytes exist. TLS 1.3 0-RTT and PSK/session-ticket resumption are disabled in V1: every connection
performs a full certificate handshake and reruns current membership, generation, and epoch
admission. A resumed TLS session MUST NOT outlive revocation or credential expiry.

| Plane | ALPN | Carries | Authenticated by | Expiry |
|---|---|---|---|---|
| **Consensus** | `codecomm-consensus/1` | Raft election, replication, and snapshots; `POST /v1/credentials/{renew,endorse}`, `POST /v1/consensus/prove`, and `GET /v1/consensus/status` only | Committed long-lived **device identity** key (§4.1) | None; revocation is the only removal |
| **Content** | `codecomm-content/1` | REST/SSE, Git/object artifacts, bootstrap, presence, acks, conflicts, and every agent-facing network surface | **Quorum-authorized ephemeral epoch** key | Fixed 1800 s (30 min) |

Pairing is a pre-membership admission surface on `codecomm-pairing/1`, with the pinned inviter and
invite proof of §4.5; it reaches only `POST /v1/pairing/{request,confirm}`. A client MUST offer
exactly one CodeComm ALPN. The server chooses the matching certificate before application dispatch
and rejects multiple, absent, or cross-profile offers. Distinct ALPNs are required: with one ALPN a
server cannot know during the TLS handshake whether to present its identity or epoch certificate.
The listener obtains the current local content certificate from a concurrency-safe provider on every
content handshake. A missing, expired, or invalid content key rejects that handshake only; pairing
and consensus remain available so renewal never depends on a current content credential.

Before certificate parsing or pairing allocation, one source-IP-keyed limiter enforces §11.2's
attempt, pending-handshake, tracked-source, idle-expiry, and aggregate-byte ceilings across all three
ALPNs. Its bounded entries contain only rate state; live handshakes occupy the separate global
semaphore. At capacity the daemon expires idle entries, then evicts the oldest idle source, otherwise
silently drops the excess attempt. It never allocates an unbounded wait queue or logs per attempt.

**Why the consensus plane does not expire.** A consensus channel whose authentication can
expire cannot recover itself. If every device sleeps past its credential lifetime, no
authenticated path remains on which to elect a leader and authorize replacement
credentials — the cluster deadlocks precisely when it is least able to ask an operator for
help. V1 previously answered this with a second restricted listener that re-authenticated
long-lived identities to bootstrap an election; ADR-039 records why that was collapsed
rather than patched. If long-lived identity is going to authenticate consensus in the
deadlock case anyway, having it authenticate consensus *always* removes a listener, an
ALPN, a closed dispatcher, a pre-election data-confinement argument, a snapshot-transfer
carve-out, and two whole classes of defect — with no change to what stops a revoked device,
because expiry was never what stopped it (§3).

**Why the content plane does expire.** Repository bytes and ordinary coordination APIs flow here;
settled nonvoters also catch up through signed event batches and snapshots here. Voters and staging
nonvoters receive coordination events and logical snapshots through guarded Raft replication on the
consensus plane, but that is not an ordinary content API: only the current applied leader sends it,
and only to its live configuration. A peer that never observes a revocation — a device partitioned
away when an owner revokes a member — stops serving that member content within 1800 s plus the 120 s
verifier skew. On consensus, expiry would buy little: a replica that does not hold the committed
revocation is below quorum; one that holds it must apply it before an elected leader can replicate.
A follower serves no state, and neither case can authorize a content credential for the revoked
member.

**What expiry does not replace.** Informed peers enforce revocation immediately at **connection
admission against applied application membership**, on both planes, as a local check needing no
leader or reconciliation (§3). Content expiry is only the bounded backstop when a serving peer has
not applied the revocation; it grants no consensus authority.

#### Consensus-plane authentication

Each side presents a self-signed certificate whose SPKI is the enrolled Ed25519 identity key
from which `device_id` derives (§4.1), and whose one critical CodeComm extension binds
`session_id`, `recovery_generation`, and `device_id`. Verification pins that exact key to
locally committed membership and rejects a device its applied membership shows as revoked, a
mismatched `session_id` or `recovery_generation`, Web PKI roots, and any certificate carrying
the content-plane extension. The fixed profile uses a positive random serial, Ed25519 signature,
digital-signature key usage, client/server-auth EKUs, no unknown critical extension, and
`notBefore = 1970-01-01T00:00:00Z`, `notAfter = 9999-12-31T23:59:59Z`. The custom pinned verifier
checks the self-signature and profile but deliberately grants no authority to X.509 time validity;
the wide interval only prevents an accidental generic-stack expiry. Phase 1 verifies that the
chosen Go TLS/X.509 path parses this interval on every supported OS. The TLS 1.3 handshake proves
fresh possession of the identity private key, so no additional nonce exchange is required.

The custom extensions are fixed DER, not implementation-selected JSON or ASN.1. Their protocol-fixed
OIDs encode the corresponding UUID as eight unsigned 16-bit arcs below `2.25.0`:

```text
id-codecomm-identity = 2.25.0.26471.65027.42495.17119.33263.9253.31782.62832
                       (words of UUID 6767fe03-a5ff-42df-81ef-24257c26f570)
id-codecomm-content  = 2.25.0.49525.52721.12607.20230.41112.42680.14771.1646
                       (words of UUID c175cdf1-313f-4f06-a098-a6b839b3066e)

IdentityBinding ::= SEQUENCE {
  formatVersion       INTEGER,       -- exactly 1
  sessionId           OCTET STRING,  -- exactly 16 UUID network-order bytes
  recoveryGeneration  INTEGER,       -- unsigned uint64
  deviceKeyDigest     OCTET STRING   -- exactly 32 SHA-256 bytes
}

ContentBinding ::= SEQUENCE {
  formatVersion             INTEGER,       -- exactly 1
  sessionId                 OCTET STRING,  -- exactly 16 UUID network-order bytes
  deviceKeyDigest           OCTET STRING,  -- exactly 32 SHA-256 bytes
  epoch                     INTEGER,       -- unsigned uint64, at least 1
  authorizationChainIndex   INTEGER        -- unsigned uint64, at least 1
}
```

The leading zero distinguishes this compatibility encoding from the X.667 single-decimal-arc UUID
form. Go's `crypto/x509` rejects an OID arc above signed 31-bit range before a custom verifier runs,
so the X.667 forms are not interoperable with the selected runtime. The eight-word mapping is
injective, fixed by the protocol, and tested as exact DER; extension authority still comes only from
the closed profile and pinned verifier, never from public OID registration.

The identity OID carries `IdentityBinding`; the content OID carries `ContentBinding`; each extension
is critical and exactly one is present. DER minimal-length rules apply, negative/overflow integers
fail, trailing bytes fail, and `deviceKeyDigest` is the raw digest encoded by the `device_id` after
its `cc1` prefix. Certificate serials are independent CSPRNG integers in `[1, 2^127-1]`.

The member planes are structurally non-confusable: a consensus certificate's critical extension
carries no `epoch`, a content certificate's carries `(session_id, device_id, epoch,
authorization_chain_index)`, and each ALPN verifier rejects the other's form. The ALPN selects both
the local certificate and the closed dispatcher; a connection authenticated by an identity key
cannot reach a content endpoint even if it sends a valid HTTP path.

Three rules bound what the consensus plane discloses, and they are what withholds history
from a revoked device that a stale peer still admits:

- **Only an elected leader replicates.** `AppendEntries` carrying entries and `InstallSnapshot`
  are sent solely by the current leader, and only to active devices present in its live committed
  Raft configuration: voters and the staging nonvoters that must catch up before promotion (§3).
  Settled application nonvoters are outside that configuration and catch up through signed event
  batches. A follower MUST NOT serve log entries or snapshots; Raft state flows leader→server only.
- **A leader applies before it replicates.** Log completeness guarantees an elected leader
  *holds* any committed revocation, but the gate above reads *applied* membership, and a leader
  begins replicating on election before draining its backlog. A leader MUST therefore apply
  through its committed membership index before replicating to any peer, which is the same
  catch-up it already owes before forwarding `credential.authorized`. After restart, Raft's
  volatile commit index may be zero while a quorum already holds an unapplied committed tail. The
  maintained transport MAY then send an `AppendEntries` batch containing only payload-empty
  `LogNoop` and `LogBarrier` entries to an applied-active peer in the durable committed
  configuration. Commands, configuration entries, mixed batches, payload-bearing entries, and
  snapshots remain blocked, so an up-to-date majority can recover commitment without disclosing
  coordination content and a lagging peer cannot use the exception.
- **Quorum is whatever the committed Raft configuration says, and nothing else.** A daemon
  MUST NOT alter vote-granting logic, quorum size, or majority counting based on applied
  application membership. Doing so would let two replicas halted at different indices (§5.5)
  compute different quorums for the same term — a split-brain of the safety argument itself.
  Application membership gates *who a peer will talk to*; the committed configuration decides
  *what constitutes a majority*. Where they disagree, the configuration wins for consensus and
  membership wins for access.

A revoked device may therefore complete a handshake and exchange votes with a peer that has
not yet applied its revocation. It receives no entries and no snapshot from a non-leader, an
elected leader refuses it, and it can obtain no content credential (below). Vote exchange
reveals only term and last-log index/term — log extents, not content.

#### Content-plane credentials

An active member begins renewal 300 s before expiry. The replacement activates 120 s before
the old credential expires, allowing make-before-break connection replacement; the old
credential's own expiry is never extended. At most two epochs may be simultaneously valid: the
old epoch and its overlap successor. CodeComm MUST NOT pre-authorize a stockpile of future keys or
accept an expired key. Impending expiry is visible with a countdown (§9).

The rotation procedure:

1. The member generates a fresh ephemeral Ed25519 key and persists it in the protected credential
   store before requesting authorization.
2. Its long-lived identity signs the binding of that public key to `session_id`, `device_id`, and
   the next epoch number under `codecomm/v1/credential-binding`.
3. The member submits the binding on `POST /v1/credentials/renew`. Any voter forwards it to the
   leader. The requester cannot supply validity times. The leader chooses a whole-second UTC
   `issued_at` from its clock and asks the devices in the committed `credential_authority` set to
   endorse `(session_id, subject_device_id, epoch, key_digest,
   authority_voter_set_version, issued_at)` on
   `POST /v1/credentials/endorse`. An endorser signs under
   `codecomm/v1/credential-time-endorsement` only when `issued_at` is within
   `credential_clock_skew_seconds` of its local clock. This is a clock attestation, not an
   authorization decision. A version-halted daemon serves no consensus route and therefore does not
   endorse until upgraded. Endorsement requests and replies carry no repository or coordination
   content.
4. The leader proposes `credential.authorized` only with distinct valid endorsements from active
   devices that form a majority of the **full exact activated authority set**. Revocation never
   shrinks this denominator; §3 rejects a revocation that would leave too few active authority
   members. The committed object contains everything a peer
   needs:

   | Field | Meaning |
   |---|---|
   | `subject_device_id` | Authorized active member |
   | `epoch_public_key`, `key_digest`, `epoch` | Full key, SHA-256 digest, and per-device sequence |
   | `role` | Committed membership role; display/audit only |
   | `issued_at`, `not_before`, `validity` | Endorsed issue time, activation, fixed 1800 s lifetime |
   | `authority_voter_set_version`, `clock_endorsements[]` | Exact activated authority and sorted majority attestations |
   | `binding_signature` | Subject signature over `(epoch_public_key, session_id, device_id, epoch)` |

   Every reducer validates committed state only: the subject is active; `epoch` is exactly the
   prior epoch plus one (or 1 initially); `validity = credential_epoch_seconds`; key digest and
   binding signature match and the key is new; role equals current membership; authority version
   and sorted distinct endorsers belong to the current `credential_authority`, are active in
   committed membership, and form the authority set's majority; and every endorsement signature
   covers the exact object fields above.

   For the first authorization, `not_before = issued_at`. For a successor:

   ```text
   issued_at >= prior.not_before + prior.validity - credential_renewal_lead_seconds
   not_before = max(issued_at,
                    prior.not_before + prior.validity - credential_overlap_seconds)
   ```

   The lower bound prevents rapid future-key stockpiling. There is deliberately **no upper bound at
   the prior expiry**: such a bound makes a laptop that slept past expiry permanently unable to
   renew. A late renewal activates at its endorsed current time; an early renewal activates only in
   the overlap. Quorum clock endorsements replace the unsafe upper clamp: one fast leader cannot
   obtain a majority for a far-future `issued_at`, while reducers validate the evidence without
   reading clocks. An authority activation during collection rejects the object and restarts
   endorsement. A newly committed voter target does **not** change credential authority: §3 keeps
   the prior proven set active until every target voter is promoted and
   `membership.voter_set_activated` commits. Thus an unreachable replacement cannot expire the
   credentials needed to repair its own transition.
5. The member presents a self-signed TLS 1.3 certificate whose subject key is
   `epoch_public_key`; CN and a SAN URI carry `codecomm:<session_id>/<device_id>`;
   `notBefore`/`notAfter` mirror the committed interval; and one critical extension carries
   the exact `ContentBinding` above. No CA, chain, Web PKI root, or
   other extension grants authority. The fixed certificate profile also requires a positive random
   serial in the range above, a valid self-signature, Ed25519, digital-signature key usage,
   client/server-auth EKUs, and no unknown critical extension; CN/SAN are display/routing fields,
   never authorization.
6. A peer accepts it only after applying the authorization chain index and confirming active
   membership, presented-key digest, certificate/object equality, and
   `local_now + credential_clock_skew_seconds >= not_before && local_now < not_after`. The skew is deliberately asymmetric:
   it tolerates a slow verifier at activation but adds no explicit grace after local expiry; bounded
   slow-clock error still makes the real-time stale-access ceiling
   `validity + credential_clock_skew_seconds`, not
   `validity + 2*credential_clock_skew_seconds`. Authorization reads the role from current membership, never the historical
   credential object. A peer behind the authorization refuses and retries. At handshake, the peer
   arms a monotonic close timer for the lesser of local time remaining and one credential validity;
   later wall-clock rollback cannot extend the connection. Rollover establishes replacements before
   draining old links.

The history may retain every authorization, but at any instant a verifier accepts only the
currently valid epoch and its overlap successor. Keys are never reused; superseded private keys are
erased after their connections drain.

`credential_epoch` is per **(session, device)**, not global to the session or installation. There is
no leader certificate or shared
CA key. The time endorsements authorize only the candidate timestamp; Raft commitment and the
reducer authorize the key.

**Wake with an expired epoch.** A device suspended past its content-credential expiry reaches
the consensus plane immediately on wake, since that plane never expired. It submits a binding,
the cluster authorizes it if both a Raft voter majority and the activated credential-authority
majority are reachable, and content links reopen with no operator action. In settled state those
sets are identical; §3 preserves the old authority during a transition. If either required majority
is unreachable, the device continues local work and reads against
already-applied state, its content links stay closed, and strong proposals queue; renewal retries
on every connectivity change. An all-devices-asleep cluster recovers by ordinary election on the
consensus plane — there is no distinct cold-start mode, and this is not §3.1 quorum recovery.

**Version-halted voters.** The selected Raft API cannot safely suppress campaigning while retaining
vote and replication service. A halted daemon therefore stops Raft and all consensus routes and is
unavailable, while the persisted configuration remains the sole quorum definition. A compatible
majority can still elect, commit, and authorize credentials; otherwise those operations pause until
enough voters upgrade. The remedy is upgrading a voter, not §3.1 recovery, because committed state
is intact and merely unapplied.

Pairing (§4.5) and the consensus plane are the only network surfaces reachable without a current
content credential. Their ALPN dispatchers are closed independently. Plain HTTP is limited to
OS-user-restricted local IPC or explicit development-only loopback wiring.
