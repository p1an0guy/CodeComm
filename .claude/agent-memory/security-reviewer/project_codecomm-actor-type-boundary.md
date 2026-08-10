---
name: codecomm-actor-type-boundary
description: In CodeComm's design, human-vs-agent actor_type is unverifiable at apply time, so every operator-only verb is a local-daemon property, not a replicated one
metadata:
  type: project
---

CodeComm's entire operator-override boundary (`task.reassign`, `task.cancel`,
`*.force_release`, `plan.current_selected`, `policy.changed`, membership changes) rests on
`origin.actor_type` in the §5.2 signed event envelope. No replica can recheck it: `human`
and `agent` events from one device are signed by the same device identity key, so §5.3
step 5's "actor binding" recheck can only verify internal consistency (`agent` ⇒
`agent_session_id` set and owned by that device), never that a `human` event really came
from a person.

Consequence for any future review: "operator-only" and "absent from MCP" are properties of
the *proposing daemon's* IPC dispatch, not of the replicated state machine. They hold only
if the daemon — never a client — populates the envelope's origin block from the accepted
connection, pinning MCP connections to `agent` for their lifetime.

**Why:** rev 0.10 asserts these verbs are "structurally absent" from MCP (§7.1, §6.4,
§5.4) without naming the mechanism, and a subverted-member threat is explicitly in scope
(§2.1) while a compromised OS account is not.

**How to apply:** when reviewing any part that claims a verb is human-only or unreachable
over MCP, check for a normative envelope-construction rule before accepting the claim; and
do not credit reducer validation as the enforcement point. Related: [[codecomm-design-review-complete]].
