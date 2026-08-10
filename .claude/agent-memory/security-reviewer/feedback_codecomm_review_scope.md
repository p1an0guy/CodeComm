---
name: codecomm-review-scope
description: When reviewing CodeComm design docs, critique specification/disclosure quality — do not re-litigate the settled architectural decisions
metadata:
  type: feedback
---

When security-reviewing the CodeComm design (`/Users/ijonahch/Dev/CodeComm/docs/design/`),
critique whether a control is **specified and honestly disclosed**, not whether the underlying
decision was right. Settled and off-limits: no read-only role, no data-at-rest encryption in V1
(FDE reliance), `device_id` as the sole principal, no Byzantine tolerance, revocation not
covering already-downloaded data.

**Why:** these were each decided interactively with the user across earlier revisions (see the
rev-0.7 resolution history in the user's auto-memory); re-arguing them wastes the review and
the user has explicitly ruled them out of scope.

**How to apply:** for each settled decision, ask instead — is the consequence enumerated
completely, is the residual risk stated where a reader will see it, and does any *other* part
of the design quietly depend on the excluded protection? That last question is where the real
findings are (e.g. §10 declaring a compromised OS account out of scope while the IPC, credential
store, and agent surfaces all sit inside that boundary). Reviews are done part-by-part; ignore
doc-splitting artifacts, and verify asserted controls against the part that would implement them
rather than trusting the summary.
