# Security (plan) review

## Actor
Security (claude-code harness). Lean self-review: this STRENGTHENS a control
(narrows a blanket suppression), so the threat direction is favorable.

## Threat model
The blanket `.mpd/state/**` `paths` entry suppresses ALL secret-scan rules on the
ledger directory at both the pre-commit staged scan and the pre-push outgoing scan
(both honor the allowlist). Threat: a real branded token (GitHub PAT, Slack bot
token, AWS key id, private-key block) landing in a `.mpd/state/*.json` file — via a
persona artifact embedded in a ledger, or a receipt — is silently exempt today.
Narrowing to `{path, rule:"generic-secret-assignment"}` exposes the ledger to all
CURATED rules → such a token is now caught, while only the generic backstop stays
suppressed on machine-generated ledger data (digests/paths/receipts) that could
structurally misfire the keyword+run heuristic. Net: strictly more detection.
Residual (unchanged from before, now the ONLY residual): an unbranded generic-only
secret (a raw AWS *secret* key) committed into a ledger stays generic-suppressed —
but the path-independent egress content scan still covers push, and the generic
rule is a backstop with documented accepted misses regardless.

## Conditions for Builder
Inherits design.md Conditions 1-4. Security emphasis: the narrowed entry must be
rule-scoped to `generic-secret-assignment` ONLY (no blanket, no other rule), and
the planted-branded-token check must confirm a curated finding SURVIVES the filter.

## Verdict
PASS — no threat-model gap; the change removes an all-rules blind spot and keeps
only a targeted, justified generic-rule suppression on machine-generated ledger
data. Security (code) will confirm the exact entry shape and the survives-the-filter
verification.
