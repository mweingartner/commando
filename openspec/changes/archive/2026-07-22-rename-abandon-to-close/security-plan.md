# Security (plan) review

## Actor
Security (claude-code harness). Lean self-review: a back-compatible CLI rename with
no threat surface.

## Threat model
No trust boundary, credential, egress, or untrusted-input surface is touched. The
only correctness risks are (1) breaking the existing `mpd archive --abandon --yes`
loop that AGENTS.md/hooks depend on, and (2) accidentally changing closure BEHAVIOR
while renaming. Both are addressed: (1) `--abandon` and `mpd closure abandon` remain
as aliases (Condition 1, verified by a parse/dispatch test); (2) the change is
names + user-facing strings only — the closure logic and `abandon_apply` are
untouched (Condition 2). The command's guarded semantics (AwaitingCommit-only,
`--yes` confirmation, "repository targets are untouched") are unchanged.

## Conditions for Builder
Inherits design.md Conditions 1-4. Emphasis: the `--abandon` alias MUST keep working
(the running loop uses it), and closure behavior MUST be byte-identical.

## Verdict
PASS — no threat-model gap; a back-compatible ergonomic rename. Security (code) will
confirm the alias works and no behavior changed.
