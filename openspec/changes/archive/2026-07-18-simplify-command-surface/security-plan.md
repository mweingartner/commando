# Security (plan) — simplify-command-surface

Governance: risk medium, threat profile local-trusted-user. A CLI ergonomics
refactor; the security-relevant surface is two paths it touches.

## Threat model

No new capabilities. The refactor must PRESERVE two existing safety properties
while reshaping the CLI:
1. **Security-FAIL evidence rigor.** Today a Security FAIL cannot be recorded
   without a credible exploit path (attacker/capability/boundary/harm/fix) — the
   gate builds `Exploitability` unconditionally and `bounded_text` rejects any blank
   field. Collapsing the 5 flags into `--exploit` must not turn a mandatory field
   into an optional one.
2. **Archive transaction safety.** Folding `closure recover|abandon` into `archive`
   must not weaken the journaled two-phase archive, nor make recovery unreachable in
   the pending-closure state it exists for.

Everything else (manifest flatten, help tiering, hiding `begin`/`closure`) is a
signature/visibility change with no trust-boundary effect (confirmed: no
`infer_subcommands`, `resolve_change` path validation preserved, `hide` is help-only).

## Conditions for Builder

Two HIGH conditions from the review, folded into design.md D4/Cond 2 and D3/Cond 3:

1. **[Finding 1, HIGH] `--exploit` is MANDATORY on a Security FAIL** — not merely
   validated-when-present. Its absence must error identically to a malformed value.
   Implement via the exhaustive 4-arm `match (verdict, security, exploit)` (D4), NOT
   `exploit.map(parse).transpose()?` (which lets `None` record a FAIL with no exploit
   evidence). `parse_exploit` = split `|` → exactly 5 fields, each `bounded_text`.
   Closing evidence (Security-code): a Security FAIL with NO `--exploit` is refused.
2. **[Finding 2, HIGH] Route `--recover`/`--abandon` in `run()` BEFORE `cmd_archive`**
   — `cmd_archive`'s first check refuses on a pending closure, which is exactly the
   state recovery exists for. Mutual-exclusion vs each other, `--skip-specs`,
   `--change`; `--json` scoped to the recover/abandon branch; `cmd_closure_*` and the
   transaction path unchanged. Closing evidence (Security-code): an e2e reusing the
   `AwaitingCommit` setup drives `mpd archive --recover`/`--abandon` and reaches the
   recovery logic, not the "already pending" refusal.

Advisory (folded in): `--exploit --reuse` refused; `--change`+recover/abandon rejected.

## Verdict

**CONDITIONAL PASS.** The refactor's intent (preserve today's validation + transaction
safety) is sound; the two HIGH findings are gaps in the plan's explicit wiring/tests,
now closed in D4/Cond 2 and D3/Cond 3. Both are the class of subtle wiring bug that
only surfaces by reading the actual match arms, so **Security (code) MUST independently
re-verify both against the real diff** (not a Builder self-report) and run the
pending-closure e2e. Proceed to Build.
