# Security plan review: proportional MPD process governance

## Scope and trust model

Reviewed `proposal.md`, `design.md`, all three delta specifications, `tasks.md`,
and the current Rust persistence, CLI, directive, configuration, command-runner,
and symlink-refusing file-read boundaries.

Commando is a local developer CLI operating on a repository selected by the
current OS user. The governance declaration is review context and audit state;
it is not an authentication or authorization boundary. A user who can modify
the repository can already modify MPD ledgers, directives, test commands, and
source. This change must not claim to make those records tamper-proof. The
credible risks introduced here are unsafe parsing/rendering of the new values,
path or command injection, accidental gate bypass through reconciliation, loss
of audit history, and leakage of command output or local secrets.

## Abuse-case review

- Risk levels, threat profiles, and failure classes are closed enums and never
  become paths or commands.
- Exploitability and reconciliation text are bounded data. They are persisted
  as JSON evidence only and must not be evaluated as shell, paths, or policy.
- A reconciliation authorizes one specifically numbered attempt for the current
  phase. It neither advances the phase nor converts, erases, or bypasses FAIL.
- Changing risk or threat profile changes Security's approved boundary, so the
  design correctly retains history and invalidates Security plan and every
  downstream latest verdict.
- Classification is evidence, not execution policy. In particular,
  `environment` and `infrastructure` FAIL records remain blocking until a real
  rerun advances the gate.
- Attempt and timestamp telemetry contain no raw command output, prompts,
  source, environment, or credentials. Backward clock movement is explicitly
  clamped rather than used in security decisions.
- Artifact budgets are advisory. Their reads reuse the existing contained,
  symlink-refusing, size-capped helper and cannot authorize a gate.
- Deferred publication parity and evidence reuse are accurately excluded; the
  design does not make an unverifiable security claim.

## Findings

No blocking finding.

[LOW] `openspec/changes/improve-mpd-process-governance/design.md:113` -> When
rendering new repository-stored exploitability and reconciliation strings in
human output, escape or reject terminal control characters (especially ESC and
OSC/C1 controls), while leaving JSON serialization standard. This is defensive
hardening for a user inspecting a repository modified by another contributor,
not a blocker under the declared local-trusted-user model. Add a focused test if
the current shared renderer does not already sanitize such text.

## Conditions for Builder verification

1. Compatibility and serde defaults are explicit in the migration and test plan.
2. New typed values and free text are bounded and prohibited from becoming path
   or shell fragments.
3. FAIL classification and Security-only exploitability combinations fail
   before checks or writes.
4. Exploitability remains reviewer judgment; no keyword scoring or automatic
   downgrade is proposed.
5. Attempt accounting is history-derived and reconciliation is one-shot without
   changing a prior verdict.
6. Governance-boundary changes retain history and rewind from Security plan,
   leaving Design and Architecture intact.
7. Artifact size is advisory and uses the existing safe read boundary.
8. Human/JSON parity is required and sensitive raw material is excluded.
9. Timestamp arithmetic clamps backward-clock duration to zero.
10. Bundled, dogfood, and OpenSpec copies are synchronized and tested.
11. Deferred evidence reuse, commit-scope, publication, and remote-parity
    capabilities are not claimed.
12. Formatting, Clippy, workspace tests, release build, and installed-command
    smoke coverage are required before delivery.

## Reviewed and not reviewed

Reviewed the plan and current trust-boundary implementations only. Production
code for this change does not yet exist and therefore was not reviewed. The
Security (code) gate must inspect actual parsing limits, flag-combination
validation order, reconciliation consumption/invalidation, output rendering,
serde compatibility, and the complete diff.

## Verdict

**PASS** — no plausible exploit path blocks Build under the actual local CLI and
repository model. The terminal-control note is non-blocking defense in depth.
