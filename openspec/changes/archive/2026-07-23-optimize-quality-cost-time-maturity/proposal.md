# Quality-adjusted cost and time maturity

## Why

MPD can prove exact-subject objective validation, but it cannot currently show the
quality-adjusted model cost of a change, enforce bounded model-work budgets, or prove
that its static model routing is economically justified. Several operational defects
also make healthy hooks, archived-current status, superseded doctrine, and abandoned
candidate caches harder to diagnose safely.

## What Changes

- Add bounded, exact-attempt usage attestations and independently authenticated review
  provenance readiness without claiming that provenance proves semantic quality. Required
  authentication remains fail-closed when activated, while this release stays
  cooperative/optional and visibly `NOT DEPLOYED` until a real external issuer exists.
- Add risk-specific soft/hard model-work budgets and the two-blocker/30-minute
  stop-and-replan rule; observation and recording completed work remain available.
- Make validation receipts expose check-level executed/reused dispositions and permit
  reuse only under the existing exact identity closure.
- Configure and exercise real documentation-only Build, Security(code), and Test lanes
  through the trusted local sandbox without weakening mandatory phases or floors.
- Add offline, versioned, blind routing-evidence evaluation and preview-first application
  of deterministic Pareto-eligible recommendations.
- Replace the unavailable Codex Documenter Luna assignment with the user-authorized Terra
  route, then benchmark the resulting configured Codex routes (Sol and Terra) through
  actual blind sessions; no Luna samples are fabricated or retained as coverage.
- Add additive economics/provenance/routing coverage to `next`, gate output, status, and
  stats, preserving `UNREPORTED` rather than inventing zero.
- Repair trusted-hook diagnosis and archived-current status; add mechanically checked
  doctrine supersession and identity-safe candidate-cache inspection/pruning.

No existing config block is required for compatibility. Legacy ledgers remain readable,
and missing evidence is displayed as missing, never upgraded to authenticated evidence.

## Capabilities

### New Capabilities

- `usage-attestation`: exact-attempt, bounded model usage and review-session evidence.
- `budget-anti-stall`: risk-specific budgets and bounded continuation policy.
- `validation-check-reuse`: check-level executed/reused validation evidence.
- `documentation-validation-lane`: trusted lighter profiles for honest docs-only scope.
- `routing-benchmarking`: offline blind evidence evaluation and guarded route updates.
- `review-provenance`: authenticated issuer/session identity and independence reporting.
- `operator-recovery`: accurate hook/status recovery, doctrine supersession, and safe cache cleanup.

### Modified Capabilities

- `model-config`, `process-governance`, `gate-evidence`, `evidence-reuse`,
  `local-validation`, and `outcome-measurement` receive additive implementations of
  the new capability contracts. Existing phase order, exact Candidate/Commit truth,
  and local validation authority are unchanged.

## Impact

Primary code is in `config.rs`, `ledger.rs`, `harness.rs`, `cli.rs`, `stats.rs`,
`closure.rs`, `local_validation.rs`, and `githooks.rs`, with narrow new modules for
attestation/economics, routing evidence, and cache lifecycle where separation avoids
inflating the CLI. The reviewed `security/tool-lock.json`, `.mpd/config.json`, durable docs, delta specs, unit/property tests,
CLI golden tests, and trusted-sandbox e2e fixtures change. No network service, billing
API, model execution, new sandbox fallback, or secret key storage is introduced.
