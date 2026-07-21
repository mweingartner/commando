# Closure Defects and Measurement

## Why

The first two self-hosted closures (`2026-07-20-harness-aware-agent-docs`,
`2026-07-20-local-first-verification-hardening`; commits bd7f92c and 6dbd6ec) exercised
the full strict pipeline end-to-end for the first time and surfaced seven reproducible
defects — one of which (pre-push allowlist blindness) currently blocks every push from a
repo that carries allowlisted redaction fixtures. This change fixes all seven and adds
the minimal outcome measurement (Phase-5 scope) the pipeline needs so future closures
produce comparable evidence about their own cost and failure profile.

## What Changes

- **Pre-push allowlist blindness (push blocker).** Outgoing pre-push blobs are scanned
  as synthetic `git-object:<oid>` subjects, so the path-based secret allowlist
  (`.mpd/secret-allowlist.json`) can never suppress a fixture finding. Outgoing objects
  will be enumerated with their tree paths and blobs scanned under their real
  repo-relative paths with the allowlist applied; a blob with no known path keeps the
  synthetic name and full strictness. Fail-closed semantics are preserved.
- **Archive validation panics.** `mpd archive --yes` turns late closure-plan validation
  errors inside the transaction callback into `.expect(...)` panics (reproduced twice).
  These become ordinary fail-closed errors reported before the transaction is prepared.
- **Closure-commit scope contradiction.** The pre-commit AwaitingCommit scope is built
  only from transaction classification rows (the archive's own file ops), while the
  retained closure plan lists the full expected tree — making a first-ever closure
  commit impossible. Closure scope becomes the union of the transaction rows and the
  retained closure-plan entry paths.
- **`mpd check` worktree gitleaks noise.** The external gitleaks invocation scans `.`
  including `target/` (123 findings of sandbox-probe debris). The invocation gains a
  minimal build-artifact exclusion that never overrides a repo-owned gitleaks config.
- **Ledger version-skew guardrail.** Older binaries fail with raw serde errors on newer
  ledgers (reproduced: unknown variant `design-mock-artifact`). Ledger loads gain a
  version probe that converts an unreadable newer ledger into "this ledger requires a
  newer mpd" guidance, and saved ledgers gain a numeric format marker.
- **Actor separation depth.** The strict actor-separation gate compares only the latest
  upstream actor, so alternating two labels defeats it. Each judgment gate must now also
  differ from the actor of the phase whose output it reviews, while keeping the
  legitimate persona reuse (Designer 3x, Security 2x, Architect at Doc Validation).
- **`mpd stats` (new, read-only).** Aggregates every `.mpd/state/*.json` ledger
  (active and archived) into per-change and aggregate outcome measures: attempts per
  phase, reconciliations, rewinds, failure classes, wall-clock per phase,
  weakened-tuning incidence, deferrals. Human table plus `--json`. No mutation, no
  network.
- **`mpd conduct --fix --introduced-by <archived-change>`.** Records a defect-escape
  provenance link in the new change's ledger (optional field), validated against the
  existing archive, and surfaced by `mpd stats` as defect-escape counts per originating
  change.
- **Tree hygiene carried by this closure.** This change's commit also carries the five
  pending spec merges plus the two new spec directories
  (`openspec/specs/local-validation/`, `openspec/specs/agent-onboarding/`) left as
  worktree postimages by the two landed closures, removes both stray active-manifest
  copies (`openspec/changes/local-first-verification-hardening/manifest.json`,
  `openspec/changes/harness-aware-agent-docs/manifest.json` — retained solely as
  pre-commit coherence reads for the landed closure commits), and commits the
  `.claude/pipeline-gates.json` `secretAllow` addition. The manifest declares all of it.

No breaking changes: every ledger field is additive and defaulted, and every fixed
behavior was previously either a panic, a false block, or a silent gap.

## Capabilities

### New Capabilities

- `outcome-measurement` — read-only pipeline outcome statistics (`mpd stats`) and the
  defect-escape provenance link (`--introduced-by`).

### Modified Capabilities

- `local-validation` — path-mapped outgoing secret scanning with allowlist application;
  worktree external-scanner scope excludes build artifacts.
- `change-manifest` — closure-commit scope unions the retained closure-plan entries;
  archive validation fails closed without panicking.
- `gate-evidence` — adversarial actor separation gains the review-subject rule.
- `process-governance` — ledger version-skew diagnosis on load.

## Impact

- `crates/mpd/src/local_validation.rs` — outgoing object enumeration and scanning
  (`enumerate_update_objects`, `scan_outgoing_objects`, plus their tests).
- `crates/mpd/src/cli.rs` — archive transaction callback error propagation
  (`cmd_archive`), pre-commit closure scope (`staged_precommit_governance`),
  actor separation (`strict_actor_separation_issue`), `conduct`/`begin` flag plumbing,
  `stats` wiring.
- `crates/mpd/src/checks/mod.rs` — gitleaks invocation scope.
- `crates/mpd/src/ledger.rs` — format marker + version-skew load diagnosis +
  `introduced_by` field.
- `crates/mpd/src/stats.rs` (new) — the read-only aggregation behind `mpd stats`.
- `crates/mpd/src/closure.rs` — closure-plan reuse from pre-commit (read-only helper
  surface only, if any signature needs widening).
- `openspec/specs/**`, stray change-dir manifests, `.claude/pipeline-gates.json` —
  tree hygiene carried by the closure commit (no code semantics).
- No new dependencies, no network surface, no schema-breaking ledger change.
