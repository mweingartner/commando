# Proportionate Governance

## Why

On any repository that carries a structured `local_validation` block (which is every
strict repository, including this one), the risk classifier appends two synthetic
signals — `deployment-configured` and `local-validation-process-hook-sandbox-policy`
(`crates/mpd/src/closure.rs:2088-2099`) — to **every** change regardless of declared
scope, and any signal at all makes `derived = High` (`closure.rs:2102-2106`). Because
`effective = max(requested, derived)`, a two-file documentation change conducted with
`--risk low` still runs at effective-high: the Test gate selects the `high-risk-test`
profile, and every objective gate pays the full sandbox candidate validation
(compile + clippy + full test suite + release build + four scan lanes, observed
10–40 minutes per gate) — as many cycles for a docs chore as for the verification
kernel itself. Proportionality is currently impossible even when it is provably safe.

## What Changes

- **Documentation-only scope predicate.** A new fail-closed, allowlist-based predicate
  over the change manifest's declared patterns decides whether a change's scope is
  provably documentation/process-only (`docs/**`, `openspec/specs/**`, the change's own
  `openspec/changes/<change>/**`, root-level `*.md`). Any other pattern — including
  `crates/**`, `security/**`, `.githooks/**`, `.mpd/**`, `scripts/**`, `Cargo.*`, an
  empty scope, or anything unrecognized — makes the predicate false and keeps full
  rigor.
- **Risk classifier v2.** When (and only when) the predicate holds, the synthetic
  repo-configuration signals and keyword false-cognates on documentation paths no
  longer force `derived = High`; `derived` reflects the actual blast radius (Low), with
  the suppressed signals retained in the reasons trail and bound into the signal
  digest. `effective = max(requested, derived)` is unchanged — requested risk is never
  lowered, and an owner can still raise it.
- **Proportionate validation profiles (opt-in via config).** `GateProfiles` gains three
  *optional* gate names — `docs-build`, `docs-security-code`, `docs-test`. When the
  predicate holds, effective risk is Low, and the optional gate is configured, the
  strict Build/Security(code)/Test gates run that lighter profile inside the same
  sandbox candidate validator. Any docs profile that lacks a `secret-scan`-kind check
  (or, for build/test, the doc-staleness check) blocks at selection. Absent
  configuration means byte-identical behavior to today: full profiles.
- **Property tests** for the predicate and the classifier's max-law/suppression
  invariants; e2e coverage that no code/security/config-scoped change can ever reach
  the lighter path.

No behavior changes for any change whose scope touches code, configuration, security
policy, hooks, or scripts. No gate is skipped for anyone; the secret scan runs in every
profile that can be selected.

## Capabilities

### New Capabilities

None.

### Modified Capabilities

- `process-governance` — the "Effective risk cannot be lowered" requirement gains the
  documentation-only carve-out semantics (synthetic-signal suppression only under the
  fail-closed predicate), and a new requirement defines proportionate validation
  profile selection with its mandatory-check floor.

## Impact

- `crates/mpd/src/closure.rs` — `classify_effective_risk` (v2), the new scope
  predicate, `RISK_CLASSIFIER_VERSION` bump, classifier tests.
- `crates/mpd/src/config.rs` — optional `docs-build`/`docs-security-code`/`docs-test`
  fields on `GateProfiles`; new `doc-check` check kind.
- `crates/mpd/src/cli.rs` — one shared profile-selection helper used by the strict gate
  executor (cli.rs:3258) and post-archive workflow status (cli.rs:1557); selection-time
  mandatory-check floor.
- `crates/mpd/tests/e2e.rs`, `crates/mpd/src/pathmatch.rs` (read-only reuse) — tests.
- `docs/proportionate-governance.md` — operator documentation including the
  `.mpd/config.json` adoption recipe (this change does **not** edit
  `.mpd/config.json`; adopting the lighter lane is a separate, deliberately
  high-rigor config change).
- `.mpd/state/proportionate-governance.json`, `openspec/changes/proportionate-governance/**`,
  `openspec/specs/**` — process artifacts.
