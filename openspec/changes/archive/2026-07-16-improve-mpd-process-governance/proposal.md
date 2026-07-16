# Proposal: proportional MPD process governance

## Why

Commando already enforces ordered gates, preserves verdict history, runs real
checks, tracks conditions, and blocks incomplete archives. Dogfooding on
Elysium nevertheless showed that it cannot state the risk boundary a review is
supposed to protect, distinguish a product defect from an environmental gate
failure, or stop repeated review attempts from expanding without an explicit
human decision. The result can be technically conformant but disproportionate.

## What Changes

- Add explicit `low`, `medium`, and `high` risk levels and six threat profiles
  to each change, with visible, backward-compatible defaults.
- Put the declared governance context in `begin`, `status`, `next`, and JSON so
  every persona reviews the same boundary.
- Require a structured exploitability case before Security may record a
  blocking FAIL: attacker, prerequisite capability, crossed boundary, concrete
  harm, and exact fix.
- Classify FAIL events as `product`, `test`, `infrastructure`, `environment`, or
  `policy`; record attempt number and timestamps for useful retrospectives.
- Add advisory artifact/review budgets. After the risk-specific attempt limit,
  require a recorded `mpd reconcile` decision before another attempt; this
  authorizes one review cycle but never bypasses a FAIL.
- Allow reconciliation to change risk or threat profile only by invalidating
  Security plan and all downstream approvals while preserving history.
- Update the bundled protocol, persona directives, templates, README, and
  durable documentation to explain the proportional workflow.

No existing phase is removed or skipped. Existing ledgers load with safe legacy
defaults, and existing `mpd begin` and non-FAIL `mpd gate` invocations remain
valid.

## Capabilities

### New Capabilities

- `process-governance`: risk/threat declarations, budget visibility, and
  explicit reconciliation.
- `gate-evidence`: classified failures, structured Security exploitability, and
  attempt/timestamp telemetry.

### Modified Capabilities

- `directives`: persona briefs and bundled doctrine carry the declared threat
  boundary and proportional-review rules.

## Impact

- CLI and persistence: `crates/mpd/src/cli.rs`, `ledger.rs`, `scaffold.rs`,
  `config.rs`, `harness.rs`, and focused supporting modules.
- Doctrine/templates: `crates/mpd/assets/`, `.mpd/directives/`, and
  `openspec/schemas/mpd/`.
- Tests: unit and end-to-end coverage in `crates/mpd/src/*` and
  `crates/mpd/tests/e2e.rs`.
- Documentation: `README.md` and this change's durable documentation.
- No new dependency, network call, automatic commit/push, or source-content
  telemetry is introduced.

Remote-parity closeout, content-addressed evidence reuse, and staged-file
manifests are intentionally deferred. They require a lifecycle design that
resolves archive-after-gates mutations; adding them here would produce stale
publication receipts or unsafe cache claims.
