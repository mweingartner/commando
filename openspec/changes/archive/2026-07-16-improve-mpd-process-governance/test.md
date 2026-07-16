# Tester report: proportional MPD process governance

## Verdict

**PASS.** Both boundary findings from the initial failed run were corrected,
covered by focused regression tests, and verified by a fresh complete run. No
open Tester conditions remain.

## Findings

1. **RESOLVED — oversized artifacts no longer silently count as zero pages.**
   `artifact_budget` now preserves an explicit unreadable state and emits a
   bounded “estimate unavailable” warning. The E2E test
   `oversized_artifact_reports_unknown_budget_in_status_and_brief` verifies
   terminal status, status JSON, and next-brief JSON against a file beyond the
   16 MiB safe-read limit without reading unbounded content.

2. **RESOLVED — attempt increment is saturating.**
   The shared `next_attempt_number` helper uses `saturating_add(1)`, and
   `next_attempt_saturates_at_usize_max` verifies the numeric boundary directly.
   As previously assessed, this was robustness hardening rather than an
   exploitable security issue.

## Risk-to-evidence map

| Risk or invariant | Evidence | Result |
|---|---|---|
| Existing commands and old ledgers remain compatible | `old_ledger_without_history_deserializes`; E2E happy path and prior command tests | PASS |
| Risk/threat defaults and overrides persist | `governance_defaults_overrides_and_brief_parity`; config compatibility unit test | PASS |
| Security FAIL requires a class and complete exploitability fields | `fail_class_and_security_exploitability_are_strict_and_persisted`; all failure-class E2E cases | PASS |
| PASS/CONDITIONAL reject FAIL-only fields | classified-failure E2E negative cases | PASS |
| Excess attempt blocks until one-shot reconciliation | `excess_attempt_requires_one_shot_reconciliation`; ledger consumption unit test | PASS |
| Governance change preserves history and invalidates Security onward | ledger invalidation unit test | PASS; threat-profile path is direct and risk uses the same invalidation branch |
| Human and JSON outputs expose the same governance/authorization state | governance and reconciliation E2E parity assertions | PASS |
| Terminal rendering strips control bytes | `terminal_rendering_strips_control_sequences` property/unit coverage | PASS |
| Artifact guidance remains bounded on large input | 1,100-word warning case plus >16 MiB unreadable-artifact terminal/JSON regression | PASS |
| Attempt accounting remains total at numeric boundary | normal, second-attempt, and `usize::MAX` saturation tests | PASS |
| Structured input/parser robustness remains intact | 9 property tests plus parser/security/edge suites | PASS |

## Commands and counts

- `cargo fmt --all -- --check` — exit 0.
- `cargo clippy --workspace --all-targets --all-features -- -D warnings` — exit 0.
- Focused boundary tests — exit 0; **2 passed, 0 failed**.
- `cargo test --workspace --all-features` — exit 0; **171 passed, 0 failed, 0 ignored** across 10 test binaries, including **9 property tests** and **5 security tests**.
- `cargo build --workspace --release --all-features` — exit 0; optimized workspace release build completed.
- `git diff --check` — exit 0.
- Bundled/project directive and schema-template `cmp` checks — exit 0 for all
  five synchronized pairs.

## Categories and omissions

- Functional, error, boundary, backward-compatibility, reconciliation,
  invalidation, Security schema, terminal safety, human/JSON parity, and
  structured-input property coverage were inspected.
- No network, persistence-format migration, concurrency, or load/stress suite
  was added because this change introduces no network service, external data
  store, concurrent worker, or throughput-sensitive execution path.
- Deployment and installed-target verification must still be completed by the
  authorized Deploy gate; this PASS covers source, tests, release compilation,
  and synchronized shipped assets.
