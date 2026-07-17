# Test: self-enforcing-pipeline

## Coverage

Every risk-to-test row R1–R17 (tasks.md) is implemented, plus the Security(code)
containment regression and property/fuzz coverage on the new parser-ish surface.

**Load-bearing audit (the priority for a gate-enforcement feature).** All eight
security-gate tests were empirically proven non-vacuous by reverting the specific
guard in source, confirming the test went RED, then restoring:

| R | Test | Guard whose removal turns it RED |
|---|------|----------------------------------|
| R3 | strict gate requires the phase's own authored artifact | (a) `validate_evidence` own-artifact equality; (b) the `strict_artifact_issues` call in the gate branch |
| R5 | waiver bypasses only the artifact check, never objective gates / a FAIL | the `waiver` predicate; objective-gate ordering anchored by `build_gate_refuses_when_tests_fail` + a `"test":"false"`-through-a-waiver negative |
| R11 | waiver is attempt-scoped across a reconcile rewind | `waivers.retain(phase < SecurityPlan)` in `invalidate_from_security` (e2e + ledger unit) |
| R13 | strict `--reuse` still requires the phase's own artifact | the `strict_artifact_issues` call on the `--reuse` early-return |
| R14 | autonomous refuses threat-profile change / risk downgrade / Security waiver | the autonomous halt blocks in `cmd_gate` + `cmd_reconcile` |
| R17 | `--waive-artifact` rejected with `--reuse` | the mutual-exclusion at the top of `cmd_gate` |

**Containment regression (SEC-CTX-1)** — `strict_symlinked_change_dir_is_refused_
and_never_surfaced` (e2e) proven load-bearing (neuter `read_contained` → `next
--context` surfaces the out-of-tree canary) + `assert_contained` intermediate-
directory-symlink unit test.

**Property/fuzz (proptest, seeded, non-vacuous):** `validate_evidence` (arbitrary
path-shaped inputs never panic/escape/leak content; accept only the exact in-tree
own artifact), `check_sections` (never panics; section detected iff its `##`
heading present — metamorphic), `extract_section` (output ≤ cap + ellipsis,
terminal-safe), plus a deterministic Cond-2 escape/absolute/basename-alias test.
Each caught its reverted guard.

**Non-functional:** this is a CLI state-machine + structural-check feature with no
new perf/load/concurrency surface; the pre-existing perf benchmark is unaffected.

## Results

- `cargo test --workspace` = **401 passed / 0 failed / 1 ignored** (+4 over the
  Build baseline; the ignored one is the pre-existing perf benchmark).
- `cargo clippy --workspace --all-targets -- -D warnings` = clean.
- `cargo fmt --all --check` = clean.
- **No production defect** surfaced under any guard-revert or fuzzing. One vacuous
  proptest generator (inputs rarely reaching the guarded branch) was caught and
  fixed during authoring — the lesson that a green proptest whose generator misses
  the branch is still vacuous.

## Verdict

**PASS.** Full suite green with a real non-zero count; every security-critical
gate check is proven load-bearing (would fail if reverted); the enforcement,
containment, waiver-scoping, reuse-seam, autonomous, and model-bump invariants
each have a non-vacuous regression. Independently re-verified (401/0, clippy
`--all-targets`, fmt) outside the Tester's self-report.
