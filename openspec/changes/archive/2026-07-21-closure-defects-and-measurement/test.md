# Test report

## Actor

Tester

## Coverage

Pre-grepped before writing anything: the Builder's inline suite already covered the
D1 happy/multi-binding/tag-on-blob/merge edges, the F1 regression, both D2 panic
reproductions, the D3 union/missing/invalid-plan triad, all nine D5 probe shapes,
the full D6 matrix + exploit + adjacency tests, ten D7 stats tests, and the D8
validation set. This pass added what was genuinely thin and left the rest alone.

**Functional (existing, verified present and passing).** 403 unit tests in the
`mpd` binary (1 pre-existing ignored) + 92 e2e tests + 131 tests across
`openspec-core` and the remaining workspace targets. Includes the Builder's
regression tests for every reproduced defect: F1
(`outgoing_scan_fails_closed_when_any_binding_of_a_blob_has_an_invalid_path`),
the two archive-panic inputs
(`build_candidate_closure_plan_rejects_a_durable_doc_path_outside_the_manifest`,
`build_candidate_closure_plan_reports_a_retained_manifest_read_failure_without_panicking`),
the closure-scope union triad, the D6 matrix
(`actor_separation_preserves_every_documented_persona_reuse_pattern` — Designer at
Mock/Review/Signoff, Security at both gates, Architect at Architecture +
DocValidation, all allowed) and exploit
(`actor_separation_blocks_the_alternating_label_self_review_exploit` — blocked on
the review-subject rule), and the D8 e2e round-trip.

**New — metamorphic (D1).** The pre-push path mapping is a parser over
`diff-tree -z --raw` output, so it got the metamorphic pass the pipeline mandates
for parsers (table-driven; a proptest lane over live git repos would cost minutes
per case for no added relation coverage):

- `outgoing_scan_outcome_is_invariant_under_commit_order_and_unrelated_files` —
  all 6 permutations of 3 commits, in two scenarios (secret only at an allowlisted
  path → always suppressed; same dedup'd blob also at a real source path → always
  blocked). Asserts the entire oid→paths map is *identical* across permutations
  (blob oids are content-addressed, so any divergence is a parser defect) and the
  suppress/block decision never flips when commit order changes or unrelated
  files are added. 12 throwaway git repos.
- `outgoing_scan_invalid_path_binding_fails_closed_at_every_commit_position` —
  the F1 invariant made positional: an invalid-path binding at commit position
  0, 1, or 2 always hard-fails the whole mapping pass with
  `outgoing-path-mapping-unsafe-path`, and the scan (hence any allowlist
  suppression) provably never runs.

**New — boundary.** `map_outgoing_blob_paths_rejects_a_malformed_commit_argument`
— a non-oid commit argument is rejected by `validate_oid` before any git
subprocess spawns.

**Strengthened — D7 read-only.** `stats::tests::collect_is_strictly_read_only`
now snapshots (path, mtime, full byte content) of *every* entry under `.mpd`
recursively — including a deliberately malformed ledger, proving an unreadable
row triggers no repair/rewrite — runs `collect` three ways (unfiltered, filtered
valid, filtered broken), and asserts the snapshot is bit-identical and
`.mpd/current` never appears. The prior version compared only an entry count and
one file's length.

**Property/fuzz (existing, seeded, re-run).** `ledger::tests` property lanes
(`effective_risk_max_law`, `seeded_phase_reference_model_preserves_gate_truth`)
and both `cli.rs` proptest lanes (`parse_exploit_*`, evidence-path fuzz) pass;
seeded regressions in `crates/mpd/proptest-regressions/{ledger.txt,cli.txt}`
(e.g. `cc 4eff54f2…` shrinking to `actions = [26, 69, 9]`) are re-run before
novel cases, so the suites are reproducible.

**Non-functional.** Resource/limit enforcement is covered by the 12
`sandbox::tests` supervisor tests (output-limit, worktree-limit, process-cap,
deadlines, reaping — real `/bin/sh` children); the D1/D7 caps are bounded-read
tested below threshold; the full parallel workspace run doubles as a load test
(and is exactly what exposed the flake below). Accessibility: N/A — no UI
surface; terminal-safety of disk-derived strings is covered by the stats
`safe_string`/symlink/mismatch tests. gitleaks tests run against a real
installed gitleaks 8.30.1, not mocks.

**Honest omissions.** (1) Cap-overflow of the D1 mapping pass
(`outgoing-path-mapping-cap-exceeded`) is not exercised at its real thresholds:
`MAX_PUSH_PATH_MAPPINGS = 250 000` bindings / 64 MiB enumeration would need a
disproportionate fixture, and the function takes a live repo (no injection seam
without a refactor). The branch is fail-closed by code review (Security Cond 1)
and its labeling split (genuine cap vs `git-failed: {error}`) was re-audited. (2)
No cli-level e2e drives `cmd_archive` through a full structured-Candidate
pipeline (same proportionality call the Builder recorded; the checkpoint is
covered directly). (3) The Build gate's sandboxed environment itself was not
re-run — the brief excludes `mpd gate` commands.

## Results

All commands `--offline --locked`, exit 0 unless noted.

- `cargo test --workspace --all-targets --offline --locked` — **626 passed / 0
  failed / 1 ignored (pre-existing)** across 11 targets; run 1 wall 1:31.90, run
  2 (stability confirmation) identical counts, wall 1:24.09. Largest targets:
  mpd unit 403 passed in 44.85 s, e2e 92 passed in 42.44 s, openspec-core 58
  passed in 1.38 s.
- New/strengthened tests in isolation:
  `cargo test -p mpd --bin mpd -- outgoing_scan_outcome_is_invariant outgoing_scan_invalid_path_binding_fails_closed map_outgoing_blob_paths_rejects_a_malformed collect_is_strictly_read_only`
  — 4 passed in 18.43 s (the metamorphic pair builds 15 throwaway repos).
- Seeded property suites: `cargo test -p mpd --bin mpd -- ledger::` — 43 passed
  in 0.12 s, seeds re-run from `crates/mpd/proptest-regressions/`.
- `cargo fmt --all -- --check` — clean.

**Flakiness investigation (the Build-gate "failed once, passed on retry"
observation) — root-caused and fixed.** Reproduced deterministically enough to
name: with the new metamorphic subprocess load in the suite, two consecutive
full-workspace runs failed **the same two tests**
(`sandbox::tests::supervisor_distinguishes_success_and_nonzero_exit`,
`sandbox::tests::supervisor_blocks_output_and_worktree_floods` — 401/2/1,
`assertion failed: matches!(outcome, RunOutcome::Blocked…`), while both passed
in isolation in 0.65 s. The brief's first hypothesis is ruled out: the
gitleaks-invoking `checks/mod.rs` tests passed in every run. Mechanism: the
test-local `limits()` used `per_check = 150 ms` / `aggregate = 400 ms`, and
`supervise` sets its deadline at spawn (`now + per_check.min(aggregate)`,
sandbox.rs:319) — correct fail-closed gate behavior, but under full-suite
parallel load spawning `/bin/sh` alone can exceed 150 ms, turning an expected
`Passed`/`output-limit`/`worktree-limit` into a spurious `check-timeout`. This
is a test-budget defect, not a product bug: the supervisor did exactly what its
contract says. Fix (test code only, `crates/mpd/src/sandbox.rs`): `limits()`
now uses 30 s / 60 s for the tests that do not test deadlines;
`supervisor_enforces_check_and_aggregate_deadlines` pins its own 150 ms budget
explicitly (deterministic against `sleep 5` under any load — a delayed spawn
only makes the timeout more certain); the reap-promptness bound was widened
3 s → 10 s, still far below the 30 s sleep/deadline it discriminates against.
Post-fix: 12/12 sandbox tests pass in isolation and both full-suite runs are
green. Residual honesty: these supervisor tests self-skip when genuinely nested
in the validation sandbox (`nested_in_validation_sandbox`), so the gate-run
flake was not replayed under the gate harness itself — but it is the only
load-dependent nondeterminism found in the whole suite, and the mechanism
(deadline-vs-load race) does not depend on the harness.

No new product defect was found; nothing was massaged.

## Verdict

PASS

Full workspace suite green twice consecutively (626 passed / 0 failed / 1
pre-existing ignored, real counts shown above) after deepening D1 with the
mandated metamorphic pass (commit-order/unrelated-file invariance + positional
F1 fail-closed invariance), hardening the D7 read-only assertion to full
mtime/content identity over a tree that includes a malformed ledger, and
root-causing the sandbox-flake observation to two under-budgeted supervisor
test deadlines — fixed in test code with the deadline behavior itself still
pinned by an explicit short-budget test. The two honest gaps (cap-threshold
overflow fixture, full-pipeline archive e2e) are proportionality calls carried
forward, not silent skips.
