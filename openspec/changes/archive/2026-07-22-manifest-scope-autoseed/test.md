# Test report

## Actor
Tester (claude-code harness). Builder wrote the full test set; this phase confirms
at scale (no separate Tester deepening — the predicate is a pure function already
property-tested).

## Coverage
**Unit + property (closure.rs `missing_process_scope_tests`):** conventional trio →
∅; `**` → ∅; narrow `["crates/**"]` → both entries (exact strings);
change-dir-only → reports doc; doc-only → reports change-dir; `shared_paths`
counts; custom `docs_dir` honored; single-star change-dir → still incomplete
(pathmatch `*`-doesn't-cross-`/`); proptest over arbitrary safe patterns —
self-healing (adding reported entries → ∅) and never panics.
**Closure archive-hint:** `build_candidate_closure_plan_hints_the_missing_scope_entry_for_a_never_retained_manifest`
reproduces the real NotFound path end-to-end and asserts the new hint text.
**e2e:** `strict_build_gate_refuses_and_then_accepts_missing_process_scope_entries` —
strict change, narrow manifest, Build gate refuses naming both entries, phase does
not advance, add-only fix clears the process-scope refusal.

## Results
`cargo test -p mpd`: unit **502 passed; 0 failed; 1 ignored** (pre-existing perf
`#[ignore]`); e2e **110 passed; 0 failed** (was 109 + the new test). clippy/fmt
clean. Orchestrator independently re-ran the 9 `missing_process_scope` tests + the
NotFound-hint test (all green) and confirmed #19's own ledger-less manifest passed
the new Build-gate check (dogfood).

Two honest deviations (Builder, reviewed): (1) the e2e cannot assert a genuine
strict Build PASS — that needs the full trusted-policy bootstrap the suite
deliberately routes around; the test instead proves the process-scope refusal
clears and only the unrelated pre-existing trusted-policy boundary remains. (2) A
hard-asserting "every archived manifest passes" test was dropped: 3 archived
changes predate manifest.json and several older ones use broad legacy patterns
that predate this feature — asserting on them would be factually wrong; the 10
most-recent changes satisfy the check.

## Verdict
PASS — full suite green with a real non-zero count; the fix surfaces the manifest
requirement at the Build gate (dogfood-confirmed) and weakens no gate.
