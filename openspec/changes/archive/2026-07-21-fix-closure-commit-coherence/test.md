# Test report

## Actor

Tester

## Coverage

**Functional — the archived-closure fallback arm (unit + e2e).** The Builder's
18 cases were verified present and green, then deepened with 3 new e2e attack
tests (below). Unit lane (`crates/mpd/src/cli.rs`): 12 tests covering the
trigger (`stages_removal_of_matches_delete_and_rename_origin_never_copy` — `D`
and `R`-origin fire, status `C` and near-miss prefix names never do), guidance
hygiene (`removed_manifest_change_name_extracts_only_a_validated_single_component_name`,
`closure_recovery_hint_names_the_change_suggests_use_never_recover_or_recreate`,
`bounded_record_hint_strips_control_bytes_and_truncates_long_input`), and the
authority function (`archived_closure_fallback_scope_*`: blocks on empty
`system_paths`, blocks on missing plan, blocks on rebound plan binding,
authorizes legacy `candidate_id: None` from `system_paths` alone, authorizes
the `system_paths` ∪ plan-entries union). E2e lane (`crates/mpd/tests/e2e.rs`):
12 tests driving the real binary through the actually-installed
`.githooks/pre-commit` (PATH pinned to the freshly built binary), including
real `git commit` landings for both the correct flow and the post-abandon
recovery flow.

**Bypass-attack regression tests (the priority; 3 added this phase):**

- `post_landing_fallback_trigger_cannot_be_reforged_for_archived_scope_smuggling`
  (new) — after the closure commit lands, the coordinator pointer and the
  archive record deliberately survive; the test proves `git rm` of the
  non-HEAD manifest fails (the `D` signature is structurally unstageable),
  then stages smuggled content *inside* the frozen footprint (under the dated
  archive directory, which a replayed fallback would cover) and confirms the
  hook blocks via the ordinary path ("active manifest is absent or unreadable
  in the index") — the record can never re-authorize a second commit.
- `post_abandon_fallback_blocks_foreign_stray_manifest_deletion_outside_frozen_scope`
  (new) — the footprint-replay containment: under a fully valid trigger
  (own-manifest `D` staged, record+plan bound), a staged `D` of a *different*
  change's stray manifest that entered HEAD after the scope snapshot froze is
  BLOCKED ("outside archived closure scope"); unstaging it lets the genuine
  archived diff through, proving the block was containment, not a broken
  trigger. Distinct manifest content forces `-M -C` rename detection to pair
  the archive move with the change's own manifest.
- `post_abandon_fallback_blocks_when_worktree_ledger_is_unreadable` (new) —
  the Condition-10 second arm: a corrupted `.mpd/state/<change>.json` under a
  closure-shaped staged diff blocks with "unreadable archive record" and is
  asserted to NEVER fall through to the ordinary index-based manifest read.
- Pre-existing (Builder, re-verified green):
  `post_abandon_fallback_blocks_staged_path_outside_archived_scope` (staged
  path outside `system_paths` ∪ plan entries blocks under a valid trigger),
  `in_progress_change_deleting_own_manifest_without_archive_record_blocks_as_today`
  (no record → byte-identical ordinary protected-artifact block),
  `post_abandon_fallback_blocks_when_candidate_bound_plan_is_missing_and_sanitizes_hostile_text`
  (missing plan + hostile record text sanitized and bounded),
  `post_abandon_fallback_blocks_on_legacy_record_with_empty_system_paths`,
  and unit `archived_closure_fallback_scope_blocks_when_plan_binding_differs_from_record`
  (the loads-but-mismatches rebound variant — unit-level by design; a
  black-box e2e cannot cheaply fabricate a byte-valid on-disk plan).

**Ordinary-path-unchanged regressions (Condition 1):**
`ordinary_in_progress_commit_regression_with_foreign_stray_deletion_in_scope`
(foreign stray deletion within declared scope passes; the same change's own
manifest deletion without a record still blocks with today's exact string) and
`in_progress_change_deleting_own_manifest_without_archive_record_blocks_as_today`
— both green; the shared `ordinary_else_governance` extraction is exercised
from every fall-through site.

**Boundary / error paths:** empty `system_paths` (unit + e2e), missing plan
(unit + e2e), rebound plan binding (unit), legacy `candidate_id: None`
(unit + e2e authorize), unreadable ledger (e2e, new), no archive record (e2e),
status `C` excluded (unit), non-HEAD `D` unforgeable (e2e, new), no-coordinator
guidance naming the change and never suggesting `archive --recover`
(`pre_commit_guidance_names_change_when_no_coordinator_for_closure_shaped_diff`).

**Integration:** every fallback e2e drives the real installed hook; two tests
land real `git commit`s through it (correct flow before abandon, and
post-abandon via `mpd use`). `assert_hook_read_only` pins the hook as
non-mutating (index + worktree snapshots byte-compared) in every blocking
test. The macOS validation-sandbox handshake e2e ran in this suite. Build and
Security (code) receipts for this change were produced in the sandboxed
pipeline lanes and are recorded in their own artifacts.

**Stray-removal verification (design Goal 4 / F1 closure):**
`git status --porcelain 'openspec/changes/*/manifest.json'` shows staged `D`
for all three archived-change strays — `candidate-lifecycle-defects`,
`closure-defects-and-measurement`, `proportionate-governance` — and
`git ls-files 'openspec/changes/*/manifest.json'` excluding `archive/` returns
nothing (exit 1 from the grep filter): no non-archive active manifest remains
in the index. The only untracked manifest belongs to this in-flight change,
whose ledger carries no `archive_closure` record.

**Non-functional:** the changed surface is the pre-commit hook (runs on every
commit): each e2e hook invocation completes in well under a second inside
tests that finish in single-digit seconds including a full pipeline drive
(3 new attack tests: 9.57s combined); the full 106-test e2e lane completes in
~33s. Resource/immutability: the read-only-hook invariant is asserted in every
blocking case. Load/perf regression guards ran in-workspace:
`nonfunctional.rs` (5,000-requirement parse/render within a 500ms budget;
concurrent-parse determinism across threads) — 2/2 green. Accessibility: not
applicable, no UI surface (CLI/hook only; hostile terminal-escape output is
covered by the sanitization tests).

**Fuzz/property/metamorphic:** this change introduces no new parser,
serializer, or decode path (Security Condition 3: hardened loaders reused —
`ledger::load`, `load_candidate_closure_plan`, `union_closure_scope`,
`covers_concrete_paths`), so no new fuzz target is warranted. The existing
property suites covering those load-bearing surfaces all ran green: ~42
proptest properties embedded across `crates/mpd/src` (ledger, digest, config,
candidate, harness, git, closure, cli) plus 9 property tests in
`crates/openspec-core/tests/props.rs`; recorded regression seeds are checked
in and replayed deterministically before novel cases
(`crates/mpd/proptest-regressions/{cli,config,ledger}.txt`).

## Results

Command (full suite, offline + locked):

```
cargo test --workspace --all-targets --offline --locked
```

All lanes green — **705 passed, 0 failed, 1 ignored** (the macOS
sandbox-nesting guard), real non-zero counts per target:

- `mpd` unit (`src/main.rs`): 469 passed, 1 ignored (plus 1 self-reinvoked
  sandbox-handshake child pass)
- `mpd` e2e (`tests/e2e.rs`): 106 passed (103 Builder-era + 3 new attack tests)
- `openspec-core` lib: 58; `fidelity`: 5; `merge_tests`: 15;
  `nonfunctional`: 2; `parse_edge_cases`: 16; `project_tests`: 20;
  `props`: 9; `security_tests`: 5 — all 0 failed

Focused lanes (verified independently): the 3 new e2e attack tests — 3 passed,
0 failed, 9.57s; fallback unit lane — 12 passed, 0 failed.

Hygiene: `cargo fmt --all -- --check` clean (one reflow in a new test fixed
during this phase); `cargo clippy --workspace --all-targets --offline --locked
-- -D warnings` clean.

No defect found: every new attack test passed on first run against the shipped
code — the post-landing replay, foreign-stray-deletion, and unreadable-ledger
behaviors were already correct; the new tests pin them as regressions.

Honest deferrals: (a) the rebound-plan e2e variant remains unit-level only, as
the Builder recorded — the missing-plan e2e covers the same fail-closed arm
end-to-end; (b) an e2e through `publish --verify` for post-landing history is
out of this change's hook-scope (verifier unchanged by design Non-Goals);
(c) coverage/mutation adequacy measurement is not configured in this repo —
adequacy here is argued by the per-arm enumeration above, not a metric.

## Verdict

PASS

All 705 workspace tests pass with zero failures through the real installed
hook, including 3 new bypass-attack regressions proving the fallback trigger
is unforgeable post-landing, contained against foreign-manifest deletions
outside the frozen footprint, and fail-closed on an unreadable ledger. The
ordinary-path byte-identical guarantee and the complete stray-set removal are
both verified against the live repository state. fmt and clippy
(`-D warnings`, all targets) are clean.
