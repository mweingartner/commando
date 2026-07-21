# Builder Plan: Closure Defects and Measurement

`design.md` is the sole Builder authority (decisions D1-D9, Conditions 1-12). Check a
box only when its focused code + test evidence exists. Write the initial tests in the
same pass as each fix; every reproduced defect gets a regression test that fails on the
old code.

## 1. Pre-push allowlist blindness (D1, Conds 1-2, 10)

- [x] 1.1 Add the capped per-commit `diff-tree -r -m --no-renames --root` blob-path
  mapping pass in `crates/mpd/src/local_validation.rs` (oid → validated repo-relative
  path set; unmapped/invalid paths stay unmapped; cap overflow blocks).
  Evidence: `map_outgoing_blob_paths` (local_validation.rs); caps
  `MAX_PUSH_PATH_MAPPINGS`/`MAX_PUSH_ENUM_TOTAL_BYTES`; structural parse failures and
  cap overflow return `Err`.
  **Security-code F1 fix (post-review):** a path that fails UTF-8/canonical
  validation is now a hard error for the WHOLE mapping pass, not a dropped
  per-occurrence continue — dropping it silently let a blob with one valid
  allowlisted binding and one invalid-path binding map to only the allowlisted
  path, laundering a secret reachable at the (dropped) real path. Fail-closed at
  the whole-pass level closes this unconditionally. Also fixed: `canonical_git`
  failures in this function were all mislabeled `outgoing-path-mapping-cap-exceeded`
  regardless of actual cause — now only genuine cap overflows use that label,
  other git failures surface as `outgoing-path-mapping-git-failed: {error}`.
- [x] 1.2 Rework `scan_outgoing_objects`: mapped blobs scan once per path with
  `Allowlist` filtering (suppression counted and reported); unmapped blobs and
  commit/tag messages keep synthetic-name full strictness.
  Evidence: `scan_outgoing_objects` now takes `path_map`; suppressed count printed;
  a finding surviving under ANY mapped path blocks (no first-wins).
- [x] 1.3 Bump `scanner_digest` to `...-outgoing-secret-scan-v2`; `rules_digest` stays
  at v1 (post-review correction — the underlying secret-detection rules did not
  change, only the outgoing scan/mapping semantics did; bumping `rules_digest` too
  would have been dishonest per Cond 10).
  Evidence: `mpd-builtin-outgoing-secret-scan-v2` / `mpd-builtin-secret-rules-v2`.
- [x] 1.4 Tests: allowlisted fixture blob pushes; same-content blob at fixture AND
  source path blocks; unmapped blob with a secret blocks; commit-message secret blocks
  regardless of allowlist; existing scan tests updated, none deleted.
  Evidence (local_validation.rs tests): `outgoing_scan_allowlist_requires_match_under_every_mapped_path`,
  `outgoing_scan_annotated_tag_on_blob_stays_unmapped_and_never_allowlisted` (Cond 20
  tag-on-blob edge), `outgoing_scan_maps_paths_introduced_by_a_merge_side_branch`
  (Cond 20 merge edge); pre-existing `outgoing_scan_catches_secrets_fresh_despite_preexisting_receipt`
  kept and updated for the new signature.
  **F1 regression test:** `outgoing_scan_fails_closed_when_any_binding_of_a_blob_has_an_invalid_path`
  — the same secret committed at an allowlisted canonical path AND a second path
  containing a literal backslash (valid Unix filename byte, rejected by
  `validate_canonical_path`); asserts `map_outgoing_blob_paths` returns
  `Err("outgoing-path-mapping-unsafe-path")`, so the push blocks before
  `scan_outgoing_objects` (and any allowlist suppression) is ever reached.

## 2. Archive panics become errors (D2, Cond 3)

- [x] 2.1 Capture `build_candidate_closure_plan`'s `Result` (and the
  documentation-postimage contract check) through the callback RefCell in
  `cmd_archive`; check and fail BEFORE `openspec_core::prepare`. Verify `build_plan`
  writes nothing before that check.
  Evidence: `closure_plan_out: RefCell<Option<Result<CandidateClosurePlan,String>>>`;
  new `require_closure_plan` checkpoint runs before
  `closure::save_candidate_closure_plan` (Cond 13) and before `openspec_core::prepare`.
  Both `.expect()` call sites removed.
- [x] 2.2 Regression tests for both reproduced panics (durable-doc path outside
  manifest; retained-manifest read failure): nonzero exit, diagnostic, no pending
  transaction, tree untouched.
  Evidence: `cli::tests::require_closure_plan_never_panics_on_a_captured_validation_error`
  (the panic→Result checkpoint itself); closure.rs
  `build_candidate_closure_plan_rejects_a_durable_doc_path_outside_the_manifest` and
  `build_candidate_closure_plan_reports_a_retained_manifest_read_failure_without_panicking`
  reproduce the two exact inputs against a real captured Candidate, asserting a clean
  `Err` naming the defect. A full cli.rs-level e2e repro (driving `cmd_archive` through
  a genuinely activated structured Candidate pipeline) was judged disproportionate —
  no e2e fixture in this codebase exercises that pipeline end-to-end today; the
  structural fix (single checkpoint before either durable write) is what eliminates
  both panics, and is covered directly.

## 3. Closure-commit scope union (D3, Cond 4)

- [x] 3.1 In `staged_precommit_governance`, union validated closure-plan entry paths
  (loaded by `view.transaction_id`) into the AwaitingCommit scope; missing plan keeps
  rows-only; invalid plan blocks.
  Evidence: `union_closure_scope` + `closure::candidate_closure_plan_recorded` (added
  to correctly distinguish "no plan ever saved" — 3 different not-found shapes — from
  "plan present but invalid"; the naive single-string-match approach broke 2 existing
  e2e tests, caught and fixed).
- [x] 3.2 Tests: first-ever closure commit over the full expected tree passes; staged
  path outside rows∪entries blocks; tampered/mis-bound plan blocks.
  Evidence: `union_closure_scope_widens_rows_with_plan_entries_sorted_and_deduped`,
  `union_closure_scope_keeps_rows_only_when_no_plan_was_ever_recorded`,
  `union_closure_scope_blocks_on_any_recorded_but_invalid_plan` (cli.rs);
  `candidate_closure_plan_recorded_covers_every_not_recorded_shape` (closure.rs);
  re-verified the 3 pre-existing e2e closure-scope tests still pass.

## 4. gitleaks worktree scope (D4, Cond 9)

- [x] 4.1 In `checks::run_external_scanners`, use the ephemeral extend-default config
  excluding `target/` only when the repo has no `.gitleaks.toml`; temp-write failure
  falls back to the unexcluded scan.
  Evidence: `run_gitleaks` + `write_ephemeral_gitleaks_config` (create_new/0600/
  O_NOFOLLOW, Cond 14).
- [x] 4.2 Tests: config chosen/skipped per repo state; invocation unchanged when a repo
  config exists.
  Evidence: `write_ephemeral_gitleaks_config_creates_a_private_extend_default_file`,
  `run_gitleaks_excludes_target_but_still_catches_real_secrets_elsewhere`,
  `run_gitleaks_defers_to_a_repo_owned_gitleaks_toml_unmodified` — all 3 run against a
  real installed gitleaks 8.30.1 binary, not mocked.

## 5. Ledger version-skew guardrail (D5, Conds 6, 11)

- [x] 5.1 Add `LEDGER_FORMAT = 2` + defaulted `format` field; `save` writes it; probe
  the failure path in `load`/`load_observed`/`load_observed_exact` for the
  "requires a newer mpd" vs contextual-error split.
  Evidence: `LEDGER_FORMAT`, `ledger_format_v1`, `serialized_ledger` stamps the current
  format on every write, `ledger_version_probe` (format read via
  `serde_json::Value::as_u64` only — Cond 15 non-u32 handling).
  Post-review fix: the probe's `change`-field hint is now length-bounded
  (`MAX_CHANGE_HINT_CHARS = 200`, truncated with `…`) before rendering, matching the
  bounded-string discipline used everywhere else (Cond 15/17) — it was previously
  unbounded.
- [x] 5.2 Tests: valid current ledger loads byte/field-identical; `format: 99` ledger
  produces the newer-mpd message; corrupt JSON keeps the original error; legacy
  fixtures (no `format`) load as format 1; byte-identity fixtures updated knowingly.
  Evidence: 9 tests in `ledger::tests` (`legacy_ledger_without_a_format_field_defaults_to_format_one`,
  `new_ledger_is_stamped_with_the_current_format`,
  `save_always_stamps_the_current_format_even_over_a_legacy_in_memory_value`,
  `a_ledger_that_parses_is_returned_identically_regardless_of_format`,
  `format_exceeding_this_binary_produces_the_newer_mpd_message`,
  `format_at_or_below_current_keeps_the_original_error_with_a_hint`,
  `absent_format_keeps_the_original_error_with_a_hint`,
  `non_u32_format_values_are_treated_as_absent`,
  `probe_failure_on_non_json_leaves_the_original_error_unchanged`). No pre-existing
  ledger fixture test asserted exact bytes, so none needed updating.

## 6. Actor separation depth (D6, Cond 7)

- [x] 6.1 Implement `review_subject` and the dual-rule check in
  `strict_actor_separation_issue` with a message naming rule + actors.
  Evidence: `review_subject` table + adjacency/subject checks, each with a distinct
  message naming the rule.
- [x] 6.2 Matrix tests: every documented persona-reuse pattern passes; the
  alternating-label self-review exploit fails on the subject rule; adjacency rule still
  fires as before.
  Evidence: `actor_separation_preserves_every_documented_persona_reuse_pattern`,
  `actor_separation_blocks_the_alternating_label_self_review_exploit`,
  `actor_separation_adjacency_rule_still_fires`; re-verified the pre-existing e2e
  `strict_actor_separation_is_enforced_by_the_real_gate` still passes.

## 7. `mpd stats` (D7, Cond 5)

- [x] 7.1 New `crates/mpd/src/stats.rs`: bounded no-follow enumeration of
  `.mpd/state/*.json`, per-change measures, aggregate section, defect-escape grouping;
  `cli.rs` gains wiring only.
  Evidence: `stats::collect` reuses `ledger::load` directly (inherits D5's bounded/
  no-follow/version-probe discipline for free); `cmd_stats` in cli.rs is wiring only.
- [x] 7.2 Human table (terminal-safe) + stable sorted `--json`; unreadable ledgers are
  reported rows.
  Evidence: `render_human`, `safe_string` (terminal_safe + length bound, Cond 17),
  `ChangeRow::Unreadable` with a coarse stable `error_class`.
- [x] 7.3 Tests: aggregation over fixture ledgers (attempts, wall-clock,
  reconciliations, rewinds, failure classes, weakened tuning, deferrals); read-only
  property (no writes, no git, deterministic output); malformed-ledger row.
  Evidence: 10 tests in `stats::tests`, incl. `collect_is_strictly_read_only`,
  `a_symlinked_state_file_is_reported_not_followed`,
  `json_output_is_deterministic_and_sorted_by_change_name`.

## 8. `--introduced-by` provenance (D8, Cond 8)

- [x] 8.1 Add the clap flag (`requires = "fix"`) to conduct/begin, archive-existence
  validation (ledger `archive_closure` OR dated archive dir), and the additive
  `introduced_by` ledger field; surface in `mpd status`.
  Evidence: `--introduced-by` on `Begin`/`Conduct` (clap `requires = "fix"`);
  `validate_introduced_by` + `legacy_dated_archive_exists` + `dated_archive_matches`
  (exact `<YYYY-MM-DD>-<name>` decomposition, Cond 18); `Ledger::introduced_by`
  (write-once at begin, never read by any gate/readiness path — Cond 19); surfaced in
  `mpd status` (human, `--brief`, and `--json`).
- [x] 8.2 Tests: invalid name / missing archive creates nothing; valid link persists,
  round-trips, and appears in `mpd stats` defect-escape counts.
  Evidence: cli.rs unit tests (`dated_archive_decomposition_is_exact_never_substring_or_prefix`,
  `validate_introduced_by_rejects_an_invalid_name_and_creates_nothing`,
  `validate_introduced_by_rejects_a_change_with_no_archive_evidence`,
  `validate_introduced_by_accepts_a_ledger_with_archive_closure`,
  `validate_introduced_by_accepts_a_legacy_dated_archive_directory`); e2e
  `introduced_by_validates_before_creating_anything_and_surfaces_downstream` drives
  the real binary through an unresolvable rejection (no ledger/scaffold/`.mpd/current`
  created), then a real archive + `--introduced-by` link, confirming it round-trips
  through `mpd status --json` and `mpd stats --json`'s defect-escape grouping.

## 9. Closure hygiene (D9)

- [ ] 9.1 At commit time, stage per the manifest: pending spec merges + two new spec
  dirs, DELETE both stray active-manifest copies, `.claude/pipeline-gates.json`, this
  change's artifacts/state/docs, `crates/mpd/**`. No `openspec-core` changes.
  Not done by Builder: D9 is explicitly Architect-owned commit-time staging over files
  outside `crates/mpd/**` and this change's own dir (the Builder's declared scope), and
  requires running `mpd archive`/`git commit`, which the Builder brief explicitly
  excludes. The change's own `manifest.json` already matches D9's declared paths
  exactly (verified, unchanged). Left for the Deploy/main-session phase.
