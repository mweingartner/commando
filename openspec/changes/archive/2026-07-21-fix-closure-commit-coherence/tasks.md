
## 1. Stray-manifest cleanup (pre-archive, ordinary commit path)

- [x] 1.1 Delete `openspec/changes/candidate-lifecycle-defects/manifest.json` and
      `openspec/changes/proportionate-governance/manifest.json` (both declared
      verbatim in this change's manifest scope). Evidence: `git rm` staged both
      paths (worktree deletion staged during Build; done FIRST per
      security-plan Condition 13).
- [ ] 1.2 Commit the deletions as an ordinary in-progress commit BEFORE
      `mpd archive --yes` (design.md D6/Condition 7 — the AwaitingCommit closure
      scope cannot cover deletions). Owner: main session (Build only stages the
      `git rm`; sequencing the actual commit is outside the Builder's phase).

## 2. Pre-commit archived-closure fallback (`staged_precommit_governance`)

- [x] 2.1 Add the fallback trigger (design.md D2): no pending closure, resolved
      change `C`, `ledger.archive_closure` present, staged diff removes
      `openspec/changes/<C>/manifest.json` (status `D`, or `R` with that
      `orig_path`), non-empty `record.system_paths`. Evidence: `stages_removal_of`
      + the `else if stages_removal_of(&entries, &manifest_path)` arm in
      `staged_precommit_governance` (cli.rs); test
      `stages_removal_of_matches_delete_and_rename_origin_never_copy`.
- [x] 2.2 Enforce plan discipline: `candidate_id: Some` requires
      `load_candidate_closure_plan` to succeed and bind field-for-field as in
      `verify_commit_coherence` (`closure.rs:3284-3288`); `candidate_id: None`
      (legacy) keeps `system_paths`-only scope; any failure blocks (Condition 4/5).
      Evidence: `archived_closure_fallback_scope` (cli.rs); tests
      `archived_closure_fallback_scope_blocks_when_candidate_bound_plan_is_missing`,
      `archived_closure_fallback_scope_blocks_when_plan_binding_differs_from_record`,
      `archived_closure_fallback_scope_authorizes_legacy_record_from_system_paths_alone`,
      e2e `post_abandon_fallback_blocks_when_candidate_bound_plan_is_missing_and_sanitizes_hostile_text`,
      e2e `post_abandon_fallback_authorizes_from_legacy_record_with_candidate_id_none`.
- [x] 2.3 Authorize scope as `union_closure_scope(record.system_paths, plan)` and
      check every staged orig/dest path with `covers_concrete_paths`, keeping
      exactly the four existing policy-path exemptions; skip the protected-artifact
      and `staged_blob` manifest/ledger reads only inside this arm (Condition 2/6).
      Evidence: `archived_closure_fallback_scope` + the coverage loop in the fallback
      arm (cli.rs); tests
      `archived_closure_fallback_scope_authorizes_union_of_system_paths_and_plan_entries`,
      e2e `post_abandon_fallback_blocks_staged_path_outside_archived_scope`,
      e2e `post_abandon_closure_commit_succeeds_via_use_and_real_git_commit`.
- [x] 2.4 Keep the ordinary ELSE path byte-identical whenever the trigger does not
      fully hold (Condition 1); partial trigger matches block with the specific
      reason, never fall through or consult the worktree (Condition 4). Evidence:
      `ordinary_else_governance` extracted and reused byte-for-byte from both call
      sites (cli.rs); e2e
      `in_progress_change_deleting_own_manifest_without_archive_record_blocks_as_today`,
      e2e `ordinary_in_progress_commit_regression_with_foreign_stray_deletion_in_scope`.

## 3. Error guidance and messaging

- [x] 3.1 When `resolve_change` fails (or resolves a different change) and the
      staged diff removes some `openspec/changes/<X>/manifest.json`, name `X`
      (validated via `validate_change_name`, rendered via `harness::terminal_safe`)
      and direct: commit before `mpd archive --abandon`; recover now with
      `mpd use <X>` + retry; never re-create the active manifest (design.md D5,
      Condition 8). Evidence: `removed_manifest_change_name`, `closure_recovery_hint`,
      the enhanced `resolve_change(...).map_err(...)` closure and the D5 hint appended
      in `ordinary_else_governance`'s coverage-check failure (cli.rs); tests
      `removed_manifest_change_name_extracts_only_a_validated_single_component_name`,
      `closure_recovery_hint_names_the_change_suggests_use_never_recover_or_recreate`,
      e2e `pre_commit_guidance_names_change_when_no_coordinator_for_closure_shaped_diff`.
- [x] 3.2 Never suggest `mpd archive --recover` for the abandoned state. Evidence:
      asserted directly in `closure_recovery_hint_names_the_change_suggests_use_never_recover_or_recreate`
      and e2e `pre_commit_guidance_names_change_when_no_coordinator_for_closure_shaped_diff`.
- [x] 3.3 Extend `cmd_closure_abandon` success output with the ordering reminder
      (design.md D7 — message only, no semantic change). Evidence: added `println!`
      in `cmd_closure_abandon`'s `Ok(())` arm (cli.rs); no gate/behavior change.

## 4. Tests (Builder writes initial tests in the same pass)

- [x] 4.1 e2e: post-abandon closure commit succeeds via `mpd use <change>` +
      `git commit` with no active manifest anywhere in index or worktree. Evidence:
      e2e `post_abandon_closure_commit_succeeds_via_use_and_real_git_commit` (drives
      a real `git commit` through the installed hook, PATH-pinned to the freshly
      built binary via `git_commit_through_installed_hook`).
- [x] 4.2 e2e: correct-flow closure commit (archive → commit → abandon) still
      succeeds — AwaitingCommit branch regression. Evidence: e2e
      `correct_flow_closure_commit_succeeds_via_real_git_commit_before_abandon`
      (new, drives a real `git commit`); also unchanged pre-existing
      `pre_commit_accepts_exact_pending_closure_scope_and_blocks_unrelated_paths`
      and `check_staged_resolves_pending_closure_and_still_blocks_unrelated_paths`
      stay green (AwaitingCommit branch code is untouched).
- [x] 4.3 Fail-closed unit/e2e cases: unrelated staged path outside the union;
      missing archive record; tampered/rebound plan; legacy record with empty
      `system_paths`. Evidence: unit
      `archived_closure_fallback_scope_blocks_on_empty_system_paths`,
      `archived_closure_fallback_scope_blocks_when_candidate_bound_plan_is_missing`,
      `archived_closure_fallback_scope_blocks_when_plan_binding_differs_from_record`;
      e2e `post_abandon_fallback_blocks_staged_path_outside_archived_scope`,
      `in_progress_change_deleting_own_manifest_without_archive_record_blocks_as_today`
      (missing record), `post_abandon_fallback_blocks_when_candidate_bound_plan_is_missing_and_sanitizes_hostile_text`
      (tampered/rebound-shaped — missing-plan variant; the loads-but-mismatches
      variant is unit-tested directly since it needs a byte-valid on-disk plan a
      black-box e2e test cannot cheaply fabricate),
      `post_abandon_fallback_blocks_on_legacy_record_with_empty_system_paths`.
- [x] 4.4 Legacy `candidate_id: None` record authorizes from `system_paths` alone.
      Evidence: unit
      `archived_closure_fallback_scope_authorizes_legacy_record_from_system_paths_alone`;
      e2e `post_abandon_fallback_authorizes_from_legacy_record_with_candidate_id_none`.
- [x] 4.5 Ordinary in-progress commit regression, including deleting another
      change's stray manifest within declared scope (task 1 path). Evidence: e2e
      `ordinary_in_progress_commit_regression_with_foreign_stray_deletion_in_scope`.
- [x] 4.6 Guidance test: closure-shaped staged diff with no coordinator produces
      the named-change `mpd use` message. Evidence: e2e
      `pre_commit_guidance_names_change_when_no_coordinator_for_closure_shaped_diff`.

## 5. Documentation

- [ ] 5.1 `docs/fix-closure-commit-coherence.md`: canonical flow
      (`mpd archive --yes` → `git commit` → `mpd archive --abandon --yes`),
      post-abandon recovery flow (`mpd use <change>` → `git commit`), and the rule
      that the active manifest is never re-created after archive (design.md D8).
      Owner: Documenter (Documentation phase, after Test — out of Build's scope).
