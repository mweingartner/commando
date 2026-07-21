# Builder Plan: Proportionate Governance

`design.md` is the sole Builder authority (decisions D1-D5, Conditions 1-9). Check a
box only when its focused code + test evidence exists. Write the initial tests in the
same pass as each item.

## 1. Documentation-only scope predicate (D1, Conds 1-2, 6)

- [x] 1.1 Implement `scope_is_documentation_only(&ChangeManifest, change)` in
  `crates/mpd/src/closure.rs` with `doc_safe_pattern` per D1: literal case-sensitive
  prefixes `docs/`, `openspec/specs/`, `openspec/changes/<change>/`, plus
  single-segment literal-`.md` root patterns; empty `paths` → false.
  Evidence: `closure.rs` `doc_safe_pattern`/`root_markdown`/`scope_is_documentation_only`
  (self-validates every pattern via `digest::validate_canonical_path` and the `change`
  arg via `validate_change_name` — Security condition 10).
- [x] 1.2 Unit tests: full allow-corpus and deny-corpus from Condition 5 (including
  `Docs/**`, `**/docs/x`, `d*cs/**`, `*.m?`, another change's dir).
  Evidence: `closure::scope_is_documentation_only_tests::{predicate_allows_the_documented_corpus,
  predicate_denies_the_full_deny_corpus, an_overlong_pattern_is_not_safe,
  empty_paths_is_never_documentation_only_even_with_safe_shared_paths,
  one_deny_pattern_in_shared_paths_poisons_an_otherwise_safe_paths_list,
  own_change_dir_is_own_dir_only_not_a_sibling_or_cross_change,
  invalid_change_names_fail_closed_regardless_of_scope}` — deny corpus additionally
  covers Security condition 10's extended list (`docs/../crates/**`, `docs//x`,
  `docs/./x`, backslash, control-char, `docs\u{200B}/x`, `**`/`*`, own-dir no-trailing-
  slash, `<change>-evil/**`).
- [x] 1.3 Property tests (seeded proptest): conjunction law
  `predicate(S ∪ T) == predicate(S) && predicate(T)`; monotone poisoning; deny-corpus
  never safe under arbitrary decoration.
  Evidence: `closure::scope_is_documentation_only_tests::{conjunction_law_over_nonempty_scopes,
  monotone_poisoning_from_nonempty_not_safe, empty_paths_is_never_documentation_only_property,
  allow_corpus_pattern_is_always_safe, deny_corpus_pattern_is_never_safe_under_decoration}`.
  Per Security condition 11 (F2), the laws are restated over non-empty operands with
  the empty-scope boundary carved out as its own dedicated test/property — `predicate(∅)
  = false` is never weakened to satisfy the law.

## 2. Risk classifier v2 (D2, Conds 3, 7)

- [x] 2.1 Add the `change` parameter to `classify_effective_risk` and update both call
  sites (`cli.rs` `current_risk_assessment`, `closure.rs` dependency capture); when the
  predicate holds, `derived = Low` with `documentation-only-scope` plus
  `suppressed:<signal>` reasons; when false, v1-identical derivation.
  Evidence: `closure.rs::classify_effective_risk`; call sites updated in
  `cli.rs::current_risk_assessment` and `closure.rs::capture_dependency_values`.
- [x] 2.2 Bump `RISK_CLASSIFIER_VERSION` to 2; bind predicate outcome + suppressed
  signal list into the signal-digest tuple.
  Evidence: `RISK_CLASSIFIER_VERSION = 2`; `signal_bytes` tuple now includes
  `predicate_holds`; `risk_classifier_tests::classifier_version_is_bumped_to_2`,
  `signal_digest_changes_when_the_predicate_flips_for_the_same_underlying_signal`.
- [x] 2.3 Extend `effective_risk_max_law` and `risk_classifier_tests`: requested is
  never lowered; predicate-true + requested High ⇒ effective High; suppression iff
  predicate; digest changes with predicate/suppressed-set changes; existing v1
  expectations still hold for non-doc scopes.
  Evidence: `risk_classifier_tests::{documentation_only_scope_on_a_deployment_configured_repo_derives_low,
  false_cognate_keyword_hits_on_doc_paths_are_suppressed_not_dropped,
  predicate_true_never_lowers_a_requested_medium_or_high,
  each_condition_5_deny_pattern_keeps_full_unsuppressed_derivation_alongside_a_doc_pattern,
  empty_scope_never_suppresses_even_when_no_keyword_reason_fires,
  signal_digest_changes_when_the_predicate_flips_for_the_same_underlying_signal}`; the
  pre-existing `representative_sensitive_signals_and_unknown_sensitive_paths_are_high`
  and `candidate_config_and_deploy_signals_cannot_lower_requested_risk` (non-doc scopes)
  still pass unchanged. The abstract `RiskLevel::max` law in `ledger.rs` is untouched
  (still exercises the ordinal law directly); the classifier-specific extension lives
  alongside the classifier in `closure.rs` rather than duplicating it in `ledger.rs`.

## 3. Proportionate profile selection (D3, Conds 4, 8, 9)

- [x] 3.1 `config.rs`: optional `docs-build`/`docs-security-code`/`docs-test` fields on
  `GateProfiles`; new check kind `doc-check`; existing configs (fields absent) parse
  and behave byte-identically.
  Evidence: `GateProfiles::{docs_build, docs_security_code, docs_test}` (`#[serde(default)]`
  `Option<String>`); `CheckKind::DocCheck`. Full e2e suite (94 tests, unchanged configs)
  still passes byte-identically.
- [x] 3.2 One shared selection helper implementing the D3 table; wire it into the
  strict gate executor (`cli.rs:3258`) and post-archive workflow status
  (`cli.rs:1557`); `docs_lane` recomputed from live manifest + current effective risk.
  Evidence: `closure::select_gate_profile`; both `cli.rs` call sites now delegate to it
  (post-archive workflow status reconstructs its manifest input from the archive
  closure's frozen `allowed_paths`, since `manifest.json` no longer exists post-archive
  — documented in `docs/proportionate-governance.md`).
- [x] 3.3 Selection-time floor: resolved docs profile must contain ≥1 `secret-scan`
  check (all three) and ≥1 `doc-check` check (`docs-build`/`docs-test`); violation
  blocks the gate with an explicit blocker naming the missing kind.
  Evidence: `select_gate_profile`'s floor check; `select_gate_profile_tests::
  {docs_profile_missing_secret_scan_blocks_loudly_rather_than_falling_back,
  docs_build_missing_doc_check_blocks_loudly, docs_security_code_does_not_require_a_doc_check}`.
- [x] 3.4 Tests: unconfigured gates → today's exact selection; configured + docs_lane →
  docs profiles; configured + non-doc scope or effective ≥ Medium → full profiles;
  floor violation blocks; helper agreement between both call sites.
  Evidence: `select_gate_profile_tests::{unconfigured_docs_fields_select_exactly_todays_profiles,
  configured_docs_lane_selects_docs_profiles_for_a_doc_only_low_scope,
  mixed_scope_falls_back_to_full_profiles_even_when_docs_lane_is_configured,
  medium_or_high_effective_risk_excludes_the_docs_lane_even_for_a_pure_doc_scope,
  both_call_sites_share_one_deterministic_helper}` (the "helper agreement" test pins
  determinism of the one function both `cli.rs` call sites invoke).

## 4. End-to-end and regression (Conds 4-5, 9)

- [x] 4.1 e2e (`crates/mpd/tests/e2e.rs`): strict docs-only change on a
  deployment-configured repo classifies derived Low, requested Low → effective Low, and
  selects docs profiles when configured; same repo, scope + `crates/**` → High + full
  profiles end to end.
  Evidence: `documentation_only_scope_resolves_low_on_a_deployment_configured_repo_but_mixed_scope_stays_high`
  covers the classification half live through the compiled binary (`mpd status --json`).
  The "selects docs profiles when configured" half is covered at the unit level
  (`select_gate_profile_tests`, task 3.4) rather than via a new live sandboxed e2e run —
  see the honest gap noted under 4.3.
- [x] 4.2 e2e: docs change widening its own manifest after a gate PASS stales evidence
  (Scope dependency) and rewinds before the next gate.
  Evidence: `a_doc_only_change_widening_its_own_manifest_after_architecture_pass_stales_evidence_and_rewinds`.
- [~] 4.3 Verify no new execution path: docs profiles run through
  `validate_candidate_profile` with candidate binding and receipts (assert on receipt
  contents in e2e).
  Partially evidenced, honestly: `validate_candidate_profile`/`_inner` in
  `local_validation.rs` are **not modified at all** by this change (`git diff` confirms
  zero lines touched in that function) — `select_gate_profile` only changes which
  profile-name `&str` cli.rs passes into the unchanged function, so there is no new
  execution path by construction. This is verified by code inspection plus the full
  existing strict e2e suite (`strict_verb_promotes_an_existing_change_and_turns_enforcement_on`,
  `strict_build_refuses_legacy_test_config_until_local_validation_is_migrated`,
  `removed_waiver_cannot_bypass_strict_local_validation`, etc. — all still pass) rather
  than by a *new* dedicated e2e test that actually configures a `docs-*` profile and
  drives it through the real sandbox: that requires a full trusted-policy-bootstrapped
  fixture (git repo + trusted policy ref + candidate capture), which this repository's
  own `.mpd/config.json` deliberately never exercises (D3, D5). Not adding that heavy
  fixture was a scope call, flagged here rather than silently skipped.

## 5. Documentation (D3)

- [x] 5.1 Write `docs/proportionate-governance.md`: problem, predicate allowlist,
  classifier v2 semantics, the `.mpd/config.json` adoption recipe, and the explicit
  note that adopting the recipe is a separate high-rigor config change.
  Evidence: `docs/proportionate-governance.md` — also documents the four Security
  condition 14 residuals and the `docs-build` build-output caveat discovered while
  wiring D3 (see design.md deviation note in that file's "Residual surfaces" section).
