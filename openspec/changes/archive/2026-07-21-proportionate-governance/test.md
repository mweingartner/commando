# Test report

## Actor

Tester

## Coverage

**Security (code) condition C1 — closed with new test code.** Three seeded,
classifier-level property tests were added to
`crates/mpd/src/closure.rs::risk_classifier_tests` (additive test code only;
the classifier/selection kernel itself is untouched, per the C1 constraint).
They draw scopes from the same allow ∪ deny pattern corpora the predicate
proptests use (`scope_is_documentation_only_tests::{arb_allow_pattern,
arb_deny_pattern}`, now shared `pub(super)`), crossed with every requested
level and both synthetic-signal config bits, and exercise
`classify_effective_risk` itself — not the abstract `RiskLevel::max` ordinal
law that `ledger.rs::effective_risk_max_law` checks without ever calling the
classifier:

1. `classifier_max_law_holds_and_suppression_occurs_iff_the_predicate_holds` —
   for arbitrary `paths`/`shared_paths` × requested ∈ {Low, Medium, High} ×
   deploy-bit × local-validation-bit: `effective == max(requested, derived)`,
   `effective.rank() >= requested.rank()`, `effective.rank() >=
   derived.rank()`; the `documentation-only-scope` marker and any
   `suppressed:` relabel appear **iff** `scope_is_documentation_only` holds;
   under a true predicate `derived == Low`, no reason survives raw, and each
   of the two synthetic signals (`deployment-configured`,
   `local-validation-process-hook-sandbox-policy`) is suppressed exactly when
   its config bit is set; under a false predicate (any sensitive pattern
   anywhere) zero suppression occurs and derivation is v1-identical (High iff
   any reason fired, both synthetic signals present raw iff configured).
2. `signal_digest_binds_the_classifier_version_and_never_collides_with_a_v1_world`
   — recomputes the exact v2 digest tuple `(version, sorted paths, reasons,
   deploy bit, local-validation bit, predicate)` and asserts byte-equality
   with the classifier's `signal_digest` (pinning that the version, relabeled
   reasons, config bits, AND predicate outcome are all in the preimage), then
   reconstructs the v1 world's digest for the same scope and config (version
   1, raw un-relabeled reasons, no predicate field) and asserts it never
   equals v2's — the v1↔v2 replay is closed in both directions.
3. `same_scope_digest_diverges_when_only_the_predicate_or_suppressed_set_flips`
   — metamorphic: with the declared path scope held byte-identical, flipping
   only the predicate outcome (own-change dir vs another change's identity)
   or only the suppressed set (toggling the deploy bit under a true
   predicate) always moves `signal_digest`, so suppressed and unsuppressed
   assessments can never collide or replay into each other.

**Functional (unit + e2e).** The Builder's 30 targeted unit/property tests
plus both new e2e tests, all re-executed: predicate allow/deny corpus
(`predicate_allows_the_documented_corpus`,
`predicate_denies_the_full_deny_corpus` — 27-pattern deny corpus including
traversal, doubled/empty segments, backslash, control byte, zero-width
Unicode, case variants, leading wildcards), classifier v2 examples
(`documentation_only_scope_on_a_deployment_configured_repo_derives_low`,
`false_cognate_keyword_hits_on_doc_paths_are_suppressed_not_dropped`),
selection (`unconfigured_docs_fields_select_exactly_todays_profiles`,
`configured_docs_lane_selects_docs_profiles_for_a_doc_only_low_scope`,
`both_call_sites_share_one_deterministic_helper`), and the two live e2e runs
through the compiled binary
(`documentation_only_scope_resolves_low_on_a_deployment_configured_repo_but_mixed_scope_stays_high`,
`a_doc_only_change_widening_its_own_manifest_after_architecture_pass_stales_evidence_and_rewinds`).

**Regression (escape-hatch and max-law pins).** Representative:
`each_condition_5_deny_pattern_keeps_full_unsuppressed_derivation_alongside_a_doc_pattern`
(every Condition 5/10 deny pattern, mixed with a doc pattern, restores full
High derivation with the raw `deployment-configured` reason and no doc-only
marker); `predicate_true_never_lowers_a_requested_medium_or_high` and
`candidate_config_and_deploy_signals_cannot_lower_requested_risk`
(effective = max pins at both corners);
`mixed_scope_falls_back_to_full_profiles_even_when_docs_lane_is_configured`
and `medium_or_high_effective_risk_excludes_the_docs_lane_even_for_a_pure_doc_scope`
(selection-side escape pins); the widening e2e pins the self-widening rewind.

**Property/metamorphic (seeded, reproducible).** The three new classifier
properties above (256 cases each, proptest defaults) plus the five predicate
properties (`conjunction_law_over_nonempty_scopes`,
`monotone_poisoning_from_nonempty_not_safe`,
`empty_paths_is_never_documentation_only_property`,
`allow_corpus_pattern_is_always_safe`,
`deny_corpus_pattern_is_never_safe_under_decoration`), the untouched
`ledger::effective_risk_max_law` and
`seeded_phase_reference_model_preserves_gate_truth` (persisted seed
`cc 4eff54f2…` in `crates/mpd/proptest-regressions/ledger.txt`, re-run first
on every execution), and the config proptests
(`arbitrary_control_bearing_policy_paths_are_rejected`,
`lenient_persona_deser_degrades_bad_tokens_and_the_rest_of_config_survives`)
— all green. Seeds persist via proptest's standard mechanism to
`crates/mpd/proptest-regressions/` (`cli.txt`, `config.txt`, `ledger.txt`
present and checked in); no `closure.txt` exists because no closure property
has ever failed — the file is created on first failure, which keeps any
future counterexample reproducible.

**Boundary/error.** Empty scope
(`empty_paths_is_never_documentation_only_even_with_safe_shared_paths`,
`empty_scope_never_suppresses_even_when_no_keyword_reason_fires`, plus the
dedicated property); malformed/hostile patterns (`an_overlong_pattern_is_not_safe`,
`docs//x`, `docs/./x`, `docs\evil`, control-byte and `docs\u{200B}/x` entries
of the deny corpus); cross-change directory
(`own_change_dir_is_own_dir_only_not_a_sibling_or_cross_change`); one
sensitive pattern among docs
(`one_deny_pattern_in_shared_paths_poisons_an_otherwise_safe_paths_list`);
invalid change names (`invalid_change_names_fail_closed_regardless_of_scope`);
floor violations blocking loudly
(`docs_profile_missing_secret_scan_blocks_loudly_rather_than_falling_back`,
`docs_build_missing_doc_check_blocks_loudly`).

**Integration.** The full e2e suite (94 tests) drives the compiled binary in
sandboxed git fixtures, including the strict candidate-validation paths with
receipts (`strict_verb_promotes_an_existing_change_and_turns_enforcement_on`
and siblings) and the two new e2e tests above; all green with unchanged
configs, confirming byte-identical behavior when the docs lane is unwired.

**Non-functional.** `openspec-core/tests/nonfunctional.rs` green (2 tests).
The classifier remains O(patterns × categories) with no I/O; the three new
property suites add ~0.1 s to the unit run (13 `risk_classifier_tests` finish
in 0.09 s). The `#[ignore]`d `scoped_digest_throughput_over_10k_paths_100mb`
benchmark was not run: this change does not touch the scoped-digest hot path
(`scoped_digest_for_patterns` has zero changed lines). Accessibility: not
applicable — CLI-only change with no UI surface (the Design phases were
skipped for this change accordingly).

**Deferred, honestly: live docs-profile e2e.** No e2e configures
`docs-build`/`docs-security-code`/`docs-test` in a fixture and drives a gate
through the real sandbox to assert on the receipts (Builder disclosed this in
tasks.md 4.3; Security recorded it under F-2/F-3 and verified Condition 9 by
construction). Rationale: it requires a full trusted-policy-bootstrap fixture
(git repo + trusted policy ref + candidate capture) that nothing in this
repository exercises — `.mpd/config.json` deliberately carries no `docs-*`
keys (design D3/D5), `validate_candidate_profile`/`_inner` have zero changed
lines (selection only changes which profile-name string is passed into the
unchanged validator), and selection itself is pinned at unit level at both
call sites. Recommendation carried forward: the first change that actually
adopts the docs lane in a real repository should add that fixture-backed e2e
as part of its own (High-rigor, `.mpd/`-scoped) validation.

## Results

All commands run offline and locked from the workspace root; every exit code 0.

- `cargo test --workspace --all-targets --offline --locked` — **684 passed,
  0 failed, 1 ignored** across 10 targets: mpd unit 460 (+1 ignored: the
  deliberately `#[ignore]`d 100 MB digest-throughput benchmark), mpd e2e 94,
  openspec-core lib 58, fidelity 5, merge_tests 15, nonfunctional 2,
  parse_edge_cases 16, project_tests 20, props 9, security_tests 5. (A
  harness line reading `1 passed; 460 filtered out` also appears mid-run:
  it is the sandbox supervisor re-invoking the test binary from within a
  sandbox test, not an eleventh suite.)
- `cargo test -p mpd --bin mpd --offline --locked -- closure::risk_classifier_tests
  closure::scope_is_documentation_only_tests closure::select_gate_profile_tests
  effective_risk_max_law seeded_phase_reference_model
  arbitrary_control_bearing_policy_paths_are_rejected persona` — **45 passed,
  0 failed** in 0.09 s, covering all 13 `risk_classifier_tests` (including
  the three new C1 properties), all 12 predicate tests (5 properties), all 8
  selection tests, the ledger max-law + seeded phase reference model, and the
  config proptests.
- `cargo fmt --all -- --check` — clean.
- `cargo clippy --workspace --all-targets --offline --locked -- -D warnings`
  — clean.

No defect was found: the three new properties (3 × 256 seeded cases per run)
confirmed the shipped classifier's max-law, suppression-iff-predicate
coupling, and digest version/suppression sensitivity without producing a
single counterexample, and the recomputed-tuple equality pin proves the test
is bound to the production digest computation, not a parallel model. No new
`proptest-regressions/closure.txt` was created (failure-only file).

Test-code changes (all additive, `crates/mpd/src/closure.rs` only): the three
properties plus local helpers (`manifest_of`, `config_with`,
`arb_requested_risk`, `arb_scope_pattern`) in `risk_classifier_tests`, and
`pub(super)` visibility on the two shared corpus strategies
(`scope_is_documentation_only_tests`) and the two config fixtures
(`select_gate_profile_tests::{gates, policy}`) they reuse.

## Verdict

PASS

Security (code) condition C1 is closed: the seeded classifier-level property
suite named above exists in `crates/mpd/src/closure.rs::risk_classifier_tests`
and executed green inside the full Test-gate run (max-law over arbitrary
scope × requested level, suppression iff `scope_is_documentation_only`, and
`signal_digest` sensitivity to the classifier version, the predicate outcome,
and the suppressed set). Full workspace suite green with real counts (684
passed / 0 failed / 1 deliberately-ignored benchmark), fmt and clippy
(all-targets, `-D warnings`) clean. The one deferred item — a live
sandbox e2e over a configured docs profile — is recorded above with its
rationale and a forward recommendation; it does not gate this change, whose
own repository leaves the docs lane unwired and whose validator machinery is
verifiably unchanged.
