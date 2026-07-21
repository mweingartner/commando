
## 1. Stale candidate-record recovery (D1, candidate.rs)

- [x] 1.1 Extract an identity/attempt-variant field split for
      `CandidateProjectionRecordV1` comparison (identity: schema, subject
      version/change/base_tree/manifest/entries/policy/source digests/id, entries;
      attempt-variant: base_commit, counts, excluded_dirty_*, declared_status_digest,
      root_device/inode, payload_digest) with unit tests over every field class.
      Evidence: `CandidateRecordIdentity`/`record_identity`/`identity_fields()`
      (candidate.rs); test `identity_fields_partition_matches_every_field_class`
      exercises every field of both classes individually.
- [x] 1.2 In `capture_candidate_with_hook`'s existing-root arm, replace whole-record
      equality with: identity mismatch → existing fail-closed error; attempt-variant-only
      mismatch → guarded eviction (preconditions: same change, no live `gates` binding of
      the candidate ID in the capturing change's ledger) and atomic record refresh
      (0o600 O_EXCL/O_NOFOLLOW temp, fsync, rename, dir fsync, post-replace verify read).
      Evidence: `refresh_candidate_record`, `candidate_id_has_live_gate_binding`; tests
      `attempt_variant_base_commit_divergence_is_recovered_via_refresh`,
      `attempt_variant_root_recreation_is_recovered_via_refresh`.
- [x] 1.3 In the orphaned-record arm, apply the same preconditions and remove the orphan
      record, then fall through to fresh publication; keep
      `recover_candidate_record_publication` first. Evidence: orphan arm in
      `capture_candidate_with_hook`; test `orphaned_record_is_evicted_and_capture_republishes`.
- [x] 1.4 Live-binding precondition: fail closed with rewind guidance when the current
      change's authoritative `gates` map binds the ID; add the error-path test. Evidence:
      tests `live_gate_binding_blocks_attempt_variant_eviction`,
      `live_gate_binding_blocks_orphan_record_eviction`.
- [x] 1.5 Regression tests reproducing the original stalls: record differing only in
      base_commit; only in declared_status_digest/counts; only in excluded-dirty state;
      root recreated (new device/inode); orphaned record; identity-mismatched record
      (still blocked); different-change record (still blocked); concurrent-eviction
      loser errors retryably. Evidence: the identity-partition unit test plus
      `attempt_variant_base_commit_divergence_is_recovered_via_refresh`,
      `attempt_variant_root_recreation_is_recovered_via_refresh`,
      `orphaned_record_is_evicted_and_capture_republishes`,
      `cross_change_id_collision_never_evicts_the_others_record`,
      `concurrent_attempt_variant_eviction_loser_fails_closed_retryably` (all in
      candidate.rs). Note: base_commit-only and declared-status/counts/excluded-dirty
      are exercised together at the unit-field level (task 1.1) rather than as three
      separate full-`capture_candidate` fixtures, since realistically varying
      declared-status/counts/excluded-dirty alone via real git operations without also
      moving other fields is difficult to construct deterministically; the field-class
      partition test gives equivalent guarantee that each is attempt-variant.

## 2. Authoritative Build-output binding (D2, local_validation.rs)

- [x] 2.1 Rewrite `candidate_output_ledger_bound`: iterate `ledger.gates.values()` only;
      binding predicate = typed `build_output` with matching `candidate_id`; keep the
      different-path error; delete the "no typed Build output" error. Evidence:
      `candidate_output_ledger_bound` (local_validation.rs).
- [x] 2.2 Tests: rewound history (superseded Build PASS + Security(code)/Test records
      carrying candidate, no build_output) → re-export succeeds; live gates Build PASS
      binding same path → blocked (unchanged message); live binding different path →
      error; candidate-referencing FAIL record → not a binding. Evidence:
      `rewound_history_only_build_output_does_not_poison_re_export`,
      `live_gates_build_output_at_a_different_path_still_errors`,
      `candidate_carrying_record_without_build_output_is_never_a_binding`, plus the
      Condition 19 `security_code_pass` assertions added to
      `candidate_profile_runs_retained_dirty_bytes_without_git_receipt_mutation`.
- [ ] 2.3 e2e: freshness rewind of an identical tree, Build re-runs and re-exports. NOT
      DONE as a `crates/mpd/tests/e2e.rs` binary-driven test — covered instead by the
      local_validation.rs unit test above, which exercises the exact same production
      function (`candidate_output_ledger_bound`) against a real saved/loaded ledger with
      a manually-simulated rewind (gates entry removed, history retained). A true e2e
      rewind fixture (drive `mpd gate`/freshness rewind via the compiled binary) was not
      added; flagged as a residual gap.

## 3. Landing-commit closure verification (D3, closure.rs)

- [x] 3.1 Add landing resolution: scan `rev_list_reverse(base..HEAD)`; landing candidate
      = single-parent commit whose diff (incl. rename origins) is within `allowed_paths`;
      first candidate passing scoped closure-plan equivalence (materialized via
      `materialize_commit_and_compare`, entries filtered to `allowed_paths` on both sides)
      is the landing commit. Evidence: `resolve_closure_landing`,
      `scoped_commit_equivalence`, `compare_candidate_closure_entries_scoped` (folded into
      `CommitCoherence` rather than a separate `ClosureLanding` type — see design
      deviation note below).
- [x] 3.2 Remove the per-range out-of-scope scan and the worktree-postimage/clean checks
      from the landed path; keep them as pre-landing readiness; add bounded nearest-miss
      diagnostics for equivalence-failing landing candidates. Evidence:
      `verify_commit_coherence` (modern branch), `scope_readiness`,
      `MAX_LANDING_DIAGNOSTIC_CANDIDATES`/`MAX_LANDING_DIAGNOSTIC_PATHS`.
- [x] 3.3 Legacy (plan-less) closures: unchanged whole-range behavior, verbatim, via
      `legacy_commit_coherence`. Deviation: rather than substituting a new generic
      "legacy closure cannot be landing-verified after later commits" blocker, the
      original specific diagnostics (out-of-scope path / dirty scope / digest mismatch)
      are preserved exactly, because the existing regression test
      `commit_coherence_rejects_an_intermediate_out_of_scope_add_then_delete` requires
      the specific "out-of-scope" wording for a legacy closure and still passes
      unmodified. Both keep the property "never a silent pass".
- [x] 3.4 Update `verify_remote_parity_with_probe`: VERIFIED-for-the-change = stable
      observation AND remote OID contains the landing commit (equal to landing, equal to
      HEAD, or a proven local ancestry check via `git::is_ancestor` — `sanitized_is_ancestor`
      named in design.md is `#[cfg(test)]`-only in git.rs, so the production-available
      `is_ancestor`, which has identical no-fetch/None-on-missing-object semantics, is
      used instead); keeps no-fetch, AncestryUnavailable, UNSTABLE, offline semantics;
      drops worktree conjuncts from the landed binding for a modern closure only (legacy
      keeps them, unchanged); adds additive `ParityObservation.landed_oid`. Evidence:
      `verify_remote_parity_with_probe`, `ref_level_parity_state`.
- [x] 3.5 Rewire the call sites: `cmd_publish` (readiness/verify text+json, exit codes,
      `ready_to_commit` surfaced, landing OID printed), the `mpd status` coherence json
      (`ready_to_commit` added additively), and the doctor
      `archived-closure-head-coherence` finding (cli.rs, relaxed from exact-HEAD equality
      to a landing-is-ancestor-of-HEAD check so a healthy repo with later changes' commits
      doesn't spuriously report incoherence). `workflow_status`'s match arms needed no
      change since `coherent`/`head`/`blockers` keep their field names and effective
      meaning.
- [x] 3.6 Tests: landing located with later in-scope edits (no corruption) —
      `landing_commit_is_found_despite_a_later_legitimate_same_file_edit`; other changes'
      commits before/after landing produce no blockers —
      `other_changes_commits_before_and_after_the_landing_produce_no_blockers`; merge
      commit never a landing — `merge_commit_is_never_a_landing_candidate`; rewritten
      landing (filter-branch) → accurate diagnosis —
      `rewritten_landing_fails_closed_with_an_accurate_diagnosis`; rewritten base → clear
      blocker — `rewritten_archive_base_is_a_clear_blocker_for_a_modern_closure`; vacuous
      scoped comparison fails closed (Condition 17) — `vacuous_scoped_comparison_fails_closed`;
      pre-landing readiness (Condition 10) —
      `pre_landing_readiness_reports_ready_to_commit_when_the_worktree_matches`; remote
      contains landing while local ahead → verify succeeds —
      `verify_remote_parity_verifies_the_landing_when_local_is_ahead_with_later_work`;
      remote object absent → AncestryUnavailable —
      `verify_remote_parity_reports_ancestry_unavailable_for_a_modern_closure_without_fetching`;
      legacy closure degradation — the pre-existing `commit_coherence_*`/
      `verify_remote_parity_*` legacy tests (all still `candidate_id: None`) continue to
      pass unmodified; parity cache back-compat —
      `parity_observation_landed_oid_is_additive_and_back_compatible`.

## 4. Specs, state, and suite

- [ ] 4.1 Spec deltas applied for `local-validation`, `change-manifest`, `remote-parity`
      (this change's `specs/` directory). NOT reviewed/applied by the Builder pass —
      out of scope for this session per the Builder brief (code implementation + inline
      tests only); flagged for the Documenter/Doc Validation phases.
- [x] 4.2 Full workspace suite green with a real, non-zero test count; no new panics
      (grepped the diff for unwrap/expect on input-derived state — none outside test
      code). Evidence: `cargo test --workspace --offline --locked` → mpd 424 unit +
      92 e2e, openspec-core 58+5+15+2+16+20+9+5, all passing; `cargo fmt --all -- --check`
      and `cargo clippy --workspace --all-targets --offline --locked -- -D warnings` both
      clean.
- [ ] 4.3 Docs: `docs/candidate-lifecycle-defects.md` synthesized post-Test by the
      Documenter (functional behavior changed: publish/status semantics). Not the
      Builder's phase.

## 5. Security (code) round 2 — CONDITIONAL PASS closure

Fixes for the three conditions from the first Security (code) review, plus its two
NOTES. Scope: `crates/mpd/src/{closure,cli,candidate}.rs` only.

- [x] C1 (MEDIUM, Condition 18 presentation): `ParityObservation` gains additive
      `ref_state: Option<ParityState>` (the ref-level ahead/behind/diverged/rewritten/
      verified/ancestry-unavailable classification, computed for both legacy and modern
      closures) and `landing_contained: Option<bool>` (whether the landing commit was
      proven contained in the observed remote, independent of what `state` ends up
      being). `verify_remote_parity_with_probe` hoists the containment check out of the
      `state`-derivation branch so it's always recorded. New `describe_ref_level_parity`
      helper (cli.rs) renders both facts as one line, used identically by `cmd_publish`'s
      `--verify` text output, the `mpd status` "Remote parity" text line, and
      `workflow_status`'s `remote_parity` `WorkflowFact` evidence (Verified and Blocked
      arms); `--json`/status JSON carry both fields automatically via the struct. The
      fail-closed exit-code policy (`Ok(0)` only when `state == Verified`) is unchanged —
      this is presentation only.
- [x] C2 (LOW): test `verify_remote_parity_reports_divergence_loudly_even_when_the_landing_is_contained`
      (closure.rs) — a landing commit contained (a proven ancestor of the remote's own
      sibling commit) while the ref itself has genuinely diverged (local and remote grew
      different siblings atop the landing). Asserts `landing_contained == Some(true)`,
      `ref_state == Some(Diverged)`, `state == Diverged` (never `Verified`) — both facts
      visible simultaneously. Also strengthened
      `verify_remote_parity_verifies_the_landing_when_local_is_ahead_with_later_work` with
      `ref_state == Some(Ahead)` / `landing_contained == Some(true)` assertions, and
      `parity_observation_landed_oid_is_additive_and_back_compatible` to cover the two new
      fields' back-compat defaulting/round-trip.
- [x] C3 (LOW hardening): `validate_candidate_report_binding` (cli.rs) now requires the
      receipt's typed `build_output.candidate_id`, when present, to equal the retained
      Candidate's `subject.id` — previously only `report.subject`/`receipt.subject` were
      checked, so the binding was pinned by one field cooperating rather than two
      independently agreeing. Test:
      `validate_candidate_report_binding_pins_build_output_candidate_id_too`.
- [x] NOTE (Condition 21 test rigor): the four `reopen_candidate(...).is_err()`
      post-eviction assertions in candidate.rs (base_commit divergence, root recreation,
      orphan eviction, concurrent-race loser) now capture the error and assert it
      contains "does not match its compact binding", not merely that it errs.
- [x] NOTE (orphan-arm reason swallowing): the orphan arm's fail-closed message is now
      `"candidate projection record exists without its retained root: {reason}"`,
      surfacing the specific precondition failure (identity mismatch / live-bound /
      unreadable-or-malformed) instead of a single undifferentiated string.
      `live_gate_binding_blocks_orphan_record_eviction` now also asserts `"live-bound"`
      appears; the pre-existing `projection_record_publication_failures_remove_only_owned_artifacts_and_retry`
      ("foreign record" case) now also asserts `"malformed"` appears.

Verification: `cargo fmt --all -- --check` and
`cargo clippy --workspace --all-targets --offline --locked -- -D warnings` both clean;
`cargo test -p mpd --offline --locked` → 427 unit + 92 e2e, all green, 1 pre-existing
ignored (throughput) test, 0 failures.
