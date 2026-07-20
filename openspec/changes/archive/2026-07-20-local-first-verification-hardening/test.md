# Test report

## Actor

Tester

## Coverage

Deepened the Builder's inline suite along six axes, closing the two test-adequacy
residuals handed over by Security (code) and exercising the non-functional workload.

**Functional.** Full workspace suite, all targets, offline and locked:
`cargo test --workspace --all-targets --offline --locked` — exit 0, wall 57.7s,
**579 passed, 0 failed, 1 ignored** (the deliberately `#[ignore]`d release-mode
throughput workload, run separately below). Per binary: mpd unit 358 passed
(+1 ignored, of 359), mpd e2e 91, openspec-core lib 58, fidelity 5, merge_tests 15,
nonfunctional 2, parse_edge_cases 16, project_tests 20, props 9, security_tests 5.
The interleaved `1 passed; 358 filtered out` line inside the unit suite is
`local_validation::tests::candidate_output_crash_publication` deliberately
re-invoking the test binary (`--exact local_validation::tests::candidate_output_crash_child`)
to prove crash-safe candidate-output publication; it is by design, not an anomaly.

**Regression (new — closes Security residuals R1 and R2).**

- `sandbox::tests::ambient_sandbox_marker_alone_does_not_satisfy_containment_guard`
  (crates/mpd/src/sandbox.rs, beside the helper it pins) — R1: with ambient
  `MPD_SANDBOXED=1` set via a scoped RAII env guard but `/private/etc/hosts`
  readable (uncontained host), `nested_in_validation_sandbox()` returns false; also
  asserts false with the marker absent, proving both conjuncts are required and the
  marker alone can never skip the guarded supervisor coverage. Under genuine
  containment (hosts unreadable) it early-returns without mutating the environment,
  so it cannot flip any concurrent test in the in-sandbox lane; on an uncontained
  host the transient marker is inert for every other guard site (hosts readable ⇒
  guard false regardless). Result: **ok**.
- `harness::tests::terminal_rendering_strips_bidi_directional_controls`
  (crates/mpd/src/harness.rs, beside `terminal_rendering_strips_control_sequences`)
  — R2: asserts exact output with every terminal-relevant directional control
  stripped — the full embedding/override range U+202A–U+202E (incl. U+202A, U+202E)
  and isolate range U+2066–U+2069 (incl. U+2066, U+2069) — individually and in a
  mixed payload alongside OSC/BEL (C0) and a C1 control (U+009B), with allowed
  `\n`/`\t` surviving. Result: **ok**.

Neither test exposed a defect; both pass against the shipped code, confirming the
Security (code) fixes are behaviorally real, not just structural.

**Integration (sandboxed gate receipts).** The Build and Security (code) gates ran
the real profiles inside the validation sandbox against the exact retained
candidate; receipts in `.mpd/state/local-first-verification-hardening.json`:

- Build gate: candidate `4fe35ae5cd8a92d9…`, receipt `e3e6d8553bcd0e3e…` — lanes
  format, clippy, **workspace-tests passed with count 578 in-sandbox**,
  release-build; all passed.
- Security (code) gate: same candidate, receipt `f37b8c6163867215…` — machine lanes
  policy-static, dependency-audit, gitleaks, semgrep; all passed.
- The attempt-3 receipt cited in security-code.md (`2a1b5aa50862e6c1…`, candidate
  `45eddcbffc7b8eed…`, workspace-tests 578) is retained at history entry 42.

**Boundary / error / adversarial.** The e2e set exercises hostile inputs end to end
via the real binary; representative:
`strict_symlinked_artifact_reads_empty_and_never_exfils`,
`pre_push_isolated_global_hook_and_filter_config_cannot_execute_or_mutate`,
`validation_never_executes_unactivated_candidate_policy`,
`change_flag_rejects_path_traversal`, `check_staged_blocks_on_secret` — all passed
in the 91-test e2e run.

**Concurrency / resource / load-stress.** Supervisor suite (uncontained lane):
`supervisor_enforces_check_and_aggregate_deadlines`,
`supervisor_reaps_background_pipe_holders`,
`supervisor_blocks_process_groups_over_the_cap`,
`supervisor_blocks_output_and_worktree_floods`,
`supervisor_blocks_and_reaps_when_process_observation_fails` — all passed. Required
non-functional throughput workload:
`cargo test --release -p mpd scoped_digest_throughput_over_10k_paths_100mb --offline --locked -- --ignored --nocapture`
— exit 0, **1 passed** (`closure::remote_parity_tests::scoped_digest_throughput_over_10k_paths_100mb`);
10,000 paths / 100,000,000 bytes written in 727.9 ms, `scoped_digest_for_patterns`
completed in **480.1 ms ≈ 198.6 MB/s** (digest `dd4a49195cb9ba6b…`), suite wall
6.41 s, well inside any per-request budget.

**Property / fuzz / metamorphic (seeded, reproducible).**
`cargo test -p mpd --offline --locked ledger::` — 34 passed, 0 failed, including
proptests `effective_risk_max_law` and
`seeded_phase_reference_model_preserves_gate_truth` (independent reference model of
the phase-transition kernel; does not call `Ledger::record` to compute expectations).
`cargo test -p mpd --offline --locked cli::tests` — 18 passed, 0 failed, including
`parse_exploit_rejects_any_wrong_field_count`,
`parse_exploit_accepts_five_nonblank_fields`, and the adversarial path fuzz
`validate_evidence_only_ever_accepts_the_own_artifact`. Committed regression seeds
exist and re-run first: `crates/mpd/proptest-regressions/ledger.txt` (1 seed),
`crates/mpd/proptest-regressions/cli.txt` (2 seeds). openspec-core's `props.rs`
(9 property tests) also ran green in the workspace suite.

**Accessibility.** CLI surface: honest plain-text rendering with no raw control
bytes is the relevant guarantee; the `terminal_safe` tests above (control, OSC/BEL,
C1, bidi) plus the design sign-off's rendering checks cover it. No GUI surface.

**Omissions — explicit, not silent.**

- **R3** (disclosure of the corroborated in-sandbox guard skips inside the receipt's
  workspace-tests count, rather than counting them invisibly among passes) is
  **deferred to the Phase-4 backlog, owner: Builder**, tracked alongside open tasks
  7.2/7.3 and design-signoff finding F1. Per security-code.md, R3's evidence bar is
  "receipt/log surfacing **or** a short note in the change docs": this note is that
  documented rationale. The skips are containment-proven (SC-1), their `eprintln`
  lands in the digest-bound lane log, and the new R1 test adds an eighth such
  guarded skip site (`ambient_sandbox_marker_alone_does_not_satisfy_containment_guard`),
  which the Phase-4 disclosure work must count as well. No security exposure is
  reopened.
- Tasks 7.2/7.3 (broader adversarial/property matrix and the full exact-host
  closure-commit rehearsal) remain open Phase-4 work per tasks.md; they are outside
  this gate's scope and unchanged by this report.

## Results

All commands run at the working tree containing only the two new tests (no
production code modified in this phase); every exit code 0:

- `cargo test --workspace --all-targets --offline --locked` — **579 passed,
  0 failed, 1 ignored**, wall 57.7 s (mpd unit 358 in 26.9 s; e2e 91 in 23.4 s;
  openspec-core 58 + 5 + 15 + 2 + 16 + 20 + 9 + 5).
- `cargo test --release -p mpd scoped_digest_throughput_over_10k_paths_100mb
  --offline --locked -- --ignored --nocapture` — **1 passed**, 6.41 s suite wall
  (63.6 s total including release compile); 198.6 MB/s digest throughput.
- `cargo test -p mpd --offline --locked ledger::` — 34 passed. `cargo test -p mpd
  --offline --locked cli::tests` — 18 passed. Proptest seeds committed and re-run.
- `cargo fmt --all -- --check` — clean, exit 0.

No bug was found by the deepened coverage; the two new regression tests pin the
SC-1 and SC-2 fixes (R1, R2) and pass. Unit-test delta vs. the Build baseline:
356 → 358 passed (+2, exactly the two named regression tests).

## Verdict

PASS

Full workspace suite green with real non-zero counts (579 passed / 0 failed /
1 ignored, the latter executed separately and passed), the required non-functional
throughput workload passed with recorded runtime, seeded property suites and
committed regression seeds ran, and Security residuals R1/R2 are closed by named
regression tests. R3 is closed at its documented-rationale evidence bar and its
receipt-surfacing improvement transferred to the Phase-4 backlog (owner: Builder) —
no unresolved Test condition remains open against deployment.
