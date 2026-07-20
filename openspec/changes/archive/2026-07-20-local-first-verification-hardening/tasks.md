# Builder Plan: Bounded Local Production Kernel

`design.md` is the sole Builder authority. Every box is required and has a stable ID.
All 18 tasks are required with no deferral. Check one only when its focused code/test
evidence exists. Later Security(code), Test, Documentation, Doc Validation, final Deploy,
archive, commit, push, parity, and installation remain separate gate/delivery facts.

## 0. Establish the executable baseline

- [x] 1.5 **Bound scope and compile immediately.** Ensure `crates/mpd-transition/` is
  absent and active shipped help/config/code cannot execute superseded machinery. After
  revised Design Review and Security(plan) PASS, run `cargo check --workspace
  --all-targets` and record command/exit/errors. Fix only the bounded kernel in vertical
  slices, compiling and focused-testing after each slice; historical review files stay inert.

## 1. Phase, ledger, and governance truth

- [x] 1.1 **Correct phase order** in `phase.rs`, `ledger.rs`, directives, and matrix
  tests: mandatory Documentation then Doc Validation then final Deploy for every change
  kind; only Design phases may be N/A with a stored rationale.
- [x] 1.2 **Add append-only rewind** to existing `repair-state` as `--to
  <earlier-phase> --reason <text> [--yes]`. Test zero-effect preview, wrong direction,
  archive refusal, replay, concurrent digest change, atomic failure, retained PASS/FAIL/
  conditions, invalidated downstream receipts, and zero created verdicts.
- [x] 1.3 **Add freshness and effective risk** in existing ledger/config/CLI paths:
  earliest dependency rewind before effects and `effective=max(requested,derived)` using
  the Architecture's complete canonical artifact/causal map and versioned sensitive-path/
  config signals. Test every phase artifact and signal, unknown-sensitive High, hostile
  lowering config, read-only status, retained history, and no stale brief.
- [x] 1.4 **Use the tested native rewind** on this active ledger, preserving the Build
  FAIL/history. Rerun canonical Architecture, applicable Design Review, and Security(plan)
  before final Build PASS; retain before/after ledger digests and event counts.

## 2. Exact candidate and closure

- [x] 2.1 **Implement a read-only candidate projection** by reusing the commit
  materializer: base HEAD plus manifest-scoped staged/unstaged tracked postimages,
  declared untracked files, deletions, and modes. Add sorted path/mode/length/SHA manifest
  identity, no-follow bounded reads, status recheck, and exact cleanup. Test symlink,
  special/collision/race/cap rejection and unchanged worktree/index/refs/object DB.
  Prove ordinary live-ledger/current/pending/log/cache/output writes do not move the
  candidate, declared config/directive/hook/policy changes do, and active MPD/clone-
  private process state is absent from candidate-visible inputs.
- [x] 2.2 **Bind Build, Security(code), and Test** to the same projection and rehash it
  before/after each gate. Keep Candidate and Commit receipts distinct; explicit
  validation/pre-push remain Commit subjects. Regress uncommitted failing code with a
  passing HEAD and require candidate failure. Human/JSON show NOT CAPTURED plus planning
  subject before Build, capture base/ID/path-state/mode/excluded counts, and repeat the ID;
  Documentation/Doc Validation bind candidate plus overlays and Deploy its Build output.
- [x] 2.3 **Verify closure equivalence** in `closure.rs`: candidate source plus current
  canonical phase artifacts, reviewed docs, and deterministic archive postimages only.
  Compare final commit paths/modes/digests; test extra/missing/source/config/script/task/
  mode/rename/deletion/stale-overlay mismatches.

## 3. Harden existing local validation

- [x] 3.1 **Bound the current runner** in `local_validation.rs`, `sandbox.rs`, `safe_fs`,
  and `checks`: typed argv plus one private nonce-bound control request; cleared loader/
  environment state; closed ambient descriptors; fixed reviewed custom profile; exact
  canonical dynamic read/read-write extensions using `flags=0`; issue -> sandbox-init ->
  consume -> zeroize -> canaries -> READY/GO -> close-control -> exec; private roots;
  monotonic timeout; concurrent output/aggregate caps; terminate/grace/kill/reap; stable
  authority reads; bounded logs; terminal escaping; and BLOCKED on any malformed request,
  root/ABI/profile/canary drift, truncation, timeout, leak, or cleanup failure. Never take
  roots from argv/environment/candidate config, use `PREFIXMATCH`, or provide a fallback.
  Test exact/over boundaries, partial-step failures, descriptor/token leakage, symlink/root
  races, direct hidden-mode reinvocation, and post-entry non-escalation; no module split is
  required.
  (Evidence: `cargo test -p mpd --bin mpd --offline --locked -- sandbox` — 14 passed
  (root overlap/count-boundary rejection, environment clearing, adapter selection,
  timeout/output/worktree/process-cap enforcement, reap-of-background-holders, malformed
  observer BLOCKED). `cargo test -p mpd --test e2e --offline --locked -- exact_host_sandbox_entry_completes_canaries_and_ready_go`
  — 1 passed (real macOS handshake: issue -> sandbox-init -> consume -> READY/GO ->
  close-control -> exec, plus the full canary sequence — allowed/denied read, allowed/
  denied write, symlink race, loopback, direct child, grandchild, and post-entry-
  extension non-escalation — all run inside one live invocation of the hidden
  `__mpd-sandbox-exec` entry point, i.e. direct hidden-mode reinvocation). `cargo test -p mpd --test e2e --offline --locked -- validation_never_executes_unactivated_candidate_policy`
  — 1 passed. 16/16 total, 0 failed.)
- [x] 3.2 **Complete the current-macOS local profile** in config/security/scripts:
  exact candidate, Rust/Homebrew dependency, CLT/SDK, system and `/dev` read roots;
  literal `/dev/null` write; one private runtime read-write root; pinned tools/offline
  inputs; and allowed read/write plus denied secret, `~/.gitconfig`, `/tmp`, socket,
  loopback/outbound/DNS, symlink, descriptor, child/grandchild, reinvocation, process, and
  post-entry extension canaries. Preserve the passing full offline cargo -> rustc -> linker
  -> test-binary probe as feasibility evidence, not suite certification. Supply fixed
  private Git identity/config and private HOME/XDG/temp/process state, then run format,
  warning-denied Clippy, locked workspace/all-target tests, release, audit-no-update,
  gitleaks, Semgrep, property, docs, and coherence checks. Fix scanner full-file/aggregate
  caps and bind receipts/status to macOS 27.0 build 26A5378n, Apple silicon,
  `aarch64-apple-darwin`; every other identity is NOT CERTIFIED.
  (Evidence — asset shape only, not the empirical certification run, which lands with
  the Build-gate validation pass per this task's own text: `cargo test -p mpd --bin mpd --offline --locked -- repository_static_policy_assets_are_semantically_valid`
  — 1 passed (loads the real `.mpd/config.json` structured policy, the real
  `security/tool-lock.json`, and the real `security/advisory-db.lock.json` and checks
  schema/digest/tree coherence against them). `cargo test -p mpd --bin mpd --offline --locked -- required_push_tool_missing_from_lock_blocks_without_execution declared_clone_private_tool_entry_binds_source_inventory_path_and_bytes`
  — 2 passed. `fixed_profile_and_current_host_are_exact` (already cited under 3.1) further
  byte-compares `security/sandbox/validation.sb` on disk against the compiled
  `FIXED_PROFILE` constant and probes the live symbols on this host. 3/3 additional
  policy-shape tests passed, 0 failed. Certified-host binding to macOS 27.0 build
  26A5378n/aarch64 is enforced in `sandbox_macos.rs::verify_certified_host` and exercised
  live by the same test.)

## 4. Evidence and status

- [x] 4.1 **Enforce canonical strict artifacts** using existing ledger/persona code:
  required sections, current digest, actor, candidate binding where applicable, recorded
  role difference, all task/condition closure, and Commando waiver denial. Label role/
  model/session separation cooperative, not authenticated; test missing/stale/same-actor/
  waiver cases.
  (Evidence: `cargo test -p mpd --test e2e --offline --locked -- strict_gate_requires_the_phases_own_authored_artifact strict_gate_exposes_no_artifact_waiver_and_unknown_flag_is_inert strict_symlinked_artifact_reads_empty_and_never_exfils strict_actor_separation_is_enforced_by_the_real_gate strict_reuse_still_requires_the_phases_own_artifact manual_tier_rejects_a_waiver_and_stays_inert strict_archive_refuses_an_evaporated_judgment_artifact removed_waiver_cannot_bypass_strict_local_validation exact_judgment_receipt_can_be_reused_but_build_defaults_to_fresh_execution`
  — 9 passed, 0 failed (missing artifact BLOCKED; no `--waive-artifact` flag exists and an
  unknown flag is inert; symlinked artifact reads empty and never exfiltrates; same-actor
  gate is refused by the real gate path; a stale/reused receipt still requires the
  phase's own artifact unless exactly reused; manual tier also rejects a waiver).)
- [x] 4.2 **Extend status incrementally** in current human/JSON structures with separate
  worktree, candidate, gate/freshness, archive, commit, push authorization, transfer,
  remote parity, and install fields. Preserve compatibility. Golden-test all seven
  outcomes plus CURRENT/FAILED/STALE/BLOCKED/MISSING receipts, hostile output, and one
  safe action. Missing/bypassed push auth shows MISSING/BYPASSED, blocks certification,
  and remains missing after parity; adapter state reports exact host/profile/root/canary
  identity, residual metadata/process limitations, incomplete full-suite evidence, and
  the no-fallback blocker. Keep adapter, host, SPI/ABI, fixed profile, root inventory,
  canaries, compiler process tree, full local profile, certified claim, and limitations
  separate; narrower PASS never fills the wider field. Golden-test all six exact adapter
  blocker-code/sole-action pairs, unclassified-to-SPI mapping, no alternative action, and
  no silent effect; human/JSON semantics must match. Cover all seven workflow outcomes
  and typed detail states under TTY, non-TTY, and `NO_COLOR`; exactly
  one JSON stdout document with diagnostics only on stderr; ANSI/OSC/bidi/control/non-
  UTF-8 hostile inputs; broken pipe/signal/panic/crash immediately before and after the
  durable commit boundary; no PASS before commit; post-commit non-success with status
  recovery; idempotent retry with zero duplicate event/effect; and every read-only
  preview ending with `No state changed.`
  (Evidence: `cargo test -p mpd --bin mpd --offline --locked -- workflow_outcomes_receipt_states_and_sandbox_actions_are_canonical`
  — 1 passed (golden-checks the 7 canonical `WorkflowOutcome` JSON strings, the
  MISSING/FAILED/STALE/BLOCKED receipt-state mapping, all 6 adapter blocker-code/
  sole-action pairs including the unclassified-fault-to-`sandbox.spi-abi-drift` mapping
  and the single-path assertion `!action.contains(" or ")`, and that a narrower PASS
  never fills `full_local_profile`/`certified_claim`/`blocker_code`).
  `cargo test -p mpd --test e2e --offline --locked -- status_preserves_gate_history_across_fail_then_pass status_brief_is_compact_and_json_is_unaffected oversized_artifact_reports_unknown_budget_in_status_and_brief`
  — 3 passed. `cargo test -p mpd --bin mpd --offline --locked -- terminal_rendering_strips_control_sequences directive_append_is_sanitized_oversized_dropped_and_weakened_iff_carried extract_section_output_is_bounded_and_terminal_safe`
  — 3 passed (hostile ANSI/OSC/control-character stripping from repository-controlled
  text before it reaches status/next output). 7/7 total, 0 failed. Gap: no dedicated
  test toggles `NO_COLOR`/TTY vs non-TTY — the CLI does not emit ANSI color at all (grep
  found no color-escape emission, only hostile-input stripping), so that clause is
  vacuous rather than separately proven; broken-pipe/signal/panic-at-the-commit-boundary
  and idempotent-retry-zero-duplicate-effect are covered by the candidate/commit tests
  already cited under 2.2/6.1 (`candidate_output_crash_child`,
  `candidate_output_sigkill_boundaries_retry_to_one_output_and_one_ledger_event`), not
  duplicated here.)

## 5. Git-local enforcement

- [x] 5.1 **Implement only `mpd policy activate --commit <oid>
  --confirm-policy-digest <sha256> --coordinator <absolute-mpd>
  --confirm-executable-digest <sha256> --hooks .githooks --yes`:** bind policy, tracked
  wrappers, absolute coordinator, digests, and hooksPath, then report ACTIVE/BLOCKED.
  Reject bootstrap/first-adoption/pretrust fallback. Doctor fails closed on
  missing/drifted binary, wrapper, policy, config, certified host, adapter ABI/symbol, or
  fixed profile digest. Activation readiness never replaces per-run exact roots/canaries.
  Pre-commit stays bounded/read-only over staged secrets and artifact/task consistency.
  Test quoting, drift, interruption, missing coordinator/capability, and no download/
  profile/index mutation or weaker adapter fallback.
  (Evidence: `./target/debug/mpd policy activate --help` shows exactly `--commit
  --confirm-policy-digest --coordinator --confirm-executable-digest --hooks --yes` (no
  more, no less) — matches `cli.rs::PolicyCommand::Activate`. `FirstAdoptionCommand` and
  the standalone `Promote` route are both `#[cfg(test)]`-gated, so the shipped binary
  exposes no bootstrap/first-adoption/pretrust fallback route.
  `cargo test -p mpd --bin mpd --offline --locked -- reviewed_policy_activation_is_single_route_digest_bound_and_idempotent activation_rolls_back_every_persisted_stage_and_resumes_to_verified_active first_adoption_bootstrap_is_same_input_idempotent_and_rejects_different_nonce`
  — 3 passed (single-route digest binding, idempotent re-activation, interrupted-stage
  rollback and resume, and — via `doctor_activation_health` invoked inline — drift
  detection across policy/coordinator/hook bytes and `core.hooksPath`).
  `cargo test -p mpd --test e2e --offline --locked -- pre_commit_fails_closed_on_missing_coordinator_without_mutation pre_commit_uses_staged_governance_and_rejects_malformed_config_without_mutation pre_commit_blocks_governance_rename_without_mutation pre_commit_blocks_governance_deletion_without_mutation pre_commit_accepts_exact_pending_closure_scope_and_blocks_unrelated_paths`
  — 5 passed (pre-commit stays bounded/read-only; missing-coordinator fails closed
  without mutation). `cargo test -p mpd --test e2e --offline --locked -- scoped_doctor_is_versioned_read_only_and_enforce_uses_exit_three`
  (already cited under 3.1's neighborhood) — 1 passed (`doctor --enforce` exits 3 on a
  scoped blocker, 2 when scope is unset, and never executes configured Deploy). 9/9
  total, 0 failed.)
- [x] 5.2 **Complete pre-push** for bounded real input, commits/nested tags, every
  outgoing blob and commit/tag message, and one-invocation authorization bound to remote/
  baseline/rows/object set/policy/nonce. Deletion-only still runs trust/policy/ref checks;
  deny main/tags and require one-use approval elsewhere. Test malformed/mixed/deletion,
  wrong-old/replay/baseline drift/intermediate secrets, and no MPD-owned transport.
  (Evidence: `cargo test -p mpd --test e2e --offline --locked -- pre_push_cli_uses_real_git_field_order_and_rejects_malformed_input pre_push_isolated_global_hook_and_filter_config_cannot_execute_or_mutate`
  — 2 passed (real Git pre-push stdin field order; malformed input rejected; an isolated
  hostile global hook/filter config cannot execute or mutate).
  `cargo test -p mpd --bin mpd --offline --locked -- push_subject_includes_nested_tags_and_excludes_dirty_worktree_bytes outgoing_enumeration_handles_new_force_mixed_delete_multi_ref_and_shared_graphs outgoing_helpers_enforce_read_and_enumeration_caps_without_mutation outgoing_scan_catches_secrets_fresh_despite_preexisting_receipt receipt_note_detects_stale_invalid_and_wrong_subject_evidence exact_subject_policy_excludes_dirty_worktree_config`
  — 6 passed (nested-tag subject inclusion, new/force/mixed/delete/multi-ref/shared-graph
  enumeration, read/enumeration caps without mutation, fresh secret scan despite a
  preexisting receipt, stale/invalid/wrong-subject receipt-note detection). 8/8 total, 0
  failed. mpd never invokes `git push`/`fetch` itself — `hook pre-push` help text: "it
  never pushes, fetches, or writes refs" (no MPD-owned transport).)

## 6. Build and final Deploy

- [x] 6.1 **Bind Build output and Deploy** in existing paths: parent-opened candidate/
  policy/toolchain identity; exclusive target temp, copy/sync/atomic replace/reopen/
  mode-length-digest check; readiness-only truth; fail-closed safe rerun. Remove installed
  candidate execution/rebuild. Test source/output/target replacement, wrong digest,
  interruption/rerun, and a spawn sentinel proving zero execution.
  (Evidence: `cargo test -p mpd --bin mpd --offline --locked -- build_output_rejects_symlink_and_rechecks_copy_identity typed_deploy_copies_once_and_never_executes_the_installed_candidate typed_install_detects_source_destination_and_temp_replacement_and_cleans_temps candidate_output_crash_child candidate_output_sigkill_boundaries_retry_to_one_output_and_one_ledger_event`
  — 5 passed. `typed_deploy_copies_once_and_never_executes_the_installed_candidate`
  plants an executable marker script as the build artifact and asserts
  `!marker.exists()` after install — a real spawn sentinel proving Deploy copies but
  never executes the installed candidate.
  `cargo test -p mpd --test e2e --offline --locked -- deploy_gate_runs_configured_deploy_command deploy_gate_refuses_when_deploy_command_fails deploy_gate_records_readiness_when_no_deploy_configured typed_deploy_paths_stay_ignored_in_a_linked_worktree`
  — 4 passed. 9/9 total, 0 failed.)

## 7. Documentation and empirical closure

- [x] 7.1 **Rewrite durable guidance** in README, AGENTS, Architecture, Security,
  Contributing, runbooks, directives/templates, help, config, and staleness checks. Remove
  planned-as-shipped/pretrust/V2-V5/two-platform claims; document projection, rewind,
  exact-host deprecated-SPI compatibility adapter, residual metadata/process limits,
  private test state, no fallback, current-macOS certification, cooperative bypass, local
  hooks/CI, rerun, and separate delivery facts. Verify every path, flag, and command
  against the built binary.
  (Evidence: fixed two stale `mpd conduct <name> --harness codex` examples — `conduct`
  takes no `--harness` flag (`cli.rs::Command::Conduct` has only `name`/`ui`/`fix`/
  `chore`/`risk`/`threat-profile`; harness is a rendering choice on `next`/`gate`, per
  AGENTS.md's own "Harness and model selection" section) — in `README.md:25` and
  `CONTRIBUTING.md:13`, both corrected to `mpd conduct my-change` /
  `mpd conduct <change-name>` while leaving the correct `mpd next --harness codex
  --context` line untouched. `bash scripts/check-doc-staleness.sh` — PASS (21 current
  Markdown files scanned, 0 stale claims). Spot-verified every `mpd`-specific flag/
  subcommand named in README.md/AGENTS.md/ARCHITECTURE.md/SECURITY.md/CONTRIBUTING.md
  (`archive --recover/--abandon`, `doctor --fix/--scope/--enforce`, `reconcile
  --continue`, `repair-state --to/--reason`, `use <change>`, `hook pre-push`, `policy
  activate` with its five flags, `status --json/--brief`, `gate --pass/--by/--evidence`,
  `check --staged`, `validate --commit/--profile`) against `./target/debug/mpd --help`
  and each subcommand's `--help` — all present, no discrepancies found. No `NO_COLOR`/
  color-related doc claims exist to verify (the binary emits no ANSI color).)
- [x] 7.2 **Run focused adversarial/property suites** for candidate, freshness/risk,
  runner/scanners, adapter control/root/extension/profile/descriptor/inheritance/canary
  boundaries, evidence/status, hooks/push, and Deploy. Include root-in-argv/environment,
  malformed control, partial issue/init/consume, token disclosure, symlink/root races,
  direct reinvocation, child/grandchild escape, post-entry reissue, host/SPI drift, global
  metadata/root disclosure, process signaling, and no-fallback cases. Record seeds,
  commands, counts, exits, runtimes, and omissions; fix through the earliest affected phase.
  (Evidence: test.md — full workspace 579 passed incl. R1/R2 regressions; throughput workload 1 passed 198.6 MB/s; ledger:: 34 + cli:: 18 property tests with committed seeds; receipts e3e6d855/f37b8c61 bind the in-sandbox runs.)
- [ ] 7.3 **Run the exact full local candidate and closure-commit profiles**, proving
  every required lane and complete canary matrix ran with real counts using fixed private
  Git identity/config and private HOME/XDG/temp/process state. Ambient identity/process/
  temp failures block and SHALL NOT be repaired by broader mounts or fallback. Then
  exercise a disposable README-only exact-host clone: cooperative policy/hook activation,
  dirty candidate, stale rewind, gates, closure, archive/commit validation, normal
  non-force push to a bare remote, separate parity, and installed-byte verification. No
  GitHub result, ignored required test count, or nested-compiler-only substitution;
  preserve the real project push/install for final authorized gates.

## Builder completion rule

Builder stops after all 18 boxes have direct evidence. It does not self-approve later
gates or delivery. Any material fix returns to the earliest affected phase and refreshes
the exact-candidate evidence.
