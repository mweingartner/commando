# Security (code): Candidate scope integrity — attempt 2 (fix verification)

## Actor
Security (code reviewer, attempt 2, claude-code harness) — adversarial security persona, distinct from the Architect and the Builder.

## Findings

Attempt 1 raised five findings. All five are REMEDIATED on the code actually on disk; no new finding was introduced by the fixes.

### Finding 1 [HIGH] — archive digest loop compared every Architecture postimage to design.md's digest — REMEDIATED
- **Fix location:** `cli.rs:6873-6877` (`is_phase_judgment_artifact`) and `cli.rs:7308-7310` (the `cmd_archive` postimage loop).
- **Verified:** `is_phase_judgment_artifact(phase, filename)` is a pure predicate — `phase.judgment_artifact().is_some_and(|(name, _)| name == filename)` — true ONLY for the exact file `Phase::judgment_artifact()` names. The archive loop routes a postimage through `verify_judgment_artifact_digest` only under that predicate. Consequences confirmed against `Phase::judgment_artifact` (phase.rs:123-151) and `closure::canonical_phase_artifact_names` (closure.rs:530-543):
  - Architecture (the sole multi-file phase): only `design.md` is digest-checked; `proposal.md`/`tasks.md` return false and remain covered by the `ArchitecturePlan` freshness key — a legitimate archive no longer false-fails on siblings.
  - Documentation (`judgment_artifact()` → `None`): never routed, so no spurious legacy-record warning.
  - The pin is preserved, not defeated: `design.md` always flows through the check (Architecture never skips; the loop hard-errors on a missing gate record at cli.rs:7289-7291); a PRESENT digest mismatch is still unconditionally fatal (cli.rs:6896-6907).
- **Verifying tests:** `is_phase_judgment_artifact_selects_only_the_judgment_artifact_file` (cli.rs:9478), `archive_digest_loop_pins_design_md_only_not_its_architecture_siblings` (cli.rs:9511 — all-three-clean passes, mutated `design.md` fails naming it, mutated `proposal.md` with clean `design.md` passes), `verify_judgment_artifact_digest_never_downgrades_a_mismatch_and_accepts_legacy_absence` (cli.rs:9435).
- **C5 end-to-end:** with the false comparison removed, a legitimate candidate-backed archive succeeds while `design.md` tampering after its gate still refuses. C5 now genuinely HOLDS end-to-end.

### Finding 2 [MEDIUM] — `enforce_landing_commit_scope` exempted 4 policy paths from D5b — REMEDIATED
- **Fix location:** `cli.rs:5854-5914`. The `policy_path` exemption is gone: the offender filter is solely `!closure::allowed(&record.allowed_paths, path)` (cli.rs:5894-5898), applied to BOTH sides of every rename/copy entry (cli.rs:5860). The comment now states D5b's literal contract.
- **Pre-existing non-landing sites untouched:** the `policy_path` carve-outs at cli.rs:5375/5512/5541 are the ordinary/pending/fallback `staged_precommit_governance` paths, as before. They cannot re-open the landing hole: the pre-commit hook runs `staged_precommit_governance` and then `enforce_landing_commit_scope` unconditionally (cli.rs:5923-5924), and any landing commit stages `openspec/changes/archive/**`, so the exemption-free check always applies; `publish --verify` purity/equivalence remains the final authority behind `--no-verify`.
- **Legitimate policy-declaring change still lands:** a change that declares `.mpd/config.json` in its manifest gets it into `allowed_paths` (cli.rs:7361-7365) and passes on that declared basis.
- **Verifying test:** `enforce_landing_commit_scope_refuses_an_undeclared_policy_path_but_allows_a_declared_one` (cli.rs:9800).

### Finding 3 [LOW] — reuse-branch lenient config load — REMEDIATED
- **Fix location:** `cli.rs:3580` — the Build/Test `--reuse` prose lane now calls `enforce_prose_secret_scan(&root, &change, &Config::load_strict(&root)?)`, parity with the execute path (cli.rs:3700/3748). `Config::load_strict` (config.rs:1007-1016) never converts missing/unsafe/oversized/malformed policy bytes into defaults, so a corrupted config can no longer silently drop gitleaks' `required` status on the reuse path.
- **Note (not a defect):** `Config::load` remains at cli.rs:3553/4125 for `capture_dependency_values` — dependency capture, not a trust decision; a lenient load there only perturbs captured values (receipt mismatch → fresh execution, fail-safe), symmetric with the execute path.

### Finding 4 [LOW] — `exists()`-based trust of the repo-root gitleaks config — REMEDIATED
- **Fix location:** `checks/mod.rs:96-120`. Trust is now `symlink_metadata` + explicit `!is_symlink() && is_file()`, `unwrap_or(false)`; a symlinked/non-regular `.gitleaks.toml` falls back to the ephemeral extend-default config (0600, `O_EXCL`+`O_NOFOLLOW`, unpredictable pid+nonce path — checks/mod.rs:142-164). Both branches still always pass explicit `-c` (Condition 1 preserved). A non-UTF-8 config path yields `None` → requiredness turns it into a gate refusal, never an un-configured invocation.
- **Verifying test:** `run_gitleaks_refuses_a_symlinked_repo_root_config_and_falls_back_to_ephemeral` (checks/mod.rs:491).

### Finding 5 [LOW] — `scan_change_prose` UTF-8-validate/rescan TOCTOU — REMEDIATED
- **Fix location:** `checks/mod.rs:228-245` (`scan_validated_bytes`) and `:266-310` (`scan_change_prose`). Each regular-file artifact is read exactly once (fs::read at :276), UTF-8-validated on that buffer (:279), and scanned via `scan_validated_bytes` against that SAME buffer (:282) — no second `fs::read` anywhere in the lane, so a co-writer can no longer swap content between the validating read and the scan.
- **Fail-closed refusals preserved:** a symlinked artifact is retained and routed through `scan_secrets` → `secrets::scan_paths`, whose non-regular refusal blocks; a non-symlink non-regular artifact refuses directly (:286-290); only `NotFound` skips (:291); every other stat error blocks; non-UTF-8 is a hard refusal.
- **Equivalence to `secrets`' own scanning (in-scope implementation via public API):** `scan_validated_bytes` composes exactly the primitives `scan_paths` uses — `suspicious_filename` (secrets.rs:25) and `scan_text` (secrets.rs:97) — so filename and content rules are byte-identical. Per-file cap mirrors `MAX_FILE_BYTES` at 16 MiB. The one `scan_paths` check not replicated — the 256 MiB aggregate cap — cannot fire here: at most 11 artifacts × 16 MiB = 176 MiB < 256 MiB. Net behavior is identical-or-stricter (strict UTF-8 refusal is stricter than `scan_paths`' lossy conversion).
- **Verifying tests:** `scan_validated_bytes_scans_the_given_buffer_never_touching_disk` (checks/mod.rs:1025), `scan_change_prose_detects_a_real_secret_in_a_regular_artifact` (:1042), `scan_change_prose_retains_a_symlinked_artifact_so_the_scan_fails_closed` (:998), `scan_change_prose_skips_absent_artifacts_but_fails_closed_on_other_errors` (:952).

### New findings
None. One non-blocking hardening observation, NOT introduced by these fixes (pre-dates them): `scan_change_prose`'s single read is an unbounded `fs::read` with the 16 MiB cap enforced post-read; a bounded `take(cap + 1)` read would additionally bound peak memory on a maliciously huge artifact. Detection/blocking unaffected — oversize still refuses closed. Severity Low, advisory only.

## Conditions verified

All ten security-plan.md conditions verified against the post-fix tree. C1-C4 and C6-C10 verified HOLD at attempt 1; re-checked here at the fix-touched surfaces (cli.rs, checks/mod.rs) for regression.

- **C1 (gitleaks config pinning) — HOLDS.** Always explicit `-c` in both branches (checks/mod.rs:107-131); repo-root trust now regular-file-only (Finding 4 strengthens); `enforce_prose_secret_scan` refuses an in-change-dir `.gitleaks.toml`/`.gitleaksignore` (cli.rs:3286-3292); subdirectory-config evasion pinned (checks/mod.rs:520).
- **C2 (requiredness parity) — HOLDS.** `gitleaks_lane_verdict` refuses on unavailable-but-required (cli.rs:3326-3337); requiredness read via `Config::load_strict` on BOTH execute (cli.rs:3700) and reuse (cli.rs:3580 — Finding 3 fix) paths; pinned (cli.rs:9610).
- **C3 (stat/encoding fail-closed) — HOLDS.** Only `NotFound` skips; other stat errors block; non-UTF-8 hard-refuses; symlinks retained into the fail-closed path (checks/mod.rs:266-310); Finding 5 fix strengthens.
- **C4 (ordering at all five lanes) — HOLDS, no regression.** Build execute (cli.rs:3748), Security(code)/Test execute (cli.rs:3766), Build/Test `--reuse` (cli.rs:3580, before `evaluate_strict_objective_reuse` at :3587) — drift guard first, prose lane second, capture/reopen last, at every lane.
- **C5 (D6 digest integrity) — NOW HOLDS END-TO-END.** Recording side unchanged and correct (digest from the single `strict_artifact_issues`-validated buffer on both execute cli.rs:4072-4082 and reuse cli.rs:3520-3534; `read_contained` symlink-refusing). Verification side fixed: attempt 1's false-positive sibling comparison gone (Finding 1); mismatch remains unconditionally fatal; legacy-absent remains a printed warning naming phase+file (cli.rs:6890-6918).
- **C6 (prune/inventory fail-closed) — HOLDS.** `candidate.rs` untouched this round; attempt-1 verification stands.
- **C7 (D5b completeness) — HOLDS, strengthened.** Both rename/copy sides checked (cli.rs:5860); malformed name, unreadable ledger, missing `archive_closure` each block; non-landing commits untouched; Finding 2 removed the last carve-out. Tests cli.rs:9711/9749/9846/9800.
- **C8 (schema boundary) — HOLDS.** Untouched; attempt-1 verification stands.
- **C9 (single source of truth) — HOLDS.** `scan_change_prose` still enumerates via `closure::change_process_artifact_paths` (checks/mod.rs:269); byte-threading changed how bytes are scanned, not which paths.
- **C10 (commit-floor pinning) — HOLDS.** `scan_staged_postimages` unchanged (checks/mod.rs:333-362); attempt-1 e2e stands.

## Independent review

I re-read every fix-touched surface on disk rather than trusting the Builder's description: cli.rs:3513-3650 (reuse branch), :3700-3800 (execute lanes), :4066-4143 (record construction), :4615-4704 (artifact validation/byte threading), :5340-5560 (governance sites), :5824-5924 (D5b + hook wiring), :6863-6918 (predicate + digest), :7240-7380 (archive loop + closure scope), :9400-9880 (tests); checks/mod.rs in full; secrets.rs:25-38/:97-110/:381-426; phase.rs:113-151; closure.rs:530-543. Scope discipline confirmed: remediations live entirely in cli.rs and checks/mod.rs (both manifest-declared); the Finding 5 implementation composes `secrets`' existing public API (keeps secrets.rs untouched, behaviorally equivalent-or-stricter, 176 MiB < 256 MiB bound). Honest limits: (1) read-only tooling — named tests verified to exist and assert the right behavior by reading; the strict gate's machine-run profile remains the executing authority. (2) No e2e drives the candidate-backed archive loop end-to-end through the real binary — the pre-existing, documented trusted-policy-wall gap (e2e.rs:2404-2416); the unit test at cli.rs:9511 replicates the loop's exact gating. (3) Deterministic backstops present (built-in scanner floor + gitleaks/semgrep, `.githooks`, Semgrep config, Dependabot) — this review is layered on automated gates.

## Refutation

Attacks attempted against each fix, all defeated:
1. **Bypass `is_phase_judgment_artifact` to skip a real `design.md` tamper?** The predicate's inputs are a `Phase` enum and a filename from the static `canonical_phase_artifact_names` table — neither attacker-influenced at archive time. For it to return false for (Architecture, "design.md"), `Phase::judgment_artifact()` would have to change — a reviewed source change pinned by `judgment_artifacts_map_judgment_phases_only` (phase.rs:392). Architecture never skips, the gate record is mandatory (cli.rs:7289), strict gates always record `Some(digest)` — the tamper check cannot be starved into the legacy arm without editing the ledger (the accepted local-tamper class, backstopped by `scoped_commit_equivalence`).
2. **Does removing the D5b exemption open anything?** No — strictly narrowing; the refusal set only grows. The non-landing carve-outs can't resurrect the hole (the hook runs the exemption-free landing check unconditionally, cli.rs:5923-5924; a landing commit always stages `openspec/changes/archive/**`). Legitimate flows unbroken (closure paths enter `allowed_paths` via `system.paths()`; a policy-touching change passes by declaring the path — both test-pinned).
3. **Starve the strict loader?** `Config::load_strict` failing at cli.rs:3580 propagates as an error — the gate refuses rather than degrading to defaults. Fail-closed.
4. **Race or alias the repo-root gitleaks config?** A hardlink/race requires repo-root write access — the same local-writer trust class as authoring the reviewed config; no privilege gained. The symlink vector (crossing a trust boundary outside reviewed content) is closed and test-pinned.
5. **Defeat the byte-threading?** A co-writer swapping the artifact after the single read changes nothing: the scanned bytes ARE the validated bytes; swapped-on-disk content is separately caught by the staged pre-commit scan (C10) and pre-push floor. Symlink/FIFO route to the fail-closed arms.

## Verdict

PASS

All five attempt-1 findings are remediated correctly and completely at the cited locations, each pinned by a dedicated test; Conditions 1-10 all HOLD, with C5 now holding end-to-end (the archive digest loop pins exactly the judgment artifact — a legitimate archive succeeds and a tampered `design.md` still refuses fatally); the fixes are strictly narrowing or equivalence-preserving and open no new secret-smuggling or validation-evasion path. This is High-risk novel surface: this verdict is the required post-fix Security (code) re-run, and no further inline fixes are outstanding.
