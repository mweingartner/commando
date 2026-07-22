# Security (code) review

## Actor

Security (claude-code harness, deep tier — high-risk deep_tier_bump). Code-stage
audit of the real implementation on disk.

## Findings

No code-behavior defect. Two comment-only findings (F1, F2 below), both fixed
inline. The three attacker doors are closed and pinned by tests that bite.

## Conditions verified

Against the real `crates/mpd/src/checks/mod.rs`, `crates/mpd/src/cli.rs`,
`crates/mpd/tests/e2e.rs`:

- **Fail-closed + complete (Cond 1).** `git_tracked_files` (mod.rs:150-158) →
  `Result<Vec<PathBuf>, String>` on `crate::git::ls_files` with `.map_err(...
  "cannot enumerate tracked files: {e}")?`; filter is `symlink_metadata().is_ok()`
  (mod.rs:156), never `exists()`; no default-on-error fallback; `git_files`
  deleted (grep: zero source refs). git-failure/over-cap/non-UTF-8 → `Err`;
  quotepath names verbatim via `-z`; dangling symlinks retained.
- **Ok(empty) vs Err (Cond 1 / advisory A2) — CLOSED.** Zero tracked files →
  `Ok(vec![])` (git exit 0, empty stdout), pinned by
  `git_tracked_files_ok_empty_for_zero_tracked_files` (mod.rs:617-628).
- **Both callers block, no launder (Cond 4).** cmd_gate (cli.rs:3420-3428): `Err`
  → `return Ok(gate_blocked(...))` before allowlist filter, external scanners,
  `secrets_clean = Some(true)`. cmd_check (cli.rs:5220): `?` on both. Caller
  census: exactly two + the mod.rs test.
- **(c) implemented (Cond 3, 7).** Dangling symlink retained → `scan_secrets`
  `Err` "non-regular", no target leak (mod.rs:537-570, still-a-symlink guard);
  worktree-absent omitted, remaining scan Ok (mod.rs:577-611). Regression pins
  (quotepath, dangling) demonstrably bite against pre-fix code.
- **Fixture hygiene (Cond 6).** e2e AKIA fixture assembled via `format!`
  (e2e.rs:1333); `first_party_source_is_scanner_clean` intact.
- **Scope (Cond 10) — CLOSED.** `git diff --stat`: exactly
  `crates/mpd/src/checks/mod.rs`, `crates/mpd/src/cli.rs`,
  `crates/mpd/tests/e2e.rs`, `docs/scan-secrets-fail-closed.md` (350 ins / 35 del,
  4 files). `git.rs`/`secrets.rs`/allowlist byte-unchanged.
- Diagnostics: `GitError` fixed labels only (no raw git output). Doc-narrow
  accurate (no overclaim; preserves the worktree-absent omission).

## Independent review

Fresh-eyes: the `.git`-file git-failure fixture (`gitdir: /nonexistent`) is
hermetic (takes precedence over any outer repo → deterministic exit 128); the
e2e variant is reversible + asserts exit 2 + prefix + no "Checks passed". A1
(terminal-escape sanitization) confirmed NOT addressed here — correctly deferred
(task_d38104fe); this change adds no new path-rendering surface beyond what A1
already prices in.

## Refutation

Strongest attacks: (1) a name class still dropped after `-z` → refuted (verbatim;
non-UTF-8 → whole-enum Err; malformed empty token → root-dir → scan_paths
non-regular → fail closed). (2) D5 as an exclusion primitive → refuted (staged +
egress content-scans cover the stage-then-rm and commit-then-rm cases; residual
predates this change and is a capability the attacker already has). (3) git-failure
blocking a legitimate flow → refuted (fresh repo = Ok(empty), pinned). No new
blocking finding.

## Verdict

**CONDITIONAL PASS** (all conditions now closed).

- **F1 [Medium] — waiver comment mis-attributed authority — FIXED.** The comment
  for the deliberately-skipped `security_code_gate_blocks_when_enumeration_fails`
  e2e (e2e.rs:1376-1387) cited "the plan's explicit allowance"; no such allowance
  exists in design.md/security-plan.md (it was in the orchestrator's Build
  instructions). The skip is technically sound — a candidate-backed gate walk
  hits `candidate::validate_worktree_surface`'s OWN `git::ls_files` first (out of
  scope), so the test would assert on an out-of-scope failure. Reworded to own
  the deviation on its technical merits and explicitly disclaim any
  design-doc allowance.
- **F2 [Low] — stale `exists()` in an assertion message — FIXED.** e2e.rs:1250
  message reworded (the filter is now lstat-presence). Behavior unaffected.
- **Condition 3 (scope attestation) — CLOSED.** `git diff --stat` above confirms
  the 4-file delta; tests run as a real non-zero count in the Build/Test objective
  validations.

## Re-review addendum (F1/F2 fix delta)

F1 and F2 are COMMENT / assertion-message text only — no executable line changed;
the security-relevant surface (`git_tracked_files`, both callers, the six tests'
assertions) is byte-identical to what was audited above. Per the novel-surface
rule this needs no Security re-spawn; the edits stale the Build candidate, so
Build → Security (code) → Test re-run over the corrected tree with the verdict
unchanged. e2e.rs re-compiles clean.
