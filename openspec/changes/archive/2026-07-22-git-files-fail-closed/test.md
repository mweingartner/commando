# Test report

## Actor

Tester (claude-code harness). The Builder wrote the full test set (Security-code
verified it non-tautological); this phase confirms it at scale.

## Coverage

**Unit (checks/mod.rs):** `git_tracked_files_fails_closed_when_git_fails`
(hermetic broken-`.git` → Err); `git_tracked_files_retains_quotepath_quoted_names`
(`core.quotepath=true` + `sécrets.txt`, vacuity guard on octal-quoted line-mode
output — bites against pre-fix code); `git_tracked_files_retains_dangling_symlink_and_scan_fails_closed`
(#[cfg(unix)], retained → `scan_secrets` Err "non-regular" — bites pre-fix);
`git_tracked_files_skips_worktree_absent_tracked_path` (D5 omission);
`git_tracked_files_ok_empty_for_zero_tracked_files` (advisory A2 — empty is
legitimate clean); updated `scan_secrets_fails_closed_on_tracked_symlink`.

**Black-box e2e (tests/e2e.rs):** `check_blocks_when_enumeration_fails` (broken
git → exit 2, "cannot enumerate tracked files", no "Checks passed");
`check_scans_quotepath_quoted_tracked_file` (`sécrets.txt` + assembled AKIA →
exit 1, stderr has "crets.txt" + "aws-access-key-id"). The security-code gate
walk was intentionally skipped (candidate validation's own ls_files fails first —
out of scope; documented at e2e.rs).

Not a novel parser surface beyond git.rs's already-tested NUL parsing; property
invariants (completeness, fail-closed dichotomy, no-disclosure) are covered by
the example pins + git.rs's existing `nul_tokens` tests.

## Results

`cargo test -p mpd`: bins **492 passed; 0 failed; 1 ignored** (pre-existing perf
`#[ignore]`); e2e **109 passed; 0 failed**. `cargo test --workspace` green;
`cargo clippy -p mpd --tests` clean; `cargo fmt --check` clean. Orchestrator
independently re-ran the 5 unit + 2 e2e enumeration tests (all green) and
confirmed the two regression pins fail against the pre-fix enumeration.
`first_party_source_is_scanner_clean` green (AKIA fixture assembled via format!).

## Verdict

PASS — full suite green with a real non-zero count; the three attacker doors
(git-failure vacuous-clean, quotepath name exclusion, break-the-link symlink
bypass) are closed and pinned by tests that bite; the sole intentional omission
(worktree-absent paths) is pinned. No product defect.
