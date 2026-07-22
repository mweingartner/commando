## 1. Enumeration (crates/mpd/src/checks/mod.rs)

- [ ] 1.1 `git_tracked_files -> Result<Vec<PathBuf>, String>` built on `crate::git::ls_files`; error prefix "cannot enumerate tracked files: {e}"; lstat-presence filter (`symlink_metadata().is_ok()`), never `exists()`; doc comment states the fail-closed contract and the single intentional omission (worktree-absent paths).
- [ ] 1.2 Delete `git_files` (no remaining callers).

## 2. Callers (crates/mpd/src/cli.rs)

- [ ] 2.1 `cmd_gate` @3419: match the enumeration result; `Err(e)` → `return Ok(gate_blocked(&format!("{} gate refused: {e}", phase.label())))` before allowlist/external scanners/`secrets_clean`.
- [ ] 2.2 `cmd_check` @5212: `checks::scan_secrets(&checks::git_tracked_files(&root)?)?`.
- [ ] 2.3 `cargo build` — compiler confirms no other call sites.

## 3. Unit regression pins (checks/mod.rs `mod tests`)

- [ ] 3.1 Update `scan_secrets_fails_closed_on_tracked_symlink` @418 to `.expect(...)`; reword stale `exists()` comments.
- [ ] 3.2 `git_tracked_files_fails_closed_when_git_fails` — `.git` gitfile → `/nonexistent`; assert Err with the "cannot enumerate tracked files" prefix.
- [ ] 3.3 `git_tracked_files_retains_quotepath_quoted_names` — `core.quotepath=true`; vacuity guard on octal-quoted line-mode output; `sécrets.txt` retained. (Must fail against pre-fix code.)
- [ ] 3.4 `git_tracked_files_retains_dangling_symlink_and_scan_fails_closed` (#[cfg(unix)]) — retained; `scan_secrets` errs "non-regular", no fixture bytes in the error. (Must fail against pre-fix code.)
- [ ] 3.5 `git_tracked_files_skips_worktree_absent_tracked_path` — unstaged deletion omitted; remaining scan Ok.

## 4. Black-box e2e (crates/mpd/tests/e2e.rs)

- [ ] 4.1 Fix stale `git_files`/`exists()` comment (~@1216-1217).
- [ ] 4.2 `check_blocks_when_enumeration_fails` — exit 2, stderr "cannot enumerate tracked files", no "Checks passed".
- [ ] 4.3 `security_code_gate_blocks_when_enumeration_fails` — walk to security-code, break git (reversible gitfile), gate refused with the diagnostic, restore, phase still "security-code".
- [ ] 4.4 `check_scans_quotepath_quoted_tracked_file` — `sécrets.txt` + assembled `AKIA`+`IOSFODNN7EXAMPLE`; quoting vacuity guard; exit 1; stderr has "crets.txt" and "aws-access-key-id".

## 5. Spec + docs

- [ ] 5.1 Spec delta: MODIFIED boundary note + ADDED "Fail-closed tracked-file enumeration" with four scenarios.
- [ ] 5.2 Narrow `docs/scan-secrets-fail-closed.md` Scope residual bullet (enumeration now closed; name the intentional omission; keep the diagnostics bullet). No literal secret example.

## 6. Verification & landing

- [ ] 6.1 Full suite green with real non-zero count; `first_party_source_is_scanner_clean` green; gitleaks/semgrep gates green.
- [ ] 6.2 Confirm pins 3.3/3.4 fail against pre-fix enumeration.
- [ ] 6.3 Rebuild release coordinator; `mpd policy activate` re-activation BEFORE commit (crates/** changed; activation binds the coordinator digest).
- [ ] 6.4 Confirm this tree has no dangling tracked symlinks / quotable-named tracked files so self-hosted `mpd check` stays green.
