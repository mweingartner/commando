## 1. Wrapper (crates/mpd/src/checks/mod.rs)

- [ ] 1.1 Change `scan_secrets` to `-> Result<SecretReport, String>`; map `scan_paths` errors via `format!("built-in secret scan failed closed: {e}")` and `?`; delete `unwrap_or_default()`.
- [ ] 1.2 Update its doc comment: errors propagate, callers must block.

## 2. Callers (crates/mpd/src/cli.rs)

- [ ] 2.1 `cmd_gate` secret-gate branch: `match` the result; on `Err(e)` `return Ok(gate_blocked(&format!("{} gate refused: {e}", phase.label())))`, before any allowlist filtering.
- [ ] 2.2 `cmd_check` non-staged branch: append `?`, symmetric with the staged branch.
- [ ] 2.3 `cargo build` — confirm no other call sites (compiler-verified).

## 3. Regression tests (crates/mpd/src/checks/mod.rs, existing `mod tests`)

- [ ] 3.1 `scan_secrets_fails_closed_on_tracked_symlink` (#[cfg(unix)]): temp git repo, benign `safe.txt` + `git add`ed symlink to it; assert symlink present in `git_tracked_files` output; assert `scan_secrets` errs mentioning "non-regular"; assert error excludes file content bytes; cleanup.
- [ ] 3.2 `scan_secrets_reports_clean_on_regular_files`: regular benign file → `Ok`, empty findings, scanner "builtin".
- [ ] 3.3 Confirm `first_party_source_is_scanner_clean` still passes (no secret-shaped literals introduced).

## 4. Black-box caller test (crates/mpd/tests/e2e.rs) — SECURITY(plan) Condition 2, Tester

- [ ] 4.1 e2e assertion: a temp git repo with a `git add`ed tracked symlink (target existing) makes non-staged `mpd check` exit non-zero with the fail-closed diagnostic on stderr and NOT print the clean-scan success line. Proves the caller actually blocks (compile-enforcement alone does not).

## 5. Spec (openspec/specs/local-validation/spec.md — via change delta)

- [ ] 5.1 Add "Fail-closed built-in secret scan" requirement + two scenarios, scoped to the scanner-input boundary with the enumeration boundary named as an accepted residual.

## 6. Verification

- [ ] 6.1 Full suite green with a real non-zero count (`cargo test`).
- [ ] 6.2 Confirm this repo has no tracked symlinks (`git ls-files -s | awk '$1 == 120000'`) so self-hosted gates stay green.
- [ ] 6.3 Freeze the enumeration boundary: no change to `git_files`/`git_tracked_files` filtering (Builder condition 11).
- [ ] 6.4 Flag (not fix) stale fail-open references: `crates/mpd/src/checks/secrets.rs:506-511` and `:279-281` doc comments; `docs/secret-fixture-hygiene.md`. File the `git_files` enumeration-boundary hardening follow-up.
