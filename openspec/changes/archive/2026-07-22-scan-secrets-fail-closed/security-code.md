# Security (code) review

## Actor

Security (claude-code harness, deep tier — high-risk deep_tier_bump). Code-stage
audit of the real implementation on disk.

## Findings

**No defects.** The shipped code is faithful to D1-D6 and Conditions 1-11. No
inline fixes were made; none are needed.

## Conditions verified

Verified against the real code (grep + full read; every caller enumerated
repo-wide):

1. **Fail-closed, no default-on-error (Cond 1)** — `scan_secrets`
   (checks/mod.rs:180-187) is `Result<SecretReport, String>`, body
   `secrets::scan_paths(paths).map_err(|e| format!("built-in secret scan failed
   closed: {e}"))?` then `Ok(...)`. No `unwrap_or_default`/`.ok()`/`.unwrap_or`
   in the wrapper or scanning flow (the only such hits in the file are the
   pre-existing gitleaks tooling paths). ✓
2. **Both call sites block (Cond 1, 3)** — exactly two production callers:
   `cmd_gate` (cli.rs:3419-3429) and `cmd_check` (cli.rs:5212). `cmd_gate`'s
   `Err` arm `return Ok(gate_blocked(&format!("{} gate refused: {e}",
   phase.label())))` sits before the allowlist filter (cli.rs:3431-3432) and
   before `summary.secrets_clean = Some(true)` (cli.rs:3463); `gate_blocked` =
   stderr + exit 1. `cmd_check` propagates via `?` → exit 2. ✓
3. **Allowlist cannot mask an error (Cond 2, D4)** — the filter only ever
   receives `report.findings` from the `Ok` binding; on `Err` both callers leave
   before the filter runs. No path maps `Err` to an empty findings vec. ✓
4. **No content leakage (Cond 4)** — error is `scan_paths`' message (cause +
   `path.display()` only) behind the fixed prefix; std `io::Error` is
   OS-message-only. Test asserts `!err.contains("safe bytes")` (mod.rs:430-433). ✓
5. **Non-vacuous tests (Cond 5, 9, 10)** — `scan_secrets_fails_closed_on_tracked_symlink`
   (mod.rs:385-435, `#[cfg(unix)]`): real git repo, `git add`ed symlink to an
   existing target, **vacuity guard** asserting `link.txt` is in
   `git_tracked_files` output before the error assertion; asserts the real
   `"non-regular"` substring (secrets.rs:301) + absence of content; cleanup.
   `scan_secrets_reports_clean_on_regular_files` (mod.rs:440-457): `Ok`, empty,
   `scanner=="builtin"`. ✓
6. **No fixture secret literals (Cond 6)** — only `"safe bytes\n"` + benign
   filenames; empty-allowlist meta-test passes over this code. ✓
7. **Scope + frozen boundary (Cond 7, 11)** — CLOSED with recorded diff evidence
   (Condition 1 below): `git diff HEAD` on `secrets.rs` and `e2e.rs` is EMPTY;
   `mod.rs`+`cli.rs` show exactly four hunks — `@172` wrapper, `@372` two tests,
   `@3418` cmd_gate, `@5201` cmd_check — and `git_files`/`git_tracked_files`
   appear in no hunk. ✓
8. **Success path byte-identical (Cond 8)** — `Ok` path yields `scanner:"builtin"`
   and the unchanged downstream flow; `mpd check` clean line + exit 0 intact. ✓

## Independent review

Deep-tier re-audit beyond the plan's sight: `phase.label()` (phase.rs:270-285) is
a total match returning `"Security (code)"` for `SecurityCode` — cannot panic;
`requires_secret_scan` = `matches!(self, SecurityCode)` so the changed branch
fires only where intended. No `.unwrap()`/`.expect()` in new production code
(only `match` + `?` + a formatting `map_err`). `let scanner = report.scanner;`
copies a `&'static str` before `report.findings` moves into the filter — no
borrow workaround. No new `#[allow(...)]`/clippy suppression in either hunk.

## Refutation

Strongest attack attempted: *can any error still be laundered to "clean"?* Traced
every path — the old `unwrap_or_default()` is deleted and nothing replaced it; on
`Err`, `cmd_gate` returns before the allowlist/`secrets_clean` write and
`cmd_check` propagates before its filter. The remaining fail-open surface is the
**enumeration boundary** `git_files` (empty-on-git-failure, `core.quotepath`
drop, dangling symlink) — deliberately frozen here (Cond 11) and tracked as a
named follow-up; compensated at egress by the path-independent pre-push blob
scan. Refutation fails for the scanning boundary; the enumeration residual is
disclosed, not hidden.

## Verdict

**CONDITIONAL PASS.**

- **Condition 1 [Low — orchestrator] — CLOSED.** Mechanical byte-identity scope
  check the read-only reviewer could not run. Evidence: `git diff HEAD --
  crates/mpd/src/checks/secrets.rs crates/mpd/tests/e2e.rs` is empty; the
  `mod.rs`/`cli.rs` hunks are exactly the four listed above; `git_files`/
  `git_tracked_files` untouched. Recorded here.
- **Condition 2 [Medium — Tester, pre-Test gate] — CARRIED, OPEN.** The plan-stage
  black-box e2e (`mpd check` exits non-zero on a tracked symlink,
  crates/mpd/tests/e2e.rs) is still absent; it blocks the Test gate / archive,
  not this gate. Tracked as open condition security-plan.1/.2.

No inline fixes; the code is verified secure at the scanning boundary. Per the
novel-surface rule, if any change lands outside the four reviewed hunks this gate
is invalidated and must re-run.

Advisories (non-blocking): live doc drift at secrets.rs:279-281 / :508 and
docs/secret-fixture-hygiene.md (owned by the follow-up, not edited here); CI is
absent (.github/workflows/ci.yml deleted) so these regression tests are
locally-enforced only — recommend restoring a `cargo test` + gitleaks workflow.

## Re-review addendum (Test-phase delta)

The Test phase added test-only code, staling the Build candidate and rewinding to
Build; re-driving Build → Security (code) → Test. The delta since the PASS above,
reviewed under the novel-surface re-run rule:
- `crates/mpd/tests/e2e.rs` — one added hunk: `check_fails_closed_on_tracked_symlink`
  (the Condition-2 black-box test).
- `crates/mpd/src/checks/mod.rs` — the `mod tests` block grew by one test
  (`scan_secrets_fails_closed_on_every_error_class_at_any_position`); the four
  production/reviewed hunks (@172 wrapper, @3418 cmd_gate, @5201 cmd_check) are
  byte-identical.
Assessment: **no re-audit finding.** The delta is pure test code — no production
or frozen-boundary change (`git diff` on secrets.rs, e2e-production, and
`git_files`/`git_tracked_files` remains empty/frozen), no secret-shaped literals
(fixtures use `"safe bytes\n"` only; the empty-allowlist meta-test
`first_party_source_is_scanner_clean` passes over the new code — machine-enforced
in both the Build and Test objective validations), and the additions strengthen
rather than weaken the control (they add error-class and black-box coverage). The
scanning-boundary verdict stands: **CONDITIONAL PASS**, Condition 1 closed,
Condition 2 now satisfied by the added e2e test (resolved at Test).
