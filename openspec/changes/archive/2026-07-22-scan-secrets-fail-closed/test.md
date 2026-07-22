# Test report

## Actor

Tester (claude-code harness, deep tier — high-risk deep_tier_bump).

## Coverage

**Functional — the fix's behavior (fail-closed on scan error):**
- `scan_secrets_fails_closed_on_tracked_symlink` (checks/mod.rs, `#[cfg(unix)]`,
  Builder): real git repo, `git add`ed symlink to an existing target; vacuity
  guard asserts the symlink is in `git_tracked_files` output; then `scan_secrets`
  errs with the real `"non-regular"` substring and not the file content.
- `scan_secrets_reports_clean_on_regular_files` (checks/mod.rs, Builder):
  benign regular file → `Ok`, empty findings, `scanner == "builtin"`.
- `scan_secrets_fails_closed_on_every_error_class_at_any_position`
  (checks/mod.rs, Tester — deepening): deterministic table (enumeration strictly
  stronger than sampling for this small axis set) covering the error classes the
  symlink test does not — missing/unreadable path at every position 0..=3
  (the TOCTOU window between `git ls-files` and the scan), a directory
  (non-regular, runs on all platforms), and an oversize file (16 MiB+1 via sparse
  `set_len`, cap fires before any read → `"byte cap"`). In-test control: the
  regular-only set is `Ok`/empty, so every `Err` is attributable to the injected
  entry. Aggregate-overflow class omitted (would require reading ≥256 MiB;
  shares the identical single `map_err` propagation path).

**Black-box — caller actually blocks (Security-plan Condition 2, archive-blocker):**
- `check_fails_closed_on_tracked_symlink` (crates/mpd/tests/e2e.rs, `#[cfg(unix)]`,
  Tester): temp repo via the existing `Sandbox` harness; tracks `safe.txt` +
  a `git add`ed symlink `link.txt`; runs non-staged `mpd check`. Vacuity guards:
  `git ls-files` contains `link.txt`, `symlink_metadata` confirms it is a symlink,
  target exists. Asserts exit `== Some(2)` (operational-error path, distinct from
  findings=1 / clean=0); stderr contains `built-in secret scan failed closed`,
  `non-regular`, and `link.txt`; stderr excludes `safe bytes` (no content leak);
  stdout excludes `Checks passed`. **Adequacy (mutation-equivalent):** the pre-fix
  wrapper is still at HEAD (`unwrap_or_default`), and against it this test fails
  (exit 0, "Checks passed") — it detects exactly the regression it guards.

Non-functional / fuzz: not a parser/interpreter/serializer/codec/protocol
(Security concurred) — no fuzz obligation. No performance/resource surface
introduced (the change removes a swallowed error; success path is byte-identical).

## Results

Command: `cargo test -p mpd` (binary crate: unit tests under `--bins`, e2e under
the integration target).
```
(bins)  test result: ok. 478 passed; 0 failed; 1 ignored; 0 measured; 0 filtered out
(e2e)   test result: ok. 107 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out
```
`cargo test --workspace` fully green (incl. openspec-core). `cargo clippy -p mpd
--tests` clean, zero warnings. The 1 ignored is the pre-existing by-design
`#[ignore]` perf test `scoped_digest_throughput_over_10k_paths_100mb`.

Independent verification (orchestrator re-ran, not self-reported): the new e2e
test and the new table test each pass in isolation; `git diff` confirms
production code (wrapper + both callers) and the frozen files
(`secrets.rs`, `git_files`/`git_tracked_files`) are unchanged by the Test phase —
additions are confined to the `mod tests` block of checks/mod.rs and one hunk in
e2e.rs.

No product defect surfaced; the implementation behaved exactly as designed at
both the unit and black-box levels.

## Verdict

PASS — full suite green with a real non-zero count; Security-plan Condition 2
(black-box caller-blocking e2e) satisfied. Ready for Documentation/Deploy.
