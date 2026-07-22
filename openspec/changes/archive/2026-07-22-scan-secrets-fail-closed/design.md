# Design: Fail-closed `scan_secrets` (built-in secret-scan wrapper)

## Actor

Architect (claude-code harness, deep tier).

## Context

`checks::scan_secrets` (`crates/mpd/src/checks/mod.rs:175`) is the only fail-open
scanner entry point in `checks/`. `secrets::scan_paths`
(`crates/mpd/src/checks/secrets.rs:287`) returns `io::Result<Vec<Finding>>` and
deliberately errors on: a symlink or other non-regular file (secrets.rs:299-304),
a file over the 16 MiB per-file cap (305-311), aggregate-size overflow (312-314),
aggregate over the 256 MiB cap (315-319), and unreadable metadata/bytes (`?`).
`scan_secrets` discards all of that with `unwrap_or_default()`, so an incomplete
scan is reported as clean.

Both callers already have a blocking-failure channel:
- `cmd_gate(...) -> CmdResult` (`cli.rs`, `type CmdResult = Result<i32, String>`)
  — the secret-scan branch (cli.rs:3421) runs only for the phase where
  `requires_secret_scan()` is true (`SecurityCode`, `phase.rs:102-104`). Every
  sibling failure in this branch is a gate *refusal* via `gate_blocked(msg)`
  (stderr + exit 1): test gate, findings, external scanners. The allowlist
  filter runs *after* the scan (cli.rs:3423-3424).
- `cmd_check(staged, quiet) -> CmdResult` — the `staged` branch already does
  `checks::scan_staged_postimages(&root)?`, proving `String` errors propagate via
  `?` with no conversion (CmdResult's error *is* `String`); `run()` maps `Err`
  to `error: {msg}`, exit 2.

`git_files` filters through `Path::exists()` (checks/mod.rs:158), which follows
symlinks — so a *tracked* symlink is retained in the scan set only when its
target exists (a dangling tracked symlink is silently dropped upstream; see
Risks). The test module `#[cfg(test)] mod tests` at checks/mod.rs:217 has an
established temp-git-repo fixture pattern. `first_party_source_is_scanner_clean`
(secrets.rs:513) scans `crates/**` with an empty allowlist — fixtures must carry
no secret-shaped literals; the symlink test needs none (the error fires before
any content is scanned).

This file is the canonical current-state contract. Move superseded drafts and
reviews to `history/`; do not accumulate contradictory amendments here.

## Goals / Non-Goals

**Goals.** Every `scan_paths` error surfaces as a blocking, non-zero-exit failure
at both call sites; the compiler enforces caller handling (a `Result` cannot be
ignored); the tracked-symlink case is regression-tested end-to-end through the
real caller composition (`git_tracked_files` → `scan_secrets`).

**Non-Goals.** No change to `secrets::scan_paths` (already correct). No change to
`scan_staged_postimages`, external scanners, pre-push, or structured profiles. No
new handling for dangling tracked symlinks dropped by `git_files`' `exists()`
filter (pre-existing, lower severity — Risks). No e2e.rs edit (out of scope).

## Decisions

**D1 — Signature mirrors `scan_staged_postimages` exactly.**
`pub fn scan_secrets(paths: &[PathBuf]) -> Result<SecretReport, String>`. Body:
`let findings = secrets::scan_paths(paths).map_err(|e| format!("built-in secret
scan failed closed: {e}"))?;` then `Ok(SecretReport { scanner: "builtin",
findings })`. Doc comment gains a sentence: any scanner error is propagated as
`Err` (never an empty report) and callers must treat it as blocking.
*Rationale:* identical error type and doctrine as the sibling; `scan_paths`
messages already name cause + path without file contents. *Alternative rejected:*
returning `io::Result` — would force conversion at both call sites and diverge
from the established `Result<_, String>` idiom.

**D2 — `cmd_gate` blocks via `gate_blocked`, not `?`.** Replace the call at
cli.rs:3421 with a `match`; on `Err(e)` `return Ok(gate_blocked(&format!("{}
gate refused: {e}", phase.label())))`. *Rationale:* every sibling failure in
this branch is a gate refusal (stderr + exit 1), not an operational `Err` (exit
2). A scan that cannot complete is a refusal: the gate ran and said no. This also
makes `summary.secrets_clean = Some(true)` unreachable on error. *Alternative
rejected:* `.map_err(...)?` — blocks too, but breaks the function's
refusal/operational-error distinction and would exit 2 mid-gate.

**D3 — `cmd_check` propagates with `?`.** Non-staged branch (cli.rs:5204) becomes
`checks::scan_secrets(&checks::git_tracked_files(&root))?`. *Rationale:* the
staged branch already proves the identity conversion; both branches now fail the
same way (exit 2). The exit-1 `failed` path stays reserved for *findings*.

**D4 — Error resolves before the allowlist.** In both callers the `match`/`?` on
`scan_secrets` happens strictly before `Allowlist::load(&root).filter(...)`. An
`Err` structurally never reaches the filter, so an incomplete scan can never be
laundered into "0 findings, allowlist-filtered, clean".

**D5 — Regression tests in `checks/mod.rs`'s existing `mod tests`.** Two tests
modeled on the git fixture pattern: (a)
`scan_secrets_fails_closed_on_tracked_symlink` (`#[cfg(unix)]`): temp dir →
`git init` + identity → write `safe.txt` = "safe bytes\n" → `symlink("safe.txt",
root/"link.txt")` → `git add` both → `files = git_tracked_files(&root)` → assert
the symlink path is present (proves a tracked symlink survives the `exists()`
filter; target must exist) → `scan_secrets(&files).unwrap_err()` → assert the
error mentions "non-regular" and does NOT contain "safe bytes" (no content leak)
→ cleanup. (b) `scan_secrets_reports_clean_on_regular_files`: a benign regular
file → `Ok`, empty findings, `scanner == "builtin"` (guards against inverting the
fix). No secret literal in either fixture.

**D6 — Caller fail-closed is compile-enforced; e2e is flagged, not planned.**
`cmd_gate`/`cmd_check` resolve the repo from the process cwd and no existing test
uses `set_current_dir` (racy under parallel tests). The `Result` signature makes
an unhandled error a compile failure and D2/D3 pin the exact handling. A
black-box `mpd check` assertion belongs in `crates/mpd/tests/e2e.rs` (pattern at
its ~line 2905) but that file is out of declared scope — flagged for the Tester /
scope owner, not planned here.

## Risks / Trade-offs

- [Newly-blocking repos] A consumer repo with a tracked symlink or oversize
  tracked file now blocks where it previously (unknowingly) skipped scanning.
  → Intentional; the diagnostic names the path and cause; remediation is fixing
  the tree (or migrating gates to structured validation).
- [Exit-code asymmetry] Gate refusal exits 1 (`gate_blocked`); `mpd check` exits
  2 (`Err`). → Matches each function's existing idioms; both are non-zero and
  fail closed.
- [Enumeration-boundary residuals, out of scope — SECURITY(plan) Condition 1]
  This change closes the *scanning* boundary (`scan_secrets`/`scan_paths`) but
  not the *enumeration* boundary that builds the scan set, `git_files`
  (checks/mod.rs:146-159), which retains three silent-drop doors. Naming all
  three honestly:
  (a) **git-failure → vacuous clean.** If the `git ls-files` spawn fails or exits
      non-zero, `git_files` returns `Vec::new()` (mod.rs:148-153); `scan_secrets(&[])`
      is then `Ok` with zero findings and the SecurityCode gate records
      `secrets_clean = Some(true)` having scanned nothing. Same "incomplete scan
      reported clean" class, one function upstream.
  (b) **`core.quotepath` drop — attacker-controllable.** `git ls-files` is invoked
      without `-z`/`-c core.quotepath=false`, so a tracked path with non-ASCII
      bytes (or `"`/`\`) is emitted C-quoted; `root.join(quoted)` names a
      nonexistent path and the `exists()` filter (mod.rs:158) drops it. A local
      actor can exclude a secret-bearing regular file from the builtin gate scan
      by naming it e.g. `sécrets.txt`.
  (c) **dangling tracked symlinks** — dropped by the same `exists()` filter; no
      worktree content to leak, only the filename rule + target text go unscanned.
  → Compensated at egress: the staged-postimage scan applies filename rules and
  scans blob text (mod.rs:198-208), and the pre-push outgoing scan scans every
  outgoing blob content-wise with no path dependence
  (local_validation.rs:6777-6784); pre-commit rejects quoted staged paths via
  `validate_canonical_path` (mod.rs:195-196). These downgrade but do not make the
  SecurityCode gate's `secrets_clean:true` fully honest. Deliberately NOT widened
  here (keeps this change to the user-scoped wrapper fix); tracked as a named
  follow-up: harden `git_files` (`git ls-files -z -c core.quotepath=false`, and a
  `Result` return so git failure blocks instead of yielding empty). This change
  freezes the `git_files`/`git_tracked_files` filtering as-is (Builder condition
  11) so the follow-up owns the boundary deliberately.
- [Doc drift, out of scope] After this fix, references describing the wrapper as
  fail-open go stale: the doc comment at `secrets.rs:506-511`, the size-cap
  comment at `secrets.rs:279-281` ("Larger files … are *skipped* for content"
  — already contradicts the actual `return Err` at 305-311 and will now describe
  a blocking control as a skip), and `docs/secret-fixture-hygiene.md`
  (~lines 53/96/115). The meta-test correctly keeps calling `scan_paths` directly
  (it wants raw findings), but its stated *reason* becomes false. Archived
  artifacts under `openspec/changes/archive/**` must NOT be edited. → Recommend a
  comment/doc touch-up follow-up (comment-only; `secrets.rs` is out of this
  change's scope per Builder condition 7).

## Conditions for Builder

1. **Fail closed on every scan error.** No `unwrap_or_default`, `.ok()`,
   `.unwrap_or(...)`, or default-on-error in the wrapper or either call site. The
   only path producing a clean/PASS outcome is `Ok(report)` with zero surviving
   findings.
2. **The allowlist must never mask a scan error.** In both callers the `Err` is
   resolved before `Allowlist::load(&root).filter(...)` executes; an error must
   be structurally unable to reach the filter (D4).
3. **Gate refusal, not silent pass, in `cmd_gate`.** The error path must
   `return Ok(gate_blocked(...))` before `summary.secrets_clean = Some(true)` can
   execute, using the `"{} gate refused: …"` message shape of its siblings.
4. **Error text must not leak file contents.** Propagate `scan_paths`' messages
   (cause + path only); add no content snippets. The regression test asserts the
   error string excludes the fixture file's bytes.
5. **The test must exercise the tracked-symlink path for real:** symlink created
   in a real git repo, `git add`ed, target existing (else `git_files`' `exists()`
   filter drops it and the test proves nothing); flowing through
   `git_tracked_files` → `scan_secrets` → `Err`. Assert the symlink path is
   present in `git_tracked_files` output before asserting the error.
6. **No secret-shaped literals in any fixture** — `first_party_source_is_scanner_clean`
   scans `crates/**` with an empty allowlist. Use benign content ("safe bytes");
   any future secret-shaped fixture must be assembled at runtime via
   `concat!`/`format!`.
7. **Scope is exactly** `crates/mpd/src/checks/mod.rs`, `crates/mpd/src/cli.rs`,
   `openspec/specs/local-validation/spec.md`. `secrets.rs` is untouched. No
   e2e.rs edit.
8. **Success-path behavior is byte-identical:** clean scan → same `scanner ==
   "builtin"` label, same summary lines, same exit codes as today.
9. `#[cfg(unix)]`-gate the symlink test; the clean-path test runs everywhere.
10. Tests remove their temp dirs (match the existing fixtures' cleanup pattern).
11. **Freeze the enumeration boundary.** Do NOT change `git_files` /
    `git_tracked_files` filtering (checks/mod.rs:146-159) in this change — the
    three silent-drop residuals (git-failure vacuous-clean, `core.quotepath`
    drop, dangling symlink) are owned by a deliberate follow-up, not touched
    incidentally here.

## Amendments (post Security-plan review)

Security (plan) returned **CONDITIONAL PASS**. Condition 1 (Architect,
pre-Build): the Risks section now names all three enumeration-boundary residuals
(a/b/c above) and the spec delta is scoped to the scanner-input boundary with the
enumeration boundary called out as an accepted residual pending a named
follow-up; Builder condition 11 freezes that boundary. Condition 2 (Tester,
pre-Test gate): a black-box e2e assertion that `mpd check` exits non-zero on a
tracked symlink — `crates/mpd/tests/e2e.rs` is now added to the manifest scope
for it. See `security-plan.md` for the full verdict and closing evidence.

## Verdict

PASS — plan is complete, in-scope, and fail-closed by construction; ready for
Security (plan) review.
