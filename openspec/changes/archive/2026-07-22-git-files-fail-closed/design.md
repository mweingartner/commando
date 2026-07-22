# Design: Fail-closed tracked-file enumeration (`git_tracked_files`)

## Actor

Architect (claude-code harness, deep tier — high-risk deep_tier_bump).

## Context

`git_tracked_files` → `git_files` (checks/mod.rs:142-160) is fail-open: a git
spawn failure or non-zero exit returns `Vec::new()` (:148-153), and the line-mode
parse (`from_utf8_lossy` + `.lines()` + `exists()`, :154-159) drops any tracked
path git's line-mode output quotes (non-ASCII / `"` / `\`), plus — discovered
while planning — embedded-newline names (split into bogus lines) and
whitespace-only names (killed by `!l.trim().is_empty()`), and dangling symlinks
(dropped by `exists()`, which follows links).

Key discovery: **git.rs already has the exact hardened helper** —
`git::ls_files(repo) -> Result<Vec<String>, GitError>` (git.rs:345-348) runs
`git ls-files -z` through the bounded runner (fixed argv, `GIT_PAGER=cat`,
`GIT_TERMINAL_PROMPT=0`, stdin null, 64 MiB stdout cap with kill-on-overflow) and
`nul_tokens` (:329-336, correct trailing/empty/absent-NUL handling, `NonUtf8` on
invalid bytes). It has five production callers and a Linux non-UTF-8 fail-closed
test. `scan_paths` (secrets.rs:388-426) lstat's each path and hard-errors on
symlink/non-regular/missing/oversize — the single fail-closed authority on
non-regular inputs. Both callers run under `find_root()` (an mpd project = a git
repo by doctrine). Compensating egress control confirms this is NOT a push-time
leak: `scan_outgoing_objects` (local_validation.rs:6738-6797) content-scans every
outgoing blob path-independently; the dishonest artifact is the SecurityCode
gate's `secrets_clean: true` and `mpd check`'s `Checks passed`.

This file is the canonical current-state contract. Move superseded drafts to
`history/`; do not accumulate contradictory amendments here.

## Goals / Non-Goals

**Goals.** Enumeration fails closed (git failure ⇒ `Err`, never empty set) and is
complete (no tracked path dropped for name bytes; dangling symlinks retained).
Both callers block on `Err`. Reuse the existing hardened plumbing.

**Non-Goals.** No change to `git.rs` (reuse `ls_files`), `secrets.rs`, structured
validation, or the allowlist. No new git helper. No new scan of worktree-absent
tracked paths (they have no content to scan).

## Decisions

**D1 — Reuse `git::ls_files`; delete `git_files`; no new helper, no inline
invocation.** The helper the task brief suggested adding already exists and is
hardened + tested with five callers. Duplicating would fork plumbing conventions;
inlining would re-create the unhardened one-off being removed.

**D2 — `-z` alone; NO `-c core.quotepath=false`.** With `-z`, `git ls-files`
emits pathnames verbatim — `core.quotePath` governs only line-mode output.
Adding the config flag would touch the shared helper five other sites use, for a
no-op. Immunity is pinned empirically: tests set `core.quotepath=true` in the
fixture repo and prove retention, with a vacuity guard asserting git's line-mode
output really does quote the fixture name.

**D3 — Signature `Result<Vec<PathBuf>, String>`, error prefix `"cannot enumerate
tracked files: {e}"`.** Mirrors `scan_staged_postimages`'s
`"cannot enumerate staged postimages: {e}"` (mod.rs:195); composes with
`CmdResult = Result<i32, String>` so `cmd_check` uses bare `?`. `GitError`'s
`Display` renders only fixed safe labels (git.rs:42-73) — no stdout/stderr/URLs.

**D4 — (c): dangling tracked symlinks are RETAINED and fail closed; the filter
becomes `symlink_metadata().is_ok()`, never `exists()`.** A tracked symlink whose
target exists already hard-blocks this scan; under `exists()`, deleting the
target silently flipped the gate from block to pass — the symlink policy was
bypassable by *breaking* the link. `scan_paths` is the single fail-closed
authority on non-regular inputs; enumeration should not pre-adjudicate. A dangling
symlink lstat's fine, reaches `scan_paths`, and errors "non-regular" — same
verdict/message/remediation as a healthy tracked symlink. Legitimate-case cost is
near zero (danglingness adds no new legitimate class). Also fail-closed-consistent
for FIFO/device/directory substitutions at a tracked path. (Gitlink/submodule
directory entries were retained + blocked under `exists()` too — pre-existing,
unchanged.)

**D5 — Worktree-absent tracked paths (lstat fails: unstaged deletion, sparse
checkout) remain omitted — intentionally and testedly.** The scan protects
worktree content; an absent path has zero worktree bytes, and its *name* is still
covered by the staged scan (commit) and egress scans (push). The alternative (no
filter) would hard-block every sparse checkout and every routine `rm` awaiting
staging — a large false-positive class purchasing nothing. TOCTOU cuts safe: a
path present at enumeration that vanishes before scanning still errs inside
`scan_paths` (missing-path-fails-closed), so the omission window is exactly
"absent when enumerated," never "absent when scanned."

**D6 — git-failure blocks even where "not a git repo" was previously
silent-clean.** Both callers run under `find_root()`; a project whose git breaks
mid-flight must not attest `secrets_clean`. Also newly fail-closed: over-cap
listings (`OutputTooLarge`), non-UTF-8 (`NonUtf8`, was mangled-then-dropped),
embedded-newline and all-whitespace names.

**D7 — Hermetic git-failure fixture:** a `.git` *file* containing `gitdir:
/nonexistent/…` (deterministic exit 128 even inside an outer repo; reversible via
rename-back so a gate e2e can assert phase-not-advanced afterward).

## Risks / Trade-offs

- [Repos that silently passed with quoted-name / non-UTF-8 files now surface
  findings or block] → intended; remediation: rename or allowlist findings, or
  structured tier for exotic trees.
- [macOS NFC/NFD byte forms in the `sécrets.txt` fixture] → assert the ASCII
  suffix `"crets.txt"` + the octal-quoting vacuity guard; compare via the scan
  finding rather than exact `PathBuf` equality if a normalization flake appears.
- [`run()` does not pin `GIT_CONFIG_GLOBAL=/dev/null` outside the test runner] →
  unchanged trust posture shared by all five existing `ls_files` callers; quoting
  immunity comes from `-z`, not config, and is pinned with `quotepath=true`.
- [Gitlink/submodule entries still block] → pre-existing under `exists()`,
  unchanged, documented not fixed.
- [>64 MiB path listing now errs] → pathological, fail-closed by design.

## Conditions for Builder

1. **No vacuous clean, anywhere.** No `unwrap_or_default`/`.ok()`/`let _
   =`/`Vec::new()` fallback on the `git::ls_files` result; `Err` propagates with
   the `"cannot enumerate tracked files: {e}"` prefix.
2. **Reuse `git::ls_files` verbatim.** No new `Command::new("git")` in
   checks/mod.rs; no line-mode parsing; `git_files` deleted; `git.rs` untouched.
3. **Only lstat-absence may drop a path.** Filter is `symlink_metadata().is_ok()`
   — never `Path::exists()`. Dangling symlinks, directories, FIFOs — anything with
   an lstat entry — must reach `scan_secrets`.
4. **Both callers block.** `cmd_gate`: `return Ok(gate_blocked(...))` strictly
   before allowlist filtering, external scanners, and any `secrets_clean =
   Some(true)`. `cmd_check`: `?` on both calls (exit 2). Grep-confirm no third
   caller.
5. **No content or raw git output in diagnostics.** Error text = fixed prefix +
   `GitError` safe labels only.
6. **Fixture hygiene.** No contiguous secret-shaped literal in any source/test
   file: assemble via `format!("aws_key = AKIA{}\n", "IOSFODNN7EXAMPLE")`
   (gitleaks-ignored placeholder, builtin-detected). `first_party_source_is_scanner_clean`
   (empty allowlist) and the repo's gitleaks gate must stay green.
7. **(c) behavior exact.** Dangling tracked symlink → retained → `scan_secrets`
   `Err` containing `"non-regular"`; worktree-absent tracked path → omitted and
   the remaining scan `Ok`; both pinned by tests.
8. **Regression pins must bite.** The quotepath and dangling-symlink unit tests
   must fail against the pre-fix enumeration.
9. **Vacuity guards mandatory.** Quotepath tests assert git line-mode output
   contains the octal-quoted form; symlink test asserts tracked + still-a-symlink;
   git-failure fixtures use the `gitdir: /nonexistent` `.git`-file mechanism.
10. **Scope confined** to: checks/mod.rs, cli.rs (the two named hunks), e2e.rs,
    the spec delta, docs/scan-secrets-fail-closed.md. Nothing else.
11. **Landing order.** Full workspace suite green → release build → `mpd policy
    activate` re-activation (coordinator digest changes) BEFORE the commit →
    commit through the activated hooks. Never `--no-verify`.

## Verdict

PASS — small (one function rewritten onto existing tested plumbing, two call-site
hunks), strictly rigor-increasing, closes an attacker-controllable
scan-exclusion primitive plus two environmental vacuous-clean doors and the
symlink-policy bypass, with the sole intentional omission (worktree-absent paths)
argued from content-coverage grounds and pinned by test. Ready for Security
(plan).
