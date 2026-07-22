# Fail-closed tracked-file enumeration for the built-in secret scan

## Why

The prior change (`2026-07-22-scan-secrets-fail-closed`) made the scan *wrapper*
fail closed but explicitly deferred the *enumeration* boundary. `git_files`
(checks/mod.rs:146-159) still has three silent-drop doors that re-open
"incomplete scan reported clean" one layer up: (a) a git spawn failure or
non-zero exit returns an empty set, and `scan_secrets(&[])` is a vacuous clean —
the SecurityCode gate records `secrets_clean: true` having scanned nothing; (b)
`git ls-files` runs without `-z`, so `core.quotepath` C-quotes any tracked name
with non-ASCII/quote/backslash bytes, `root.join(quoted)` names nothing, and the
`exists()` filter drops it — a local actor excludes a secret-bearing file from
the builtin gate scan by naming it `sécrets.txt`; (c) dangling tracked symlinks
are dropped by the same filter, so breaking a tracked symlink's target un-blocks
a gate that a healthy symlink blocks. These are compensated at egress (pre-push
`scan_outgoing_objects` content-scans every outgoing blob; pre-commit validates
canonical staged paths), so this is not a push-time leak — it is the SecurityCode
gate's and `mpd check`'s clean attestation being dishonest. Threat profile:
local-untrusted-input, dishonest control attestation. Risk: high.

## What Changes

- `checks::git_tracked_files` returns `Result<Vec<PathBuf>, String>`, built on the
  existing hardened `git::ls_files` (`git ls-files -z`, NUL-parsed, bounded,
  fail-closed); `git_files` is deleted. Enumeration failure (spawn, non-zero
  exit, oversized or non-UTF-8 output) propagates as `Err`.
- The `exists()` filter becomes an lstat-presence filter
  (`symlink_metadata().is_ok()`): dangling symlinks (and any non-regular worktree
  entry) are retained and fail closed in `scan_paths`; only tracked paths with no
  worktree entry at all (unstaged deletion, sparse checkout) are omitted —
  intentionally and under test.
- `cmd_gate` (SecurityCode, legacy tier) turns enumeration `Err` into a gate
  refusal via the existing `gate_blocked` idiom, before allowlist/external
  scanners/`secrets_clean`; non-staged `mpd check` propagates with `?` (exit 2).
- Regression pins: unit tests (git-failure Err; quotepath-quoted name retained;
  dangling symlink retained→blocks; absent path skipped) and e2e black-box tests
  (enumeration failure blocks `mpd check` and the SecurityCode gate; a
  `sécrets.txt`-named tracked file with an assembled secret shape is scanned).
- Spec delta for `local-validation`: enumeration SHALL fail closed on git failure
  and SHALL NOT silently drop tracked paths with unusual names; the prior
  requirement's boundary note is narrowed. `docs/scan-secrets-fail-closed.md`'s
  residual note is narrowed in the same change (it becomes false otherwise).

Not **BREAKING** for correct trees. Intentional behavior changes: a repo where
git enumeration fails now blocks (was: vacuous clean); a secret in an unusually
named tracked file is now found (was: silently unscanned); a dangling tracked
symlink now blocks like every tracked symlink (was: silently skipped).

## Capabilities

### New Capabilities

None.

### Modified Capabilities

- `local-validation` — the "Fail-closed built-in secret scan" requirement's
  boundary note is narrowed (MODIFIED), and a new "Fail-closed tracked-file
  enumeration" requirement is ADDED governing the construction of the scan set.

## Impact

- Affected code: `crates/mpd/src/checks/mod.rs` (enumeration + tests),
  `crates/mpd/src/cli.rs` (`cmd_gate` secret branch, `cmd_check` non-staged
  branch), `crates/mpd/tests/e2e.rs` (three tests + one stale comment),
  `openspec/specs/local-validation/spec.md` (applied delta),
  `docs/scan-secrets-fail-closed.md` (Scope narrow).
- No change to `git.rs` (`ls_files` reused as-is), `secrets.rs`, or structured
  validation.
- Self-hosting: this repo is strict-tier, so its own SecurityCode gate takes the
  structured path; the fix is exercised here by non-staged `mpd check` and the
  full test suite. Landing requires a coordinator rebuild and `mpd policy
  activate` re-activation before the commit (crates/** changed; activation binds
  the coordinator digest).
