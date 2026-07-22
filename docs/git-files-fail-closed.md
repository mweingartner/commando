# Fail-closed tracked-file enumeration

## Purpose

The built-in secret scan's *enumeration* step (`git_tracked_files`) used to fail
open: a git failure returned an empty set (scanned nothing, reported clean), and
tracked files with unusual names or dangling symlinks were silently dropped. This
change makes enumeration fail closed and complete, so the Security (code) gate and
`mpd check` can no longer attest "secrets clean" over a set that was silently
shrunk.

## Value

Closes the residual the prior fail-closed-wrapper change deferred: the honesty of
the gate's clean attestation now holds one layer up, at the boundary that builds
the scan set — including against a local actor who names a secret-bearing file so
git's line-mode output would quote it.

## Scope

**Covers:** `git_tracked_files` now returns a `Result` — a git spawn failure,
non-zero exit, oversized listing, or non-UTF-8 output blocks the gate/check
(diagnostic: "cannot enumerate tracked files: …"); paths are obtained NUL-delimited
(`git ls-files -z`) so unusual name bytes are enumerated verbatim, not quoted-and-
dropped; dangling tracked symlinks (and any non-regular entry) are retained and
fail closed in the scanner. Both callers block on the error.

**Does not cover (single intentional omission):** a tracked path with no worktree
entry at all (an unstaged deletion or sparse-checkout absence) is omitted — it has
no worktree bytes to scan, and its name is covered by the staged scan (commit) and
the egress scan (push).

## Functional details

- `checks::git_tracked_files -> Result<Vec<PathBuf>, String>`, built on the
  existing hardened `git::ls_files` (`-z`, NUL-parsed, bounded). `git_files` is
  removed. The presence filter is `symlink_metadata().is_ok()` (lstat), never
  `exists()` (which followed symlinks and dropped dangling ones).
- `cmd_gate` turns the enumeration error into a gate refusal (exit 1);
  non-staged `mpd check` propagates it (exit 2). No curated rule, the scanner
  wrapper, or the allowlist is changed.

## Usage

- A repo whose git is broken → `mpd check` exits non-zero with "cannot enumerate
  tracked files: …" (was: a false "Checks passed").
- A tracked file with a non-ASCII name containing a secret → now enumerated and
  flagged, blocking exactly as an ASCII-named file would (was: silently skipped).
- A repo with zero tracked files → still a legitimate clean pass (empty is not an
  error).
