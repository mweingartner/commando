# Fail-closed built-in secret scan

## Purpose

The built-in secret-scan wrapper `checks::scan_secrets` used to swallow scanner
errors (`unwrap_or_default()`) and report an empty = clean result, so a single
tracked symlink or other non-regular file silently disabled the built-in content
scan for the Security (code) gate and `mpd check`. This change makes the wrapper
fail *closed*: a scan that cannot complete is a blocking error, never a clean
pass.

## Value

Restores the "always-available floor so coverage is never zero" guarantee for the
built-in secret scan. A developer or CI relying on the Security (code) gate or
`mpd check` can no longer be told "secrets clean" over content that was never
scanned because of an unsafe file in the tree — the gate now refuses, naming the
cause (and, for a non-regular or oversize file, the offending path).

## Scope

**Covers:** the built-in scanner over the path set it is handed — errors on a
symlink/non-regular file, a file over the per-file size cap, aggregate-size
overflow, or an unreadable path now block at both call sites (the Security (code)
phase gate and non-staged `mpd check`).

**Does not cover (explicit residuals, by design):**
- The *enumeration* boundary that builds the scan set (`git_files`) is unchanged
  and can still silently shrink the set — a `git ls-files` failure, a
  `core.quotepath`-quoted (non-ASCII) filename, or a dangling symlink. These are
  compensated at egress by the path-independent pre-push blob scan and are
  tracked as a separate follow-up; they are called out honestly in the spec's
  boundary note rather than claimed fixed.
- The error diagnostic **never includes file contents** — the trust-boundary
  invariant verified by Security and the tests. It always names the cause; it
  names the offending path for the non-regular and oversize classes, while the
  aggregate-cap and some OS-level (unreadable-path) errors carry the cause only.

## Functional details

- `checks::scan_secrets(paths) -> Result<SecretReport, String>` (previously
  `-> SecretReport`). On any `secrets::scan_paths` error it returns
  `Err("built-in secret scan failed closed: <cause>")` — the cause names the
  offending path for the non-regular/oversize classes and is cause-only for the
  aggregate-cap/unreadable classes; on success an
  `Ok(SecretReport { scanner: "builtin", .. })` identical to before.
- **Security (code) gate** (`cmd_gate`): a scan error becomes a gate *refusal*
  (stderr diagnostic, exit 1) via the same `gate_blocked` path as its sibling
  refusals — it returns before the allowlist filter and before any
  `secrets_clean = true` is recorded, so an incomplete scan can never be laundered
  into a clean verdict.
- **`mpd check`** (non-staged): the error propagates (exit 2), symmetric with the
  already-fail-closed staged path.
- The success path is byte-identical: a clean scan still reports
  `Checks passed (secret scan clean via builtin).` and exits 0.

## Usage

Derived from the spec scenarios:

- **Tracked symlink in the scanned set** — with a tracked symlink present:
  ```
  $ mpd check
  error: built-in secret scan failed closed: secret scanner refuses unsafe non-regular path /path/to/repo/link.txt
  $ echo $?        # non-zero — the scan refused rather than reporting clean
  2
  ```
  The Security (code) gate refuses the same way (exit 1) instead of recording
  "secrets clean". Remediation: untrack the symlink/non-regular file (or, for a
  repo that legitimately needs such entries, migrate the gate to structured
  validation).
- **Clean tree** — no non-regular/oversize tracked files:
  ```
  $ mpd check
  Checks passed (secret scan clean via builtin).
  $ echo $?
  0
  ```
