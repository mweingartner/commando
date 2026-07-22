# Fail-closed `scan_secrets` (built-in secret-scan wrapper)

## Why

The built-in content secret scan is the always-available floor so coverage is
never zero, but its wrapper `checks::scan_secrets` is fail-open: it swallows
every `secrets::scan_paths` error via `unwrap_or_default()`, turning it into an
empty (clean) finding set. `scan_paths` deliberately errors on unsafe input — a
symlink or other non-regular file, a file over the per-file size cap, aggregate
size overflow, or an unreadable path — so a single tracked symlink anywhere in
the repository silently disables the entire built-in content scan for the
Security (code) gate and for non-staged `mpd check`, which then report secrets
clean. This contradicts the fail-closed doctrine every sibling control already
follows (`scan_staged_postimages`, pre-push authorization, structured profiles).
Threat profile: local-untrusted-input. Risk: high.

## What Changes

- `checks::scan_secrets` returns `Result<SecretReport, String>`, matching the
  `scan_staged_postimages` idiom exactly; a scan error is propagated, never
  defaulted to clean.
- The Security (code) phase gate (`cmd_gate`) treats a scan error as a gate
  refusal via the existing `gate_blocked` idiom (exit 1, no PASS record, the
  allowlist is never consulted).
- Non-staged `mpd check` propagates the error with `?` (exit 2), symmetric with
  its staged branch which already does `scan_staged_postimages(&root)?`.
- Regression tests in `checks/mod.rs`: a git-tracked symlink makes `scan_secrets`
  fail closed; clean regular files still pass.
- Spec delta for `local-validation`: the built-in secret scan MUST fail closed
  when it cannot complete.

Not **BREAKING** for correct trees. Intentional behavior change: a repo with a
tracked symlink, a tracked file over the per-file cap, or aggregate tracked bytes
over the aggregate cap now blocks (with a diagnostic naming the cause) where it
previously passed the builtin scan without scanning.

## Capabilities

### New Capabilities

None.

### Modified Capabilities

- `local-validation` — gains a requirement that the built-in secret scan fails
  closed when it cannot complete. No existing requirement governed the built-in
  scan's completion semantics, so the delta ADDs a requirement under this
  modified capability.

## Impact

- Affected code: `crates/mpd/src/checks/mod.rs` (the wrapper + its tests),
  `crates/mpd/src/cli.rs` (both call sites: `cmd_gate` secret-gate branch and
  `cmd_check` non-staged branch), `openspec/specs/local-validation/spec.md`
  (the applied delta at archive).
- No change to `secrets::scan_paths` — it already errors correctly.
- Self-hosting: this repo's own gates exercise the new behavior immediately;
  the tree must have no tracked symlinks / oversize tracked files
  (`git ls-files -s | awk '$1 == 120000'`) for gates to stay green.
