# Rename `mpd archive --abandon` to `--close`

## Why
`mpd archive --abandon` releases the spent AwaitingCommit closure metadata after
the commit is in — it does NOT discard the change (its own message: "removed only
its own ignored metadata; repository targets are untouched"). "Abandon" reads like
throwing the work away and is genuinely confusing; "close" describes what it does.

## What Changes
- `mpd archive --close` becomes the primary flag; `--abandon` stays as a HIDDEN
  deprecated alias so the AGENTS.md loop and any scripts keep working.
- The `mpd closure abandon` subcommand gains `close` as the primary name with
  `abandon` as an alias.
- All USER-FACING strings change "abandon(ed)" → "close(d)": the "Closed the pending
  closure …" message, the `→ next: … mpd archive --close --yes` archive hint, the
  "run `mpd archive --recover` or `mpd archive --close` first" blockers, help text,
  and the JSON output key (`{"closed": true}`).
- `docs/fix-closure-commit-coherence.md` references updated to `--close`.
- Internal function names (`abandon_apply`, `cmd_closure_abandon`) are left as-is —
  implementation detail, not user-visible — to keep the change small and low-risk.

Not **BREAKING**: `--abandon` and `mpd closure abandon` still work via alias.

## Capabilities
### New Capabilities
None.
### Modified Capabilities
None (CLI ergonomics; no spec'd requirement governs the flag name).

## Impact
- `crates/mpd/src/cli.rs` (flag/subcommand names + aliases, messages, help, hints,
  JSON key), `crates/openspec-core/src/transaction.rs` (user-facing error strings),
  `docs/fix-closure-commit-coherence.md`. Because it edits crates/**, landing needs
  a coordinator rebuild + reactivation. The `.githooks`/AGENTS.md loop's existing
  `--abandon --yes` continues to work through the alias.
