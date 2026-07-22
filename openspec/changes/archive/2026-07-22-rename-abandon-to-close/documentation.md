# `mpd archive --close` (renamed from `--abandon`)

## Purpose
The step that releases the spent AwaitingCommit closure metadata after a commit
was named `--abandon`, which misleadingly implied discarding the change. It is now
`--close`; `--abandon` remains as a hidden back-compat alias.

## Value
Clearer terminology: `close` describes what the step does (finish the closure
transaction) instead of `abandon` (which sounded like throwing work away). Existing
scripts and the AGENTS.md loop keep working via the alias.

## Scope
**Covers:** `mpd archive --close` (alias `--abandon`) and `mpd closure close`
(alias `abandon`); all user-facing messages, help, the `→ next` archive hint, the
blocker messages, and the JSON output key (`{"closed": true}`).
**Unchanged:** closure/transaction behavior and the internal functions — this is a
naming change only.

## Functional details
- `mpd archive --close --yes` releases the pending closure after the commit is in
  (same guarded semantics: AwaitingCommit-only, repository targets untouched).
- `--abandon` and `mpd closure abandon` still parse and dispatch identically
  (verified by alias-parity tests).

## Usage
- New: `mpd archive --close --yes` (after committing the archived result).
- Still works: `mpd archive --abandon --yes` (deprecated alias).
- The post-archive hint now prints `→ next: … run mpd archive --close --yes`.
