# Design: promote an existing change to the strict tier

Canonical current-state contract. Superseded drafts go to `history/`.

## Context

`Ledger.strict` is write-once/monotonic, mutated only by `set_strict()`
(ledger.rs:415, sets `true`). It is set at creation by `mpd conduct` and
`begin --strict`. There is no verb to flip an already-begun change from
`strict=false` to `true`; the `self-enforcing-pipeline` design recorded this as an
accepted residual. `mpd use` (cli.rs:2973) is the pattern to mirror: `find_root`,
`validate_change_name`, confirm the ledger file exists, mutate, print.

## Goals / Non-Goals

**Goals.** A first-class `mpd strict <change>` that promotes to strict safely,
idempotently, with a clear message. **Non-Goals.** No demotion (the write-once
invariant forbids true→false and this verb only ever calls `set_strict`); no new
schema or config; no change to how strict gates behave once set.

## Decisions

- **`mpd strict <change>`** (a dedicated verb, discoverable next to `mpd use` /
  `mpd conduct`) over `conduct --promote` — `conduct` means "begin under strict";
  operating on an existing change is a distinct action deserving its own verb.
- Reuse `set_strict()` so monotonicity is enforced in one place; the command never
  writes `strict=false`.
- Idempotent: if the ledger is already strict, print "already strict" and exit 0
  (no error, no rewrite churn).

## Risks / Trade-offs

- [A future edit adds a strict→false path] → the write-once invariant is already
  pinned by the `self-enforcing-pipeline` monotonicity test; this verb only calls
  `set_strict`, so it cannot regress it.
- [Promoting mid-pipeline surprises the operator] → strictness only adds
  enforcement going forward (already-recorded gates are untouched); the message
  states what changed.

## Conditions for Builder

1. `mpd strict <change>` MUST `validate_change_name` and confirm the ledger file
   exists (via `ledger::state_path(...).is_file()`) before mutating — mirroring
   `cmd_use` — and error clearly (pointing at `mpd begin`) otherwise.
2. It MUST mutate strictness ONLY through `ledger::Ledger::set_strict()` (never by
   assigning `strict = ...` directly), so the write-once/monotonic invariant
   holds; it MUST NOT ever set `strict=false`.
3. It MUST be idempotent: an already-strict change prints a "already strict"
   no-op message and returns success without rewriting the ledger.
4. On success it prints a clear confirmation naming the change and that strict
   enforcement is now on; all user-facing text is `terminal_safe`.
5. It touches ONLY the change's own ledger (`.mpd/state/<change>.json`) — no
   other file, no `.mpd/current`, no config.
