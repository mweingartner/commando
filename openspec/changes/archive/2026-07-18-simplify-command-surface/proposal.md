# Simplify the mpd command surface (tiering + safe merges)

Canonical current state. Superseded drafts go to `history/`.

## Why

The CLI grew to 18 top-level verbs presented flat, and `gate` carries 17 flags.
The functional surface is justified, but the *cognitive* surface hides that the
everyday harness path is only ~6 verbs (`conduct → next → gate → status → archive
→ publish`). This simplifies the surface — tiering + safe merges — **without
losing any functionality**.

## What Changes

- **Tier `--help`** into Core / Author & govern / Setup & recovery so the core loop
  leads (reorder the `Command` enum + a grouped top-level `after_help`).
- **Flatten `manifest`** — a one-subcommand group (`init`) becomes
  `mpd manifest [--change]`.
- **Fold `closure recover|abandon` under `archive`** — `mpd archive --recover` /
  `--abandon`; `closure` kept as a hidden alias for back-compat.
- **Collapse the 5 `gate` exploitability flags** into one
  `--exploit "attacker|capability|boundary|harm|fix"`.
- **Make `conduct` the single documented start verb**; keep `begin` as a hidden
  (still-functional) manual-tier alias.

Net: 18 → ~15 documented verbs, `gate` 17 → ~13 flags, every verb tiered by role.

## Capabilities

### Modified Capabilities

- `cli-surface` — verb tiering + the manifest/closure/gate-exploit consolidations +
  `begin` hidden behind `conduct`. No new functional behavior.

## Impact

`crates/mpd/src/cli.rs` (the clap command tree + `cmd_gate`/`cmd_archive`/
`cmd_manifest` dispatch), `crates/mpd/tests/e2e.rs`. A refactor (`--chore`): no new
behavior, Documentation skips; the README is refreshed separately (direct docs task).
