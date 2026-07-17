# Promote an existing change to the strict tier

Canonical current state. Superseded drafts go to `history/`.

## Why

The `strict` bit is set only at change *creation* (`mpd conduct` / `begin
--strict`). A change begun with plain `mpd begin` (strict=false) cannot opt into
the orchestration tier without re-`begin` or hand-editing `.mpd/state/<change>
.json` — the exact residual noted in the `self-enforcing-pipeline` design, hit
during its own dogfood. Close it with a first-class verb.

## What Changes

- Add `mpd strict <change>`: sets `Ledger.strict = true` on an already-begun
  change via the monotonic `set_strict` helper. Validates the change name and
  confirms the ledger exists (mirrors `mpd use`); idempotent (promoting an
  already-strict change is a stated no-op); never a downgrade (write-once holds).
- Route it in the doctrine (`AGENTS.md` / protocol.md) alongside the other
  escape/recovery verbs, and document it.

## Capabilities

### New Capabilities

- `strict-promotion` — the `mpd strict <change>` verb.

### Modified Capabilities

None (additive; the existing `strict` semantics and gates are unchanged).

## Impact

`crates/mpd/src/cli.rs` (a `Command::Strict` mirroring `Command::Use`),
`crates/mpd/src/scaffold.rs` + `crates/mpd/assets/directives/protocol.md`
(doctrine), `crates/mpd/tests/e2e.rs` (one test). No schema change, no breaking
change.
