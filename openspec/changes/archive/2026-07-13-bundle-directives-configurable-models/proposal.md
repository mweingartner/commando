# Bundle the MPD doctrine as directives; make per-persona models configurable

## Why

mpd enforces the *structure* of Model-Paired Development but not its *doctrine* —
the full persona directives live only in external `CLAUDE.md`/`AGENTS.md`/Playbook
files, so the process depends on the harness carrying them and drifts from mpd by
hand. And per-persona model assignments are hardcoded, so evolving them means a
code change and a release.

## What Changes

- **New capability `directives`:** mpd bundles the canonical MPD doctrine
  (protocol + per-persona directives) as part of the binary. `mpd init` installs
  it to `.mpd/directives/` (editable per project). `mpd next` surfaces the active
  persona's full directive; `--full` inlines the complete text so a bare harness
  is self-sufficient. `mpd doctor` reports directive status.
- **New capability `model-config`:** per-persona, per-harness model assignment
  moves into `.mpd/config.json` (`models` + `model_fallbacks`). `mpd init` seeds
  today's defaults explicitly; `model_for` reads config and falls back to the
  built-in tier default when unspecified. No CLI or on-disk-format break.

## Capabilities

### New Capabilities
- `directives` — bundled MPD doctrine installed and surfaced per project.
- `model-config` — user-configurable per-persona/per-harness models.

### Modified Capabilities
(none — no existing spec-of-record capability changes behavior contractually.)

## Impact

- `crates/mpd`: new `directives` module + assets, `config.rs` (`models`,
  `model_fallbacks`), `harness.rs` (`model_for` reads config), `scaffold.rs`
  (install directives + seed models), `cli.rs` (`next --full`, `doctor`).
- Reads new files under `.mpd/directives/` — hardened (symlink/size) like other
  mpd reads.
- Existing projects without a `models` config keep current behavior (defaults).
