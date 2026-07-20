# Agent Onboarding Delta

## ADDED Requirements

### Requirement: Claude Code entry point

The repository SHALL carry a root `CLAUDE.md` that directs Claude Code sessions to the
required operating loop in `AGENTS.md` and names `--harness claude-code`. It SHALL NOT
duplicate loop or model details that can drift from `AGENTS.md`.

#### Scenario: Claude Code session starts a non-trivial change

- **GIVEN** a Claude Code session that auto-loaded `CLAUDE.md`
- **WHEN** it starts a non-trivial change
- **THEN** it follows `AGENTS.md`'s required operating loop and runs
  `mpd next --harness claude-code --context` for each phase

### Requirement: Harness-correct operating loop

`AGENTS.md`'s required operating loop SHALL show `mpd conduct <change>` with no
`--harness` flag (the `conduct` subcommand accepts none) and SHALL show
`mpd next --harness <harness> --context` with the harness left reader-conditional.

#### Scenario: Codex session follows the loop verbatim

- **GIVEN** a Codex session reading `AGENTS.md`
- **WHEN** it runs the operating loop as written with `<harness>` set to `codex`
- **THEN** every shown command is accepted by the installed `mpd` binary without an
  unknown-flag error

### Requirement: Accurate harness and model mapping

`AGENTS.md` SHALL carry a "Harness and model selection" section mapping reader →
harness: Claude Code → `--harness claude-code` (deep phases resolve to Fable with an
Opus fallback, all other phases to Sonnet); Codex → `--harness codex` (deep phases
resolve to Sol, all other phases to Terra, noting this repository's `.mpd/config.json`
override of the Codex Documenter to Luna). Every harness value named SHALL be one of
`generic`, `claude-code`, or `codex` exactly as accepted by `mpd next`, and the section
SHALL state that `mpd next` output is authoritative over prose.

#### Scenario: Prose matches binary resolution

- **GIVEN** the "Harness and model selection" section in `AGENTS.md`
- **WHEN** its model claims are compared against `builtin_default` and
  `builtin_fallback` in `crates/mpd/src/harness.rs` and the `models` block of
  `.mpd/config.json`
- **THEN** every named model (fable/opus/sonnet; sol/terra/luna) matches the resolved
  value, and the deep tier is exactly the Design phases, Architecture, and
  Doc Validation per `Phase::is_deep`

#### Scenario: Prose and binary output disagree

- **GIVEN** a session whose `mpd next --harness <h>` output names a different model
  than the prose table
- **WHEN** the session chooses which to follow
- **THEN** it treats the `mpd next` output as authoritative, as the section instructs
