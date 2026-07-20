# Harness-Aware Agent Docs

## Why

Claude Code auto-loads `CLAUDE.md` but not `AGENTS.md`, so Claude Code sessions never
saw the required mpd operating loop; and `AGENTS.md` hardcoded `--harness codex` and
showed a `--harness` flag on `mpd conduct` that the CLI does not accept (verified
against the `Conduct` struct in `crates/mpd/src/cli.rs`). Both harnesses need a correct,
reader-conditional entry point into the loop.

## What Changes

- New `CLAUDE.md` at the repo root: a short pointer that directs Claude Code sessions to
  the required operating loop in `AGENTS.md` and names `--harness claude-code`. It
  deliberately does not duplicate loop details.
- `AGENTS.md` "Required operating loop" corrected: `mpd conduct <change>` (no
  `--harness` — the flag does not exist on `conduct`) and
  `mpd next --harness <harness> --context`.
- New `AGENTS.md` section "Harness and model selection" mapping reader → harness:
  Claude Code → `--harness claude-code` (deep phases Fable with Opus fallback, others
  Sonnet); Codex → `--harness codex` (deep phases Sol, others Terra, with this repo's
  `.mpd/config.json` overriding the Codex Documenter to Luna). It states that
  `mpd next` output is authoritative over any prose table.
- Deliberate exclusion: `README.md` still carries the stale
  `mpd conduct my-change --harness codex` example, but README is owned by the in-flight
  `local-first-verification-hardening` change and is out of scope here.

No breaking changes; documentation only, no code or behavior changes.

## Capabilities

### New Capabilities

- `agent-onboarding` — the repo's agent-facing instruction files (`CLAUDE.md`,
  `AGENTS.md`) get both Claude Code and Codex sessions into the mpd operating loop with
  a valid harness flag and accurate model expectations. Delta in
  `specs/agent-onboarding/spec.md`.

### Modified Capabilities

None. Existing capabilities (`directives`, `model-config`, `process-governance`, …)
govern mpd's own binary/config behavior, not the repository's agent onboarding docs.

## Impact

- Files: `CLAUDE.md` (new), `AGENTS.md` (modified). No source, test, config, or
  dependency changes.
- Systems: none at runtime; affects only how agent harnesses bootstrap into the mpd
  loop when reading this repository.
- Out of scope: `README.md` (owned by `local-first-verification-hardening`), all code
  under `crates/`, `.mpd/` configuration.
