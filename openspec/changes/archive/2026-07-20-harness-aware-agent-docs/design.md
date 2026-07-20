# Design: Harness-Aware Agent Docs

## Actor

Architect

## Context

This file is the canonical current-state contract. Move superseded drafts and
reviews to `history/`; do not accumulate contradictory amendments here.

Claude Code auto-loads a repo-root `CLAUDE.md` but never `AGENTS.md`, so Claude Code
sessions in this repo were not reliably entering the mpd operating loop. `AGENTS.md`
also carried two harness defects: the loop hardcoded `--harness codex`, and it passed
`--harness` to `mpd conduct`, a flag the `Conduct` struct in `crates/mpd/src/cli.rs`
does not define. Harness is a per-`mpd next` rendering choice, not a property of the
change. Model facts verified against `crates/mpd/src/harness.rs`
(`builtin_default`: claude-code → fable/sonnet, codex → sol/terra;
`builtin_fallback`: fable → opus), `Phase::is_deep` in `crates/mpd/src/phase.rs`
(Design phases + Architecture + Doc Validation), and `.mpd/config.json` `models.codex.Documenter = "luna"`.

The two file edits already exist on disk (user-directed); this plan describes them
precisely and sets the invariants Security and Test verify against the real files.

## Goals / Non-Goals

Goals:

- A Claude Code session that loads only `CLAUDE.md` reaches `AGENTS.md`'s required
  operating loop with `--harness claude-code`.
- `AGENTS.md` shows only commands the installed `mpd` binary accepts, for both
  harnesses.
- Model expectations in prose match `harness.rs` resolution and defer to `mpd next`
  as authoritative.

Non-Goals:

- Fixing `README.md`'s stale `mpd conduct my-change --harness codex` example — README
  is owned by the in-flight `local-first-verification-hardening` change (deliberate,
  recorded exclusion).
- Any change to code, config, hooks, or mpd behavior.

## Decisions

- **Pointer `CLAUDE.md`, not a duplicate loop.** `CLAUDE.md` names the loop's shape in
  one breath and defers to `AGENTS.md` for the contract. Alternative — duplicating the
  loop and model table — was rejected: two copies drift, and `AGENTS.md` is already the
  canonical cross-harness instruction file.
- **One reader-conditional file, not per-harness files.** Harness selection is
  documented as a conditional inside `AGENTS.md` ("set `<harness>` by which agent is
  reading this file") rather than as separate `AGENTS-codex.md`/`AGENTS-claude.md`
  files. The loop, gates, role discipline, and trust-boundary text are harness-invariant;
  only one two-bullet mapping varies. Splitting would fork 100+ shared lines to vary 6.
- **Prose defers to the binary.** The model mapping is useful orientation but
  `mpd next --harness <h>` is declared authoritative, so config changes (like the Luna
  Documenter override) cannot silently invalidate the doc.
- **README exclusion.** The same stale example exists in `README.md`, but that file is
  in-flight under `local-first-verification-hardening`; touching it here would create a
  cross-change conflict for a one-line fix that change already owns.

## Risks / Trade-offs

- [Prose model table drifts from config/code] → Section explicitly subordinates itself
  to `mpd next` output; Doc Validation re-checks against `harness.rs`.
- [CLAUDE.md pointer is too thin and Claude Code skips AGENTS.md] → The pointer names
  the concrete loop commands' shape and the harness flag, enough to make skipping it a
  visible protocol violation.
- [README still shows the invalid `conduct --harness` example until the other change
  lands] → Accepted; recorded as a deliberate exclusion in proposal and here.

## Conditions for Builder

- **C1** — `CLAUDE.md` must not duplicate loop or model details that can drift; it
  points to `AGENTS.md` and names only the harness flag and the loop's shape.
- **C2** — `AGENTS.md` must never show `--harness` on `mpd conduct`; the flag does not
  exist on that subcommand (`Conduct` struct, `crates/mpd/src/cli.rs`).
- **C3** — Every harness value named in prose must be one of `generic`, `claude-code`,
  or `codex`, exactly as accepted by `mpd next --harness`.
- **C4** — Model names in prose must match `crates/mpd/src/harness.rs` resolution
  (deep: fable with opus fallback / sol; standard: sonnet / terra; config override
  luna for the Codex Documenter) with the deep tier per `Phase::is_deep`, and the text
  must state that `mpd next` output is authoritative over prose.
- **C5** — No secrets, no code changes, and no files touched outside `CLAUDE.md`,
  `AGENTS.md`, and `openspec/changes/harness-aware-agent-docs/`.

## Verdict

PASS
