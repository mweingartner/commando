# Harness-Aware Agent Docs

## Purpose

Claude Code auto-loads a repository-root `CLAUDE.md` on every session but never reads
`AGENTS.md`, so Claude Code sessions in this repo were silently skipping the required
mpd operating loop — nothing pointed them at it. Separately, `AGENTS.md` itself was
wrong: its loop example hardcoded `--harness codex` (steering Claude Code sessions at
the wrong model tier) and showed a `--harness` flag on `mpd conduct`, which that
subcommand does not accept (`Conduct`, `crates/mpd/src/cli.rs:77-95`, defines no
harness field — `harness` belongs to `Next`, cli.rs:660-666). This change adds a root
`CLAUDE.md` pointer and corrects `AGENTS.md` so both harnesses reach a working,
reader-conditional entry point into the loop.

## Value

Every Claude Code session now sees the operating loop at load time instead of relying
on stumbling into `AGENTS.md` by chance. Every session, on either harness, gets a loop
it can run verbatim — no unknown-flag failure to improvise around. And the harness/model
mapping in `AGENTS.md` states plainly that `mpd next --harness <harness>` output is
authoritative over its own prose table, so a future config or resolver change (or a
governance risk bump) can't leave stale documentation steering a phase at the wrong
model.

## Scope

Exactly two files, both already delivered: `CLAUDE.md` (new, 9 lines) and `AGENTS.md`
(modified — corrected loop plus a new "Harness and model selection" section). Nothing
else changes: no code, tests, config, or dependencies. `README.md` carried the same
stale `mpd conduct my-change --harness codex` example this change fixed in `AGENTS.md`,
but fixing it there was deliberately excluded from this change's scope because that
file was owned by the `local-first-verification-hardening` change, which has since
landed (`bd7f92c`) and corrected it — README.md:25 now reads `mpd conduct my-change`
with no `--harness` flag.

## Functional details

**Reader → harness.** `CLAUDE.md` is a pointer, not a second copy of the loop: it
tells a Claude Code session to read `AGENTS.md`, names the loop's shape in one
parenthetical, and states the harness value (`--harness claude-code`) — nothing else,
so there is no second copy of loop or model detail to drift out of sync (design.md
C1). `AGENTS.md`'s "Harness and model selection" section (AGENTS.md:18-32) makes the
mapping explicit for both readers: Claude Code sessions use `--harness claude-code`;
Codex sessions use `--harness codex`.

**Deep/standard tiers, with fallback.** Both harnesses resolve every phase to one of
two tiers, matching `builtin_default` (`crates/mpd/src/harness.rs:316`) and
`Phase::is_deep` (`crates/mpd/src/phase.rs:235-240`, exactly {Design Mock, Design
Review, Design Sign-off, Architecture, Doc Validation}):

- Claude Code: deep phases resolve to Fable, falling back to the latest Opus when
  Fable is unavailable (`builtin_fallback`, harness.rs:343); every other phase
  resolves to Sonnet.
- Codex: deep phases resolve to GPT-5.6 Sol; every other phase resolves to Terra.

**Luna override.** This repository's own `.mpd/config.json`
(`models.codex.Documenter = "luna"`) overrides the Codex Documenter specifically, off
the Terra default — named explicitly in `AGENTS.md` so a Codex session doesn't expect
Terra there and get confused when `mpd next` prints Luna instead.

**The authority clause, and why it must survive edits.** `AGENTS.md:29-30` states:
"`mpd next --harness <harness>` prints the resolved model for each phase; treat that
output as authoritative over any prose table, including this one." That sentence is
load-bearing, not boilerplate: `mpd`'s governance risk logic bumps Security and Tester
to the deep-tier model whenever derived risk is High (`model_for_governed`,
harness.rs:152-174; pinned by
`high_risk_bumps_seeded_security_and_tester_to_the_deep_tier`, harness.rs:736), which
the flat "every other phase resolves to Sonnet/Terra" sentence does not capture. This
very change is the demonstration: its own risk was requested low but derived high, and
Security (code) ran at the deep-tier model as a direct result — exactly the case the
authority clause exists to cover. Security (plan) and Security (code) both pinned this
as condition C6 and re-verified the sentence is present verbatim; Doc Validation
must check it again after any future edit to this section.

## Usage

A Claude Code session's first steps on any non-trivial change:

```sh
# CLAUDE.md is auto-loaded; it points here
mpd conduct <change>
mpd next --harness claude-code --context
# perform only the current phase's role, write its artifact
mpd gate <phase> --pass --by <actor> --evidence <artifact>
```

Repeat `next -> work -> gate` until `mpd next` reports Done, then archive/commit/push
and run `mpd publish --verify`, per the loop `AGENTS.md` already documents.

A Codex session runs the identical loop with its own harness flag:

```sh
mpd conduct <change>
mpd next --harness codex --context
mpd gate <phase> --pass --by <actor> --evidence <artifact>
```

In both cases, trust what `mpd next --harness <harness> --context` prints for the
model over the prose table in "Harness and model selection" — that is what the
section itself instructs.
