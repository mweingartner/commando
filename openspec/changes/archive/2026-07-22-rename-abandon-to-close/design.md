# Design: Rename `--abandon` to `--close`

## Actor
Architect (claude-code harness).

## Context
User-facing "abandon" appears in: the `mpd archive` `--abandon` flag (cli.rs:332);
the `mpd closure abandon` subcommand (`ClosureCommand::Abandon`, cli.rs:6348); the
"Abandoned the pending closure …" message (cli.rs:6395); the JSON `{"abandoned":
true}` (cli.rs:6392); the `→ next` archive hint (cli.rs:6902); blocker messages
(cli.rs:990, 6446); help/doc-comment strings; and openspec-core error strings
("mpd closure … abandon", transaction.rs:882, :1443). The user's complaint is the
misleading TERM, not the internal implementation.

## Goals / Non-Goals
Goal: users see and type "close"; the term "abandon" is deprecated but still works
(no breakage of the AGENTS.md loop / scripts). Non-Goal: no behavior change; no
rename of internal functions (`abandon_apply` etc.) — implementation detail.

## Decisions
**D1 — Primary "close", hidden "abandon" alias.** `mpd archive`: clap field renamed
to `close` with `#[arg(long = "close", alias = "abandon", ...)]` (keep the alias
hidden/undocumented in help if the framework allows; otherwise a plain alias is
fine). `mpd closure`: the `Abandon` variant renamed to `Close` with
`#[command(alias = "abandon")]`. All match arms/handlers updated (the internal
handler `cmd_closure_abandon` keeps its name — private).
**D2 — All user-facing strings say "close(d)".** Message → "Closed the pending
closure …"; JSON key → `"closed"`; `→ next` hint → `mpd archive --close --yes`;
blockers and openspec-core strings → `--close` / `mpd closure close`. Keep the
"(removed only its own ignored metadata; repository targets are untouched)"
clarifier.
**D3 — Doc reference** in docs/fix-closure-commit-coherence.md updated to `--close`.

## Risks / Trade-offs
- [A script parsing the JSON key `abandoned`] → low (personal tool); if desired the
  Builder MAY emit both `closed` and `abandoned` keys — leave to Builder, prefer
  `closed` only unless a test depends on `abandoned`.
- [Tests asserting the old message/flag] → update them to `close` (the alias keeps
  `--abandon` working, so any test that INVOKES `--abandon` still passes; tests that
  assert the OUTPUT string must move to "Closed").

## Conditions for Builder
1. `mpd archive --close` and `mpd archive --abandon` BOTH work (alias); same for
   `mpd closure close`/`abandon`. Verify with an e2e or CLI-parse test.
2. No behavior change — only names/strings; the closure logic and `abandon_apply`
   are untouched.
3. Every USER-FACING "abandon(ed)" string becomes "close(d)"; grep to confirm none
   remain in help/messages/hints/JSON (comments may keep "abandon" where they
   describe the alias or internal fn).
4. Scope: cli.rs, openspec-core/transaction.rs, crates/mpd/tests/e2e.rs (the one e2e assertion of the recovery-hint string), docs/fix-closure-commit-coherence.md.

## Verdict
PASS — mechanical, back-compatible rename; ready for Security.
