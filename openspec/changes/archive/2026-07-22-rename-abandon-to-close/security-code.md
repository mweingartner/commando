# Security (code) review

## Actor
Security (claude-code harness). Behavior-preserving CLI rename; verified against
the built binary + full suite.

## Findings
None. Names and user-facing strings only; closure/transaction logic untouched.

## Conditions verified
- **Back-compat alias (Cond 1):** `mpd archive --close` primary + `--abandon` alias;
  `mpd closure close` + `abandon` alias. Two new unit tests
  (`archive_close_flag_and_its_abandon_alias_parse_to_the_same_field`,
  `closure_close_subcommand_and_its_abandon_alias_dispatch_to_the_same_variant`) prove
  both forms resolve identically — verified passing.
- **No behavior change (Cond 2):** `openspec_core::abandon_apply`, `cmd_closure_abandon`,
  and all closure/transaction logic are byte-unchanged (transaction.rs's own
  `abandon_*` unit tests pass unmodified). Only the `ClosureCommand` variant name,
  the flag long-name, and user-facing strings changed.
- **All user-facing strings say close(d) (Cond 3):** grep of cli.rs +
  transaction.rs confirms remaining "abandon" hits are ONLY internal (fn names,
  `alias = "abandon"` declarations, comments) — no help/message/hint/JSON contains
  it. JSON key is now `"closed"`; the message is "Closed the pending closure …"
  (metadata clarifier preserved); the `→ next` hint says `mpd archive --close --yes`.
- **Scope (Cond 4):** cli.rs, transaction.rs, e2e.rs (one recovery-hint assertion),
  docs/fix-closure-commit-coherence.md — all declared in the (corrected) manifest.

## Independent review
Built-binary sanity: `mpd archive --help` shows `--close` primary; `mpd archive
--abandon` and `--close` both accepted; `mpd closure --help` shows `close` with the
`abandon` alias. The AGENTS.md loop's `mpd archive --abandon --yes` therefore keeps
working unchanged.

## Refutation
Strongest attack: did the rename silently change closure behavior or break the
running `--abandon` loop? Refuted — logic byte-identical (transaction tests
unchanged), and the alias parity tests + binary check confirm `--abandon` still
dispatches to the same handler.

## Verdict
PASS — a back-compatible, behavior-preserving rename; may proceed to Test.
