# Security (code): promote-to-strict

Governance: risk **low**, threat profile **local-trusted-user**. Reviewed as a
documented main-session audit — proportionate to a ~20-line verb with no
untrusted input that mirrors the already-hardened `cmd_use`.

## Findings

**None.** `cmd_strict` (cli.rs) was read in full and greped for the risk patterns.
It: `find_root` → `validate_change_name(&change)` → refuse (pointing at
`mpd begin`) unless `ledger::state_path(...).is_file()` → `ledger::load` →
idempotent no-op if already strict → `ledger.set_strict()` → `ledger::save`. A
grep of the function body for `strict =` / `set_strict` / `set_current` / `fs::` /
`write` returns exactly one hit — `ledger.set_strict()` — confirming no direct
strictness assignment, no other file write, and no `.mpd/current` mutation.

## Conditions verified

- **Cond 1** — `validate_change_name` + `state_path(...).is_file()` run before any
  mutation; an unknown/invalid change errors and no ledger is created. ✓
- **Cond 2** — strictness is mutated ONLY through `set_strict()` (which only ever
  sets `true`); there is no `strict = false` anywhere in the command, so the
  write-once/monotonic invariant (pinned by the self-enforcing-pipeline
  monotonicity test) cannot be regressed. ✓
- **Cond 3** — an already-strict ledger prints "already strict" and returns `Ok(0)`
  without a rewrite. ✓
- **Cond 4** — the only user-controlled text is the change name, which
  `validate_change_name` restricts to a safe kebab-case charset (no control
  characters), so `{change:?}` output is terminal-safe by construction. ✓
- **Cond 5** — the command reads and writes only the change's own ledger
  (`ledger::load`/`save`); no other file, no `.mpd/current`, no config. ✓

## Verdict

**PASS.** No finding within or crossing into the declared threat profile. The verb
is a validated, monotonic, single-file ledger flip that reuses the codebase's
existing hardened primitives; every Condition for Builder holds in the
implementation.
