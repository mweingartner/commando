# Doc Validation: promote-to-strict

Validation of `documentation.md` against the shipped `cmd_strict` + doctrine.

## Architect lens

- "Sets `strict=true` through `set_strict()`, only writes the change's own
  ledger, idempotent, write-once/never-demote" — matches `cmd_strict` (cli.rs)
  line-for-line and the Conditions for Builder. ✓
- "Validates the change name and confirms the ledger exists (mirroring
  `mpd use`)" — matches the `validate_change_name` + `state_path(...).is_file()`
  guard. ✓
- The doctrine claim that a change can now be promoted with `mpd strict <change>`
  matches the updated `AGENTS_MD` (scaffold.rs) and `protocol.md`, which replaced
  the prior "there is no verb to promote" text — so the doc, the doctrine, and the
  code now agree (no stale "no verb" statement remains). ✓

No inaccuracy found.

## Designer lens

The verb reads naturally next to its siblings: `mpd use <change>` / `mpd strict
<change>` — a short, discoverable escape/recovery verb with a clear confirmation
line ("Promoted … judgment gates now enforce their artifacts") and an honest
idempotent no-op ("already strict"). The subcommand's `--help` one-liner states
it is monotonic and idempotent. No naming or pattern drift from the established
verb vocabulary.

## Verdict

**PASS.** `documentation.md` accurately and completely describes the shipped verb
(Purpose/Value/Scope/Functional details/Usage all present and grounded in code),
and the doctrine's previously-contradictory "no promote verb" statement was
corrected in the same change.
