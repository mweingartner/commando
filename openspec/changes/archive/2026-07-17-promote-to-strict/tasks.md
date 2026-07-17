Canonical current checklist. Superseded plans go to `history/`.

## 1. Implement

- [ ] 1.1 Add `Command::Strict { change }` + `cmd_strict(change)` in cli.rs,
  mirroring `Command::Use`/`cmd_use`: validate name, confirm ledger exists,
  load, idempotent no-op if already strict, else `set_strict()` + save +
  confirmation. (cli.rs)
- [ ] 1.2 Route `mpd strict <change>` in the doctrine — `AGENTS_MD` (scaffold.rs)
  + `assets/directives/protocol.md` escape/recovery verbs. (scaffold.rs, assets)

## 2. Verify

- [ ] 2.1 e2e test: `begin` (non-strict) → `mpd strict <change>` → a strict
  judgment gate now refuses without its artifact (enforcement is on); a second
  `mpd strict` is an idempotent no-op; an unknown change errors. (e2e.rs)

## Risk-to-test matrix

- [ ] R1 Promotion turns strict enforcement ON: after `mpd strict`, a judgment
  gate refuses without its artifact (was accepted before) (2.1, Cond 1–2).
- [ ] R2 Idempotent: `mpd strict` on an already-strict change is a no-op success
  (2.1, Cond 3).
- [ ] R3 Unknown change / missing ledger errors, never creates one (2.1, Cond 1).
- [ ] R4 Never sets strict=false (only calls `set_strict`); write-once holds
  (Cond 2, covered by the existing monotonicity test).
