## 1. CLI flag + subcommand (crates/mpd/src/cli.rs)
- [ ] 1.1 `mpd archive`: `--close` primary + `--abandon` alias; update the match on `(recover, close)` and the handler dispatch.
- [ ] 1.2 `mpd closure`: `Close` variant (alias `abandon`); update the dispatch match.
- [ ] 1.3 User-facing strings → "close(d)": the "Closed the pending closure …" message (keep the metadata clarifier), JSON key `"closed"`, `→ next` archive hint, blocker messages, help/`--recover/--close` text.

## 2. Core error strings (crates/openspec-core/src/transaction.rs)
- [ ] 2.1 "mpd closure … abandon" user-facing strings (transaction.rs:882, :1443) → "mpd closure close" / `--close`. (Internal `abandon_apply` name unchanged.)

## 3. Docs
- [ ] 3.1 docs/fix-closure-commit-coherence.md `--abandon` references → `--close`.

## 4. Tests + verify
- [ ] 4.1 A test that BOTH `--close` and `--abandon` parse/dispatch identically (alias back-compat); update any test asserting the old output string to "Closed".
- [ ] 4.2 Full cargo test green; grep confirms no user-facing "abandon(ed)" string remains (help/messages/hints/JSON).

## 5. Landing
- [ ] 5.1 Rebuild + reactivate coordinator before commit (crates/**).
