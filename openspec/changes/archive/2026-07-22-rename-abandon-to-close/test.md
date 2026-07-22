# Test report

## Actor
Tester (claude-code harness). Behavior-preserving rename; the full suite + two new
alias-parity tests cover it.

## Coverage
- **Alias parity (new unit tests, cli.rs):** `mpd archive --close` and `--abandon`
  parse to the same field; `mpd closure close` and `abandon` dispatch to the same
  variant.
- **Output-string regression:** the recovery-hint assertions (unit
  `closure_recovery_hint_names_the_change…` + e2e :4581) now assert
  `archive --close --yes`.
- **No-behavior-change:** transaction.rs's own `abandon_*` unit tests pass
  unmodified (the internal fn is untouched); dozens of existing e2e tests that
  INVOKE `--abandon`/`closure abandon` pass unchanged via the alias — direct proof
  of back-compat.

## Results
`cargo test -p mpd`: **504 passed; 0 failed; 1 ignored** (lib) + **110 passed; 0
failed** (e2e). `cargo test -p openspec-core`: 58 + 5 + 15 + 2 + 16 + 20 + 9 + 5
passed, 0 failed. clippy (`--workspace --tests`) + fmt clean. Orchestrator
independently confirmed the two alias-parity tests pass and no user-facing "abandon"
string remains in cli.rs.

## Verdict
PASS — full suite green; the rename is back-compatible (—abandon still works) and
behavior-identical.
