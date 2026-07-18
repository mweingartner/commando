# Test — simplify-command-surface

Governance: risk medium. Functional + guard + parser-property coverage for the CLI
refactor; the two HIGH Security conditions are pinned by proven load-bearing tests.

## Coverage

- **`--exploit` mandatory-presence + validation (Cond 2 / Finding 1):**
  `fail_class_and_security_exploitability_are_strict_and_persisted` (e2e) — absent
  `--exploit` on a Security FAIL refused; malformed (too-few / blank field) refused;
  well-formed records all 5 fields; `--exploit` outside a Security FAIL refused;
  `history.len()==1` proves refusals never mutate the ledger. **Property tests**
  (cli.rs): `parse_exploit` never panics and errors on any field count ≠ 5; five
  non-blank fields round-trip verbatim.
- **Closure fold-in routing (Cond 3 / Finding 2):**
  `archive_recover_and_abandon_reach_the_closure_logic_not_the_pending_refusal`
  (e2e) drives a real AwaitingCommit state and asserts `archive --recover`/`--abandon`
  reach the closure logic, not the "already pending" refusal;
  `archive_recovery_flags_are_mutually_exclusive_and_scoped` covers the four guards.
- **Back-compat (Cond 1):** `begin_is_hidden_but_still_starts_a_manual_change`
  (hidden yet functional, manual tier); `manifest_is_flattened_and_seeds_the_stub`
  (flat `manifest` seeds; old `manifest init` refused); the pre-existing
  `closure_recover_and_abandon_via_binary` still passes (the hidden `closure` alias +
  the plain-archive pending refusal both intact).
- **Help tiering (Cond 4):** `help_leads_with_the_core_loop` asserts the Command
  groups guide leads with the Core loop.

**Load-bearing proofs (revert→red→restore):** neutering `(Fail,true,None)=>Err` to
`=>None` reddens the absent-`--exploit` case; routing `--recover` through `cmd_archive`
reddens the archive-recover test with the "already pending" refusal.

## Results

Full workspace suite: **239 unit + 76 e2e + supporting = all pass, 0 failed** (1
pre-existing ignored perf test). `cargo clippy --all-targets` clean (0 warnings);
`cargo fmt --check` clean. No implementation bugs found. Command: `cargo test`
(workspace) / `cargo clippy` / `cargo fmt --check`.

## Verdict

**PASS.** Functional, guard, and parser-property coverage is green with a real
non-zero count; both HIGH Security conditions are pinned by proven load-bearing
tests. Ready for Deploy.
