# Security (code) — simplify-command-surface

Independent re-verification of the two HIGH Security-plan conditions against the
real diff (`cli.rs`, `tests/e2e.rs`) — not a Builder self-report. Governance: risk
medium, local-trusted-user.

## Findings

No Critical/High. No credential exposure, injection, path-traversal, or auth-bypass
in the diff. `bounded_text`/`Exploitability` primitives are byte-identical/untouched.

Two LOW advisories (cosmetic/docs, no trust-boundary effect, non-blocking):
- **A1** The flat `mpd --help` subcommand list is not physically reordered — the
  tiering is delivered by the `after_help` "Command groups" guide (which leads with
  the Core loop) rather than a `Command`-enum reorder. Equivalent user outcome;
  reviewer cleared it as cosmetic. Accepted (a physical reorder / `display_order`
  pass is deferred as polish with zero security impact).
- **A2** `README.md` and three `closure.rs` doc comments still reference the removed
  syntax (`manifest init`, `closure recover|abandon` as primary, `--attacker` etc.).
  Fixed in the follow-on docs pass (the README restructure), since README is a
  persistent top-level doc this chore's skipped Documentation phase does not cover.

## Conditions verified (both HIGH, against the source)

1. **`--exploit` MANDATORY on every Security FAIL (Finding 1) — CLOSED.**
   `cmd_gate` (cli.rs) builds exploitability via the exhaustive
   `match (verdict, security, exploit)`: `(Fail, true, Some) => parse_exploit`,
   `(Fail, true, None) => Err` (mandatory presence), `(_, _, Some) => Err` (refused
   outside a Security FAIL, incl. with `--reuse` which forces Pass), `(_, _, None)
   => None`. NOT `.map/.transpose`. `parse_exploit` requires exactly 5 `|`-fields,
   each `bounded_text`. e2e `fail_class_and_security_exploitability_...` pins
   absent/malformed/blank-refused + well-formed-records-5 + outside-Security-refused,
   with `history.len()==1` proving refusals don't mutate the ledger. **Proven
   load-bearing** (neuter `(Fail,true,None)=>Err` → the absent-case assertion reddens).
2. **`--recover`/`--abandon` routed before `cmd_archive` (Finding 2) — CLOSED.**
   The `run()` `Command::Archive` arm routes recover/abandon DIRECTLY via `find_root()`
   → `cmd_closure_recover`/`cmd_closure_abandon`, never through `cmd_archive` (whose
   pending-closure early-return is reached only by the plain `(false,false)` arm).
   Guards: recover XOR abandon; neither with `--skip-specs` or `--change`; `--json`
   scoped away from the plain path. e2e reaches a real AwaitingCommit state and
   asserts `archive --recover`/`--abandon` reach the closure logic, not the "already
   pending" refusal. **Proven load-bearing** (route `--recover` through `cmd_archive`
   → the test reddens with "already pending").

No functional regression: `Begin`/`Closure` hidden but dispatched (aliases still
work — `closure_recover_and_abandon_via_binary` passes); `manifest` flatten preserves
the seed + `resolve_change` path-validation; nothing beyond the 5 planned decisions
changed.

## Verdict

**PASS.** Both HIGH conditions genuinely closed in code with non-vacuous e2e evidence;
no security defects. The two advisories are cosmetic/docs (A1 accepted; A2 fixed in
the docs pass). Proceed to Test.
