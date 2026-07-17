# Test — persona-tuning

Canonical current-state artifact. Governance: risk medium, threat profile
local-trusted-user. Functional + non-functional + property/fuzz/metamorphic
coverage; the Builder wrote the initial tests, the Tester deepened and closed the
Security-code F2 condition.

## Coverage

Every design Condition (1–12) and Risk-to-test-matrix row (R1–R12, incl. R4b/R4c/
R6b) has at least one test; the security-critical invariants have load-bearing
(revert→red→restore) proofs.

**Unit (config.rs / harness.rs / ledger.rs / closure.rs):**
- Leniency (R2, Security-code F1): unknown-token AND wrong-type AND null values in
  `rigor`/`depth`/`directive_append` degrade per-field to `None`, never fail
  `Config::load`, and the rest of the config (model pins, test command) survives —
  example-based + a **proptest** over arbitrary JSON values simultaneously in all
  three fields.
- Resolver (R1/R3/R4/R4b/R4c/R5/R8): baseline inertness; high-risk floor to `high`
  for the adversarial set with NO model-equality clause (custom-pin variant);
  ordinal effort compose (no `String::max` inversion); depth Test-only; reviewers
  additive/clamped; directive sanitize (oversized→None, control stripped, weakened
  iff carried). **Property tests:** effort is never ranked below the tier baseline,
  is monotonic in rigor rank, and paranoid ≥ deep.
- Ledger (R11 merge): `is_baseline`, conditional/monotonic `record_brief_tuning`,
  `merge_weakest_seen` weakest-seen semantics, legacy-defaulting. **Property test:**
  the merge never downgrades any input flag/ordinal (anti-laundering).
- Closure (R6b): the narrow `persona_tuning_digest` stales on a persona tuning/
  directive change but NOT on an unrelated config edit, and not across personas;
  golden dependency-policy table + phase-causality audit updated for `PersonaTuning`.

**End-to-end (tests/e2e.rs, through the built binary):**
- R11(a) config weakening survives reset before gate (next→gate TOCTOU close).
- R11(b) conditional-write-no-erase survives a clean re-brief.
- R11(b2) the weakest-seen MERGE survives a reconfigured non-weakened re-brief.
- R11(d) directive-file weakening survives restore via a PLAIN `next` (proves the
  write is unconditional/pre-branch — round-4 F4-1).
- R11(c)/R1 an untuned `next` leaves the ledger byte-identical; a baseline gate is
  unstamped.
- R10 tuning never blocks advancement.
- R7 `persona set` rejects an unknown persona name + enum term; `show --json`
  exposes current/range/baseline/dangerous.
- **F2 (Security-code condition):** a `gate --reuse` under a tuned persona carries
  the `persona_tuning` stamp on the reused record; a governed-persona tuning change
  AND a directive-file edit each stale the receipt so `--reuse` is refused, while an
  unrelated `test`/`models` edit does NOT.

**Load-bearing proofs (non-vacuity, documented in test comments):** neutering
`merge_weakest_seen` reddens the merge/anti-laundering tests; gating the
`brief_tuning` write behind `--full` reddens the plain-`next` directive test;
nulling the reuse-site stamp reddens the reuse-stamp test; dropping `PersonaTuning`
from `DependencyPolicy::for_phase` reddens the reuse-staling test.

## Results

Full workspace suite: **428 passed, 0 failed, 1 ignored** (a pre-existing
perf-throughput test, unrelated to this change). Real, non-zero count. `cargo clippy
--all-targets` clean (0 warnings); `cargo fmt --check` clean. No implementation bugs
found by the Tester; no non-test source changed during deepening.

Command: `cargo test` (workspace), `cargo clippy --all-targets`, `cargo fmt --check`.

## Verdict

**PASS.** Functional, non-functional (config-parse leniency fuzz, ordinal-composition
properties), and metamorphic (merge monotonicity) coverage is green with a real
non-zero count; the Security-code F2 condition is closed with a load-bearing
end-to-end reuse test. The change is ready for Documentation and Deploy.
