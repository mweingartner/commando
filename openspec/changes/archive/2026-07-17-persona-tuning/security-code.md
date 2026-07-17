# Security (code) — persona-tuning

Canonical current-state artifact. Governance: risk medium, threat profile
local-trusted-user. This was a full-depth audit of the real code on disk (novel
integrity surface), an independent review by a fresh reviewer who did not write the
code, against design.md Conditions 1–12 and the four round-4 Security-plan
conditions.

## Findings

No Critical or High. **No silent-weakening path survives in the implementation.**
All Round-1–3 silent-weakening paths are genuinely closed against the source (not
superficially): the model-clause floor (removed + custom-pin test), the reuse-site
stamp + narrow dependency binding, the `next`→`gate` TOCTOU for BOTH un-rankable
vectors (record-at-next, derive-at-gate, zero `directives::for_persona` in
`cmd_gate`), the wrong-type leniency, the whole-config over-stale (narrow digest),
the monotonic merge, the `String::max` inversion (ordinal `effort_rank`), and the
stale-record masking (exact `(phase, attempt)` filter).

Three LOW findings, all test-adequacy/hardening — none leaves the silent-weakening
invariant open:

- **F1 (LOW, config-revert class) — FIXED INLINE (Builder).** `PersonaTuning.
  directive_append` was a plain `Option<String>`; a hand-edited wrong-type value
  (`"directive_append": 5`) would fail the whole `Config` and revert model pins —
  the same class Cond 2 fixed for the ordinals, but Cond 2's letter named only
  `rigor`/`depth`. Closed with a `de_lenient_string` adapter (permissive `Value` →
  non-string ⇒ `None`, never `Err`), mirroring the reviewed ordinal adapters, plus
  a regression test. This is a 1-field mirror of an already-reviewed pattern on a
  non-weakening surface (not reachable via `mpd persona set`, which always writes a
  valid string), so it was fixed inline rather than re-running Security (code).
- **F2 (LOW, test coverage → Tester).** The reuse-path R6 obligation (Cond 6) is
  correct in code (both `GateRecord` sites stamp; reuse evaluates validity so a
  tuning change stales the receipt) and unit-tested at the digest level
  (`persona_tuning_digest_is_narrow_to_the_persona...`), but lacks an END-TO-END
  test that `gate --reuse` under a tuned persona carries the stamp, and that a
  governed-persona tuning change re-executes `--reuse` while a `test`/`models` edit
  does not. **Deferred to the Test phase (condition below).**
- **F3 (LOW, test completeness → Tester, optional).** The explicit R11(b)
  conditional-write-no-erase case (`set(append) → next → reset → next(clean) →
  gate` still stamped) is bracketed by the (a) and (b2) tests but has no standalone
  test. Code is correct. Optional.

## Conditions verified

All ten mandatory checks passed against the source:
1. **F4-1 (load-bearing):** `base_modified` + `brief_tuning` write in `cmd_next` is
   unconditional + pre-branch (before `--json`/`--context`/`--full`); **zero
   `directives::for_persona` in `cmd_gate`**; the plain-`next` regression test is
   non-vacuous (gating the write behind `--full` reddens it — verified by the
   Builder's revert→red→restore).
2. Both un-rankable vectors symmetric in stamp AND dependency paths.
3. Monotonic weakest-seen merge (OR/max); non-vacuous merge test (neutering it
   reddens the anti-laundering test — verified by revert→red→restore).
4. Conditional write / inertness: untuned `next` leaves the ledger byte-identical;
   baseline `--json` omits all five tuning fields.
5. Leniency: permissive `Value`, unknown/wrong-type/null → `None`, config survives.
6. Floor predicate: no model-equality clause; ordinal `effort_rank`, never String.
7. Stamp at both `GateRecord` sites; narrow `DependencyKey::PersonaTuning`; exact
   `(phase, attempt)` match with live fallback.
8. `persona set` rejects unknown persona names + enum terms; writes via `Config::save`.
9. Reverse-TOCTOU (clean `next` → set-weaken → gate stamps via live fallback) and
   Security-rewind (attempt filter prevents stale masking) both fail-safe.
10. Load-bearing tests confirmed non-vacuous.

## Verdict

**CONDITIONAL PASS.** The code correctly implements all twelve design Conditions and
the four round-4 conditions; no Critical/High; no silent-weakening path survives; all
prior FAILs genuinely closed. F1 was fixed inline (non-weakening, already-reviewed
pattern). One condition carries to the Test phase:

- **[F2 → Tester]** Add the end-to-end reuse-path coverage: (a) a `gate --reuse`
  under a tuned persona carries the `persona_tuning` stamp; (b) a governed-persona
  tuning change (or directive-file edit) makes `--reuse` re-execute; (c) an
  unrelated `test`/`models` edit does NOT stale a governed receipt. F3 (standalone
  R11(b)) is optional deepening.

Proceed to Test. The Test phase closes F2 and runs the non-functional + fuzz/property
passes; the full suite must be green with a real, non-zero count.
