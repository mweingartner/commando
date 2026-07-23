# Quality-adjusted cost and time maturity

## Purpose

Document the exact controls and evidence MPD can use to protect output quality while
bounding model cost, elapsed time, and redundant local verification.

## Value

Operators receive typed coverage and negative states instead of inferred savings. The
maturity assessment separates enforced controls from external evidence still missing.

## Scope

It covers cooperative review attestation, usage budgets, anti-stall policy, exact-check
reuse, docs profiles, offline routing evidence, and typed recovery. It does not claim
authenticated provenance without an external issuer, comparable provider billing without
complete evidence, or globally optimal routing.

## Functional details

`status`/`stats` render per-metric coverage; hard budgets and repeated typed blockers stop
new briefs but preserve observation. Reuse binds the complete Candidate identity and never
reuses security scans or artifact production. Effective-Low docs changes use reviewed
reduced profiles while retaining a release artifact. Routing is offline/read-only before a
previewed allowlisted write. Cache pruning quarantines only unreferenced verified entries.

## Usage

```sh
mpd status --json
mpd stats --json
mpd routing evaluate --evidence <routing-evidence.json>
mpd routing apply --evidence <routing-evidence.json>
mpd cache inspect --json
mpd cache prune
```

Use mutation `--yes` flags only after reviewing the preview. Supply `--attestation` only
for the exact gate attempt it binds.

## Maturity method

This assessment uses five evidence thresholds:

1. **Initial** — controls are ad hoc and results are not repeatable.
2. **Defined** — controls and responsibilities are documented and repeatable.
3. **Managed** — controls are enforced and produce current operational evidence.
4. **Measured** — trusted longitudinal quality, cost, and time data demonstrates outcomes.
5. **Optimizing** — controlled experiments repeatedly improve quality-adjusted cost or
   time without weakening security or output quality.

A dimension receives the highest level supported by both controls and evidence. An
implemented mechanism does not by itself prove effectiveness. The assessed release is
commit `d284a924ad4412f4d7c48d3e10f76165bb2e64fc`, archived on 2026-07-23. Its exact
Commit-profile receipt is
`25eff17c4c2fcd72e605991fa00b410022b52d217bee4c57c86a895d61284177`.

## Assessment

**Headline: Defined, approaching Managed.** Quality assurance and time controls are
Managed, while cost efficiency is only Defined. Because cost is a required part of the
question and has no trusted usage coverage, the combined system cannot yet be called
Measured or empirically optimized.

| Dimension | Level | What the evidence supports | What blocks the next level |
| --- | --- | --- | --- |
| Output-quality assurance | **3/5 — Managed** | Written intent, ordered role-separated gates, explicit verdicts and conditions, exact Candidate/Commit identities, fresh adversarial checks, local containment, and a typed Build-to-Deploy artifact are enforced. Release acceptance passed 853 tests with no failures; the ignored 10,000-path/100 MB workload passed separately. | There is no independent longitudinal scoring of task-output quality. Actor labels are cooperative, and acceptance exposed five real defects before the final pass, showing that process rigor reduces escape risk but does not prove model correctness. |
| Model-cost efficiency | **2/5 — Defined** | Risk budgets, per-metric coverage, hard/soft limits, anti-stall stops, exact-check reuse, documentation lanes, and guarded routing are implemented. Missing values remain unavailable instead of being guessed. | The assessed traversal reported usage for **0 of 30** applicable attempts: tokens, active time, currency, and cost were not trusted or comparable. With no quality-adjusted cost baseline, savings and route optimality cannot be measured. |
| Time efficiency | **3/5 — Managed, evidence-limited** | Wall-clock coverage was **30/30** and totalled **4,921 seconds (about 82 minutes)**. The fixed two-blocker/30-minute stop rule limits unproductive continuation. On a byte-identical prose re-drive, format reused a 1,455 ms result and doctrine reused a 905 ms result while security and artifact checks ran fresh. | Active-time coverage was **0/30**, and there is no longitudinal baseline or median by change type/risk. Thirty attempts, 12 freshness rewinds, and five acceptance-time defects indicate material process overhead that has not yet been optimized. |
| Review provenance | **2/5 — Defined** | Attempt records bind cooperative actor, phase, artifact, subject, and optional attestation fields; required mode is designed to fail closed. | Authenticated external provenance is **NOT DEPLOYED**: no external issuer is configured, so model/session/usage claims remain cooperative and the repository owner boundary remains explicit. |
| Model routing | **2/5 — Defined/experimental** | A versioned blinded suite, deterministic evaluator, preview-before-write flow, allowlisted mutations, and preserve-current-mapping fallback exist. Actual sessions covered 6 Sol Architect/Designer samples and 12 Terra Security/Builder/Tester/Documenter samples. | The committed result is **INSUFFICIENT** because trusted token counts, active duration, currency/cost, and independent blind scores are missing. The mapping was therefore preserved, correctly, rather than declared optimal. |

The quality score measures enforcement maturity, not semantic correctness. The cost and
time scores measure the model-orchestration path only where evidence exists; local build
time and model active time are not interchangeable. The release evidence is in the
[archived test report](../openspec/changes/archive/2026-07-23-optimize-quality-cost-time-maturity/test.md),
[Security review](../openspec/changes/archive/2026-07-23-optimize-quality-cost-time-maturity/security-code.md),
and [tracked ledger](../.mpd/state/optimize-quality-cost-time-maturity.json).

## Effectiveness and risks

- **Quality:** the control stack is effective at making scope, review, verification,
  deployment, and failure states explicit. It cannot establish that a model-produced
  design or answer is objectively good without an independent outcome evaluator.
- **Cost:** budgets can stop known overruns, but incomplete telemetry makes most
  token/cost decisions unavailable. Calling the present routing cheaper would be an
  unsupported inference.
- **Time:** exact-check reuse and bounded continuation can remove redundant work, but high
  retry/rewind counts may dominate small changes when scope classification or reuse
  eligibility is wrong.
- **Trust:** cooperative labels improve accountability but are not authenticated
  provenance and do not isolate the coordinator from a same-user repository owner.
- **Optimization:** routing cannot be optimized responsibly until comparable routes have
  trusted usage, cost, active-time, and independently blinded quality scores.

These conclusions follow the repository's primary contracts for
[quality, cost, and time](../README.md#quality-cost-and-time-maturity),
[governance economics and provenance](../ARCHITECTURE.md#governance-economics-and-provenance),
and [attestation, economics, routing, and cache effects](../SECURITY.md#attestation-economics-routing-and-cache-effects).
The configured budgets and routing are in [`.mpd/config.json`](../.mpd/config.json), and
the current experimental decision is recorded in the
[routing run status](../benchmarks/routing-v1/run-status.json).

## Priorities to reach Measured maturity

1. **P0 — trustworthy denominators:** capture externally attested per-attempt input,
   output, and cached tokens; active duration; currency; and cost micro-units. Preserve
   unavailable values rather than estimating them.
2. **P0 — independent quality outcomes:** define representative task families and blind,
   independent scoring bound to the exact prompt/output/evaluator envelope.
3. **P1 — longitudinal quality-adjusted economics:** report medians and variation by
   change kind, effective risk, persona, and route for quality, model cost, active time,
   wall time, defect escape, rework, and freshness rewinds.
4. **P1 — prove efficiency mechanisms:** measure documentation-lane eligibility,
   execution-versus-reuse hit rates, saved validator time, and false eligibility or stale
   reuse incidents.
5. **P2 — controlled routing trials:** require a predefined minimum sample, comparable
   currency/time evidence, blinded quality thresholds, and rollback before changing a
   reviewed route.

Level 4 requires at least 95% trusted token and active-time coverage for applicable
attempts, independently scored representative outputs, explicit per-currency cost
coverage (or an explicit unavailable state), and predefined before/after trials showing
quality-adjusted improvement without a security, quality, or defect-escape regression.
Level 5 additionally requires repeated controlled improvements across multiple task
families and observation windows. The present release does not meet either threshold.
