# Design: Complete the MPD maturity assessment

## Actor

Architect-Terra-52

## Context

The durable document describes controls but omits the requested maturity scores and even
links to itself for those absent scores. The correction must assess effectiveness, not
equate implemented mechanisms with proven outcomes.

## Goals / Non-Goals

Goals: define a stable 1-5 scale; score quality, cost, time, provenance, and routing;
distinguish control maturity from empirical outcome evidence; cite repository evidence;
name risks and prioritized next steps.

Non-goals: change code or policy, invent provider cost/token data, claim authenticated
provenance, claim routing optimality, or recast a single benchmark run as longitudinal
evidence.

## Decisions

1. Use levels Initial, Defined, Managed, Measured, and Optimizing. A level requires both
   repeatable controls and evidence appropriate to that level.
2. Score the three requested dimensions separately and add provenance/routing as supporting
   dimensions because they materially constrain the quality/cost claims.
3. Derive the headline from the three requested dimensions without fabricating a weighted
   precision score: `Defined, approaching Managed`.
4. Cite local primary evidence: committed configuration, source architecture/security
   contracts, routing run status, archived gate/test records, and the immutable release
   receipt identifiers.
5. Keep `docs/optimize-quality-cost-time-maturity.md` as the canonical assessment and add
   `docs/complete-maturity-assessment.md` as the follow-up correction record required by
   the change-scoped documentation contract.

## Risks / Trade-offs

- False precision -> use integer levels and confidence/evidence qualifiers.
- Positive-bias overstatement -> list missing telemetry and negative states beside controls.
- Stale operational numbers -> label the assessed release and observation date.
- Self-reference or unverifiable claims -> link each conclusion to a concrete repository
  source or receipt identifier.

## Verdict

PASS

## Conditions for Builder

1. Modify only the declared documentation/OpenSpec paths; no runtime or policy bytes.
2. Do not invent token, active-time, provider-price, cost, quality-score, or attestation
   evidence; missing remains missing.
3. Keep authenticated provenance `NOT DEPLOYED` and routing evidence `INSUFFICIENT`.
4. Preserve the observed release identifiers and distinguish Candidate, Commit, remote,
   and installed artifact facts.
5. Every maturity score must include both supporting evidence and the gap preventing the
   next level.
6. Run docs-profile Build/Security/Test, doc validation, archive, commit, push, parity, and
   installed-byte recheck; documentation does not make the prior binary stale.
