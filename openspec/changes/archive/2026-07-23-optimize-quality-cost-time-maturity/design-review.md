# Design Review: Quality-adjusted cost and time maturity

## Actor

Designer-Terra-36

## Intent check

The current Design Mock, Architecture, Builder plan, and seven delta specifications now
realize one coherent operator contract. Quality, model economics, elapsed time,
provenance, validation work, routing evidence, and recovery remain separately typed facts
under existing workflow truth. The release remains cooperative/optional and explicitly
`MISSING`/`NOT DEPLOYED` for required authenticated provenance until a real external
issuer exists; future required mode is fail closed and never treats a fixture, owner
assertion, actor label, or unavailable verifier as authenticated evidence.

## Reviewed scope

Reviewed the current `design-mock.md`, `proposal.md`, `design.md`, `tasks.md`, and all
seven delta specifications. This review specifically rechecked the Security(plan)
revisions for the `security/tool-lock.json`-bound SSHSIG verifier and the shared
`AttestationVerifierState`, plus the final D4/D5 corrections derived from certified-host
acceptance: semantic adapter identity excludes materialization paths, docs Build retains
a fresh release-build artifact, and secret/release checks are ineligible for reuse. No
production code was approved by this pre-Build design review.

## Review result

The Mock's visible typed verifier surface is now fully represented in Architecture,
tasks, and the provenance specification:

- `LOCKED` is possible only after the reviewed absolute `/usr/bin/ssh-keygen -Y verify`
  invocation completes under the exact tool lock; no `PATH`, alternate algorithm, key, or
  unsigned fallback exists.
- `BLOCKED` covers `attestation.verifier-drift`,
  `attestation.verifier-unavailable`, and `attestation.trust-root-mismatch` before
  objective validation.
- `INVALID` covers the Mock's `attestation.namespace`, `attestation.signature`, and
  `attestation.key` codes; all terminal-safe errors remain evidence refusals rather than
  a judgment about review quality.
- `REPLAYED` is `attestation.replay-consumed`, atomically durable across history even if
  the first gate later fails.

The earlier namespace mismatch is closed: `design.md` now enumerates
`attestation.namespace` in the bounded invalid code set, task 1.2 requires it, and the
provenance requirement classifies an invalid namespace accordingly. The remaining seven
outcomes also retain their negative-state contracts: missing usage is not zero; budgets
block only new briefs; reuse preserves fresh security/publication floors; docs lanes are
fail closed; routing uses actual blind Sol/Terra evidence with no fabricated Luna samples;
and operational recovery stays typed, read-only where required, and ambiguity safe.

Human and JSON projections remain shared, additive, terminal-safe, and accessible without
color-only state. No Design Mock acceptance criterion is quietly degraded by the revised
Architecture.

The docs lane now preserves the full Build-to-Deploy artifact contract while narrowing
other checks only for honest effective-Low documentation scope. This is a smaller
efficiency gain than a no-artifact lane, but it keeps deployment semantics uniform and
meets the quality-first design intent.

## Verdict

PASS
