# Security Plan Review: Quality-adjusted cost and time maturity

## Actor

Security-Terra-37

## Reviewed scope

Reviewed the current `proposal.md`, `design-mock.md`, `design.md`, `tasks.md`, all seven
delta specifications, `design-review.md`, `SECURITY.md`, `.mpd/config.json`,
`security/tool-lock.json`, and the existing tool-lock resolution seam in
`crates/mpd/src/local_validation.rs:7995-8288`. I also reviewed the current validation
receipt identity seam (`local_validation.rs:2361-2442`) and marker-only compatibility hook
(`githooks.rs:100-107`), including the final semantic-adapter and docs Build artifact
corrections recorded in Architecture.

No production code was changed or approved by this review. The actual SSHSIG tool-lock row,
resolver support, verifier implementation, and trusted-policy activation are Build and
Security(code) obligations; they are not claimed as present in the current working tree.

## Prior findings resolved in the approved plan

- [HIGH — RESOLVED] `design.md:36-58` formerly left issuer-material confinement and the
  verifier mechanism underspecified. The plan now requires activated-policy-bound no-follow
  trust material and only `sshsig-ed25519-v1`: absolute tool-lock-bound
  `/usr/bin/ssh-keygen -Y verify`, fixed `mpd-attestation-v1` namespace, exact issuer/key
  identity, canonical length-delimited payload bytes, private bounded message/signature/
  allowed-signers inputs, typed argv, cleanup, and exit-status-only acceptance. Task 1.1
  requires the reviewed path/digest/platform/argv lock entry; task 1.2 requires known-answer
  and tool-drift tests. Security(code) must confirm the candidate entry and resolver rather
  than treating this plan as implementation evidence; required mode must be `BLOCKED`,
  never silently fall back.

- [HIGH — RESOLVED] `design.md:77-87` now requires durable full-history, ledger-lock
  consumption of a valid attestation digest before objective execution. The replay claim
  survives a later objective failure, while malformed or unclaimed input has no state
  effect. `specs/usage-attestation/spec.md:8-16` adds the concurrent-claim scenario.

- [HIGH — RESOLVED] `design.md:177-183` and
  `specs/routing-benchmarking/spec.md:28-43` bind routing apply to a reviewed allowlist of
  existing harness/persona entries. Evidence cannot add/delete keys, cross harnesses, or
  change non-routing configuration; preview digest drift refuses the atomic write.

- [HIGH — RESOLVED] `design.md:222-246` and
  `specs/operator-recovery/spec.md:34-45` replace check-then-recursive-delete with complete
  live/archived reference retention plus an opened-parent, descriptor-relative no-follow
  same-parent quarantine, post-rename identity revalidation, and ambiguity retention.

- [MEDIUM — RESOLVED] `design.md:69-76`, task 1.2, and
  `specs/review-provenance/spec.md:23-34` add the missing namespace refusal contract:
  `attestation.namespace` is bounded `INVALID`, while verifier drift/unavailability and
  trust-root mismatch are `BLOCKED`; none may be rendered as review quality or a gate PASS.

## Security assessment

The plan correctly preserves the existing local-only boundary. Attestation use is optional
and cooperative in this release; a future required mode fails closed before objective
validation unless the external issuer, exact session binding, locked verifier, namespace,
key, signature, replay state, and trust root all validate. It neither stores private keys
nor substitutes actor labels or fixtures for authenticated provenance.

Budget/anti-stall policy is typed and blocks only issuance of a new brief; observation and
completed-evidence recording remain possible. Incomplete telemetry is unavailable rather
than zero, and clock ambiguity blocks issuance. Reuse remains complete-identity closed with
fresh Security(code), secret scan, Commit, and pre-push floors. Documentation profiles are
effective-Low/docs-only with fail-closed configured floors. Routing stays offline and
preview-first. Hook/archive/doctrine/cache changes preserve typed read-only or
ambiguity-blocked behavior.

## Threat model

Attackers may provide malformed, oversized, replayed, cross-bound, or terminal-hostile
attestation and routing files; replace paths/sidecars during inspection; manipulate
environmental tool lookup; submit stale receipts with matching names; or exploit clock and
ledger-concurrency edges. They do not include the cooperative repository owner, who can
replace local code, policy, records, or hooks and remains an explicit nonclaim in
`SECURITY.md`. The crossed boundaries are external evidence to gate provenance, reviewed
policy to routing/tool invocation, and clone-private cache state to deletion. Resulting harm
would be false authenticated provenance, unauthorized routing changes, stale validation
reuse, unsafe deletion, or false readiness. The approved containment is exact binding,
tool-lock identity, private bounded I/O, atomic ledger claims, full receipt identity,
reviewed write allowlists, descriptor-relative quarantine, and fail-closed typed states.

## Conditions for Builder

1. Implement only `sshsig-ed25519-v1` using the reviewed absolute verifier, fixed
   namespace/identity, canonical payload, bounded clone-private inputs, and a verified
   `security/tool-lock.json` entry; any missing or drifted component is BLOCKED.
2. Atomically consume accepted attestation digests under the ledger lock before objective
   execution and never use actor labels, fixture keys, missing evidence, or a failed first
   attempt as an authentication/replay bypass.
3. Keep budgets/reuse/docs/routing/cache behavior within the exact policy floors and typed
   negative states described by `design.md`; security/publication checks, non-routing
   config, referenced cache entries, and archived state remain protected.
4. Before every mutation, bind and revalidate the exact reviewed subject; preview/read-only
   commands make no writes, all effects are bounded/atomic/terminal-safe, and ambiguity
   blocks rather than degrades.

## Required downstream verification

Security(code) must inspect the real implementation for: exact tool-lock entry/digest/path
validation; no ambient PATH or fallback; fixed SSHSIG argv/namespace/identity; private-temp
cleanup and output caps; canonical-payload and rejection vectors; atomic replay races;
routing write scope; and descriptor-relative cache effects. Tester must execute the stated
property, race, sandbox e2e, and full authoritative profiles. Required authenticated
provenance remains `MISSING`/`NOT DEPLOYED` until a real external issuer exists.

## Omitted scope

This plan gate does not approve implementation, dependency/bootstrap provenance, an actual
issuer, routing adoption, sandbox receipts, deployment, installation, Git transport, or
remote parity. Those require their own downstream evidence even when present in the current
working tree.

## Verdict

PASS
