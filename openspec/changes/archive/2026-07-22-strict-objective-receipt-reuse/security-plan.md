# Security (plan) review

## Actor
Security (claude-code harness, deep tier — high-risk). Reuse-of-verification is the
highest-stakes surface; full adversarial review of the equality set.

## Threat model
The change relaxes when strict mode may reuse a prior Build/Test validation receipt
instead of re-executing the sandbox. The attack is: reuse a receipt when the thing
it certified is no longer true (a stale-evidence hole). Verified against real code
that the equality set is COMPLETE and every mismatch is fail-closed:
- **Candidate id** binds base_tree + manifest + entries + policy + source
  (candidate.rs:2657-2675); base_tree is the full HEAD tree so any committed change
  (Cargo.lock/toml, .mpd/config.json, tool-lock, toolchain files) changes it;
  undeclared dirty files are EXCLUDED from the candidate and validation runs inside
  the materialized root, so they can't influence the run; re-capture runs
  verify_retained_projection (detects retained-root tampering).
- Every validation input maps to a covering term: policy (checks/profiles/sandbox/
  advisory-pins/limits) is INSIDE the id via policy_digest; TestCommand, Toolchain,
  Source, Scope, PersonaTuning are per-key compared by evidence_validity (a missing
  non-hermetic key can't even snapshot → refuse); profile by A2 item 3 (id doesn't
  bind profile — computed from CURRENT effective risk after the freshness commit);
  build output by A2 item 5 (disk revalidate); coordinator/platform/env/inputs by
  hermetic keys (HermeticExecutable binds the running binary's digest → coordinator
  swap refuses).
- A0 attestation defensible: all cargo checks --offline --locked; semgrep in-repo
  rules metrics-off; gitleaks local dir; cargo-audit --no-fetch vs a policy-pinned
  advisory DB (bump → policy_digest → id); env-cleared sandbox with policy-pinned
  allowlist + network-deny; execution-time tool-digest verification vs tool-lock,
  bound as HermeticInput. Config-only, parses under deny_unknown_fields (misspelling
  fails to parse, doesn't grant reuse).
- A1 (SecurityCode-only refusal) sound: SecurityCode never carries forward; every
  rewind wipes gates >= Architecture and re-runs the full deterministic scan set
  (policy-static, dependency-audit, gitleaks, semgrep) fresh on the candidate. This
  is the premise that makes reusing Test's embedded scans safe.
- Fail-closed: evaluate_reuse failure errors BEFORE any ledger write; every miss →
  fresh execution; --reuse strictly opt-in (explicit receipt hex, requires --pass;
  mpd next only prints the offer). Freshness/rewind logic untouched.

## Conditions for Builder
Inherits design.md Conditions 1-9. Plus these three from the review (verify at
Security (code)):
- **C1 [Medium] Machine-pin the security-code scan floor.** A1's soundness rests on
  the security-code profile containing the full deterministic scan set
  (config.json profiles.security-code). A future trim would let NEW pipelines reuse
  Test with no fresh dependency-audit/gitleaks/semgrep anywhere. Add a
  selection-time floor for the security-code gate profile (mirror the docs-lane
  floor, closure.rs:2357-2379) requiring kinds {self-check, dependency-audit,
  secret-scan, sast}, OR minimally an e2e pinning the resolved security-code check
  set (red when a scan kind is removed).
- **C2 [Medium] Receipt<->candidate binding mirror for BOTH phases.** Apply the
  validate_candidate_report_binding-equivalent checks (subject.requested ==
  "candidate:<id>", base commit/tree, build_output candidate_id) to the ORIGIN
  record for Build AND Test reuse. Negative test: an origin whose validation_receipt
  subject names a different candidate refuses for each phase.
- **C3 [Medium — CLOSED here] Name the residual ambient inputs.** The
  external_state:"none" attestation must not imply ZERO external reads; the
  genuinely-ambient-but-mitigated inputs are: (a) user-level cargo config under
  $CARGO_HOME/$HOME (allowlisted through the sandbox) — mitigated by --offline
  --locked + Cargo.lock checksums; (b) SDK/linker via DEVELOPER_DIR — mitigated by
  the pinned DEVELOPER_DIR env contract; (c) OS version beyond os-arch
  (HermeticPlatform binds os-arch only) — mitigated by offline+locked hermetic
  builds; (d) cargo binary version beyond `rustc --version` — mitigated by
  execution-time tool-digest verification vs security/tool-lock.json. The
  attestation means "no UNPINNED external mutable state feeds validation," not
  "zero external reads." The Builder's docs task states this.

Low advisories (non-blocking): Toolchain uses unwrap_or_default on rustc --version
(fail-closed in practice; consider erroring for execution-bearing phases); the reuse
path bypasses attempt_authorized (pre-existing, executes nothing; worth a comment).

## Re-review (attempt 2)
The design was amended after Security (code) to correct a false premise (the
"prose-only edit → byte-identical candidate → reuse" scenario is unachievable — the
change's prose is bound into the Candidate via mandatory process scope, so prose edits
correctly force fresh execution). This is a documentation-accuracy correction: it does
NOT alter the reuse equality set, the threat model, or any fail-closed property this
review traced. C1 and C2 are now confirmed satisfied in code and tests
(`validate_required_lane_coverage`, config.rs:661-733; `validate_origin_receipt_candidate_binding`,
cli.rs:3020-3047 with per-phase negative tests) and C3 remains closed; additionally L2
(`deny_unknown_fields` on `HermeticReusePolicy`/`ClosureConfig`) makes the earlier
"parses under deny_unknown_fields" note precisely true. The plan-stage conditions are
therefore discharged.

## Verdict
PASS. The equality set is complete for every validation-consuming input traced, and
every mismatch is fail-closed; no stale-receipt hole found. C1/C2 discharged in code,
C3 closed, L2 hardened. Build may proceed.
