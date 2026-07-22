# Test report

## Actor
Tester (claude-code harness). Functional + boundary verification of the strict
receipt-reuse equality set and the A0/A1/A2 conditions; non-functional surface
assessed and scoped.

## Coverage

**Functional — the reuse equality set (A2), exercising the real shipping functions**
(`attempt_strict_reuse`, cli.rs:9627, drives the actual `capture_dependency_values` /
`evidence_validity` / `evaluate_reuse` / `evaluate_strict_objective_reuse`; only the
thin cmd_gate glue is reproduced):
- `strict_build_and_test_reuse_succeed_on_a_byte_identical_candidate` (cli.rs:9768) —
  the success path for BOTH phases; asserts the Reused record carries the FRESH
  recapture's candidate id, the build-output (Build) / validation receipt, and a
  `"reused from receipt"` check summary.
- Per-phase **negative** binding tests (cli.rs:9997-10044) — an origin whose
  validation-receipt subject names a different candidate REFUSES for Build and Test
  (C2); build-output binding unit at cli.rs:10046-10058.
- Profile mismatch refuses (origin `test` vs current High→`high-risk-test`,
  cli.rs:9859-9877); HermeticExecutable digest drift refuses (cli.rs:9900-9939);
  Build-output disk drift/deletion refuses (cli.rs:10060-10110); missing hermetic
  policy → `AlwaysExecutes` refusal (cli.rs:9880-9897).
- **A1** SecurityCode categorical refusal, end-to-end through the real binary
  (e2e.rs:554-577), with byte-identical-ledger + Git-state assertions; Build/Test
  refuse mutation-free at "no receipt exists" (e2e.rs:581-614).
- **C1** scan-floor red-test (cli.rs:10113-10133) — removing a required scan kind
  makes `LocalValidationConfig::validate` fail closed.
- **CA** real-binary e2e (`strict_build_test_reuse_via_real_binary_reaches_the_trust_wall_and_prose_edits_are_never_free`,
  e2e.rs:2260) — drives the actual `mpd` binary: A0 opens no bypass (still hits the
  trusted-policy wall), `--reuse` with no history reaches the ordinary origin-lookup
  refusal (not a categorical block), and an in-scope design.md edit genuinely stales
  Architecture/SecurityPlan and forces a rewind (the negative half of the corrected
  firing set). The full subprocess success path is architecturally infeasible (no
  `lib` target; a real Build PASS needs an activated host-pinned trust floor) — the
  in-process success tests above are the accepted evidence.
- **L2** serde-hardening red tests — `hermetic_policy_rejects_an_unknown_field`
  (closure.rs) and `unknown_field_inside_closure_hermetic_reuse_block_fails_parse`
  (config.rs); the real `.mpd/config.json` still parses.

**Serializer/parser surface** (config deserialization of `HermeticReusePolicy`) is
covered by the L2 red tests plus the closed-enum `NoExternalState` parse test
(closure.rs:4066-4079); with `deny_unknown_fields` the accept/reject boundary is
exhaustive for this small struct, so a dedicated fuzz pass adds no meaningful signal.
The risk-classifier proptests (closure.rs:5246+) are untouched and still green.

**Non-functional:** N/A with rationale — the reuse decision is a deterministic
equality check over already-persisted receipts; it starts NO new sandbox workload
(it exists precisely to AVOID one), adds no network/concurrency/accessibility surface,
and the one shared-state write is now the same CAS the execute path uses (L1). No
performance, load/stress, or resource budget applies.

## Results
- `cargo test --workspace --all-targets --offline --locked` = **517 passed / 0 failed
  / 1 ignored** (mpd bin unit; the ignored is the pre-existing 10k-path perf
  benchmark) + **111 passed / 0 failed** (mpd e2e, includes the new reuse e2e, named
  in output) + **58 + 5 + 15 + 2 + 16 + 20 + 9 + 5 passed** (openspec-core lib +
  integration). Zero failures.
- `cargo clippy --workspace --all-targets --offline --locked -- -D warnings` = clean.
- `cargo fmt --all -- --check` = clean.
- The authoritative Build and high-risk Test gate profiles re-execute this suite in
  the hermetic, exact-Candidate sandbox; both recorded PASS with a real non-zero count.
- No production defect surfaced during testing.

## Verdict
PASS. Every A0/A1/A2/C1/C2 behavior and each closed condition (CA/L1/L2) has a
non-vacuous, load-bearing assertion; the full suite is green with real counts and
re-verified by the sandbox Build/Test gates; non-functional surface is genuinely N/A.
