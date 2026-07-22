## 1. Config opt-in (.mpd/config.json)
- [x] 1.1 Add `closure.hermetic_reuse` (snake_case; external_state:"none", environment:[], input_paths:["security/tool-lock.json"]). Parses (HermeticReusePolicy), stales nothing. Hardened with `deny_unknown_fields` (L2).

## 2. Reuse path (crates/mpd/src/cli.rs)
- [x] 2.1 Narrow the strict --reuse refusal to SecurityCode only (was Build|SecurityCode|Test).
- [x] 2.2 Strict Build|Test reuse block: candidate-id equality (fresh capture / retained_candidate_for_objective_gate), profile equality, policy equality, build-output revalidation (Build, incl. device/inode), reuse-origin from history + evidence_validity/evaluate_reuse; origin receipt↔candidate binding for BOTH phases (C2); record the Reused GateRecord carrying candidate/validation_receipt/build_output/CheckSummary via the execute-path CAS save (L1). Any miss → fresh execution.

## 3. Must-not-weaken tests (crates/mpd/tests/e2e.rs + cli.rs units)
- [x] 3.1 Source/config edit → objective re-run + rewind; reuse refused (headline).
- [x] 3.2 Byte-identical-candidate rewind (off-Candidate cause) → judgment re-runs fresh, Build+Test reuse succeed through the real `evaluate_strict_objective_reuse` with matching candidate/receipt/build-output ids (cli.rs:9768); the real-binary e2e (e2e.rs:2260) drives `mpd` to the trust wall and confirms an in-scope prose edit forces a rewind (reuse refused). NOTE (corrected from the false "prose-only edit reuses" premise): prose is in the Candidate, so a prose edit is NOT reusable; the full subprocess success path is infeasible (no lib target / trust floor) — the in-process success test is the accepted evidence.
- [x] 3.3 SecurityCode --reuse categorically refused (strict, e2e.rs:554); profile-mismatch refuses; hermetic-gap refuses; Test ordering refuses; missing/drifted build-output refuses.
- [x] 3.4 (C1) security-code scan-floor red-test; (L2) unknown-field parse-refusal red-tests.

## 4. Docs (README.md, AGENTS.md, .mpd/directives/protocol.md + crates/mpd/assets/directives/protocol.md in sync)
- [x] 4.1 AGENTS.md operating loop: lean protocol (freeze prose before gating; tier-match / self-author low-surface reviews; batch same-scope small changes; non-blocking findings as notes; declare the manifest completely; `--close` landing). Accurate risk→tier mapping.
- [x] 4.2 README.md model/risk/effort guidance: High LOOSENS the attempt limit (real High cost = deep-model bump + effort floor + heavy Test profile); the strict-reuse rule stated with the CORRECTED firing set (byte-identical candidate only; prose edits re-execute).
- [x] 4.3 protocol.md + shipped twin in sync (one accurate reuse sentence).
- [x] 4.4 design.md/proposal.md/tasks.md/README/AGENTS corrected after Security (code): the "prose-only edit reuses" premise removed; documentation.md + docs/<change>.md written.

## 5. Verification & landing
- [x] 5.1 Full suite green (517 unit + 111 e2e + openspec-core, real counts); freshness files byte-unchanged; clippy/fmt clean.
- [ ] 5.2 Rebuild + reactivate coordinator before commit.
