# Builder Plan: Quality-adjusted cost and time maturity

`design.md` is the sole Builder authority. Every box is required and has a stable ID.
All 24 tasks are required with no deferral. Check a box only when its focused code and
test evidence exists; later gates, archive, commit, push, parity, and installation remain
separate facts.

## 1. Compatible evidence foundations

- [x] 1.1 Add validated governance/routing/docs-profile config schemas, including activated-policy-bound no-follow issuer trust roots, a reviewed routing-target allowlist, and `security/tool-lock.json` for the exact SSHSIG verifier path/digest/platform/argv, with legacy/malformed round-trip tests.
- [x] 1.2 Add bounded attestation/usage/provenance types, fixed-field canonical `sshsig-ed25519-v1` encoding verified only through tool-lock-bound `/usr/bin/ssh-keygen -Y verify` with its fixed namespace, exact issuer/key identity, capped private temporary inputs, exact binding, full-history atomic replay consumption, typed `LOCKED`/`BLOCKED`/`INVALID`/`REPLAYED` refusal states and codes (including `attestation.namespace`), and trust-root/adversarial/known-answer/tool-drift/property tests.
- [x] 1.3 Add defaulted ledger records for usage, provenance, brief expectations, and one-use continuations with compatibility fixtures.
- [x] 1.4 Add external-issuer conformance fixtures/protocol, explicit `MISSING`/`NOT DEPLOYED` readiness, and fail-closed required-mode tests; do not activate required mode or present fixture/owner-self-signed evidence as production proof.

## 2. Economics and bounded model work

- [x] 2.1 Implement per-metric coverage-aware currency/token/active/wall aggregation and soft/hard budget evaluation, including known-overrun lower bounds and incomplete-coverage UNAVAILABLE behavior, with overflow/clock property tests.
- [x] 2.2 Extend `NextBrief` and gate ingestion with required-attestation preflight, typed blocker classification/clock-regression handling, budget/anti-stall blocking, and atomic one-use continuation.
- [x] 2.3 Add shared human/JSON status, gate, and stats projections; golden-test every state, hostile output, narrow/non-TTY/NO_COLOR, and missing-versus-zero.

## 3. Exact check reuse

- [x] 3.1 Add executed/reused check dispositions to validation receipts and bind them into receipt identity.
- [x] 3.2 Implement current-change/current-subject full-identity check reuse with stable semantic environment identity, executed-origin flattening, and mismatch/property/concurrency tests.
- [x] 3.3 Preserve fresh Security(code), outgoing secret scan, Commit, and pre-push floors; integrate phase-level closure reuse and labeled source durations.

## 4. Documentation-only validation adoption

- [x] 4.1 Implement docs profile selection and fixed floor with distinct absent-full-lane versus partial/broken-BLOCKED reason codes and fail-closed unit/property tests.
- [x] 4.2 Configure Commando's docs Build/Security(code)/Test profiles without weakening mandatory phases or the typed Build-to-Deploy artifact floor.
- [x] 4.3 Add trusted-policy sandbox e2e proving all three docs profiles and negative code/config/Medium/High/broken-floor cases.

## 5. Evidence-based routing

- [x] 5.1 Implement strict offline routing-evidence parsing, freshness, blind sample sufficiency, metric aggregation, Pareto dominance, and deterministic recommendation tests.
- [x] 5.2 Add read-only `routing evaluate` plus preview-first `routing apply`; derive allowed existing config targets from reviewed policy and test guarded atomic writes, concurrent drift, target-scope escalation, insufficiency, mixed currency, and hostile labels.
- [x] 5.3 Bind applied suite/evidence digest to model config and freshness; document that recommendations are Pareto-eligible, not globally optimal.
- [x] 5.4 Change Codex Documenter from unavailable Luna to user-authorized Terra, then add a versioned representative blind task/rubric manifest and run it through actual sessions for every configured Sol/Terra route; record coverage/evidence digest and apply only a sufficient deterministic recommendation, otherwise preserve visible `MISSING`/`INSUFFICIENT`; fixtures do not satisfy this task.

## 6. Operator recovery

- [x] 6.1 Replace marker-only hook diagnosis with typed manual/activated/drifted inspection using trusted activation/coordinator identity; preserve compatibility boolean.
- [x] 6.2 Add typed archived-current/pending/AwaitingCommit/closed status selection while keeping `next`/`gate` blocked and all status paths read-only.
- [x] 6.3 Add direct doctrine supersession validation and fix the known contradiction; test valid relation, missing/dangling/noncanonical targets, chains, cycles, and doctrine-key conflicts.
- [x] 6.4 Add candidate-cache inspect/preview/prune with live and archived reference retention, descriptor-relative no-follow quarantine/deletion and post-rename identity revalidation, race/interruption/retry/cap tests, and separate archive cleanup reporting.

## 7. Verification and delivery

- [x] 7.1 Update durable docs and verify every named path, flag, profile, state, supersession target, and command.
- [x] 7.2 Run pre-gate fmt, clippy, full workspace/all-target tests with real count, the explicit ignored release 10k-path/100MB test with one pass, release build, and doc checks; reserve authoritative high-risk exact-Commit validation for the immutable post-gate commit as a separate delivery fact.
- [x] 7.3 Prepare the post-gate closure contract and rollback checklist for coherent archive/commit, normal hooked push, remote parity, typed installation of the exact tested Build output, and installed hash/mode verification. Actual archive, commit, transfer, parity, and installation remain separate delivery facts executed only after all gates pass.
