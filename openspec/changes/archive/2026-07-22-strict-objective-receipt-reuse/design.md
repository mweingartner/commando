# Design: Strict objective-receipt reuse on a byte-identical candidate

## Actor
Architect (claude-code harness, deep tier).

## Context
**Corrected after Security (code) (condition CA): the original "prose-only edit →
byte-identical candidate → reuse" premise was FALSE.** Prose artifacts are excluded
from the Source dependency KEY (closure.rs:2882-2905; test closure.rs:8585-8643), but
that is not what the reuse check compares. The Candidate id is
`candidate_id(base_tree, manifest_digest, entries_digest, policy_digest,
source_digest)` (candidate.rs:2657-2675), and the mandatory process scope
(`missing_process_scope`, closure.rs:1725-1746) forces `openspec/changes/<change>/**`
— the change's own design.md/proposal.md/tasks.md — into the manifest, so those files
are bound into `entries_digest`/`base_tree` (candidate.rs:2433; excluded only for
`.mpd` process-state paths, candidate.rs:905-922). They are in the Candidate ON
PURPOSE, so the secret scanner covers prose. Therefore **a genuine prose edit changes
the Candidate id and reuse correctly REFUSES at A2 item 2 (fail-closed)** — the safe
direction, but not the scenario originally pitched.

What still holds: a prose edit stales Architecture/SecurityPlan/SecurityCode (they
bind ArchitecturePlan); stale_dependency_rewind maps that to Architecture
(closure.rs:2403-2411); invalidate_for_freshness removes every gate record at phase
>= Architecture (ledger.rs:968-973), including the Build/Test records. ledger.history
survives (append-only), `mpd next` offers the newest history receipt (cli.rs:2546-2574,
2639-2652), and `gate --reuse` revalidates via evidence_validity + evaluate_reuse
(closure.rs:2586-2610). Two blocks today: strict categorically refuses reuse for
Build/SecurityCode/Test (cli.rs:3093-3101), and execution-bearing reuse needs a
complete hermetic policy (evaluate_reuse → AlwaysExecutes) which this repo's config
lacks.

**True firing set (what actually reuses):** only a rewind that leaves the Candidate
BYTE-IDENTICAL — i.e. one driven by a causal input OUTSIDE the Candidate: a
persona-directive edit that is not itself manifest-scoped (Test's PersonaTuning key),
a governance/risk re-derivation that does not touch an in-scope file, a `repair-state`
rewind, or an edit that was reverted to byte-identical. ANY edit to a manifest-scoped
file — source, config, OR the change's prose — changes the Candidate id and forces
fresh execution. The value is narrower than the original pitch; it removes redundant
re-execution for the residual off-Candidate rewinds only.

This file is the canonical current-state contract.

## Goals / Non-Goals
Goal: on a rewind that leaves the Candidate byte-identical (see the true firing set
above — an off-Candidate cause such as a persona/governance/risk re-derivation, a
repair-state rewind, or a reverted edit), re-run the fast JUDGMENT gates
(Architecture, SecurityPlan, SecurityCode) but REUSE the still-valid Build/Test
objective receipts. A rewind whose cause is an in-scope file edit (source, config, or
the change's prose) is explicitly NOT reusable — it changes the Candidate and must
re-execute. Non-Goals: no change to freshness/rewind/invalidate logic, receipt
schemas, evidence_validity, or archive; no automatic (non-`--reuse`) reuse; no
risk-classifier change; no change to what the Candidate binds (prose stays in-Candidate
for scan coverage).

## Decisions
**A0 — config opt-in (no code):** add `.mpd/config.json` `closure.hermetic-reuse`
(type HermeticReusePolicy, closure.rs:222-235): `{schema:1, external_state:"none",
environment:[], input_paths:["security/tool-lock.json"]}`. Future Build/Test/
SecurityCode receipts then bind HermeticPlatform/Executable/Environment/Input
(closure.rs:3088-3100) — including the running mpd binary's digest, so a coordinator
swap refuses reuse. Side-effect-free: no phase policy binds the Config key; the risk
signal digest folds only `deploy.is_some()`/`local_validation.is_some()`; the
candidate policy_digest covers only local_validation — so this stales nothing.
external_state:"none" is a project attestation (a Security review item).

**A1 — narrow the strict refusal (cli.rs:3093-3101):** `Build | SecurityCode | Test`
→ `SecurityCode` only. SecurityCode evidence is never carried forward; every rewind
still runs one fresh full deterministic-scan pass (policy-static, cargo-audit,
gitleaks, semgrep) on the candidate.

**A2 — strict reuse block (cli.rs:3183-3250):** when `ledger.strict && matches!(phase,
Build|Test)`, after the existing checks (strict_artifact_issues, origin lookup in
history, evidence_validity + evaluate_reuse — which already enforce Executed-origin,
unconditional PASS, currently-Valid snapshot, hermetic-complete), require ALL of
(each miss → fresh execution, fail-closed):
1. Origin record carries candidate + validation_receipt (+ build_output with
   candidate_id == candidate.subject.id for Build; mirror cli.rs:2991-3008).
2. Candidate identity NOW: Build — load_candidate_policy then capture_candidate
   (idempotent over the retained root) and require fresh.subject.id ==
   origin.candidate.subject.id (id binds base_tree+manifest+entries+policy+source,
   candidate.rs:600-606 — so any drift refuses); record the FRESH capture. Test —
   retained_candidate_for_objective_gate (enforces current Build PASS + SecurityCode
   PASS with the same candidate binding) and require its id == origin's, plus
   reopen_candidate.
3. Profile equality (load-bearing): select_gate_profile(local,phase,&live_manifest,
   change,effective_risk) == origin.validation_receipt.profile (the candidate id
   does NOT bind the selected profile — without this a risk escalation could reuse a
   plain-`test` receipt in place of `high-risk-test`).
4. Policy equality: current candidate policy_digest ==
   origin.candidate.subject.policy_digest (+ receipt consistency).
5. Build output revalidation (Build only): revalidate the recorded BuildOutputV1 vs
   disk (the cli.rs:2760-2765 primitive); missing/drifted → refuse (Deploy depends).
6. Record the reused GateRecord carrying the verified candidate/validation_receipt/
   build_output + a CheckSummary "reused from <receipt>" (not None), so downstream
   (retained_candidate_for_objective_gate, archive equivalence) keep working.

No changes to freshness_projection, stale_dependency_rewind, invalidate_for_freshness,
evidence_validity, schemas, or archive. Judgment gates still re-run fresh (their
receipts are genuinely stale). Only the redundant Build/Test sandbox executions
become reusable, under strictly more conditions than the manual tier requires.

**A-fallback:** if Security(plan) balks at Build's build_output carry-forward, land
Test-only reuse (drop items 2-Build/5; Build re-runs fresh, Test — the heavy
superset profile — reuses). Still captures most of the wall-clock cost.

## Risks / Trade-offs
- [A reuse-condition bug lets a stale receipt pass] → every relaxation is gated by
  the existing property-tested validity machinery PLUS pure-restriction equality
  checks; a stale candidate is refused twice (receipt staleness + id inequality);
  profile/policy drift refused by new checks; `--reuse` stays an explicit audited
  operator action.
- [Deploy artifact drift after Build reuse] → item 5 revalidates on disk.

## Conditions for Builder
1. **Source/config edit still forces objective re-run + rewind** (headline): e2e —
   full traversal → edit an in-scope `.rs` → rewind on Source; `gate build --reuse`
   refuses (receipt NotValid / candidate id differs).
2. **Byte-identical-candidate rewind reuses safely** (corrected from the false
   "prose-only edit" scenario): e2e through the REAL `cmd_gate`/binary path (not the
   `attempt_strict_reuse` replica) — drive a full traversal to Test PASS, trigger a
   rewind that leaves the Candidate byte-identical (an off-Candidate cause: a
   `repair-state` rewind, or an edit to a causal input NOT in the manifest), re-run the
   judgment gates, then `gate build --reuse` and `gate test --reuse` succeed; records
   are Reused{source_receipt} carrying candidate/receipt/(build-output) with matching
   ids; archive completes with candidate equivalence. Plus the negative companion: an
   in-scope prose edit (design.md) DOES change the Candidate and `gate build --reuse`
   refuses (candidate id differs).
3. **SecurityCode --reuse stays categorically refused in strict mode** (pin the
   message at cli.rs:3097-3100).
4. **Profile mismatch refuses** (origin `test`, current High → `high-risk-test`).
5. **Hermetic gaps refuse** (pre-opt-in receipt → AlwaysExecutes; differing
   HermeticExecutable digest → NotValid).
6. **Test reuse ordering**: refuse without a current Build PASS + SecurityCode PASS
   binding the same candidate.
7. **Missing/drifted build output refuses Build reuse.**
8. **No freshness-logic edits**: freshness_projection, stale_dependency_rewind,
   invalidate_for_freshness byte-unchanged (review-scope).
9. Fixture/source hygiene; no secret-shaped literals.

## Verdict
PASS — a fail-closed reuse of genuinely-valid objective evidence, gated by strictly
more conditions than the manual tier; removes redundant execution, not rigor. Ready
for Security (plan) — scrutinize the equality set + the external_state attestation.
