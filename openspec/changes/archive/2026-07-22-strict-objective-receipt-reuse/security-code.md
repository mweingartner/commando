# Security (code) review

## Actor
Security (code) — deep tier, high-risk reuse-of-verification audit: full adversarial review of the strict Build/Test receipt-reuse equality set against real code on disk (attempt 1, independent fable pass), plus a delta review of the L1/L2/CA condition-closure changes (attempt 2).

## Findings
Three findings from the attempt-1 audit, most severe first — all now REMEDIATED (attempt 2); no residual exploitable defect, and no stale-evidence hole in the equality set.

- **CA [Medium] — contract-accuracy + test-coverage gap (FIXED).** The design/README/AGENTS headline "prose-only edit → byte-identical candidate → reuse" was FALSE: the change's prose is bound into the Candidate id via the mandatory `openspec/changes/<change>/**` process scope (closure.rs:1725-1746; candidate.rs:2433, `mutable_process_path` at 905-922 excludes only `.mpd` state/cache), so a prose edit changes the id and reuse correctly refuses at A2 item 2 (fail-closed, cli.rs:3186-3192). Fix: design.md/proposal.md/tasks.md/README.md/AGENTS.md and the cli.rs:9768 test comment corrected to the true firing set (reuse fires only on a byte-identical, off-Candidate rewind). Success-path coverage is via the real shipping functions (`attempt_strict_reuse`, cli.rs:9627, calls the real `evaluate_strict_objective_reuse`; `strict_build_and_test_reuse_succeed_on_a_byte_identical_candidate`, cli.rs:9768, asserts the Reused bindings); the added real-binary e2e (e2e.rs:2260) drives `mpd` to the trust wall and confirms an in-scope prose edit forces a rewind. A full subprocess success e2e is architecturally infeasible (no `lib` target; a real Build PASS needs an activated host-pinned trust floor) — documented; residual gap is the non-security-critical cmd_gate glue only.
- **L1 [Low] — reuse-path save was not compare-and-swap (FIXED).** cli.rs:3475 now uses `ledger::save_exact_observed(&root, &ledger, &observed)` via `resolve_candidate_save_outcome`, the same CAS the execute path uses (cli.rs:3987), against the `observed` snapshot from the post-freshness ledger reload. Strictly safer; no semantic change.
- **L2 [Low] — policy structs lacked `deny_unknown_fields` (FIXED).** Added to `HermeticReusePolicy` (closure.rs:223) and `ClosureConfig` (config.rs:879); top-level `Config` intentionally left permissive. Red tests `hermetic_policy_rejects_an_unknown_field` and `unknown_field_inside_closure_hermetic_reuse_block_fails_parse`; real `.mpd/config.json` still parses. Removes the silent-binding-narrowing advisory and makes the Security(plan) `deny_unknown_fields` note precisely true.

Carried Low advisories (non-blocking, notes): Toolchain `unwrap_or_default` on `rustc --version` (closure.rs:3051-3058); the reuse path bypasses `attempt_authorized` (executes nothing).

## Conditions verified
Each Condition for Builder from the plan, checked against shipped code:

- **C1 [Medium] — security-code scan floor machine-pinned: HOLDS.** `validate_required_lane_coverage` (config.rs:661-733) requires the resolved security-code profile to contain kinds `{SelfCheck, DependencyAudit, SecretScan, Sast}` by content; it runs inside `load_candidate_policy` (local_validation.rs:6897) on every strict execution AND inside the reuse evaluation (cli.rs:3129), so a trimmed scan set fails the typed config closed. Red-test cli.rs:10113-10133 (removing dependency-audit → `validate()` fails).
- **C2 [Medium] — origin receipt↔candidate binding for BOTH phases: HOLDS.** `validate_origin_receipt_candidate_binding` (cli.rs:3020-3047) checks `subject.requested == "candidate:<id>"`, `pushed_kind`, base commit/tree/pushed_oid, empty tag_chain, and build_output `candidate_id`, applied to the ORIGIN record for Build and Test (cli.rs:3125). Per-phase negative tests cli.rs:9997-10044; build_output unit cli.rs:10046-10058.
- **C3 [Medium — CLOSED in plan] — residual ambient inputs named: HOLDS.** README.md:84-99 and design.md carry the "no *unpinned* external mutable state" framing with the exact enumeration (cargo config, DEVELOPER_DIR, tool binaries, OS beyond os-arch) and mitigations.
- **A2 equality set (items 1-6): COMPLETE and fail-closed.** `evaluate_strict_objective_reuse` (cli.rs:3097-3215): (1) origin retained Candidate + validation receipt + Build output, bound; (2) candidate identity re-derived NOW equals origin (Build recapture+rehash, Test retained); (3) profile from current effective risk == origin profile; (4) policy digest equality + origin internal consistency; (5) Build-output disk revalidation incl. device/inode (cli.rs:3056-3075); (6) non-None CheckSummary. Every miss errors before any ledger write.
- **A1 — SecurityCode never reuses: HOLDS** (cli.rs:3304-3309, pinned e2e.rs:554-577; refusals mutation-free e2e.rs:581-614).

## Independent review
Attempt 1 was an independent deep-tier (fable) re-audit that did not trust the plan: it traced every validation-consuming input to a covering term in the candidate id / policy digest / profile / per-key hermetic set / disk-revalidated build output, read the real `evaluate_strict_objective_reuse` and its callees line by line, and confirmed the config opt-in is fail-closed. Attempt 2 (this pass) independently verified the three condition-closure deltas (L1/L2/CA) against the shipped diff and the green suite; all three are strict-hardening or test/doc-only and none touches the reuse decision logic.

## Refutation
1. **Equality set complete — can any sandbox input change without changing id/policy/profile/build-output?** No: source, scope/manifest, policy (all validation policy inside policy_digest), profile, toolchain, persona-tuning, coordinator (HermeticExecutable), platform, env, build artifact, and prose (in the id) all map to a covering term; undeclared dirty files are excluded from candidate and sandbox. L1/L2 add no inputs.
2. **Coordinator/binary swap?** Refused — HermeticExecutable no-follow digest; capture failure omits the key and `(Some, None)` still refuses (cli.rs:9900-9939).
3. **Test reuse of stale scans (SecurityCode not re-run)?** No — A1 + a current SecurityCode PASS bound to the same candidate whose profile carries the full scan floor; candidate-id equality means fresh scans covered byte-identical content (cli.rs:9942-9974).
4. **Ok-but-would-have-failed path?** None found; the Deploy artifact is disk-revalidated (item 5); retained-root tampering caught by rehash/reopen.
5. **deny_unknown_fields gate?** Now complete after L2 — required fields/enum and optional fields both fail-closed on typos.

No stale-evidence hole was found; all attempt-1 conditions (CA/L1/L2) are closed; C1/C2/C3 hold.

## Verdict
PASS. The equality set is complete for every validation-consuming input and every mismatch is fail-closed; the three attempt-1 findings are remediated by strict-hardening/doc/test changes that do not alter the reuse decision logic. No exploitable defect. Code may proceed to Test.
