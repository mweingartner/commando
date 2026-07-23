Canonical current checklist for candidate-scope-integrity.

## 1. Canonical exclusion set (crates/mpd/src/closure.rs)
- [ ] 1.1 Add `change_process_artifact_paths(change) -> [String; 11]` + `is_change_process_artifact(change, path)`; refactor `source_digest` (closure.rs:2883-2895) to consume them (digest behavior byte-identical); unit test pins the exact 11 names and the source_digest linkage.

## 2. Candidate exclusion + schema (crates/mpd/src/candidate.rs)
- [ ] 2.1 `prune_change_process_artifacts(root, change)` (file-only, symlink → error), called after `prune_mutable_process_paths` at capture (:565); make `mutable_process_path` `pub(crate)`.
- [ ] 2.2 Thread `change` through `overlay_plan` (exclude prose to `excluded` with `change-artifact-excluded:` status), `inventory_directory`/`inventory_projection`/`inventory_read_only_projection`/`verify_retained_projection` (encountering prose = error), and `rehash`.
- [ ] 2.3 Bump `CANDIDATE_SCHEMA` to 2; extend reopen's version error (:365-367) with the Build-rewind remedy.
- [ ] 2.4 Unit tests: dirty prose → excluded_dirty (status label), absent from entries; committed prose pruned from projection; prose-invariance property (arbitrary prose bytes, uncommitted → identical id; single declared code-byte flip → different id); rehash green across prose edits, drift on code edits; inventory refuses a planted prose file; v1 reopen refusal message.

## 3. Prose secret-scan lane (crates/mpd/src/checks/mod.rs + cli.rs)
- [ ] 3.1 `checks::scan_change_prose(root, change)` (lstat-enumerated: NotFound skipped, symlinks retained so scan fails closed); generalize `run_gitleaks` with a source-dir arg; lane helper in cli.rs applying allowlist + refusal formatting.
- [ ] 3.2 Wire into strict Build execute (after 4.2's guard), Security(code)/Test execute, and Build/Test `--reuse` (before `evaluate_strict_objective_reuse`); scan error or finding ⇒ gate_blocked.
- [ ] 3.3 Tests: secret in design.md blocks Build execute AND Build reuse; untracked prose secret blocks; symlinked prose blocks; allowlisted finding suppressed with count printed; staged-commit regression test pinning `scan_staged_postimages` coverage of prose.

## 4. Source-drift guard (closure.rs + cli.rs)
- [ ] 4.1 `closure::scope_drift(root, manifest, change) -> ScopeDrift` (tracked vs untracked; covers() ∪ SystemScope ∪ mutable_process_path exemptions; rename orig_path included; unmerged = tracked).
- [ ] 4.2 Enforce at strict Build/Security(code)/Test execute + Build/Test reuse: tracked drift ⇒ gate_blocked naming ≤12 paths + declare/stash remedies; untracked ⇒ stderr note only. Unit + e2e: tracked out-of-scope edit refused at Build (d482a20 shape); `.mpd/state/<change>.json` never trips it; untracked never refuses.
- [ ] 4.3 Pre-commit mixed-landing guard in `cmd_hook PreCommit`: staged `openspec/changes/archive/**` ⇒ every staged path must match the closure's allowed_paths (expose `closure::allowed` pub(crate)); fail closed on unreadable ledger/malformed name; e2e: mixed landing blocked, pure landing passes, pure user commit passes.

## 5. Coherence diagnostics (closure.rs + cli.rs)
- [ ] 5.1 `resolve_closure_landing`: bounded out-of-scope diagnostic instead of silent continue (:3577-3579).
- [ ] 5.2 `verify_commit_coherence` ready-arm (:3431-3438): surface "no commit matches" + diagnostics; keep ready_to_commit semantics; arm-sweep test pinning `coherent:false ⟹ blockers non-empty` (except genuine awaiting-first-commit); `cmd_publish` next-hint wording.
- [ ] 5.3 Regression e2e: landing commit with out-of-scope files ⇒ `publish --verify` error names the paths.

## 6. Archive postimage lane + judgment digests (closure.rs + cli.rs + ledger.rs)
- [ ] 6.1 `canonical_phase_artifact_names(phase)`; rework `build_candidate_closure_plan`'s artifact match (:569-581) to the membership model (multi-file Architecture, shared receipt id).
- [ ] 6.2 Extend `cmd_archive` assembly (:6882-6916) to the nine-phase list with per-phase filenames; is_active skips; missing active-phase file fails closed.
- [ ] 6.3 `GateRecord.judgment_artifact_sha256: Option<String>` (serde default); record at strict execute + reuse gate sites from the validated artifact bytes; archive verifies when present / warns when absent; tests: tampered security-plan.md post-gate refuses archive; legacy record (absent digest) warns and proceeds; plan places prose at archive paths post-rename.

## 7. End-to-end + fixture updates (crates/mpd/tests/e2e.rs and unit fixtures)
- [ ] 7.1 Reuse synergy e2e: strict drive to Test PASS → uncommitted design.md edit → rewind → Build `--reuse` fires (same id), Security(code) re-executes, Test `--reuse` fires; committed prose edit variant re-executes (base moved).
- [ ] 7.2 Update candidate/closure/e2e fixtures for the exclusion (declare paths / adjust expected counts) additively; never weaken assertions.
- [ ] 7.3 Full `cargo test --workspace` green with real counts; clippy/fmt clean.

## 8. Docs (README.md, AGENTS.md, protocol twins, adoption-quickstart)
- [ ] 8.1 README:84-102 — new firing set (uncommitted process-artifact edits + prior off-candidate causes; committed edits re-execute; prose scanned by the dedicated lane).
- [ ] 8.2 AGENTS.md:47-56 — reuse now rescues prose-edit rewinds; keep "freeze prose" as judgment-phase economy; add drift-guard doctrine sentence near :132.
- [ ] 8.3 `.mpd/directives/protocol.md`:21 + `crates/mpd/assets/directives/protocol.md` — update and keep byte-identical (verify parity).
- [ ] 8.4 `docs/adoption-quickstart.md`:89-100 — publish --verify now names files; note drift guard + v1-candidate upgrade caveat.
- [ ] 8.5 Rebuild + reactivate coordinator before commit.
