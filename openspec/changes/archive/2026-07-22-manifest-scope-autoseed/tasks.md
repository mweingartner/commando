## 1. Validation predicate (crates/mpd/src/closure.rs)
- [ ] 1.1 Add pure `missing_process_scope(manifest, change, docs_dir) -> Vec<String>` (probe change-dir manifest + nested spec + docs path; glob over paths ∪ shared_paths; never probe the ledger).
- [ ] 1.2 Unit + property tests: trio → ∅; `**` → ∅; `["crates/**"]` → both entries (exact strings); each entry individually; shared_paths counts; custom docs_dir; single-star `openspec/changes/<c>/*` still reports the change-dir entry; self-healing property (adding returned entries → ∅); never panics on arbitrary safe patterns.

## 2. Build-gate hook + guidance (crates/mpd/src/cli.rs)
- [ ] 2.1 Gate Build arm (~:3311, before execute_strict_candidate_build): call missing_process_scope; non-empty → return gate_blocked with the copy-pasteable entries.
- [ ] 2.2 cmd_manifest (~:5930) guidance string names the two required entries.

## 3. Archive-error hints (crates/mpd/src/closure.rs)
- [ ] 3.1 closure.rs:540 (NotFound only) + :1076: append remediation suffix naming the entry; extend the existing NotFound-hint test to assert the entry name.

## 4. e2e + fixtures (crates/mpd/tests/e2e.rs)
- [ ] 4.1 One e2e: strict change, manifest ["crates/**"], gate to Build, assert refusal names both entries, fix manifest, Build passes. Update the "shippable" fixture + any other narrow-manifest+gate-build fixtures (add-entries-only).

## 5. Verification
- [ ] 5.1 Full cargo test green (real count); every openspec/changes/archive/*/manifest.json passes the new check; clippy/fmt clean.
- [ ] 5.2 Rebuild + reactivate coordinator before commit.
