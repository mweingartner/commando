# Doc validation

## Actor
Architect (claude-code harness, deep tier) — validating `documentation.md` /
`docs/candidate-scope-integrity.md` for accuracy against what shipped.

## Architect lens
Validated the durable doc against the amended design, the Security(code) attempt-2
PASS, and the real code:
- **Prose-exclusion set accurate.** The doc names the 11 canonical process artifacts as
  excluded and correctly lists source/config/`specs/**`/`manifest.json`/`history/**`
  as still Candidate-bound — matching `change_process_artifact_paths` (closure.rs:2901)
  and D1/D9. "Only the active change's artifacts are excluded" matches the code.
- **Scan-lane claims real.** The fail-closed lane (built-in floor + gitleaks with
  explicit `-c`, in-tree config refused, required-unavailable refuses, untracked
  covered, non-UTF-8/symlink refuse) matches `scan_change_prose`/`run_gitleaks`/
  `enforce_prose_secret_scan` and Security(code) C1–C4. "Strictly wider coverage" is
  the Security(plan) finding, restated accurately.
- **Drift/landing/coherence/archive claims real.** Tracked-refuse/untracked-note
  (D5), the pre-commit landing guard (D5b), `publish --verify` naming paths (D7), and
  the receipt-bound postimages + `judgment_artifact_sha256` (D6) all match the shipped
  code and the closed conditions.
- **Reuse-synergy caveat correct.** "Uncommitted prose edit reuses; committed edit
  re-executes" matches D8 and the id preimage (`base_tree` moves on commit).
- **Schema-v2 caveat correct.** The v1-candidate rewind-to-Build remedy matches D3.
- No overclaim: the doc does not promise reuse for committed edits or for in-scope
  code changes, and states the trust boundary honestly.

## Designer lens
N/A — backend/tooling change with no user-visible UI/UX surface (CLI text only,
covered by the Architect lens). No design intent to validate.

## Verdict
PASS. The documentation is accurate against the shipped code, config, and the
corrected contract; every named flag, path, artifact, and behavior was verified to
exist.
