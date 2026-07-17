# Security (code): self-enforcing-pipeline

Governance: risk **medium**, threat profile **local-trusted-user**. Adversarial
audit of the on-disk implementation across 6 surfaces (5-surface workflow +
1 re-run) mapped to the 17 Conditions for Builder.

## Findings

**The security-critical core came back CLEAN** (0 findings each):
- **Strict gate branch + evidence validation + waiver + reuse seam** (cmd_gate) —
  Conditions 2/5/13/15/17 all honored: validate_evidence strips at first `#`,
  rejects absolute before join, `assert_contained`, `symlink_metadata` existence,
  metadata-only (no content read), post-join exact own-artifact equality;
  `--waive-artifact` is bounded/terminal-safe/attempt-scoped, runs after the
  objective gates, requires `--pass`, is rejected on a non-judgment phase and
  mutually exclusive with `--reuse`; the `--reuse` early-return also enforces the
  artifact check; every strict refusal prints the escape.
- **Ledger: strict monotonic + Waiver scoping + archive re-check** — Conditions
  4/5/9/14 honored: `strict` write-once, `invalidate_from_security` drops
  rewound-phase waivers, archive re-check honors valid waivers, serde defaults.
- **Model bump + autonomous reconcile** — Conditions 10/12 honored: bump elevates
  only the seeded-default case, autonomous refuses all threat-profile changes +
  risk downgrades + Security-phase waivers.

**One class of finding — CONFIRMED, now FIXED.** `read_capped` lstat's only the
FINAL path component, so several new change-dir/`.mpd` reads would follow an
intermediate directory symlink (a symlinked change dir or `.mpd/`), violating
Condition 1's explicit `assert_contained` requirement:
- **SEC-CTX-1 (MEDIUM)** — `render_context_slice`, `strict_artifact_issues`
  (enforcement-critical: a symlinked change dir could point the gate at a planted
  out-of-tree artifact and PASS), and `artifact_stub_issues` read change-dir files
  without containment.
- **F1 (LOW)** — `fix_gitignore` + `uncovered_transient_paths` read `.mpd/.gitignore`
  without containment (bounded: content never surfaced, write independently
  blocked; residual = fail-open reporting).
- **F2 (LOW)** — `fix_gitignore`'s pre-write `assert_contained` sat before
  `create_dir_all`, not immediately before the write (Config::save double-check
  pattern).

**Fix (uniform):** a `read_contained(root, path)` helper (`assert_contained`
before `read_capped`, else `""`) applied at every flagged change-dir/`.mpd` read
(`cmd_gate` doc-check, `render_context_slice`, `strict_artifact_issues`,
`artifact_stub_issues`, `uncovered_transient_paths`, `artifact_budget`); a
refused path reads as `""` and fails the caller's structural check / reports
fail-closed — never followed, never surfaced. `fix_gitignore` gains F1 (contain
before read, fail-closed Err) + F2 (second `assert_contained` immediately before
`fs::write`). The stale "symlink-refusing" doc comment on `strict_artifact_issues`
was corrected.

## Conditions verified

Conditions 2, 4, 5, 9, 10, 12, 13, 14, 15, 17 verified honored in code (file:line
evidence in the audit transcripts). Condition 1 (containment on all new reads)
and Condition 7 (doctor-fix double-check) were the gap → closed by the fix above,
independently re-verified. Conditions 3 (check_sections equivalence), 6 (mpd use),
8 (shared transient constant / pre-flight-fix lockstep), 11 (terminal_safe),
16 (dogfood) confirmed by the Build stages + their tests; 16 is exercised at
Deploy (this change promoted to strict, retaining its own artifacts).

## Verdict

**CONDITIONAL PASS → PASS.** The core enforcement, ledger, and model/autonomous
surfaces are clean; the single containment class (1 MEDIUM + 2 LOW, all
Condition-1/7 letter-violations on gate-critical reads) is fixed uniformly with
`assert_contained`, re-verified, and 397/0 + clippy `--all-targets` + fmt remain
green. No CRITICAL/HIGH. The two advisory reads (`archived_manifest`, doc-fold)
were routed through the same guard. The load-bearing regression LANDED and is
PROVEN non-vacuous: `strict_symlinked_change_dir_is_refused_and_never_surfaced`
(e2e) fails when `read_contained` is neutered — `next --context` then surfaces
`SECRET-OUT-OF-TREE` — and `project::containment_tests::
refuses_an_intermediate_directory_symlink` (unit) pins the mechanism. **PASS.**
