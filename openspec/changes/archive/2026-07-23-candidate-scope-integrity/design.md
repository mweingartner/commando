# Design: Candidate scope integrity

## Actor
Architect (claude-code harness, deep tier).

## Context

The Candidate is the exact immutable subject strict Build/Security(code)/Test validate:
`capture_candidate_with_hook` (candidate.rs:541-867) materializes base HEAD, prunes
mutable `.mpd/` process paths (candidate.rs:565, 2534-2548), overlays manifest-declared
dirty paths (`overlay_plan`, candidate.rs:952-1027; exclusion arm 958-980), inventories
only declared paths (`inventory_directory`, candidate.rs:2433), and derives
`candidate_id(CANDIDATE_SCHEMA, base_tree, manifest_digest, entries_digest,
policy_digest, source_digest)` (candidate.rs:2657-2675, schema const at :17).
`missing_process_scope` (closure.rs:1726-1747) forces `openspec/changes/<change>/**`
into every strict manifest, so the change's own prose is currently bound into
`entries_digest` → id. Consequences, all verified in code:

- A prose edit changes the Candidate id, so `evaluate_strict_objective_reuse`
  (cli.rs:3097-3215, id equality at :3186) refuses reuse — even though Build/Test
  receipts do NOT bind `ArchitecturePlan` (`DependencyPolicy::for_phase`,
  closure.rs:1950-1974), i.e. the dependency-freshness layer already permits reuse.
  Judgment artifacts left by a prior attempt (e.g. `test.md`) also enter the
  recaptured Candidate and forever break id equality on re-drives.
- Prose coverage by the secret scanner currently comes from four lanes: the sandbox
  gitleaks/semgrep checks over the Candidate at Security(code)/Test
  (.mpd/config.json profiles; run inside `run_profile`, local_validation.rs:7159+),
  the staged pre-commit scan (`scan_staged_postimages`, checks/mod.rs:190-219, via
  `mpd hook pre-commit` → `cmd_check(true, …)`, cli.rs:5595-5611), the full
  `mpd check` tracked-file scan (cli.rs:5479-5543 — tracked files only), and the
  pre-push outgoing scan. Removing prose from the Candidate deletes the first lane's
  prose coverage.
- The archive closure plan is built from the Candidate's physical tree
  (`build_candidate_closure_plan` → `inventory_closure_tree(candidate_root)`,
  closure.rs:561) plus receipt-bound postimages for post-Candidate artifacts only
  (closure.rs:566-599; cmd_archive assembly cli.rs:6882-6916), then the
  active→archive rename (closure.rs:644, 1168-1197). Prose must therefore re-enter
  the plan another way or `scoped_commit_equivalence` fails on every landing.
- d482a20 root cause: `overlay_plan` silently retains base-HEAD bytes for undeclared
  dirty tracked files (candidate.rs:960-969), `resolve_closure_landing` silently
  skips out-of-scope commits (closure.rs:3577-3579), and `verify_commit_coherence`
  drops the landing diagnostics when the worktree happens to match the archived
  postimage (`ready==true` arm, closure.rs:3431-3438) — producing the bare
  `closure commit is not coherent:` from cli.rs:6384-6388 / closure.rs:3779-3785.
- Rewinds remove rewound gates from `ledger.gates` (ledger.rs:970), so recapture at
  an unchanged id refreshes the sidecar record via the existing D1 attempt-variant
  path (candidate.rs:682-711) without tripping `candidate_id_has_live_gate_binding`
  (candidate.rs:1672-1698). The strict flow commits once at landing, so prose edits
  are *uncommitted* at reuse time and `base_tree` is stable.
- `source_digest` for the `Source` dependency key already excludes exactly eleven
  change-process artifacts (closure.rs:2883-2895) — the canonical definition this
  design promotes to a single shared function.

This file is the canonical current-state contract.

## Goals / Non-Goals

Goals: (1) prose edits stop changing the Candidate id, making `--reuse` fire on the
common prose-edit rewind; (2) zero net loss — strictly a gain — in secret-scan
coverage of prose, fail-closed at every lane; (3) tracked out-of-scope drift refuses
at the Build gate and mixed landing commits refuse at `git commit`, so a
d482a20-class escape cannot recur silently; (4) `publish --verify` names the
offending files when coherence fails; (5) archived prose remains receipt-bound and
tamper-evident.

Non-Goals: no change to receipt schemas, the reuse equality set
(`evaluate_strict_objective_reuse` items 1-6), dependency-policy tables, the sandbox,
or the manual tier; no exclusion of spec deltas (`specs/**`), `manifest.json`,
`.openspec.yaml`, or `history/**` from the Candidate (see R6); no divergence
acknowledgment verb; no auto-migration of v1 candidates.

## Decisions

**D1 — The exclusion set is exactly the eleven canonical change-process artifacts,
defined once.** Add to closure.rs (beside `source_digest`, :2857):

```rust
/// The eleven canonical process artifacts of `change`, repo-relative.
pub fn change_process_artifact_paths(change: &str) -> [String; 11];
pub fn is_change_process_artifact(change: &str, path: &str) -> bool;
```

`source_digest` (closure.rs:2883-2895) is refactored to consume it (byte-identical
digest behavior — same list, same membership test), and candidate.rs + the new scan
lane consume it too, so the three subsystems cannot drift. Only the ACTIVE change's
files are excluded; a sibling change's prose caught by a broad glob stays
Candidate-bound (inclusion binds more, never less — fail-safe direction).
Rationale for the full set (not just design/proposal/tasks): judgment artifacts are
rewritten on every prose-edit re-drive (design-review, security-plan) and left behind
by prior attempts (test.md, security-code.md …); any of them inside the Candidate
re-breaks id equality and kills the reuse goal. Every one of the eleven already has a
non-Source binding: proposal/design/tasks → `ArchitecturePlan`/`DesignArtifacts`,
design-mock → `DesignMockArtifact`, documentation → `Documentation`, and the six
judgment files → the new D6 digest.

**D2 — Exclusion is physical prune + overlay skip + inventory refusal.** In
candidate.rs:
- `prune_change_process_artifacts(root: &Path, change: &str) -> Result<(), String>`
  (mirror of `prune_mutable_process_paths`, :2534-2548; file-only, symlink in base
  tree → error), called at capture immediately after the existing prune (:565).
- `overlay_plan(manifest, change, statuses)` gains `change` and routes prose to
  `excluded` with status `change-artifact-excluded:{status}` (insertion point
  :958-980, same shape as `process-state-excluded`).
- `inventory_directory` / `inventory_projection` / `inventory_read_only_projection` /
  `verify_retained_projection` thread `change` and **fail closed** if a prose path is
  physically encountered (`candidate projection retains a change process artifact`)
  — proves the prune ran; defense in depth, not a skip.
- `rehash` (:274-332) passes `change` to `overlay_plan` (:286); prose edits after
  capture no longer register as drift — by design.
Alternatives rejected: overlay-skip-only (base-HEAD-committed prose would leak stale
unbound bytes into the sandbox and the closure tree); inventory-skip-only (unbound
bytes in a validated subject).

**D3 — `CANDIDATE_SCHEMA` 1 → 2; no domain-string changes; fail-closed back-compat.**
The schema const participates in the id preimage (:2665-2667) and is checked at
reopen (`capture.subject.version != CANDIDATE_SCHEMA`, :365), so v1/v2 ids are
disjoint and v1 captures refuse to reopen. Extend that error to name the remedy:
`unsupported candidate subject version; rewind Build to recapture under the current
schema`. `CANDIDATE_RECORD_SCHEMA` stays 1 (record shape unchanged). Consequences,
all fail-closed: mid-drive upgrade ⇒ Security(code)/Test/archive refuse until Build
recaptures; `--reuse` against a v1 origin ⇒ id mismatch ⇒ fresh execution; stale v1
retained roots/records are inert (never compared — different id namespace).

**D4 — Prose secret-scan lane (the non-negotiable compensation).** New API:
- checks/mod.rs: `pub fn scan_change_prose(root: &Path, change: &str) ->
  Result<SecretReport, String>` — enumerate `closure::change_process_artifact_paths`,
  keep every path whose `symlink_metadata` succeeds (symlinks INCLUDED so
  `secrets::scan_paths` fails closed on them; only NotFound is skipped — an absent
  artifact is legitimate), then `scan_secrets`. Path-addressed, NOT
  `git ls-files`-based, so untracked prose is covered (the full `mpd check` tracked
  scan misses exactly that case today).
- checks/mod.rs: generalize `run_gitleaks` (:85-110) with a source-dir parameter
  (`-s openspec/changes/<change>` / same ephemeral-config rules) and run it over the
  change dir in the lane when installed; absence is skipped-not-clean, exactly the
  `run_external_scanners` semantic. The built-in scan is the mandatory fail-closed
  floor; gitleaks is best-of-breed parity with the sandbox lane this replaces.
- cli.rs: `enforce_prose_secret_scan(root, change) -> Result<(), String>` applying
  the allowlist (`Allowlist::load(...).filter`, suppression count printed — mirror of
  cli.rs:3702-3718) and turning findings/scan errors into a gate refusal.
Call sites (strict tier only): Build execute arm (after the D5 guard, before
`execute_strict_candidate_build`, cli.rs:~3576); Security(code)/Test execute arm
(before `retained_candidate_for_objective_gate`, :~3582); Build/Test `--reuse` branch
(inside the strict-objective arm, before `evaluate_strict_objective_reuse`, :~3435).
Security(code) reuse is categorically refused already (:3304-3309). Commit-time
coverage is unchanged (`scan_staged_postimages` scans every staged path) and gets a
pinning e2e test. Net coverage vs today: strictly wider (worktree prose at three
gates including reuse paths + untracked prose; previously only Candidate-frozen prose
at two sandbox profiles).

**D5 — Source-drift guard: refuse tracked drift at the strict objective gates; keep
untracked user-owned.** New closure.rs helper:

```rust
pub struct ScopeDrift { pub tracked: Vec<String>, pub untracked: Vec<String> }
pub fn scope_drift(root: &Path, manifest: &ChangeManifest, change: &str)
    -> Result<ScopeDrift, String>;
```

Classification per `git::status_v2` entry (path AND `orig_path`): skip `Ignored`;
`Untracked` → `untracked` bucket; everything else (ordinary modified/deleted,
renamed/copied, unmerged) → `tracked` bucket when
`!manifest.covers(path, &active_system_scope(root, change))` (closure.rs:1590-1598,
:2797-2808) AND `!candidate::mutable_process_path(path)` (make that helper
`pub(crate)`, candidate.rs:905-922 — single source of truth; it already exempts
`.mpd/state/**`, `.mpd/current`, build-output, caches). Enforcement (strict tier
only): non-empty `tracked` ⇒ `gate_blocked` listing ≤12 paths (+count) and both
remedies — `add the path(s) to openspec/changes/<change>/manifest.json "paths"` (if
part of this change) or `git stash push -- <path>` (if user-owned) — at Build
execute (right after the `missing_process_scope` refusal, cli.rs:3568-3575), at
Security(code)/Test execute, and at Build/Test reuse. Non-empty `untracked` ⇒ one
stderr note (first 5 paths + count), never a refusal. This resolves the AGENTS.md
"user-owned" tension explicitly: *untracked* dirt is presumed user-owned (it cannot
enter a commit without an explicit `git add`); *tracked* modifications are exactly
the class that shipped unvalidated in d482a20 (swept into the landing commit while
the Candidate silently pinned base-HEAD bytes) and must be dispositioned before the
gate. AGENTS.md gains the corresponding sentence so doctrine and code agree.
Trade-off flagged for Security(plan): the guard reads ambient status and is
TOCTOU-racy relative to capture — acceptable because it is advisory-refusal UX; the
integrity authorities remain the Candidate binding, D5b, and coherence.

**D5b — Mixed-landing pre-commit guard.** In `cmd_hook PreCommit`
(cli.rs:5595-5611), after `staged_precommit_governance`: enumerate staged paths
(`git::diff_cached_name_status`); if any staged path lies under
`openspec/changes/archive/<dated>/…`, derive each such change name (strip the
`YYYY-MM-DD-` prefix; malformed → block), load `.mpd/state/<change>.json`
(fail-closed on unreadable/missing `archive_closure`), and require EVERY staged path
to satisfy `closure::allowed(&closure.allowed_paths, path)` (expose the private
matcher, closure.rs:3128-3134, as `pub(crate)`). Violation ⇒
`pre-commit blocked: landing commit for <change> stages out-of-scope path(s): …;
commit them separately or declare them in the manifest before Build`. Pure
non-landing commits and pure out-of-scope commits are untouched — the doctrine's
user-owned lane stays open. (`--no-verify` bypass exists but is policy-prohibited;
`publish --verify` remains the authority.)

**D6 — Archived prose is receipt-bound: pre-Candidate postimage lane + judgment
artifact digests.**
- closure.rs: `fn canonical_phase_artifact_names(phase: Phase) -> &'static [&'static str]`
  — Architecture → `["proposal.md","design.md","tasks.md"]`; DesignMock/DesignReview/
  SecurityPlan/SecurityCode/DesignSignoff/Test/Documentation/DocValidation → their one
  file; else `[]`. `build_candidate_closure_plan`'s match (:569-581) becomes a
  membership check against this table (allowing multiple postimages per phase, one
  receipt id shared); `apply_postimage` (:1066-1073) already inserts new paths and
  `claim_overlay` (:1016-1028) already refuses duplicates; postimages are applied
  before the rename (:644) so archived prose lands under the archive path.
- cli.rs `cmd_archive` assembly (:6882-6916): extend the loop to
  `[DesignMock, Architecture, DesignReview, SecurityPlan, SecurityCode,
  DesignSignoff, Test, Documentation, DocValidation]`, per-phase filename lists,
  `is_active` skip unchanged, worktree read + receipt id unchanged; Architecture
  contributes three postimages under its one receipt. A missing file for an active
  phase fails closed (existing `closure_postimage_from_file` behavior).
- ledger.rs `GateRecord` (:479-524): add
  `#[serde(default, skip_serializing_if = "Option::is_none")]
  pub judgment_artifact_sha256: Option<String>` — recorded by `cmd_gate` for every
  strict phase with a `judgment_artifact()` (phase.rs:123-148), on BOTH the execute
  and reuse record sites, as the SHA-256 of the artifact bytes that just passed
  `strict_artifact_issues`. At archive, when a phase's gate record carries the digest
  and the postimage file IS that phase's judgment artifact, bytes must match
  (fail-closed); absent digest (legacy record) ⇒ accept with a printed warning.
  Why needed: freshness already tamper-protects proposal/design (exact bytes in
  `ArchitecturePlan`), tasks (normalized), design-mock (`DesignMockArtifact`) and
  documentation (`Documentation`) — `cmd_archive` runs
  `enforce_freshness_before_effects` (cli.rs:6702) and `current_evidence_blockers`
  (:6795) — but NO dependency key binds the six pure judgment artifacts; today the
  Candidate byte-pins the pre-Build ones (design-review, security-plan) and this
  design would otherwise lose that. The digest restores it AND extends it to the
  post-Build artifacts that were never protected. Not a receipt-schema change; an
  optional ledger field.

**D7 — Coherence diagnostics.**
- `resolve_closure_landing` (closure.rs:3553-3618): replace the silent `continue` at
  :3577-3579 with a bounded diagnostic —
  `commit <12-hex>: parent-diff touches out-of-scope path(s): a, b, c (+N more)` —
  reusing `MAX_LANDING_DIAGNOSTIC_CANDIDATES` / `MAX_LANDING_DIAGNOSTIC_PATHS`, and
  keep scanning (an out-of-scope commit is still "not a landing candidate").
- `verify_commit_coherence` (:3421-3453): in the `ready == true` arm (:3431-3438),
  return `blockers = ["no commit in `<base>..<head>` matches this change's archived
  closure", …diagnostics]` (sorted/deduped) while KEEPING `ready_to_commit: true` —
  the field's meaning ("worktree scoped content matches the archived postimage") is
  unchanged for its consumers (cli.rs:2127, :6339-6371). Invariant after this change:
  `coherent == false ⟹ !blockers.is_empty()` for every arm. `cmd_publish`'s `next`
  hint (:6337-6343) distinguishes "AWAITING COMMIT" with blockers: `review the
  blockers — commits exist but none matches the archived closure`.

**D8 — Reuse firing set becomes true, and is documented.** With D1-D3, a rewind whose
only Candidate-relevant delta is *uncommitted* edits to the eleven process artifacts
leaves `base_tree`, `manifest_digest`, `entries_digest`, `policy_digest`, and
`source_digest` unchanged ⇒ same id ⇒ `--reuse` eligible (Build recapture refreshes
the sidecar record via the attempt-variant path; rewind already cleared the live gate
bindings). Still re-executes, correctly: any committed edit (base HEAD moves), any
in-scope code/spec/`manifest.json`/policy/config edit, `history/**` shuffles, and
Security(code) always. Docs to update, keeping the two protocol.md twins
byte-identical: README.md:84-102, AGENTS.md:47-56 (+ a D5 doctrine sentence near
:132), `.mpd/directives/protocol.md`:21 + `crates/mpd/assets/directives/protocol.md`,
`docs/adoption-quickstart.md`:89-100 (publish --verify now names the files; drift
guard exists).

**D9 — What deliberately does NOT change.** Dependency policies and keys; receipt and
reuse schemas; `missing_process_scope`; the sandbox and its profiles (prose is simply
absent from the projection the sandbox scans); the non-strict tier (legacy lane
cli.rs:3683-3737 still scans all tracked files); `mpd check`/pre-push lanes;
`source_digest` semantics (same exclusions, now shared).

## Risks / Trade-offs

- [R1 Prose lane weaker than sandbox scan for prose] → builtin floor is fail-closed;
  gitleaks-dir added when installed (policy-required on this repo); semgrep loss on
  markdown is negligible (SAST targets code). Explicitly flagged for Security(plan).
- [R2 Tracked-drift refusal fights genuinely unrelated tracked dirt] → refusal names
  stash/declare remedies; untracked stays non-blocking; strict tier only. Doctrine
  updated in AGENTS.md so the rule is written, not folklore.
- [R3 Mid-drive mpd upgrade strands v1 candidates] → reopen error names the remedy;
  one Build re-execution; documented in adoption-quickstart.
- [R4 Exclusion-set drift between digest/candidate/scan-lane] → single canonical
  function + pinning test asserting the exact 11 names and that `source_digest` uses it.
- [R5 Prose tamper between gate and archive] → freshness keys (proposal/design/tasks/
  design-mock/documentation) + D6 digests (six judgment files); legacy records
  warn-only — a ratchet, stated honestly.
- [R6 `history/**` and spec-delta edits still re-execute] → accepted; bounded,
  well-defined exclusion set beats an open-ended "all markdown in the change dir"
  rule; documented in AGENTS.md.
- [R7 Fixture fallout: candidate/closure/e2e tests that put prose in candidates] →
  update fixtures additively; never weaken an assertion; the d482a20-shaped e2e is new
  coverage, not a rewrite.
- [R8 D5b hook parses archive paths from staged names] → malformed/unreadable state
  fails closed (blocks the commit); pure non-landing commits bypass by construction.

## Conditions for Builder

1. **Single source of truth:** `change_process_artifact_paths` is the ONLY definition
   of the exclusion set; `source_digest`, candidate pruning/overlay/inventory, and
   `scan_change_prose` all consume it. A unit test pins the exact 11 filenames.
2. **Fail-closed inventory:** encountering a physically present process artifact
   during candidate inventory/verification is an ERROR, never a skip. The prune
   refuses symlinks (mirror `remove_projection_path` semantics).
3. **Only the active change's artifacts are excluded**; sibling changes' files in
   scope remain Candidate-bound.
4. **CANDIDATE_SCHEMA=2 everywhere the const is read** (capture, id preimage, reopen
   check at candidate.rs:365); reopen's version error must name the Build-rewind
   remedy. Do not touch `CANDIDATE_RECORD_SCHEMA` or digest domain strings.
5. **Prose lane runs on EVERY strict Build/Security(code)/Test gate recording an
   advancing verdict — including `--reuse` paths — before any candidate
   capture/reopen/receipt evaluation.** Scan errors block (never skipped); symlinked
   prose blocks; the allowlist is applied with suppression counts printed; findings
   never print file contents.
6. **The prose lane enumerates by path, not by git tracking** — untracked prose is
   scanned.
7. **Drift guard:** tracked (non-ignored, non-untracked) status entries — both `path`
   and `orig_path` — outside `manifest.covers(·, SystemScope) ∪
   mutable_process_path` refuse the strict Build/Security(code)/Test gates and the
   Build/Test reuse paths; untracked never refuses. `.mpd/state/**` and the other
   mutable process paths must remain exempt (reuse `mutable_process_path`, do not
   re-list).
8. **Pre-commit landing guard fails closed** on unreadable ledger, missing
   `archive_closure`, or malformed archive dir name; it blocks only commits that
   stage an `openspec/changes/archive/**` path.
9. **Coherence invariant:** `verify_commit_coherence` never returns
   `coherent:false && blockers.is_empty()` in any arm except the genuine
   awaiting-first-commit ready state (:3403-3419), which keeps `ready_to_commit:true`
   and empty blockers by design. Add a test sweeping all arms. Diagnostics are
   bounded by the existing MAX_LANDING_* caps and never print file contents.
10. **Closure plan:** pre-Candidate postimages are admitted only through
    `canonical_phase_artifact_names` with a canonical receipt id; `claim_overlay`
    duplicate refusal and the postimages-before-rename order are preserved.
    `verify_candidate_scope_entries` must still pass with prose absent from entries.
11. **D6 digest:** recorded on both gate record sites (execute + reuse) from the same
    bytes `strict_artifact_issues` just validated; archive verifies when present,
    warns when absent (legacy), and never downgrades a mismatch to a warning.
12. **No changes** to dependency policy tables, receipt/reuse schemas, sandbox
    profiles, or the manual tier's lanes.
13. **Docs:** the two protocol.md twins are byte-identical after the edit (add/keep a
    test or verify via `directives::bundled` parity); README/AGENTS.md state the new
    firing set including the "uncommitted prose only — a mid-drive commit moves base
    HEAD and re-executes" caveat.
14. **Tests accompany the build** (see tasks 7.x): the prose-invariance property
    (arbitrary prose bytes ⇒ same id; any declared code byte ⇒ different id), the
    secret-smuggling e2e (design.md secret blocked at Build execute, Build reuse, and
    staged commit), the d482a20 e2e (tracked out-of-scope edit refused at Build;
    committed variant named by publish --verify), and the empty-blockers regression.
15. **Never weaken an existing assertion to make a fixture pass**; extend fixtures
    (declare paths, move prose out) instead.

## Verdict
PASS
