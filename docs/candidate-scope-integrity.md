# Candidate scope integrity

## Purpose
Two verification-kernel defects surfaced during self-hosting. (1) The change's own
planning prose (`design.md`/`proposal.md`/`tasks.md` and the judgment artifacts) was
bound into the code-validation Candidate, so every prose edit forced a full Build/Test
sandbox re-execution — the largest self-hosting cost driver, and the reason receipt
reuse almost never fired. (2) A *tracked* source file edited outside the manifest was
silently captured at base `HEAD`, so the gates validated code that did not include the
edit and the change shipped it unvalidated (detected only, uninformatively, at
`mpd publish --verify`). This change removes prose from the Candidate — compensating
with a dedicated fail-closed secret-scan lane — and closes the scope-drift hole.

## Value
Uncommitted prose edits (a wording fix, a closed review condition) stop re-running the
sandbox: the Candidate is byte-identical, so `mpd gate <phase> --pass --reuse` fires on
the common rewind. And a change can no longer silently ship an unvalidated source file
— the strict gates refuse tracked out-of-scope drift, a pre-commit guard blocks mixed
landing commits, and `publish --verify` names any offending path instead of a bare
"not coherent".

## Scope
**Covers:** the strict tier's Candidate composition, its secret-scan lanes, the
source-drift guard, the pre-commit landing guard, coherence diagnostics, and the
archive postimage/digest lanes.

**Excluded from the Candidate (by design):** the change's 11 canonical process
artifacts (proposal/design/tasks + design-mock/design-review/security-plan/
security-code/design-signoff/test/documentation/doc-validation). **NOT excluded:**
source, config, `specs/**`, `manifest.json`, `history/**` — all remain Candidate-bound
and sandbox-scanned. Only the *active* change's artifacts are excluded; a sibling
change's prose stays bound.

**Trust boundary:** prose is instead scanned by a fail-closed lane (the built-in
scanner floor plus gitleaks over the change directory, always with an explicit config)
at every strict Build/Security(code)/Test gate — including the reuse paths — on top of
the unchanged staged-commit and pre-push floors. Net secret-scan coverage of prose is
strictly *wider* than before (more gate sites, live worktree bytes, untracked prose
covered). `CANDIDATE_SCHEMA` bumps to v2: a candidate captured by an older binary
refuses to reopen mid-drive and rewinds to Build.

## Functional details
- **Prose exclusion (schema v2):** the 11 artifacts are physically pruned from the
  Candidate projection and excluded from its inventory, `entries_digest`, and id. One
  canonical function (`change_process_artifact_paths`) drives the exclusion,
  `source_digest`, and the scan lane, so the three cannot drift.
- **Prose scan lane:** path-addressed (covers untracked prose); only a missing file
  skips; non-UTF-8, symlinked, or non-regular artifacts refuse; gitleaks always runs
  with an explicit `-c` (an in-tree `.gitleaks.toml`/`.gitleaksignore` is itself a
  refusal); when config declares gitleaks required, an unavailable gitleaks refuses.
- **Source-drift guard:** a tracked file modified/deleted/renamed outside
  `manifest ∪ SystemScope ∪ mutable-process-paths` refuses the strict Build/
  Security(code)/Test gates (naming the paths and the declare-or-stash remedies);
  untracked out-of-scope files produce a note, never a refusal.
- **Pre-commit landing guard:** a commit that stages an `openspec/changes/archive/…`
  landing must have every staged path within the closure's allowed scope, else it is
  blocked (fail-closed on a malformed/unreadable ledger).
- **Coherence diagnostics:** `publish --verify` names the out-of-scope paths when a
  landing commit drifts; the empty-blockers "not coherent" is gone.
- **Archive integrity:** prose re-enters the closure through receipt-bound postimages,
  and each judgment gate records the artifact's SHA-256 on its `GateRecord`, so archive
  verifies the exact bytes that gated (a mismatch is fatal; a legacy record with no
  digest warns).

## Usage
Normal driving is unchanged; the visible differences:
- After an *uncommitted* prose edit that rewound the pipeline, `mpd next` offers the
  reusable Build/Test receipt — `mpd gate <phase> --pass --reuse <receipt>` skips
  re-execution. A *committed* prose edit (base `HEAD` moves) still re-executes.
- If you edited a tracked source file that is part of the change, declare it in
  `openspec/changes/<change>/manifest.json` `paths` (the Build gate names it); stash
  genuinely unrelated edits.
- After an mpd upgrade that bumps the candidate schema, a mid-drive v1 candidate
  refuses to reopen — rewind Build to recapture.
