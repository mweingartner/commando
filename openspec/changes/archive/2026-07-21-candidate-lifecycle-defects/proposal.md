# Candidate Lifecycle Defects

## Why

While the pipeline self-hosted its first four changes (landed through HEAD `8c7b7c5`),
three closure/candidate-lifecycle defects were reproduced live, each of which hard-stalls
a legitimate pipeline run: (1) a fresh candidate capture collides with a stale cached
projection record from a superseded attempt and errors instead of recovering; (2) after a
freshness rewind of an identical tree, Build cannot re-export its output because a
superseded ledger event still "binds" it; (3) `mpd publish --verify` verifies one
change's closure against the whole `base..HEAD` range and the current worktree, so any
legitimate later commit — including a forced post-archive fixture redaction — is reported
as corruption, and earlier commits are judged against the wrong change's scope.

## What Changes

- **Stale candidate-record recovery (capture never hard-stalls on cache).** The
  candidate ID is pure content identity (`base_tree`/manifest/entries/policy/source
  digests), but the cached projection record additionally freezes attempt-variant
  process state (`base_commit`, overlay/status digests, excluded-dirty inventory,
  counts, root device/inode). `capture_candidate` currently requires whole-record
  equality, so a superseded attempt's leftover record with identical content but
  different process state stalls the gate. Capture will now split identity fields from
  attempt-variant fields: identity disagreement stays fail-closed; an attempt-variant-
  only mismatch (and an orphaned record without its retained root) is evicted and
  atomically republished — but only when the record belongs to the same change and no
  authoritative ledger gate currently binds that candidate ID.
- **Authoritative-only Build-output binding (rewind does not poison re-export).**
  `candidate_output_ledger_bound` scans the append-only `history` plus the `gates` map,
  and errors on any record that references the candidate without a typed Build output —
  which every Security (code)/Test record legitimately does. After a freshness rewind
  (which clears `gates` for rewound phases but preserves `history` by design), re-running
  Build against the identical tree can therefore never re-export. The binding check will
  consider only authoritative records (the current `gates` map), and only records that
  actually carry a typed `BuildOutputV1` for this candidate ID. Live double-bind
  protection and the same-path consistency check are retained.
- **Per-change landing-commit verification for `publish --verify`.** Closure
  verification stops asserting "nothing else happened since archive" and instead
  asserts "this change's archived closure landed, and the remote contains that landing
  commit": locate the change's own landing commit in `base..HEAD` (single-parent commit
  whose diff stays inside the closure scope and whose in-scope tree is equivalent to the
  archived closure plan), check scope purity only on that commit, verify parity by
  remote containment of the landing commit, and keep the worktree-postimage checks only
  for the pre-commit readiness report. Later legitimate commits that edit the same files
  are no longer corruption; each landed change verifies against its own commit.
  History rewrites that destroy the landing commit (e.g. a `git filter-branch`
  redaction) still fail closed, but with an accurate per-change diagnosis; an explicit
  operator acknowledgment verb for authorized rewrites is out of scope (deferred).

## Capabilities

### New Capabilities

None.

### Modified Capabilities

- `local-validation` — candidate capture gains stale-record recovery semantics; a new
  requirement pins authoritative-only Build-output binding.
- `change-manifest` — "Archived closure commit" moves from whole-range base-to-HEAD
  coherence to per-change landing-commit coherence.
- `remote-parity` — parity for a change verifies remote containment of that change's
  landing commit; observational/no-push guarantees unchanged.

## Impact

- `crates/mpd/src/candidate.rs` — capture-time record comparison and orphan handling;
  atomic record refresh.
- `crates/mpd/src/local_validation.rs` — `candidate_output_ledger_bound` scope and
  predicate.
- `crates/mpd/src/closure.rs` — landing-commit resolution replaces whole-range
  `verify_commit_coherence` semantics; parity binding updated.
- `crates/mpd/src/cli.rs` — `cmd_publish` and the two status coherence call sites.
- `.mpd/state/candidate-lifecycle-defects.json`, change artifacts, spec deltas, and
  `docs/candidate-lifecycle-defects.md`.
- No UI surface; no new dependencies; ledger and parity-cache schema changes are
  additive only.
