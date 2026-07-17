# Tasks: content-addressed release closure

## 1. Canonical content and Git model

- [x] 1.1 Add SHA-256 canonical stream hashing and safe Git plumbing adapters.
- [x] 1.2 Add typed manifest, receipt, dependency, archive-closure, and parity
  observation schemas with legacy serde defaults.
- [x] 1.3 Add path-scope matching, non-UTF-8/symlink/submodule handling, and
  mixed index/worktree classification.

## 2. Evidence lifecycle

- [x] 2.1 Capture phase-specific dependency snapshots for newly executed gates.
- [x] 2.2 Golden-test `DependencyPolicy::for_phase` so outputs first created by
  later phases cannot stale earlier receipts.
- [x] 2.3 Compute valid/stale/absent independently from reuse eligibility; show
  exact invalidation or ineligibility reasons in status, next, archive, and JSON.
- [x] 2.4 Add explicit `gate --reuse <receipt-id>` with append-only provenance
  and forbid reuse for external-state Deploy evidence.
- [x] 2.5 Default execution phases to labeled always-execute; implement versioned
  hermetic opt-in and unconditional-PASS-only reuse, with fresh-gate guidance
  for CONDITIONAL receipts.

## 3. Manifest and archive lifecycle

- [x] 3.1 Seed and validate `manifest.json`; block out-of-scope staged paths in
  status, check/pre-commit, and archive without mutating the index.
- [x] 3.2 Extend archive planning to preview generated scope and write the
  post-archive closure record only after successful archive mutation.
- [x] 3.2a Implement the normative transaction journal: staged postimages,
  pre/post/mode/tree digests, state transitions, replacement/sync abstraction,
  and completion-only digest recovery without semantic re-merge.
- [x] 3.3 Verify a clean descendant commit whose base-to-HEAD changed paths and
  final scoped digest exactly match the archived closure.
- [x] 3.4 Use a per-commit path union including intermediate add/delete and
  rename/copy pairs; endpoint diff is insufficient.
- [x] 3.5 Preserve one pending-closure pointer after archive so zero-argument
  status/publish and the archive commit hook resolve and enforce its scope.
- [x] 3.6 Add crash-safe pointer stages, `closure recover`, and confirmed
  pointer-only abandon; block begin/second archive while closure is pending.
- [x] 3.6a Implement shared human/JSON `TransactionView`; recover/abandon preview
  by default, `recover --yes` eligible roll-forward only, and `abandon --yes`
  AwaitingCommit metadata-only.
- [ ] 3.7 Inject crashes after every journal/stage/target/rename/ledger boundary;
  prove convergence or zero-write third-state refusal across platform paths.
- [x] 3.8 Test preview non-mutation, third-state `--yes` refusal, no rollback/
  atomicity claims, and stage/write-eligibility/durability/path-count parity.

## 4. Remote parity

- [x] 4.1 Add publication target config/manifest resolution and `mpd publish`
  readiness output.
- [x] 4.2 Add bounded `publish --verify` using safe Git arguments, exact OID
  comparison, ancestry classification, and an untracked observation cache.
- [x] 4.3 Resolve configured remote names only, snapshot/recheck local+remote
  state, and never fetch absent ancestry objects.
- [x] 4.4 Cover exact, offline, ahead, behind, diverged, rewritten, unstable,
  ancestry-unavailable, missing, detached, unborn, and remote/ref injection.

## 5. Integration and delivery

- [x] 5.1 Update status/next/archive/doctor/hooks, directives, README, templates,
  and durable documentation with human/JSON parity.
- [x] 5.2 Run format, warnings-denied Clippy, full workspace tests, release build,
  and isolated local-bare-remote E2E tests with actual counts.
- [x] 5.3 Dogfood gates, archive, commit the archived result, push normally,
  freshly verify parity, install the release binary, and smoke-test it.
