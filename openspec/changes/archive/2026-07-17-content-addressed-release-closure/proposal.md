# Proposal: content-addressed release closure

## Why

MPD records gate results but cannot prove that a result still covers current
content, that a commit contains exactly one declared change, or that a remote
ref equals the archived change commit. This leaves local tests, archive, commit,
push, deployment, and publication easy to conflate.

## What Changes

- Add a versioned change manifest with declared path scope and deterministic
  content digests.
- Bind gate receipts to phase-specific content, governance, configuration,
  toolchain, scanner, and artifact dependencies; report content validity
  separately from reuse eligibility. Only exact-input unconditional PASS may be
  reused; execution phases require an explicit labeled hermetic policy or run
  fresh under the default always-execute policy.
- Block mixed staged content without changing the Git index.
- Change closeout to: gates -> archive -> commit the archived result -> verify
  the exact configured remote ref.
- Make archive a journaled, digest-driven transaction with durable staged
  postimages so interruption can roll forward without rerunning semantic merge.
- Make recovery and abandonment preview-only by default; only explicit `--yes`
  may roll forward or remove eligible transaction metadata.
- Add a read-only `mpd publish` readiness report and `publish --verify` remote
  observation. MPD never pushes, force-pushes, creates refs, or deploys here.
- Preserve a local, untracked last-observation cache for status while requiring
  fresh verification for final closure.
- Verify every intermediate commit path, resolve only configured remote names,
  recheck immutable local/remote snapshots, and degrade to explicit unstable or
  ancestry-unavailable states without hidden fetches.

## Capabilities

### New Capabilities

- `evidence-reuse`
- `change-manifest`
- `remote-parity`

### Modified Capabilities

- None.

## Impact

Adds Git inspection, canonical SHA-256 hashing, receipt/manifest schemas,
archive closure state, publish commands, config, tests, directives, README, and
durable documentation. Existing ledgers/configs remain readable; legacy gate
records have absent reusable evidence. One pure-Rust SHA-256 dependency is added;
there is no service or Node runtime dependency.
