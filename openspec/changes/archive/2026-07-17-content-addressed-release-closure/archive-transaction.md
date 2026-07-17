# Archive transaction protocol

This appendix is normative and is incorporated by `design.md`. It replaces
pointer-only archive recovery with digest-driven completion of a precomputed
transaction. Recovery never reruns OpenSpec parsing or semantic merge.

## Types and ownership

`openspec-core::Project::plan_archive` remains the pure semantic operation that
computes merged spec postimages and the directory move. Add
`openspec_core::transaction`:

```rust
struct ArchiveTransactionPlan {
    version: u32,
    id: Digest,
    change: String,
    base_commit: OidText,
    targets: Vec<TransactionTarget>,
    directory_move: DirectoryMove,
    final_scoped_digest: Digest,
}
struct TransactionTarget {
    target: RelativePath,
    preimage: ImageState,
    postimage: FileImage,
    staged: RelativePath,
}
enum ImageState { Absent, File(FileImage) }
struct FileImage { digest: Digest, mode: u32, length: u64 }
struct DirectoryMove { source: RelativePath, destination: RelativePath,
    tree_digest: Digest }
enum TransactionState { Preparing, Prepared, Applying, Renaming,
    RecordingClosure, AwaitingCommit }
```

The MPD CLI composes spec outputs from `ArchivePlan`, the durable documentation
copy, and the final ledger/closure postimage into one transaction plan. The
final digest is computed from planned postimages, so the staged ledger can carry
it without a self-reference (ledger bytes remain excluded from that digest).
Direct `Project::commit_archive` is replaced by the transaction executor; no
production caller may retain the old sequential-write path.

## Journal and staged data

The ignored pointer stores transaction ID and state, not merely a change name.
The journal lives at `.mpd/tmp/archive/<id>/journal.json`. Every target postimage
is staged on the same filesystem and preferably as a hidden sibling of its
target; the journal stores only contained project-relative paths and digests.
All counts, paths, files, and total staged bytes are capped.

Preparation, before the first target mutation:

1. Open every existing target without following symlinks; capture kind, mode,
   length, and digest. Record explicit `Absent` for a new target.
2. Write every postimage to an exclusive new staged file, `sync_all` the file,
   re-open non-following, and verify its postimage tuple.
3. Write the complete journal to an exclusive temporary file, `sync_all`, rename
   it over the journal, and sync its parent directory where supported.
4. Atomically replace and sync `.mpd/pending-closure` in `Prepared` state.

If preparation fails, no project target has changed. Cleanup may remove only
paths created under this transaction ID after containment and digest checks.

## Apply and recovery state machine

For each target in canonical path order, inspect current target and staged file:

- exact preimage (including `Absent`) plus exact staged postimage: replace with
  the staged postimage;
- exact postimage: the step already completed; continue;
- any third state, missing/corrupt staged content before completion, changed
  type/mode, or symlink: stop `manual-recovery-required` without writing.

Replacement uses a sibling temporary on the same filesystem. On Unix, rename
over the target, then sync the file and parent directory. On platforms where
standard-library replacement of an existing file is not atomic, retain the
durable staged file, use the narrowest replace sequence available, and sync; an
intermediate absent target is recoverable only when the exact staged postimage
still exists. MPD reports the platform durability level and never claims
power-loss atomicity the filesystem/API cannot provide.

After all file targets are exact postimages, set/sync `Renaming`. For the
directory move: exact source tree + absent destination means rename and parent
sync; absent source + exact destination tree means already complete; every
other combination refuses. Then verify all postimages again, set
`RecordingClosure`, replace/sync the final ledger closure postimage if not
already exact, and set pointer+journal `AwaitingCommit`.

`mpd closure recover` loads the pointer and journal with capped, symlink-refusing
reads, rederives every allowed path from change/config/archive date, compares
plan ID and digests, and runs only this state machine. It never calls
`plan_archive`, merge, render, or documentation synthesis. Because preimage
bytes are not retained, automated rollback is not offered. An unexpected third
state prints affected paths/digests safely and requires explicit manual repair;
after repair, recover may resume by digest.

Journal/pointer removal is allowed only after all postimages and the directory
move are verified and remote parity completes, or by confirmed abandonment in
`AwaitingCommit`. Abandonment before that state refuses. It deletes only ignored
transaction metadata, never repository targets.

## CLI mutation contract

`mpd closure recover` is read-only. It validates the journal and current digests,
then emits a `TransactionView` in human or JSON form: durable stage, durability
level, total affected-path count, bounded path details/classification, whether
roll-forward would write, write eligibility, blockers, and one next action.
`recover --yes` is the only recovery mutation and is accepted only when every
pending step is exact-preimage plus exact staged postimage. It performs
completion-only roll-forward. A third state, corrupt journal/staging, or weak
precondition sets `write_eligible=false`; `--yes` refuses before any write.

`mpd closure abandon` is also read-only. `abandon --yes` is accepted only in
`AwaitingCommit` and removes the ignored pointer/journal/staging owned by the
transaction after containment checks. It never changes repository targets,
ledger history, index, commits, or remote state. Both renderers use identical
stage, write-eligibility, durability, affected-path-count, and next-action data.
Neither command uses “rollback” or “atomic” as an outcome; output explicitly
states that preimages were not retained and actual durability is platform/filesystem dependent.

## Crash and fault verification

Tests inject process termination after: each staged-file sync; journal sync;
pointer sync; state transition; every individual target replacement; directory
rename before/after parent sync; closure-ledger replacement; and final state
sync. Restarted recovery must converge to all postimages or refuse a planted
third state. It must never double-apply a delta. Repeat with absent new targets,
existing targets, multiple spec outputs, documentation, ledger, symlink swaps,
corrupt/truncated journal/staging, size limits, and forced sync/rename failures.
Every refusal proves no additional target/index/worktree mutation.
Command tests additionally prove preview is byte-for-byte non-mutating,
`recover --yes` converges only eligible states, third-state `--yes` refuses, and
`abandon --yes` is metadata-only and AwaitingCommit-only, with human/JSON parity.
