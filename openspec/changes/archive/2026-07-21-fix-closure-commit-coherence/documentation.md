# Fix Closure Commit Coherence

## Purpose

A properly-archived closure commit could not complete without resurrecting a stray
active-manifest copy. The pre-commit hook's ELSE branch (`ordinary_else_governance`,
`cli.rs:4819`, invoked from `staged_precommit_governance`, `cli.rs:4905`) demanded
`openspec/changes/<change>/manifest.json` from the Git index whenever no closure was
pending — but a properly-archived change has deleted exactly that file. Committing
after `mpd archive --abandon` (or otherwise without the pending closure still open)
fell straight into that branch and hard-errored "active manifest is absent or
unreadable in the index," with no recovery command: `recover_apply` refuses without a
pointer, and nothing recreates an abandoned transaction. The only escape was
resurrecting a stray `openspec/changes/<change>/manifest.json` copy and committing it.
Two such strays were already in HEAD (`candidate-lifecycle-defects`,
`proportionate-governance`); the stray copies polluted the tree and were each an
"extra path" against their closure plan, so `resolve_closure_landing` never found a
landing commit and `mpd publish --verify` stayed red for those changes. Security
(code) review found a third, `closure-defects-and-measurement`, in the identical
state (finding F1) and it was folded into this change's scope before landing. Worse,
the strays were not just clutter: a committed copy of an archived change's active
manifest re-opens that change's frozen `archive_closure` record as commit-authorization
material — exploitable footprint-replay trigger material, not inert debris.

## Value

Closure commits no longer need a resurrected manifest. An archived-closure fallback
arm in the pre-commit gate authorizes the commit from the clone-private
`ArchiveClosure` record's `system_paths` united with the retained closure plan — the
same authority pair `verify_commit_coherence` (`closure.rs:3243`) already trusts after
abandonment — so `mpd publish --verify` can clear for cleanly-committed changes. The
three committed strays are removed, closing both the `publish --verify` red and the
footprint-replay window at once: with no archived change's active manifest left in
HEAD, the fallback's trigger signature is unstageable for anything but a change's own
genuine post-archive commit.

## Scope

The manifest's declared paths cover `crates/mpd/src/cli.rs` (the fallback arm and its
call sites), `crates/mpd/tests/e2e.rs` (bypass-attack and regression coverage), and
the three stray manifest deletions: `openspec/changes/candidate-lifecycle-defects/manifest.json`,
`openspec/changes/closure-defects-and-measurement/manifest.json`, and
`openspec/changes/proportionate-governance/manifest.json`. Out of scope: the
AwaitingCommit branch, the archive transaction, `abandon_apply` semantics, and
`verify_commit_coherence` itself — none are touched. No refusal of
`mpd archive --abandon` before the closure commit is added; this is messaging and
authorization only, no new flags or commands.

## Functional details

The archived-closure fallback fires only on an exhaustive, fail-closed trigger,
checked in `staged_precommit_governance` (`cli.rs:4905`) before the ordinary manifest
read is ever attempted:

1. No pending closure exists (the ELSE precondition, unchanged).
2. `resolve_change` resolves a coordinated change `C` (post-abandon this requires an
   explicit `mpd use C`).
3. `ledger::load(root, C)` succeeds and carries `archive_closure = Some(record)`.
4. The staged diff itself removes `C`'s own active manifest — `stages_removal_of`
   (`cli.rs:4677`) matches a `D` entry at `manifest_path` or an `R` entry whose
   `orig_path` is `manifest_path`, byte-exact, never a copy (`C`) and never a
   prefix/suffix near-miss. This is the unforgeable half of the signature: a
   post-landing change's active manifest is absent from HEAD, so `git diff --cached`
   cannot stage a `D` for it at all; an in-progress change has no `archive_closure`
   record (condition 3 fails) and its own manifest deletion is independently blocked
   as a protected artifact by the ordinary path.
5. `record.system_paths` is non-empty (a pre-`system_paths` legacy record degrades to
   empty and must fail closed here).
6. Plan discipline mirrors `verify_commit_coherence` (`closure.rs:3284-3288`)
   field-for-field: a candidate-bound record requires `load_candidate_closure_plan`
   to succeed and its `candidate_id`, `candidate_base_commit`, `archive_path`, and
   `archive_transaction_id` to bind exactly to the record; a legacy record with
   `candidate_id: None` keeps `system_paths`-only scope.

When every conjunct holds, `archived_closure_fallback_scope` (`cli.rs:4761`)
authorizes scope as `union_closure_scope(record.system_paths, plan)` — record and
plan are the **sole** authorizing input; nothing else may widen it, and any
additional check may only narrow or block. The staged-path coverage check still
runs unchanged: every staged orig/dest path is checked against the union with
`covers_concrete_paths`, with exactly the four existing policy-path exemptions
(`.mpd/config.json`, `.mpd/directives/`, `.githooks/pre-commit`,
`.githooks/pre-push`). Protected-artifact D/R/C blocking and the `staged_blob`
manifest/ledger reads are skipped **only inside this arm**, exactly as the
AwaitingCommit branch already skips them for the same commit in the correct flow.

Ordinary in-progress commits are byte-identical: the trigger requires both an
archive record and the staged removal of the resolved change's own manifest, which
an in-progress change has neither. When the trigger only partially holds, the branch
fails closed with a specific reason rather than sliding to the ordinary path or
authorizing a narrowed scope — a `None` record routes to the byte-identical ordinary
block (`ordinary_else_governance`, `cli.rs:4819`, shared across every call site so
the two copies cannot drift); a `ledger::load` error is a distinct block that never
falls through to an index read; a missing, invalid, or rebound plan blocks by name.
Any record- or plan-derived string that reaches an error message (`archive_path`,
`candidate_id`) is rendered through `bounded_record_hint` (`cli.rs:4737`), which
applies `harness::terminal_safe` and a length cap — the worktree ledger is
owner-writable and therefore attacker text under the gate's own cooperative-owner
threat model.

**Correct operator flow.** Commit **before** `mpd archive --abandon`: while
`.mpd/pending-closure` still exists at `AwaitingCommit`, the existing AwaitingCommit
branch authorizes the commit from the transaction's classified rows unioned with the
closure plan's entries, and no active manifest is ever read. Post-abandon, the new
fallback arm handles it via `mpd use <change>` plus an ordinary `git commit` — the
archive record substitutes for the deleted manifest. Either way, an archived change's
active manifest must never be resurrected: security review is explicit that a stray
active manifest is exploitable trigger material, not just clutter, because a
committed copy re-opens that change's frozen archive record as a fresh
authorization source. `cmd_closure_abandon` (`cli.rs:6350`) now reiterates this
ordering in its success output.

## Usage

Canonical closure-commit sequence (commit while the closure is still pending):

```sh
mpd archive --yes
git commit
mpd archive --abandon --yes
```

Post-abandon recovery, when the closure commit was not made before abandoning
(the fallback arm authorizes it from the archive record):

```sh
mpd use <change>
git commit
```

Never restore a stray `openspec/changes/<change>/manifest.json` to force a closure
commit through — after an archive, that file's absence from the index is exactly
what the fallback arm is designed to tolerate, and recreating it re-opens the
change's archive record as authorization material for an unrelated commit.
