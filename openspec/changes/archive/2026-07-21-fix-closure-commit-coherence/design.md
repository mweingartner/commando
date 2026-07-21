# Design: Fix Closure Commit Coherence

## Actor

Architect

## Context

This file is the canonical current-state contract. All file/line references were
verified against the current tree. No UI surface; risk is **high** because the change
edits the pre-commit governance gate itself.

### The two branches of the pre-commit gate

The mpd pre-commit hook (`HookCommand::PreCommit`, `cli.rs:5057-5070`) calls
`staged_precommit_governance` (`cli.rs:4673-4937`), which has exactly two authorities:

- **AwaitingCommit branch** (`cli.rs:4679-4711`). `openspec_core::inspect` finds a
  pending closure at `TransactionState::AwaitingCommit`. Scope = the transaction's
  classification rows (with `"src -> dst"` rows split into both sides) unioned with the
  validated closure plan's expected entry paths via `union_closure_scope`
  (`cli.rs:4651-4667`, D3 of closure-defects-and-measurement). Coverage uses
  `closure::covers_concrete_paths` (`closure.rs:1588` — concrete paths, `/`-boundary
  prefix, never globs). **No active-manifest read.** A pending closure at any other
  stage blocks (`cli.rs:4707-4709`). This is the correct path for the closure commit.

- **ELSE branch** (`cli.rs:4712-4830`). With no pending closure, the change is resolved
  by `resolve_change` (`cli.rs:862-875`: `.mpd/current` via `ledger::current`, else the
  pending view, else error). Derived paths (`cli.rs:4737-4751`): `manifest_path` =
  `openspec/changes/<change>/manifest.json`, `tasks_path`, `ledger_path` =
  `.mpd/state/<change>.json`, and the judgment artifact paths. The branch (a) blocks
  `D`/`R`/`C` of those protected artifacts (`cli.rs:4769-4789`); (b) reads the active
  manifest and ledger **from the index** via `git::staged_blob` (`cli.rs:4795`,
  `cli.rs:4805`; `git.rs:454` — `git show :<path>`, canonical-path-validated, bounded)
  so an unstaged worktree edit can never broaden a hook decision, hard-erroring
  "active manifest is absent or unreadable in the index" when the index has no entry;
  and (c) checks every staged orig/dest path against `manifest.covers(path, &system)`
  (`cli.rs:4814-4828`; `closure.rs:1567`, `active_system_scope` `closure.rs:2712`).
  Its purpose is coherence for **ordinary in-progress commits**: the change's declared
  scope, read from an authoritative index postimage, must cover everything staged.

### The footgun, traced

`mpd archive --yes` prepares and drives the archive transaction to AwaitingCommit
(`cli.rs:6569-6582`), clears the `.mpd/current` convenience pointer
(`cli.rs:6587-6589`), and prints the intended order: "commit the archived result, then
run `mpd archive --abandon --yes`" (`cli.rs:6596-6599`).

- **Correct flow (commit before abandon)** — confirmed to avoid the ELSE branch
  entirely: while `.mpd/pending-closure` exists at AwaitingCommit, `inspect` returns
  the view and the AwaitingCommit branch authorizes the commit from rows ∪ plan
  entries. No active manifest is read; no stray copy is ever needed.

- **Commit after abandon** — `abandon_apply` (`transaction.rs:1536-1561`) deletes only
  the pointer, journal, and staged files. The next `git commit` finds no pending
  closure and falls into the ELSE branch: `resolve_change` fails ("no active change
  coordinator", `.mpd/current` was cleared) or, after `mpd use <change>`
  (`cli.rs:6608` — which exists precisely to recover the cleared pointer), the branch
  demands `openspec/changes/<change>/manifest.json` in the index — a file the archive
  correctly deleted. `recover_apply` cannot help: it refuses without a pointer
  (`transaction.rs:1497-1506`), and nothing recreates an abandoned transaction. The
  state is a dead end whose only escapes are resurrecting a stray active-manifest copy
  or bypassing the hook. The stray route is what happened twice:
  `openspec/changes/candidate-lifecycle-defects/manifest.json` and
  `openspec/changes/proportionate-governance/manifest.json` are in HEAD (confirmed via
  `git ls-files`), and each is an "extra path" against its closure plan
  (`diff_closure_entries`, `closure.rs:882`), so `resolve_closure_landing` never finds
  a landing commit and `mpd publish --verify` stays red for those changes.

### What survives abandonment (the authoritative record)

Abandon never touches: the change's ledger `.mpd/state/<change>.json` with its
`archive_closure: ArchiveClosure` record (`closure.rs:239-282`) — `base_commit`,
`archive_path`, `transaction_id`, `candidate_id`, `allowed_paths` (patterns), and
crucially `system_paths` (`closure.rs:259-277`): the **concrete, frozen snapshot** of
every path in declared/system scope at archive time, including the dated archive
target as a prefix entry — nor the retained closure plan in
`.git/mpd/closure-plans/<transaction-id>` (`closure.rs:819-822`), whose loader
enforces no-follow open, the size cap, canonical round-trip, and transaction-id
binding. `verify_commit_coherence` (`closure.rs:3243`) already trusts exactly this
pair after abandonment, with explicit plan↔record binding checks
(`closure.rs:3284-3288`).

There is already an in-tree precedent for the authority split this design extends:
`manifest_view` (`cli.rs:1850-1900`) falls back to
`ledger.archive_closure.system_paths` with `covers_concrete_paths` when the active
manifest is gone, citing the spec scenario "Active change directory has been
archived". The pre-commit hook is the one consumer that never got the same treatment.

## Goals / Non-Goals

**Goals**

1. A properly-archived closure commit never requires a resurrected active-manifest
   copy — in the correct flow (already true) and in the post-abandon flow (new).
2. The ELSE branch's coherence guarantee for ordinary in-progress commits is
   preserved bit-for-bit: declared scope, read from authoritative index postimages,
   covers every staged path.
3. Every ambiguity fails closed with an actionable message; no message ever directs
   the operator to re-create `openspec/changes/<change>/manifest.json`.
4. Delete the committed archived-change strays so `publish --verify` can clear for those changes.

**Non-Goals**

- No change to the AwaitingCommit branch, the archive transaction, `abandon_apply`
  semantics, or `verify_commit_coherence`.
- No refusal of `mpd archive --abandon` before the closure commit (messaging only —
  see D7); no new flags or commands.
- No repair of the two already-red archived closures beyond removing the strays
  (their landing history is what it is; the goal is that the strays stop being load-
  bearing and stop appearing as extra paths going forward).

## Decisions

### D1 — Chosen option: archived-closure fallback sourced from the ledger record + retained plan

The ELSE branch gains a second authority arm. When its trigger (D2) holds, scope is
authorized from the clone-private archive record: `ArchiveClosure::system_paths`
(concrete frozen footprint) unioned with the retained closure plan's validated entry
paths, matched with `covers_concrete_paths` — reusing `union_closure_scope` with
`system_paths` as the rows argument so the widen-or-block semantics are literally the
same code as the AwaitingCommit branch.

Options weighed:

- **Rejected: source coherence from the archived manifest in the index**
  (`openspec/changes/archive/<date>-<change>/manifest.json`). The archived manifest is
  part of the very tree being committed — the staged content would authorize itself.
  It would also add a new manifest-parse trust path in the hook and re-derive system
  scope (whose `archive_target` uses `today_utc`, wrong across a date boundary). The
  ledger record + plan are outside the staged tree, written by the archive
  transaction, digest- and transaction-id-bound, and are exactly what
  `verify_commit_coherence` will later hold the commit to. Self-consistency between
  the gate and the verifier is the strongest coherence available here.
- **Rejected: actionable error only.** Post-abandon there is no recovery command
  (`recover_apply` refuses without a pointer), so a pure error leaves `git commit
  --no-verify` as the only exit — replacing one gate bypass with another. The error
  text survives as the fail-closed arm of D2/D5 for every state the record cannot
  authorize.
- **Chosen variant of Option 2** ("tolerate an archived change"): tolerance is granted
  only by the archive record, never by relaxing the manifest requirement.

### D2 — Trigger: exhaustive, fail-closed conditions

The fallback arm engages only when **all** of the following hold; otherwise the branch
behaves exactly as today (falls through to the ordinary path or blocks with guidance):

1. No pending closure exists (already the ELSE precondition).
2. `resolve_change` produced a change `C` (post-abandon this requires `mpd use C`;
   the operator is told so — D5).
3. `ledger::load(root, C)` succeeds and carries `archive_closure = Some(record)`.
4. The staged diff **itself removes C's active manifest**: an entry with status `D`
   and `path == manifest_path`, or status `R` with `orig_path == manifest_path`
   (`diff_cached_name_status` runs with `-M -C`, `git.rs:437-447`, so the archive move
   may surface either way). This is the unforgeable signature of the closure commit:
   an in-progress change cannot have it (no archive record — condition 3 — and the
   deletion is blocked as a protected artifact today), and a post-landing commit
   cannot stage a deletion of a path absent from HEAD.
5. `record.system_paths` is non-empty. A pre-`system_paths` legacy record degrades to
   empty (`closure.rs:4211-4226`) and must fail closed here, mirroring
   `manifest_view`'s note.
6. Plan discipline, mirroring `verify_commit_coherence` exactly:
   - `record.candidate_id` is `Some` → the retained plan MUST load
     (`load_candidate_closure_plan`) and MUST bind: `plan.candidate_id`,
     `plan.candidate_base_commit`, `plan.archive_path`, `plan.archive_transaction_id`
     equal the record's fields (`closure.rs:3284-3288`). Any failure blocks — never a
     silent narrowing to `system_paths` only.
   - `record.candidate_id` is `None` (legacy pre-candidate archive) → no plan is
     expected; scope is `system_paths` alone, matching `union_closure_scope`'s `None`
     semantics.

When the arm engages: scope = `union_closure_scope(record.system_paths, plan)`; every
staged orig/dest path must satisfy `covers_concrete_paths(scope, path)` with the same
policy-path exemptions as both existing branches (`.mpd/config.json`,
`.mpd/directives/`, `.githooks/pre-commit`, `.githooks/pre-push`). The protected-
artifact D/R/C check is skipped **inside this arm only** — deleting/renaming the
active governance artifacts is the point of a closure commit, exactly as in the
AwaitingCommit branch, and the scope union is the guard. `staged_ledger` is `None`, so
the strict judgment-artifact content checks are skipped exactly as in the
AwaitingCommit branch today; the path-keyed config/directive/hook-policy content
checks (`cli.rs:4885-4934`) still run unchanged.

### D3 — Ordering inside `staged_precommit_governance`

The trigger is evaluated **before** the protected-artifact check and before the
`staged_blob` manifest read (both are skipped in the fallback arm; the arm never
attempts to read the deleted manifest). When any of conditions 3-6 fails, the branch
does NOT fall back to the ordinary path silently: if condition 4 matched (the staged
diff removes C's active manifest) but the record/plan cannot authorize, the result is
a block with the specific reason (no archive record / legacy record without concrete
footprint / plan missing / plan invalid or bound elsewhere). If condition 4 does not
match, the ordinary path runs unchanged — this is what keeps every in-progress commit
byte-identical, including deletions of *other* changes' stray manifests (their paths
are not the resolved change's `manifest_path`, so the trigger never fires; scope
coverage governs them, as today).

### D4 — Ordinary-commit behavior is provably unchanged

The fallback arm requires an `archive_closure` record and the staged removal of the
resolved change's own active manifest. An in-progress change satisfies neither.
Therefore: same protected-artifact blocks, same index reads of manifest and ledger,
same `manifest.covers` checks, same error strings. This is the branch's coherence
guarantee and it is a Condition for Builder (below) with a regression test.

### D5 — Error guidance (no new authority, text only)

- `resolve_change` failure in the hook, when the staged diff removes some
  `openspec/changes/<X>/manifest.json`: name `X` (after `validate_change_name`,
  rendered via `harness::terminal_safe`) and say: a closure-shaped commit was detected
  without its pending transaction; the closure commit belongs **before**
  `mpd archive --abandon --yes`; to commit it now, run `mpd use <X>` and retry; do not
  re-create `openspec/changes/<X>/manifest.json`.
- The same hint is appended when the resolved change is a *different* active change
  and the scope check trips over `X`'s closure paths.
- No message suggests `mpd archive --recover` for the abandoned state — recover
  requires the pointer that abandon deleted; suggesting it would be false guidance.

### D6 — Stray deletion lands as an ordinary in-progress commit

The AwaitingCommit scope is rows ∪ plan entries; a deleted path appears in neither
(plan entries are the expected *post-archive tree*), so the closure commit cannot
carry the stray deletions. The Builder therefore deletes both strays and commits that
deletion mid-change through the ordinary ELSE gate: the paths are declared verbatim in
this change's manifest (`openspec/changes/candidate-lifecycle-defects/manifest.json`,
`openspec/changes/proportionate-governance/manifest.json` — see the edited
`manifest.json`), they are not this change's protected artifacts, and `covers` matches
them exactly. This works under the **current** hook already — no fix needed to delete
the strays — and the fixed hook leaves it untouched (D3). This change's own closure
then runs the correct flow (archive → commit → abandon) and needs no stray.

### D7 — Abandon messaging

`cmd_closure_abandon` (`cli.rs:6090-6111`) success output gains one sentence
reiterating order: abandon is post-commit housekeeping; if the closure commit has not
been made yet, the archived change can still be committed via `mpd use <change>`
followed by `git commit` (the gate authorizes it from the archive record). Message
only; semantics untouched.

### D8 — Operator procedure is documentation

`docs/fix-closure-commit-coherence.md` (Documenter phase) records: canonical flow
`mpd archive --yes` → `git commit` → `mpd archive --abandon --yes`; recovery flow
after an early abandon: `mpd use <change>` → `git commit`; and the rule that
`openspec/changes/<change>/manifest.json` must never be re-created after archive.

## Risks / Trade-offs

- **[New authority arm in a security gate]** → The arm reuses existing hardened
  loaders only (`ledger::load`, `load_candidate_closure_plan`,
  `union_closure_scope`, `covers_concrete_paths`); no new parser, no new index read,
  no worktree read. Binding checks mirror `verify_commit_coherence`, so the gate can
  only authorize what the verifier would hold the commit to.
- **[Trigger misfire on exotic staged diffs]** → The trigger keys on the resolved
  change's own `manifest_path` as a `D`/`R`-source plus a recorded `archive_closure`;
  in-progress and post-landing states cannot produce both. Anything partial blocks
  with a specific reason (D3), never falls open.
- **[Junk added under the archive directory via the fallback]** → Possible only for a
  path inside `system_paths` ∪ plan entries — the same bound the AwaitingCommit branch
  grants — and `verify_commit_coherence` still rejects any landing tree with an extra
  path. The gate is scope-level; content-level equivalence remains the verifier's job,
  unchanged.
- **[Stray deletion staged into the closure commit by mistake]** → Blocked by the
  AwaitingCommit scope (not rows, not entries); tasks order the deletion commit before
  `mpd archive --yes` and the e2e test pins it.
- **[Legacy records]** → `candidate_id: None` keeps the concrete-footprint scope;
  empty `system_paths` blocks. Both are explicit, tested arms.

## Conditions for Builder

1. **ELSE-branch coherence guarantee preserved.** For every commit where the fallback
   trigger (D2) does not fully hold, the ordinary path is byte-identical: protected-
   artifact D/R/C blocks, manifest + ledger read from the index via `git::staged_blob`
   (never the worktree), `manifest.covers` over every staged orig/dest path, identical
   error strings. Regression-test an ordinary in-progress commit before and after.
2. **A closure commit never requires a resurrected active manifest.** Correct flow:
   AwaitingCommit branch untouched. Post-abandon flow: the fallback arm never attempts
   `staged_blob(manifest_path)` and no error path directs the operator to re-create
   `openspec/changes/<change>/manifest.json`.
3. **Authority reads use the existing hardened loaders only.** Ledger via
   `ledger::load`; plan via `load_candidate_closure_plan` (no-follow open, size cap,
   canonical round-trip, transaction-id binding); scope union via
   `union_closure_scope`; matching via `covers_concrete_paths`. Do NOT read the
   archived manifest (index or worktree) as an authority; do not add any new
   parse/read path. This satisfies the "same no-follow/canonical discipline as the
   active read" requirement by never introducing a weaker parallel read.
4. **Fail closed on any ambiguity.** If the staged diff removes the resolved change's
   active manifest but any of D2.3-D2.6 fails (no record; empty `system_paths`;
   candidate plan missing, invalid, or bound to a different transaction/base/archive
   path/candidate), the commit blocks with the specific reason. Never silently narrow
   a candidate closure to `system_paths`-only; never fall through to the ordinary
   manifest read; never consult the worktree.
5. **Plan↔record binding mirrors `verify_commit_coherence`** (`closure.rs:3284-3288`)
   field-for-field: `candidate_id`, `candidate_base_commit` vs `base_commit`,
   `archive_path`, `archive_transaction_id` vs `transaction_id.to_hex()`.
6. **No new bypass of the staged-scope coverage check.** In the fallback arm, every
   staged path — destination AND rename origin — is checked with
   `covers_concrete_paths` against `system_paths` ∪ validated plan entries, with
   exactly the existing four policy-path exemptions and no others. The strict
   judgment/tasks content checks may skip only to the extent the AwaitingCommit branch
   already skips them (`staged_ledger = None`); the path-keyed config, directive, and
   githooks content checks still run.
7. **Stray deletions are in this change's declared scope and land pre-archive.** The
   the archived-change stray paths stay declared verbatim in this change's `manifest.json`; the
   Builder deletes both files and commits that deletion as an ordinary in-progress
   commit BEFORE `mpd archive --yes` (the closure scope cannot cover deletions — D6).
8. **Untrusted-text hygiene in new errors.** Any change name derived from staged paths
   passes `openspec_core::validate_change_name` before use and is rendered via
   `harness::terminal_safe`; no staged content is echoed raw.
9. **Initial tests written in the Build pass**, minimum: (a) e2e post-abandon closure
   commit succeeds via `mpd use <change>` + `git commit` with no active manifest
   anywhere; (b) e2e correct-flow closure commit still succeeds (AwaitingCommit branch
   regression); (c) fallback blocks: unrelated staged path outside the union; missing
   archive record; tampered/rebound plan; legacy record with empty `system_paths`;
   (d) legacy `candidate_id: None` record authorizes from `system_paths` alone;
   (e) ordinary in-progress commit regression (Condition 1), including deleting
   another change's stray manifest within declared scope; (f) the D5 guidance appears
   when no coordinator is set and a closure-shaped diff is staged.

## Verdict

PASS — plan complete; conditions enumerated for the Security (plan) gate and Builder.
