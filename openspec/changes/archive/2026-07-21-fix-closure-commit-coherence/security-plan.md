# Security (plan) review

## Actor

Security

## Threat model

**Trust boundary under review.** `staged_precommit_governance` (`cli.rs:4673-4937`)
is the commit-gate: the last machine check between staged content and repository
history. This change adds a third authorization arm to it (alongside the
AwaitingCommit branch and the ordinary manifest-scope branch), so the review
question is whether the new arm can authorize anything the existing two would not.

**Principal model (stated explicitly).** The gate runs client-side in a clone whose
owner controls the worktree, the index, `.mpd/`, `.git/mpd/`, and the hook wiring
itself, and can always run `git commit --no-verify`. The gate is therefore a
coherence/anti-footgun boundary against mistakes (including agent mistakes), not a
security boundary against a malicious clone owner. The correct bar is: **the
fallback must not make an unauthorized commit easier or quieter than it is today**,
and every ambiguous state must block.

**Attacker capabilities considered:** (a) arbitrary staged content and staged
statuses, including crafted `R`/`C` entries under `-M -C` detection; (b) unstaged
worktree edits, including to the tracked `.mpd/state/<change>.json` ledger; (c)
hostile bytes in the ledger record and the retained plan; (d) hostile path/name
strings surfacing in hook output (terminal injection); (e) cross-change confusion
(coordinator pointed at one change while another change's archive content is
staged).

### 1. Fallback-as-bypass — can arbitrary staged paths ride the new arm?

No, for the states the design covers. The trigger (design.md D2) is conjunctive and
each conjunct was verified against real code:

- **In-progress change:** its ledger has no `archive_closure` (only
  `cmd_archive`'s `build_plan` callback writes one, `cli.rs:6494-6507`), so D2.3
  fails; and the staged deletion of its own `manifest.json` is independently
  blocked by the protected-artifact check in the ordinary path
  (`cli.rs:4769-4789`). Two independent failures.
- **Post-landing change:** the active manifest path is absent from HEAD, so a `D`
  (or `R`-origin) entry for it cannot be staged at all — `git diff --cached` has
  nothing to delete. The trigger signature is unforgeable here, not merely checked.
- **Partial matches block, never authorize.** Record present but `system_paths`
  empty (pre-`system_paths` legacy record, verified to parse-degrade to empty,
  `closure.rs:4211-4227`) → block. Candidate-bound record with a missing,
  malformed, non-canonical, oversized, or differently-bound plan → block
  (`union_closure_scope` already turns `Some(Err)` into a hard block,
  `cli.rs:4651-4667`; the binding quadruple mirrors `closure.rs:3284-3288`). No
  conjunct subset yields authorization; the only fall-open path would be a Builder
  deviation, pinned by Conditions 1/4 and condition 10 below.
- **Scope inside the arm is bounded**, not open: `system_paths` ∪ validated plan
  entries via `covers_concrete_paths` (`closure.rs:1588` — exact or `/`-boundary
  prefix, never globs), checked over destination AND rename origin with only the
  four existing policy-path exemptions. This is the same bound the AwaitingCommit
  branch grants for the identical commit in the correct flow — no widening
  relative to committing before abandon.

**One honest residual window, verified concretely (the strays).** The trigger is
constructible today for exactly the two stray changes: both
`openspec/changes/candidate-lifecycle-defects/manifest.json` and
`openspec/changes/proportionate-governance/manifest.json` are in HEAD, both
ledgers carry candidate-bound archive records with non-empty `system_paths` (75
and 73 concrete paths, spanning most of `crates/mpd/src/*.rs`), and both retained
plans exist in `.git/mpd/closure-plans/`. Until the task-1 deletions land, an
operator who runs `mpd use <stray-change>` and stages that stray's deletion gets
one commit authorized by that old change's frozen footprint instead of any current
change's scope — and because "later commits editing archived-scope files" are
legitimate history, `publish --verify` would never flag the smuggled edit
afterward. Assessment: owner-only (within the cooperative boundary), bounded to
the recorded footprint, requires a deliberate three-step sequence no canonical
flow produces, and is closed **permanently** by task 1 (once the strays are gone,
no archived change's manifest path exists in HEAD, so the signature is again
unforgeable). It must be named, ordered first, and its recurrence path (re-creating
a stray) called out in the guidance — condition 13.

### 2. Authority source integrity

Both authorities survive `abandon_apply` (verified: it deletes only the pointer,
journal, and staged transaction files, `transaction.rs:1536-1561`) and are read
through the existing hardened loaders only: the ledger via `ledger::load` →
`read_contained_capped` (containment + byte cap, `ledger.rs:1663-1669`); the plan
via `load_candidate_closure_plan` (symlink refusal + `O_NOFOLLOW`, 64 MiB cap,
canonical round-trip, transaction-id binding, owner-only `0700` directory checks,
`closure.rs:782-852`). No new parser, no new read path — Condition 3 is sound and
matches what the code offers.

**The worktree-read asymmetry, examined.** The ordinary branch reads its
authorities from the index precisely so an unstaged worktree edit can never
broaden a decision; the fallback reads the ledger from the worktree. This is a
letter-level deviation but the correct choice, for two reasons verified in code:
(a) closure-commit authorization has *always* rested on clone-local state — the
AwaitingCommit branch trusts the untracked pointer, journal, and `.git/mpd` plan,
none of which are index content; (b) `verify_commit_coherence` reads the same
worktree ledger record, so gate and verifier judge from the same source and cannot
diverge. Forgery calculus: a principal who can write `.mpd/state/<change>.json`
can already `--no-verify` (or rewrite the hook wiring), so the fallback does not
make forgery easier — it makes one previously-impossible *legitimate* commit
possible, held to the same record+plan pair the verifier enforces. The forgeable
inputs do demand output hygiene (a forged `archive_path` or `candidate_id`
reaching an error message is attacker text) — condition 12.

### 3. Ordinary-commit path unchanged

The trigger requires an archive record plus the staged removal of the resolved
change's own active manifest; an in-progress commit has neither, so the ordinary
branch — protected-artifact D/R/C blocks, index-only `staged_blob` reads of
manifest and ledger, `manifest.covers` over every orig/dest path, identical error
strings — is untouched (design D4, Condition 1). One ambiguity found: design D3's
parenthetical lists "no archive record" among the fallback's specific-reason
blocks, while the spec scenario "Closure-shaped commit without an archive record"
requires the *ordinary governance-artifact protection* to block with no
archive-record authorization engaging. Both fail closed, but they produce
different behavior for a record-less in-progress change deleting its own manifest;
left unreconciled the Builder could change an ordinary-path error string, violating
Condition 1. Condition 10 fixes the precedence.

### 4. Change resolution — cross-change authorization

Sound as designed, with one pin needed. Post-abandon, `resolve_change`
(`cli.rs:862-875`) can only resolve via `.mpd/current` (the pending-view arm is
vacuous in the ELSE branch), i.e. an explicit `mpd use`. The trigger keys on the
resolved change's OWN `manifest_path` and OWN ledger record: staging change X's
archive content while coordinating C either fails the trigger (X's manifest
deletion ≠ C's `manifest_path` → ordinary path, where C's manifest must cover it)
or, if C's own closure shape is also staged, bounds everything to C's record —
X's archive directory is not in C's `system_paths` (only C's own dated archive
target is a prefix entry there). What must not regress: the equality must be
byte-exact against the path built from the validated change name, and a
staged-path-derived name must never *select* the authorizing ledger (it may only
name a change in D5 error text). Condition 11.

### 5. Stray deletion commit

Sound and needs no bypass. Verified: both stray paths are declared verbatim in
this change's `manifest.json`; they are not this change's protected artifacts
(`protected()` guards only the resolved change's own paths); `covers` matches them
exactly; manifest and ledger are present in the index for the ordinary branch to
read. The deletion commits under the *current* hook unchanged, and under the fixed
hook the trigger cannot fire on them (their paths are not the resolved change's
`manifest_path`). D6 is correct that the AwaitingCommit scope (rows ∪ expected
post-archive entries) cannot cover a deletion, so pre-archive ordering is not just
style — it is the only ordering that works. Condition 13 additionally makes it the
first commit, closing the §1 window as early as possible.

### 6. Coverage check never weakened

Confirmed by design text and code shape: the fallback arm provides a scope and
runs the same per-entry orig+dest `covers_concrete_paths` loop the AwaitingCommit
branch runs, with exactly the four policy-path exemptions; the path-keyed content
checks for `.mpd/config.json`, `.mpd/directives/`, and the two `.githooks/`
policies live in the shared tail loop (`cli.rs:4832-4935`) and run in all three
arms. Skipping the protected-artifact check and the strict judgment content checks
inside the arm mirrors the AwaitingCommit branch exactly (`staged_ledger = None`)
and is inherent to a closure commit — deleting the governance artifacts is its
purpose, and the scope union is the guard. Condition 6 is sound. Note for
completeness: the arm (like the AwaitingCommit branch today) permits staging a
modified or deleted ledger inside scope; content-level equivalence is the
verifier's job — the retained plan binds the exact ledger postimage
(`DeterministicArchivePostimages.ledger`, `cli.rs:6527-6533`), so tampered staged
ledger content fails landing verification. No new exposure.

**Conditions for Builder in design.md (1-9): reviewed individually — sound,
testable, and consistent with the code they cite.** Condition 3's "no weaker
parallel read" and Condition 5's field-for-field binding are exactly right;
Condition 9's test matrix covers the fail-closed arms. The additions below close
the gaps found above.

## Conditions for Builder

Design.md Conditions 1-9 are adopted wholesale. Numbered additions:

10. **Record-absent precedence.** When the staged diff removes the resolved
    change's active manifest and `ledger.archive_closure` is `None`, the ordinary
    path runs byte-identical and blocks via the existing protected-artifact check
    (spec scenario "Closure-shaped commit without an archive record") — the
    fallback's specific-reason blocks are reserved for a *present but unusable*
    record (empty `system_paths`; plan missing, invalid, or rebound). A
    `ledger::load` failure with a closure-shaped diff staged blocks with that
    reason and never falls through to the ordinary manifest read. Prevents: silent
    ordinary-path behavior drift (Condition 1 violation) and a fail-open gap
    between "no record" and "bad record" handling. Test: in-progress change
    staging its own manifest deletion yields today's exact
    "deletion of required governance artifact" error.

11. **Trigger equality discipline.** `manifest_path` is built from the resolved,
    `validate_change_name`-validated coordinator name and compared byte-exact
    against `entry.path` (status `D`) or `entry.orig_path` (status `R`) — no
    prefix/suffix matching. Status `C` with the manifest as origin never triggers
    (the manifest remains present; the ordinary path's copy-protection blocks).
    A change name derived from a *staged path* is used only to render D5 guidance,
    never to select which ledger record authorizes. Prevents: cross-change
    authorization and copy-shaped trigger confusion.

12. **Untrusted-text hygiene extended to record/plan-derived strings.** Any string
    sourced from the ledger record or retained plan (`archive_path`,
    `candidate_id`, plan fields) that appears in new hook output is rendered via
    `harness::terminal_safe` and length-bounded (follow the
    `ledger_version_probe` precedent, `ledger.rs:1690-1708`). The worktree ledger
    is owner-writable, therefore attacker text under this arm's own threat model.
    Prevents: terminal escape/spoofing injection through hook error output.

13. **Close the stray window first and name its recurrence.** The task-1 stray
    deletions are the FIRST commit of this change, before any other commit of this
    change and before the fallback is exercised anywhere. The D8 doc and the D5/D7
    guidance state the security rationale explicitly: committing a copy of an
    archived change's active manifest re-opens that change's archive record as a
    commit-authorization source — which is *why* the manifest must never be
    re-created, not just tidiness. Evidence: after the deletion commit,
    `git ls-files 'openspec/changes/*/manifest.json'` lists only active
    (unarchived) changes. Prevents: the §1 footprint-replay window persisting or
    silently recurring.

14. **The record+plan pair is the sole authorizing input of the arm.** Scope may
    be computed only from `record.system_paths` and the validated plan's entry
    paths; no other source — the staged ledger, the archived manifest (index or
    worktree), HEAD content, or any worktree file — may *widen* it. Any additional
    consistency check the Builder adds may only narrow/block, never authorize.
    Single read, single decision per hook invocation. Prevents: a well-meaning
    secondary source quietly becoming a parallel authority the verifier does not
    enforce.

## Verdict

CONDITIONAL PASS

The archived-closure fallback is a safe authorization path, not a bypass, under
the gate's actual (cooperative-owner) trust model: its trigger is unforgeable
outside the one state it exists to serve — post-landing it cannot be staged,
in-progress it lacks the record and is independently blocked — every partial
match fails closed, its scope is the same record+plan bound the verifier holds
the commit to (gate/verifier self-consistency), and the ordinary branch's
coherence guarantee is preserved. Authority reads reuse only the existing
hardened loaders; forgery is not made easier than `--no-verify` already makes it.
The pass is conditional on: the record-absent precedence being resolved in favor
of the byte-identical ordinary block (10), exact-equality trigger discipline (11),
terminal hygiene for record-derived text (12), the stray window being closed by
the first commit and its rationale documented (13), and the record+plan pair
remaining the arm's only authorizing input (14). Owner: Builder. Closing
evidence: implementation + the Condition 9 test matrix extended per 10/11/13,
reviewed at Security (code). Unresolved conditions block that gate.
