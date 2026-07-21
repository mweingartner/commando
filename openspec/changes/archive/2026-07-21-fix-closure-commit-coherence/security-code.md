# Security (code) review

## Actor

Security

## Findings

### F1 — Stray-window closure was incomplete: a third stray remained exploitable (MEDIUM; scope/completeness, not a code bypass) — CONFIRMED, then FIXED in this change; re-verified closed

**Location:** repository data, not the diff — but it breaks the change's own
Security-plan **Condition 13** closing evidence and design **Goal 4**. Trigger
material: `git ls-tree HEAD` still lists
`openspec/changes/closure-defects-and-measurement/manifest.json` in HEAD after
this change lands; `.mpd/state/closure-defects-and-measurement.json` carries a
live candidate-bound `archive_closure` record (79 `system_paths`, including
`crates/mpd/src/cli.rs` and most of `crates/mpd/src/*.rs`); its retained plan
`.git/mpd/closure-plans/f2e97bbf0264a610…json` is present. The change deletes
only the two strays named in the plan
(`candidate-lifecycle-defects/manifest.json`,
`proportionate-governance/manifest.json`, both staged `D`); a **third** archived
change is in the identical exploitable state and is NOT in this change's declared
`manifest.json` scope, so the Builder could not have removed it without widening
scope.

**Attack (the exact §1 footprint-replay window the plan says task 1 closes
"permanently"):** an operator/agent runs `mpd use closure-defects-and-measurement`,
stages `git rm openspec/changes/closure-defects-and-measurement/manifest.json`
plus arbitrary content anywhere inside that change's frozen 79-path footprint,
and the fallback authorizes one commit from that old change's recorded scope
instead of any current change's scope. Because "later commits editing
archived-scope files are legitimate history," `publish --verify` never flags the
smuggled edit afterward. This is byte-for-byte the residual the Security-plan
elevated to a named condition — the plan simply undercounted the strays as
"exactly two" (the third was landed at commit `8c7b7c5` "Land
closure-defects-and-measurement", plausibly after the plan was written).

**Severity rationale:** owner-only within the gate's cooperative-owner trust
model, bounded to the recorded footprint, and requires a deliberate three-step
sequence no canonical flow produces — the same envelope the plan accepted for the
two named strays. It is NOT a defect in the new fallback code (that code is
sound — see below). It is a completeness gap: Condition 13's closing evidence
(`git ls-files 'openspec/changes/*/manifest.json'` lists only active/unarchived
changes) is **false as shipped**, and the window the change exists to close
stays open for one change.

**Remediation applied (remediation option (a)) and re-verified:**
`openspec/changes/closure-defects-and-measurement/manifest.json` was added to
this change's declared `manifest.json` scope and `git rm`'d; design.md's
stray-cleanup wording was generalized from "the two strays" to the
archived-change strays as a set. Re-audit evidence, checked directly against
the repository after the fix:

- `git status --porcelain 'openspec/changes/*/manifest.json'` shows staged `D`
  for all three archived-change strays: `candidate-lifecycle-defects`,
  `closure-defects-and-measurement`, `proportionate-governance`.
- `git ls-files 'openspec/changes/*/manifest.json'` excluding `archive/` is
  **empty** — no non-archive active manifest remains in the index at all, so the
  check is comprehensive by construction (nothing left to classify as in-flight
  vs archived).
- The only in-flight change, `fix-closure-commit-coherence` itself, has an
  untracked (not-yet-committed) manifest and **no** `archive_closure` record in
  `.mpd/state/fix-closure-commit-coherence.json`, so even once tracked it is not
  trigger material.
- The fallback code is byte-identical to the audited version: same function
  anchors (`archived_closure_fallback_scope` `cli.rs:4761`,
  `ordinary_else_governance` `cli.rs:4819`, `staged_precommit_governance`
  `cli.rs:4905`) and same `crates/mpd/` diff stat (1228 insertions / 68
  deletions across the same three files) — only governance artifacts changed,
  so the code-audit conclusions carry over unmodified.

Once the staged deletions land, no archived change's active manifest exists in
HEAD, so the fallback's `D`/`R`-origin trigger signature is unstageable for every
change except one genuinely inside its own post-archive commit window — the §1
footprint-replay window is closed for the complete set, not just the two the
plan named. The window's only recurrence path remains re-committing a copy of an
archived change's active manifest, which the spec delta now prohibits ("SHALL
never be re-created") and the D5/D7 guidance actively steers away from.
Mis-ordering the deletion commit fails closed, not open: the AwaitingCommit
closure scope cannot cover deletions (design D6), so the strays can only land
via the ordinary in-scope pre-archive commit as planned.

## Conditions verified

The change's own Conditions for Builder are Design 1-9 plus Security-plan 10-14.
All were checked against the shipped code on disk.

1. **ELSE-branch coherence preserved (Design 1 / Cond 10).** HOLDS. The old
   inline ELSE body is extracted verbatim into `ordinary_else_governance`
   (`cli.rs:4819-4903`): same protected-artifact `D`/`R`/`C` blocks with the
   identical strings ("deletion of required governance artifact {path}",
   "rename/copy of required governance artifact"), same index-only
   `git::staged_blob` reads of manifest+ledger (never the worktree), same
   `manifest.covers` loop with the same four policy exemptions. It is invoked
   from all three fall-through sites (`cli.rs:5057`, `5081`) so the copies cannot
   drift. The only message divergence is the deliberately-designed D5 enrichment
   (`cli.rs:4886-4896`) appended ONLY when the out-of-scope path is itself a
   *different* change's `openspec/changes/<X>/manifest.json` with a valid name —
   which is exactly what design D5 authorizes and Cond 11 permits (staged-derived
   name in error text only). e2e `in_progress_change_deleting_own_manifest_
   without_archive_record_blocks_as_today` and
   `ordinary_in_progress_commit_regression_with_foreign_stray_deletion_in_scope`
   pin the base strings. VERIFIED green.

2. **A closure commit never requires a resurrected manifest (Design 2).** HOLDS.
   The fallback arm (`cli.rs:5022-5079`) never calls `staged_blob(manifest_path)`;
   scope comes from `archived_closure_fallback_scope`. No error path emits a
   "re-create the manifest" instruction — `closure_recovery_hint`
   (`cli.rs:4721-4735`) says the opposite ("Do not re-create …"). e2e
   `post_abandon_closure_commit_succeeds_via_use_and_real_git_commit` commits
   through the real installed hook with no active manifest anywhere.

3. **Hardened loaders only (Design 3).** HOLDS. Ledger via `ledger::load`
   (`ledger.rs:1663` → `read_contained_capped`, containment + byte cap); plan via
   `closure::load_candidate_closure_plan` (`closure.rs:782-817`: symlink refusal,
   `O_NOFOLLOW`/`O_CLOEXEC`, 64 MiB cap, canonical round-trip, txid binding,
   `0700` owner-only dir checks). No new parser, no archived-manifest read, no new
   index read path.

4. **Fail closed on any ambiguity (Design 4 / Cond 10).** HOLDS. Inside the
   trigger: empty `system_paths` → block (`cli.rs:4767-4773`); candidate plan
   missing → block (`4781-4790`); plan binding mismatch → block (`4787-4802`);
   `ledger::load` error → distinct hard block that never falls to the ordinary
   index read (`cli.rs:5071-5078`); record `None` → `ordinary_else_governance`,
   which blocks the manifest deletion as a protected artifact (`5057-5065`). Every
   partial match fails closed; none narrows silently.

5. **Plan↔record binding mirrors `verify_commit_coherence` (Cond 5).** HOLDS.
   `cli.rs:4787-4802` compares `plan.candidate_id`, `plan.candidate_base_commit`
   vs `record.base_commit`, `plan.archive_path`, `plan.archive_transaction_id` vs
   `record.transaction_id.to_hex()` — field-for-field identical to
   `closure.rs:3284-3288`. Unit test
   `archived_closure_fallback_scope_blocks_when_plan_binding_differs_from_record`
   proves a base_commit mismatch blocks with "binding differs" rather than
   narrowing.

6. **Coverage never weakened (Cond 6).** HOLDS. The fallback supplies a scope and
   still runs the per-entry orig+dest `covers_concrete_paths` loop
   (`cli.rs:5036-5050`) with exactly the four policy exemptions
   (`.mpd/config.json`, `.mpd/directives/`, `.githooks/pre-commit`,
   `.githooks/pre-push`) — byte-identical to the AwaitingCommit and ordinary arms.
   The path-keyed config/directive/hook content checks in the shared tail
   (`cli.rs:5145-5193`) run in all arms. e2e
   `post_abandon_fallback_blocks_staged_path_outside_archived_scope` stages a path
   outside the union under a valid trigger and confirms it BLOCKS.

7. **Strays declared + land pre-archive (Cond 7).** HOLDS (after the F1 fix).
   All three archived-change strays — the two the plan named plus
   `closure-defects-and-measurement` found by this audit — are declared verbatim
   in this change's `manifest.json` and staged as ordinary `D` deletions;
   `git ls-files` excluding `archive/` lists no remaining non-archive change
   manifest. The deletion can only land via the ordinary pre-archive commit
   (the AwaitingCommit scope cannot cover deletions), so the ordering constraint
   is self-enforcing.

8. **Untrusted-text hygiene in new errors (Cond 8).** HOLDS. `removed_manifest_
   change_name` (`cli.rs:4692-4719`) accepts only single-component names that pass
   `validate_change_name`; the D5 hint applies `harness::terminal_safe`. All
   entry paths pass `digest::validate_canonical_path` up front (`cli.rs:4976-4988`)
   before any name derivation. Unit test
   `removed_manifest_change_name_extracts_only_a_validated_single_component_name`
   rejects `../../etc`, `a/b`, and `Evil_Name`.

9. **Initial tests present (Cond 9).** HOLDS. 9 unit + 9 e2e cases cover every
   arm: authorized union, empty `system_paths`, missing plan, rebound plan, legacy
   `candidate_id:None`, outside-scope block, no-record ordinary block, foreign
   stray in scope, and the no-coordinator guidance. All 18 run green (verified
   below).

10. **Record-absent precedence (Cond 10).** HOLDS. `cli.rs:5053-5065`: record
    `None` routes to `ordinary_else_governance` (byte-identical block), NOT a
    fallback-specific message; a `ledger::load` failure is a separate specific
    block (`5071-5078`) that never falls through to the ordinary index read. e2e
    `in_progress_change_deleting_own_manifest_without_archive_record_blocks_as_today`
    confirms today's exact string.

11. **Trigger equality discipline (Cond 11).** HOLDS. `stages_removal_of`
    (`cli.rs:4677-4690`) matches `entry.path == path` for `D` / `orig_path ==
    Some(path)` for `R`, byte-exact, and returns `false` for `C` and every other
    status. `manifest_path` is built from the resolved coordinator name only
    (`cli.rs:4992`); the ledger is loaded by resolved `change`
    (`cli.rs:5028`) — never a staged-path-derived name. Unit test
    `stages_removal_of_matches_delete_and_rename_origin_never_copy` proves `C`
    never triggers and `thing-evil` is not a prefix match.

12. **terminal_safe + bounded record/plan text (Cond 12).** HOLDS. `bounded_
    record_hint` (`cli.rs:4737-4746`) applies `harness::terminal_safe` and a
    200-char cap with `…`; it wraps the only two record-derived strings that reach
    output — `candidate_id` (`cli.rs:4797`) and `record.archive_path`
    (`cli.rs:4799`). The union-scope `map_err` path (`cli.rs:4813-4814`) is
    unreachable in this arm (the plan is pre-validated to `Some(Ok)`/`None`, so
    `union_closure_scope` never returns its `Some(Err)` error). e2e
    `post_abandon_fallback_blocks_when_candidate_bound_plan_is_missing_and_
    sanitizes_hostile_text` injects a 300-char `candidate_id` with `\x07`/`\x1b`
    and confirms control bytes are stripped and the tail is truncated.

13. **Close the stray window first / name recurrence (Cond 13).** HOLDS (after
    the F1 fix). The audit initially found this condition's closing evidence
    false — a third archived stray (`closure-defects-and-measurement`, live
    record + retained plan) remained in HEAD. The deletion set was extended to
    the complete set of archived-change strays and re-verified:
    `git ls-files 'openspec/changes/*/manifest.json'` excluding `archive/` now
    lists nothing, and the sole in-flight change carries no archive record.
    Design.md's wording is generalized from "two strays" to the archived-change
    strays as a set; the spec delta states the never-re-create rule. The
    deletions are staged to land in the pre-archive ordinary commit, ahead of
    this change's own closure.

14. **Record+plan pair is the sole authority (Cond 14).** HOLDS.
    `archived_closure_fallback_scope` (`cli.rs:4761-4816`) derives scope only from
    `record.system_paths` and the loaded+bound plan's entries; it reads no other
    worktree file, no archived manifest (index or worktree), no HEAD content. The
    binding check can only block, never widen. The worktree-read asymmetry (ledger
    read from worktree, not index) is the one the plan §2 examined and accepted:
    `verify_commit_coherence` reads the same worktree record, so gate and verifier
    judge from one source, and a principal who can write it can already
    `--no-verify`.

## Independent review

Re-audited the trigger from the attacker's side, ignoring the first pass's
conclusions:

- **Forge a `D` of an absent manifest.** `git diff --cached` reports a `D` only
  for a path in HEAD; a post-landing change's active manifest is absent from HEAD,
  so no `D` can be staged for it — the signature is structurally unforgeable, not
  merely checked. The one state where "manifest in HEAD" AND "archive record
  present" coincide is the post-abandon closure commit itself and the stray
  changes (F1). Confirmed against `diff_cached_name_status` (`git.rs:440-447`,
  `-M -C`) and `parse_name_status_z` (`git.rs:393-435`).

- **Cross-change record selection.** The authorizing ledger is `ledger::load(root,
  &change)` where `change` is the resolved coordinator (`.mpd/current`, validated
  by `ledger::current` → `validate_change_name`). No staged-path-derived string
  reaches the loader or the scope; `removed_manifest_change_name` output flows only
  into `format!`/`push_str` guidance. Traced both call sites (`cli.rs:4964`,
  `4886`).

- **Partial-trigger fall-open.** Exercised each conjunct failing in isolation
  (empty footprint, missing plan, rebound plan, unreadable ledger, absent record):
  every one reaches a `return Err`/`?` block, none reaches an authorize. The
  record-`None` and ledger-`Err` arms specifically do NOT fall through to the
  ordinary index read.

- **Coverage escape under a valid trigger.** Every staged entry's origin and
  destination are checked; the archive move's destination
  (`openspec/changes/archive/<date>-<change>/…`) is covered only because the
  archive target is a `/`-boundary prefix entry in `system_paths`, and
  `covers_concrete_paths`/`path_is_within` (`closure.rs:1580-1596`) reject
  `a/b-evil` against `a/b`. An unrelated staged path is blocked (e2e-verified).

Test execution verified, not self-reported: `cargo test -p mpd --bin mpd`
fallback unit lane = 9 passed / 0 failed; `cargo test -p mpd --test e2e` fallback
lane = 9 passed / 0 failed (real `git commit` through the installed
`.githooks/pre-commit`, PATH-pinned to the freshly built binary). Diff grep for
secret patterns and `unsafe`/`allow(` in the changed hunks: none. The only
`closure.rs` change is a `pub(crate)` visibility widening of `closure_tree_digest`
for a test helper (`closure.rs:1320-1329`) — no production caller, no logic
change.

## Refutation

The strongest attack against a PASS is: **can any staged content that is not the
archived closure be authorized through the new arm?**

Two candidate escapes were pushed hard and both fail as *code* defects:

1. **Worktree-ledger scope inflation.** The arm reads the record from the
   worktree, so an owner could hand-edit `.mpd/state/<change>.json` to inflate
   `system_paths` and stage arbitrary content within the inflated scope. This does
   not lower the bar below `--no-verify`: it requires the same write access that
   enables `--no-verify`, the inflated ledger fails `verify_commit_coherence`'s
   plan-binding + postimage-digest checks if committed, and an uncommitted
   worktree-only inflation makes the closure tree diverge from the retained plan —
   so the smuggled commit is *louder* (leaves the change red at
   `publish --verify`), not quieter. Consistent with the plan's cooperative-owner
   bar. Not a finding.

2. **Policy-path exemption abuse.** `.githooks/pre-commit` etc. are exempt from
   the scope check in the fallback arm. But this exemption is byte-identical to
   the two pre-existing arms (`cli.rs:5009-5012` AwaitingCommit, `4875-4878`
   ordinary), the content checks (`#!/bin/sh` prefix, known-directive, valid
   config) still run in the shared tail, and the exemption is not introduced by
   this change. No new exposure.

The attack that **did** land was not against the code but against the change's
completeness: the fallback was genuinely unforgeable *for the states the plan
enumerated*, but the plan miscounted the strays, so the same trigger the arm
serves remained constructible for `closure-defects-and-measurement` (F1). That
gap is now closed — the third stray is declared in scope and staged for deletion
alongside the other two, and the post-fix re-audit confirms no archived change's
active manifest remains in the index. With the complete stray set removed, the
refutation attempt fails on every front: the arm is not a bypass, and no state
outside a change's own genuine post-archive window can produce its trigger.

## Verdict

PASS

The archived-closure fallback arm is a safe authorization path, not a bypass. Its
trigger is structurally unforgeable outside the single state it exists to serve —
post-landing the manifest `D` cannot be staged, in-progress the record is absent
and the deletion is independently blocked as a protected artifact. Every partial
match fails closed with a specific reason; scope is the same record+plan pair the
verifier holds the commit to (gate/verifier self-consistency); the ordinary
branch's coherence guarantee is preserved byte-for-byte via the shared
`ordinary_else_governance`; authority reads reuse only the existing hardened
loaders; record/plan-derived error text is `terminal_safe` and length-bounded;
and forgery is not made easier than `--no-verify` already makes it. All 18 unit +
e2e cases run green through the real installed hook.

The one material finding of the first pass — F1, a third archived-change stray
(`closure-defects-and-measurement/manifest.json`) left in HEAD with live trigger
material, which falsified Condition 13's closing evidence — was fixed within this
change and independently re-verified: the complete set of archived-change stray
active-manifests is staged for deletion, `git ls-files` excluding `archive/`
lists no non-archive change manifest, the sole in-flight change carries no
archive record, and the fallback code is byte-identical to the audited version.
With that, all fourteen conditions (Design 1-9, Security-plan 10-14) hold, the
§1 footprint-replay window is closed for the complete stray set, and the
recurrence rule (never re-create an archived change's active manifest) is pinned
in the spec delta and guidance text. Code may proceed to Test.
