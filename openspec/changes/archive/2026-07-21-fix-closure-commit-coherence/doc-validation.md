# Doc validation

## Actor

Architect+Designer

## Architect lens

Validated `documentation.md` claim-by-claim against the working tree (`git diff
HEAD -- crates/mpd/` shows exactly `cli.rs`, `closure.rs`, `e2e.rs` plus the three
staged manifest deletions — nothing outside this change's declared paths) and the
tree-built `./target/debug/mpd` (binary mtime is newer than both touched sources).

**Cited symbols and lines — all `cli.rs` citations exact.**
- `stages_removal_of` — `cli.rs:4677`. Matches the doc: `D` at `entry.path == path`
  or `R` with `orig_path == path`, exact equality only, `C` never triggers
  (cli.rs:4678-4682).
- `bounded_record_hint` — `cli.rs:4737`. Applies `harness::terminal_safe` plus a
  200-char cap (cli.rs:4738-4744). Both record-derived strings that reach error
  text go through it: `candidate_id` (cli.rs:4782) and `archive_path`
  (cli.rs:4796). The owner-writable-ledger threat framing matches the code's own
  comment (cli.rs:4731-4736).
- `archived_closure_fallback_scope` — `cli.rs:4761`.
- `ordinary_else_governance` — `cli.rs:4819`, and the quoted hard-error string
  "active manifest is absent or unreadable in the index" is verbatim at
  cli.rs:4851.
- `staged_precommit_governance` — `cli.rs:4905`; `cmd_closure_abandon` —
  `cli.rs:6350`, and its success output does reiterate the ordering ("If the
  closure commit has not been made yet... run `mpd use <change>` then
  `git commit` (do not re-create the active manifest)").

**Six-conjunct fail-closed trigger — verified conjunct-for-conjunct.**
(1) No pending closure: the fallback arm is the `else if` reached only when
`pending_scope` is `None` (cli.rs:5022). (2) `resolve_change` names the resolved
change; post-abandon `.mpd/current` is cleared, so this requires `mpd use`
(cli.rs:4944-4973; `mpd use --help` says exactly that). (3) `ledger::load`
success with `archive_closure = Some(record)` (cli.rs:5028-5030). (4) Staged
D/R-orig of the change's OWN manifest via `stages_removal_of` (cli.rs:5022).
(5) Empty `system_paths` fails closed (cli.rs:4765-4773). (6) Plan binding
mirrors `verify_commit_coherence` field-for-field — `candidate_id`,
`candidate_base_commit`↔`record.base_commit`, `archive_path`,
`archive_transaction_id` (cli.rs:4788-4791 vs closure.rs:3290-3293); legacy
`candidate_id: None` keeps `system_paths`-only scope (cli.rs:4804).

**Sole authority, coverage, and fail-closed routing — accurate.** Scope is
`union_closure_scope(record.system_paths, plan)` and nothing else (cli.rs:4808);
the staged-path coverage check still runs over every orig/dest path with
`covers_concrete_paths` and exactly the four policy exemptions
(cli.rs:5036-5050, identical to the ordinary path at cli.rs:4872-4875 and the
AwaitingCommit branch at cli.rs:5009-5012). A `None` record routes to the shared
`ordinary_else_governance` (call sites cli.rs:5057 and 5081 — one function, so
"cannot drift" is literally true); an unreadable ledger is a distinct block that
never falls through to an index read (cli.rs:5071-5078). Protected-artifact
D/R/C blocking and the `staged_blob` manifest/ledger reads live only inside
`ordinary_else_governance`, so they are skipped in the fallback arm exactly as
in the AwaitingCommit branch (`staged_ledger` is `None` in both).

**Stray manifests — confirmed real.** `git ls-tree -r HEAD` shows all three
(`candidate-lifecycle-defects`, `closure-defects-and-measurement`,
`proportionate-governance`) still in HEAD; all three are archived
(`openspec/changes/archive/2026-07-21-*`); all three deletions are staged (`D` in
`git status --porcelain`); `git ls-files 'openspec/changes/*/manifest.json'`
excluding `archive/` returns zero entries — no stray survives in the index. The
security-review provenance is accurate: `security-code.md` F1 names
`closure-defects-and-measurement` as the third stray, folded into this change.

**Unforgeability claim — holds.** `git diff --cached` produces a `D` (or an
`R`-origin) only for a path present in HEAD; post-landing the archived change's
manifest is absent from HEAD, so the trigger signature cannot be staged. An
in-progress change fails conjunct 3 and its own manifest deletion is blocked as
a protected artifact by the ordinary path (cli.rs:4834-4840). Both halves are
pinned by e2e regressions
(`post_landing_fallback_trigger_cannot_be_reforged_for_archived_scope_smuggling`,
e2e.rs:4232; foreign-stray and ordinary-path regressions at e2e.rs:4108, 4339).

Non-goals restated in Scope are accurate: `verify_commit_coherence` and
`abandon_apply` are untouched (the only `closure.rs` diff is the
`closure_tree_digest` visibility widening + comment; `openspec-core` has no
working-tree diff), and no new flags or refusals exist on `mpd archive
--abandon`.

**One non-material erratum.** The two `closure.rs` line citations are 6 lines
stale against the shipped tree: `verify_commit_coherence` now begins at
closure.rs:3249 (its doc comment at 3243, where the doc points) and the binding
check is at closure.rs:3290-3294, not 3284-3288. The drift is caused by this
change's own 6-line comment insertion above (the `closure_tree_digest`
visibility note), and cli.rs:4786's code comment carries the same stale range.
Both citations still land inside `verify_commit_coherence`'s own text, the
mirrored field list is verified exactly correct, and no operator is misled about
safety or sequence — noted for a future touch-up (cite 3249 and 3290-3294), not
blocking.

## Designer lens

**Usage sequences match the real built surfaces.** Verified against
`./target/debug/mpd`: `mpd archive --yes` ("Apply the archive"), `--abandon`
("Abandon owned closure transaction metadata after AwaitingCommit"), and
`--json` all exist on `mpd archive`; `mpd use <CHANGE>` exists and its own help
text names this exact recovery ("recovers a cleared pointer (e.g. after `mpd
archive --abandon`...)"); `mpd publish --verify` exists as claimed. The
canonical sequence (archive --yes → git commit → archive --abandon --yes) is the
order the built tool itself teaches: `cmd_closure_abandon`'s D7 output frames
abandon as post-commit housekeeping, and the post-abandon recovery sequence
(`mpd use <change>` → `git commit`) is verbatim what both the abandon success
message and `closure_recovery_hint` (cli.rs:4721-4729) tell the operator. The
doc, the hook's error text, and the command output speak with one voice — no
sequence in the doc contradicts a surface in the binary.

**The "never restore a stray manifest" warning is accurate and actionable.** It
states the concrete hazard correctly — a committed stray re-arms the frozen
archive record as fallback-trigger material for content the frozen footprint
covers, which is exactly the replay the e2e attack test exercises — and gives
the right alternative (the fallback tolerates the manifest's absence; use
`mpd use` + `git commit`). It matches, rather than merely paraphrases, the
tool's own "do not re-create the active manifest" guidance.

**Vocabulary is the established language, no invented terms.** "Closure",
"archive record", "closure plan", "landing commit", "fallback", "trigger",
"AwaitingCommit", and "frozen footprint" all appear with the same meaning in the
change's spec delta (`specs/change-manifest/spec.md`), design.md, and the code's
own comments. "Clone-private" for the archive record follows proposal.md:20 and
design.md:118 and the project's broader clone-private idiom (the authority is
read from the local worktree ledger, never from HEAD or the index, at
authorization time). Error strings quoted in the doc are byte-identical to the
shipped ones. Nothing in the doc names a flag, command, or message that the
built binary does not present.

## Verdict

PASS

Both lenses verified every load-bearing claim against the working tree and the
tree-built binary. The single erratum (two closure.rs line citations 6 lines
stale, self-inflicted by this change's own comment insertion) is non-material:
it cannot mislead an operator about the fallback's safety, the trigger's shape,
or the commit sequence. No discrepancy touches the doc's operator-facing
guidance.
