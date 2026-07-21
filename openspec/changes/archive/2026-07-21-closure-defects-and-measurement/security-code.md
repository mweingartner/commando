# Security (code) review

## Actor

Security

## Findings

### F1 — MEDIUM-HIGH (CONFIRMED → FIXED, re-audit verified): invalid-path binding drop enabled multi-binding secret laundering past the D1 scan

- **Original defect (first pass)**: in `map_outgoing_blob_paths`, a diff-tree
  row whose path failed UTF-8 decoding or `validate_canonical_path` was
  `continue`d — dropped per-*occurrence* — with no per-blob consequence. A blob
  with one valid (allowlisted) mapping and one invalid-path mapping was scanned
  **only** under the valid path. Verified end-to-end at the git layer: the same
  secret content committed at `fixtures/leak.txt` (matching allowlist glob
  `fixtures/**`) and `fixtures\leak2.txt` (backslash — legal via plain
  `git add` on POSIX; control characters, `.`/`..` components, or non-UTF-8
  bytes reachable via `git mktree`) dedups to ONE blob oid; diff-tree emits
  both rows; the invalid row was dropped; every finding was suppressed; the
  push **passed** and the secret reached the remote at a path no allowlist
  reviewer approved and that was never scanned. This contradicted design.md
  D1's "the blob keeps synthetic strictness" and the plan review's "closed by
  construction" claim, within the declared "hostile tree content" adversary
  (merged external branches and plumbing-created history are exactly what the
  push gate exists for — the pre-commit hook's canonical-path check at
  cli.rs:4658 cannot cover them).
- **Fix (Builder, not inline — novel-surface rule respected)**: the invalid
  path is now a **hard error for the whole mapping pass** —
  `crates/mpd/src/local_validation.rs:6713-6716`: `from_utf8` failure or
  `validate_canonical_path` failure returns
  `Err("outgoing-path-mapping-unsafe-path")` immediately. This is the stricter
  of the two remediations this review named (whole-pass fail-closed rather
  than flag-and-strict-scan).
- **Re-audit — fix verified closed**:
  - *Ordering*: `authorize_pre_push` calls `map_outgoing_blob_paths(..)?` at
    local_validation.rs:6453 **before** `scan_outgoing_objects` (:6454), which
    is the only place the allowlist is loaded — so the hard error precedes any
    suppression for EVERY blob in the outgoing set; no partial map is ever
    consumed.
  - *No remaining silent skip*: the only `continue`s left in the parse loop are
    status ∉ {A,M,C,R,T} (:6696-6699 — deletion/unmerged rows bind no new blob
    content; a D row's destination oid is the zero oid) and mode `160xxx`/
    `040xxx` (:6700-6703 — gitlink/tree rows, not blobs; a gitlink target is a
    foreign-repo commit oid, never packed blob content, and tree rows cannot
    appear without `-t`). Every row that can bind a BLOB to a path now either
    validates that path or hard-fails the pass.
  - *Regression test*:
    `outgoing_scan_fails_closed_when_any_binding_of_a_blob_has_an_invalid_path`
    builds the exact laundering shape (allowlisted + backslash binding of the
    same blob) and asserts `Err("outgoing-path-mapping-unsafe-path")` —
    executed and passing.
  - *Accepted deviation from the original design text*: design.md D1 said an
    invalid path is "NOT mapped … never an error"; the fix deliberately errors
    instead. This is strictly MORE fail-closed than designed (documented in
    the function comment, :6617-6630), at the availability cost that a repo
    with any genuinely non-canonical tracked path in the outgoing range cannot
    push until it is renamed. Correct direction; no gate is weakened.

### Notes (non-blocking; first-pass notes folded in by the Builder, re-verified)

- FOLDED: `canonical_git` failures are no longer uniformly labeled
  `outgoing-path-mapping-cap-exceeded` — real cap overflow (matched against
  `canonical_git_run`'s exact "exceeded its cap" string) keeps that label,
  everything else becomes `outgoing-path-mapping-git-failed: {error}`
  (local_validation.rs:6655-6664). Verified safe: every `canonical_git_run`
  error is a fixed static string (:110-199 — stderr content and paths are
  never embedded), so no attacker bytes reach the terminal. Cosmetic residue:
  the `!output.success` branch (:6665-6667, git nonzero exit) still says
  "cap-exceeded" — fail-closed, diagnostics-only.
- FOLDED: `rules_digest` reverted to `mpd-builtin-secret-rules-v1`
  (local_validation.rs:6524) since the detection rules in `checks/secrets.rs`
  did not change; only `scanner_digest` carries the v2 bump (:6523) for the
  changed scan semantics. Honest per Cond 10.
- FOLDED: the D5 probe's `change` hint is now length-bounded to 200 chars
  after `terminal_safe`, before Debug-escaping (ledger.rs:1693-1708
  `MAX_CHANGE_HINT_CHARS`), matching the stats discipline.

## Conditions verified

Design Conditions 1-12 and Security-plan Conditions 13-20, each checked against
the code on disk:

1. **Fail-closed unmapped scanning** — HOLDS (after the F1 fix). Unmapped
   blobs and commit/tag bodies scan under the synthetic name with no allowlist
   (local_validation.rs:6770-6777); structural parse failures, cap overflow,
   AND invalid-path rows are hard errors (:6665-6695, :6713-6716,
   :6717-6725); a finding surviving under any one mapped path blocks
   (:6754-6768, proven by
   `outgoing_scan_allowlist_requires_match_under_every_mapped_path`); an
   invalid binding of an otherwise-allowlisted blob blocks the whole push
   (proven by
   `outgoing_scan_fails_closed_when_any_binding_of_a_blob_has_an_invalid_path`).
2. **Suppression counted and reported** — HOLDS: printed whenever nonzero, even
   when the push is about to be blocked (:6781-6786).
3. **No panic paths in archive** — HOLDS: both reproduced `.expect`s are gone;
   the doc-receipt is `ok_or`-checked pre-transaction (cli.rs:6349-6353), the
   callback captures a `Result` (cli.rs:6420-6442), `require_closure_plan`
   (cli.rs:6019) unwraps it as an ordinary error. Remaining `.expect`s are
   machine invariants (digest hex round-trip, in-memory serialize), permitted
   by the design. Regression tests cover both reproduced inputs
   (closure.rs `build_candidate_closure_plan_rejects_a_durable_doc_path_outside_the_manifest`,
   `..._reports_a_retained_manifest_read_failure_without_panicking`; cli.rs:7864).
4. **Scope never narrows below plan entries** — HOLDS: `union_closure_scope`
   (cli.rs:4580) only extends; `candidate_closure_plan_recorded` → missing =
   rows-only, present-but-invalid = block (cli.rs:4631-4634); TOCTOU between
   the two resolves narrow-or-block, never wider. Loader enforces O_NOFOLLOW,
   64 MiB cap, canonical round-trip, entry validation, transaction binding
   (closure.rs:711-745); scope matching is concrete-path containment, not
   globs (closure.rs:1478).
5. **Stats strictly read-only** — HOLDS: no write/git/network call in
   stats.rs (grep-verified over non-test code); `cmd_stats` (cli.rs:5594) never
   calls `resolve_change`; reads reuse `ledger::load`'s contained no-follow
   capped read (openspec-core safe_fs.rs:25); test
   `collect_is_strictly_read_only` passes.
6. **Version guard never misreads valid ledgers** — HOLDS: probe only inside
   `map_err` on all three load paths (`load`, and `load_observed` via
   `load_observed_exact`); happy path byte-identical; "requires a newer mpd"
   only when probed `format > LEDGER_FORMAT` (ledger.rs:1677-1717); tests
   cover happy-path identity, >, <=, absent, and non-JSON cases.
7. **Actor rule preserves persona reuse** — HOLDS: `review_subject` table
   (cli.rs:4164) matches D6 exactly; matrix test
   `actor_separation_preserves_every_documented_persona_reuse_pattern` and
   exploit test `actor_separation_blocks_the_alternating_label_self_review_exploit`
   both pass; message names the rule and the actor, Debug-escaped.
8. **`--introduced-by` validates before creating anything** — HOLDS:
   validation precedes ledger creation (cli.rs:997-999 vs :1030+); e2e asserts
   no ledger/scaffold/`.mpd/current` on failure; write-once (no mutation verb
   touches it — grep-verified).
9. **gitleaks never weakens an owner's config** — HOLDS: repo-owned
   `.gitleaks.toml` → `GITLEAKS_DEFAULT_ARGS`, byte-identical to the old
   invocation (checks/mod.rs:69,88-90); ephemeral config extends defaults and
   excludes only `target/` paths; any temp failure → unexcluded scan.
10. **Scanner digests honest** — HOLDS, now more precisely than at first pass:
    `scanner_digest` carries the v2 bump for the changed scan semantics while
    `rules_digest` honestly stays v1 (unchanged rules)
    (local_validation.rs:6518-6524); both sit inside `push_authorization_id`'s
    digest; the audit record is observation-only and "never accepted by the
    pre-push authorization path", so no stored pre-bump receipt can authorize
    anything.
11. **Ledger compatibility** — HOLDS: `format` defaulted to 1 for legacy
    bytes, `introduced_by` absent-serializing; legacy-shape test passes; save
    stamps the current format deliberately (ledger.rs:1880-1890, tested).
12. **Match existing patterns** — HOLDS: logic in `stats.rs`/existing modules,
    `cli.rs` gains wiring; bounded/no-follow reads reuse existing loaders.
13. **Error check precedes every durable effect** — HOLDS:
    `require_closure_plan(...)?` at cli.rs:6464 precedes
    `save_candidate_closure_plan` (:6467) and `openspec_core::prepare`
    (:6470); `openspec_core::build_plan` verified write-free (transaction.rs
    :657+, metadata lookups only).
14. **Ephemeral config exclusive-create** — HOLDS: `create_new` + 0600 +
    `O_NOFOLLOW|O_CLOEXEC`, pid + 16-byte `/dev/urandom` nonce name; ANY
    failure → `None` → unexcluded scan (checks/mod.rs:117-140).
15. **Probe output typed and sanitized** — HOLDS: `as_u64` +
    `u32::try_from` only (ledger.rs:1683-1686), non-u32 degrades to the
    original-error path (tested for string/float/negative/bool/null); `change`
    hint passes `terminal_safe` and is Debug-escaped (see length note above).
16. **Stats arithmetic never panics/wraps** — HOLDS: `duration_secs` is
    `saturating_sub`; all folds are `saturating_add` (stats.rs:159, 237, 240,
    343-372).
17. **Stats renders disk strings as data** — HOLDS: `safe_string` =
    `terminal_safe` + 200-char bound (stats.rs:41-52); identity =
    `validate_change_name`-checked stem cross-checked against the `change`
    field, mismatch → `change-identity-mismatch` row; error classes are a
    closed vocabulary; per-file processing; symlinks reported, never followed
    (test passes); `--json` relies on serde escaping.
18. **Archive-dir resolution exact** — HOLDS: `strip_suffix("-<name>")` +
    exactly-10-char digit/dash date check, non-recursive listing
    (cli.rs:923-963); prefix/suffix/substring near-misses rejected (tested).
19. **`introduced_by` stays out of gate logic** — HOLDS: exhaustive grep shows
    reads only in stats collection/rendering and `mpd status` display
    (cli.rs:2069, 2098, 2133); no readiness/gate/scope/verification read.
20. **D1 tag-on-blob and merge edge tests** — HOLD:
    `outgoing_scan_annotated_tag_on_blob_stays_unmapped_and_never_allowlisted`
    (blocks despite a `**` allowlist) and
    `outgoing_scan_maps_paths_introduced_by_a_merge_side_branch` both present
    and passing.

## Independent review

A second pass deliberately not trusting the first: instead of re-reading the
Rust, the git substrate and the mechanical properties were probed directly.
(1) A scratch repository verified the exact `-z --raw --no-commit-id` byte
format for a merge with `-m` (no commit-id lines pollute the stream; per-parent
diffs concatenate as header/path NUL pairs) and for a root commit — so the
`chunks_exact(2)` parse is structurally sound, and any R/C three-field row
(impossible under `--no-renames`) misaligns into a hard parse error, fail
closed. (2) The same scratch repo confirmed git dedups identical content to one
blob oid across a valid and a backslash path and that diff-tree emits both
rows — the empirical premise of F1. (3) Mechanical grep lanes over the diff:
no `Command::new`/write/rename/network in `stats.rs` non-test code; only
machine-invariant `.expect`s remain in the archive callback; `introduced_by`
reads confined to display paths. (4) `scan_text` was checked to be
content-only (its path argument is a label, so mapped-path scanning cannot
change detection), and `Allowlist::load` fails closed to an empty allowlist on
malformed input. (5) The full unit suite was executed: 399 passed, 0 failed
(includes all new D1/D2/D3/D5/D6/D7/D8 tests), plus the new D8 e2e test
(`introduced_by_validates_before_creating_anything_and_surfaces_downstream`,
passed). The deterministic scanner lanes (gitleaks/semgrep/cargo-audit) run
sandboxed at the gate itself.

**Re-audit after the F1 fix** (novel-surface rule: Security re-ran on the
fixed diff, first pass untrusted): the changed region of
`local_validation.rs` was re-diffed and re-read in full; the diff stat
confirmed only `local_validation.rs` and `ledger.rs` moved since the first
audit (the other five files byte-identical to the reviewed state). The parse
loop was re-swept specifically for any remaining silent-skip route for an
invalid binding (none — see F1 re-audit), the `authorize_pre_push` ordering
was re-confirmed (mapping hard-fails at :6453 before the allowlist is ever
loaded at :6454→`scan_outgoing_objects`), the `canonical_git_run` error
strings were re-read end-to-end to confirm the new `git-failed: {error}`
label can only embed fixed static text, and the full unit suite was
re-executed by this reviewer: 400 passed / 0 failed / 1 ignored, including
the new `outgoing_scan_fails_closed_when_any_binding_of_a_blob_has_an_invalid_path`
regression.

## Refutation

The deliberate attempt to refute a PASS produced F1. The strongest attacks
tried, in order: (a) multi-binding laundering with two *valid* paths — closed
(per-path scan, suppression requires an allowlist match under every mapped
path; test-proven); (b) enumeration completeness — every outgoing blob is
either introduced by some outgoing commit's diff against at least one parent
(`-m` covers each merge parent, `--root` covers roots) or is reachable only
via a tag-on-blob/tag-on-tree and stays strictly synthetic — no laundering
route found; (c) crafted-path parse confusion — non-UTF-8, quoted, colon- or
space-bearing paths cannot break the NUL-delimited field structure, and
crafted modes (gitlink-on-blob) at worst exclude an object git would not pack
anyway; (d) invalid-path bindings — REFUTATION SUCCEEDED ON THE FIRST PASS: the
per-occurrence `continue` left a dually-bound blob scanned only under its
allowlisted name (F1 above). Re-attacking the FIXED code: the same laundering
shape now dies inside `map_outgoing_blob_paths` itself with
`outgoing-path-mapping-unsafe-path` before the allowlist is loaded; ordering
variants (invalid binding in an earlier commit, a later commit, the same
commit, or a merge parent's diff) all traverse the same parse loop and hit the
same hard error; hiding the invalid row behind a skipped status or mode is
impossible for blob content (D rows carry the zero oid, gitlink/tree rows
carry no packable blob); and starving the pass so the invalid row is never
parsed requires exceeding a byte/pair cap, which is itself a hard block. No
route back to suppression was found. Attacks against the other decisions
failed: the alternating two-label
exploit is blocked and two labels provably cannot reach Test (subject=Build
vs adjacency exhausts both); a forged closure plan must sit at the pending
transaction's digest-named path, survive O_NOFOLLOW/canonical/binding
validation, and can still only widen toward a tree the downstream coherence
and parity checks re-verify; a hostile ledger cannot steer the D5 probe into
a version claim with a non-u32 `format` nor inject terminal sequences through
the Debug-escaped, `terminal_safe`d hint; a pre-placed or symlinked gitleaks
temp path loses to `create_new` + O_NOFOLLOW and degrades to the louder scan.

## Verdict

PASS

The first pass FAILED on one CONFIRMED finding (F1): `map_outgoing_blob_paths`
dropped invalid-path bindings per-occurrence, letting a secret blob bound at
both an allowlisted path and a non-canonical path be suppressed under the
allowlisted name and reach the remote unscanned. Per the novel-threat-surface
rule the fix was made by the Builder (not inline) and Security (code) re-ran
on the fixed diff. The fix is verified closed: an invalid-path row now
hard-fails the entire mapping pass (`outgoing-path-mapping-unsafe-path`,
local_validation.rs:6713-6716) before `scan_outgoing_objects` — and therefore
before any allowlist suppression — is ever reached (:6453-6454); the parse
loop retains no silent-skip route for a blob-binding row; the exact laundering
shape is pinned by the new regression test
`outgoing_scan_fails_closed_when_any_binding_of_a_blob_has_an_invalid_path`.
The three non-blocking first-pass notes were folded in and re-verified
(honest cap-vs-git-failure labeling with only static strings echoed;
`rules_digest` honestly back at v1 with `scanner_digest` alone at v2; the D5
change hint length-bounded). All 20 Conditions for Builder now hold with the
cited evidence; the full unit suite (400 passed, 1 ignored) and e2e pass; the
one residual is cosmetic and fail-closed (a git nonzero exit in the mapping
pass is still labeled "cap-exceeded"). The deliberate deviation from the
original D1 text — hard-error instead of unmapped-but-strict for invalid
paths — is strictly more fail-closed than designed and is accepted. No gate
is weakened; this change may proceed to Test.
