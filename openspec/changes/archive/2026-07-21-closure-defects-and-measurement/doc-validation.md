# Doc validation

## Actor

Architect+Designer

## Architect lens

Every functional claim in `documentation.md` was checked against the real diff
(`git diff HEAD -- crates/mpd/` plus the new untracked `crates/mpd/src/stats.rs`)
and the tree-built `./target/debug/mpd` (binary newer than every source file;
verified with `find -newer`). Read-only commands actually run: `mpd stats`,
`mpd stats --json`, `mpd stats --change closure-defects-and-measurement`,
`mpd stats --help`, `mpd conduct --help`.

Confirmed accurate:

- **D1.** `enumerate_update_objects` keeps `rev-list --objects
  --no-object-names` (`local_validation.rs:6571-6574`); `map_outgoing_blob_paths`
  (`:6630`) runs one capped `diff-tree -r -m --no-renames --root --no-commit-id
  --raw -z --end-of-options <commit>` per outgoing commit — the doc's quoted
  command now matches the invocation at `:6641-6652` flag for flag, in order —
  and builds `oid -> BTreeSet<path>`; `scan_outgoing_objects` scans a mapped
  blob once per distinct path and suppression requires an allowlist match under
  EVERY mapped path — one surviving finding blocks (`:6753-6768`, comment says
  "never first-wins"); unmapped blobs and commit/tag messages keep the
  synthetic `git-object:<oid>` scan with no allowlist (`:6770-6777`).
  `scanner_digest` = `mpd-builtin-outgoing-secret-scan-v2` (`:6523`),
  `rules_digest` stays `mpd-builtin-secret-rules-v1` (`:6524`).
- **F1 resolution described as built.** An invalid (non-UTF-8 or non-canonical)
  diff-tree path is a hard `Err("outgoing-path-mapping-unsafe-path")` for the
  whole mapping pass (`local_validation.rs:6713-6716` — the doc's citation is
  exact), raised at the `map_outgoing_blob_paths` call (`:6453`) before
  `scan_outgoing_objects` and any allowlist consultation. The fail-closed
  deviation from the original per-blob design is documented in the F1 code
  comment (`:6707-6712`), and the regression test named in the doc exists
  verbatim: `outgoing_scan_fails_closed_when_any_binding_of_a_blob_has_an_invalid_path`
  (`:12981`). Not per-blob taint — whole-pass fail-closed, exactly as documented.
- **D2.** Both prior `.expect()`s are gone from the archive callback; the
  closure plan and the documentation-postimage contract flow through
  `closure_plan_out: RefCell<Option<Result<...>>>` (`cli.rs:6343-6345`,
  `:6420-6442`), unwrapped by `require_closure_plan` (`:6019`) at `:6464` —
  before `closure::save_candidate_closure_plan` (`:6467`) and before
  `openspec_core::prepare` (`:6470`), so an `Err` returns with nothing
  journaled. Remaining `.expect`s in the callback are internal-invariant only
  (serde/digest), matching the doc's precise claim.
- **D3.** `union_closure_scope` (`cli.rs:4580`) = rows ∪ plan entry paths;
  `None` (no recorded plan) keeps rows-only; `Some(Err)` blocks the commit
  (`:4586-4591`). The doc now correctly splits the two helpers: existence via
  `closure::candidate_closure_plan_recorded`, load/validation via
  `closure::load_candidate_closure_plan` — exactly the gated call at
  `:4632-4633`.
- **D4.** `checks/mod.rs:89` runs gitleaks unmodified when the repo owns
  `.gitleaks.toml`; otherwise an ephemeral `create_new`, 0600, pid+nonce-named
  config (`:112-132`) extends defaults excluding only `target/` paths; any
  creation failure falls back to the unexcluded scan (`:108`).
- **D5.** `LEDGER_FORMAT = 2` (`ledger.rs:28`), `#[serde(default =
  "ledger_format_v1")]` (`:730`), `save` stamps (`:1898-1902`); the probe runs
  only after full deserialization fails, reads `format` as unsigned integer
  only (`:1676-1687`), emits the exact documented "requires a newer mpd"
  message (`:1711-1716`) with a 200-char terminal-safe `change` hint. Per-file
  reads via `openspec_core::DEFAULT_MAX_BYTES` = 16 MiB (`safe_fs.rs:15`).
- **D6.** `review_subject` (`cli.rs:4164-4174`) matches the doc's table row for
  row (DesignReview/SecurityPlan→Architecture, SecurityCode/DesignSignoff/
  Test→Build, DocValidation→Documentation, `_ => None` for the five listed
  no-subject phases); adjacency retained plus the subject comparison
  (`:4220-4232`); the alternating-label exploit and legitimate persona reuse
  are as described.
- **D7.** `stats.rs`: the doc now correctly attributes the bounded/no-follow/
  16 MiB-per-file discipline to `ledger::load` and the ledger-count cap to
  stats' own `MAX_STATS_LEDGERS = 10_000` (`stats.rs:35`); a cap hit sets
  `aggregate.truncated` and the header suffix rather than erroring
  (`:282-283`, `:104`, `:396`), matching the doc's "reported as `truncated`
  rather than a hard error". Unreadable ledgers become tagged rows with a
  stable `error_class`, never fatal (tests `:788`, `:830`); disk strings pass
  `terminal_safe` + length bounds (`:39-44`); strictly read-only (no writes,
  no git, no network, no `.mpd/current`). Ran against the live tree: 13
  ledgers, exit 0, per-change attempts/wall-clock/reconciliations/rewinds/
  failure-classes/weakened-tuning/deferrals all render.
- **D8.** `requires = "fix"` on both `conduct` and `begin`
  (`cli.rs:78`, `:105`); `validate_introduced_by` (`:905`) runs
  `validate_change_name` then requires `archive_closure` on the kept ledger or
  an exact-decomposition dated archive dir (`dated_archive_matches`, `:949` —
  never substring); validation happens before any ledger/scaffold/current
  creation (`:997-998` precede creation at `:1041`); the field is additive,
  display-only, surfaced by `mpd status` (`:2098`, `:2133`) and grouped into
  `defect_escapes_by_originating_change` by stats.
- **Scope.** `manifest.json` declares exactly the eight path groups the doc
  lists; `openspec-core` is absent from it and `git status` shows
  `crates/openspec-core/` clean. The two deferred defects (candidate-ID
  base-collision, re-export-after-rewind) appear nowhere in the diff — the
  doc's "documented here, not fixed" flag is honest in both directions.
- **"Seven defects."** Consistent with the proposal and design Context: the D2
  site comprises two distinct reproduced `.expect` panics, so
  D1(1)+D2(2)+D3(1)+D4(1)+D5(1)+D6(1) = 7.

The three minor imprecisions flagged in the first pass (abbreviated diff-tree
command, `candidate_closure_plan_recorded` credited with the load, the
10,000-ledger cap attributed to `ledger::load`) are all corrected in the
revised doc and re-verified above against the cited source lines.

## Designer lens

The command surfaces were run, not assumed:

- `mpd stats --help` shows exactly `--change <CHANGE>` and `--json`; the three
  Usage invocations (`mpd stats`, `mpd stats --json`, `mpd stats --change
  <name>`) all execute with exit 0 against the live tree.
- `mpd conduct --help` shows `--fix` and `--introduced-by <INTRODUCED_BY>`
  with help text stating it requires `--fix` — the documented invocation
  `mpd conduct my-defect-fix --fix --introduced-by <archived-change-name>` is
  the real surface.
- The per-change header renders exactly as documented:
  `closure-defects-and-measurement [feature strict] risk=high
  threat=local-trusted-user`, with `[<kind> archived strict]` for archived
  changes; `attempts:`/`wall-clock:`/`reconciliations:`/`rewinds:` lines match,
  `introduced-by:` renders when present (`stats.rs:415`).
- `--json` emits `{"schema":1,"changes":[...],"aggregate":{...}}`, changes
  sorted by name (verified programmatically), unreadable rows tagged
  `"status":"unreadable"` with `error_class` (`stats.rs:58` serde tag).
- All five "Operator-visible behavior changes" bullets are accurate against the
  built code, and the established vocabulary (candidate, closure, allowlist,
  review-subject, ledger, receipt) is used with its codebase meaning — no
  invented terms.

**Prior material finding — RESOLVED.** The first validation pass found the
`mpd stats` human-report layout described inverted: the doc placed the
`mpd stats (schema 1): ...` summary line (carrying the `(TRUNCATED at the
ledger cap)` integrity marker) after the per-change table, while the built
binary prints it first and closes with an `aggregate:` totals block. The
revised Usage section now describes the real layout exactly: the report
**opens** with that header line ("so a capped report is visible as capped
before anything else is read"), the per-change table follows, and the report
**closes** with the `aggregate:` totals block (total attempts, total
wall-clock, combined failure classes) — with an explicit note to check the end
of the output for the totals. Re-verified against a fresh run of
`./target/debug/mpd stats` and against the renderer (`stats.rs:391-397` header,
trailing aggregate block): the description and the binary now agree, and the
truncation marker is documented where it actually appears.

## Verdict

PASS

All four revisions verified against the diff, the cited source lines, and
fresh runs of the tree-built binary: the human-report layout now matches
`mpd stats` output exactly (header first with the TRUNCATED marker, `aggregate:`
totals last), the D1 diff-tree command is quoted in full, D3 names the
existence probe and the loader separately and correctly, and D7 attributes the
per-file read discipline to `ledger::load` and the 10,000-ledger cap to
`MAX_STATS_LEDGERS` in `stats.rs` — including the accurate new claim that a cap
hit reports `truncated` instead of erroring. No remaining discrepancy in either
lens: all eight D-items, the F1 fail-closed resolution, the deferred-defect
flags, the scope list, and both CLI surfaces are accurate as documented.
