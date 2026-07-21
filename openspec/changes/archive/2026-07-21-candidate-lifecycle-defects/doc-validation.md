# Doc validation

## Actor

Architect+Designer

## Architect lens

Validated `documentation.md` against the tree-built `./target/debug/mpd` (built
2026-07-20) and `git diff HEAD -- crates/mpd/` (5 files, +2988/−252). Every
cited symbol and behavior was located and checked in the shipped code.

**D1 (candidate.rs) — accurate.** `candidate_id` (candidate.rs:2657) digests
exactly `(CANDIDATE_SCHEMA, base_tree, manifest_digest, entries_digest,
policy_digest, source_digest)` as documented. `CandidateProjectionRecordV1`
(candidate.rs:162) carries the documented attempt-variant state (`base_commit`
via `CandidateSubject` at candidate.rs:102, counts, `excluded_dirty_digest`,
`declared_status_digest`, `root_device`/`root_inode`), and the
`CandidateRecordIdentity` slice (candidate.rs:186) is the identity class.
`capture_candidate_with_hook`'s eviction arm (candidate.rs:683–708) enforces
the three documented preconditions: identity match (mismatch fails closed with
the unchanged string `existing candidate projection record does not match its
ID`, candidate.rs:695), same owning change (`change` is an identity field, so a
foreign record fails precondition 1's comparison, exactly as the doc states),
and no live binding via `candidate_id_has_live_gate_binding`
(candidate.rs:1672), which scans only `ledger.gates.values()` — the
authoritative map, as documented. `refresh_candidate_record`
(candidate.rs:1576) writes the fresh `expected_record` (built entirely from the
fresh capture at candidate.rs:651–665) with the documented durability
discipline: 0o600 `create_new` + `O_NOFOLLOW` temp, `sync_all`, atomic rename,
`sync_directory`, and a post-replace verification read comparing against
`expected`. The orphan arm (candidate.rs:738–780) applies the same identity +
live-binding preconditions before deleting and falling through.
`reopen_candidate` (candidate.rs:361) is untouched by the diff (all diff hunks
naming it are new tests) and retains exact-binding strictness.

**D2 (local_validation.rs) — accurate.** `candidate_output_ledger_bound`
(local_validation.rs:1378) iterates only `ledger.gates.values()`; records
without `build_output` are skipped (never a binding, never an error), a
matching `BuildOutputV1` at the same path yields `bound` and the caller refuses
re-export with the unchanged message `candidate Build output is already bound
by a durable ledger event` (local_validation.rs:1555), and a different path
fails closed (`candidate ledger binding points at a different output path`,
local_validation.rs:1412). The per-candidate output lock is acquired at
local_validation.rs:1545, before the ledger check at :1554, as documented. The
Build-only typed-output pin is a real regression assertion
(local_validation.rs:10848–10852, "only the configured Build profile may ever
attach a typed build_output"), plus
`rewound_history_only_build_output_does_not_poison_re_export`
(local_validation.rs:10181) driving real saved/loaded ledgers.

**D3 (closure.rs / cli.rs) — accurate.** `resolve_closure_landing`
(closure.rs:3289) scans oldest-first for the first single-parent commit
(merges/roots skipped via `git::single_parent`) whose parent diff — including
`orig_path` rename origins (closure.rs:3307–3312) — stays inside
`closure.allowed_paths`, then requires scoped content equivalence against the
retained plan. The vacuous-scope guard (Condition 17) at closure.rs:3117–3137
fails closed before any commit comparison when zero plan entries match the
scope matcher, and the same `allowed` matcher drives diff-purity and both
sides of the entry filter (`scoped_commit_equivalence` doc, closure.rs:3356–
3360). `ParityObservation.ref_state` and `.landing_contained` exist as
additive `#[serde(default)]` `Option` fields (closure.rs:376, :388);
`landing_contained` is computed for legacy and modern alike (closure.rs:3599–
3603), and the state computation (closure.rs:3614–3628) makes a
Diverged/Rewritten ref win over containment, so `VERIFIED` is unreachable for
a diverged/rewritten ref. (Nuance, consistent with the doc's "never only one":
the Unstable early return at closure.rs:3586–3588 records *neither* field —
both are `None` together.) `describe_ref_level_parity` (cli.rs:5708) renders
both on one line, and `--json` prints the full `ParityObservation`
(cli.rs:5807). The exit-code policy is exactly as documented: `cmd_publish`
returns 0 only when `observation.state == ParityState::Verified`
(cli.rs:5826), else 1.

**Status/doctor claim — accurate.** Status JSON carries
`ready_to_commit`/`blockers` (cli.rs:2092, :5759); the
`archived-closure-head-coherence` doctor finding accepts landing == HEAD *or*
`git::is_ancestor(landing, HEAD) == Some(true)` (cli.rs:7524–7530), and the
parity-side coherence re-assertion is likewise ancestor-based for modern
closures (closure.rs:3565–3567).

**Incidental fix — accurate.** The diff to config.rs shows
`arbitrary_out_of_range_sensitive_index_is_rejected` widened from
`3usize..10_000` (rejection-only) to `0usize..10_000` with the boundary
derived from the actual argv length (config.rs:1412–1424), matching the doc's
description that only past-argv indices previously exercised the rejection
branch.

**Deferred items — honest.** `grep -rn "accept.divergence\|accept_divergence"
crates/mpd/ docs/` finds nothing outside this change's own openspec text: no
accept-divergence verb exists, matching the deferral. No binary-driven
landing/rewind e2e fixture exists in crates/mpd/tests/e2e.rs; the equivalent
coverage is module-level against real git repos and real ledgers as the doc
states (local_validation.rs:10181, closure.rs:5669
`landing_commit_is_found_despite_a_later_legitimate_same_file_edit`,
closure.rs:5936 `vacuous_scoped_comparison_fails_closed`, closure.rs:6615ff
contained-but-diverged).

**Binary checks.** `./target/debug/mpd publish --help` shows exactly
`--verify` and `--json`. `./target/debug/mpd publish --verify` on this repo
fails closed with `error: change has no archived closure; run mpd archive
first` (exit 2) because the active change — this one — has not been archived
yet; that is the correct fail-closed gate upstream of parity, so the full
verified-output rendering was validated against the source format strings
(cli.rs:5811–5824), which match the Usage block character-for-character.
`./target/debug/mpd status` runs clean (exit 0) and its parity section reuses
the same `describe_ref_level_parity` renderer (cli.rs:2277).

Scope section matches `manifest.json` `paths` exactly (five entries,
verbatim). Nothing overstated; no drift found.

## Designer lens

The Usage example is the real surface, not an idealization: `Remote parity:
{STATE}` uppercased (cli.rs:5811–5813), `  local:  ` with the two-space
alignment shown (cli.rs:5814), `  remote: ` with `(missing)` fallback,
`  this change's landing commit: {oid}` printed when a landing is resolved
(cli.rs:5819–5821), the combined `ref-level state: AHEAD; landing commit
contained in remote: yes` line (cli.rs:5718 — uppercase label, `yes`/`no`
containment), and the closing `No push or deploy performed.` — every line of
the documented transcript corresponds to an actual `println!`. The
contained-but-diverged example (`ref-level state: DIVERGED; landing commit
contained in remote: yes`, still non-zero exit) is precisely the behavior
pinned at closure.rs:3614–3620 and covered by the test at closure.rs:6615ff.

The doc's Usage line "on separate lines" (containment verdict vs. ref-level
state) and Functional details' "renders both on one line" (ref-state +
containment boolean) describe different pairs and are both correct for the
actual output — the `Remote parity:` verdict line and the `ref-level state:`
line are separate; ref-state and the containment boolean share the latter.

Vocabulary is the project's established language, used correctly throughout:
candidate / candidate ID, closure, landing commit ("this change's landing
commit" is the binary's own phrasing), parity and ref-level state (matching
`ParityState` labels `Ahead`/`Behind`/`Diverged`/`Rewritten`/`Unstable`/
`AncestryUnavailable`, closure.rs:314–324), freshness rewind
(`invalidate_for_freshness`), authoritative `gates` map vs. append-only
`history`, and identity vs. attempt-variant — the last matching the code's own
doc comments (candidate.rs:175–185) rather than inventing terms. Error
messages are quoted verbatim from the source. Operator-visible behavior claims
(multi-change histories verify per-change; diverged refs reported distinctly
and never `VERIFIED`; status/doctor tolerate later unrelated commits) all
trace to verified code paths cited above. No invented flags, no invented
output, no term drift.

## Verdict

PASS

Both lenses verified every load-bearing claim against the built binary and the
working-tree diff. The two observations recorded above (the Unstable path
records neither optional parity field, and `publish --verify` could only be
exercised up to its correct pre-archive fail-closed gate on this repo) are
consistent with what the documentation says and are not discrepancies. Nothing
material to fix; the doc is accurate as written.
