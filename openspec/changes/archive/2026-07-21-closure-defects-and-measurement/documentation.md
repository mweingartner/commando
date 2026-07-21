# Closure Defects and Measurement

## Purpose

The pipeline's first two self-hosted closures (`harness-aware-agent-docs`,
`local-first-verification-hardening`; commits `bd7f92c` and `6dbd6ec`) ran the full
strict pipeline end-to-end for the first time and surfaced seven reproducible defects —
one of which, pre-push allowlist blindness, currently blocks every push from a repo
carrying allowlisted redaction fixtures. This change fixes all seven and adds `mpd`'s
first outcome-measurement surface, so future closures produce comparable evidence about
their own cost and failure profile instead of none at all.

## Value

The pipeline can now push at all (D1/D3 unblock the remote and the closure commit), it
fails safe instead of panicking (D2, D5), its actor-separation gate resists a concrete
alternating-label exploit (D6), and — for the first time — it can measure its own
process: `mpd stats` gives attempts, wall-clock, reconciliations, rewinds, and failure
classes per phase and per change, and `--introduced-by` links a defect fix back to the
change that let the defect escape. This closure is also the pipeline's own proof of
concept for its adversarial rigor: Security (code)'s first-pass audit of the D1 scanning
surface found F1, a CONFIRMED multi-binding secret-laundering hole, and the
novel-threat-surface re-run verified the fix — direct evidence the pipeline catches what
a single pass would have shipped.

## Scope

The manifest (`openspec/changes/closure-defects-and-measurement/manifest.json`) declares:
`.claude/pipeline-gates.json`, this change's own ledger and OpenSpec directory,
`crates/mpd/**`, `docs/closure-defects-and-measurement.md`, the two prior closures'
OpenSpec directories, and `openspec/specs/**`. That last group is deliberate: this
closure's own commit also carries the tree hygiene left behind by the two prior landed
closures — five pending spec merges (`directives`, `evidence-reuse`, `gate-evidence`,
`process-governance`, `remote-parity`), two new spec directories
(`openspec/specs/local-validation/`, `openspec/specs/agent-onboarding/`), removal of two
stray active-manifest copies
(`openspec/changes/{local-first-verification-hardening,harness-aware-agent-docs}/manifest.json`,
retained only as pre-commit coherence reads for those two already-landed closures), and
the `.claude/pipeline-gates.json` `secretAllow` addition. `openspec-core` is intentionally
not declared — no planned work touches it.

Two defects were surfaced and worked around during this change's own closure but are
**documented here, not fixed**, and are explicitly out of scope: a candidate-ID
base-collision that stalls on a stale cache, and a re-export-after-rewind binding
conflict. Both are deferred to follow-up changes. Also out of scope: any broader
proportionality overhaul of the pipeline's gate rigor.

## Functional details

**D1 — path-mapped outgoing secret scanning (pre-push).** `enumerate_update_objects` in
`crates/mpd/src/local_validation.rs` keeps its existing capped
`rev-list --objects --no-object-names` enumeration as the authoritative object set. A new
`map_outgoing_blob_paths` pass runs one capped
`git diff-tree -r -m --no-renames --root --no-commit-id --raw -z --end-of-options <commit>`
per outgoing commit and builds `oid -> BTreeSet<repo-relative path>` for every
blob-adding/modifying row,
covering merges (`-m`) and root commits (`--root`). `scan_outgoing_objects` then scans a
mapped blob once per distinct path through `secrets::scan_text`, filtering findings
through `Allowlist::load(root)`; suppression requires an allowlist match under **every**
mapped path — a finding surviving under any one path still blocks the push. A blob with
no mapped path (unreachable via any outgoing commit diff, e.g. an annotated tag directly
on a blob) keeps the exact prior behavior: scanned as `git-object:<oid>` with no
allowlist applied. Commit/tag messages are never allowlisted. The push
authorization's `scanner_digest` bumped to `mpd-builtin-outgoing-secret-scan-v2`
(`rules_digest` stays `mpd-builtin-secret-rules-v1` — the detection rules themselves
didn't change).

**The fail-closed invariant, and the F1 fix.** Security (code)'s first-pass audit found
F1 (MEDIUM-HIGH, CONFIRMED): a diff-tree row whose path failed UTF-8 decoding or
`validate_canonical_path` was silently `continue`d per-occurrence, so a blob bound at
both an allowlisted path and an invalid (e.g. backslash-containing) path was scanned
**only** under the allowlisted name — the invalid binding vanished instead of forcing
strict scanning, letting the same secret content reach the remote unscanned at the
invalid path. Per the novel-threat-surface rule the fix was made by the Builder (not
inline) and Security re-ran on the fixed diff. The fix, verified in the re-audit: an
invalid path is now a hard error for the **whole** mapping pass
(`local_validation.rs:6713-6716`, `outgoing-path-mapping-unsafe-path`), raised before
`scan_outgoing_objects` — and therefore before any allowlist suppression — is ever
reached. This is stricter than the original design text (which said an invalid path
should stay unmapped-but-scanned); the deviation is documented in the function comment
and accepted as strictly more fail-closed. The regression test
`outgoing_scan_fails_closed_when_any_binding_of_a_blob_has_an_invalid_path`
pins the exact laundering shape.

**D2 — archive errors instead of panics.** `cmd_archive`'s `build_plan` transaction
callback no longer `.expect()`s `build_candidate_closure_plan`'s result or the
documentation-postimage contract check. Both are captured through
`closure_plan_out: RefCell<Option<Result<CandidateClosurePlan, String>>>` and unwrapped
by a `require_closure_plan` checkpoint that runs before `closure::save_candidate_closure_plan`
and before `openspec_core::prepare` — so a validation failure (e.g. a durable-doc path
outside the manifest, or an unreadable retained manifest) surfaces as an ordinary
nonzero-exit error with no pending transaction and no modified repository bytes, instead
of a panic.

**D3 — closure-commit scope union.** `staged_precommit_governance`'s AwaitingCommit scope
is now the union of the transaction's classification rows and the retained closure
plan's expected entry paths (`union_closure_scope`): existence is checked via
`closure::candidate_closure_plan_recorded`, and a recorded plan is then loaded and
validated via `closure::load_candidate_closure_plan`. A missing plan (legacy closure) keeps the
rows-only scope unchanged; a plan that is present but invalid, non-canonical, oversized,
or bound to a different transaction blocks the commit rather than silently narrowing to
rows-only. This makes a first-ever closure commit (source tree never previously
committed) possible, since every staged source path is then an expected plan entry — the
union never narrows, and out-of-tree paths still block via the unchanged commit-coherence
check.

**D4 — gitleaks worktree scope.** `checks::run_external_scanners` invokes gitleaks
unmodified when the repo root has its own `.gitleaks.toml`. Otherwise it writes an
ephemeral, exclusive-create (`create_new`, 0600, pid+nonce-named) config extending
default rules and excluding only `target/`-rooted paths, passed via `-c`; any failure to
create or write that file falls back to the unexcluded (louder, never quieter) scan.
Semgrep and the built-in git-tracked-file scanner are untouched.

**D5 — ledger version-skew guardrail.** `Ledger` gains `format: u32`
(`#[serde(default = "ledger_format_v1")]`, defaulting pre-existing ledgers to `1`); `save`
always stamps the current `LEDGER_FORMAT = 2`. When full deserialization fails in
`load`/`load_observed`/`load_observed_exact`, a bounded probe re-parses the same
already-capped bytes as `serde_json::Value` and reads `format` as an unsigned integer
only (a string/float/negative/absent value degrades to "absent," never a panic or a false
claim). If the probed format exceeds `LEDGER_FORMAT`, the error becomes `"<path>: this
ledger requires a newer mpd (ledger format <found>, this binary supports up to
<LEDGER_FORMAT>)"` (with a length-bounded, terminal-safe `change` hint when present);
otherwise the original serde error is kept, with path context. The probe runs only on the
failure path — a ledger that parses is returned byte- and field-identical to before.

**D6 — actor separation: adjacency + review-subject.** Each judgment gate keeps the
existing adjacency rule (its actor must differ from the latest upstream gate's actor) and
now also compares against a defined **review subject** — the phase whose output it
adjudicates:

| Gate phase    | Review subject |
|---------------|----------------|
| DesignReview  | Architecture   |
| SecurityPlan  | Architecture   |
| SecurityCode  | Build          |
| DesignSignoff | Build          |
| Test          | Build          |
| DocValidation | Documentation  |

DesignMock, Architecture, Build, Documentation, and Deploy have no review subject and
keep adjacency only. This closes the reproduced exploit — alternating two labels A,B,A,B
(Build=A, SecurityCode=B, DesignSignoff=A) passed adjacency at every step, but now fails
because DesignSignoff's subject is Build and A==A — while every documented persona-reuse
pattern still passes: Designer at DesignMock/DesignReview/DesignSignoff, Security at both
Security gates, and Architect at Architecture and Doc Validation.

**D7 — `mpd stats` (new, read-only).** `crates/mpd/src/stats.rs` enumerates every regular
file under `.mpd/state/*.json` (active and archived changes alike — an archived ledger
persists there with `archive_closure` set), reusing the same bounded, no-follow,
16 MiB-per-file reads `ledger::load` already provides (inheriting D5's version-probe
diagnostics for free) and adding its own cap on total ledgers processed
(`MAX_STATS_LEDGERS = 10,000`, reported as `truncated` rather than a hard error if hit).
Per change it reports: kind, archived/strict/risk/
threat-profile, `introduced_by` when present, attempts per phase (max `attempt` over
`history` records, falling back to the `gates` record for legacy ledgers), wall-clock per
phase (summed `GateRecord::duration_secs()`), reconciliations by kind, rewinds
(`legacy_repairs` + `freshness_invalidations`), a failure-class histogram, weakened-tuning
incidence, and active task deferrals. An aggregate section totals all of the above plus
defect-escape counts grouped by originating change. An unreadable or unparsable ledger is
reported as an `unreadable` row with a stable error class — never silently skipped, never
fatal to the rest of the report. All disk-derived strings are sanitized through
`terminal_safe` and length-bounded before rendering. `mpd stats` performs no file writes,
no git subprocess calls, no network access, and no `.mpd/current` resolution.

**D8 — `--introduced-by` defect-escape provenance.** `mpd conduct --fix --introduced-by
<archived-change>` (and the underlying `mpd begin --fix --introduced-by ...`) records
which archived change a defect fix was opened to address. Clap enforces
`requires = "fix"`. Before anything is created, `validate_introduced_by` runs
`openspec_core::validate_change_name` on the argument and then requires that the named
change resolve to a real archive: either its ledger (kept at `.mpd/state/<name>.json`
even post-archive) has `archive_closure` set, or a legacy dated archive directory
`openspec/changes/archive/<YYYY-MM-DD>-<name>` exists, matched by exact decomposition
(`dated_archive_matches`) — never substring or prefix matching. A failed resolution
creates no ledger, no scaffold, and no `.mpd/current` change. The field
(`Ledger.introduced_by: Option<String>`) is additive, absent-serializing, and written
once at begin; no gate, readiness, or scope decision ever reads it — it is display and
measurement data only, surfaced by `mpd status` and aggregated by `mpd stats`.

## Usage

Measure the pipeline's own outcomes, in human or machine form:

```sh
mpd stats
mpd stats --json
mpd stats --change <name>
```

The human report opens with a header line —
`mpd stats (schema 1): <n> ledger(s) scanned, <r> readable, <u> unreadable`, with a
`(TRUNCATED at the ledger cap)` suffix if the 10,000-ledger cap was hit — so a capped
report is visible as capped before anything else is read. Below that, the per-change
table shows, per change: `<name> [<kind> archived? strict?] risk=<risk>
threat=<threat-profile>`, then lines for `introduced-by`, `attempts:` (per phase),
`wall-clock:` (per phase, seconds), `reconciliations:` (by kind), and `rewinds:` when
nonzero. The report closes with an `aggregate:` totals block (total attempts, total
wall-clock, and the combined failure-class histogram across all ledgers) — check the end
of the output for that block, not just the header, to see the full-run totals. `--json`
emits `{"schema":1, "changes":[...], "aggregate":{...}}` with stable keys, sorted by
change name, and unreadable ledgers appear as `{"status":"unreadable","change":...,
"error_class":...}` rows rather than being dropped.

Record which prior closure a defect fix is closing the loop on:

```sh
mpd conduct my-defect-fix --fix --introduced-by <archived-change-name>
```

This fails before creating any ledger, scaffold, or `.mpd/current` change if the name is
invalid or its archive can't be resolved. Once recorded, the link shows up in
`mpd status` and is counted against the originating change in `mpd stats`'s
`defect_escapes_by_originating_change`.

**Operator-visible behavior changes:**

- **Push now scans outgoing objects under their real repo-relative paths, honoring the
  allowlist.** A push carrying a secret at a path the allowlist doesn't cover still
  blocks, even if the same blob also happens to sit at an allowlisted fixture path
  elsewhere in the outgoing range.
- **Archive failures are now clean, nonzero-exit errors, never panics.** A closure whose
  durable-doc path falls outside the manifest, or whose retained manifest can't be read,
  reports the specific problem and leaves the tree untouched — no pending transaction to
  clean up.
- **A too-old `mpd` reading a newer ledger gets a clear version message** —
  `"this ledger requires a newer mpd (ledger format <found>, this binary supports up to
  <supported>)"` — instead of a raw, unexplained `serde_json` parse error.
- **`mpd check`'s gitleaks pass no longer reports `target/` build-artifact noise** in
  repos that don't ship their own `.gitleaks.toml`.
- **The strict actor-separation gate now also rejects self-review by alternation:** a
  label that recorded Build can no longer sign off on Design Sign-off, Security (code),
  or Test for that same Build by alternating with one other label in between.
