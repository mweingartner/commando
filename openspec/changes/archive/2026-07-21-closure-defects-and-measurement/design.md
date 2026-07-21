# Design: Closure Defects and Measurement

## Actor

Architect

## Context

Both self-hosted closures landed (bd7f92c, 6dbd6ec) and each defect below was reproduced
live during those runs. All file/line references were verified against the current tree.
This change is pure backend/tooling (no UI surface); risk is high because it touches the
pre-push secret gate, the archive transaction, and the pre-commit closure gate — the
three places where a wrong fix either leaks a secret, corrupts a closure, or bricks the
one commit a closure is allowed to make.

Current defect sites:

- `crates/mpd/src/local_validation.rs` — `enumerate_update_objects` (~6549) strips
  object names (`--no-object-names`); `scan_outgoing_objects` (~6590) scans blobs as
  `git-object:<oid>`, so `crate::allowlist::Allowlist` (path-glob based) never applies.
- `crates/mpd/src/cli.rs` `cmd_archive` — the `build_plan` transaction callback ends in
  `.expect("archive inputs were validated before the transaction callback")` (~6165)
  and `.expect("modern Candidate closure has documentation evidence")` (~6156).
- `crates/mpd/src/cli.rs` `staged_precommit_governance` (~4384-4472) — AwaitingCommit
  scope comes only from `view.classifications` rows.
- `crates/mpd/src/checks/mod.rs` `run_external_scanners` (~48) — gitleaks runs
  `detect --no-banner --no-git -s .` from repo root, sweeping `target/`.
- `crates/mpd/src/ledger.rs` `load`/`load_observed`/`load_observed_exact` (~1634-1680) —
  raw `serde_json` errors surface unexplained on version skew.
- `crates/mpd/src/cli.rs` `strict_actor_separation_issue` (~4021) — compares only the
  latest upstream gate actor (`.last()`).

## Goals / Non-Goals

Goals:

1. Every reproduced defect gets a fix with a regression test that fails on the old code.
2. `mpd stats` gives per-change and aggregate outcome measures from existing ledger
   fields only — strictly read-only.
3. `--introduced-by` records defect-escape provenance with archive-existence validation.
4. The closure commit for this change also carries the documented tree hygiene
   (pending spec merges, stray manifest removals, pipeline-gates addition) — declared in
   `manifest.json`, which this design owns.

Non-Goals:

- No new authentication claims: actor separation remains cooperative label discipline,
  not identity verification (`directives` spec, "Truthful cooperative authority").
- No retroactive help for already-shipped old binaries reading new ledgers — the
  version guard makes *future* skew diagnosable; it cannot patch binaries in the field.
- No dashboards, trend storage, or cross-repo aggregation in `mpd stats` (Phase-5
  minimal scope). No mutation of any ledger by `stats`.
- No change to gitleaks behavior in repos that ship their own gitleaks config.
- No new dependencies.

## Decisions

### D1 — Path-mapped outgoing secret scanning (pre-push)

**Enumeration.** Keep the existing capped `rev-list --objects --no-object-names`
enumeration in `enumerate_update_objects` as the authoritative *object set* (caps,
dedup, and byte accounting unchanged). Add a second, capped mapping pass that builds
`oid -> BTreeSet<repo-relative path>` for blobs: for every outgoing **commit** in the
enumerated set, run
`git diff-tree -r -m --no-renames --root --end-of-options <commit>` and collect
`(blob_oid, path)` pairs for blob-adding/modifying rows. This is deliberately per-commit
diff-based rather than trusting `rev-list`'s single first-seen name: `rev-list` names
each object once, so a secret blob present at BOTH an allowlisted fixture path and a
real source path would be scanned only under the fixture name and wrongly suppressed.
With diff-tree, every path binding introduced anywhere in the outgoing range is
observed, and a multi-path blob is scanned once per distinct path.

- `-m` covers merge commits (diff against each parent), `--root` covers root commits,
  `--no-renames` keeps rows as plain adds/modifies.
- Parse only rows whose destination status is `A`/`M`/`C`/`R`/`T` and whose object type
  is blob (skip gitlinks/mode-160000 and tree rows). Validate every parsed oid with
  `validate_oid` and every path with the existing canonical-path validation; a path that
  fails validation is NOT mapped (the blob keeps synthetic strictness) — never an error
  that could be used to skip scanning, and never a scan under a non-canonical name.
- Cap the mapping pass with the existing enumeration byte cap
  (`MAX_PUSH_ENUM_BYTES`-family) and pair-count cap (reuse `MAX_PUSH_OBJECTS` order of
  magnitude). Cap overflow is a hard error (fail closed), same as today's enumeration.

**Scanning.** In `scan_outgoing_objects`:

- A blob with one or more mapped paths is scanned once per mapped path via
  `secrets::scan_text(<repo-relative path>, ...)`, and the findings are filtered
  through `Allowlist::load(root)` / `is_allowed(rel_path, line, rule)`. Suppression
  requires the allowlist to match under EVERY path the finding appears at — a finding
  surviving under any one path fails the push. Suppressed counts are printed (allowlist
  doctrine: counted and reported, never silent).
- A blob with NO mapped path (unreachable via any outgoing commit diff, or its path
  failed validation) keeps today's exact behavior: scanned as `git-object:<oid>` with
  no allowlist applied.
- Commit and tag objects keep today's exact behavior: message scan under the synthetic
  name, never allowlisted (a secret in a commit message has no path and no fixture
  excuse).
- The scanner and rules digests recorded in `PushAuthorizationV1` gain a version bump
  (`mpd-builtin-outgoing-secret-scan-v2`) since the effective scan semantics changed.

Rejected alternative: scanning `rev-list`'s own name annotations (drop
`--no-object-names`) — one name per object reintroduces the multi-path suppression hole
described above. Rejected alternative: full `ls-tree -r` of every outgoing commit —
strictly more work than diff-tree for no additional blob coverage within the range.

### D2 — Archive validation errors, not panics

Make the `build_plan` closure-plan callback in `cmd_archive` infallible-by-construction
plus captured-error, never panicking:

- Change `closure_plan_out` to
  `RefCell<Option<Result<closure::CandidateClosurePlan, String>>>`. Inside the callback,
  store the `Result` of `build_candidate_closure_plan` instead of `.expect`ing it. The
  callback still returns the `TargetWrite` it must produce (the ledger bytes are
  independent of the closure plan's validity).
- Replace `.expect("modern Candidate closure has documentation evidence")` with a
  captured error through the same channel (construct the error before calling
  `build_candidate_closure_plan` when `documentation_postimages` is `None` while
  `candidate_context` is `Some` — an internal contract violation reported as a normal
  fail-closed error).
- Immediately after `build_plan` returns and BEFORE `openspec_core::prepare`, unwrap the
  captured result: on `Err`, print the error and return failure. At that point nothing
  has been journaled or staged — the transaction was never started, so the tree is
  untouched (fail-closed, no cleanup needed). Builder must verify `build_plan` itself
  performs no filesystem writes (its name and current usage indicate pure plan
  construction; if that assumption is wrong, the error check must move before the first
  write instead).
- The two reproduced panic inputs (durable-doc path outside manifest; retained-manifest
  read failure) become regression tests asserting a nonzero exit, a diagnostic
  mentioning the failing path/read, and no pending transaction afterwards.

The pre-existing `expect`s on digest hex round-trips stay: those are genuine
machine-invariants (a digest we just serialized always parses), not input validation.

### D3 — Closure-commit scope = transaction rows ∪ closure-plan entries

In `staged_precommit_governance`, when the pending transaction is `AwaitingCommit`:

- Keep building the classification-row scope exactly as today.
- Additionally attempt `closure::load_candidate_closure_plan(root,
  &view.transaction_id.to_hex())`:
  - Plan loads and validates → union `plan.entries[].path` (repo-relative expected
    post-archive tree paths) into the scope before sort/dedup.
  - Plan is *missing* (`"Candidate closure plan is missing"`) → legacy/non-candidate
    closure; keep today's rows-only behavior unchanged.
  - Plan is present but malformed, non-canonical, oversized, or bound to a different
    transaction → BLOCK the commit with the loader's error. A present-but-invalid plan
    is evidence of tampering or corruption, and falling back to rows-only would silently
    narrow authority in exactly the case where suspicion is warranted.
- The loader already enforces no-follow open, 64 MiB cap, canonical round-trip, and
  transaction-id binding; pre-commit adds no weaker parallel read path.

This makes the first-ever closure commit (source tree never previously committed)
possible: every staged source path is an expected closure-plan entry. It never *narrows*
scope — union only — and out-of-tree paths remain blocked because the base-to-HEAD
commit-coherence check (`change-manifest` spec) is unchanged.

### D4 — gitleaks worktree scope

In `checks::run_external_scanners`:

- If the repo root contains its own gitleaks config (`.gitleaks.toml`), invoke gitleaks
  exactly as today — the repo owner's config wins, unmodified (gitleaks resolves
  `(target)/.gitleaks.toml` natively).
- Otherwise, write an ephemeral config into the session temp area (`std::env::temp_dir`
  scoped file with a pid/nonce name, best-effort removed afterwards) containing:

  ```toml
  [extend]
  useDefault = true

  [allowlist]
  paths = ['''^target/''', '''/target/''']
  ```

  and pass it via `-c`. This is the minimal exclusion: default rules stay intact; only
  the Rust build-artifact directory is skipped. If the temp write fails, run gitleaks
  WITHOUT the config (louder, never quieter — degraded exclusion must not become a
  skipped scan).
- Semgrep invocation is untouched (its findings were not part of the reproduced noise).
- The built-in scanner path (`scan_secrets`) is untouched — it already scans only
  git-tracked files.

Rejected alternative: a committed `.gitleaks.toml` in this repo only — fixes Commando
but not every repo mpd governs; the tool-level exclusion fixes the class.

### D5 — Ledger version-skew guardrail

- Add `pub const LEDGER_FORMAT: u32 = 2;` and a `Ledger` field
  `#[serde(default = "ledger_format_v1")] pub format: u32` (default fn returns 1 so
  every pre-existing ledger decodes as format 1). `save` always writes the current
  constant. `Ledger` does not use `deny_unknown_fields`, so already-shipped binaries
  ignore the new field.
- In `load`, `load_observed`, and `load_observed_exact`: when full deserialization
  fails, probe-parse the same bytes as `serde_json::Value` and read the top-level
  `format` (and `change`) fields:
  - Probe shows `format > LEDGER_FORMAT` → error
    `"this ledger requires a newer mpd (ledger format {found}, this binary supports up
    to {LEDGER_FORMAT})"`.
  - Probe parses but `format <= LEDGER_FORMAT` (or absent) → the original serde error,
    prefixed with the ledger path and a one-line hint that the ledger may have been
    written by a newer or different mpd. Honest: we cannot distinguish corruption from
    forward-skew for pre-format ledgers.
  - Probe itself fails (not JSON) → original serde error unchanged.
- The probe runs ONLY on the failure path: a ledger that deserializes successfully is
  returned identically to today, byte-for-byte and field-for-field (invariant tested).
- Bump `LEDGER_FORMAT` in future changes whenever a new enum variant or
  semantics-bearing field would make older readers fail — starting with this change
  (the `design-mock-artifact` receipt-kind era is retroactively "format 2" from now on).

This is forward-looking by necessity: the binaries that produced the reproduced raw
serde error are already shipped and cannot be taught the friendly message.

### D6 — Actor separation: adjacency + review-subject rule

Current rule (kept): the gate actor must differ from the actor of the latest applicable
upstream gate record (adjacent-phase separation).

Added rule: each judgment phase has a defined **review subject** — the phase whose
output it adjudicates — and the gate actor must ALSO differ from the actor recorded on
the current subject-phase gate:

| Gate phase      | Review subject |
|-----------------|----------------|
| DesignReview    | Architecture   |
| SecurityPlan    | Architecture   |
| SecurityCode    | Build          |
| DesignSignoff   | Build          |
| Test            | Build          |
| DocValidation   | Documentation  |

DesignMock, Architecture, Build, Documentation, and Deploy have no review subject
(authoring/synthesis/execution phases) and keep the adjacency rule only.

Reasoning, considered and rejected alternatives:

- "Differ from ALL distinct upstream actors" is wrong by construction: the Designer
  legitimately records DesignMock, DesignReview, and DesignSignoff; Security records
  both Security gates; the Architect records Architecture and (with the Designer)
  DocValidation. The dual-persona reality is by design, not a bypass.
- The reproduced exploit — alternating two labels A,B,A,B — passes adjacency at every
  step yet lets A sign off on A's own Build (e.g. Build=A, SecurityCode=B,
  DesignSignoff=A). The review-subject rule blocks exactly this: DesignSignoff's
  subject is Build, and A == A fails.
- The combined rule is the strongest that preserves every documented persona-reuse
  pattern: for each row above, the canonical persona of the gate differs from the
  canonical persona of the subject, so the table constrains impostors without
  constraining the pipeline.
- Both comparisons read only the current `gates` map (latest record per phase), which a
  rewind clears — so the rule naturally scopes to the change's current attempt cycle.
  A subject phase with no current record contributes no comparison (nothing to review
  against); adjacency still applies.

Implementation: a `fn review_subject(phase: Phase) -> Option<Phase>` beside
`strict_actor_separation_issue` (or in `phase.rs` if Builder finds it cleaner), with the
issue message naming which rule fired and both actors.

### D7 — `mpd stats` (read-only outcome measurement)

New module `crates/mpd/src/stats.rs`; new subcommand:

```
mpd stats [--json] [--change <name>]
```

Data source: every regular file `.mpd/state/*.json` (the ledgers of active AND archived
changes — archived ledgers persist there with `archive_closure` set, and the archive
directories under `openspec/changes/archive/` carry no ledger of their own). Reads are
bounded (no-follow, per-file size cap of 16 MiB, max 10 000 ledgers) and best-effort per
file: an unreadable or unparsable ledger is REPORTED as an `unreadable` row with the
load error class (leveraging D5's version probe) — never silently skipped, never fatal
to the rest of the report.

Per-change measures (all derived from existing fields; names in parentheses):

- change, kind, archived (from `archive_closure`), strict, risk, threat profile.
- attempts per phase: max `attempt` over `history` records per phase (fallback to the
  `gates` record when history is empty — legacy ledgers).
- wall-clock per phase: sum of `GateRecord::duration_secs()` over `history` records per
  phase (phase-active time between `started_at_epoch_secs`/`completed_at_epoch_secs`).
- reconciliations: count by `ReconciliationKind` from `governance.reconciliations`.
- rewinds: `legacy_repairs.len() + freshness_invalidations.len()` (also broken out).
- failure classes: histogram of `failure_class` over FAIL records in `history`.
- weakened-tuning incidence: count of `history` records whose
  `persona_tuning.weakened` is true, plus any `brief_tuning` slot with `weakened`.
- deferrals: active `task_deferrals` (latest event is `Deferred`).
- introduced-by: the D8 provenance field, when present.

Aggregate section: totals and per-phase attempt/wall-clock aggregates across all
ledgers, the combined failure-class histogram, and defect-escape counts grouped by
originating change (ledgers with `introduced_by`).

Output: a bounded, terminal-safe human table (existing `harness::terminal_safe`
discipline for anything string-typed from disk); `--json` emits
`{"schema":1, "changes":[...], "aggregate":{...}}` with stable keys, sorted by change
name. Strictly read-only: no file writes, no git subprocesses, no network, no ledger
mutation, and no `.mpd/current` resolution side effects.

### D8 — `--introduced-by` defect provenance

- `mpd conduct --fix --introduced-by <archived-change>` (and the hidden
  `begin --fix --introduced-by ...` for parity, since conduct delegates to begin).
  Clap-level constraint: `--introduced-by` requires `--fix` (a feature/chore cannot
  "escape from" a prior change in this model).
- Validation before the ledger is created, fail-closed:
  - `openspec_core::validate_change_name` on the argument.
  - The referenced archive must exist: `.mpd/state/<name>.json` loads and has
    `archive_closure` present, OR (legacy pre-closure archives) a directory matching
    `openspec/changes/archive/<YYYY-MM-DD>-<name>/` exists. Neither → error listing the
    resolution rule; nothing is created.
- Storage: `Ledger.introduced_by: Option<String>` with
  `#[serde(default, skip_serializing_if = "Option::is_none")]` — additive, absent on
  every existing ledger, byte-inert for changes that do not use the flag. Written once
  at begin; no mutation verb edits it afterwards (provenance, not workflow state).
- Surfaced by `mpd status` (one line when present) and aggregated by `mpd stats` (D7).

### D9 — Manifest and tree hygiene (Architect-owned)

`manifest.json` for this change declares (written by this design, final):

```
.claude/pipeline-gates.json
.mpd/state/closure-defects-and-measurement.json
crates/mpd/**
docs/closure-defects-and-measurement.md
openspec/changes/closure-defects-and-measurement/**
openspec/changes/harness-aware-agent-docs/**
openspec/changes/local-first-verification-hardening/**
openspec/specs/**
```

This lets the closure commit carry: the five pending spec merges
(`directives`, `evidence-reuse`, `gate-evidence`, `process-governance`,
`remote-parity`), the two new spec directories (`local-validation`,
`agent-onboarding`), the REMOVAL of both stray active-manifest copies (tracked files
`openspec/changes/{local-first-verification-hardening,harness-aware-agent-docs}/manifest.json`,
which existed solely as pre-commit coherence reads for the two landed closures and must
be deleted in this commit), the `.claude/pipeline-gates.json` `secretAllow` addition,
this change's own artifacts/state/docs, and the code under `crates/mpd/**`. The
`openspec-core` crate is intentionally NOT declared: no planned work touches it, and
scope should not be wider than the plan (if Build discovers a genuine need, that is a
manifest amendment with a recorded reason, not a silent widening).

## Risks / Trade-offs

- [D1 widens per-push git subprocess count (one diff-tree per outgoing commit)] →
  bounded by the existing object/byte caps; commits are already individually resolved
  and size-capped; cap overflow stays a hard block.
- [D1 multi-path scanning could double-report one blob] → dedup by (oid, path) pairs;
  reporting per path is intentional (each path is a distinct trust decision).
- [D3 unioning plan entries widens the staged-path allowance] → the union is exactly
  the digest-bound expected post-archive tree from a validated, transaction-bound plan;
  the commit-coherence and parity checks downstream are unchanged and still enforce the
  recorded closure scope.
- [D4 ephemeral config changes gitleaks precedence] → only applied when the repo has no
  gitleaks config of its own; degraded temp-write falls back to the louder full scan.
- [D5 `format` field changes saved-ledger bytes] → additive field ignored by old
  readers (no `deny_unknown_fields` on `Ledger`); archived closure digests are never
  recomputed; any byte-identity test fixtures must be updated deliberately.
- [D6 could block a legitimate small-team label] → the review-subject table is the
  minimal strengthening; every documented persona-reuse pattern was checked against it
  (see D6 reasoning); reconcile/rewind flows are unaffected.
- [D7 stats over hostile ledger files] → bounded no-follow reads, size/count caps,
  terminal-safe rendering, per-file error containment.
- [D9 `openspec/specs/**` is broad] → it is precisely the pending-merge debris this
  closure must carry; the spec merge machinery owns those paths at archive anyway.

## Conditions for Builder

1. **Path-mapped scanning stays fail-closed for unmapped blobs.** Any outgoing blob
   without a validated repo-relative path mapping MUST be scanned as
   `git-object:<oid>` with NO allowlist applied. Commit/tag messages are NEVER
   allowlisted. Enumeration/mapping cap overflow or parse failure MUST block the push,
   never skip an object. A finding suppressed under one path but present under another
   mapped path MUST still block.
2. **Allowlist suppression is counted and reported** in pre-push output, matching the
   allowlist module's doctrine — never silent.
3. **No panic paths in archive.** `cmd_archive`'s transaction callback MUST NOT contain
   `.expect`/`.unwrap` on input-derived state; a validation failure MUST surface as a
   nonzero-exit error BEFORE `openspec_core::prepare` (transaction never started) with
   the tree untouched. Regression tests MUST cover both reproduced panic inputs
   (durable-doc path outside manifest; retained-manifest read failure).
4. **Closure scope never narrows below plan entries.** The AwaitingCommit staged scope
   MUST be the union of transaction classification rows and validated closure-plan
   entry paths. A missing plan (legacy) keeps rows-only; a present-but-invalid plan
   MUST block the commit. A first-ever closure commit over the full expected tree MUST
   pass; a staged path outside the union MUST still block.
5. **`mpd stats` is strictly read-only.** No file creation/modification/deletion, no
   git subprocess, no network, no `.mpd/current` mutation. Bounded no-follow reads with
   the caps in D7; unreadable ledgers are reported rows, never silent skips and never
   fatal. `--json` output is stable-keyed and deterministic (sorted by change name).
6. **Version guard never misreads valid current ledgers.** The D5 probe runs only when
   full deserialization has already failed; a ledger that parses MUST be returned
   exactly as today. The "requires a newer mpd" message MUST appear only when the
   probed `format` exceeds `LEDGER_FORMAT`; otherwise the original serde error (with
   path context) is preserved.
7. **Actor rule preserves documented persona reuse.** The D6 table MUST be implemented
   exactly: Designer at DesignMock/DesignReview/DesignSignoff, Security at both
   Security gates, and Architect at Architecture + DocValidation MUST all pass with
   distinct-per-persona labels, while the alternating-label self-review exploit
   (subject actor == gate actor) MUST fail with a message naming both the rule and the
   actors. Matrix-test both.
8. **`--introduced-by` validates before creating anything.** An invalid change name or
   an archive that resolves neither via `archive_closure` nor via a dated archive
   directory MUST fail with no ledger, no scaffold, and no `.mpd/current` change. The
   field is write-once at begin and additive-defaulted on load.
9. **gitleaks exclusion never weakens an owner's config.** With a repo-root
   `.gitleaks.toml` present, the invocation MUST be byte-identical to today's. The
   ephemeral config MUST extend defaults (`useDefault = true`) and exclude only the
   build-artifact paths in D4; a temp-file failure falls back to the unexcluded scan.
10. **Scanner digests are honest.** The pre-push authorization's `scanner_digest`/
    `rules_digest` constants MUST change with the D1 semantics change
    (`...-outgoing-secret-scan-v2`).
11. **Ledger compatibility.** All new `Ledger` fields are `#[serde(default)]`-safe,
    absent-serializing where specified, and every pre-existing ledger fixture in the
    test suite still loads with unchanged semantics. Update byte-identity fixtures
    knowingly, never by regenerating blindly.
12. **Match existing patterns.** Bounded/no-follow reads follow the existing
    `load_candidate_closure_plan` discipline; terminal output goes through the existing
    terminal-safety helpers; new code lands in `stats.rs`/existing modules as planned —
    `cli.rs` gains wiring, not logic. Initial tests are written in the same Build pass
    (unit + e2e for each defect, seeded and deterministic).

## Verdict

PASS

This approves the plan, not the code. Build proceeds only after Security (plan) passes
this design; Security (code) re-reviews the real diff, and no inline-fix shortcut
applies to the pre-push scanning surface (novel-threat-surface rule: re-run Security
after every fix there).
