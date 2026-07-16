# Design: gate-history-and-guards

> Non-UI feature (Design phases N/A -- the mpd CLI has no UI surface). Adds
> audit-trail preservation + two guards + init hygiene, grounded in the source.

## Context

Three gaps, each pinned to a source line:
- `Ledger::record` (`ledger.rs`) overwrites via `gates.insert(phase, record)` --
  a re-recorded phase loses its prior verdict, so a FAIL -> PASS is unrecoverable.
- `check_documentation` (`cli.rs`) already rejects `<!--` placeholders, but only
  for `documentation.md`; `proposal/design/tasks.md` have no equivalent guard.
- `cmd_status` (`cli.rs`) ends without pointing at the next command.
- `scaffold::init` (`scaffold.rs`) writes no gitignore, so `.mpd/current` (a
  transient pointer) reads as uncommitted in every fresh project.

## Goals / Non-Goals
**Goals**: preserve the full verdict trail; block archive on unfilled core-artifact
stubs; nudge the operator to the next command; gitignore transient state on init.
**Non-Goals**: changing gate/advancement/readiness *semantics* (the latest-per-phase
map still drives them); test-result caching; gate-skipping presets; a planner-write
command (harness concern).

## Decisions

### 1. Gate history -- append-only, latest-per-phase preserved
- New `pub struct GateEvent { pub phase: Phase, pub record: GateRecord }`.
- `Ledger.history: Vec<GateEvent>` with `#[serde(default)]` (backward compatible;
  old ledgers deserialize with an empty history).
- `record(phase, rec)`: push `GateEvent { phase, record: rec.clone() }` to
  `history`, THEN `gates.insert(phase, rec)`. `gates` stays latest-per-phase and
  keeps driving advancement + `blocking_reasons`/`ready_to_archive` -- unchanged.
- `mpd status`: after the pipeline, when `history` has more entries than distinct
  latest verdicts, render a chronological "Gate history:" block
  (`Security (code): FAIL (by, at)` / `Security (code): PASS (by, at)`), so a
  catch-then-fix is visible. JSON gains `history`.
- No cap: history size is bounded by developer gate recordings (a handful per
  change); it is developer-recorded, not adversary-controlled -- no DoS surface.

### 2. Stub-artifact guard
- Shared `fn artifact_stub_issues(project, change) -> Vec<String>`: for
  proposal.md / design.md / tasks.md, read via `openspec_core::read_capped`
  (symlink-refusing, size-capped -- identical hardening to the doc check) and flag
  each that is missing/empty or still contains a `<!--` placeholder.
- `cmd_archive`: after the existing unmet-gate/condition guard, refuse (exit 1)
  when `artifact_stub_issues` is non-empty, listing them -- the same
  irreversibility-guard pattern already there.
- `cmd_status`: append the stub issues to the "Ready to archive: no" reasons so
  the operator sees them before attempting archive.

### 3. `mpd status` next-action nudge
- End of `cmd_status` (non-JSON): open conditions -> `-> resolve: mpd resolve <n>`;
  else phase not Done -> `-> next: mpd next`; else ready -> `-> archive: mpd archive --yes`;
  else (Done but blocked by stubs) -> the stub reasons already printed suffice.

### 4. init `.mpd/.gitignore`
- `scaffold::init` writes `.mpd/.gitignore` = `"/current\n/tmp/\n"` via the
  existing symlink-safe `write_new`. Self-contained to `.mpd/`; state/config/
  directives stay tracked. Non-destructive (re-running init on an existing
  project adds it if absent).

## Risks / Trade-offs
- [Ledger schema change] -> additive `#[serde(default)]`; regression test loads an
  old-format ledger (no `history`) and round-trips.
- [Stub heuristic false-positive on a deliberate `<!--`] -> rare; the author removes
  it, same rule as the existing documentation gate. Accepted for consistency.
- [status/archive reads follow a symlink] -> prevented by `read_capped`.

## Conditions for Builder
1. `history` is `#[serde(default)]`; old `.mpd/state/*.json` (no history field)
   MUST still deserialize -- regression test required.
2. `record` appends to `history` AND updates `gates` (latest). Gates/advancement/
   readiness semantics UNCHANGED -- every existing `ledger.rs` test still passes.
3. Stub-artifact reads use `openspec_core::read_capped` (symlink-refusing,
   size-capped) -- never a raw `read_to_string`. Match `check_documentation`.
4. `cmd_archive` REFUSES (exit 1) on stub artifacts, listing them, before any
   irreversible move -- alongside the existing unmet-gate guard.
5. The stub check covers proposal/design/tasks.md only (documentation.md keeps its
   own gate). Missing / empty / contains-`<!--` == stub.
6. `.mpd/.gitignore` is written via the symlink-safe `write_new`; contents scope to
   `.mpd/` only (`/current`, `/tmp/`), leaving state/config/directives tracked.
7. New tests: history FAIL->PASS preserved + old-ledger load; stub detection (stub
   blocks archive, filled passes); init writes `.mpd/.gitignore`. `cargo test
   --workspace` and `cargo clippy` clean.
