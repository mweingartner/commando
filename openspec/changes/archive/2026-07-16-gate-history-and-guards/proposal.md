# Proposal: gate-history-and-guards

## Why

Dogfooding mpd on a large Lucy security push surfaced three gaps where the tool
diverges from its own "machine-enforced, audit-preserving" philosophy:

1. **The gate ledger overwrites verdicts, erasing the audit trail.**
   `Ledger::record` does `gates.insert(phase, record)`, so a FAIL -> fix -> PASS
   cycle discards the FAIL. The single most valuable signal an adversarial
   pipeline produces -- *what a gate caught* -- is destroyed the moment the phase
   is re-recorded PASS. A ledger that shows only green stamps cannot prove
   Security ever caught anything.
2. **Archive does not guard against unfilled artifact stubs.** `mpd begin` seeds
   proposal/design/tasks.md from templates; nothing stops archiving a change
   whose design.md is still the `<!-- ... -->` stub. The Documentation gate
   already rejects placeholder stubs -- the same check is absent for the core
   OpenSpec artifacts, so empty stubs shipped into archives in practice.
3. **`mpd init` doesn't gitignore the transient state pointer.** `.mpd/current`
   is a per-developer pointer, not durable record, but `mpd init` never adds it
   to a gitignore, so it surfaces as an uncommitted file the commit/stop hooks
   nag about every turn.

## What Changes

- **Gate history**: `Ledger` gains an append-only `history: Vec<GateEvent>`;
  `record` appends every verdict before updating the latest-per-phase map.
  `mpd status` renders the verdict trail (e.g. `Security (code): FAIL -> PASS`);
  the JSON carries `history`. `gates` (latest-per-phase) still drives
  advancement/readiness -- no change to gating behavior.
- **Stub-artifact guard**: `mpd archive` refuses (and `mpd status` surfaces) when
  proposal/design/tasks.md still contain unfilled `<!--` template placeholders,
  generalizing the existing documentation.md check with the same symlink-refusing,
  size-capped reads.
- **`mpd status` action nudge**: after the readiness block, status prints the
  recommended next command (`mpd next` / `mpd resolve <n>` / `mpd archive --yes`).
- **`mpd init` gitignores transient state**: init writes a self-contained
  `.mpd/.gitignore` (`/current`, `/tmp/`) so new projects never surface the
  pointer as uncommitted, while state/config/directives stay tracked.

## Capabilities

### Modified Capabilities
- `gate-ledger`: verdict history preserved (append-only) alongside latest-per-phase.
- `archive`: blocks on unfilled core-artifact template stubs.
- `status`: shows verdict history + a next-action nudge.
- `init`: writes `.mpd/.gitignore`.

## Impact

- **Modified**: `crates/mpd/src/ledger.rs` (GateEvent + history + record),
  `crates/mpd/src/cli.rs` (status history/nudge, archive stub-guard),
  `crates/mpd/src/scaffold.rs` (init `.mpd/.gitignore`).
- **Ledger schema**: additive `history` field (`#[serde(default)]`) -- existing
  `.mpd/state/*.json` load unchanged.
- **No breaking changes**: gates/advancement/readiness semantics unchanged; the
  new checks only add blocking reasons for genuinely-incomplete changes.
- **Out of scope (considered, rejected/deferred)**: test-result caching across
  Build/Test gates (the double-run is often correct -- the Tester deepens the
  suite between them -- so caching risks masking a regression, conflicting with
  "verify your verification"); proportionality gate-skipping presets (conflicts
  with "gates never skip", especially Security); an `mpd plan --stdin`
  planner-write affordance (the planner persona's lack of a Write tool is a
  harness agent-toolset concern, not the mpd CLI).
