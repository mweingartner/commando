# Gate History and Archive Guards

## Purpose
Three mpd improvements surfaced while dogfooding the pipeline on a large security
push, each closing a gap between mpd's behavior and its "machine-enforced,
audit-preserving" philosophy: preserve the full gate-verdict trail, refuse to
archive unfilled artifact stubs, and stop nagging about transient state.

## Value
Reviewers and auditors get an honest record of what the pipeline *caught*, not
just a row of green stamps: a gate that FAILed and was later re-recorded PASS is
now visible. Empty template stubs can no longer be folded into the permanent
record. New projects no longer surface the transient current-change pointer as an
uncommitted file. The net effect is a ledger you can trust and a smoother loop.

## Scope
Covers four mpd surfaces: the gate ledger (`Ledger::record` / `history`), the
`status` command (verdict history + next-action nudge), the `archive` command and
readiness check (core-artifact stub guard), and `init` (writing `.mpd/.gitignore`).
It does NOT change gate/advancement/readiness *semantics* (the latest-per-phase
map still drives them), does not add test-result caching, does not add
gate-skipping presets, and does not touch the persona/harness or secret machinery.

## Functional details
- **Gate history**: `Ledger` carries an append-only `history: Vec<GateEvent>`
  (`#[serde(default)]`, so pre-existing ledgers load unchanged). `record` appends
  every verdict before updating the latest-per-phase `gates` map. `mpd status`
  renders a chronological "Gate history:" section when any phase was recorded more
  than once, and the `--json` output always includes `history`.
- **Stub-artifact guard**: `mpd archive` refuses (exit 1), and `mpd status`
  surfaces as a not-ready reason, when `proposal.md` / `design.md` / `tasks.md` are
  missing, empty, or still contain an unfilled template placeholder. Placeholder
  detection is backtick-aware: a `<!--` that appears only inside an inline-code
  span (a doc *describing* the convention) is not treated as a stub. Reads are
  symlink-refusing and size-capped.
- **Next-action nudge**: `mpd status` ends by pointing at the next command —
  `mpd resolve` when conditions are open, `mpd next` while phases remain, or
  `mpd archive --yes` once ready.
- **init hygiene**: `mpd init` writes a self-contained `.mpd/.gitignore`
  (`/current`, `/tmp/`), leaving `.mpd/state/`, config, and directives tracked.

## Usage
- See a caught-then-fixed gate: after `mpd gate security-code --fail` then, once
  fixed, `mpd gate security-code --pass`, run `mpd status` — the "Gate history:"
  section shows both the FAIL and the PASS, and `mpd status --json` carries the
  full `history` array.
- Guarded archive: running `mpd archive --yes` on a change whose `design.md` is
  still the seeded template fails with "core artifacts are incomplete"; fill the
  artifacts and it proceeds.
- Fresh project: after `mpd init`, `.mpd/current` is already gitignored, so it
  never shows up as an uncommitted change.
