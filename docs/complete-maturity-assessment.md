# Complete the MPD maturity assessment

## Purpose

Correct the shipped quality/cost/time guide, which described controls but omitted the
requested maturity scores and linked back to itself for those absent results.

## Value

Operators and maintainers get a falsifiable assessment that separates implemented process
controls from demonstrated output quality, model economics, and elapsed-time outcomes.

## Scope

The canonical guide scores output-quality assurance, model-cost efficiency, time
efficiency, review provenance, and routing on an explicit five-level scale. It binds the
scores to the pushed `d284a924` release, tracked ledger, archived tests, and routing status.
It does not change executable, configuration, policy, dependencies, or installation. It
does not infer absent usage/cost data, authenticate cooperative actors, or call an
insufficient routing experiment optimal.

## Functional details

The headline is **Defined, approaching Managed**. Quality assurance is 3/5 (Managed),
model-cost efficiency is 2/5 (Defined), and time efficiency is 3/5 (Managed,
evidence-limited). Provenance and routing are each 2/5. Every score gives supporting
evidence and the missing evidence that blocks the next level. The guide retains zero of
30 trusted usage reports, 30/30 wall coverage totalling 4,921 seconds, 12 rewinds,
`NOT DEPLOYED` authenticated provenance, and `INSUFFICIENT` routing as explicit negative
states. It closes with a prioritized measurement and controlled-experiment roadmap.

## Usage

Read the [canonical assessment](optimize-quality-cost-time-maturity.md#assessment) and its
[archived test evidence](../openspec/changes/archive/2026-07-23-complete-maturity-assessment/test.md).
Inspect the live coverage and routing evidence without mutation:

```sh
mpd status --json
mpd stats --json
mpd routing evaluate --evidence <routing-evidence.json>
```

Use `routing apply --yes` only after sufficient evidence produces a reviewed preview;
missing or insufficient evidence preserves the current mapping.
