# Quality-adjusted cost and time maturity

## Purpose

Document the exact controls and evidence MPD can use to protect output quality while
bounding model cost, elapsed time, and redundant local verification.

## Value

Operators receive typed coverage and negative states instead of inferred savings. The
maturity assessment separates enforced controls from external evidence still missing.

## Scope

It covers cooperative review attestation, usage budgets, anti-stall policy, exact-check
reuse, docs profiles, offline routing evidence, and typed recovery. It does not claim
authenticated provenance without an external issuer, comparable provider billing without
complete evidence, or globally optimal routing.

## Functional details

`status`/`stats` render per-metric coverage; hard budgets and repeated typed blockers stop
new briefs but preserve observation. Reuse binds the complete Candidate identity and never
reuses security scans or artifact production. Effective-Low docs changes use reviewed
reduced profiles while retaining a release artifact. Routing is offline/read-only before a
previewed allowlisted write. Cache pruning quarantines only unreferenced verified entries.

## Usage

```sh
mpd status --json
mpd stats --json
mpd routing evaluate --evidence <routing-evidence.json>
mpd routing apply --evidence <routing-evidence.json>
mpd cache inspect --json
mpd cache prune
```

Use mutation `--yes` flags only after reviewing the preview. Supply `--attestation` only
for the exact gate attempt it binds. See `docs/optimize-quality-cost-time-maturity.md` for
the maturity scores, evidence limits, and NOT DEPLOYED provenance state.
