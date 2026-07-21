# Outcome Measurement Delta

## ADDED Requirements

### Requirement: Read-only outcome statistics

`mpd stats` SHALL aggregate every readable change ledger — active and archived — into
per-change and aggregate outcome measures derived solely from existing ledger fields:
attempts per phase, wall-clock per phase, reconciliations by kind, rewinds (legacy
repairs plus freshness invalidations), failure-class histogram, weakened-tuning
incidence, active task deferrals, and defect-escape provenance. It SHALL emit a
bounded terminal-safe human table and, with `--json`, a stable-keyed deterministic
document. It SHALL be strictly read-only: no file mutation, no Git subprocess, no
network, and no current-change pointer change. Ledger reads SHALL be bounded and
no-follow, and an unreadable or unparsable ledger SHALL be reported as such — never
silently skipped and never fatal to the rest of the report.

#### Scenario: Aggregation over active and archived ledgers

- **WHEN** `mpd stats` runs in a project with archived and active changes
- **THEN** it SHALL report each change's measures and an aggregate section without
  modifying any file

#### Scenario: Malformed ledger among readable ones

- **WHEN** one ledger file fails its bounded read or parse
- **THEN** stats SHALL report that ledger as unreadable with its error class and SHALL
  still report every other change

#### Scenario: Machine-readable output

- **WHEN** `mpd stats --json` runs twice with no state change
- **THEN** both outputs SHALL be byte-identical, sorted by change name, with a
  versioned schema field

### Requirement: Defect provenance link

A defect-fix change SHALL be able to record the archived change that introduced the
defect via `--introduced-by <archived-change>` at conduct/begin time. The flag SHALL
require the defect-fix kind, SHALL validate that the referenced change name is safe and
that its archive exists before creating any state, and SHALL store the link as an
additive optional ledger field written once. Status SHALL surface the link, and stats
SHALL aggregate defect-escape counts per originating change.

#### Scenario: Valid provenance link

- **WHEN** `mpd conduct --fix --introduced-by <name>` names a change whose archive
  exists
- **THEN** the new ledger SHALL carry the link, status SHALL display it, and stats
  SHALL count it against the originating change

#### Scenario: Missing archive is refused before creation

- **WHEN** `--introduced-by` names a change with no resolvable archive
- **THEN** MPD SHALL fail with the resolution rule and SHALL create no ledger,
  scaffold, or current-change pointer

#### Scenario: Provenance requires the fix kind

- **WHEN** `--introduced-by` is supplied without the defect-fix kind
- **THEN** the command SHALL be refused before any state is created
