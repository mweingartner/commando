# Gate Evidence Delta

## ADDED Requirements

### Requirement: Canonical strict judgment artifact

Every strict judgment gate SHALL require its canonical contained artifact, required
sections, current digest, actor, and exactly one final `PASS`, `CONDITIONAL PASS`, or
`FAIL` token matching the requested CLI verdict. Commando SHALL deny artifact waivers.

#### Scenario: Artifact and requested verdict disagree

- **WHEN** the artifact verdict differs from the CLI verdict or is absent/ambiguous
- **THEN** MPD SHALL refuse before objective checks or ledger mutation and retain the
  current phase

### Requirement: Exact candidate binding

Build, Security(code), and Test PASS records SHALL name the same current candidate ID.
Documentation and Doc Validation SHALL additionally bind their reviewed overlay digest;
Deploy SHALL bind the candidate-bearing Build output. Candidate and Commit receipts
SHALL remain structurally distinct.

#### Scenario: Passing HEAD hides a failing worktree

- **GIVEN** HEAD passes but a declared staged, unstaged, untracked, deleted, or mode-
  changed candidate postimage fails a required check
- **WHEN** Build, Security(code), or Test runs
- **THEN** the gate SHALL test the captured candidate, fail or block, and SHALL NOT issue
  evidence for HEAD

### Requirement: Durable bounded obligations

Condition resolutions and task deferrals SHALL store bounded metadata plus contained
evidence pointer/digest. Changed or missing evidence SHALL reopen/block the obligation
without erasing its history.

#### Scenario: Resolution evidence changes

- **WHEN** a later status, gate, or archive recheck finds a digest mismatch
- **THEN** the obligation SHALL be stale/open, its historical events SHALL remain, and
  archive SHALL be blocked
