# Evidence Reuse Delta

## ADDED Requirements

### Requirement: Causal phase-specific evidence

Every PASS receipt SHALL bind only inputs available to or produced by that phase. A
changed input SHALL stale the earliest causally affected phase without retroactively
invalidating an earlier phase that did not review it.

#### Scenario: Architecture authors its artifacts after Design Mock

- **GIVEN** Design Mock bound its own artifact, scope, and effective governance
- **WHEN** Architecture creates or revises proposal, design, tasks, or specs
- **THEN** Design Mock SHALL remain current unless one of its actual inputs changed

#### Scenario: Product source changes after Security plan

- **GIVEN** Security(plan) reviewed the accepted Architecture rather than implementation
- **WHEN** product source, tests, policy, hooks, or scripts change
- **THEN** freshness SHALL rewind to Build, retain Security(plan) history, and require
  new Build and downstream evidence

### Requirement: Rewind before effects

`next`, `gate`, archive, and Deploy SHALL calculate freshness under the ledger lock
before another effect. If stale, they SHALL append one rewind/invalidation event, reopen
dependent obligations, stop, and create no downstream brief, verdict, archive, or install.
`status` SHALL compute the same stored/effective projection without writing.

#### Scenario: Stale gate is first observed by archive

- **WHEN** archive detects a changed dependency for an earlier PASS
- **THEN** archive SHALL perform no archive or Git mutation, retain all verdict history,
  and leave the change at the earliest affected phase
