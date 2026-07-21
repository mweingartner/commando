# Evidence Reuse

## Requirements

### Requirement: Content-bound gate receipts

MPD SHALL bind new gate evidence to a versioned canonical digest of every
phase-specific input needed to support that result.

#### Scenario: Bound input changes

- **WHEN** a bound content, governance, configuration, tool, scanner, or artifact
  input differs from the recorded snapshot
- **THEN** evidence SHALL be stale and name each changed dependency class

#### Scenario: Later-phase output changes

- **WHEN** documentation or archive output created after Build/Test changes but
  every input actually reviewed by that earlier phase remains identical
- **THEN** the earlier receipt SHALL remain valid rather than bind future output

#### Scenario: Legacy gate has no receipt

- **WHEN** an old gate record has no content-bound receipt
- **THEN** evidence SHALL be absent rather than assumed valid

### Requirement: Explicit exact-input reuse

MPD SHALL reuse evidence only through an explicit receipt identifier whose
complete dependency snapshot is valid, and SHALL append a distinct reused event.

Content validity and reuse eligibility SHALL be separate fields. Valid evidence
MAY remain ineligible because its phase always executes, lacks a complete
hermetic policy, or originated as CONDITIONAL PASS.

#### Scenario: Content-valid execution phase uses default policy

- **WHEN** a Build/Test/Security-code receipt still matches content but no
  complete hermetic policy enables reuse
- **THEN** MPD SHALL show `valid` plus `reuse disabled: always executes` and
  offer the fresh gate command rather than `--reuse`

#### Scenario: Hermetic policy enables reuse

- **WHEN** a content-valid unconditional PASS has a complete hermetic policy
- **THEN** MPD SHALL label it hermetic reuse eligible and expose the policy
  version in JSON

#### Scenario: Valid receipt is reused

- **WHEN** `gate --reuse` names a valid receipt for the current phase
- **THEN** MPD SHALL append a reused event pointing to the original without
  executing the gate again or erasing history

#### Scenario: Stale receipt is requested

- **WHEN** any dependency differs
- **THEN** reuse SHALL fail without ledger changes and name the rerun reason

#### Scenario: Deploy receipt is requested

- **WHEN** reuse targets the external-state Deploy phase
- **THEN** MPD SHALL refuse reuse and require fresh target verification

#### Scenario: Conditional approval was later resolved

- **WHEN** reuse names a CONDITIONAL PASS receipt even if its old condition closed
- **THEN** MPD SHALL refuse reuse and offer a fresh persona gate so the
  obligation cannot disappear

#### Scenario: Execution phase lacks hermetic policy

- **WHEN** Build, Test, or Security code has no complete versioned hermetic policy
- **THEN** its receipt SHALL be non-reusable and the configured check SHALL run

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
