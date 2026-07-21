# Gate Evidence

## Requirements

### Requirement: Classified gate failures

Every newly recorded FAIL SHALL identify exactly one of `product`, `test`,
`infrastructure`, `environment`, or `policy`, and the class SHALL be visible in
human history and JSON.

#### Scenario: FAIL omits classification

- **WHEN** an operator records FAIL without a failure class
- **THEN** MPD SHALL refuse the record without changing the ledger

#### Scenario: Non-FAIL supplies classification

- **WHEN** an operator supplies a failure class with PASS or CONDITIONAL PASS
- **THEN** MPD SHALL reject the invalid flag combination

### Requirement: Structured Security exploitability

A Security plan or Security code FAIL SHALL record a nonblank attacker,
prerequisite capability, crossed trust boundary, concrete harm, and exact fix.

#### Scenario: Security FAIL describes a credible path

- **WHEN** all five exploitability fields and a failure class are supplied
- **THEN** MPD SHALL preserve them as structured evidence attached to the FAIL

#### Scenario: Security FAIL is only theoretical prose

- **WHEN** any exploitability field is missing or blank
- **THEN** MPD SHALL refuse the blocking finding and leave the ledger unchanged

#### Scenario: Other phase supplies exploitability fields

- **WHEN** exploitability flags are supplied for a non-Security phase
- **THEN** MPD SHALL reject them rather than create a misleading record

### Requirement: Attempt and duration telemetry

MPD SHALL record each phase attempt and bounded wall-clock timestamps without
storing raw output, prompts, source contents, environment variables, or secrets.

#### Scenario: Repeated phase preserves telemetry

- **WHEN** a phase records FAIL and is later attempted again
- **THEN** append-only history SHALL show monotonically increasing attempt
  numbers and retain both classified events

#### Scenario: System clock moves backward

- **WHEN** a completion timestamp precedes the recorded phase start
- **THEN** rendered duration SHALL clamp to zero and MUST NOT panic or underflow

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

### Requirement: Adversarial actor separation

Strict gates SHALL enforce cooperative actor separation on two axes over the change's
current attempt cycle: the gate actor SHALL differ from the actor of the latest
applicable upstream gate record, and a judgment gate with a defined review subject —
Design Review and Security (plan) reviewing Architecture; Security (code), Design
Sign-off, and Test reviewing Build; Doc Validation reviewing Documentation — SHALL also
differ from the actor recorded on that subject phase. Authoring and execution phases
(Design Mock, Architecture, Build, Documentation, Deploy) carry only the
adjacent-upstream rule. The documented persona-reuse patterns (Designer at the three
Design gates, Security at both Security gates, Architect at Architecture and Doc
Validation) SHALL remain valid. Actor labels remain recorded cooperative provenance,
not authenticated identity.

#### Scenario: Alternating labels attempt self-review

- **WHEN** the actor who recorded Build later attempts the Design Sign-off, Security
  (code), or Test gate under the same label, with a different label recorded in between
- **THEN** the gate SHALL be refused with a message naming the review-subject rule and
  both actors

#### Scenario: Documented persona reuse proceeds

- **WHEN** one Designer label records Design Mock, Design Review, and Design Sign-off,
  one Security label records both Security gates, and the Architect label records
  Architecture and Doc Validation, with each gate actor distinct from its adjacent
  upstream actor and its review subject's actor
- **THEN** every gate SHALL proceed

#### Scenario: Rewound subject leaves nothing to compare

- **WHEN** a judgment gate runs while its review-subject phase has no gate record in
  the current attempt cycle
- **THEN** only the adjacent-upstream comparison SHALL apply
