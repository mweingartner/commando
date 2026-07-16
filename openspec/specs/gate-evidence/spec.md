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
