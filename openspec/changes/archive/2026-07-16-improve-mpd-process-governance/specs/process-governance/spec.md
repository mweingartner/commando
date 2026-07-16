# Process Governance Delta

## ADDED Requirements

### Requirement: Declared governance context

MPD SHALL store a typed risk level and threat profile for every change and SHALL
surface the resolved values in begin, status, next, and JSON output.

#### Scenario: Existing begin command receives visible defaults

- **WHEN** an operator begins a change without governance flags
- **THEN** MPD SHALL infer a documented risk level, use the local-trusted-user
  threat profile, print both values, and persist them

#### Scenario: Explicit governance is preserved

- **WHEN** an operator supplies a supported risk and threat profile
- **THEN** every subsequent brief and status view SHALL report those exact values

#### Scenario: Legacy ledger loads safely

- **WHEN** MPD loads a ledger created before governance fields existed
- **THEN** it SHALL use documented conservative defaults without corrupting or
  invalidating the existing verdict history

### Requirement: Advisory artifact budget

MPD SHALL report an approximate canonical-artifact budget derived from risk but
SHALL NOT fail a gate solely because the estimate is exceeded.

#### Scenario: Medium-risk artifacts exceed guidance

- **WHEN** canonical artifacts exceed the medium-risk guidance
- **THEN** status and next SHALL emit a concise warning and the next actionable
  command without changing any gate verdict

#### Scenario: High-risk change has no page warning

- **WHEN** a change is declared high risk
- **THEN** MPD SHALL NOT impose a fixed artifact-page warning

### Requirement: Bounded review reconciliation

MPD SHALL require a recorded reconciliation decision before an attempt beyond
the risk-specific phase limit and SHALL preserve every prior verdict.

#### Scenario: Excess attempt is blocked

- **WHEN** a phase has exhausted its attempt allowance
- **THEN** MPD SHALL refuse another gate record and direct the operator to
  reconcile scope, continuation, risk, or threat profile

#### Scenario: Continue authorizes one attempt

- **WHEN** the operator records a nonblank continue reason
- **THEN** exactly the next attempt for the current phase SHALL be authorized
  without advancing or changing the prior verdict

#### Scenario: Risk change rewinds security review

- **WHEN** reconciliation changes the risk level
- **THEN** MPD SHALL retain history, invalidate Security plan and downstream
  latest verdicts, and return the active phase to Security plan

#### Scenario: Threat-profile change rewinds security review

- **WHEN** reconciliation changes the declared threat profile
- **THEN** MPD SHALL retain the old and new profiles in history, invalidate
  Security plan and downstream latest verdicts, and return the active phase to
  Security plan

### Requirement: Canonical current-state artifacts

MPD doctrine and templates SHALL define proposal, design, and tasks as the
current approved contract and SHALL direct superseded drafts to `history/`
without automatically rewriting user-authored content.

#### Scenario: Oversized design receives preservation guidance

- **WHEN** an artifact warning is emitted
- **THEN** MPD SHALL recommend consolidating the canonical contract and moving
  superseded prose to history rather than deleting or rewriting it automatically
