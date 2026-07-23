# Budget Anti Stall

## Requirements

### Requirement: Risk-specific bounded model work

MPD SHALL evaluate configured soft and hard cost, token, active-time, and wall-time
limits against known evidence with explicit coverage. Soft crossings warn; hard crossings
block issuance of a new persona brief without altering any gate verdict.

#### Scenario: Hard cost limit reached

- **GIVEN** an effective-risk hard cost budget is configured
- **WHEN** attested same-currency cost reaches the effective-risk hard limit
- **THEN** `next` issues no brief, identifies the limit, and offers one bounded reconciliation action

#### Scenario: Coverage is incomplete

- **GIVEN** a budget report spans multiple applicable attempts
- **WHEN** one or more applicable attempts have no usage evidence
- **THEN** MPD reports UNAVAILABLE with coverage and does not infer zero or a provider price

### Requirement: Anti-stall bounded continuation

MPD SHALL stop new model work after two consecutive infrastructure/environment/policy
blockers or 30 minutes without advancement. Only bounded typed blocker outcomes stored in
the ledger may increment that counter. One explicit reconciliation SHALL authorize one
bound continuation without resetting totals, clocks, or history.

#### Scenario: Read-only observation at a stop

- **GIVEN** no bounded continuation is currently authorized
- **WHEN** the anti-stall limit is reached
- **THEN** status, stats, and evidence inspection remain read-only and available

#### Scenario: Continuation races

- **GIVEN** one continuation is bound to one phase attempt
- **WHEN** two writers attempt to consume the same continuation
- **THEN** at most one succeeds and the other observes a stable refusal

#### Scenario: Time or taxonomy ambiguity

- **GIVEN** the persisted advancement timestamp regresses or a gate contains unclassified reviewer text
- **WHEN** `next` evaluates anti-stall state
- **THEN** the clock ambiguity blocks a new brief pending reconciliation, while unclassified text does not increment the typed consecutive-blocker counter
