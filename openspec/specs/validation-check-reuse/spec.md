# Validation Check Reuse

## Requirements

### Requirement: Check-level validation disposition

Every local validation result SHALL identify whether it executed or reused an exact
passing executed source check. Reuse SHALL name the source receipt/check identity and
source duration, and the disposition SHALL be bound into the receipt identity.

#### Scenario: Complete identity match

- **GIVEN** a current passing executed source check exists
- **WHEN** subject, check definition, policy, tool, host/adapter, inputs, environment, result policy, and coordinator identities match a current passing executed result
- **THEN** MPD may reuse it and flattens the source to the executed origin

#### Scenario: Any identity differs

- **GIVEN** a prior check has the same display name
- **WHEN** any required identity differs or is absent
- **THEN** MPD executes the check or blocks according to policy and never silently reuses it

### Requirement: Fresh security and publication floors

Security(code) SHALL remain a fresh gate; its security-specific checks, outgoing secret
scan, exact Commit validation, and pre-push authorization SHALL not be satisfied by
stale or unrelated check reuse.

#### Scenario: Reusable general checks at Security code

- **GIVEN** Security(code) is being invoked for the exact Candidate
- **WHEN** general checks are reusable during Security(code)
- **THEN** all security-specific floor checks still execute and the receipt distinguishes both dispositions
