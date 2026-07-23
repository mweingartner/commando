## ADDED Requirements

### Requirement: Honest documentation-only profile selection
MPD SHALL select docs Build, Security(code), and Test profiles only for requested-Low,
effective-Low, documentation-only scope with no code, config, or policy paths. Every
phase remains applicable.

#### Scenario: Eligible documentation change
- **GIVEN** all mandatory phases and docs profile floors are configured
- **WHEN** a trusted-policy change is honestly docs-only and each configured profile satisfies its fixed floor
- **THEN** all three objective phases run the docs profiles and receipts bind their profile/check identities

#### Scenario: Ineligible or malformed lane
- **GIVEN** the profile selector has classified current exact scope and effective risk
- **WHEN** scope includes code/config/policy, effective risk is Medium/High, or a docs profile misses its floor
- **THEN** MPD selects the existing full lane where eligible or blocks malformed configuration; it never silently weakens validation

### Requirement: Real sandbox adoption evidence
Commando SHALL exercise the first docs-lane adoption through the trusted local policy
sandbox rather than treating a config-only unit test as deployment evidence.

#### Scenario: Trusted sandbox fixture
- **GIVEN** immutable reviewed policy has activated the docs profiles
- **WHEN** the docs-only e2e traverses Build, Security(code), and Test
- **THEN** each actual sandbox receipt names the expected docs profile and required checks
