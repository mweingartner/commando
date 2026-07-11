## ADDED Requirements

### Requirement: Data export
The system SHALL allow users to export their data in CSV format.

#### Scenario: Successful export
- **WHEN** the user clicks Export
- **THEN** the system downloads a CSV file

## MODIFIED Requirements

### Requirement: Login flow
The system MUST authenticate users via SSO.

#### Scenario: SSO login
- **WHEN** a user signs in
- **THEN** they are redirected to the identity provider

## REMOVED Requirements

### Requirement: Legacy export
**Reason**: Replaced by the new export system
**Migration**: Use the /api/v2/export endpoint

## RENAMED Requirements

- FROM: `### Requirement: Old dashboard`
- TO: `### Requirement: New dashboard`
