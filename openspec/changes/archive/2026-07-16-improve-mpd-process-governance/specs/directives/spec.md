# Directives Delta

## ADDED Requirements

### Requirement: Governance-aware persona directives

MPD SHALL include the declared risk and threat profile in every persona brief,
and Security directives SHALL reserve blocking FAIL for a described exploit path
within or into that profile.

#### Scenario: Security receives local trusted-user profile

- **WHEN** Security requests the next brief for a local-trusted-user change
- **THEN** the brief SHALL name that profile and direct out-of-profile hardening
  to advisory evidence unless it crosses into the declared boundary
