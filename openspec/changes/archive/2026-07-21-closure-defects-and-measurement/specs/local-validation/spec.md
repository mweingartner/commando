# Local Validation Delta

## MODIFIED Requirements

### Requirement: Complete local pre-push authorization

Pre-push SHALL parse bounded real Git input, validate accepted policy for every batch,
resolve every non-deletion commit/tag subject, and scan every outgoing blob plus commit/
tag message, including objects introduced and removed within the outgoing range.
Authorization SHALL bind remote, baseline, rows, complete object set, policy, result, and
invocation nonce and SHALL not be reusable.

Outgoing blobs SHALL be scanned under their repo-relative tree paths, derived from the
per-commit diffs of the outgoing range, with the version-controlled secret allowlist
applied per path; every suppression SHALL be counted and reported. A blob whose path
cannot be derived or validated SHALL be scanned under a synthetic object name with no
allowlist applied, and commit/tag messages SHALL never be allowlisted. A finding
suppressed under one path but present under another mapped path SHALL still deny the
push. Path-mapping enumeration SHALL be capped, and cap overflow or parse failure SHALL
deny the push rather than skip any object.

Deletion-only SHALL still run trust, policy, input, and ref checks. Deletion of `main` or
any tag SHALL be denied. Other deletion approval SHALL atomically bind and consume once:
remote name/location digest, raw ref bytes, old OID, zero new OID, complete batch and
baseline digest, policy digest, and nonce. Git, not MPD, SHALL own transport.

#### Scenario: Deletion-only protected ref update

- **WHEN** pre-push receives deletion of `refs/heads/main` or `refs/tags/**`
- **THEN** it SHALL deny before approval lookup and SHALL NOT treat the empty outgoing
  object set as authorization

#### Scenario: Allowlisted fixture blob is pushed

- **WHEN** an outgoing blob's only tree paths match the repository's secret allowlist
  for its findings
- **THEN** pre-push SHALL suppress those findings, report the suppression count, and
  authorize the push

#### Scenario: Same secret content at an allowlisted and a source path

- **WHEN** one outgoing blob object is introduced at both an allowlisted fixture path
  and a non-allowlisted path
- **THEN** pre-push SHALL scan it under every mapped path and SHALL deny the push for
  the non-allowlisted occurrence

#### Scenario: Unmapped blob keeps full strictness

- **WHEN** an outgoing blob has no derivable validated tree path
- **THEN** pre-push SHALL scan it under a synthetic object name with no allowlist
  applied

## ADDED Requirements

### Requirement: Worktree external-scanner scope

Filesystem-mode external secret scans invoked by MPD SHALL exclude build-artifact
directories through a configuration that extends the scanner's default rules, SHALL
leave the invocation unchanged when the repository provides its own scanner
configuration, and SHALL fall back to the unexcluded scan — never a skipped scan — when
the exclusion cannot be prepared.

#### Scenario: Repository without its own scanner config

- **WHEN** the worktree external secret scan runs in a repository with no scanner
  config of its own and findings exist only under the build-artifact directory
- **THEN** the scan SHALL report clean while default rules remain in force elsewhere

#### Scenario: Repository owns its scanner config

- **WHEN** the repository root provides its own scanner configuration
- **THEN** MPD SHALL invoke the scanner without overriding that configuration
