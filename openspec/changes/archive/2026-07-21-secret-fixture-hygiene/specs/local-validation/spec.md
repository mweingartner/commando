## ADDED Requirements

### Requirement: Scanner-clean first-party source

First-party source and assets under `crates/` SHALL contain no contiguous text
that the built-in secret scanner's rules match. Realistic secret fixtures SHALL
be assembled at runtime from split literals so detection and redaction tests
keep their full-strength runtime values while the source text matches no rule;
this applies uniformly to fixtures, assertions, rule-definition literals, and
production constants. The standard test lane SHALL enforce the invariant with a
meta-test that scans the tree using the production scan functions themselves —
never a parallel pattern list — and fails on any finding. A suppression SHALL
require an explicit in-test allow entry scoped to path and rule with a written
justification, SHALL never cover a full-token-shaped literal, and the
version-controlled secret allowlist SHALL NOT carry whole-file suppressions for
first-party source files.

#### Scenario: Contiguous fixture is reintroduced

- **WHEN** a file under `crates/` gains contiguous text matching any built-in
  secret-detection rule
- **THEN** the meta-test SHALL fail in the standard test lane, reporting the
  file, line, and rule, before commit or push gates are ever reached

#### Scenario: Scanner rules stay split in their own source

- **WHEN** the scanner defines or tests a rule whose bare pattern text would
  match that rule
- **THEN** the source SHALL carry the pattern only in compile-time split form
  with identical compiled bytes, and the meta-test SHALL pass with no allow
  entry for the scanner's own files

#### Scenario: Gates rescan formerly suppressed source files

- **WHEN** commit or pre-push scanning covers a first-party source file that
  previously had a whole-file allowlist suppression
- **THEN** findings in that file SHALL be reported and SHALL deny the
  operation; suppression SHALL NOT be restorable by a whole-file entry

#### Scenario: New rule makes existing source self-match

- **WHEN** a detection rule is added or extended such that existing first-party
  source text matches it
- **THEN** the meta-test SHALL fail until that text is converted to split form
  in the same change that alters the rule
