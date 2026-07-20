# Remote Parity Delta

## ADDED Requirements

### Requirement: Orthogonal delivery observations

Local candidate/gate evidence, archive closure, commit coherence, push authorization,
observed transfer, remote parity, and installed bytes SHALL remain separate status and
publication fields. No field SHALL imply another.

#### Scenario: Remote OID matches but local authorization is absent

- **WHEN** fresh remote observation finds exact OID parity without current push
  authorization evidence
- **THEN** remote parity SHALL be `verified`, authorization SHALL remain MISSING or
  BYPASSED, and output SHALL not call the result fully certified or installed

#### Scenario: Local candidate passed but no closure commit exists

- **WHEN** Build/Security(code)/Test have current Candidate evidence before archive
- **THEN** candidate evidence SHALL be current while archive, commit, push, transfer,
  parity, and install remain independently pending

### Requirement: Publication remains observational

`mpd publish --verify` SHALL perform fresh bounded observation of the exact configured
remote/ref and compare it with the coherent local closure commit. It SHALL NOT validate a
candidate, write gate or validation evidence, activate hooks, fetch, push, deploy, or
install.

#### Scenario: Remote observation is unavailable

- **WHEN** the configured remote cannot be resolved or contacted
- **THEN** publication SHALL report unavailable/offline without changing local gate,
  archive, commit, authorization, or install facts
