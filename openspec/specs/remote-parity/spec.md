# Remote Parity

## Requirements

### Requirement: Non-pushing remote observation

`mpd publish` SHALL report readiness and `mpd publish --verify` SHALL observe the
configured remote/ref without pushing, force-pushing, creating refs, staging,
committing, archiving, or deploying.

#### Scenario: Exact remote parity

- **WHEN** the archived coherent HEAD OID exactly equals the freshly observed
  remote ref OID
- **THEN** remote parity SHALL be verified for that commit and observation time

#### Scenario: Network is unavailable

- **WHEN** bounded remote observation fails or times out
- **THEN** parity SHALL be offline, local evidence SHALL remain intact, and the
  command SHALL not report divergence

### Requirement: Accurate Git-state classification

MPD SHALL distinguish verified, not-verified, offline, ahead, behind, diverged,
rewritten, unstable, ancestry-unavailable, and unavailable using exact object
IDs and ancestry where available, without fetching.

#### Scenario: Previously verified history is rewritten

- **WHEN** a fresh remote OID no longer descends from the last verified remote OID
- **THEN** parity SHALL be rewritten and MPD SHALL NOT recommend force-push

#### Scenario: Publication ref is undefined

- **WHEN** the repository is unborn, the remote/ref is missing, or detached HEAD
  lacks an explicit publication ref
- **THEN** parity SHALL be unavailable with no invented target

#### Scenario: Remote token names a local path

- **WHEN** a publication remote token is not an exact configured remote name
- **THEN** verification SHALL refuse it even if Git could resolve it as a path

#### Scenario: Local or remote snapshot moves during verification

- **WHEN** HEAD, index, scoped bytes, or observed remote OID changes before recheck
- **THEN** verification SHALL report unstable and SHALL NOT write a verified cache

#### Scenario: Remote object is absent locally

- **WHEN** exact OIDs differ and the remote object is not already local
- **THEN** MPD SHALL not fetch and SHALL report ancestry unavailable

### Requirement: Private bounded observation cache

Last-observation state SHALL be local, untracked, bounded, and free of remote
URLs, credentials, raw network output, source content, and environment values.

#### Scenario: Status uses cached observation

- **WHEN** a matching cached observation exists
- **THEN** status SHALL label its timestamp and last-observed nature and SHALL
  require fresh `publish --verify` for final closure

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
