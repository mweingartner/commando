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
