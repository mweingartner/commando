# Remote Parity Delta

## MODIFIED Requirements

### Requirement: Non-pushing remote observation

`mpd publish` SHALL report readiness and `mpd publish --verify` SHALL observe the
configured remote/ref without pushing, force-pushing, creating refs, staging,
committing, archiving, or deploying.

#### Scenario: Landing commit is on the remote

- **WHEN** a stable observation finds the change's landing commit equal to, or a
  locally provable ancestor of, the freshly observed remote ref OID
- **THEN** the change's publication SHALL be verified for that observation time, even
  when the local ref carries later commits beyond the landing commit

#### Scenario: Network is unavailable

- **WHEN** bounded remote observation fails or times out
- **THEN** parity SHALL be offline, local evidence SHALL remain intact, and the
  command SHALL not report divergence

### Requirement: Publication remains observational

`mpd publish --verify` SHALL perform fresh bounded observation of the exact configured
remote/ref and compare it with the change's own landing commit — never the whole
base-to-HEAD range, the current worktree bytes, or included-scope cleanliness of an
already-landed change. Ref-level state (verified, ahead, behind, diverged, rewritten,
unstable, ancestry-unavailable) SHALL continue to be classified between local HEAD and
the remote OID as separate information. It SHALL NOT validate a candidate, write gate
or validation evidence, activate hooks, fetch, push, deploy, or install. The bounded
observation cache MAY additionally record the landing commit OID; the field SHALL be
additive and optional so prior caches remain readable.

#### Scenario: Remote observation is unavailable

- **WHEN** the configured remote cannot be resolved or contacted
- **THEN** publication SHALL report unavailable/offline without changing local gate,
  archive, commit, authorization, or install facts

#### Scenario: Local ref is ahead of the landing commit

- **GIVEN** the change landed and later legitimate commits exist locally and remotely
- **WHEN** the stable remote OID contains the landing commit
- **THEN** the change's verification SHALL succeed while the ref-level classification
  still reports the actual HEAD-to-remote relationship

#### Scenario: Remote object is absent locally

- **WHEN** the observed remote OID is neither the landing commit nor locally present
  for ancestry proof
- **THEN** MPD SHALL not fetch and SHALL report ancestry unavailable rather than
  claiming the closure landed remotely
