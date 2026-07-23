# Review Provenance

## Requirements

### Requirement: Authenticated review provenance

When configured, MPD SHALL verify an attestation issuer and exact opaque model/session
identity for the gate attempt. Authentication proves provenance only and SHALL NOT be
described as proof of review quality.

The only accepted authenticated format in this release SHALL be `sshsig-ed25519-v1`: a
fixed-field length-delimited canonical `AttestationPayloadV1`, verified only by the
tool-lock-bound absolute `/usr/bin/ssh-keygen -Y verify` with fixed namespace
`mpd-attestation-v1` and exact issuer/key identity. JSON transport SHALL NOT itself be
signed. Issuer keys SHALL use one comment-free canonical OpenSSH `ssh-ed25519` encoding;
the message, allowed-signers line, and SSHSIG envelope SHALL be bounded private per-run
files and cleaned after verification. Algorithm agility, ambient PATH, dynamic crypto
tools, and unsigned fallback are forbidden.

#### Scenario: Signed transport ambiguity

- **GIVEN** an envelope has valid-looking JSON but a changed field order, duplicate key,
  noncanonical OpenSSH key, wrong SSHSIG namespace/identity, unsupported algorithm, or
  signature over transport bytes instead of the canonical payload
- **WHEN** provenance is required
- **THEN** MPD rejects it before objective execution without trying another algorithm or key

### Requirement: Typed verifier refusal surface

MPD SHALL report the completed verifier state as `LOCKED`, `BLOCKED`, `INVALID`, or
`REPLAYED` with one bounded stable refusal code. Tool-lock drift or an unavailable verifier
is `BLOCKED`; an invalid namespace, signature, or exact issuer key is `INVALID`; a durably consumed
exact-attempt envelope is `REPLAYED`. These states SHALL never be presented as a verdict on
review quality or as a passed gate.

#### Scenario: Required verifier cannot be used

- **GIVEN** required authentication is active
- **WHEN** the tool lock drifts, `/usr/bin/ssh-keygen` is unavailable, verification fails,
  issuer trust-root material mismatches, or the exact envelope was already consumed
- **THEN** MPD prints and emits the matching terminal-safe typed state/code, performs no
  objective validation, and does not fall back to another verifier, key, or algorithm

#### Scenario: Independent review required

- **GIVEN** trusted policy requires an independent review session
- **WHEN** policy requires independence and the review attestation uses the current review subject's session
- **THEN** MPD blocks the gate as SAME SESSION before objective execution

#### Scenario: Actor labels alternate without session evidence

- **GIVEN** only cooperative actor strings are available
- **WHEN** actor strings differ but no trusted session evidence exists
- **THEN** independence is UNKNOWN and cannot satisfy authenticated independence

### Requirement: Fail-closed readiness before external deployment

MPD SHALL ship external-issuer verification and fail closed when required authentication is
activated, but Commando SHALL keep that mode cooperative/optional and report `NOT DEPLOYED`
until a real external issuer supplies an exact-session attestation. Fixtures and
owner-self-signed claims are test-only and SHALL NOT activate the deployment state.

#### Scenario: No real issuer is configured

- **GIVEN** Commando has shipped verifier code and conformance fixtures but has no trusted
  external issuer producing exact-session attestations
- **WHEN** provenance readiness is rendered
- **THEN** it reports cooperative/optional provenance and required authentication as
  `MISSING` and `NOT DEPLOYED`, while a policy that nevertheless requires it fails closed

### Requirement: Coverage-aware provenance reporting

Status and stats SHALL report required, authenticated, independent, same-session,
missing, and invalid counts without silently dropping unreadable ledgers.

#### Scenario: Mixed historical coverage

- **GIVEN** legacy and current gate records are both readable
- **WHEN** only some required gates carry current authenticated evidence
- **THEN** human and JSON output report the numerator/denominator and missing states
