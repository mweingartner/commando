# Usage Attestation

## Requirements

### Requirement: Exact-attempt usage evidence

MPD SHALL accept bounded integer usage evidence only when it binds the exact change,
phase, attempt, actor, resolved model, artifact, and Candidate or planning subject.
Missing evidence SHALL be UNREPORTED and SHALL NOT be represented as zero.

#### Scenario: Required evidence is replayed

- **GIVEN** policy requires authenticated usage for the current gate
- **WHEN** a valid attestation is submitted for a different phase, attempt, subject, artifact, or model, or is submitted again for the same exact attempt
- **THEN** MPD rejects it before objective validation and records no PASS or usage

#### Scenario: Concurrent exact-attempt replay

- **GIVEN** two gate processes present the same otherwise valid attestation for one exact attempt
- **WHEN** each reaches attestation preflight
- **THEN** the ledger lock durably claims the evidence digest for one process before objective execution, the other refuses as replayed, and a later objective failure does not release the claim

#### Scenario: Cooperative legacy gate

- **GIVEN** the repository has not enabled required attestation
- **WHEN** attestation is optional and no evidence is supplied
- **THEN** the gate retains existing behavior and reports cooperative provenance with UNREPORTED usage

### Requirement: Privacy-safe normalized storage

MPD SHALL store only bounded normalized counters, identities, state, and evidence digests;
it SHALL NOT store prompts, source contents, private keys, credentials, or raw model output.

#### Scenario: Hostile structured input

- **GIVEN** an attestation file is treated as untrusted bounded input
- **WHEN** evidence contains duplicate keys, floats, overflow, controls, oversized fields, or an unsupported signature algorithm
- **THEN** parsing fails closed without reflecting raw input or changing state

### Requirement: Activated-policy-bound issuer material

An issuer public key or locator SHALL be accepted only from activated reviewed policy. A
locator SHALL be a bounded canonical path under the fixed clone-private trust root, be
opened no-follow, and match the configured digest; ambient, network, candidate-controlled,
or symlinked material SHALL be refused.

#### Scenario: Trust-root substitution

- **GIVEN** configured issuer material is replaced, symlinked, or its digest drifts
- **WHEN** a required authenticated attestation is verified
- **THEN** verification fails closed before objective execution and no fallback key is used
