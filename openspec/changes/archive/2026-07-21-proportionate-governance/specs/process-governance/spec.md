# Process Governance Delta

## MODIFIED Requirements

### Requirement: Effective risk cannot be lowered

MPD SHALL store requested, versioned derived, and effective risk with reasons and signal
digest. Effective risk SHALL be the maximum of requested and derived risk. The derived
classifier SHALL conservatively classify auth/credentials, untrusted parsing, network,
process execution, Git/hooks, persistence, sandboxing, cryptography, deployment, and
unknown additions under sensitive roots as High.

A change whose declared scope is provably documentation-only under a fail-closed
allowlist predicate — every declared pattern (including shared paths) is literally and
case-sensitively contained in `docs/`, `openspec/specs/`, the change's own
`openspec/changes/<change>/` directory, or is a single-segment root pattern ending in
the literal `.md` — MAY derive Low: for such a scope the classifier SHALL suppress only
synthetic signals (repository-configuration signals and keyword matches on
allowlisted documentation paths), SHALL record the predicate outcome and every
suppressed signal in the reasons and signal digest, and SHALL never lower the requested
risk. An empty, mixed, unknown, or wildcard-prefixed scope SHALL NOT qualify and SHALL
receive the full conservative derivation. The predicate SHALL be covered by seeded
property tests, including the law that adding any pattern never turns a non-qualifying
scope into a qualifying one.

#### Scenario: Operator requests Low for hook changes

- **WHEN** declared scope includes `.githooks/**` or accepted hook policy
- **THEN** derived/effective risk SHALL be High and neither flags nor candidate config
  SHALL lower it

#### Scenario: Documentation-only scope on a deployment-configured repository

- **WHEN** a change declares only patterns within the documentation allowlist and the
  repository configures deployment and structured local validation
- **THEN** derived risk SHALL be Low, the suppressed synthetic signals SHALL be listed
  in the assessment reasons and bound into the signal digest, and effective risk SHALL
  remain the maximum of requested and derived

#### Scenario: Mixed scope keeps full derivation

- **WHEN** a change declares one documentation pattern and one pattern outside the
  allowlist (for example `crates/**` or `.mpd/config.json`)
- **THEN** the documentation predicate SHALL NOT hold, no signal SHALL be suppressed,
  and derived risk SHALL follow the full conservative classifier

#### Scenario: Requested High on a documentation-only change

- **WHEN** an operator requests High risk for a change whose scope qualifies as
  documentation-only
- **THEN** effective risk SHALL be High and every High-rigor obligation SHALL apply

## ADDED Requirements

### Requirement: Proportionate validation for documentation-only scope

MPD MAY select configured lighter validation profiles (`docs-build`,
`docs-security-code`, `docs-test`) for the strict Build, Security(code), and Test gates
only when the documentation-only scope predicate holds against the live manifest at
gate time and effective risk is Low. Selection SHALL use one shared decision for gate
execution and status reporting. A selected documentation profile SHALL resolve to at
least one secret-scan check, and the documentation build and test profiles SHALL
additionally resolve to at least one doc-staleness check; a profile missing this floor
SHALL block the gate with an explicit configuration blocker rather than silently
falling back or skipping. Documentation profiles SHALL execute through the same
sandboxed candidate validator, receipts, and freshness dependencies as full profiles.
When the optional documentation gates are not configured, or the predicate does not
hold, or effective risk exceeds Low, MPD SHALL select the full profiles exactly as
before.

#### Scenario: Unconfigured repository is unchanged

- **WHEN** a repository's gate configuration declares no documentation profiles
- **THEN** every change, including a documentation-only one, SHALL run the full
  configured profiles unchanged

#### Scenario: Documentation lane floor is violated

- **WHEN** a configured documentation profile resolves without a secret-scan check
- **THEN** the gate SHALL block with an explicit configuration blocker and SHALL NOT
  run the profile or silently substitute another

#### Scenario: Code-scoped change cannot reach the lighter lane

- **WHEN** a change's declared scope includes any pattern outside the documentation
  allowlist
- **THEN** Build, Security(code), and Test SHALL select the full profiles regardless of
  requested risk or configured documentation gates
