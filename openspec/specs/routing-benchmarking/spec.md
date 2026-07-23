# Routing Benchmarking

## Requirements

### Requirement: Offline blind routing evaluation

MPD SHALL evaluate bounded versioned benchmark evidence without network access. Evidence
must identify blind rubric/task digests, seeded samples, minimum sample counts, and
quality, escapes, rework, latency, tokens, and currency-specific cost.

The reviewed Codex configuration SHALL assign the Documenter route to the user-authorized
Terra model. A real blind suite covers every configured route under comparison after that
change (Sol and Terra); unavailable Luna samples SHALL NOT be fabricated or counted.

#### Scenario: Evidence is insufficient

- **GIVEN** routing evaluation has no network or provider fallback
- **WHEN** evidence is unblinded, undersampled, stale, missing a required metric, invalid, or mixes currencies in a comparison
- **THEN** MPD reports the reason and produces no applicable recommendation

#### Scenario: Configured-route coverage is unavailable

- **GIVEN** the suite lacks sufficient actual blind sessions for configured Sol or Terra
- **WHEN** routing evidence is evaluated
- **THEN** MPD reports `MISSING` or `INSUFFICIENT`, preserves the mapping, and does not
  substitute fixtures or Luna samples

#### Scenario: Current route is nondominated

- **GIVEN** sufficient blind versioned evidence covers the current route
- **WHEN** current routing is Pareto-eligible under sufficient evidence
- **THEN** MPD recommends no change and does not call the route globally optimal

### Requirement: Preview-first guarded application

Routing evaluation SHALL be read-only. Application SHALL preview an exact deterministic
role mapping and evidence digest; only explicit confirmation after concurrent-digest
revalidation may atomically update reviewed routing/model fields. The writable roles and
harnesses SHALL be derived from an existing reviewed allowlist, not evidence labels; apply
SHALL reject additions, deletions, cross-harness mappings, and any non-routing config delta.

#### Scenario: Configuration changes after preview

- **GIVEN** a deterministic preview recorded the prior config digest
- **WHEN** the config digest differs before the confirmed write
- **THEN** apply refuses without partial mutation

#### Scenario: Evidence attempts target-scope escalation

- **GIVEN** otherwise sufficient evidence names a role or harness outside the reviewed routing target allowlist
- **WHEN** an operator previews or confirms apply
- **THEN** MPD refuses before writing and leaves all model and non-routing config entries unchanged
