# Operator Recovery

## Requirements

### Requirement: Typed hook diagnosis

Doctor SHALL distinguish a valid activated trusted wrapper, a manual MPD hook, and a
missing/drifted/untrusted hook using activation/coordinator/policy identity rather than
marker text alone. JSON SHALL expose typed state and retain a compatibility boolean.

#### Scenario: Activated trusted wrapper

- **GIVEN** `core.hooksPath` names the clone-private activated wrapper
- **WHEN** the wrapper and current trusted activation/coordinator identities validate
- **THEN** doctor reports installed activated-trusted and does not suggest `mpd init`

### Requirement: Archived-current status recovery

Status SHALL remain read-only and usable when `.mpd/current` names archived, pending,
AwaitingCommit, or closed state. It SHALL NOT manufacture an active manifest/Candidate;
`next` and `gate` SHALL continue to refuse archived targets.

#### Scenario: Current points to AwaitingCommit archive

- **GIVEN** `.mpd/current` still names the archived change
- **WHEN** the active manifest has moved to archive
- **THEN** status reports archived-current and the exact next action without rewriting `.mpd/current`

### Requirement: Direct doctrine supersession

The doc checker SHALL validate direct visible supersession banners against canonical
current targets, reject dangling/noncanonical targets, chains and cycles, and detect a
finite configured set of contradictory doctrine keys. It SHALL NOT claim general
semantic proof.

#### Scenario: Known doctrine conflict

- **GIVEN** a finite doctrine key and canonical replacement are configured
- **WHEN** an unmarked document asserts a configured superseded doctrine
- **THEN** the checker names both documents and the doctrine key and fails

### Requirement: Identity-safe candidate cache cleanup

Cache inspection and preview SHALL be read-only. Confirmed pruning SHALL remove only
identity-verified clone-private orphan candidates after checking all live ledger,
archived ledger, pending archive, Build output, and current receipt references. Effects
SHALL use descriptor-relative no-follow operations anchored in the fixed cache parent,
atomically move the verified entry to a same-parent private quarantine, and revalidate
identity there before deletion. Ambiguous entries remain BLOCKED.

#### Scenario: Entry is replaced after preview

- **GIVEN** preview identified a clone-private orphan by its sidecar and opened identity
- **WHEN** a candidate or sidecar identity changes before confirmed deletion
- **THEN** MPD retains it, reports BLOCKED, and does not affect receipts, logs, policy, tools, Git/source, Build, or installed output
