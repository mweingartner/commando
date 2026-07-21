# Change Manifest Delta

## MODIFIED Requirements

### Requirement: Archived closure commit

MPD SHALL archive before publication and SHALL require a clean descendant commit
whose base-to-HEAD change set and final scoped content match the recorded
post-archive closure.

The staged scope of a pending awaiting-commit closure SHALL be the union of the
transaction's classified file operations and the retained closure plan's expected tree
entry paths, so a first-ever closure commit of the full expected tree is possible. A
missing closure plan (legacy closure) SHALL keep the classification-row scope; a
present but invalid, non-canonical, or differently-bound closure plan SHALL block the
commit. The scope SHALL never be narrowed below the validated plan entries.

#### Scenario: Archive completes

- **WHEN** `archive --yes` applies a valid plan
- **THEN** MPD SHALL record the pre-archive base commit, expected generated
  paths, final scoped digest, and state awaiting-commit

#### Scenario: Commit contains unrelated content

- **WHEN** base-to-HEAD contains a path outside the archived closure scope
- **THEN** commit coherence SHALL be blocked and remote parity SHALL not verify

#### Scenario: Intermediate commit adds then deletes unrelated content

- **WHEN** any commit after the archive base touches an out-of-scope path even if
  a later commit removes it before HEAD
- **THEN** the per-commit path union SHALL block coherence

#### Scenario: Operator asks for parity before archive commit

- **WHEN** archive is pending or its result is uncommitted/dirty
- **THEN** MPD SHALL report the exact blocker and MUST NOT claim publication

#### Scenario: Active change directory has been archived

- **WHEN** archive moved the active directory and the closure commit is pending
- **THEN** zero-argument status, staged checking, and publish SHALL resolve the
  single pending closure and protect its scope rather than report no current change

#### Scenario: Archive is interrupted around the directory move

- **WHEN** a pending pointer exists in archiving state and active/archive paths
  reveal partial completion
- **THEN** MPD SHALL fail closed and offer deterministic metadata recovery without
  repeating the merge or deleting user content

#### Scenario: First-ever closure commit

- **WHEN** the pending closure's plan lists source paths never previously committed and
  those paths are staged
- **THEN** the staged check SHALL accept every path within the union of transaction
  rows and plan entries and SHALL still block any staged path outside that union

#### Scenario: Retained closure plan fails validation at commit time

- **WHEN** a closure plan exists for the pending transaction but is malformed,
  non-canonical, oversized, or bound to a different transaction
- **THEN** the pre-commit check SHALL block the commit rather than fall back to the
  narrower row-only scope

### Requirement: Journaled archive transaction

Before the first archive target changes, MPD SHALL durably stage every postimage
and a versioned journal binding every target's contained path, explicit preimage,
postimage digest/mode, and the source/destination directory-tree identities.

Archive input validation SHALL fail closed as an ordinary reported error and SHALL
never panic: a validation failure discovered while constructing the closure plan SHALL
be reported before the transaction is prepared, leaving no pending transaction and no
modified repository bytes.

#### Scenario: Crash follows any target replacement

- **WHEN** recovery finds a target at its exact preimage or postimage
- **THEN** it SHALL install the recorded staged postimage or leave the exact
  postimage unchanged without rerunning merge/render/synthesis

#### Scenario: Recovery finds an unexpected third state

- **WHEN** any target, staged file, or directory identity matches neither the
  journaled preimage nor postimage contract
- **THEN** recovery SHALL stop manual-recovery-required without another write

#### Scenario: Platform cannot promise atomic replacement

- **WHEN** filesystem/platform replacement or directory sync has weaker guarantees
- **THEN** MPD SHALL retain staged recovery data, report the durability level,
  and SHALL NOT claim stronger power-loss atomicity

#### Scenario: Recovery is previewed

- **WHEN** the operator runs `mpd closure recover` without `--yes`
- **THEN** MPD SHALL make no write and SHALL report stage, write eligibility,
  durability level, affected-path count, bounded classifications, and next action

#### Scenario: Eligible recovery is confirmed

- **WHEN** every pending target is exact preimage with exact staged postimage and
  the operator runs `recover --yes`
- **THEN** MPD SHALL perform completion-only roll-forward and SHALL NOT claim
  rollback or filesystem-independent atomicity

#### Scenario: Third-state recovery is confirmed

- **WHEN** any third state makes write eligibility false and `recover --yes` runs
- **THEN** MPD SHALL refuse before writing and direct explicit manual repair

#### Scenario: Abandonment is confirmed

- **WHEN** transaction state is AwaitingCommit and `closure abandon --yes` runs
- **THEN** MPD SHALL delete only owned ignored transaction metadata and preserve
  repository bytes, ledger history, index, commits, and remote state

#### Scenario: Late closure-plan validation fails

- **WHEN** archive input validation fails while the closure plan is being constructed
  (for example a durable-documentation path outside the manifest or an unreadable
  retained manifest)
- **THEN** `archive --yes` SHALL exit nonzero with the specific error, SHALL NOT
  panic, and SHALL leave no pending transaction and no modified target
