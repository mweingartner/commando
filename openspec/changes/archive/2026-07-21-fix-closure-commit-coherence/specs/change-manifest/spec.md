# Change Manifest Delta

## MODIFIED Requirements

### Requirement: Archived closure commit

MPD SHALL archive before publication and SHALL verify each archived change against its
own landing commit: the earliest single-parent descendant of the archive base whose
parent diff (including rename origins) stays inside the closure's declared/system scope
and whose in-scope tree content is equivalent to the retained closure plan's expected
entries. Merge commits SHALL never be landing commits. Scope purity SHALL be asserted on
the landing commit itself; commits before or after it in the base-to-HEAD range belong
to other changes or other work, are policed at their own commit time by the pre-commit
staged-scope gate, and SHALL NOT be judged against this closure's scope. Commits after
the landing commit that edit files inside the closure scope are legitimate later history
and SHALL NOT be reported as corruption or coherence blockers.

Before a landing commit exists, MPD SHALL report readiness for the closure commit —
worktree scoped content matching the recorded post-archive digest, included-scope
cleanliness, and descent from the archive base — with the next action of committing the
exact archived result. When no landing commit can be located and readiness also fails,
MPD SHALL report that no commit matches the archived closure, with bounded diagnostics
naming differing in-scope paths of near-miss commits; a history rewrite that destroyed
the landing commit or the archive base SHALL fail closed with that accurate diagnosis.
A closure without a retained plan (legacy) SHALL be landing-verifiable only while the
worktree still matches its postimage and SHALL otherwise fail closed explicitly, never
silently pass. Worktree dirt SHALL never block verification of an already-landed change.

The staged scope of a pending awaiting-commit closure SHALL be the union of the
transaction's classified file operations and the retained closure plan's expected tree
entry paths, so a first-ever closure commit of the full expected tree is possible. A
missing closure plan (legacy closure) SHALL keep the classification-row scope; a
present but invalid, non-canonical, or differently-bound closure plan SHALL block the
commit. The scope SHALL never be narrowed below the validated plan entries.

Abandoning a pending closure SHALL NOT strand its uncommitted closure commit. When no
closure is pending, the coordinated change's ledger records an archive closure, and the
staged diff itself removes that change's active manifest (a staged deletion of
`openspec/changes/<change>/manifest.json`, or a rename whose origin is that path), the
staged check SHALL authorize the commit from the archive record: the closure's recorded
concrete scope footprint united with the retained closure plan's validated expected
entry paths, under the same concrete-path matching and the same policy-path exemptions
as a pending awaiting-commit closure. For a candidate-bound record, a retained plan
that is missing, malformed, non-canonical, or bound to a different transaction, base
commit, archive path, or candidate SHALL block the commit and SHALL never silently
narrow the scope; a pre-candidate legacy record SHALL keep the concrete-footprint
scope alone; a record with no recorded concrete footprint SHALL block. The staged
check SHALL never require the removed active manifest to be present in the index or
re-created, and its guidance SHALL never direct creating a copy of it. A change whose
active manifest is present in the index SHALL keep the ordinary declared-scope check
unchanged, including the protection of required governance artifacts against staged
deletion, rename, or copy.

#### Scenario: Archive completes

- **WHEN** `archive --yes` applies a valid plan
- **THEN** MPD SHALL record the pre-archive base commit, expected generated
  paths, final scoped digest, and state awaiting-commit

#### Scenario: Landing commit contains unrelated content

- **WHEN** the only commit whose in-scope tree matches the archived closure also
  touches a path outside the closure scope in its parent diff
- **THEN** it SHALL NOT qualify as the landing commit and verification SHALL report
  that no commit matches the archived closure

#### Scenario: Later commit edits archived-scope files

- **GIVEN** a change landed at its landing commit
- **WHEN** a later legitimate commit modifies files inside that closure's scope
- **THEN** the change's verification SHALL still locate its landing commit and SHALL
  report no content-mismatch or out-of-scope blocker

#### Scenario: Other changes share the commit range

- **WHEN** the base-to-HEAD range contains other changes' landing commits before or
  after this change's landing commit
- **THEN** this change's verification SHALL report no blockers for those commits

#### Scenario: History rewrite destroys the landing commit

- **WHEN** a rewrite (e.g. filter-branch) changed the landed in-scope content or removed
  the archive base from history
- **THEN** verification SHALL fail closed, naming the missing landing or base and the
  bounded set of differing in-scope paths, and SHALL NOT attribute the failure to other
  changes' commits

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

#### Scenario: Closure commit after the pending transaction was abandoned

- **GIVEN** `archive --yes` completed and `archive --abandon --yes` ran before the
  closure commit
- **WHEN** the operator points the change coordinator at the archived change and the
  exact archived result is staged, including the removal of the change's active
  manifest
- **THEN** the staged check SHALL authorize every staged path within the archive
  record's concrete footprint united with the validated plan entries and SHALL NOT
  demand the active manifest in the index

#### Scenario: Closure-shaped commit without an archive record

- **WHEN** the staged diff removes the coordinated change's active manifest but that
  change's ledger records no archive closure
- **THEN** the commit SHALL be blocked by the ordinary governance-artifact protection
  and no archive-record authorization SHALL engage

#### Scenario: Abandoned closure commit carries unrelated content

- **WHEN** the abandoned closure's staging also contains a path outside the archive
  record's concrete footprint united with the plan entries
- **THEN** the staged check SHALL block the commit naming that path

#### Scenario: Abandoned closure with an unusable retained plan

- **WHEN** the archived change's record is candidate-bound and its retained plan is
  missing, invalid, or bound to a different transaction, base commit, archive path, or
  candidate
- **THEN** the staged check SHALL block the commit with that reason and SHALL NOT
  narrow authorization to the concrete footprint alone

#### Scenario: No coordinator after abandonment

- **WHEN** no change coordinator is set and the staged diff removes an archived
  change's active manifest
- **THEN** the block message SHALL name that change and the coordinator-recovery next
  action, SHALL state that the closure commit belongs before abandonment, and SHALL
  NOT direct re-creating the active manifest
