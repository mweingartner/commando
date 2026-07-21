# Local Validation Delta

## MODIFIED Requirements

### Requirement: Exact worktree candidate

At Build, MPD SHALL create one deterministic candidate from base HEAD plus every declared
manifest-scoped staged/unstaged tracked postimage, declared untracked postimage, deletion,
and executable-mode change. Out-of-scope dirty paths SHALL retain base bytes and be
reported. Candidate capture SHALL not change the source worktree, index, refs, or object
database.

Candidate paths SHALL be canonical and collision-free. Bytes SHALL come from bounded
no-follow regular-file descriptor reads with pre/open/post metadata checks. Symlinks,
gitlinks, special files, unmerged state, cap overflow, or status/metadata drift SHALL
block. The sorted path/state/mode/length/SHA-256 inventory, base identity, manifest, and
policy SHALL determine a domain-separated candidate ID. The projection SHALL be rehashed
before and after Build, Security(code), and Test.

Active MPD process state SHALL be absent from candidate-visible inputs and SHALL not
affect candidate identity: the live `.mpd/state/**` ledger, `.mpd/current`, pending-
closure and parity observations, Build/install outputs, local receipts/logs/caches, and
every clone-private `.git/mpd/**` path are excluded. Already-committed historical ledger
files remain inert base-tree bytes and SHALL never select the active change. Live gate/
freshness state, Build output, and installed bytes SHALL bind through their separate
typed evidence. Durable declared `.mpd/config.json`, `.mpd/directives/**`, tracked hooks,
security policy, and tool inputs remain candidate content.

The candidate ID SHALL remain pure content identity. A cached clone-private projection
record additionally carries attempt-variant process state (base commit for the identical
tree, overlay/status digests, excluded-dirty inventory and counts, retained-root
filesystem identity) that is intentionally outside the ID. A leftover record or retained
root from a superseded attempt SHALL never hard-stall a legitimate re-capture of the same
content: when the record's content-identity fields (schema, subject version, owning
change, base tree, manifest/entries/policy/source digests, ID, and full entry inventory)
match the fresh capture and only attempt-variant fields differ, capture SHALL atomically
refresh the record (durable staged replace with post-replace verification) and proceed.
Refresh SHALL be refused fail-closed when any content-identity field disagrees, when the
record belongs to a different change, or when the capturing change's authoritative gate
map currently binds that candidate ID. An orphaned record whose retained root is absent
SHALL be evicted under the same preconditions and capture SHALL republish freshly.
Reopening a ledger-bound capture SHALL keep exact-binding strictness; refresh applies
only at capture time.

#### Scenario: Staged and unstaged bytes differ

- **WHEN** the same declared path has staged content and a later unstaged postimage
- **THEN** candidate capture SHALL use the final worktree postimage, report the state,
  and produce an ID different from either HEAD or the staged-only image

#### Scenario: Capture races a file or Git-state change

- **WHEN** file identity, HEAD, index identity, or normalized status changes during
  capture or rehash
- **THEN** capture SHALL clean only its owned temporary projection, return BLOCKED, and
  leave Git/worktree state unchanged

#### Scenario: Process state changes after capture

- **GIVEN** one current candidate has been captured
- **WHEN** MPD writes its live ledger/current/pending/parity/log/cache/output state
- **THEN** the candidate ID and rehash SHALL remain unchanged and candidate checks SHALL
  be unable to read those live paths as product inputs

#### Scenario: Declared governance input changes after capture

- **GIVEN** one current candidate has been captured
- **WHEN** declared config, directive, hook, security policy, or tool input changes
- **THEN** candidate rehash/freshness SHALL become STALE or BLOCKED and SHALL require a
  new Build candidate before another downstream effect

#### Scenario: Superseded attempt leaves a stale projection record

- **GIVEN** a cached projection record whose content-identity fields match a fresh
  capture but whose base commit, overlay/status digests, excluded-dirty state, counts,
  or retained-root filesystem identity differ
- **WHEN** the same change captures the same content with no live gate binding that
  candidate ID
- **THEN** capture SHALL atomically refresh the record, keep the verified retained root,
  and succeed without manual cleanup

#### Scenario: Stale record disagrees on content identity

- **WHEN** a cached record's schema, subject identity digests, ID, or entry inventory
  disagree with the fresh capture, or the record names a different change
- **THEN** capture SHALL fail closed without evicting or modifying the record

#### Scenario: Stale record is bound by a live gate

- **WHEN** the capturing change's authoritative gate map currently binds the colliding
  candidate ID
- **THEN** capture SHALL fail closed with rewind guidance and SHALL NOT modify the
  record or retained root

#### Scenario: Projection record exists without its retained root

- **WHEN** capture finds an orphaned record with no retained root, owned by the same
  change and not bound by any authoritative gate
- **THEN** capture SHALL evict the orphan and republish a fresh record and root

## ADDED Requirements

### Requirement: Authoritative Build-output binding

The exported candidate Build output SHALL be considered ledger-bound only by records in
the change's authoritative latest-per-phase gate map that carry a typed Build output
naming that candidate ID. Superseded records retained in append-only history — including
records invalidated by freshness or governance rewinds — SHALL never bind, and a record
that references a candidate without a typed Build output (Security (code), Test, or any
FAIL) SHALL never bind and SHALL never be an error. A live authoritative binding SHALL
still refuse re-export at the same path and SHALL fail closed on a different path, and
the per-candidate output lock SHALL be held before the binding check.

#### Scenario: Rewound binding does not poison re-export

- **GIVEN** a freshness rewind to Build whose superseded history retains a Build PASS
  with typed output and Security (code)/Test records referencing the same candidate
- **WHEN** Build re-runs and re-exports the identical candidate's output
- **THEN** the export SHALL succeed and the new gate record SHALL bind the fresh output

#### Scenario: Live binding still blocks double export

- **WHEN** the authoritative gate map carries a typed Build output for the candidate at
  the same path
- **THEN** re-export SHALL be refused, and a typed binding at a different path SHALL
  fail closed

#### Scenario: Candidate-referencing record without typed output

- **WHEN** the ledger contains records referencing the candidate ID without a typed
  Build output
- **THEN** the binding check SHALL treat them as non-binding and SHALL NOT error
