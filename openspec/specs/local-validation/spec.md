# Local Validation

## Requirements

### Requirement: Exact immutable commit validation

Explicit `mpd validate --commit <oid>` SHALL continue to materialize and validate only
that immutable commit and may publish clone-local Commit evidence. It SHALL not substitute
for candidate gates, incorporate dirty worktree bytes, or publish Candidate receipts as
Git notes.

#### Scenario: Explicit commit validation with dirty worktree

- **WHEN** a caller validates a locally resolvable commit while unrelated worktree bytes
  are dirty
- **THEN** only the named commit SHALL be validated and output SHALL state that the
  worktree candidate remains a separate subject

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

### Requirement: Typed bounded local profiles

MPD SHALL define versioned named checks as typed program/argv, timeout, result policy,
and required tool identities. Required Build, Security(code), Test, pre-push, and high-
risk profiles SHALL run offline with a cleared allowlisted environment, private writable
roots, mandatory current-host network/outside-write denial, concurrent stdout/stderr and
aggregate caps, monotonic deadlines, process-group termination/reap, and bounded redacted
logs. Timeout, truncation, missing capability, malformed result, leaked child, or cleanup
failure SHALL be BLOCKED.

On macOS, authoritative execution SHALL use only the exact-host dynamic-extension
compatibility adapter defined for macOS 27.0 build `26A5378n`, Apple silicon,
`aarch64-apple-darwin`. The helper SHALL accept one bounded nonce-bound canonical request
over a private close-on-exec control descriptor. Filesystem roots SHALL derive only from
the accepted candidate, policy, tool/SDK/cache inventory, and private runtime state; they
SHALL NOT derive from argv, environment, display text, or candidate-controlled config.
Before sandbox entry the helper SHALL clear loader/environment inputs, close ambient
descriptors, validate root identity, and perform no candidate read or execution.

The adapter SHALL use one fixed reviewed custom profile without variable path filters.
It SHALL deny by default and deny all network operations; allow the required process and
sysctl operations; permit global file metadata/existence tests and literal-root data
required by the macOS 27 loader; permit file read/test/map only through read or
read-write extensions; and permit file writes only through a read-write extension plus
literal `/dev/null`. Output SHALL state that path metadata, root-directory entries, and
same-user process isolation are outside the certified claim.

For each run the helper SHALL issue exact canonical directory extensions with `flags=0`,
enter `sandbox_init(fixed_profile, 0)`, consume every token, verify every return, and
zeroize token text. `SANDBOX_EXTENSION_PREFIXMATCH` SHALL NOT be used. Read roots SHALL
be limited to the exact candidate, coordinator/program, pinned Rust/Homebrew dependency,
CLT/SDK, required system and `/dev` roots. One read-write root SHALL contain private
HOME/XDG/temp/build/output/test state. Root count/length SHALL be capped; roots SHALL be
sorted, role-checked, symlink-safe, and bound by canonical path/type/device/inode plus
applicable digests.

After entry the helper SHALL run allowed read/write, denied secret/`~/.gitconfig` read,
denied `/tmp` write, denied socket/loopback/outbound/DNS, child and grandchild inheritance,
symlink-escape, descriptor-closure, direct hidden-helper reinvocation, and post-entry
extension non-escalation canaries. It SHALL report READY bound to the request/profile/
root/canary digests and execute only after matching parent GO, after closing control.
Any host, symbol, ABI, profile, root, issue/init/consume, inheritance, denial, cleanup, or
canary mismatch SHALL be BLOCKED with no App Sandbox, `sandbox-exec`, broad-read,
unsandboxed, hosted, or other fallback.

Human and JSON output SHALL separately expose containment adapter, host, SPI/ABI, fixed
profile, root inventory, canaries, compiler process tree, full local profile, certified
claim, and residual limitations. Adapter and full-profile certification SHALL each be
`CERTIFIED` or `NOT CERTIFIED`; compiler-process-tree PASS SHALL remain feasibility
evidence and SHALL NOT imply full-profile certification. Each adapter BLOCKED result
SHALL contain exactly one code and the corresponding one safe action:

- `sandbox.host-drift`: run the unchanged candidate/policy on the exact certified host;
- `sandbox.spi-abi-drift`: return to Architecture for adapter revision;
- `sandbox.profile-drift`: run the printed digest-confirmed policy activation;
- `sandbox.root-drift`: return to Build and recapture candidate/root inventory;
- `sandbox.canary-failed`: return to Security(code) with the named failure/log; or
- `sandbox.full-profile-incomplete`: run the printed complete exact-host profile for the
  current candidate.

An unclassified adapter failure SHALL use `sandbox.spi-abi-drift`. The two renderings
SHALL derive from one typed result and SHALL NOT offer another action or act silently.

#### Scenario: Required tool or sandbox capability is unavailable

- **WHEN** a profile cannot prove the accepted executable/input identity or mandatory
  current-host denial canary
- **THEN** it SHALL run no weaker fallback and SHALL NOT issue a PASS receipt

#### Scenario: Candidate attempts to widen extension roots

- **WHEN** typed command argv, environment, candidate configuration, or direct hidden-
  helper reinvocation names a path outside the accepted root inventory
- **THEN** no extension SHALL be issued for that path and the sandboxed process SHALL
  remain unable to read its content or write it

#### Scenario: Bootstrap or extension sequence is incomplete

- **WHEN** the private control request is absent/malformed, an ambient descriptor remains,
  or any issue, sandbox-init, consume, zeroization, canary, READY, or GO step fails
- **THEN** the helper SHALL execute no candidate command and SHALL return BLOCKED

#### Scenario: Descendant tries to escape inherited containment

- **GIVEN** the helper has entered the fixed profile and consumed accepted extensions
- **WHEN** a child or grandchild execs a tool, re-invokes hidden helper mode, follows a
  symlink, or tries to issue/consume a new forbidden-path extension
- **THEN** accepted-root access SHALL remain available, forbidden content/write/network
  access SHALL remain denied, and no new authority SHALL be created

#### Scenario: Nested compiler probe passes but the full suite needs ambient state

- **WHEN** exact-root offline cargo/rustc/linker/test-binary compilation passes but any
  required test expects ambient Git identity, host process state, or system temp semantics
- **THEN** the adapter MAY report feasibility evidence but production certification SHALL
  remain BLOCKED until fixed private Git identity/config and private runtime/process state
  let the complete suite and canary matrix pass

#### Scenario: Test process exits zero without tests

- **WHEN** a Test result contains no verified non-zero pass count
- **THEN** Test SHALL fail or block rather than accept exit zero alone

#### Scenario: Narrow adapter proof exists without full-profile proof

- **WHEN** adapter fields and canaries are current and compiler-process-tree proof passes
  but the complete candidate-bound local profile is missing or incomplete
- **THEN** output SHALL keep the adapter certified, mark the full profile NOT CERTIFIED,
  return BLOCKED with `sandbox.full-profile-incomplete`, and display only its defined
  complete-profile action

### Requirement: Cooperative policy and hook activation

The only supported activation SHALL bind an immutable reviewed commit/policy digest,
absolute coordinator and executable digest, tracked hook source, and `.githooks` path
through an explicit confirmed `mpd policy activate` command. Activation SHALL report
ACTIVE or BLOCKED and be safe to rerun. There SHALL be no policy-bootstrap,
first-adoption, pretrust, candidate-script, PATH fallback, or silent activation route.

#### Scenario: Coordinator or hook drifts after activation

- **WHEN** doctor, pre-commit, or pre-push reopens accepted activation state
- **THEN** it SHALL block before candidate checks or ref authorization and show the exact
  reactivation action

### Requirement: Complete local pre-push authorization

Pre-push SHALL parse bounded real Git input, validate accepted policy for every batch,
resolve every non-deletion commit/tag subject, and scan every outgoing blob plus commit/
tag message, including objects introduced and removed within the outgoing range.
Authorization SHALL bind remote, baseline, rows, complete object set, policy, result, and
invocation nonce and SHALL not be reusable.

Outgoing blobs SHALL be scanned under their repo-relative tree paths, derived from the
per-commit diffs of the outgoing range, with the version-controlled secret allowlist
applied per path; every suppression SHALL be counted and reported. A blob whose path
cannot be derived or validated SHALL be scanned under a synthetic object name with no
allowlist applied, and commit/tag messages SHALL never be allowlisted. A finding
suppressed under one path but present under another mapped path SHALL still deny the
push. Path-mapping enumeration SHALL be capped, and cap overflow or parse failure SHALL
deny the push rather than skip any object.

Deletion-only SHALL still run trust, policy, input, and ref checks. Deletion of `main` or
any tag SHALL be denied. Other deletion approval SHALL atomically bind and consume once:
remote name/location digest, raw ref bytes, old OID, zero new OID, complete batch and
baseline digest, policy digest, and nonce. Git, not MPD, SHALL own transport.

#### Scenario: Deletion-only protected ref update

- **WHEN** pre-push receives deletion of `refs/heads/main` or `refs/tags/**`
- **THEN** it SHALL deny before approval lookup and SHALL NOT treat the empty outgoing
  object set as authorization

#### Scenario: Allowlisted fixture blob is pushed

- **WHEN** an outgoing blob's only tree paths match the repository's secret allowlist
  for its findings
- **THEN** pre-push SHALL suppress those findings, report the suppression count, and
  authorize the push

#### Scenario: Same secret content at an allowlisted and a source path

- **WHEN** one outgoing blob object is introduced at both an allowlisted fixture path
  and a non-allowlisted path
- **THEN** pre-push SHALL scan it under every mapped path and SHALL deny the push for
  the non-allowlisted occurrence

#### Scenario: Unmapped blob keeps full strictness

- **WHEN** an outgoing blob has no derivable validated tree path
- **THEN** pre-push SHALL scan it under a synthetic object name with no allowlist
  applied

### Requirement: Candidate-bound no-exec Deploy

Build SHALL record one candidate ID and parent-opened release artifact identity. Deploy
SHALL reopen that exact output, copy through an exclusive target-directory temporary,
sync, atomically replace, reopen, and compare mode/length/digest. It SHALL not rebuild or
execute candidate or installed bytes to establish identity. Readiness-only SHALL record
`executed=false` and `verified=false`.

#### Scenario: Installed candidate has an identity command

- **WHEN** Deploy verifies the installed path
- **THEN** it SHALL use parent-observed file metadata and digest only; a spawn sentinel
  SHALL prove the installed executable was not run

### Requirement: Worktree external-scanner scope

Filesystem-mode external secret scans invoked by MPD SHALL exclude build-artifact
directories through a configuration that extends the scanner's default rules, SHALL
leave the invocation unchanged when the repository provides its own scanner
configuration, and SHALL fall back to the unexcluded scan — never a skipped scan — when
the exclusion cannot be prepared.

#### Scenario: Repository without its own scanner config

- **WHEN** the worktree external secret scan runs in a repository with no scanner
  config of its own and findings exist only under the build-artifact directory
- **THEN** the scan SHALL report clean while default rules remain in force elsewhere

#### Scenario: Repository owns its scanner config

- **WHEN** the repository root provides its own scanner configuration
- **THEN** MPD SHALL invoke the scanner without overriding that configuration

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

### Requirement: Scanner-clean first-party source

First-party source and assets under `crates/` SHALL contain no contiguous text
that the built-in secret scanner's rules match. Realistic secret fixtures SHALL
be assembled at runtime from split literals so detection and redaction tests
keep their full-strength runtime values while the source text matches no rule;
this applies uniformly to fixtures, assertions, rule-definition literals, and
production constants. The standard test lane SHALL enforce the invariant with a
meta-test that scans the tree using the production scan functions themselves —
never a parallel pattern list — and fails on any finding. A suppression SHALL
require an explicit in-test allow entry scoped to path and rule with a written
justification, SHALL never cover a full-token-shaped literal, and the
version-controlled secret allowlist SHALL NOT carry whole-file suppressions for
first-party source files.

#### Scenario: Contiguous fixture is reintroduced

- **WHEN** a file under `crates/` gains contiguous text matching any built-in
  secret-detection rule
- **THEN** the meta-test SHALL fail in the standard test lane, reporting the
  file, line, and rule, before commit or push gates are ever reached

#### Scenario: Scanner rules stay split in their own source

- **WHEN** the scanner defines or tests a rule whose bare pattern text would
  match that rule
- **THEN** the source SHALL carry the pattern only in compile-time split form
  with identical compiled bytes, and the meta-test SHALL pass with no allow
  entry for the scanner's own files

#### Scenario: Gates rescan formerly suppressed source files

- **WHEN** commit or pre-push scanning covers a first-party source file that
  previously had a whole-file allowlist suppression
- **THEN** findings in that file SHALL be reported and SHALL deny the
  operation; suppression SHALL NOT be restorable by a whole-file entry

#### Scenario: New rule makes existing source self-match

- **WHEN** a detection rule is added or extended such that existing first-party
  source text matches it
- **THEN** the meta-test SHALL fail until that text is converted to split form
  in the same change that alters the rule
