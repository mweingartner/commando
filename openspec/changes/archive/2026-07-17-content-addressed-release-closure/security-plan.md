# Security plan: content-addressed release closure

## Scope and threat model

Reviewed the revised proposal, 492-line design, delta specifications, tasks, and
current Rust boundaries for config/state reads, Git invocation, path containment,
terminal rendering, and archive mutation. The declared profile is
`local-untrusted-input`: tracked/untracked paths, manifests, refs, Git output,
and fetched remote objects are hostile. The local OS user and their intentional
`.git/config`/credential configuration remain trusted, but repository content
must not turn a read/verify operation into command execution, secret disclosure,
false evidence reuse, or false publication.

The canonical binary stream, SHA-256 domain separation, strict path/ref syntax,
NUL Git parsing, symlink non-following, explicit deletion/gitlink modeling,
versioned schemas, non-reusable Deploy evidence, ignored bounded caches, and
fail-closed legacy treatment are sound foundations. SHA-256 collision resistance
is sufficient here; no credible collision attack was found.

## Blocking findings

[HIGH] `openspec/changes/content-addressed-release-closure/design.md:404` ->
Endpoint `git diff base_commit..HEAD` does not reveal paths added and removed in
intermediate commits. A closure can therefore publish an out-of-scope file (for
example a credential committed and deleted in the next linear commit) while the
final endpoint diff and digest pass. Compute the union of NUL-delimited changed
paths for **every commit** in `base_commit..HEAD`, including every rename/copy
source and destination and deletion, and reject any out-of-scope path in any
commit. Continue separately checking the final tree/digest and expected archive
mutations. Add a two-commit add-then-delete out-of-scope regression.

[HIGH] `openspec/changes/content-addressed-release-closure/design.md:337` -> The
proposed Build/Test snapshot is not a complete dependency snapshot: identical
source, command text, tool version text, and artifact digest do not bind OS/SDK,
compiler executable identity, safe environment inputs, test services, or other
external state. Explicit reuse could skip tests after a meaningful environmental
change while reporting exact-input validity. Default execution-bearing phases
(Build, Test, Security code, Deploy) to `always_execute`. Permit Build/Test or
Security-code reuse only through an explicit project opt-in that declares a
versioned hermetic dependency policy; bind platform/tool executable identity and
an allowlisted set of privacy-safe environment/input digests. Missing, unreadable,
or undeclared dependencies make the receipt non-reusable. Deploy remains fixed
non-reusable. Test default refusal and independent mutation of each declared
dependency.

[HIGH] `openspec/changes/content-addressed-release-closure/design.md:353` -> Reuse
allows any “advancing” original verdict, which includes `CONDITIONAL PASS`, but
the receipt does not bind condition closure evidence or specify creation of new
conditions. A reused conditional approval can therefore advance without
reinstating its obligation. Restrict reusable origins and reused events to
unconditional `PASS`, or clone every original condition as a new open condition
whose closure evidence is independently rebound. The simpler safe rule is PASS
only. Add a regression proving a closed historical condition cannot disappear
through reuse.

[HIGH] `openspec/changes/content-addressed-release-closure/design.md:413` -> A
manifest “remote” token is passed in Git's repository argument position. A safe
token such as `.` or `repo` can be interpreted as a local repository path when it
is not an actual configured remote, allowing `publish --verify` to compare HEAD
to the current/local repository and falsely claim remote publication. Resolve the
token against the exact NUL-safe output of configured remote names first and
refuse any name not present; never accept the manifest value as a URL or path.
Then use only that resolved name. Add tests for `.`, an existing directory name,
option-like input, and a valid configured local-bare remote.

[MEDIUM] `openspec/changes/content-addressed-release-closure/design.md:404` ->
Commit coherence and remote classification span multiple processes without a
stated immutable snapshot. Concurrent HEAD/index/worktree changes can make a
command verify a different state from the one it reports; a remote ref can also
move between `ls-remote` and fetch, causing ancestry to be attributed to the
wrong observation. Capture one local HEAD OID, index identity, scoped digest, and
remote OID; use those exact values throughout, then re-check HEAD/index/scoped
cleanliness before recording or printing VERIFIED. Fetch the observed OID (not a
moving ref) when supported, verify the expected object arrived, and re-observe
the ref after fetch; if it moved, retry within a small bound or report an unstable
observation without caching. Add deterministic race fixtures.

[MEDIUM] `openspec/changes/content-addressed-release-closure/design.md:417` -> A
timeout and bounded stdout do not bound the pack/object bytes written by `git
fetch`, and repository Git config can enable recursion or maintenance. A hostile
remote can exhaust disk, while the design's claim that only unreachable objects
change is too broad. Run ancestry fetch in a temporary quarantined object
directory, disable submodule recursion, auto-maintenance, tag following, prompts,
and pagers, cap combined stdout/stderr and quarantine bytes while the child runs,
kill on either byte/time limit, validate all received OIDs/types, and delete the
quarantine on every outcome. Run merge-base with that quarantine as an alternate;
do not migrate objects into the repository. If this cannot be implemented
portably, report ancestry `unavailable` when objects are absent rather than
fetching. Exact-OID parity requires no fetch and remains authoritative.

## Required non-blocking implementation details

- Validate every pointer/cache/ledger path again when loading; derive and compare
  the archive destination from bounded change/date fields instead of trusting a
  stored joined path. Corrupt or symlinked pending state must fail closed, never
  trigger deletion, overwrite, or a repeated merge.
- Hash regular files from non-following handles and verify kind/mode before and
  after streaming; recheck the scoped snapshot before recording it. Refuse FIFO,
  device, socket, non-UTF-8, unmerged, and ambiguous gitlink states without
  opening them.
- Parse only exact plumbing formats with bounded NUL output. Invoke Git with
  argument arrays, `--` where supported, `GIT_PAGER=cat`,
  `GIT_TERMINAL_PROMPT=0`, bounded stderr, and no shell. Do not render or persist
  URLs, credential-helper output, raw remote output, or control characters.
- Annotated tag publication needs an explicit rule: either restrict v1 to
  `refs/heads/*`, or store both tag-object OID and verified peeled commit OID.
  Never run commit ancestry directly on an unpeeled tag object.
- Observation cache entries must bind schema, change, closure commit, remote
  name, ref, and observed OID. Cache corruption affects only last-known display;
  it can never satisfy fresh closure.

## Risk-to-test additions

In addition to every existing risk-to-test row, Builder must cover intermediate
add/delete history, conditional receipt reuse, fake local-path remotes, concurrent
HEAD/ref movement, hostile oversized fetch, fetch recursion/config suppression,
annotated tags, corrupt/symlinked pending pointers, and non-following file-swap
behavior. Failure cases must prove zero ledger/history/index/worktree mutation,
except bounded temporary quarantine creation and cleanup.

## Reviewed and not reviewed

This is a plan review; production implementation does not yet exist. Security
(code) must inspect the actual canonical encoder, policy table, Git environment,
bounded child-process reader/terminator, archive recovery state machine, receipt
provenance, and all mutation ordering. Remote credentials and hosting-provider
authorization are intentionally outside MPD; the command must only use the
operator's already configured Git transport without persisting its secrets.

## Verdict

**FAIL** — the six findings above include credible false-publication,
false-reuse, mixed-history, and remote resource-exhaustion paths. Build is blocked
until the design is revised with the exact fixes and Security (plan) is rerun.

## Revised-plan rerun

Re-reviewed the canonical proposal, design, specifications, and tasks after the
Security revision. The prior findings close as follows:

| Prior blocker | Closure evidence | Result |
|---|---|---|
| Endpoint diff hides transient paths | Design lines 444-452 walks every single-parent commit, unions NUL-parsed add/delete/rename/copy paths, forbids endpoint-only proof; spec adds the add-then-delete scenario | Closed |
| Incomplete execution-phase dependencies | Design lines 379-386 defaults Build/Test/Security code/Deploy to always execute; the first three require explicit versioned hermetic opt-in with platform, executable, environment-digest, and external-input bindings; Deploy cannot opt in | Closed |
| Conditional approval loses obligations | Design lines 396-402 permits only original unconditional PASS and explicitly refuses CONDITIONAL PASS; spec lines 57-60 preserves this rule | Closed |
| Remote token interpreted as path | Design lines 457-462 requires exact membership in bounded configured-remote-name output and rejects `.`, directories, and unknown tokens; spec lines 36-38 covers the path impostor | Closed |
| Local/remote TOCTOU misbinding | Design lines 444-452 snapshots and recomputes HEAD/index/scoped state; lines 462-464 re-observe the remote, bound retries, classify movement unstable, and forbid cache writes | Closed |
| Hostile fetch resource/config effects | Design lines 466-469 performs no fetch; absent ancestry objects degrade to ancestry-unavailable while exact-OID verification remains authoritative | Closed |

The revised head-only publication ref rule also closes annotated-tag peeling
ambiguity. The phase policy remains causal, schema-versioned, and exact; the
default always-execute posture means an incomplete hermetic declaration fails
safe rather than granting reuse.

### Remaining blocking finding

[HIGH] `openspec/changes/content-addressed-release-closure/design.md:430` -> The
pending pointer contains only change, archive path, base OID, and coarse stage,
but the existing archive implementation writes merged spec targets sequentially
before renaming the change directory (`crates/openspec-core/src/project.rs:355`).
A crash after one of several spec writes leaves `active exists / archive absent`,
the same coarse state as a crash before any write. Recovery cannot know which
targets hold preimages or postimages, cannot safely repeat the merge (it may
double-apply a delta), and cannot roll back because no preimages were retained.
This is a credible repository-corruption path during power loss or process
termination, and the current pointer cannot satisfy the promised deterministic,
non-repeating, non-deleting recovery.

Before mutation, persist a bounded, versioned archive transaction journal that
binds every target path to its preimage digest, planned postimage digest, mode,
and a durable staged postimage (plus an explicit absent preimage for new files),
as well as the active/archive directory identities. Fsync staged content and the
journal before the first replacement. Apply each target using contained,
symlink-refusing atomic replacement, recording or infering completion only by
exact pre/post digest. Recovery may complete a target only from exact preimage to
the recorded staged postimage, leave exact postimage unchanged, and must refuse
any third state; it must never rerun semantic merge. Only after every target is
postimage may it perform/confirm the directory rename and write the closure
record. Rollback, if offered, requires equally durable preimage content; otherwise
offer completion-only recovery and never claim rollback. Add crash injection
after journal fsync, after each target replacement, around directory rename, and
around closure-ledger write, including an unexpected third-state refusal test.

### Rerun verdict

**FAIL** — all six original blockers are resolved, but deterministic archive
recovery remains under-specified relative to the real multi-file mutation order.
Build remains blocked until the transaction journal/recovery contract above is
added and Security (plan) passes it.

## Final revised-plan rerun

Reviewed the normative `archive-transaction.md`, synchronized CLI contract,
change-manifest scenarios, task additions, risk map, and final Conditions for
Builder. Closure status is now:

| Security blocker | Final design evidence | Status |
|---|---|---|
| Transient out-of-scope intermediate commits | Per-commit single-parent walk and full rename/copy/add/delete union; endpoint proof forbidden | Closed |
| Incomplete execution-phase reuse | Always-execute default; versioned hermetic opt-in with platform, executable, environment-digest, and external-input bindings; Deploy fixed | Closed |
| Conditional approval reuse | Only executed unconditional PASS is reusable; conditional receipts always require a fresh gate | Closed |
| Remote/path argument confusion | Exact membership in bounded configured-remote names; paths, URLs, `.`, and unknown names refused | Closed |
| Local/remote snapshot races | HEAD/index/scoped snapshot recheck, two bounded remote observations, unstable refusal, and no cache on movement | Closed |
| Hostile fetch effects | No fetch; absent objects degrade to ancestry-unavailable | Closed |
| Partial multi-file archive recovery | Normative pre-mutation journal, durable staged postimages, exact pre/post state machine, third-state refusal, and completion-only recovery | Closed |

### Transaction security audit

- **Containment and ownership:** journal and pointer paths are derived from a
  typed transaction digest; every stored target/staging path is project-relative,
  capped, rederived on recovery, and checked for containment and symlinks. Cleanup
  is restricted to ignored paths owned by that transaction ID after digest checks.
- **Preparation durability:** existing targets are opened without following
  symlinks; staged files are exclusive, same-filesystem, synced, reopened, and
  tuple-verified. The complete journal is synced and parent-synced before the
  pending pointer enters `Prepared`; no project target changes earlier.
- **Recovery integrity:** only exact preimage plus exact staged postimage may be
  installed; exact postimages are idempotently retained. Changed mode/type,
  symlink, missing/corrupt staging, directory-identity mismatch, or any third
  state disables writes before mutation. Semantic merge/render/synthesis is never
  rerun.
- **Authorization and claims:** recovery previews are read-only. Only explicit
  `recover --yes` rolls forward an eligible state. No rollback is offered because
  preimage bytes are not retained, and output does not claim filesystem-independent
  atomicity. Platform durability is reported honestly.
- **Directory and closure ordering:** all target postimages are verified before
  the source/destination tree-identity transition; only exact source/absent
  destination or absent source/exact destination is accepted. All bytes are
  reverified before the closure ledger and `AwaitingCommit` state.
- **Abandonment:** preview is read-only; `abandon --yes` is available only after
  `AwaitingCommit` and deletes only contained ignored transaction metadata. It
  cannot alter targets, ledger history, index, commits, or remote state.
- **Fault evidence:** required injection points cover staged/journal/pointer sync,
  every target, every state transition, directory rename, ledger replacement,
  corrupt/truncated metadata, symlink swaps, size limits, and forced failures;
  each refusal must prove zero additional mutation.

No new path-to-command, content disclosure, cache-trust, publication, or recovery
authorization exploit is introduced by this revision. Security (code) must still
verify non-following handle use, exclusive staging, parent sync behavior,
pointer/journal state agreement, exact ownership checks, and refusal-before-write
ordering on the implemented diff.

### Final verdict

**PASS** — all seven credible plan blockers are closed with checkable invariants
and adversarial test requirements. Build may proceed under the final Conditions
for Builder; Security (code) remains mandatory before downstream approval.
