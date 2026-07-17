# Design: Content-addressed release closure

## Context

MPD currently leads an operator through gates and archive readiness with concise
text, a structurally equivalent `--json` form, explicit blockers, and one
next-command cue. It can prove that a gate ran, but it does not yet help the
operator answer three release-closeout questions:

1. Does prior gate evidence still describe the exact content being released?
2. Which repository paths and commit make up this change?
3. Does the configured remote ref resolve to that same commit?

These are distinct truths: push is an action, deploy is a target operation, and
remote parity is an observation. The CLI never collapses them.

This opening contract covers CLI interaction; Architecture below owns storage,
hashing, Git/network implementation, and trust policy.

## Established CLI language to preserve

- Use short labeled sections, plain words, and repository-relative paths.
- Keep `PASS`, `CONDITIONAL PASS`, and `FAIL` for gate verdicts; evidence state
  uses the separate words `valid`, `stale`, and `absent`.
- Explain every non-ready state with concrete indented blockers.
- End an actionable result with exactly one `→ next: ...` or `→ ready: ...`
  cue. Never show a command that would still be refused for a known blocker.
- Text and `--json` expose the same state and recommended action. JSON is not a
  lossy or more privileged interface.
- Keep output non-interactive by default. Durable mutations require the existing
  explicit-confirmation style (`--yes`) and never prompt outside a terminal.
- Use words and symbols together; color may enhance output but never carry
  status by itself. Untrusted names and refs are terminal-safe.

## Goals / Non-Goals

### Goals

- Make evidence reuse visible, understandable, deterministic to the operator,
  and distinguishable from running a gate again.
- Present a single reviewable change manifest before release closure.
- Detect mixed staged content before it is attributed to the active change.
- Give remote parity its own named verification step after the local commit is
  known and before publication is considered complete.
- Represent normal, empty, partial, offline, divergent, rewritten-remote,
  detached-HEAD, and unborn-branch states without guesswork.
- Keep automation stable through complete `--json`, meaningful exit status, and
  no requirement for prompts or ANSI parsing.

### Non-Goals

- A graphical or interactive staging UI.
- Performing a push or deployment implicitly.
- Treating Git-accepted network responses, branches, or remotes as trusted.
- Defining implementation details, cryptographic primitives, or retention.
- Claiming provenance, authorship, artifact signing, or supply-chain attestation.

## CLI information model

### Evidence state

Every applicable gate presents one evidence state:

- `valid` — recorded evidence matches the content and governing context it
  claims to cover. Reuse eligibility is shown separately: judgment phases may
  be reusable, while Build/Test/Security-code default to `always execute` until
  a complete hermetic policy is explicitly configured; Deploy always executes.
- `stale` — evidence exists but no longer matches. Output names each actionable
  reason (content, scope, or governance change); stale PASS is not current PASS.
- `absent` — no reusable evidence exists for the required gate/content pair.
- `not applicable` — the gate is outside this change's declared pipeline; this
  is not a fourth evidence result and never appears as reusable.

When reuse occurs, text says `reused` and identifies the original gate result;
it must not imitate fresh execution. `--json` likewise distinguishes
`disposition: "reused"` from `disposition: "executed"`.
Valid-but-ineligible evidence says `VALID (reuse disabled: always executes)` and
offers the normal gate run, not `--reuse`. A configured hermetic opt-in says
`VALID (hermetic reuse eligible)` and names the policy version in JSON. A
CONDITIONAL PASS is never reuse eligible, even after its old condition closes;
the next cue reruns that persona gate so the obligation cannot disappear.

Example:

```text
Evidence:
  VALID   Build          reused from 9f6d…
  STALE   Test           tracked content changed: crates/mpd/src/cli.rs
  ABSENT  Deploy         no evidence recorded

→ next: mpd next
```

### Change manifest

The UI calls this the `Change manifest`, not a release bundle, lockfile, or
attestation. It shows:

- active change name;
- local commit identity, or `not committed`;
- declared repository-relative scope;
- included paths, grouped as tracked/staged when that distinction matters;
- excluded or unrelated staged paths;
- manifest state: `ready`, `incomplete`, or `blocked`;
- precise blockers and the next safe command.

The clean case stays compact. Full path lists remain in `--json`; text may
summarize a long list with a count and point to the machine-readable view.

Mixed staged paths are never silently absorbed into the active change. If any
staged path is outside declared scope, status says `BLOCKED`, prints the paths
(or a count plus representative paths when long), and instructs the operator to
adjust staging or scope. MPD does not unstage, discard, or reclassify user work.

```text
Change manifest: BLOCKED
  Commit: not committed
  Scope: crates/mpd/**, openspec/changes/content-addressed-release-closure/**
  Included: 6 staged paths
  Unrelated staged: README.md
  - staged content falls outside this change's scope

→ next: adjust staging or the declared scope, then run mpd status
```

### Remote parity

Remote parity is displayed as a separate named section with one of:

- `verified` — configured remote ref was observed at the manifest commit;
- `not verified` — no current successful observation exists;
- `offline` — the remote could not be reached; local evidence remains intact,
  but publication is incomplete;
- `ahead` — local manifest commit is not yet the remote ref;
- `behind` — remote contains commits not present locally;
- `diverged` — neither side contains the other;
- `rewritten` — a previously verified remote ref changed to a different
  history, including a force-push;
- `unavailable` — parity cannot be defined for an unborn branch, detached HEAD
  without an explicit publication ref, missing remote, or missing upstream.
- `unstable` — the local snapshot or observed remote OID moved during the bounded
  verification/recheck; no verified observation was recorded.

When exact OIDs differ but the observed object is not local, show `not verified
(ancestry unavailable)`, not ahead/behind/diverged. MPD performs no hidden fetch.
The next cue names an explicit normal Git fetch of the already configured remote
and ref, followed by `mpd publish --verify`; it never accepts a URL/path token.

Output names the remote/ref and useful abbreviated commit identities. It never
equates `ahead` with “push failed,” `verified` with “deployed,” or `offline`
with divergence.

For detached HEAD, MPD explains that a commit exists but no publication ref is
selected. For an unborn branch, it explains that no commit can back a manifest.
No suggested command invents a branch, upstream, remote, force-push, or target.

## Command behavior contract

### `mpd status [--change N] [--json]`

`status` remains the complete read-only orientation surface. Alongside pipeline,
history, tasks, and blockers, it shows compact `Evidence`, `Change manifest`,
and `Remote parity` sections. It does not imply network freshness: a last-known
observation points to `mpd publish --verify`.

Its single next cue follows this priority: resolve conditions; complete the
current phase; fix manifest blockers; archive; commit the archived result;
verify remote parity; otherwise report completion. JSON distinguishes current
from last-observed state and never encodes unknown as false.

### `mpd next [--harness H] [--full] [--json]`

`next` keeps its persona brief. Before the phase guidance, it adds only the
release-closure facts that affect the phase: whether evidence is reusable, why
it is stale/absent, and whether manifest/parity work blocks this phase. If valid
evidence can be reused, the brief explicitly offers the reuse path and its gate
command; automation receives the same choice structurally. `next` never silently
records reuse.

### `mpd gate <phase> ...`

Gate output identifies fresh execution, newly recorded evidence, or reuse.
Reuse is explicit and succeeds only for `valid` evidence. Stale or absent reuse
fails without history changes and shows the reason plus a rerun command. Gate
results keep the existing verdict vocabulary.

### `mpd archive [--yes] [--skip-specs]`

Archive keeps dry-run-first behavior. Its preview includes scope and evidence
disposition per required gate. `--yes` confirms only the displayed archive
mutation; it never commits, pushes, verifies parity, or deploys. Because archive
changes tracked artifacts, remote parity never blocks it: status next requires
a commit containing the archived result, then fresh parity verification of that
exact commit. Evidence bound to unchanged declared inputs remains valid; the
archive move is not silently treated as fresh product evidence.

Interrupted status names its durable stage and safe-to-complete, awaiting-commit,
or manual-recovery state; it says preimages were not retained and never calls the
archive atomic or reversible. `closure recover` previews bounded paths,
durability, digest classification, and write eligibility; only `recover --yes`
rolls forward. Third/corrupt states disable `--yes`; completed recovery says
`AWAITING COMMIT`. `closure abandon` previews and refuses before that state;
`abandon --yes` removes only owned ignored metadata. Neither path stages,
commits, pushes, deploys, deletes repository content, or clears remote results.
Human/JSON share stage, eligibility, durability, path count, and next cue.

### `mpd publish [--verify] [--json]`

`publish` is the dedicated post-archive remote-parity surface. Its default form
is a readiness report: final manifest commit, selected remote/ref, local state,
last observation, blockers, and next action. `mpd publish --verify` performs a
fresh observation but does not push, force-push, create refs, or deploy. A
successful result says `Remote parity: VERIFIED`; release closure is complete
only when the archived manifest commit is the verified remote commit.

If the local branch is merely ahead, output may suggest the repository's normal
push command, but MPD does not execute it. Divergence or rewriting never suggests
a force-push. Offline results preserve prior local progress and identify the
observation time as stale. Detached/unborn states require the operator to select
or create repository state outside MPD before verification.

Only an exact configured remote name is accepted; a path, URL, `.`, or unknown
token is refused before network use. Verification snapshots and rechecks local
HEAD/index/scoped bytes and the remote OID. After one bounded internal retry, a
second movement reports `UNSTABLE`, writes no verified cache, and tells the
operator which side moved before offering a fresh verify after stabilization.
Human and JSON expose the same reuse eligibility/policy, ancestry availability,
configured-target validation, unstable cause, and recommended action.

## Noninteractive and accessibility contract

- All read-only commands terminate without prompts. Mutation requires explicit
  flags; missing confirmation fails with a dry-run and usable next command.
- `--json` writes one valid, non-ANSI JSON document to stdout; diagnostics go to
  stderr and progress animation is absent.
- Text order is stable: overall state, evidence, manifest, parity, blockers,
  then one next cue. Screen-reader users hear the status word before details.
- Every status uses an uppercase word in text and a stable lowercase enum in
  JSON. Symbols, indentation, and color are redundant aids.
- Path/ref lists are bounded in human output without hiding the total count.
  Control characters and escape sequences cannot alter terminal presentation.
- Offline/network work reports a bounded wait or progress message on terminals
  and remains interruptible; noninteractive use never waits for input.

## Risks / Trade-offs

- **Dense status output** → collapse clean sections to one line; expand only
  blockers and offer full JSON for long path sets.
- **“Valid” mistaken for “safe” or “approved”** → always qualify it as evidence
  validity and retain the independent gate verdict.
- **“Publish” mistaken for push/deploy** → dry-run by default, use `--verify`
  for observation, and state “no push or deploy performed.”
- **Stale remote observations presented as current** → label observation time
  and require explicit fresh verification for closure.
- **Mixed user work accidentally claimed** → block on out-of-scope staged paths
  and never mutate staging.
- **Force-push normalized as remediation** → classify rewritten history and stop
  with neutral diagnosis; require explicit human Git action outside MPD.

## Acceptance criteria

1. A clean common-path `status` remains scannable and ends in one executable
   next cue; text and JSON agree on all three closure dimensions.
2. Valid evidence can be explicitly reused and is visibly distinguished from a
   newly executed gate in status, next, gate output, archive preview, and JSON.
3. Stale evidence names why it is stale and cannot be reused; absent evidence
   names the required rerun without presenting a false failure.
4. A manifest shows exact change, scope, commit, and included-path truth; mixed
   staged paths block closure without modifying the index.
5. Push action, deploy result, and remote-parity observation are represented as
   three independent facts everywhere.
6. Fresh remote verification covers verified, offline, ahead, behind, diverged,
   rewritten/force-pushed, missing upstream/remote, detached HEAD, and unborn
   branch with accurate, non-destructive next guidance.
7. Archive preview states scope/evidence, performs no commit/push/verify/deploy
   side effect, then requires commit and parity proof of the archived result.
8. `publish` is non-mutating and dry-run/readiness-oriented by default;
   `publish --verify` observes remote parity and never pushes or force-pushes.
9. Color/icon never stands alone; terminal-safe text and non-ANSI JSON remain
   usable with screen readers and automation.
10. Known blockers never yield a next command that the CLI would immediately
    refuse for that same blocker.
11. Valid evidence separately reports reuse eligibility; default always-execute,
    hermetic opt-in, and CONDITIONAL refusal each show the correct runnable gate.
12. Ancestry-unavailable and unstable are explicit non-parity states with no
    hidden fetch/push, no verified cache write, and equivalent text/JSON cues.

## Design conditions carried into Architecture

- Keep distinct vocabularies for verdict, evidence, manifest, parity, push, deploy, and archive completion.
- Never silently reuse evidence, broaden scope, mutate staging, select a ref, push, force-push, deploy, or archive.
- Confirm durable mutation; refusals leave repo state unchanged; human and JSON expose equivalent unknown, last-known, and fresh facts.
- Treat paths, refs, remote output, change names, and evidence labels as untrusted.
- Preserve one safe next-command cue executable from the state just reported.

## Architecture

### Module boundaries

Add three focused modules to `crates/mpd`:

- `digest.rs`: canonical SHA-256 streams, typed `Digest`, file/symlink hashing.
- `git.rs`: argument-array-only Git plumbing, `-z` path parsing, OID/ref
  validation, ancestry, and bounded remote observation.
- `closure.rs`: manifest parsing/matching, phase dependency snapshots, evidence
  validity, archive-commit coherence, parity state, and local cache.

`cli.rs` orchestrates commands and view models; it must not hash or parse human
Git output. `openspec-core` retains semantic planning and adds the filesystem
transaction executor defined by the normative
[archive transaction protocol](archive-transaction.md). Add `sha2 = "0.10"`;
no shell, glob, Git, or network library is needed.

### Durable schemas

`openspec/changes/<name>/manifest.json` is created by `begin`:

```json
{"version":1,"paths":["crates/mpd/**"],"shared_paths":["README.md"],
 "publish":{"remote":"origin","ref":"refs/heads/main"}}
```

`paths` is required before Architecture PASS; publication is optional. Patterns
use the existing allowlist `*`/`**` semantics after extracting that matcher into
a shared module. Validate relative UTF-8 slash paths: no empty component, `.`,
`..`, NUL, backslash, absolute prefix, or control character. Remote names accept
Git-safe token characters only; refs must pass `git check-ref-format` and start
`refs/heads/`; tags are deferred so ancestry never sees an unpeeled tag. Never
accept a ref beginning with `-`.

Add serde-defaulted ledger fields:

```rust
struct EvidenceReceipt { id: Digest, schema: u32, phase: Phase,
  disposition: EvidenceDisposition, dependencies: DependencySnapshot }
enum EvidenceDisposition { Executed, Reused { source_receipt: Digest } }
struct DependencySnapshot { schema: u32,
  values: BTreeMap<DependencyKey,Digest> }
struct HermeticReusePolicy { schema: u32, external_state: NoExternalState,
  environment: Vec<String>, input_paths: Vec<String> }
struct ArchiveClosure { base_commit: Oid, archive_path: String,
  transaction_id: Digest, allowed_paths: Vec<String>,
  post_archive_digest: Digest, archived_at: u64 }
struct PendingClosurePointer { version: u32, transaction_id: Digest,
  change: String, stage: TransactionState }
struct LocalSnapshot { head: Oid, index: Digest, scoped: Digest,
  included_clean: bool }
```

`GateRecord.receipt` and `Ledger.archive_closure` default to `None`; old records
are `absent`, never valid. Do not store raw file content, command output, remote
URL, credentials, or environment values. The last observation lives under the
already-ignored `.mpd/tmp/parity/<change>.json`, is capped/symlink-refusing, and
contains only target names, OIDs, classification, and epoch time.
`.mpd/pending-closure` is also ignored, capped, symlink-refusing, atomically
replaced, and contains only the bounded recovery fields above.

### Canonical hashing

All digests are lowercase SHA-256 and domain-separated. Feed a binary stream,
never ambiguous concatenated text: magic `mpd\0`, schema u32 big-endian, domain
length+bytes, then sorted entries. Each entry is length-prefixed path bytes,
kind (`file`, `symlink`, `gitlink`, `deleted`), Git mode, content length, and
content SHA-256. Sort by canonical repository-relative UTF-8 bytes. Hash symlink
link text without following it; represent Git submodules by gitlink OID and
mode; refuse special files and non-UTF-8 paths. Deletions are explicit entries.

`scope` hashes the canonical manifest plus named MPD-owned path rules. `source`
hashes current worktree bytes for user-declared matched tracked/untracked files,
not timestamps, index blobs, the receipt-bearing ledger, or local caches. This
separation prevents self-referential receipt digests. `governance` hashes typed risk/profile data.
`config` hashes only phase-relevant normalized config values. Tool identities
are stable command/version strings with control filtering and length caps.
Receipt ID hashes the complete receipt payload excluding `id` itself.

### Dependency and invalidation rules

`DependencyPolicy::for_phase(Phase) -> &'static [DependencyKey]` is the sole
allowlist for receipt inputs; `snapshot(policy, context)` hashes exactly those
keys and stores `dependency_schema`. All phases bind scope and the canonical
artifacts available by that phase. Design/Architecture bind design
artifacts and governance; Security binds those plus source and threat profile;
Build/Test bind source, test command, toolchain, and produced artifact digests;
Security code also binds scanner identities and allowlist digest. Documentation
binds shipped behavior inputs and documentation. Deploy binds source/build
artifacts, deploy command, and fresh execution but is never reusable because
target state is external. Archive/Doc Validation bind relevant artifacts.

Build, Test, Security code, and Deploy default to `always_execute`; Deploy is
fixed. The other three become reusable only under a versioned project
`HermeticReusePolicy` declaring `external_state: "none"`, privacy-safe
environment names, and project-relative external inputs. Bind OS/architecture/
SDK identity, executable-byte digests for compiler/test/scanners, declared
environment value digests, and input digests. Missing/unreadable/undeclared
policy input makes the receipt non-reusable. Reject secret-shaped environment
names; values are never stored or shown.

“Relevant” is phase-causal: a receipt MUST NOT bind an output first created by
a later phase. Later documentation/archive movement cannot stale an earlier
Build/Test receipt when source, configuration, toolchain, and produced artifacts
are unchanged; editing an input that phase actually reviewed still makes it stale.

Later-phase outputs are structurally impossible to add to an earlier policy;
the policy table and schema version are golden-tested for every phase. Validity
recomputes the same policy and reports every differing field. A receipt
is valid only on exact equality. `mpd gate <phase> --reuse <id>` is mutually
exclusive with verdict/evidence flags, requires current phase, an advancing
original unconditional PASS, a permitted phase, and valid dependencies, then appends a new
reused receipt pointing directly to the executed origin (chains are flattened).
Reuse performs no configured check. Stale/absent/refused reuse writes nothing.
CONDITIONAL PASS is never reusable; closing an old condition cannot erase the
obligation from a new approval.

### Git manifest semantics

Use Git plumbing with `Command::args`, `--` before paths, and NUL-delimited
output: `ls-files -z`, `diff --cached --name-status -z`, `diff --name-status -z`,
`status --porcelain=v2 -z`, `rev-parse --verify HEAD^{commit}`, and `diff-tree`.
No `sh -c`. Treat rename/copy source and destination as separate scoped paths;
deletions must match scope. Any parse error or unmerged index entry blocks.

System scope includes the active change directory, its ledger, merged spec
targets, configured durable doc target, and dated archive target derived by
`ArchivePlan`; it is displayed, not silently broadened. Out-of-scope staged
paths block `status` closure readiness, `check --staged`, and archive but remain
untouched. Out-of-scope unstaged work is reported and excluded; it blocks only
when it overlaps an included path or prevents a clean closure commit.

### Archive and commit lifecycle

Before `archive --yes`, require current gates, valid manifest, safe staging, and
HEAD. Pure `ArchivePlan` computes semantic spec merges once. The CLI combines
its outputs, documentation, directory move, and final closure-ledger postimage
into the versioned transaction in [archive-transaction.md](archive-transaction.md).
Before mutation it durably stages every postimage and a journal containing each
target's explicit absent/existing preimage digest, postimage digest/mode, and
directory-tree identity, then writes the ignored pointer. Apply/recovery accepts
only exact preimage -> staged postimage or already-exact postimage; any third
state refuses. Recovery never reruns merge/render/synthesis and is completion-
only because preimage bytes are not retained. Only after all targets, directory
rename, and closure ledger are verified does state become `AwaitingCommit`.
Zero-argument commands/hooks resolve the pointer; begin/another archive refuse.
Confirmed abandonment is allowed only from AwaitingCommit and deletes metadata,
never repository targets. Digest excludes its own ledger field; the commit OID
covers ledger bytes.

After archive, `publish` captures `LocalSnapshot` using one HEAD OID, a digest
of bounded `ls-files --stage -z`, and included worktree digest/cleanliness. HEAD
must descend from `base_commit`; merges are blocked. Walk every commit from
`rev-list --reverse base_commit..HEAD`; for each single-parent commit parse
`diff-tree -r --name-status -z -M -C <parent> <commit>` and union every add,
delete, rename/copy source and destination. The union must include expected
archive mutations and no outside-scope path, catching intermediate add/delete
content hidden by endpoint diff. Final scoped digest must match. Recompute the
complete local snapshot before VERIFIED; movement is unstable/refused. This is
`commit coherent`. Pre-archive parity is never meaningful.

### Remote observation

Resolve target as manifest value, else configured default, else current branch
upstream; detached HEAD requires an explicit target. Parse bounded NUL output of
`git config --null --name-only --get-regexp ^remote\..*\.url$` into configured
remote names and require exact membership before network use. The manifest token
is never a URL/path; `.`, directories, and unknown names fail. `publish` is
local-only. `publish --verify` proves coherent HEAD, observes one exact OID/ref
with bounded `ls-remote`, then re-observes after classification. If it moved,
retry once; a second move is `unstable` and writes no cache.

Exact OID is verified without fetch. Otherwise classify ahead/behind/diverged by
`merge-base --is-ancestor` only if the observed object already exists locally.
MPD never fetches; absent ancestry objects yield `not verified (ancestry
unavailable)` rather than accepting hostile pack/config side effects. If a previously verified
remote OID is not an ancestor of the fresh remote OID, classify `rewritten`
before ordinary ancestry. Missing remote/ref, detached without target, and
unborn state are `unavailable`. Exit 0 only for verified, 1 for known non-parity,
2 for usage/config/internal errors. Never suggest force-push.

### Config, migration, and performance

Add optional `closure.default_remote`, `closure.default_ref`,
`closure.remote_timeout_secs` (1...300), `closure.hermetic_reuse`, and bounded
human path-list size. `init` seeds no publication target. Existing config and
ledger load unchanged. Existing active changes without `manifest.json` show
`manifest: incomplete` and may use `mpd manifest init`; no automatic scope guess
is accepted. Archived legacy changes remain archives, not publishable closures.

Hash each included byte once per command with streaming I/O; cap manifest paths,
patterns, receipt count, tool strings, Git output, and cache size. Status may
memoize within one process only. Target ordinary-repo status under 250 ms plus
file hashing; network work occurs only on explicit verify.

### Risk-to-test map

| Risk | Required evidence |
|---|---|
| Hash ambiguity/collision misuse | golden canonical vectors, order/mode/delete/symlink tests, property tests |
| False reuse | mutate each dependency independently; assert stale and zero history writes |
| Phase-causality drift | golden policy per phase; mutate later outputs and prove earlier receipts remain valid |
| Hidden intermediate path | two commits add/delete an outside-scope path; per-commit union rejects it |
| Lost condition | close old condition; prove CONDITIONAL receipt remains non-reusable |
| Path/index confusion | temp repos for rename/delete/unmerged/non-UTF-8/submodule/symlink and option-like refs |
| Archive/commit mismatch | base-to-HEAD exact-scope E2E, dirty index/worktree, merge, extra commit path |
| Interrupted archive | crash after every journal/target/rename/ledger boundary; converge or third-state refuse |
| Remote misclassification | configured-name/path impostor plus exact/ahead/behind/diverged/rewrite/missing/detached/unborn/moving ref |
| TOCTOU/resource/privacy | deterministic local/ref races; recheck refusal, no fetch, bounded timeout/output, cache secrecy |
| Compatibility | legacy config/ledger/change fixtures; current command regression suite |
| Performance | seeded 10k-path/100MB benchmark with byte-count and wall-time reporting |

## Conditions for Builder

1. Lifecycle is gates -> archive -> commit archived result -> fresh parity
   verification. No pre-archive or dirty-worktree state may be called published.
2. Canonical SHA-256 is domain-separated, length-prefixed, sorted, streaming,
   mode/kind/deletion aware, symlink-nonfollowing, and covered by golden vectors.
3. Reuse requires exact dependency equality and an explicit receipt ID, appends
   provenance, never executes a check, accepts only unconditional PASS, and
   never applies to Deploy. Build/Test/Security code require explicit hermetic
   opt-in with platform/executable/environment/external-input bindings.
   Dependency policies are phase-causal, schema-versioned allowlists; later
   outputs MUST NOT stale receipts for earlier phases that never reviewed them.
4. Legacy/unreadable/unknown evidence is absent or stale, never valid.
5. Manifest checks fail closed on unsafe paths, parse errors, unmerged entries,
   special files, ambiguous merges, and mixed staged scope; MPD never changes the
   index or user worktree.
6. Archive preview names every generated system path. The closure record is
   reached only through the normative journal protocol: durable staged
   postimages and pre/post digests precede mutation; exact digest state alone
   drives roll-forward; semantic merge is never rerun; third states refuse.
7. Pending closure remains discoverable after archive; status/publish and the
   archive commit hook resolve its transaction ID and cannot silently select
   another change. Recovery/abandon follow `archive-transaction.md` exactly.
8. A closure commit must descend from the recorded base, be clean, contain no
   out-of-scope path in the full per-commit history union, and match the
   post-archive digest. Endpoint diff alone is forbidden.
9. Remote commands use argument arrays, validated names/refs, bounded output and
   time, exact OIDs, and no credential-bearing URL persistence or raw output.
   Tokens MUST resolve through configured remote names, never paths/URLs.
10. Publish never fetches, pushes, force-pushes, creates refs, commits, stages,
    archives, or deploys. Missing ancestry objects reduce classification. Local
    HEAD/index/scoped state and remote OID are snapshotted and rechecked;
    movement cannot produce VERIFIED or a cache.
11. Human/JSON views agree, terminal text is safe and bounded, and every known
    blocker has one executable next action.
12. All new schemas are versioned/additive with limits; old ledgers/configs load
    and cannot accidentally receive reusable or published status.
13. No receipt binds output first created by a later phase; documentation/archive
    alone cannot stale unchanged Build/Test dependencies.
14. Builder must implement and pass every risk-to-test row, full workspace tests,
    warnings-denied Clippy, formatting, release build, isolated remote E2E, and
    installed-binary smoke verification before Deploy can pass.
