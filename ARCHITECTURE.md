# Commando Architecture

## Purpose and boundary

`mpd` is a local orchestration and evidence kernel over OpenSpec and Git. It converts a
change into written intent, separated adversarial roles, exact-subject local validation,
and distinct delivery observations. It is not a build farm, Git transport, remote
attestation service, or defense against a malicious repository owner.

The load-bearing architecture is intentionally small:

```text
OpenSpec artifacts + manifest
          |
          v
append-only Ledger --freshness/risk--> ordered gates
          |                                |
          |                                v
          +--> immutable Candidate --> local validator --> receipts
          |                                |
          v                                v
archive closure --> coherent Commit --> pre-push authorization --> normal Git
          |                                                     |
          +--> typed Build output --> final Deploy copy          v
                                                        remote parity observation
```

## Phase and ledger model

`phase.rs` defines one canonical order:

`Design Mock -> Architecture -> Design Review -> Security(plan) -> Build ->
Security(code) -> Design Sign-off -> Test -> Documentation -> Doc Validation -> Deploy`

Only Design phases are conditional on UI/human-visible impact. All verdicts, attempts,
conditions, reconciliations, freshness invalidations, task deferrals, candidate
bindings, validation receipts, Build outputs, Deploy results, archive closure, and
delivery observations are append-only or content-bound state. A repair only rewinds; it
does not synthesize a PASS or erase a prior failure.

Effective risk is `max(requested, derived)`. Derived signals include sensitive paths,
untrusted parsing/execution, policy/hook/sandbox/tool changes, persistence/network
boundaries, and unknown security-relevant scope. Configuration cannot lower risk.

Each canonical artifact has a causal dependency key. Before a brief or effect, MPD
rehashes current dependencies and projects the earliest stale phase. The next command
records that rewind atomically before returning a new brief.

## Exact Candidate

Planning is against base `HEAD`; objective work is against an immutable Candidate.
Candidate capture reuses the bounded commit materializer, then overlays only
manifest-scoped worktree postimages:

- staged and unstaged tracked files, with the worktree postimage winning;
- declared untracked regular files;
- deletions, renames, executable modes, lengths, and SHA-256 identities; and
- sorted, capped inventory metadata.

Symlinks, gitlinks, special files, collisions, unsafe/non-UTF-8 paths, unmerged state,
inventory/byte caps, identity races, and unexpected status changes fail closed. Mutable
MPD state, Git-common receipts/logs/tools, build output, install output, and process state
are excluded from the Candidate. Declared config/directive/hook/security policy changes
do move its identity.

Build captures the Candidate once. Security(code) and Test reopen and rehash that same
projection before and after their profiles. Candidate receipts are never treated as
Commit/HEAD receipts.

## Structured local validation

`.mpd/config.json` is a versioned data graph of tools, checks, profiles, gates, receipt
limits, offline inputs, sandbox policy, resource caps, and typed Build/Deploy outputs.
Execution code accepts only declared program/argv tokens and resolves exact pinned
executables. Shell strings and candidate-controlled roots are not authority.

The local validator:

1. resolves one exact Candidate or Commit subject;
2. compares the candidate policy with the clone-local immutable trusted policy;
3. verifies toolchain, tool, Cargo.lock, advisory DB, Semgrep policy, hook, and sandbox
   identities;
4. materializes the subject into a private root;
5. creates private Cargo/HOME/Git/XDG/temp/log state;
6. enters the platform adapter through a bounded nonce-bound request;
7. runs mandatory canaries, then the typed check under monotonic resource supervision;
8. rechecks the subject and Candidate; and
9. writes a bounded receipt only after all required results and cleanup succeed.

Receipts bind subject, profile, effective policy, validator binary, host/toolchain,
Cargo/advisory/tool inputs, sandbox ABI/profile/root/canary attestations, results, times,
and optional Build output. Logs are clone-private, capped, rotated, redacted, and bound by
digest rather than copied into the ledger.

## Exact-host macOS adapter

The certified adapter exists only for macOS 27.0 build `26A5378n`, Apple silicon,
`aarch64-apple-darwin`. It uses the fixed `security/sandbox/validation.sb` profile plus
dynamic read/read-write extension tokens issued with flags zero. A private, nonce-bound
control request binds the fixed profile, exact read roots, one private write root,
limits, environment keys, command, and authority digests.

The helper clears loader/ambient environment, closes ambient descriptors, validates
canonical roots, issues tokens, enters Seatbelt, consumes and zeroizes tokens, runs
allowed/denied read/write/network/symlink/child/grandchild/post-entry canaries, reports
READY bound to the request, accepts matching GO, closes control, and execs the approved
argv. Any partial issue/init/consume, token/descriptor leak, root/profile/ABI/host drift,
canary mismatch, timeout, process leak, or cleanup ambiguity is BLOCKED. There is no
weaker fallback.

The adapter relies on deprecated custom-profile entry points and undocumented extension
SPI. Its narrow certification covers accepted-root content reads, the private-root plus
`/dev/null` write boundary, and network denial. Global metadata/existence, literal-root
directory entries, and same-user process isolation are explicit nonclaims.

## Resource and output supervision

The parent applies per-check and aggregate monotonic deadlines, process/file/descriptor
limits, worktree-growth limits, and concurrent stdout/stderr aggregate caps. It owns a
process group, observes descendants, terminates, waits a grace interval, kills, reaps,
and refuses leaked background pipe holders. Terminal rendering strips or escapes ANSI,
OSC, C0/C1, bidi, and non-UTF-8 data. JSON has one stdout document; diagnostics remain on
stderr. A PASS is printed only after the identified durable commit succeeds.

## Policy activation and Git hooks

The only release activation command is `mpd policy activate`. It accepts one immutable
direct commit OID, canonical policy digest, canonical absolute coordinator path and
digest, and `.githooks`. The commit must contain exact reviewed policy assets and
executable wrapper modes. Activation checks the current certified host/profile/ABI,
creates or compares the direct trusted-policy object, installs owner-only clone-private
coordinator/wrappers atomically, and sets local `core.hooksPath` to that private
directory. Interrupted stages roll back or resume only after byte-for-byte revalidation.

The tracked `.githooks` files are reviewable source/fail-closed fallbacks. Activated
wrappers carry the absolute coordinator identity so candidate PATH cannot select the
authority. Bootstrap downloads tools/advisory inputs explicitly but never activates
policy, hooks, or validation.

Pre-commit is bounded and read-only over staged secrets plus artifact/task consistency.
Pre-push parses Git's exact NUL/newline-bounded input, resolves every ordinary/nested-tag
subject, enumerates every outgoing commit/tag/message/blob, scans fresh bytes, validates
the required exact Commit profile, and emits a single invocation authorization. The
authorization binds remote name/location, baseline, rows, object set, subjects, policy,
result, and nonce. Its clone-private audit record is observational and never reusable.
Normal Git performs transport.

## Closure, publication, and Deploy

Archive writes deterministic spec/archive postimages and a closure plan. Commit
coherence compares the final tree path/mode/SHA inventory with the exact Candidate plus
only allowed canonical phase/documentation/archive overlays. Extra, missing, rewritten,
mode-changed, or out-of-scope intermediate history blocks coherence.

`mpd publish --verify` performs one bounded fresh remote observation without fetching or
pushing. It classifies exact parity, ahead, behind, diverged, rewritten, unavailable,
offline, or unstable and caches only the observation. Push authorization, actual
transfer, and parity remain separate.

Build exports one parent-observed typed file descriptor identity. Final Deploy reopens
that file, copies it through an exclusive target-directory temporary, syncs and
atomically replaces, then reopens and verifies mode/length/SHA. It never rebuilds or
executes the installed candidate for identity. Readiness-only and installed execution
are different result modes.

## Compatibility

Legacy ledgers and configuration remain parseable where safe. Missing modern receipt,
candidate, task, actor, activation, or authorization data is absent—not implicitly
valid. Test-only codecs preserve historical formats so old evidence can
be decoded and rejected; those routes are not compiled into the release CLI.
