# Architecture: Bounded Local Production Kernel

## Actor

Architect

## Authority and trust boundary

This is the sole Builder architecture for `local-first-verification-hardening`, together
with the bounded capability deltas under `specs/`. Earlier foundation, pretrust,
transition-helper, receive-pack, mapped-loader, capped-store, persisted-clock, and V2-V5
sidecars have been removed; their failed-review provenance remains in ledger history.
Builder must not implement or execute `mpd-transition`, a pretrust supervisor, a custom
Git receiver, or a recursive ceremony that attempts to prove the tool before compiling.

The production claim is cooperative and local. MPD helps an owner and harness prevent
accidental stale review, incomplete validation, malformed input, and unvalidated pushes.
The same owner can replace the binary, edit policy/Git state, or use `--no-verify`; MPD
does not resist or independently attest against that behavior. Reviewer/model identities
are recorded claims unless an external harness authenticates them.

Compiling, formatting, linting, and testing work-in-progress before commit are normal
Builder activities. They become gate evidence only when MPD binds the result to the exact
candidate. The first command after fresh Design Review and Security(plan) PASS is
`cargo check --workspace --all-targets`; later work proceeds in focused vertical slices.

This release certifies only Apple silicon `aarch64-apple-darwin` on macOS 27.0 build
26A5378n. Every other OS build or architecture is NOT CERTIFIED; Linux remains
experimental. The macOS containment mechanism is an exact-host compatibility adapter
over the deprecated custom-profile `sandbox_init` entry point and undocumented exported
libsystem sandbox-extension SPI. It is not a supported or portable Apple API contract.
Host, symbol, ABI, profile, extension, inheritance, or canary drift is BLOCKED, with no
App Sandbox, `sandbox-exec`, broad-read, unsandboxed, or hosted fallback. GitHub Actions
and hosted checks are never gate authority.

Current empirical evidence proves exact-root read/write enforcement, network denial,
child and grandchild inheritance, post-sandbox non-escalation, and a complete offline
`cargo -> rustc -> linker -> test binary` compilation on that host. It does not certify
the full Commando suite: tests that relied on ambient Git identity, process behavior, or
system temporary paths failed. Production certification remains pending until those
tests use declared private identity/state and the complete canary matrix passes.

## Required outcomes

1. Intent, architecture, security constraints, tests, tasks, and docs are durable.
2. Build, Security(code), and Test inspect the intended tracked, unstaged, staged, and
   relevant untracked work rather than substituting `HEAD`.
3. Material changes invalidate dependent evidence before downstream work or effects.
4. A local pre-push hook validates every outgoing update, including deletion-only.
5. Candidate, gates, archive, commit, push authorization, transfer observation, remote
   parity, and installed bytes remain separate facts.
6. Authority-bearing local commands run offline with candidate/tool content reads and
   runtime writes bounded by the exact-host adapter; unavailable or drifting containment
   blocks rather than weakening the profile.

## Phase and evidence contract

```text
Design Mock? -> Architecture -> Design Review? -> Security(plan) -> Build ->
Security(code) -> Design Sign-off? -> Test -> Documentation -> Doc Validation -> Deploy
```

Only Design phases may be N/A, with a no-human-visible-impact rationale. Documentation
and Doc Validation apply to feature, fix, chore, dependency, configuration, tooling, and
documentation changes. Deploy is final; without install authority it records
readiness-only and must not imply installation.

Strict judgment gates require one canonical artifact and actor. Architecture contains
scope, file/API plan, dependency order, failure modes, risk-to-test mapping, and
Conditions for Builder. Security records severity, file/line, exploit path, remediation,
reviewed/omitted scope, and verdict. Test evidence maps risks to commands, real counts,
exits, and omissions. Commando denies artifact waivers. The append-only ledger retains
all attempts and artifact digests; timestamped correction sidecars are not authority.

## Decision 1: exact immutable candidate projection

Reuse the current exact-subject materializer and validation engine. Add the smallest
candidate abstraction needed:

```text
CandidateSubject {
  version, change, base_commit, base_tree, manifest_digest,
  entries_digest, policy_digest, source_digest, id
}
CandidateEntry { path_bytes, state: present|deleted, mode, byte_len, sha256 }
CandidateCapture { subject, clone_private_root, counts, excluded_dirty_paths, captured_at }
```

At Build, materialize base `HEAD` into an owner-only clone-private staging directory
using the existing commit materializer, then overlay the manifest-scoped worktree:
tracked staged/unstaged postimages, declared untracked files, deletions, and executable
mode. Out-of-scope dirty paths retain base bytes and are reported. Every overlay file is
opened no-follow, required to be regular, bounded, hashed from one descriptor, and
checked for metadata drift. Reobserve scoped Git status before accepting the projection.
Symlinks, gitlinks, special files, collisions, undeclared in-scope paths, or races block.

Mutable MPD process state is never candidate input: active `.mpd/state/**`,
`.mpd/current`, pending-closure pointers, parity observations, Build output,
`.mpd/local/**`, clone-private receipts/logs/caches, and every `.git/mpd/**` path are
outside the declared product scope and absent from the worktree overlay. Historical
ledger files already committed at base HEAD remain inert base bytes, never the active
ledger selected for this change. The live ledger binds gate/freshness history separately;
Build output and installation bind their own receipts. A normal ledger write therefore
cannot move the candidate ID, while a declared config/directive/hook/policy change must.
Validation executes in the retained projection with no active ledger/current pointer or
clone-private state mounted as a product input.

Sort entries by canonical UTF-8 path bytes and derive `id` from a domain-separated
canonical encoding of base tree, entries, manifest, policy, and source digests. The
clone-private storage path and display counts are capture metadata and do not affect the
ID. Atomically publish the completed projection under that ID, mark files/directories read-only;
checks write only to separate scratch/output roots. Rehash the projection before and
after each gate. Retain it through archive/closure verification and delete only its exact
recorded root. The user index, worktree, refs, and source object database never change.

Build, Security(code), and Test use this exact Candidate subject. Explicit
`validate --commit`, pre-push, and post-archive checks use Commit subjects. Candidate and
commit receipts are distinct even when their bytes later match. Build output is written
outside the projection and records the candidate ID.

Before Build, human/JSON reports show `candidate=NOT CAPTURED` and the current planning
artifact path/digest. Capture reports identical base, candidate ID, included/deleted/
untracked/mode counts, and excluded-dirty paths in both formats; every later gate repeats
the ID. Documentation and Doc Validation bind that candidate plus declared overlays;
Deploy binds its candidate-bound Build output.

Archive verifies that product source/config/test/policy/hook/script/task paths still
match the candidate. It permits only current canonical phase artifacts, reviewed durable
documentation, and deterministic archive postimages as overlays. After commit, closure
reconstructs the expected path/mode/digest set and compares it with the commit tree.

## Decision 2: freshness and append-only rewind

Extend existing ledger/receipt code rather than create a second state machine. Each PASS
records the dependency digests it reviewed. A pure projection returns stored phase,
effective phase, stale receipts, and earliest affected phase:

- Design Mock artifact -> Design Mock;
- Architecture or intent/manifest/task/risk inputs -> Architecture;
- Design Review -> Design Review; Security plan -> Security(plan);
- source/test/config/policy/tool/hook/script or Build evidence -> Build;
- Security(code), Design Sign-off, Test, Documentation, and Doc Validation artifacts ->
  their named phase; and Deploy artifact/definition -> Deploy. An earlier causal input wins.

`next`, `gate`, archive, and Deploy compute freshness under the ledger lock before any
effect. A stale mutating command appends one invalidation event, preserves every PASS/
FAIL and condition, reopens dependent obligations, rewinds, and stops. `status` is
read-only but reports the same projection. “Immediate” means the first MPD observation
blocks before it issues a downstream brief, runs a check, archives, or installs.

Extend `repair-state` with `--to <earlier-phase> --reason <text> [--yes]`. Preview is
read-only. Apply works only on an unarchived active ledger, binds its observed digest,
only rewinds, appends one reconciliation event, invalidates later receipts, preserves
history, and creates no verdict. Atomic write failure leaves the old ledger. Rerun either
applies from the same expected state or reports that the rewind already exists.

For this active change, compile and focused-test the native rewind normally, use it to
rewind to Architecture while retaining the existing Build FAIL, then rerun Architecture,
applicable Design Review, and Security(plan) before final Build PASS. No transition
helper, special commit, pretrust supervisor, or receipt ceremony is allowed for rewind;
the existing hidden exec mode used by Decision 4 is not a transition helper or second
state machine.

## Decision 3: risk cannot be lowered

Add a small versioned classifier in existing config/governance code. Derive risk from
manifest paths and settings for auth, credentials, untrusted parsing, network, process
execution, Git/hooks, persistence, sandboxing, crypto, deployment, and unknown additions
under those sensitive areas.

`effective_risk = max(requested_risk, derived_risk)`. Briefs, receipts, status, and JSON
show requested/derived/effective risk, reasons, classifier version, and signal digest.
Changing inputs invalidates Architecture. No flag or candidate config lowers the result.

## Decision 4: harden the existing local runner

Patch the existing validation path; module splitting and line-count refactors are not
release requirements. Authoritative profiles contain typed program/argv checks from
accepted policy. They never use `sh -c`, caller command strings, ambient `mpd`, or
optional required checks. Legacy strings may run only diagnostically and cannot pass a
gate, authorize push, or satisfy archive.

Every child gets a cleared environment plus allowlist, private HOME/XDG/temp/output,
monotonic timeout, concurrent stdout/stderr drains, per-stream and aggregate caps, and
terminate/grace/kill/reap behavior. Timeout, truncation, malformed result, leaked child,
cleanup failure, or cap overflow is BLOCKED, never clean. Authority-bearing files use
no-follow descriptor reads. Human/JSON output escapes control, ANSI, bidi, and invalid
path bytes; secrets and raw environments are not logged.

On the certified host only, the existing hidden exec mode becomes a digest-bound
compatibility adapter. The parent supplies one bounded canonical request over a private
close-on-exec control descriptor; filesystem roots never come from command argv,
environment, display text, or candidate-controlled configuration. The request binds its
nonce/digest, candidate, accepted policy, fixed profile digest, adapter ABI, typed
program/argv, limits, and canonical root inventory. Before sandbox entry the helper may
only clear environment/loader inputs, close every descriptor except bounded standard
streams and control, validate that request, observe root identities, and issue extension
tokens. It reads or executes no candidate input in this interval.

The helper uses a fixed reviewed profile with no variable path filters: deny by default;
allow required process operations and `sysctl-read`; allow global file metadata and
existence tests; allow `file-read-data` for the literal root directory required by the
macOS 27 dynamic loader; permit file read/test/map through read or read-write extensions;
permit file writes through read-write extensions plus literal `/dev/null`; and deny all
network operations. Global metadata/existence and literal-root directory-entry
confidentiality are not claimed. `process*` is not a claim of isolation from other
same-user processes; the full-suite process contract must stay inside the owned process
group and Security(plan) must accept or narrow that residual surface.

For each run the helper calls `sandbox_extension_issue_file` with `flags=0` for exact
canonical directories, then `sandbox_init(fixed_profile, 0)`, then consumes every token.
On this host a directory token with `flags=0` covers its subtree; the unsupported
`SANDBOX_EXTENSION_PREFIXMATCH` form returned `ENOTSUP` and is prohibited. Read roots
are the exact candidate, digest-locked coordinator/program, Rust and Homebrew dependency
roots, Command Line Tools/SDK, required system roots, and required `/dev` reads. The sole
read-write root contains private HOME, XDG, temporary, build, output, and test state;
only literal `/dev/null` is writable outside it. Roots are sorted, capped, canonical,
role-checked, symlink-safe, and bound by path/type/device/inode plus applicable digests.

Any issue, initialization, consume, identity, or cleanup failure exits without executing
the requested command. After entry the helper zeroizes token strings, runs the mandatory
canaries, and reports `READY` with the request/profile/root/canary digests. Only a matching
parent `GO` permits exec; the control descriptor closes first. Candidate re-invocation of
the hidden mode has no bootstrap channel, inherits the existing sandbox, and cannot issue
or consume a new extension. Existing open descriptors are capabilities, so no repository,
log, receipt, directory, file, or network descriptor may reach candidate execution.

Every authority-bearing run proves allowed candidate/tool reads and runtime writes;
denied controlled-secret and `~/.gitconfig` content reads; denied `/tmp` creation;
denied socket, loopback, outbound, and DNS use; child and grandchild inheritance;
symlink-escape denial; descriptor closure; and post-entry extension non-escalation.
Missing symbols, a nonmatching host, an unexpected allowance, or any ambiguous canary is
BLOCKED. There is no broader or alternate containment fallback.

The full local Commando profile runs format, warning-denied Clippy, locked workspace/
all-target tests, release build, dependency audit without update, gitleaks, Semgrep,
structured-input property tests, and documentation/coherence checks. Required tools and
offline inputs are pinned. Tests receive a fixed private Git identity and config, private
HOME/XDG/temp/process state, and no ambient user Git config, host process, or system-temp
dependency. Receipts record subject, host/build/arch, adapter ABI/profile/root/canary
digests, policy/tools, checks, real counts, exits, caps, suppressions, and bounded log
digests. The successful nested offline compiler probe is feasibility evidence only; the
full profile remains NOT CERTIFIED until every required lane and canary passes.

## Decision 5: practical Git-local enforcement

Reuse tracked `.githooks/pre-commit` and `.githooks/pre-push`. The sole ordinary route is
`mpd policy activate --commit <oid> --confirm-policy-digest <sha256> --coordinator
<absolute-mpd> --confirm-executable-digest <sha256> --hooks .githooks --yes`. It writes
clone-local policy/coordinator/wrapper digests and hooksPath, then reports `ACTIVE` or
`BLOCKED`. Wrappers quote argv/stdin and invoke only that absolute binary. Doctor checks
all identities plus the certified host, adapter ABI/symbol availability, and fixed
profile digest. Activation records adapter readiness but does not replace per-run roots,
canaries, or candidate receipts. `policy bootstrap`, `first-adoption`, pretrust proofs,
and fallback to historical paths are rejected; compilation/testing needs no activation
receipt.

Pre-commit performs bounded staged secret and artifact/task consistency checks only.
Pre-push parses Git's bounded update records and requires accepted policy for every
batch. Non-deletion updates resolve commit/tag subjects and scan every outgoing blob and
commit/tag message, including introduced-then-removed objects. Authorization binds the
remote, rows, baseline, object set, policy, result, and invocation nonce and is not a
reusable validation receipt.

Deletion-only does not return early: it runs trust/policy/input/ref checks. Commando
denies deletion of `main` and tags; another ref requires exact one-use owner approval.
Normal Git owns transport. A green hook means push authorization only. `publish --verify`
later observes OID parity; neither fact implies observed transfer or local validation.
`.github/workflows/` is absent and `scripts/ci-local.sh` invokes the same local profile.

## Decision 6: cooperative owner activation and final Deploy

A clean clone uses an owner-reviewed prior binary or ordinary locked local build. The
owner runs the full suite, inspects binary/policy/hook digests, and invokes the exact
`policy activate` command above. This is owner trust, not independent proof.
Candidate scripts never silently activate hooks/policy, install, commit, or push.

Build records one candidate-bound output from parent-opened bytes. Final Deploy reopens
it, copies through an exclusive target-directory temporary, syncs, atomically replaces,
reopens, and checks mode/length/digest. It never rebuilds or executes the installed
candidate for identity. Failure is BLOCKED and rerunnable from freshly verified source/
target state; no new journal/resume subsystem is required. A readiness-only PASS records
`executed=false` and `verified=false`.

## Incremental status contract

Extend existing human/JSON status with matching worktree, candidate, gate/freshness,
archive, commit, push authorization, transfer, parity, and install values. Receipt state
is CURRENT, FAILED, STALE, BLOCKED, or MISSING. Certification requires matching CURRENT
push authorization; absent or bypassed authorization displays MISSING/BYPASSED, and
remote parity cannot repair it. Adapter state reports exact host, profile/root/canary
digests, residual metadata/process limitations, and `BLOCKED/NOT CERTIFIED` on drift or
incomplete full-suite evidence. Preserve compatible fields and one safe next action.

Containment reporting keeps these typed layers separate in both human and JSON output:
adapter, host, SPI/ABI, fixed profile, root inventory, canaries, compiler process tree,
full local profile, certified claim, and residual limitations. Adapter and full-profile
certification are independently `CERTIFIED` or `NOT CERTIFIED`; compiler-process-tree
PASS remains feasibility evidence and cannot fill the full-profile field. These are
details under the seven workflow outcomes, not additional outcomes.

Every adapter BLOCKED result has exactly one code and one matching safe action:

- `sandbox.host-drift` -> run the unchanged candidate/policy on the exact certified host;
- `sandbox.spi-abi-drift` -> return to Architecture for adapter revision;
- `sandbox.profile-drift` -> run the printed digest-confirmed policy activation;
- `sandbox.root-drift` -> return to Build and recapture candidate/root inventory;
- `sandbox.canary-failed` -> return to Security(code) with the named failure/log; and
- `sandbox.full-profile-incomplete` -> run the printed complete exact-host profile for
  the current candidate.

An unclassified adapter failure uses `sandbox.spi-abi-drift`. Human and JSON derive code
and action from one typed result; neither rendering offers alternatives, silently acts,
or broadens containment.

All commands render one of seven workflow outcomes with identical meaning in human and
JSON forms: PASS, FAIL, BLOCKED, CONDITIONAL, STALE, IN PROGRESS, or NOT RUN. Candidate,
receipt, authorization/bypass, and readiness-versus-installed values remain typed detail
states rather than new outcome spellings. Human output carries explicit text labels;
meaning never depends on color, emoji, cursor movement, animation, or sound. TTY,
non-TTY, and `NO_COLOR` output are semantically complete.

JSON mode emits exactly one UTF-8 document to stdout; diagnostics and bounded child logs
go only to stderr. Human and JSON values derive from the same typed result. ANSI, OSC
hyperlinks, C0/C1 controls, bidi controls, hostile refs/messages/paths, and non-UTF-8 path
bytes are escaped or displayed as a safe label plus digest and never become executable
argv. A mutating operation atomically commits its identified durable result/effect before
emitting terminal PASS; output must never contain PASS before that commit succeeds.
Renderer/output failure before commit records no result. Output loss after commit returns
non-success and emits no new complete PASS, but does not erase or mislabel the committed
truth; the next read-only status and an idempotent retry report the exact event/effect
with zero duplication. A partial JSON stream is never a complete automation result.
Every read-only preview ends with the literal `No state changed.` and performs no durable
effect.

## File/dependency order

1. `phase.rs`, `ledger.rs`, `cli.rs`, config: doctrine, rewind, freshness, risk.
2. existing materializer/local validation plus focused `candidate.rs` if useful:
   projection capture, receipt subject, Build/Security/Test binding, closure comparison.
3. existing runner/scanners/sandbox: fixed-profile dynamic-extension adapter, private
   control handshake, bounded execution, canaries, and complete local profile.
4. `githooks.rs`, `.githooks/`, `scripts/ci-local.sh`: activation and full push policy.
5. existing Build/Deploy paths: candidate-bound bytes and fail-closed atomic copy.
6. status output and durable README/AGENTS/Architecture/Security/Contributing/runbooks/
   directives/help/config: one truthful shipped workflow.

## Risk-to-test map

- Candidate omission: tracked/staged/unstaged/untracked/deleted/mode/out-of-scope/race
  cases, deterministic ID, unchanged index/refs, and three-gate subject equality.
- Stale evidence: mutate every dependency class; prove earliest rewind, retained history,
  reopened obligations, read-only status, and no downstream effect.
- Risk lowering: every signal, unknown-sensitive High, maximum-law, and hostile config.
- Child/tool abuse: exact/over input/output/time/process boundaries, cleanup, terminal
  injection, canaries, missing tools, and no shell/PATH fallback.
- Sandbox bootstrap/SPI drift: root-in-argv/environment rejection, malformed/private
  control messages, pre-entry candidate access, partial issue/init/consume failures,
  inherited descriptors, token disclosure, symlink/root replacement, direct hidden-mode
  reinvocation, child/grandchild inheritance, post-entry non-escalation, host/symbol/ABI/
  profile drift, global metadata/root disclosure, process signaling, and zero fallback.
- Tool/test completeness: exact candidate/Rust/Homebrew/CLT/SDK/system/dev/runtime roots,
  nested offline compilation, private fixed Git identity, private HOME/XDG/temp/process
  state, all required lanes and canaries, and no ambient semantic dependency.
- Adapter representation: separate adapter/host/SPI/profile/root/canary/compiler-tree/
  full-profile/claim/limitation fields; all six blocker-code/action pairs, unclassified
  mapping, TTY/non-TTY/`NO_COLOR`, human/JSON parity, and no alternate action or fallback.
- Push bypass: malformed input, deletion-only/protected/mixed updates, nested tags,
  changed baseline, intermediate secrets, and one-use authorization.
- Install confusion: output/target replacement, wrong digest, interruption, rerun, and a
  spawn sentinel proving zero build/candidate execution.
- Process completeness: change-kind phase matrix, waiver denial, task/condition blocking,
  exact full local gate, docs/help coherence, clean-clone lifecycle, separate delivery facts.
- Renderer/accessibility: all seven outcomes and typed detail states across TTY,
  non-TTY, and `NO_COLOR`; one JSON stdout document; diagnostics-only stderr; ANSI/OSC/
  bidi/control/non-UTF-8 hostile values; broken pipe/signal/panic/crash on both sides of
  the durable commit boundary; idempotent retry; and literal no-effect preview
  termination.

## Conditions for Builder

1. Do not implement or execute the superseded mechanisms named above.
2. Run `cargo check --workspace --all-targets` immediately after plan gates, then build
   vertical slices with focused tests; do not postpone compilation until a commit.
3. Build, Security(code), and Test use one exact read-only candidate, never `HEAD`.
4. Freshness precedes effects; append-only rewind preserves every failed attempt.
5. Effective risk is `max(requested, derived)` and cannot be config-lowered.
6. Documentation and Doc Validation are mandatory before final Deploy; only Design may
   be N/A with rationale.
7. Authoritative execution uses the fixed-profile dynamic-extension adapter, typed argv,
   pins, caps, private state, and mandatory canaries; roots never derive from argv or
   candidate input and no hosted, shell, ambient coordinator, or fallback has authority.
8. Deletion-only receives full policy/ref authorization; normal Git owns transport.
9. Extend status incrementally and keep all delivery facts separate with honest
   cooperative-owner/reviewer limitations.
10. Certify only macOS 27.0 build 26A5378n, Apple silicon, `aarch64-apple-darwin`.
11. Deploy copies parent-observed tested bytes, executes no candidate for identity, and
    fails closed for a safe rerun rather than adding a recovery subsystem.
12. Update durable docs, verify every command/path, complete all tasks and the full local
    suite, then obtain independent Security(code), Test, and Doc Validation verdicts.
13. Keep the pre-sandbox helper path minimal: one bounded nonce-bound control request,
    cleared loader/environment state, closed ambient descriptors, exact root validation,
    issue/init/consume, zeroization, canaries, matching READY/GO, then typed exec.
14. Use `flags=0` directory extensions only; never use `PREFIXMATCH`, generated profile
    filters, inherited token text, or a broader root after an error.
15. Bind the exact adapter ABI, profile, roots, host, canaries, policy, tools, candidate,
    and command in receipts; unexpected allowance or ambiguity is BLOCKED.
16. Treat global metadata/existence, literal-root entries, and required process authority
    as explicit residual limitations; do not claim path-metadata or process isolation.
17. Supply fixed private test Git identity/config and private HOME/XDG/temp/process state;
    never repair a failing suite by mounting ambient `~/.gitconfig`, `/tmp`, or host
    process state.

## Required Design Mock replacement

Designer must keep the ordinary command flow, seven outcomes, exact-candidate display,
stale rewind, canonical artifacts, terminal accessibility, and separate delivery facts.
Remove pretrust/self-hosting/six-receipt migration, challenge-attestation ceremony,
synthetic candidate commits, two-platform certification, journaled Deploy recovery, and
authenticated-review or metadata/process-isolation claims. Replace them with read-only
projection, ordinary tested rewind, exact-host content/write/network containment,
cooperative activation, tracked local hook wrappers bound to an absolute binary,
incremental adapter status, and fail-closed rerun.

## Verdict

PASS

Implementation may begin only after fresh Design Review and Security(plan) PASS over
this architecture and the revised Design Mock. This approves the plan, not the code.
