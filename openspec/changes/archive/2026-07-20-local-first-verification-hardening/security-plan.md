# Security Plan: Exact-Host Local Validation

Date: 2026-07-19

## Actor

Security

## Review authority and artifact binding

This is the canonical plan-only Security review for
`local-first-verification-hardening`. It reviews the current operator contract,
Architecture, Design Review, Builder plan, and normative local-validation delta. It does
not inspect or approve Rust source, profile bytes, tests, receipts, hooks, installation,
archive, commit, push, or remote state. No candidate command was executed by this review.

| Reviewed artifact | Lines | SHA-256 |
| --- | ---: | --- |
| `design-mock.md` | 373 | `428e8e606270815497c3cf37322bf1d3c04e330725b56fd54db3fba33bfb3374` |
| `design.md` | 430 | `0de6fbeb73c64871c6f565e1ca72da6e48239d641b040a4f63c3be582840b01e` |
| `design-review.md` | 93 | `1b6acb59116105d4c014557af0e00d97ef36f070f040a4178049ae9e3bf18588` |
| `tasks.md` | 164 | `80a0c908b9e1f8d9908f57e6cd4f57e8da4f2dd970bf6fea32f12cd33a9ec199` |
| `specs/local-validation/spec.md` | 228 | `7ac3c591fb214822d3af9844911eb1875542683494810dcce65d042877c13984` |

The certified-platform claim is limited to macOS 27.0 build `26A5378n`, Apple
silicon, `aarch64-apple-darwin`. All other platform identities are `NOT CERTIFIED`.
That boundary is plan authority only. Current implementation and full-profile evidence
remain blocked as recorded below.

## Threat model and accepted residual risk

### Protected assets

- The exact candidate path/state/mode/byte inventory and its immutable projection.
- Candidate-bound Build output and parent-observed installed bytes.
- Append-only phase, FAIL, condition, freshness, rewind, archive, and closure truth.
- Accepted policy, typed command, coordinator, tool, hook, scanner, and offline-input
  identities used by a receipt or push authorization.
- Host credentials and content outside accepted read roots; writes outside the one
  private read-write root and literal `/dev/null`; all network access.
- Bounded child resources, process-tree cleanup, redacted logs, and terminal/JSON
  channel integrity.
- The complete Git update batch and outgoing commit/tag/message/blob set, including
  deletion-only updates and one-use deletion authorization.
- Separation of candidate, gate, local validation, archive, commit, push authorization,
  observed transfer, remote parity, Deploy readiness, and installed-byte facts.

### Adversarial inputs and effects

Treat worktree paths and symlinks, Git status/refs/hook input, policy and evidence files,
candidate configuration, typed argv, environment and loader variables, inherited file
descriptors, sandbox control messages and tokens, tool output, structured data,
interruptions, races, partial durable effects, and hostile display bytes as untrusted.
Ambiguity, drift, truncation, timeout, output/resource cap overflow, leaked descendants,
or cleanup failure cannot produce PASS or a reusable authorization.

The compatibility adapter has a privileged pre-entry interval: before Seatbelt entry it
can issue filesystem extensions and still has the parent process's ambient authority.
The adapter protocol, not candidate cooperation, must make that interval incapable of
reading or executing candidate content, selecting new roots, leaking tokens, or carrying
ambient descriptors into the child.

### Assurance boundary

The repository owner is cooperative and can replace MPD, policy, hooks, refs, receipts,
or local state and can use `--no-verify`. MPD does not resist or independently attest
against that owner. Actor/model/session identities are cooperative provenance unless an
external harness authenticates them. Normal Git owns transport. GitHub Actions and other
hosted checks are not validation authority.

The macOS adapter deliberately uses deprecated/unsupported custom-profile
`sandbox_init` behavior and undocumented exported sandbox-extension SPI. This is an
exact-host compatibility claim, not a supported or portable Apple API guarantee. The
certified claim is only accepted-root **content read**, private-root plus `/dev/null`
**write**, and **network denial**. The fixed profile permits global path
metadata/existence and literal-root directory entries; those are not confidential.
Required process authority is not isolation from other same-user processes. These
limitations are accepted only when they are explicit in human output, JSON, receipts,
and durable documentation.

## Primary security sources and local evidence boundary

The Architecture's API and empirical claims must be checked in Security(code) and Test
against the current host's local `sandbox_init(3)` manual, SDK `sandbox.h` declaration,
exported `libsystem_sandbox` extension symbols, fixed profile bytes, and recorded
exact-host canary logs. Apple's primary references *Protecting user data with App
Sandbox*, *Embedding a command-line tool in a sandboxed app*, and the *App Sandbox
temporary exception entitlements* reference are relevant only to explain the supported
signed-container model and its exceptions; they do not authorize this deprecated-SPI
adapter or provide a fallback. The successful local
`cargo -> rustc -> linker -> test binary` child/grandchild probe is feasibility evidence
only. No source reference, API presence, or narrower probe substitutes for the complete
candidate-bound local profile.

## Findings

### SP-4 — unsupported exact-host adapter can drift silently

**[HIGH]** Deprecated custom-profile `sandbox_init` plus undocumented extension SPI has
no stable cross-release contract; symbol presence alone cannot establish equivalent
semantics -> bind certification to exact macOS version/build, architecture, exported
symbols, accepted ABI, fixed profile digest, exact root inventory, and the complete
mandatory canary matrix for every authority-bearing run. Any mismatch or unclassified
failure is `BLOCKED`/`NOT CERTIFIED`, maps to the single reviewed blocker/action, and has
no App Sandbox, `sandbox-exec`, broad-read, unsandboxed, hosted, or other fallback.

Plan disposition: **CLOSED at plan level** by `design.md` Decision 4 and
`specs/local-validation/spec.md` Typed bounded local profiles. Implementation remains
unapproved and full-profile certification remains blocked.

### SP-5 — pre-entry authority and root injection

**[CRITICAL]** A helper that accepts roots from argv, environment, display text, or
candidate-controlled configuration can mint authority for an attacker-selected path
before sandbox entry -> accept exactly one bounded canonical nonce-bound request over a
private close-on-exec control descriptor; derive roots only from accepted candidate,
policy, tool/SDK/cache inventory, and private runtime state; bind request digest,
candidate, command, policy, profile, ABI, limits, and roots; reject direct hidden-mode
reinvocation without the private bootstrap channel. During the pre-entry interval clear
all loader/DYLD and non-allowlisted environment state, close every ambient descriptor
except bounded standard streams and control, validate roots, and perform no candidate
read or execution.

Plan disposition: **CLOSED at plan level**. Root-in-argv/environment/config, malformed
control, nonce replay, direct reinvocation, and pre-entry candidate-access tests are
mandatory Builder evidence.

### SP-6 — symlink, root-replacement, and stale-inventory races

**[CRITICAL]** Canonical path strings without stable object identity allow a root or
candidate path to be replaced after approval and before extension issue/use -> require
sorted, capped, role-checked roots bound by canonical path, object type, device, inode,
and applicable content/tool/profile digest; use no-follow descriptor observations and
pre/open/post identity checks; reject symlinks, special files, alias collisions, path
replacement, and root drift. Revalidate the accepted identity adjacent to extension
issue and before READY; any uncertainty returns `sandbox.root-drift` or the typed
unclassified fail-closed result without executing the candidate.

Plan disposition: **CLOSED at plan level**. Exact/over-boundary, symlink escape,
directory replacement, ABA, descriptor identity, and cleanup-ownership tests remain
mandatory.

### SP-7 — token, descriptor, and bootstrap capability leakage

**[CRITICAL]** Extension tokens and already-open descriptors are capabilities; a leaked
token or descriptor can bypass pathname policy, and an inherited bootstrap channel can
mint later authority -> issue canonical directory extensions with `flags=0` only; never
use `SANDBOX_EXTENSION_PREFIXMATCH`; call issue, `sandbox_init(fixed_profile, 0)`, then
consume every token with every return checked; zeroize all token text; run denial,
inheritance, descriptor, and post-entry non-escalation canaries; emit digest-bound READY;
require matching parent GO; close the control descriptor before typed exec. Pass only
the bounded standard streams and expressly required descriptors. A descendant or
reinvoked helper must inherit containment and have no extension-issue authority.

Plan disposition: **CLOSED at plan level**. Token disclosure, partial issue/init/consume,
zeroization, descriptor leakage, child/grandchild, post-entry reissue/consume, and
cleanup tests remain mandatory.

### SP-8 — containment overclaim

**[HIGH]** The fixed profile's global metadata/existence and literal-root access, plus
required process operations, cannot support path-metadata confidentiality or same-user
process-isolation claims -> report only accepted-root content-read containment,
private-root plus literal `/dev/null` write containment, and network denial. Show global
metadata/root-entry visibility and absent same-user process isolation as residual
limitations in the same typed human/JSON result and receipt. Prove `/dev/null` is the
only literal write outside the exact private root; deny secret/`~/.gitconfig` content,
`/tmp` creation, socket, loopback, outbound, and DNS access; exercise process signaling
and root-directory visibility without converting their expected availability into a
failure or a stronger claim.

Plan disposition: **CLOSED at plan level**. Any broader wording or a failed denial canary
returns to Security(code) and blocks certification.

### SP-9 — compiler-tree feasibility is not a complete local profile

**[BLOCKER]** A successful offline compiler child/grandchild probe does not establish the
full Commando build/test/security/doc/coherence profile, private Git/runtime semantics,
or the complete canary matrix -> keep adapter, compiler-process-tree, full-profile, and
certified-claim fields separate. Supply fixed private Git identity/config and private
HOME/XDG/temp/build/output/test/process state. Run every configured lane with pinned
offline inputs, real non-zero test counts where applicable, exact candidate binding, and
all canaries. Ambient `~/.gitconfig`, system `/tmp`, host process state, a broader mount,
or a weaker execution mode cannot repair a failing lane.

The following seven failures last observed in the earlier partial containment run are
mandatory Builder regression targets and must pass in the complete contained profile
without weakening containment or deleting the assertions:

1. `runtime_ledger_resolves_archived_state_after_current_clears_and_requires_clean_head`
2. `candidate_output_retry_preserves_unproven_preexisting_entries`
3. `candidate_output_post_link_failure_cleans_only_owned_publication`
4. `candidate_output_proof_to_arm_races_preserve_and_rollback_exactly`
5. `check_staged_resolves_pending_closure_and_still_blocks_unrelated_paths`
6. `pre_commit_accepts_exact_pending_closure_scope_and_blocks_unrelated_paths`
7. `checkpoint_scope_is_exact_read_only_and_distinguishes_deletion_from_absence`

Plan disposition: **OPEN IMPLEMENTATION BLOCKER**. This does not invalidate the plan,
but it blocks Security(code) PASS, Test PASS, production certification, archive/closure,
commit/push certification, installation, and any production-ready claim.

### SP-10 — candidate substitution and stale gate reuse

**[CRITICAL]** Validating HEAD or an immutable commit while the intended worktree differs
can approve bytes that were never reviewed -> Build, Security(code), and Test must use
one immutable exact Candidate projection and rehash it before and after each gate;
candidate and Commit receipts remain different subjects; freshness runs under the ledger
lock before every downstream brief/effect and retains all FAIL/CONDITIONAL history.
Closure later compares the exact candidate plus only reviewed canonical overlays with
the commit tree.

Plan disposition: **CLOSED at plan level**. Uncommitted-failure/passing-HEAD,
process-state-exclusion, stable-versus-moving-input, rehash-race, stale-rewind, and exact
closure-equivalence tests remain mandatory.

### SP-11 — runner, scanner, and output ambiguity

**[HIGH]** Shell strings, ambient PATH/environment, sequential pipe drains, partial file
scans, output truncation, leaked descendants, or unsafe rendering can create false green
or spoofed evidence -> accept only reviewed typed program/argv and pinned executable
identity for authority-bearing checks; clear/allowlist environment; use private writable
state; drain stdout/stderr concurrently with per-stream and shared aggregate caps; use
monotonic terminate/grace/kill/reap deadlines; scan bounded required files completely;
redact logs; escape ANSI/OSC/C0/C1/bidi/non-UTF-8 data; and treat missing tools,
truncation, malformed results, leak, timeout, cap, or cleanup failure as BLOCKED. Legacy
`sh -c` checks may be diagnostic only and cannot satisfy a gate, archive, or push.

Plan disposition: **CLOSED at plan level**. Boundary/property tests and real check/test
counts remain mandatory implementation evidence.

### SP-12 — hook activation and deletion-only push gaps

**[CRITICAL]** A PATH-resolved, bootstrap/pretrust, candidate-controlled, or drifted hook
can authorize different code; deletion-only updates can bypass object scanning; reusable
deletion consent can authorize another batch -> allow only the digest-confirmed
`mpd policy activate` route bound to an immutable reviewed commit/policy, absolute
coordinator and executable digest, tracked wrappers, and `.githooks`. Doctor and hooks
fail closed on any identity/host/profile drift. Pre-push parses bounded real input and
binds authorization to remote, baseline, raw rows, complete outgoing objects, policy,
result, and invocation nonce. It denies `main` and tag deletion before lookup and
atomically consumes other deletion approval once against the exact remote/ref/old OID/
zero new OID/batch/baseline/policy/nonce tuple. Normal Git alone performs transport.

Plan disposition: **CLOSED at plan level**. Quoting, wrapper/binary/policy drift,
malformed/mixed/nested-tag/deletion input, introduced-then-removed secrets, baseline
drift, wrong-old, replay, and concurrent one-use consumption tests remain mandatory.

### SP-13 — Deploy execution or identity confusion

**[CRITICAL]** Rebuilding or executing candidate/installed bytes during Deploy can change
the subject or run untrusted code merely to establish identity -> Deploy accepts only
parent-opened candidate-bound Build output, reopens that exact output, copies through an
exclusive target-directory temporary, syncs, atomically replaces, reopens, and compares
mode/length/digest. It never rebuilds or executes candidate or installed bytes. A
readiness-only result records `executed=false` and `verified=false`; any ambiguous or
partial effect is BLOCKED and reruns only after fresh source/target observation.

Plan disposition: **CLOSED at plan level**. Source/output/target replacement, wrong
digest, interrupted-copy/rerun, cleanup ownership, and a spawn sentinel proving zero
execution remain mandatory.

### SP-14 — durable truth and display-channel confusion

**[HIGH]** Emitting PASS before a durable result, treating partial JSON as complete, or
collapsing authorization/parity/install states can turn an output failure into false
assurance -> atomically commit the identified result/effect before terminal PASS; record
nothing on pre-commit output failure; return non-success without erasing the committed
truth after post-commit output loss; make retry/status idempotent with zero duplicate
effects. Human and JSON derive from one typed result; JSON is exactly one UTF-8 stdout
document and diagnostics are bounded stderr. Preserve the seven workflow outcomes and
separate candidate, validation, archive, commit, authorization/bypass, transfer, parity,
readiness, and installation fields.

Plan disposition: **CLOSED at plan level**. Broken pipe/signal/panic/crash tests on both
sides of the durable boundary and all human/JSON/TTY/non-TTY/`NO_COLOR` goldens remain
mandatory.

## Conditions verified

Verified at plan level: the current Design Mock, Architecture, Design Review, Builder
plan, and local-validation spec consistently require the exact-host/no-fallback adapter,
bounded cooperative-owner claim, private nonce control channel, non-candidate-derived
roots, exact root identity, fail-closed issue/init/consume protocol, token and descriptor
containment, complete canaries, candidate/gate/commit separation, complete local push
authorization, no-exec Deploy, durable result ordering, and explicit residual
limitations. The named controls are coherent and have exact Builder fixes and evidence
requirements.

Not verified by this plan review: implementation, profile bytes, SPI/ABI behavior,
canary execution, native test results, full-profile lanes, receipts, hooks, closure,
delivery, or installation. SP-9 and every implementation-dependent condition remain
unverified and **BLOCKED** until independently evidenced at Security(code) and Test.

## Conditions for Builder

1. Implement only the bounded local kernel. Do not reintroduce a transition helper,
   pretrust/first-adoption/bootstrap route, custom receiver, recursive proof ceremony,
   new supervisor, owner-resistant identity claim, or hosted validation authority.
2. Build, Security(code), and Test must use one immutable rehashed Candidate projection,
   never ambient HEAD, active MPD process state, or Commit evidence as a substitute.
3. Freshness must precede every downstream brief/effect under the ledger lock; retain
   every prior PASS/FAIL/CONDITIONAL event and stop after one earliest invalidation.
4. Keep the compatibility adapter's pre-entry path minimal: validate one private
   nonce-bound control request; clear DYLD/loader and non-allowlisted environment state;
   close ambient descriptors; validate exact root type/device/inode/digest; issue with
   `flags=0`; enter the fixed profile; consume; zeroize; run canaries; READY/GO; close
   control; then typed exec. No candidate content is read or executed before entry.
5. Roots never derive from argv, environment, display text, candidate configuration, or
   hidden-mode reinvocation. Root/symlink/identity drift blocks; there is no fallback.
6. Receipts bind candidate, host/build/arch, adapter ABI/symbols, fixed profile, exact
   roots, canaries, policy, tools, command, limits, checks, counts, exits, and log digests.
7. Certification claims only accepted-root content reads, writes confined to the private
   root plus `/dev/null`, and network denial. Always disclose global metadata/root-entry
   visibility and absent same-user process isolation.
8. SP-9 remains an implementation blocker. All seven named containment regressions, every required
   profile lane, and the complete candidate-bound canary matrix must pass with fixed
   private Git/HOME/XDG/temp/process state before a downstream PASS or production claim.
9. Runner/scanner limits, typed argv, full bounded scans, process-group cleanup, hostile
   rendering, and commit-before-terminal-PASS ordering are mandatory and fail closed.
10. Activation uses only immutable digest-bound policy/wrappers/absolute coordinator.
    Pre-push covers every update and exact outgoing object; deletion approval is exact,
    atomic, one-use, and never permits `main` or tag deletion. Git owns transport.
11. Deploy copies only parent-observed candidate-bound bytes through the reviewed atomic
    no-exec path and never promotes readiness-only to installed-and-verified truth.
12. Any material change returns to the earliest affected phase. Security(code), Design
    Sign-off, Test, Documentation, Doc Validation, and Deploy remain separate future
    gates; none may reuse this plan PASS as its evidence.

## Reviewed and omitted scope

Reviewed: current Design Mock, Architecture, Design Review, Builder plan, and normative
local-validation delta; exact candidate and freshness boundaries; exact-host adapter
authority; nonce control protocol; root, symlink, token, descriptor, child/grandchild,
non-escalation, content/write/network and residual-limit claims; typed local runner;
full-profile proof layering; cooperative policy/hook activation; complete pre-push and
deletion authorization; no-exec Deploy; durable output ordering; and separated delivery
facts.

Not reviewed: Rust implementation or diff; literal profile bytes; symbol/ABI behavior;
extension-token implementation; scanner/tool/policy/hook bytes; generated artifacts;
tests, counts, logs, fuzz seeds, performance, or resource use; actual host identity;
candidate/Build output; receipts; archive/closure; commit; push authorization or
transfer; remote parity; installation; or any platform other than the declared exact
Mac. The seven named failures are carried as earlier partial-containment implementation
evidence, not independently reproduced by this plan review.

## Verdict

PASS

The current Design Mock, Architecture, Design Review, tasks, and
local-validation spec contain a coherent fail-closed threat model and exact fixes for
the reviewed risks within the cooperative-owner, exact-host boundary. Builder may
continue under the Conditions for Builder.

**Current implementation/certification status: BLOCKED.** SP-9 remains open: all seven
named native tests and the complete candidate-bound exact-host profile/canary matrix
must pass without a broader root, ambient state, weaker sandbox, or other fallback.
Therefore this PASS does not approve Security(code), Test, production readiness,
archive/closure, commit/push certification, installation, remote parity, or any claim
that the full local profile is currently certified.
