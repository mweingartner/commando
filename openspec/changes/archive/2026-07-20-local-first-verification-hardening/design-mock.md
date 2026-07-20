# Design Contract: Bounded Local MPD

## Actor

Designer

## Purpose and boundary

This document is the target operator experience and release contract for the change. It
does not claim that the work-in-progress binary or durable guidance already conforms.
Any conflicting shipped help, command, or documentation is a release blocker to remove,
not an alternative workflow.

MPD is a local developer workflow for turning a task into a reviewed, tested,
documented, deploy-ready Git change. It coordinates phase work, records evidence, runs
local checks, and keeps engineering completion separate from Git delivery.

The trust boundary is a cooperative repository owner. An owner can replace MPD, edit
policy or Git state, bypass hooks with `--no-verify`, or forge local files. MPD makes
those actions visible when it can, but does not claim independent attestation against
that owner. GitHub Actions and other hosted checks are neither required nor accepted as
validation authority.

Compilation and tests are ordinary local development actions and may run before a
commit. A receipt records an observed check result against a named subject; it never
authorizes compilation or requires a pretrust, bootstrap, self-hosting, supervisor, or
receipt-to-create-a-receipt ceremony.

## Certified release platform

Production release certification is intentionally narrow:

- target: `aarch64-apple-darwin`;
- only eligible certification host: macOS 27.0, build `26A5378n`, Apple silicon;
- containment: the reviewed exact-host dynamic-extension compatibility adapter, with
  the accepted SPI/ABI, fixed profile, canonical root inventory, and every mandatory
  denial/inheritance/non-escalation canary current for that run;
- required full-profile evidence: warning-free release build, full workspace tests,
  configured security checks, documentation validation, and installed-artifact
  verification on that same host; and
- every other architecture or operating system is `NOT CERTIFIED`, not implicitly
  supported and not eligible to reuse the macOS receipt.

The adapter is a fail-closed compatibility boundary over deprecated custom-profile
Seatbelt entry points and undocumented exported sandbox-extension SPI. It is not a
portable or supported Apple API contract. It reports `CERTIFIED` only on the exact host
above after host, symbols, ABI, profile, roots, control handshake, and all mandatory
canaries match. Host, SPI/ABI, profile, root, inheritance, or canary drift reports
`NOT CERTIFIED` and makes the attempted validation `BLOCKED`. There is no App Sandbox,
`sandbox-exec`, broad-read, unsandboxed, hosted, or other fallback.

The certified containment claim is deliberately limited: accepted-root file content
can be read, writes are confined to the declared private read-write root plus
`/dev/null`, and network operations are denied. Global path metadata/existence and
literal-root directory entries are not confidential under the fixed profile. Required
process authority is not process isolation from other same-user processes. Status must
not claim either path-metadata confidentiality or process isolation unless a separately
reviewed proof and certification scope is later added.

A successful offline `cargo -> rustc -> linker -> test binary` child/grandchild probe
proves compiler-process-tree feasibility and inherited containment for that probe only.
It does not certify the complete local profile, the full test suite, private Git/runtime
state, every configured security lane, or installed-artifact verification. Human and
JSON output therefore show compiler-process-tree proof and full-profile certification
as separate fields. Ordinary development may occur elsewhere, but release status
remains blocked until the current candidate has both a certified adapter run and a
complete current full-profile receipt on the platform above.

At this design revision, the compiler-process-tree probe is feasibility evidence; the
complete local profile is still `NOT CERTIFIED` until its required checks, private
runtime state, and complete canary matrix pass together for the current candidate.

## Phase flow

The ordered workflow is:

```text
Design Mock? -> Architecture -> Design Review? -> Security (plan) -> Build ->
Security (code) -> Design Sign-off? -> Test -> Documentation ->
Doc Validation -> Deploy
```

Only the three Design phases may be N/A, and only with a recorded no-human-visible-
impact rationale. All other phases run with depth proportionate to risk. FAIL blocks.
CONDITIONAL does not advance until every condition has closing evidence and a fresh
verdict. A material change returns to the earliest affected phase.

`mpd conduct` derives effective risk from both the operator request and affected
capabilities. The higher risk wins. Unknown security-sensitive scope is treated as high
risk rather than silently downgraded.

## Everyday developer journey

```text
mpd conduct <change> [--ui] [--risk low|medium|high]
mpd next --harness <harness> --context
# perform exactly the displayed role work; compile and test whenever useful
mpd gate <phase> --pass|--conditional|--fail --evidence <artifact>
# repeat next/work/gate through Deploy
mpd status
mpd archive --yes
git add <reviewed-paths...>
git commit
git push
mpd publish --verify
```

The operator stages named paths, never blanket-adds the repository. Commit and push are
normal Git operations: no amend, force push, or `--no-verify` in the certified flow.
`publish --verify` is read-only remote observation after push; it does not validate,
commit, push, deploy, or repair anything.

## Exact candidate contract

Before Build capture, every human and JSON report says `Candidate: NOT CAPTURED` and
names the current planning artifact path and digest; it never substitutes `HEAD` and
calls that a candidate. Build capture and every later candidate-bearing gate report name
the exact declared worktree candidate reviewed: base commit, included paths and
deletions, relevant untracked files, modes, excluded dirty paths, and a deterministic
candidate digest. Capturing or checking a candidate does not stage files, move refs,
modify the user's index, or require a commit.

Build PASS establishes the candidate used by downstream Security(code), Test,
Documentation, Doc Validation, and Deploy. Those gates may add only their declared
phase artifact or reviewed documentation output; any source, test, policy, script,
dependency, or unexpected path change makes affected evidence `STALE` and rewinds to
the earliest invalidated phase before another action can run.

Archive verifies that all gates, tasks, conditions, documentation, and candidate-bound
evidence are current, then records the allowed archive postimage. The subsequent commit
must equal the reviewed candidate plus only those declared phase/documentation/archive
postimages. Pre-push validates the resulting immutable outgoing commit and complete
outgoing object set; worktree evidence is never silently treated as commit evidence.

## Local validation and receipts

Local checks use bounded typed commands from reviewed repository policy. Human-invoked
checks, gate checks, pre-commit checks, and pre-push checks may compile and test. They
must report the subject, command/profile, tool identity, exit status, test/check counts,
duration, bounded log location, and omissions.

A validation receipt is one of:

- `CURRENT`: passed for the exact candidate or commit and current policy/tools;
- `FAILED`: checks ran and at least one objective check failed;
- `STALE`: subject, policy, tool, or required input changed;
- `BLOCKED`: a prerequisite was unavailable or unsafe, so no valid result exists; or
- `MISSING`: no matching validation was observed.

Missing tools, timeouts, output/resource limits, malformed input, and ambiguous process
results are `BLOCKED`, never a smaller green suite. Required checks cannot be skipped or
converted to PASS by truncated output. Receipts are local, owner-forgeable evidence;
they are not signatures, gate verdicts, push authorizations, or remote observations.

Every authoritative macOS profile reports containment without collapsing its layers:

```text
Containment adapter | Host | SPI/ABI | Fixed profile | Root inventory | Canaries
Compiler process tree | Full local profile | Certified claim | Residual limitations
```

`Containment adapter: CERTIFIED` requires all adapter fields and canaries to be current
for the exact run. `Compiler process tree: PASS` is only the bounded nested-tool probe.
`Full local profile: CERTIFIED` additionally requires every configured check lane, real
non-zero counts where applicable, private Git/HOME/XDG/temp/process state, and the
candidate-bound receipt. A pass in either narrower row cannot fill a missing wider row.

An adapter blocker has one blocker code and exactly one displayed remediation action;
the renderer never offers alternatives or silently takes the action:

| Blocker code | Exactly one safe remediation action |
| --- | --- |
| `sandbox.host-drift` | Run the unchanged candidate and policy on macOS 27.0 build `26A5378n`, Apple silicon. |
| `sandbox.spi-abi-drift` | Return to Architecture for a reviewed compatibility-adapter revision. |
| `sandbox.profile-drift` | Re-run the one printed digest-confirmed policy-activation command for the reviewed fixed profile. |
| `sandbox.root-drift` | Return to Build and recapture the candidate and declared root inventory. |
| `sandbox.canary-failed` | Return to Security(code) with the one named isolation failure and bounded canary log. |
| `sandbox.full-profile-incomplete` | Run the one printed complete exact-host local-profile command for the current candidate. |

An unclassified adapter failure uses `sandbox.spi-abi-drift` and its Architecture
action; it never invents a recovery or broadens authority. The corresponding JSON
contains the same single `blocker_code` and one structured `next_action`.

## Hooks, pushes, and owner bypass

The active clone-local pre-commit hook checks the exact staged postimage and blocks
secrets or malformed process state. The pre-push hook parses Git's update batch,
validates every outgoing commit/tag required by policy, scans the complete bounded
outgoing object set, and issues authorization only for that invocation and baseline.

Deletion-only pushes do not succeed early merely because there are no outgoing blobs.
They still require valid hook input, current local policy, and ref-deletion policy.
Deletion of the default branch or a tag is denied; any permitted deletion is bound to
the exact remote, ref, and old object ID.

`git push --no-verify` remains an owner-controlled bypass. If used, push authorization
is `MISSING/BYPASSED`; later remote parity cannot retroactively create it, and the result
is not release-certified. MPD reports the limitation and does not claim hooks are an
independent security boundary.

## Truthful states and recovery

Human and JSON status keep these facts separate:

```text
Worktree candidate | Gate evidence | Local validation | Deploy/install
Archive | Commit | Push authorization | Transfer observation | Remote parity
```

No earlier fact implies a later one. In particular, PASS gates do not imply archive;
archive does not imply commit; authorization does not imply transfer; remote parity does
not prove an authorized push; and readiness-only Deploy does not claim installation.

Workflow outcomes are `PASS`, `FAIL`, `BLOCKED`, `CONDITIONAL`, `STALE`,
`IN PROGRESS`, and `NOT RUN`. Every nonterminal report provides exactly one safe next
action. Preview commands are read-only and end with `No state changed.` Mutating
recovery requires explicit confirmation, validates the recorded operation identity,
and never broadens cleanup. An unknown or partially observed effect remains BLOCKED.

The seven outcomes have one meaning in both renderings:

- `PASS`: the named phase or operation completed with its required current evidence;
- `FAIL`: an objective check or review verdict ran and failed;
- `BLOCKED`: MPD refused to run or complete because a prerequisite, input, limit, or
  effect identity was unavailable or unsafe;
- `CONDITIONAL`: review found named open obligations and no downstream phase advances;
- `STALE`: previously recorded evidence no longer matches its causal inputs;
- `IN PROGRESS`: the phase is active but has no terminal current verdict; and
- `NOT RUN`: no attempt exists for the named phase or operation.

Candidate state is separately `NOT CAPTURED`, `CURRENT`, `STALE`, or `BLOCKED`.
Validation-receipt state is separately `MISSING`, `CURRENT`, `FAILED`, `STALE`, or
`BLOCKED`. Push authorization additionally distinguishes `BYPASSED`; installation
distinguishes `readiness-only` from `installed-and-verified`. These are typed details,
not extra spellings that collapse the seven workflow outcomes. Adapter and full-profile
certification are separately `CERTIFIED` or `NOT CERTIFIED`; certification is not an
eighth workflow outcome and never promotes a `BLOCKED`, `MISSING`, `FAILED`, or `STALE`
receipt.

Representative stale output:

```text
STALE Test
Candidate: old sha256:... -> current sha256:...
Rewind: Build
History retained: yes
Next: complete Build for the current worktree candidate.
```

Representative completion output:

```text
PASS Deploy · readiness-only
Candidate: sha256:...
Installed: false · verified: false
Archive: not created · Commit: not created · Push authorization: missing
Next: run `mpd archive --yes`.
```

Representative exact-host adapter output before full-profile certification:

```text
BLOCKED Local validation
Candidate: sha256:...
Containment adapter: CERTIFIED
Host: macOS 27.0 (26A5378n) · arm64 · CURRENT
SPI/ABI: CURRENT · Fixed profile: CURRENT · Root inventory: CURRENT
Canaries: PASS <required>/<required>
Compiler process tree: PASS · feasibility evidence only
Full local profile: NOT CERTIFIED · MISSING
Certified claim: content-read/write/network isolation only
Not claimed: path-metadata confidentiality; same-user process isolation
Blocker: sandbox.full-profile-incomplete
Fallback: none
Next: complete the Test gate for candidate `sha256:...`.
```

Representative drift output:

```text
BLOCKED Local validation
Candidate: sha256:...
Containment adapter: NOT CERTIFIED
Host: macOS 27.0 (26A5378n) · arm64 · CURRENT
SPI/ABI: CURRENT · Fixed profile: STALE · Root inventory: NOT RUN
Canaries: NOT RUN
Compiler process tree: NOT RUN
Full local profile: NOT CERTIFIED · BLOCKED
Blocker: sandbox.profile-drift
Fallback: none
Next: run `mpd policy activate ...<exact reviewed digests>...`.
```

## Human and JSON parity

Human and JSON output are two renderings of one typed result. Both expose the same
outcome, code, phase, candidate/commit subject, receipt state, blockers, effects,
delivery facts, adapter certification fields, compiler-process-tree proof,
full-profile certification, certified claim, residual limitations, and single next
action. Every `BLOCKED` result carries exactly one blocker code and exactly one safe
next action in both renderings. JSON emits exactly one UTF-8 document to stdout;
diagnostics and bounded child logs go to stderr. Automation never parses human prose.

Meaning never depends on color, emoji, cursor movement, animation, or sound. `NO_COLOR`
and non-TTY output remain complete. Paths, refs, commit text, control characters, ANSI,
bidi controls, hyperlinks, and non-UTF-8 bytes are escaped or represented by a safe
display plus digest; display text is never executable argv. Secrets and raw environments
are not printed. A mutating command emits terminal PASS only after its identified
result/effect is durably committed. Broken pipe, crash, or signal before that boundary
creates no result. Output loss after commit returns non-success and emits no complete
terminal PASS, but it does not erase or mislabel the committed truth; the next read-only
status and an idempotent retry report that exact event without duplicating it.

## Known current-surface delta

The observed work-in-progress `--help` still exposes `policy bootstrap`,
`first-adoption`, pretrust language in `validate`, a legacy `policy activate` signature,
and `gate --waive-artifact`. The current `AGENTS.md` also retains historical foundation,
broker, and pretrust instructions below its supersession notice. None belongs to this
approved experience: the release must remove those active routes and references, expose
the digest-confirmed cooperative `policy activate` flow, and deny artifact waivers.
Until then, the current binary and durable guidance are explicitly nonconforming and not
release-certified. Ordinary local compilation and tests remain valid development actions
and do not wait for any of those superseded ceremonies.

## Checkable acceptance criteria

1. A developer can conduct, gate, compile, test, document, archive, commit, normally
   push, and verify parity without GitHub Actions or any hosted validation result.
2. Pre-Build gates report `Candidate: NOT CAPTURED` plus their planning subject; Build
   and every later candidate-bearing gate repeat the exact Build candidate, while
   pre-push separately validates immutable outgoing commits.
3. In-scope drift immediately marks dependent evidence stale, retains history, and
   rewinds before the next brief or effect.
4. Effective risk cannot be lowered below derived risk; security-sensitive unknowns are
   high risk.
5. Architecture, Security(plan), Build, Security(code), Test, Documentation,
   Doc Validation, and Deploy cannot be skipped; Design N/A requires rationale.
6. Full configured checks report real nonzero counts and omissions; missing tools,
   limits, or ambiguity cannot produce PASS.
7. Pre-commit and pre-push fail closed for malformed input while remaining honestly
   bypassable by the cooperative owner.
8. Deletion-only, mixed, tag, and ordinary pushes all receive the applicable local
   policy decision; protected deletions are denied.
9. Worktree, receipt, archive, commit, authorization, transfer, parity, and install
   states are never collapsed into one “done” claim.
10. Human and JSON golden tests cover all seven outcomes, stale rewind, hook bypass,
    deletion-only push, readiness-only Deploy, installed Deploy, and remote parity.
11. Terminal-hostile input cannot spoof verdicts, become argv, leak secrets, or corrupt
    the single-document JSON response.
12. Release certification passes the complete local suite and installed-artifact check
    on macOS 27.0 build `26A5378n` for `aarch64-apple-darwin`, with current matching
    SPI/ABI, fixed profile, roots, and every canary; every drift or other platform is
    blocked and reported not certified with no fallback.
13. README and `--help` present this same everyday flow, phase order, state meanings,
    platform scope, and cooperative-owner limitation.
14. No active documentation or CLI requires a pretrust, bootstrap, self-hosting,
    supervisor, or recursive receipt ceremony before ordinary compilation or tests.
15. Human and JSON output distinguish adapter certification, compiler-process-tree
    feasibility, and full-profile certification; narrower proof never implies the next.
16. Containment claims cover accepted-root content reads, private-root writes, and
    network denial, while explicitly excluding path-metadata confidentiality and
    same-user process isolation unless separately proven.
17. Golden tests cover every adapter blocker code, its sole remediation action, no
    fallback, TTY/non-TTY/`NO_COLOR`, hostile display bytes, and field parity.

## Verdict

PASS

This contract is concise, implementable, and appropriate for a local-only cooperative-
owner meta-harness. It approves the developer experience and observable state model,
not an Architecture or implementation.
