# MPD Protocol

MPD is a local-only, gate-driven overlay over OpenSpec and Git. Hosted CI is neither required nor accepted as validation authority. The trust boundary is a cooperative repository owner; actor/model/session labels are recorded provenance, not authenticated identity.

## Required phase order

`Design Mock -> Architecture -> Design Review -> Security(plan) -> Build -> Security(code) -> Design Sign-off -> Test -> Documentation -> Doc Validation -> Deploy`

Only Design phases may be N/A with a written no-human-visible-impact rationale. Every other phase runs with depth proportional to semantic risk. FAIL blocks; unresolved conditions block archive; material changes return to the earliest affected phase.

## Written intent and roles

Read project-shaping docs and affected files before acting. Architecture is a written contract with exact files/APIs, dependency order, edge cases, risk-to-test mapping, and Conditions for Builder. Builder implements only that plan. Security reviews plan and code separately. Tester reads the real implementation and maps risks to empirical evidence. Documenter updates durable guidance and verifies every path, flag, and command.

Strict judgment artifacts contain exactly one `## Actor` and `## Verdict`; the first nonblank verdict line is exactly `PASS`, `CONDITIONAL PASS`, or `FAIL`. Artifact Actor matches `--by` and differs from the latest applicable upstream actor. Commando has no artifact waiver.

## Candidate, freshness, and risk

Planning gates use base HEAD and report Candidate NOT CAPTURED. Build creates one immutable manifest-scoped Candidate from HEAD plus staged/unstaged tracked postimages, declared untracked files, deletions, and modes. Build, Security(code), and Test reopen and rehash that same Candidate. Candidate and Commit receipts are different subjects.

Before every downstream brief or effect, MPD recomputes causal dependencies and effective risk. Stale evidence appends the earliest rewind without deleting history. Effective risk is the maximum of requested and derived risk and cannot be configuration-lowered. The Candidate binds the change's source, config, specs, and manifest but excludes its own process prose (design/proposal/tasks and the judgment artifacts), which a dedicated fail-closed secret-scan lane covers at every strict Build/Security(code)/Test gate. When a rewind leaves the Candidate byte-identical — including an uncommitted process-prose edit — a strict Build or Test gate may reuse the prior validation receipt instead of re-executing, but only when the gate profile, policy digest, and revalidated build output match and the receipt is hermetic-complete; a committed edit or any in-scope code/config/spec edit re-executes, and Security(code) always re-executes. A tracked file modified outside the manifest refuses the strict objective gates.

## Local validation

Authoritative checks use a reviewed structured policy, typed program/argv, pinned tools and offline inputs, private HOME/Git/Cargo/XDG/temp/log state, bounded output/resources/process trees, and a mandatory network-denying platform adapter. Roots never come from argv, environment, or candidate configuration. Missing identity, drift, timeout, truncation, leak, failed canary, or cleanup ambiguity is BLOCKED. There is no hosted, shell, broad-read, unsandboxed, or weaker platform fallback.

This release certifies only macOS 27.0 build `26A5378n`, Apple silicon, `aarch64-apple-darwin`, using the compiled deprecated/undocumented exact-host compatibility adapter. The certified claim covers accepted-root content reads, one private-root plus `/dev/null` writes, and network denial. It does not claim global path-metadata/literal-root-entry confidentiality or same-user process isolation. Every other host is NOT CERTIFIED.

A compiler process-tree probe is feasibility evidence only. Full certification requires the complete high-risk profile and all per-run host/ABI/profile/root/canary attestations.

## Git-local authority

The sole activation route is `mpd policy activate` bound to an immutable reviewed commit, canonical policy digest, absolute coordinator digest, and tracked `.githooks`. It creates owner-only clone-private launchers. There is no legacy trust-bootstrap route.

Pre-commit performs bounded staged secret and artifact/task checks. Pre-push parses authentic Git input, scans every outgoing commit/tag/message/blob, validates the exact Commit profile, and issues one invocation-local authorization bound to the remote, baseline, rows, objects, policy, result, and nonce. Deletion-only still runs policy/ref checks and non-main deletion requires exact one-use approval. MPD never transports; normal Git pushes.

## Status, closure, and Deploy

Human and JSON output derive from one typed state and use the seven outcomes PASS, FAIL, BLOCKED, CONDITIONAL, STALE, IN PROGRESS, and NOT RUN. They keep worktree, Candidate, gate freshness, local validation, archive, commit, push authorization, transfer, remote parity, install, and containment layers separate. JSON emits one stdout document; hostile terminal bytes are escaped; PASS appears only after durable state commits.

Archive compares the final commit tree with the exact Candidate plus allowed canonical overlays. `mpd publish --verify` separately observes remote parity and never repairs missing authorization.

**Deploy** consumes the current typed Build-output receipt. Execute Deploy copies already-tested bytes through an exclusive temporary, syncs/atomically replaces, reopens, and checks mode/length/SHA. It never rebuilds or executes the installed candidate for identity. Readiness-only is not installation.

## Verification

Verification is empirical. Report commands, exit status, counts, timing, and omissions. Run the full workspace/all-target suite, warning-denied Clippy, release build, security scanners, documentation checks, and the explicit ignored 10k-path/100MB workload. Verify the verifier: zero tests is not a passing test claim.
