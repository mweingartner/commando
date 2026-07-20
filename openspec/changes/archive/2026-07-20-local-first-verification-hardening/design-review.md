# Design Review/Revision: Exact-Host Local Validation

Date: 2026-07-19

## Actor

Designer

## Reviewed scope

This gate reviews whether the reconciled Architecture and active delta specs preserve
the approved operator contract. It does not approve implementation or empirical claims.

| Artifact | Lines | SHA-256 |
| --- | ---: | --- |
| `design-mock.md` | 373 | `428e8e606270815497c3cf37322bf1d3c04e330725b56fd54db3fba33bfb3374` |
| `design.md` | 430 | `0de6fbeb73c64871c6f565e1ca72da6e48239d641b040a4f63c3be582840b01e` |
| `tasks.md` | 164 | `80a0c908b9e1f8d9908f57e6cd4f57e8da4f2dd970bf6fea32f12cd33a9ec199` |
| `specs/directives/spec.md` | 51 | `5eb3beb6005d2f53f4b50db8e8789346b343f90cea458d27a63889e7394a21d5` |
| `specs/evidence-reuse/spec.md` | 35 | `bf233f3d2835cf76884066beb059043d7a7bd044ae3e6dc49bdda778474ec5d5` |
| `specs/gate-evidence/spec.md` | 42 | `2d5c695f5ccb42da2beb96641bc93bfcd4cb5f982100f3b74888dfd84c4384fd` |
| `specs/local-validation/spec.md` | 228 | `7ac3c591fb214822d3af9844911eb1875542683494810dcce65d042877c13984` |
| `specs/process-governance/spec.md` | 85 | `55f7a9d4bd43d76f79eaba7334ab0382b0de09b2eaef3852dfb6de2ac7b8ece3` |
| `specs/remote-parity/spec.md` | 35 | `064f36f9b793bf9bf885d267f6ab6ce23a686c6c532aa197b574041a8c5a2455` |

The directives, freshness, gate-evidence, process-governance, and remote-parity deltas
were checked as constraints on the local-validation design, not only sampled by name.

## Intent check

The reviewed Architecture, all active delta specs, and `tasks.md` preserve the current
`design-mock.md` intent: exact-host fail-closed certification, the sole blocker/action
mapping, bounded containment claims and residual limitations, compiler-tree versus
full-profile proof separation, seven outcomes and receipt states, human/JSON parity,
hostile/non-TTY/`NO_COLOR` behavior, and separate delivery facts. Divergence: none.

## Findings and closure

### DR-1 — Candidate/process-state separation

**CLOSED — PASS.** The Architecture still excludes mutable MPD and clone-private state
from candidate content, binds those facts separately, and requires declared governance
input to move freshness. The local-validation and gate-evidence specs remain normative,
and tasks 2.1–2.3 retain projection, exact-subject, and closure tests. The exact-host
revision does not reopen this prior finding.

### DR-2 — Terminal and JSON contract

**CLOSED — PASS.** Architecture lines 287–334, the process-governance rendering
requirement, and task 4.2 preserve the seven outcomes (`PASS`, `FAIL`, `BLOCKED`,
`CONDITIONAL`, `STALE`, `IN PROGRESS`, `NOT RUN`) and the separate receipt states
`CURRENT`, `FAILED`, `STALE`, `BLOCKED`, and `MISSING`. Human and JSON derive from one
typed result; non-TTY and `NO_COLOR` remain complete; JSON is one UTF-8 stdout document;
diagnostics stay on stderr; hostile ANSI/OSC/bidi/control/non-UTF-8 values are safe; and
partial or pre-commit output cannot spoof PASS. Task 4.2 requires the matching golden and
abnormal-output matrix. The revision does not reopen this prior finding.

### DR-3 — Exact-host compatibility-adapter reconciliation

**CLOSED — PASS. No open finding.** The reconciled plan preserves every revised Design
Mock requirement:

| Contract | Architecture/spec/task closure | Result |
| --- | --- | --- |
| Exact certification boundary | `design.md` limits authority to macOS 27.0 build `26A5378n`, Apple silicon, `aarch64-apple-darwin`; `local-validation/spec.md` makes that identity normative; tasks 3.2, 4.2, and 7.3 require current-host evidence. | PASS |
| Drift and no fallback | Host, symbol/SPI/ABI, fixed-profile, root, inheritance, denial, cleanup, and canary mismatch are BLOCKED/NOT CERTIFIED. Architecture and spec forbid App Sandbox, `sandbox-exec`, broad-read, unsandboxed, hosted, or other fallback. | PASS |
| Sole blocker action | Architecture lines 302–314 and local-validation lines 101–117 carry the same six blocker codes and actions as the mock, including unclassified-to-`sandbox.spi-abi-drift`. Task 4.2 golden-tests each pair, one action only, no alternative, and no silent effect. | PASS |
| Bounded certified claim | Architecture and spec certify accepted-root content reads, the private-root plus `/dev/null` write boundary, and network denial. Both expressly exclude global path-metadata/root-entry confidentiality and same-user process isolation. Tasks 3.2, 4.2, 7.1, and 7.2 preserve the limitation and its tests/docs. | PASS |
| Proof layering | Architecture records `cargo -> rustc -> linker -> test binary` as feasibility evidence only. The local-validation narrow-proof scenario keeps adapter certification, compiler-tree PASS, and full-profile NOT CERTIFIED/BLOCKED separate. Tasks 3.2, 4.2, and 7.3 prohibit substituting the probe for the complete profile. | PASS |
| Human/JSON representation | Architecture exposes adapter, host, SPI/ABI, profile, roots, canaries, compiler tree, full profile, certified claim, and residual limitations as separate typed fields under the seven outcomes. The local-validation and process-governance specs make parity normative; task 4.2 provides the complete matrix. | PASS |
| Delivery truth | Architecture required outcome 5 and incremental status keep candidate, gates, archive, commit, push authorization, transfer, parity, and install distinct. Process-governance and remote-parity specs prohibit implication between them; tasks 4.2 and 7.3 exercise the separation. | PASS |

The Architecture therefore realizes Design Mock criteria 1–17. In particular, narrower
adapter or compiler-tree proof cannot fill the full-profile field, remote parity cannot
repair missing/bypassed authorization, and readiness-only Deploy cannot claim install.

## Omitted scope

This review did not inspect source code, test implementation, sandbox profile bytes,
SPI behavior, tool/root identities, canary execution, runtime output, logs, Git hooks,
closure bytes, installation, push, or remote parity. It does not establish that the
adapter or full profile is currently certified; current empirical certification remains
for Security(code), Test, Doc Validation, and Deploy. Security adequacy and residual-risk
acceptance remain Security responsibilities.

## Verdict

PASS

The reconciled Architecture, all active specs, and the Builder tasks preserve the
approved exact-host local-validation experience with no Design-level condition. This is
a Design Review PASS only; it is not a Build, Security, Test, documentation, release,
installation, push, or parity verdict.
