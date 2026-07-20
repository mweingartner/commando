# Process Governance Delta

## ADDED Requirements

### Requirement: Complete ordered phase machine

Every change kind SHALL run Architecture, Security(plan), Build, Security(code), Test,
Documentation, Doc Validation, and final Deploy in order. Design Mock, Design Review,
and Design Sign-off MAY be N/A only for no-human-visible-impact work and only with a
stored rationale. FAIL and CONDITIONAL SHALL not advance; only current-phase unconditional
PASS with objective requirements satisfied SHALL advance.

#### Scenario: Fix completes tests

- **WHEN** a fix records Test PASS
- **THEN** it SHALL advance to Documentation, then Doc Validation, then final Deploy;
  it SHALL not skip documentation or deploy early

### Requirement: Effective risk cannot be lowered

MPD SHALL store requested, versioned derived, and effective risk with reasons and signal
digest. Effective risk SHALL be the maximum of requested and derived risk. The derived
classifier SHALL conservatively classify auth/credentials, untrusted parsing, network,
process execution, Git/hooks, persistence, sandboxing, cryptography, deployment, and
unknown additions under sensitive roots as High.

#### Scenario: Operator requests Low for hook changes

- **WHEN** declared scope includes `.githooks/**` or accepted hook policy
- **THEN** derived/effective risk SHALL be High and neither flags nor candidate config
  SHALL lower it

### Requirement: Append-only earlier-only repair

`mpd repair-state --to <earlier-phase> --reason <text> [--yes]` SHALL preview without
mutation and apply only to an active unarchived ledger whose observed digest remains
current. Apply SHALL preserve verdict history and conditions, invalidate downstream
current gates, reopen dependent obligations, append one event, create no verdict, and
commit atomically. Forward/no-op/conflicting/archive repair SHALL be rejected.

#### Scenario: Repair response is lost

- **WHEN** the same confirmed repair is repeated after it already applied
- **THEN** MPD SHALL report the existing result without a second event or additional
  state change

### Requirement: Separate production truth

Human and JSON status SHALL separately report worktree, candidate, freshness/gates,
archive, commit, push authorization, observed transfer, remote parity, and installed
bytes. Each receipt SHALL be CURRENT, FAILED, STALE, BLOCKED, or MISSING; hook bypass MAY
be BYPASSED. Output SHALL provide one safe next action and preserve compatible fields.

#### Scenario: Remote parity exists without push authorization

- **WHEN** remote OID equals local closure but current push authorization is absent
- **THEN** parity SHALL be verified, push authorization SHALL remain MISSING/BYPASSED,
  and production certification SHALL remain blocked

### Requirement: Accessible terminal and JSON rendering

Every operation SHALL produce exactly one of PASS, FAIL, BLOCKED, CONDITIONAL, STALE,
IN PROGRESS, or NOT RUN with the same semantics in human and JSON modes. Candidate,
receipt, bypass, and readiness/install states SHALL remain typed details. Human output
SHALL remain complete under TTY, non-TTY, and `NO_COLOR` without color, emoji, cursor,
motion, or sound carrying meaning. JSON SHALL emit exactly one UTF-8 document to stdout;
diagnostics and bounded logs SHALL use stderr.

Hostile ANSI/OSC, control, bidi, ref/message/path, and non-UTF-8 values SHALL be safely
escaped or represented by a label plus digest and SHALL never become argv. A mutating
operation SHALL atomically commit its identified result/effect before terminal PASS is
emitted, and output SHALL never contain PASS before that commit succeeds. Output failure
before commit SHALL create no result. Output loss after commit SHALL return non-success
and emit no new complete PASS, but SHALL preserve the committed truth for the next
read-only status and idempotent retry without duplicate event/effect. Partial JSON SHALL
not be valid automation evidence. Every read-only preview SHALL perform no state change
and end with `No state changed.`

#### Scenario: Hostile non-TTY JSON request fails

- **WHEN** a result contains hostile display bytes and stdout breaks before one complete
  JSON document is written
- **THEN** MPD SHALL keep diagnostics on stderr and return non-success; if the durable
  commit boundary was not crossed it SHALL create no result, and if it was crossed the
  next status/retry SHALL report exactly the one committed result without duplication
