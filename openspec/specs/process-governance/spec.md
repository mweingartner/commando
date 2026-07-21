# Process Governance

## Requirements

### Requirement: Declared governance context

MPD SHALL store a typed risk level and threat profile for every change and SHALL
surface the resolved values in begin, status, next, and JSON output.

#### Scenario: Existing begin command receives visible defaults

- **WHEN** an operator begins a change without governance flags
- **THEN** MPD SHALL infer a documented risk level, use the local-trusted-user
  threat profile, print both values, and persist them

#### Scenario: Explicit governance is preserved

- **WHEN** an operator supplies a supported risk and threat profile
- **THEN** every subsequent brief and status view SHALL report those exact values

#### Scenario: Legacy ledger loads safely

- **WHEN** MPD loads a ledger created before governance fields existed
- **THEN** it SHALL use documented conservative defaults without corrupting or
  invalidating the existing verdict history

### Requirement: Advisory artifact budget

MPD SHALL report an approximate canonical-artifact budget derived from risk but
SHALL NOT fail a gate solely because the estimate is exceeded.

#### Scenario: Medium-risk artifacts exceed guidance

- **WHEN** canonical artifacts exceed the medium-risk guidance
- **THEN** status and next SHALL emit a concise warning and the next actionable
  command without changing any gate verdict

#### Scenario: High-risk change has no page warning

- **WHEN** a change is declared high risk
- **THEN** MPD SHALL NOT impose a fixed artifact-page warning

### Requirement: Bounded review reconciliation

MPD SHALL require a recorded reconciliation decision before an attempt beyond
the risk-specific phase limit and SHALL preserve every prior verdict.

#### Scenario: Excess attempt is blocked

- **WHEN** a phase has exhausted its attempt allowance
- **THEN** MPD SHALL refuse another gate record and direct the operator to
  reconcile scope, continuation, risk, or threat profile

#### Scenario: Continue authorizes one attempt

- **WHEN** the operator records a nonblank continue reason
- **THEN** exactly the next attempt for the current phase SHALL be authorized
  without advancing or changing the prior verdict

#### Scenario: Risk change rewinds security review

- **WHEN** reconciliation changes the risk level
- **THEN** MPD SHALL retain history, invalidate Security plan and downstream
  latest verdicts, and return the active phase to Security plan

#### Scenario: Threat-profile change rewinds security review

- **WHEN** reconciliation changes the declared threat profile
- **THEN** MPD SHALL retain the old and new profiles in history, invalidate
  Security plan and downstream latest verdicts, and return the active phase to
  Security plan

### Requirement: Canonical current-state artifacts

MPD doctrine and templates SHALL define proposal, design, and tasks as the
current approved contract and SHALL direct superseded drafts to `history/`
without automatically rewriting user-authored content.

#### Scenario: Oversized design receives preservation guidance

- **WHEN** an artifact warning is emitted
- **THEN** MPD SHALL recommend consolidating the canonical contract and moving
  superseded prose to history rather than deleting or rewriting it automatically

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

### Requirement: Ledger version-skew diagnosis

Saved ledgers SHALL carry a numeric format marker, and a failed ledger
deserialization SHALL be diagnosed with a bounded version probe: when the probed
format exceeds what the running binary supports, the error SHALL state that the ledger
requires a newer MPD with both format numbers; otherwise the original parse error SHALL
be preserved with the ledger's path context. The probe SHALL run only after full
deserialization has failed and SHALL never alter the result of a successful load.

#### Scenario: Newer ledger meets an older binary

- **WHEN** a ledger's probed format number exceeds the binary's supported format
- **THEN** the load error SHALL say the ledger requires a newer MPD and name the found
  and supported format numbers

#### Scenario: Corrupt ledger is not misattributed

- **WHEN** a ledger fails to parse and its probed format is absent or not greater than
  the supported format
- **THEN** the original parse error SHALL be reported with path context and SHALL NOT
  claim a version mismatch

#### Scenario: Valid ledger is untouched by the guard

- **WHEN** a ledger deserializes successfully
- **THEN** the load SHALL behave identically to a build without the version guard
