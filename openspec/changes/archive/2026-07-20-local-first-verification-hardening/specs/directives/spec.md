# Directives Delta

## ADDED Requirements

### Requirement: Directive and hook health

`mpd doctor` SHALL report bundled/project directive drift and active policy/coordinator/
wrapper drift with stable human and JSON findings. It SHALL never overwrite customized
doctrine or activate hooks as a side effect.

#### Scenario: Active coordinator differs from the accepted digest

- **WHEN** doctor or a hook observes a missing, moved, or digest-mismatched coordinator
- **THEN** the operation SHALL block before candidate execution and show the explicit
  digest-confirmed reactivation action


### Requirement: Local-first harness doctrine

Bundled and project directives SHALL identify local MPD profiles and activated local Git
hooks as the validation authority. Hosted checks SHALL NOT satisfy a gate. Directives
SHALL preserve manual `next`, `gate`, and `status` operation and SHALL require the phase
order, task/condition closure, archive, normal Git commit/push, and separate remote-parity
observation documented by the current binary.

#### Scenario: Harness begins non-trivial work

- **WHEN** the harness reads project instructions and `mpd next --harness <h> --context`
- **THEN** it SHALL execute only the current brief, retain FAIL/CONDITIONAL history, use
  the requested model/effort where available, and record the verdict before remediation

#### Scenario: Hosted validation reports success

- **WHEN** a hosted service reports green but the required local profile or hook evidence
  is missing, stale, blocked, or failed
- **THEN** MPD doctrine SHALL keep the gate incomplete and direct the operator to the
  local recovery action

### Requirement: Truthful cooperative authority

Directives SHALL state that actor/model/session fields are recorded provenance and that
local hooks are cooperative enforcement. They SHALL NOT claim authenticated reviewer
identity, owner-resistant policy, pretrust/self-hosting proof, filesystem read isolation,
or certification for an untested platform.

#### Scenario: Repository owner bypasses a hook

- **WHEN** a commit or push lacks current hook authorization
- **THEN** status SHALL report MISSING or BYPASSED and SHALL NOT infer authorization from
  a later remote OID match

