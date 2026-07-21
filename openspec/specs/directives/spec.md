# Directives

## Requirements

### Requirement: Bundled MPD doctrine

mpd SHALL carry the canonical Model-Paired Development doctrine — a protocol
document and one directive per persona — compiled into the binary, so the
doctrine is part of mpd and needs no external file at runtime.

#### Scenario: Doctrine is embedded

- **WHEN** mpd is built
- **THEN** the protocol doctrine and each persona directive SHALL be embedded via
  `include_str!` and available without reading any project or user file

### Requirement: Install directives at init

`mpd init` SHALL install the bundled doctrine into the project at
`.mpd/directives/` so it sets up the project and can be customized per project.

#### Scenario: Fresh init installs directives

- **WHEN** `mpd init` runs in a project without `.mpd/directives/`
- **THEN** it SHALL write `protocol.md` and `personas/<persona>.md` for every
  persona, and report them as created

#### Scenario: Existing directives are preserved

- **WHEN** `mpd init` runs and `.mpd/directives/<file>` already exists
- **THEN** it SHALL NOT overwrite the existing (possibly customized) file

### Requirement: Surface the persona directive in next

`mpd next` SHALL make the active phase's persona directive available: the brief
references the directive, and `mpd next --full` SHALL inline the complete
directive text (from the project copy when present, else the bundled default) so
a harness with no external instruction files is self-sufficient.

#### Scenario: Full brief inlines the directive

- **WHEN** `mpd next --full` is run at a phase with a persona directive
- **THEN** the output SHALL contain the full directive text for that persona

#### Scenario: Project directive overrides the bundled default

- **WHEN** `.mpd/directives/personas/<persona>.md` has been edited
- **THEN** `mpd next --full` SHALL surface the edited project copy, not the
  bundled default

### Requirement: Safe directive reads

Reading directive files SHALL refuse symlinks and cap size, reusing the hardened
reader used elsewhere, so a planted symlink cannot exfiltrate an arbitrary file.

#### Scenario: Symlinked directive leaf is refused

- **WHEN** `.mpd/directives/personas/<persona>.md` is a symlink to a file outside
  the project
- **THEN** mpd SHALL fall back to the bundled default rather than read the link
  target

#### Scenario: Symlinked intermediate directory is refused

- **WHEN** `.mpd/directives/personas` (an intermediate directory) is itself a
  symlink pointing outside the project
- **THEN** mpd SHALL fall back to the bundled default rather than read through the
  symlinked directory (containment is checked at every path component, not only
  the leaf)

### Requirement: Warn when a project directive diverges

Because a persona directive is inlined verbatim as that persona's operating
instructions and lives in the branch under review, `mpd next --full` SHALL warn
when the project copy differs from the bundled default, so a locally modified
directive is flagged for review rather than trusted silently.

#### Scenario: Divergent directive is flagged

- **WHEN** `.mpd/directives/personas/<persona>.md` differs from the bundled
  default and `mpd next --full` is run at that persona's phase
- **THEN** the output SHALL prepend a visible warning that the directive was
  locally modified and should be reviewed before it is trusted

### Requirement: Governance-aware persona directives

MPD SHALL include the declared risk and threat profile in every persona brief,
and Security directives SHALL reserve blocking FAIL for a described exploit path
within or into that profile.

#### Scenario: Security receives local trusted-user profile

- **WHEN** Security requests the next brief for a local-trusted-user change
- **THEN** the brief SHALL name that profile and direct out-of-profile hardening
  to advisory evidence unless it crosses into the declared boundary

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
