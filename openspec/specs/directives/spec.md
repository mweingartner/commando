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
