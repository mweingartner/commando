## MODIFIED Requirements

### Requirement: Fail-closed built-in secret scan

The built-in worktree secret-scan wrapper backing phase gates and `mpd check`
SHALL fail closed over the path set it is handed: when the scanner cannot
complete on that set — a symlink or other non-regular file, a file exceeding the
per-file size cap, aggregate-size overflow, or an unreadable path — the gate or
check SHALL refuse with a diagnostic naming the cause, SHALL NOT report a clean
scan, and the secret allowlist SHALL NOT be applied to or mask an incomplete
scan. The diagnostic SHALL NOT include file contents.

Boundary note: this requirement governs the scanner over its input set. The
construction of that set from the git-tracked file list is governed by the
"Fail-closed tracked-file enumeration" requirement.

#### Scenario: Tracked symlink in the scanned set

- **WHEN** the git-tracked file set passed to the built-in secret scan contains a
  symlink whose target exists
- **THEN** the scan SHALL error naming the non-regular path, the Security (code)
  gate and non-staged `mpd check` SHALL refuse with a non-zero result, and no
  allowlist filtering SHALL convert the error into a clean report

#### Scenario: Scanner cannot read or bound its handed input

- **WHEN** a file in the handed set exceeds the size cap, the aggregate cap
  overflows, or a path in the set is unreadable
- **THEN** the scan SHALL error rather than skip that input, and the invoking gate
  or check SHALL refuse rather than report secrets clean

## ADDED Requirements

### Requirement: Fail-closed tracked-file enumeration

The enumeration boundary that builds the built-in secret scan's input set from
the git-tracked file list SHALL fail closed and SHALL be complete. A failure to
enumerate — git cannot be spawned, exits non-zero, or its output exceeds the
size cap or is not valid UTF-8 — SHALL block the invoking gate or check rather
than yield an empty or partial set that scans as clean. Tracked paths SHALL be
obtained in a quoting-immune, NUL-delimited form so no path is dropped or altered
because of unusual name bytes (non-ASCII, quotes, backslashes, whitespace,
embedded newlines). A tracked path present in the worktree in any form —
including a dangling symlink or other non-regular entry — SHALL be retained and
passed to the scanner's own fail-closed handling. The single permitted omission
is a tracked path with no worktree entry at all (an unstaged deletion or
sparse-checkout absence), which has no worktree bytes to scan. The enumeration
failure diagnostic SHALL NOT include raw git output or file contents.

#### Scenario: Git enumeration failure

- **WHEN** the git-tracked file list cannot be enumerated at the Security (code)
  gate or non-staged `mpd check` (git fails to spawn or exits non-zero)
- **THEN** the gate or check SHALL refuse with a diagnostic naming the
  enumeration failure, SHALL NOT scan an empty set, and SHALL NOT record or report
  secrets clean

#### Scenario: Tracked file with a quotable name

- **WHEN** a tracked regular file has a name git's line-mode output would quote
  (e.g. non-ASCII bytes) and its content contains a secret pattern
- **THEN** the file SHALL be enumerated verbatim and scanned, and the finding
  SHALL block exactly as it would for an ASCII-named file

#### Scenario: Dangling tracked symlink

- **WHEN** the worktree contains a tracked symlink whose target does not exist
- **THEN** enumeration SHALL retain it, the scan SHALL fail closed naming the
  non-regular path, and the gate or check SHALL refuse

#### Scenario: Worktree-absent tracked path

- **WHEN** a tracked path has no worktree entry at all (an unstaged deletion or
  sparse-checkout absence)
- **THEN** enumeration SHALL omit it and the scan of the remaining set SHALL
  proceed; a path present in any form SHALL NOT be omitted
