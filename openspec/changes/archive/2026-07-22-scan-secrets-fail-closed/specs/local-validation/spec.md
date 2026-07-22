## ADDED Requirements

### Requirement: Fail-closed built-in secret scan

The built-in worktree secret-scan wrapper backing phase gates and `mpd check`
SHALL fail closed over the path set it is handed: when the scanner cannot
complete on that set — a symlink or other non-regular file, a file exceeding the
per-file size cap, aggregate-size overflow, or an unreadable path — the gate or
check SHALL refuse with a diagnostic naming the cause, SHALL NOT report a clean
scan, and the secret allowlist SHALL NOT be applied to or mask an incomplete
scan. The diagnostic SHALL NOT include file contents.

Boundary note: this requirement governs the scanner over its input set. The
separate construction of that set from the git-tracked file list (the
enumeration boundary) can still silently shrink the set (git-command failure,
`core.quotepath`-quoted paths, dangling symlinks); hardening the enumeration
boundary so it too cannot yield a vacuous clean is tracked as a distinct
follow-up and is out of scope for this requirement.

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
