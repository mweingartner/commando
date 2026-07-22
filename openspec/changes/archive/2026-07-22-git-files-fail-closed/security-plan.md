# Security (plan) review

## Actor

Security (claude-code harness, deep tier — high-risk deep_tier_bump).

## Threat model

**Change.** Harden the secret-scan enumeration boundary `git_tracked_files`
(checks/mod.rs:142-160): git-failure → `Err` (was vacuous clean); `git ls-files
-z` verbatim (was line-mode, quotepath-droppable — attacker excludes a file via
`sécrets.txt`); `symlink_metadata().is_ok()` filter retains dangling symlinks +
non-regular entries → fail closed in `scan_paths` (was `exists()`, dropped
them). Threat: local-untrusted-input controlling tracked file names/types;
the compromised asset is the honesty of the SecurityCode gate's
`secrets_clean:true` / `mpd check`'s `Checks passed`. NOT a push-time leak —
`scan_outgoing_objects` (local_validation.rs:6738-6797) content-scans every
outgoing blob path-independently.

**Verified under attack (not taken on faith).**
- **(b) door closed:** `git ls-files -z` emits verbatim (quotepath governs only
  line-mode); `git::ls_files` (git.rs:345) uses `-z` + `nul_tokens` (correct
  trailing/empty/absent-NUL/empty-output handling); NonUtf8 → whole-enum `Err`
  (fail closed); a malformed mid-stream empty token → `root.join("")` → root dir
  → `scan_paths` "non-regular" → fails closed, not dropped. **No name class is
  silently dropped after the fix.**
- **`Ok(empty)` vs `Err` structurally distinguished:** zero-tracked-file repo =
  exit 0 + empty stdout → `Ok(vec![])` (legitimate clean); only spawn-fail /
  non-zero / over-cap / non-UTF-8 → `Err`. Caller census (grep): exactly two —
  cli.rs:3420 (cmd_gate), cli.rs:5212 (cmd_check) — + the unit test at
  mod.rs:418 (task 3.1 updates it).
- **D4 no new legitimate-block class:** a healthy tracked symlink already blocks;
  D4 only removes the perverse "break the link to un-block the gate" bypass.
  Gitlinks already retained+blocked under `exists()` (unchanged). FIFO/device
  can't be in a git index; a worktree substitution lstat's fine → fails closed.
- **D5 not an exploitable exclusion primitive:** stage-secret-then-unstaged-rm →
  caught by `scan_staged_postimages` (index-blob, worktree-independent) at
  commit; committed-then-removed → caught by the path-independent egress scan at
  push. Residual (already-pushed secret) predates this change and is a capability
  the attacker already has (`git rm` + stage, or commit) — the worktree scan has
  never scanned history. Spec-pinned ("present in any form SHALL NOT be omitted")
  + test-pinned. TOCTOU cuts safe (present-at-enum/absent-at-scan errs in
  `scan_paths`).
- **No-launder:** both callers block before allowlist/external/`secrets_clean`;
  diagnostics use `GitError` fixed labels only.

## Conditions for Builder

Inherits design.md Conditions for Builder 1-11 (all verified sufficient). Plus
the two advisories below (A2 folded into Build; A1 filed as a follow-up).

## Verdict

**PASS.** No critical/high findings. The plan closes all three doors on
verified-hardened reused plumbing, the sole intentional omission (D5) is
compensated at both exfiltration channels and grants no new capability, and the
Conditions for Builder are complete. Two advisories, neither blocking:

- **A1 [Medium] — terminal-escape injection in path diagnostics — FILED AS
  FOLLOW-UP (task_d38104fe).** The fix newly retains filenames with valid-UTF-8
  control bytes (ESC 0x1b), which render verbatim via `path.display()` in
  `scan_paths` errors (secrets.rs) and `f.path` finding output (cli.rs) — a
  crafted tracked name can visually spoof terminal gate output. Machine verdict
  (exit code, `gate_blocked`, phase) stays honest (hence Medium). The fix spans
  secrets.rs + cli.rs output rendering, OUTSIDE this change's confined scope
  (Condition 10), so it is a separate diagnostic-hygiene change, not folded here.
- **A2 [Low] — pin `Ok(empty)`-is-clean — FOLDED INTO BUILD.** Add a unit test:
  a repo with zero tracked files → `git_tracked_files` returns `Ok` empty and
  `scan_secrets` returns clean (never `Err`). Ensures a future "empty-as-error"
  hardening can't break fresh repos. Builder adds it; verified at Security (code).

Builder may proceed against design.md as-is (A2 is an additive test, not a plan
change). Per the novel-surface rule, the Build's new tests are verified at
Security (code).
