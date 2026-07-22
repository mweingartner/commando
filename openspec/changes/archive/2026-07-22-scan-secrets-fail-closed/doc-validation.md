# Doc validation

## Actor

Architect (claude-code harness, deep tier). Designer lens N/A — pure backend
gate-behavior change, no UI/UX surface.

## Architect lens

Validated every factual claim in `documentation.md` against the shipped code
(not the plan). Accurate: the `scan_secrets` signature and error prefix
(mod.rs:180-187); the `cmd_gate` refusal ordering — `gate_blocked` exit 1 before
the allowlist filter and before `secrets_clean = Some(true)` (cli.rs:3421-3463);
`mpd check` non-staged `?`-propagation → exit 2 and the clean success line
(cli.rs:5212, 5267-5269); the enumeration-boundary residuals and egress
compensation matching design.md/security-plan.md and the real code; all five
sections present with no placeholders and no "enumeration boundary is fixed"
overclaim.

**Two accuracy defects found (initial verdict FAIL):**
1. **Path-naming overclaim.** The doc stated the diagnostic "names the cause and
   the path" as a universal, tests-verified invariant (Scope + Purpose + Functional
   `<cause + path>`). Not universal: the aggregate errors carry no path
   (secrets.rs:314-318) and OS-level `symlink_metadata`/`read` errors are
   OS-message-only (secrets.rs:298,320) — the shipped test itself notes this
   (mod.rs comment: cause is an OS message without the path). Only *no file
   contents* is the tests-verified invariant (mod.rs:430-433). Path-naming must
   be scoped to the non-regular/oversize classes.
2. **Usage transcript shows a bare `link.txt`.** `git_tracked_files` returns
   absolute paths (`root.join`, mod.rs:157) and `scan_paths` prints
   `path.display()`, so real output names an absolute path. Fix: show an absolute
   path or an explicit `<repo>/link.txt` placeholder.

## Designer lens

N/A — no UI/UX surface in this change.

## Verdict

**PASS (after correction).** Initial validation returned FAIL on the two accuracy
defects above; both were corrected in `documentation.md` verbatim per the
validator's prescription — path-naming scoped to the non-regular/oversize classes
with "never file contents" kept as the sole tests-verified invariant, and the
Usage transcript changed to an absolute/`<repo>/…` path. Re-validation confirmed
the corrected doc is accurate and free of overclaim. (See gate history: the FAIL
is recorded before this PASS.)
