# Security (plan) review

## Actor

Security (claude-code harness, deep tier — high-risk deep_tier_bump).

## Threat model

**Change.** Make the built-in secret-scan wrapper `checks::scan_secrets`
(crates/mpd/src/checks/mod.rs:176) fail *closed*: today `unwrap_or_default()`
converts every `secrets::scan_paths` error (non-regular file, per-file size cap,
aggregate overflow, unreadable path — secrets.rs:298-320) into an empty = clean
report, so a single tracked symlink silently disables the built-in content scan
for the Security (code) gate and non-staged `mpd check`.

**Trust boundary / attacker.** Local actor with write access to the tracked tree
(inside the trust boundary, actions attributable in history). What they control:
tracked file *types* and *names*; what they must not be able to reach: a "secrets
clean" gate result over content that was never scanned.

**Ground truth verified (not taken from the plan).** `scan_secrets` has exactly
two callers — cli.rs:3421 (gate) and cli.rs:5204 (non-staged check); `scan_paths`
is otherwise called only in fail-closed test helpers. Sibling controls are
already fail-closed: `scan_staged_postimages` (mod.rs:186-215), the pre-push
outgoing scan (`scan_outgoing_objects`, local_validation.rs:6738-6797), the
structured-profile gate (cli.rs:3334-3340). `scan_paths` error strings carry
cause + `path.display()` only — no file contents; std `io::Error`s from
`symlink_metadata`/`read` are OS-message-only. `cmd_gate` idiom confirmed:
allowlist filter runs *after* the scan (cli.rs:3423-3424), `secrets_clean =
Some(true)` at cli.rs:3455, `gate_blocked` = stderr + exit 1 (cli.rs:3827-3830),
secret branch gated on `SecurityCode` only (phase.rs:102-104). The plan's D1-D5
(signature mirrors the sibling; gate refuses via `gate_blocked`; `?` symmetry;
error-before-allowlist; composition-level symlink test) are all sound and
correctly grounded.

**Residual surface — the enumeration boundary.** The fix closes the *scanning*
boundary but not the *enumeration* boundary `git_files` (mod.rs:146-159) that
builds the scan set, which retains three silent-drop doors: (a) `git ls-files`
failure → empty set → vacuous clean; (b) `core.quotepath`-quoted paths
(non-ASCII / `"` / `\` filenames) dropped by the `exists()` filter —
attacker-controllable (name a secret file `sécrets.txt`); (c) dangling tracked
symlinks. All three are compensated at egress (pre-push scans every outgoing blob
content-wise, path-independent; pre-commit rejects quoted staged paths via
`validate_canonical_path`) — so not a push-time leak — but they keep the
SecurityCode gate's `secrets_clean:true` from being fully honest.

**Approved.** Error-text hygiene (cause + path, never contents; paths already
print in normal finding output); DoS posture (skip→block on oversize is the
correct direction; weaponization needs in-boundary write access; no
error-allowlist override); scope discipline; the two-caller inventory.

## Conditions for Builder

Inherits design.md's Conditions for Builder 1-11 (fail-closed on every error; no
allowlist masking; gate refusal before `secrets_clean`; no content leak;
non-vacuous symlink test; no secret-shaped fixtures; scope lock; success-path
byte-identity; `#[cfg(unix)]` gating; temp-dir cleanup; **freeze the enumeration
boundary — condition 11**). Plus the two review conditions below.

## Verdict

**CONDITIONAL PASS.** The plan is sound, accurately grounded, and closes the
primary fail-open hole by construction (D2/D4 make the allowlist-launder and the
`secrets_clean=Some(true)` write structurally unreachable on error). Two
conditions:

1. **[Medium — Architect, before Build] Complete the residual analysis and fix
   the spec overclaim.** design.md Risks must name all three enumeration
   residuals (a/b/c); the spec delta's "full scanned set" / "SHALL error rather
   than skip the input" wording must be scoped to the set handed to the scanner,
   with the enumeration boundary named as an accepted residual pending a named
   follow-up.
   *Closing evidence:* **CLOSED** — design.md Risks now enumerates (a) git-failure
   vacuous-clean, (b) `core.quotepath` drop, (c) dangling symlink, with Builder
   condition 11 freezing the boundary; the spec delta is reworded to the
   scanner-input boundary with an explicit boundary note; follow-up filed
   ("Harden git_files enumeration boundary (fail-closed)", task_3f96f2f5).

2. **[Medium — Tester, before the Test gate] Black-box caller-blocking test.**
   Add to crates/mpd/tests/e2e.rs: a temp git repo with a tracked symlink (target
   existing) makes non-staged `mpd check` exit non-zero with the fail-closed
   diagnostic on stderr and NOT print the clean-scan success line. Compile-
   enforcement plus the wrapper test does not prove the callers block.
   *Closing evidence (pending):* the e2e test present and green in the
   Test-phase run. `crates/mpd/tests/e2e.rs` has been added to the manifest scope
   and tasks.md §4 for it.

**Advisories (non-blocking).** (i) Add secrets.rs:279-281 ("skipped for content")
to the stale-reference flag list — done in design.md/tasks.md. (ii) `.github/
workflows/` is now empty (ci.yml deleted); these regression tests are
machine-enforced only locally. Recommend restoring a CI workflow running
`cargo test` + gitleaks so this change's own controls get a remote gate.

Condition 1 is closed; Build may proceed. Condition 2 blocks the Test gate, not
Build. Unresolved conditions block deployment.
