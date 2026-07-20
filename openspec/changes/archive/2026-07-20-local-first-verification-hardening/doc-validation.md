# Doc validation

## Actor

Architect+Designer

## Architect lens

Validated documentation.md against what was planned and built; every load-bearing
claim checked against ground truth. First round returned FAIL on one material
misattribution — the doc presented status's merged `Scope: 23` as the manifest's
declared count; the manifest declares 20 patterns (`paths`: 20, `shared_paths`: 0)
and `manifest_view` (crates/mpd/src/cli.rs:1679–1697) merges three code-owned
SystemScope paths (change directory, gate ledger, dated archive target). The
Documenter's fix states the 20 + 3 = 23 decomposition explicitly; re-verified
against manifest.json, `active_system_scope` (crates/mpd/src/closure.rs:2406),
and live status output. Also verified: the 11-phase order and gate history;
the 24-key `SANDBOX_ENV_CONTRACT_KEYS` (crates/mpd/src/sandbox.rs:44–69)
matching the Test receipt's embedded contract; the five hardening-era env pins
with their code sites; `MAX_APPROVED_READ_ROOTS`/`MAX_ROOTS` = 48 with all
enforcement points; the eight corroborated containment-guard sites and the
`sh -c` runner's `env_remove("MPD_SANDBOXED")`; the console-only diagnosability
string shape and 512-byte terminal-safe tail; all eight Usage command shapes
against `--help`; and accurate disclosure of open items F1 (both remediation
strings now quoted per site verbatim), R3, and the single 7.3 deferral
("17 done, 1 deferred, 0 open"). Nothing overstated; no drift from shipped
behavior. Final verdict this lens: PASS.

## Designer lens

Validated documentation.md against the design intent and the real user-facing
surface. First round returned FAIL on one material overclaim — the doc said
scoped doctor diagnostics "never validate, install, deploy, or probe identity
themselves," but `doctor --scope runtime-health` re-hashes the declared
installed artifact (installed-path-identity, crates/mpd/src/cli.rs:6987–6990).
The Documenter's fix scopes the claim correctly: read-only diagnostics that
never validate, install, or deploy; runtime-health re-hashes the installed
artifact read-only to compare recorded identity (size, mode, SHA-256) without
executing it. Re-verified against the code and live output. Also verified: all
Usage commands match the real CLI surface exactly (conduct, next --harness,
gate, status, validate, policy activate with its six required flags,
repair-state, reconcile --continue, task defer, archive --yes,
publish --verify); the ten separated workflow facts plus containment render as
described, including the live coexistence of `Push authorization BLOCKED
BYPASSED` with `Remote parity PASS VERIFIED`; the outcome-state and
detail-state vocabularies are now kept separate per design-review.md DR-2 with
every field-pairing example matching the live render character-for-character;
the blocker vocabulary and single-action remediation table match
`sandbox_blocker()`; and the established language (candidate, receipt,
containment, rewind, reconciliation) is used precisely as the design artifacts
define it, with no unexplained terms. Final verdict this lens: PASS.

## Verdict

PASS

Both lenses failed the first round on one material finding each; the Documenter
applied all five fixes (two material, three minor) and both lenses re-verified
the corrected regions against code, artifacts, and live CLI output before
returning PASS. A future material change to documentation.md returns here for
fresh dual-lens validation.
