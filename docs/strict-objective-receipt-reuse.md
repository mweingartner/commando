Status: SUPERSEDED
Superseded by: docs/candidate-scope-integrity.md

# Strict objective-receipt reuse (`mpd gate --reuse`)

## Purpose
A freshness rewind wipes every gate record at or after the rewound phase, including a
still-valid Build/Test validation receipt. When the rewind leaves the Candidate
byte-identical, re-executing the hermetic sandbox reproduces an identical result at
real wall-clock cost. This change lets a strict Build or Test gate **reuse** that prior
receipt instead of re-executing, under an equality set strictly tighter than the manual
tier requires.

## Value
Removes redundant sandbox re-execution — not rigor — for the narrow class of rewinds
whose cause lies *outside* the Candidate. It is fail-closed: any drift re-executes, and
Security(code) never reuses.

## Scope
**Covers:** strict `Build` and `Test` gates, via an explicit, audited `--reuse
<receipt>` operator action offered by `mpd next`; opt-in through `.mpd/config.json`.

**Does NOT cover — by design:**
- **Security(code)** — categorically re-executes on every rewind; its fresh
  deterministic scan set (self-check, dependency-audit, secret-scan, SAST) is the
  premise that makes reusing Test's embedded scans safe.
- **In-scope file edits** — the Candidate binds every manifest-scoped file: source,
  config, *and* the change's own prose (`design.md`/`proposal.md`/`tasks.md` are folded
  in via the mandatory `openspec/changes/<change>/**` process scope so the secret
  scanner covers them). Editing any of them — prose included — changes the Candidate id
  and correctly forces fresh execution. Reuse therefore does NOT accelerate the common
  "edited a planning artifact after its gate" rewind; the mitigation for that is to
  **freeze prose before gating**.

**Reuse fires only** when a rewind leaves the Candidate byte-identical: an off-Candidate
cause such as a persona-directive / governance / risk re-derivation that touches no
in-scope file, a `repair-state` rewind, or an edit reverted to byte-identical.

**Trust boundary:** reuse binds the running coordinator's own executable digest
(`HermeticExecutable`), so a binary/coordinator swap refuses; the opt-in attests only
that no *unpinned* external mutable state feeds validation (ambient cargo/SDK/tool
reads remain, pinned by offline+locked builds, `Cargo.lock` checksums, and
execution-time tool-digest verification against `security/tool-lock.json`).

## Functional details
A strict `Build`/`Test` `--reuse <receipt>` request passes only if ALL hold (each miss
errors before any ledger write; the phase then executes fresh):
1. The origin record carries a retained Candidate, a typed validation receipt, and —
   for Build — a typed build output, with the receipt bound to that Candidate (checked
   for both phases).
2. The Candidate re-derived NOW (Build recaptures + rehashes; Test reuses the retained
   Candidate the current Build+SecurityCode PASSes bound) has the same id as the origin.
3. The gate profile selected from the CURRENT effective risk equals the origin
   receipt's profile (a risk escalation cannot reuse a lighter profile).
4. The current candidate policy digest equals the origin's (and the origin receipt is
   internally consistent).
5. Build only: the recorded build output still matches disk exactly — size, mode,
   device, inode, and content digest — or reuse refuses.
6. The reused record carries the verified Candidate / validation receipt / build output
   plus a `"reused from receipt <hex>"` check summary, so downstream archive
   equivalence keeps working.

Enabled by a config opt-in that parses under `deny_unknown_fields` (a typo fails to
parse rather than silently granting reuse); the reuse-path ledger write uses the same
compare-and-swap as the execute path.

## Usage
Opt in, in `.mpd/config.json`:
```json
"closure": {
  "hermetic_reuse": {
    "schema": 1,
    "external_state": "none",
    "environment": [],
    "input_paths": ["security/tool-lock.json"]
  }
}
```
After an off-Candidate rewind, `mpd next` prints the reusable receipt for the current
phase. Reuse it explicitly:
```sh
mpd gate build --pass --reuse <receipt-hex>
mpd gate test  --pass --reuse <receipt-hex>
```
If anything the receipt certified has drifted — or the edit that caused the rewind
touched any in-scope file — the command refuses and you run the gate normally, which
re-executes the sandbox.
