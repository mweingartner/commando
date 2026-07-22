# Doc validation

## Actor
Architect (claude-code harness, deep tier) — validating `documentation.md` /
`docs/strict-objective-receipt-reuse.md` for accuracy against what shipped.

## Architect lens
Validated the durable doc against the amended design, the security-code audit, and the
real code/config:
- **Firing set accurate.** The doc states reuse fires ONLY on a byte-identical-Candidate
  (off-Candidate) rewind and explicitly says in-scope edits — source, config, AND prose
  — force fresh execution. This matches the corrected design.md Context/Goals and the
  security-code Independent-review finding (prose is in the Candidate via process scope).
  No trace of the retracted "prose-only edit → reuse" claim.
- **Flags/commands real.** `mpd gate build --pass --reuse <receipt>` and `mpd gate test
  --pass --reuse <receipt>` match the `--reuse` option in `cmd_gate` (cli.rs:3229, help
  at cli.rs); `mpd next` offering the receipt matches the brief output.
- **Config block real.** The `closure.hermetic_reuse` JSON matches `.mpd/config.json`
  (snake_case key, `schema`/`external_state`/`environment`/`input_paths`) and the
  `HermeticReusePolicy`/`NoExternalState` types; `deny_unknown_fields` claim is true
  post-L2.
- **Equality set (1-6) accurate** against `evaluate_strict_objective_reuse`
  (cli.rs:3097-3215), including the Build-only disk revalidation down to device/inode
  (item 5) and the SecurityCode-never-reuses / fresh-scan-set premise.
- **Trust-boundary text accurate** — HermeticExecutable binding and the "no *unpinned*
  external mutable state" attestation match the security-plan C3 enumeration and README.
- No overclaim of value: the doc is explicit that the common prose-edit rewind is NOT
  accelerated and names freeze-before-gating as that mitigation.

## Designer lens
N/A — this is a backend/tooling change with no user-visible UI/UX surface (CLI text
only, covered by the Architect lens). No design intent to validate.

## Verdict
PASS. The documentation is accurate against the shipped code, config, and corrected
contract; every named flag, command, path, and config key was verified to exist.
