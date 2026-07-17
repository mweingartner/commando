# Doc Validation — persona-tuning

Validation of `documentation.md` against the shipped implementation and the
design/security/test artifacts. Governance: risk medium.

## Architect lens

Functional / scope / technical accuracy — every claim cross-checked against the
code and the CLI:

- The three knobs, their ranges, and the keying (`personas` by display name +
  `DocValidation`) match `config.rs`/`phase.rs::tuning_key`. ✓
- `rigor`→effort mapping (`standard`→baseline, `deep`→`high`, `paranoid`→`max`),
  the monotonic-`max` ordinal compose, the high-risk floor for the adversarial set
  with **no model clause**, and the reviewer add/clamp match
  `harness.rs::resolve_tuning_governed`. ✓
- The two un-rankable weakening vectors (config `directive_append` + directive-file
  `base_modified`), the record-at-`next` / stamp-at-`gate` TOCTOU close, the
  conditional + monotonic weakest-seen recording, and the narrow
  `DependencyKey::PersonaTuning` reuse-staling all match `cli.rs`/`ledger.rs`/
  `closure.rs`. ✓
- The guardrails (strengthen-only menus, recorded-not-blocked, best-effort stamp vs
  structural guarantees, inert baseline) match the design's Decisions and the
  Security artifacts' scoping — no overclaim; the "best-effort, not cryptographic"
  framing is stated honestly. ✓
- The CLI usage examples were run against the installed binary and reproduce
  verbatim: the `rigor`/`depth` set messages, the `directive-append` ⚠ warning text,
  and the `persona show --json` field shape (`current`/`baseline`/`range`/
  `dangerous`). ✓

No inaccuracies, no phantom features, nothing quietly degraded.

## Designer lens

Purpose / value / representation — is the feature completely and elegantly
represented for its audience (harness authors + operators)?

- Purpose and Value lead with the actual problem (behavior was fixed except the
  model) and the actual value (strengthen freely, never silently weaken), in the
  project's own language. ✓
- Scope explicitly separates what it covers from the guardrails and trust
  boundaries — the "does NOT cover" section carries the integrity story a reader
  most needs, matching how the rest of mpd's docs foreground guarantees. ✓
- Every user-facing surface is represented: the config block, all four `mpd persona`
  verbs, the brief carriage, the receipt stamp, and — critically — the
  harness-conducted interview (with the apply-the-brief / record-before-set
  doctrine), so a harness author can implement the interview from this doc alone. ✓
- The un-rankable knob is represented with the same ⚠ prominence the tool itself
  uses, so the doc does not undersell the one dangerous lever. ✓

The representation is complete and proportionate; nothing a user interacts with is
missing or buried.

## Verdict

**PASS.** The documentation is accurate against the shipped code (CLI examples
verified against the installed binary), complete across every user-facing surface
including the interview, and honestly scoped on the integrity guarantees. Both
lenses confirm. Ready to archive.
