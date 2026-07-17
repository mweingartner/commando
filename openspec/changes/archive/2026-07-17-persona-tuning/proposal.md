# Per-persona behavior tuning (with an audited interview)

Canonical current state. Superseded drafts go to `history/`.

## Why

The only per-persona lever today is the model (`config.models[harness][persona]`).
Behavior — reasoning depth, review rigor, test emphasis, project-specific
instructions — is fixed unless you wholesale-replace a bundled persona directive
(destructive: a future hardening update to that directive is lost; undiscoverable;
unstructured). Users need to tune each adversarial persona *without* being able to
silently defeat the adversarial guarantee the tool exists for.

## What Changes

- Add a `personas` block to `.mpd/config.json` with strengthen-only, ordinal
  knobs plus one audited free-text escape, all `#[serde(default)]`:
  - `rigor` (`standard | deep | paranoid`) — all personas, **including Doc
    Validation** — expands to reasoning **effort** + reviewer count.
  - `depth` (`examples | property | fuzz`) — the **Tester** — a strengthen-only
    test-emphasis overlay.
  - `directive_append` — a non-destructive overlay appended after the bundled
    directive (never replacing it); the one *un-rankable* knob, always audited.
- Carry the resolved tuning into the `mpd next` brief (effort, reviewers,
  directive overlay) so the harness applies it — mpd never runs a model.
- **Integrity by construction:** the ordinal menus have no sub-baseline term
  (you cannot dial a persona weaker through them); `risk=high` **floors** rigor at
  `deep` for the adversarial set (Security, Tester, Doc Validation); the one
  un-rankable vector (a `directive_append`, or a wholesale directive override) is
  **recorded** — a `persona_tuning` stamp on the `GateRecord` and a `weakened`
  flag on the brief — so a tuned PASS is never indistinguishable from a full-rigor
  one.
- Add `mpd persona list/show/set/reset` (schema + current value + range +
  danger classification + safe writes), and document the **harness-conducted
  interview** loop that drives them (show current/range, warn on the un-rankable
  change, record persistently).

## Capabilities

### New Capabilities

- `persona-tuning` — the `personas` config, the governed resolver, the brief
  fields, and the `GateRecord` stamp.
- `persona-interview` — `mpd persona list/show/set/reset` + the danger classifier
  + the documented harness interview workflow.

### Modified Capabilities

- `process-governance` — `risk=high` now also floors persona rigor (composing with
  the existing model bump).

## Impact

`crates/mpd/src/{config.rs, harness.rs, ledger.rs, cli.rs, phase.rs, scaffold.rs}`,
`crates/mpd/assets/directives/protocol.md`, docs. Additive, `#[serde(default)]`; an
empty `personas` map yields a byte-identical brief and no gate change. No new
gate, no stuck-state.
