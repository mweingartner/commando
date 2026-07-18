# Sharpen the harness guidance (doctrine + a conduct risk nudge)

Canonical current state. Superseded drafts → `history/`.

## Why

Dogfooding surfaced that a harness carrying its own model-selection prior reads
past the existing "spawn on the named model" guidance and hand-picks models, and
uses too-low a risk for novel surface. The README prompt was already sharpened
(d6ca6c7); this carries the same two clarifications into the **in-binary doctrine**
(reaches every project via `mpd next --full`), and adds a once-per-change nudge so
the risk choice is deliberate.

## What Changes

- **A — `protocol.md` Harness contract:** state that the brief's `model` is resolved
  FOR the harness (tier + risk floor + config + tuning) — spawn on it, do not
  substitute; and that novel/risky surface should start at `--risk high` (floors
  Security/Tester to the deep model + max effort).
- **B — `mpd conduct` risk nudge:** when a conducted change is below high risk, print
  ONE tip (conduct is once-per-change, low-noise) that novel/risky surface warrants
  `--risk high`. The tip is forward-looking only — it does NOT recommend `mpd
  reconcile --risk high`, because that verb currently JUMPS a pre-Security change to
  `security-plan` (skipping Architecture) — a separate latent bug filed as a
  follow-up.

## Capabilities

### Modified Capabilities
- `harness-guidance` — the bundled doctrine text + the conduct nudge. No change to
  gate behavior, resolution, or the pipeline.

## Impact

`crates/mpd/assets/directives/protocol.md`, `crates/mpd/src/cli.rs` (cmd_conduct),
`crates/mpd/tests/e2e.rs`. A `--chore`: no functional gate behavior changes; the
README already carries the human-facing copy.
