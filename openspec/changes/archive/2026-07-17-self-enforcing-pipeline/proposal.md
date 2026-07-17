# Self-enforcing adversarial pipeline (two-tier)

Canonical current state. Superseded drafts go to `history/`.

## Why

mpd enforces the *objective* gates (build/test pass-count, secret scan, doc
structure, closure coherence) ruthlessly, but the *adversarial-judgment* layer —
Architecture/Security reasoning, review verdicts — is only "a verdict plus an
optional, unverified evidence pointer." Its rigor and durability therefore
depend entirely on operator discipline. Proof from this repo: the
`content-addressed-release-closure` change archived with its `security-code.md`,
`test.md`, `design-signoff.md`, and `doc-validation.md` **missing** — the
adversarial record evaporated — while `improve-mpd-process-governance` kept all
of them. A harness that believed it "used mpd correctly" still lost the review.

## What Changes

- Introduce **two interface tiers over one ledger and one gate code path**,
  selected by a durable per-change `strict` bit:
  - **Manual tier (unchanged):** raw verbs (`next`/`gate`/`status`/`check`/
    `resolve`/`reconcile`) for a human driving a local model by hand — only the
    objective machine gates apply, zero new friction.
  - **Orchestration tier (new):** `mpd conduct <name>` sets `strict=true` and
    prints the harness call-loop. In strict mode each judgment gate requires a
    structurally-checked, non-stub artifact; `--evidence` must resolve to that
    phase's own artifact; artifacts are re-checked at archive (anti-evaporation).
- Add **universal** ergonomics/recovery for both tiers: `mpd use <change>`,
  `mpd doctor --fix` (gitignore self-heal + test-command sanity + stall age),
  `mpd brief <phase>`, `mpd next --context`, `mpd status --brief`, an archive
  transient-path pre-flight, and a **risk→deep model bump** that actually fires.
- Every strict requirement ships with a one-command escape (`--waive-artifact`,
  `mpd brief`, `mpd use`, `doctor --fix`) so it can never become a stuck-state.

## Capabilities

### New Capabilities

- `strict-orchestration` — the `strict` ledger bit, `mpd conduct`/`begin --strict`,
  the strict judgment-artifact gate, evidence resolution, `--waive-artifact`,
  and the archive-time re-check.
- `operator-recovery` — `mpd use`, `mpd doctor --fix`, the archive pre-flight,
  and the autonomous-reconcile policy.
- `context-economy` — `mpd next --context`, `mpd brief <phase>`,
  `mpd status --brief`, and history windowing.

### Modified Capabilities

- `process-governance` — the risk level now drives the effective model tier for
  Security/Test (the bump).

## Impact

`crates/mpd/src/{cli.rs, ledger.rs, phase.rs, harness.rs, config.rs,
scaffold.rs}`, `crates/mpd/assets/{templates/judgment/*, directives/protocol.md}`,
the merged `openspec/specs/*` for the new capabilities, and `docs/`. No breaking
changes: additive `#[serde(default)]` ledger fields, a `strict=false` gate is
byte-identical to today, and archived changes are never re-checked.
