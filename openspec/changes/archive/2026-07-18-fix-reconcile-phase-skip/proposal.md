# Fix: reconcile before Security must not skip Architecture

Canonical current state.

## Why

`mpd reconcile --risk <l>` (and `--threat-profile`) while a change is at a phase
BEFORE Security (e.g. Architecture) advances the phase FORWARD to `security-plan`,
skipping the ungated intervening phase(s). Root cause: `Ledger::invalidate_from_security`
unconditionally sets `phase = SecurityPlan`. A governance change should only ever
REWIND (force a re-review of Security + downstream), never advance. Found while
building the conduct risk-nudge (which had to avoid recommending `reconcile` because
of this). The archive guard already refuses a missing Architecture gate, so this is a
correctness/UX defect, not a security bypass — but the harness is left mid-pipeline in
a confusing state (at `security-plan` with Architecture never gated).

## What Changes

- `invalidate_from_security` repositions to `SecurityPlan` (and resets the phase timer)
  ONLY when the current phase is already past `SecurityPlan`; when the change is at or
  before `SecurityPlan`, it stays put. The gate-removal + waiver-drop are unchanged
  (they only affect phases `>= SecurityPlan`, of which there are none before Security).

## Capabilities

### Modified Capabilities
- `process-governance` — the reconcile rewind is rewind-only; it never advances a
  pre-Security change.

## Impact

`crates/mpd/src/ledger.rs` (one guarded transition), `crates/mpd/tests/e2e.rs`. A
`--fix`; the downstream (current > SecurityPlan) rewind — the security-critical path —
is byte-for-byte unchanged.
