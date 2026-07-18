# Design: reconcile rewind is rewind-only

## Context

`Ledger::invalidate_from_security` (ledger.rs) runs on a `reconcile --risk` /
`--threat-profile` (a governance change that must force a fresh Security review). It
removes gates `>= SecurityPlan`, drops those phases' waivers, and repositions the
phase. The bug: it sets `phase = SecurityPlan` UNCONDITIONALLY, so a change at
Architecture (< SecurityPlan) jumps FORWARD, skipping Architecture. `Phase` derives
`Ord` in pipeline order (DesignMock < Architecture < DesignReview < SecurityPlan < …).

## Decisions

### D1 — rewind-only transition
Guard the reposition on `self.phase > Phase::SecurityPlan`:
```rust
if self.phase > Phase::SecurityPlan {
    self.phase = Phase::SecurityPlan;
    self.phase_started_at_epoch_secs = now_epoch_secs();
}
```
- current > SecurityPlan (Build/Test/…): rewind to SecurityPlan + reset timer —
  UNCHANGED (the security-critical re-review path).
- current == SecurityPlan: no-op (already there; the Security review is still pending).
- current < SecurityPlan (DesignMock/Architecture/DesignReview): STAY — the fix.

The gate-removal loop and waiver retain are UNCHANGED: before Security nothing is gated
`>= SecurityPlan`, so both are already no-ops there.

## Risks / Trade-offs
- [Weakening the security rewind] → the `current > SecurityPlan` branch is unchanged;
  only the pre-Security no-op case is corrected. The change is strengthening (a rewind
  can no longer skip a gate forward). A unit test pins the downstream rewind still works.
- [Timer semantics at ==SecurityPlan] → previously reset the timer even at
  ==SecurityPlan (cosmetic, affects only a gate's `duration_secs`); now a no-op there.
  Acceptable — duration is advisory.

## Conditions for Builder
1. Guard the reposition on `self.phase > Phase::SecurityPlan`; leave the gate-removal
   loop + waiver retain unchanged.
2. The downstream rewind is preserved: the existing
   `governance_change_retains_history_and_rewinds_only_security_and_downstream` unit
   test (current=SecurityCode → SecurityPlan) MUST still pass.
3. New coverage: a governance change (risk AND threat-profile) while at Architecture
   keeps `phase == Architecture` and records the reconciliation; an e2e drives
   `reconcile --risk high` at Architecture and asserts `status.phase == architecture`.
   Load-bearing (revert the guard → the Architecture case reddens).
4. Runs under strict; retains its judgment artifacts through archive.
