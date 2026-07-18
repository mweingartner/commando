# Test — fix-reconcile-phase-skip

Governance: risk medium. A state-machine guard fix; no parser/codec surface, so
functional + regression coverage (no fuzz pass warranted).

## Coverage

- **Regression (the fix):** `governance_change_before_security_stays_put_and_does_not_advance`
  (ledger unit) — a `reconcile` at Architecture for BOTH `Risk` and `ThreatProfile`
  keeps `phase == Architecture` and records the reconciliation.
  `reconcile_before_security_does_not_skip_architecture` (e2e) drives `mpd reconcile
  --risk high` at Architecture through the binary and asserts `status.phase ==
  architecture` (risk now high). **Load-bearing:** reverting the guard to
  unconditional reddens both with "must stay at Architecture, not advance" (verified
  revert→red→restore).
- **Preserved security-critical path:** the existing
  `governance_change_retains_history_and_rewinds_only_security_and_downstream`
  (current > SecurityPlan → rewinds to SecurityPlan, gates removed, history kept)
  still passes unchanged — the downstream rewind is intact.

## Results

Full workspace suite: **all pass, 0 failed** (1 pre-existing ignored perf test).
`cargo clippy --all-targets` clean; `cargo fmt --check` clean. No implementation bug.

## Verdict

**PASS.** The fix is pinned by load-bearing regression tests and the security-critical
downstream rewind is proven unchanged. Ready for Deploy.
