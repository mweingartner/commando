Canonical checklist.

## 1. Fix
- [x] 1.1 Guard the reposition in `invalidate_from_security` on `self.phase > Phase::SecurityPlan` (rewind-only); gate-removal + waiver retain unchanged. (ledger.rs)

## 2. Verify
- [x] 2.1 ledger.rs unit test: a risk reconcile AND a threat-profile reconcile at Architecture keep `phase == Architecture` (+ reconciliation recorded); the existing downstream-rewind test still passes. Load-bearing.
- [x] 2.2 e2e: `mpd reconcile --risk high` at Architecture → `status.phase == "architecture"` (not "security-plan"). (e2e.rs)
