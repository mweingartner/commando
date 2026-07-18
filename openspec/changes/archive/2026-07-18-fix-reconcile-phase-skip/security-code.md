# Security (code) — fix-reconcile-phase-skip

Reviewed the real diff (+59/-2, 2 files). Governance: risk medium; brief resolved
Security at standard tier.

## Findings

None. The only source change wraps the phase reposition in
`if self.phase > Phase::SecurityPlan { … }`:
- **`phase > SecurityPlan` (the security-critical rewind — a change past Security
  re-reviewing after a governance change):** behavior is byte-identical to before
  (set phase = SecurityPlan + reset the timer). Confirmed by the unchanged, still-
  passing `governance_change_retains_history_and_rewinds_only_security_and_downstream`.
- **`phase <= SecurityPlan`:** now stays put instead of jumping forward. This is the
  strengthening fix — a governance change can no longer skip an ungated pre-Security
  gate. Reconcile still rewinds *to* Security; it never skips it.

The gate-removal loop (`>= SecurityPlan`) and waiver retain (`< SecurityPlan`) are
untouched and remain no-ops before Security. The risk-downgrade autonomous halt
(cmd_reconcile) is a separate path, untouched. No credential/network/untrusted-input/
path/dynamic-exec surface.

## Conditions verified

1. Guard is exactly `self.phase > Phase::SecurityPlan`; gate-removal loop + waiver
   retain byte-identical — confirmed by the diff.
2. Downstream rewind preserved — the existing rewind test passes; the new
   `governance_change_before_security_stays_put_and_does_not_advance` (both Risk AND
   ThreatProfile at Architecture) and the e2e are load-bearing (neuter the guard →
   the Architecture case reddens with "must stay at Architecture, not advance";
   verified revert→red→restore).

## Verdict

**PASS.** Strengthening fix; the security-critical rewind and the risk-downgrade halt
are unchanged; no bypass introduced. Proceed to Test.
