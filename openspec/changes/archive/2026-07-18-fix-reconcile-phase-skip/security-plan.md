# Security (plan) — fix-reconcile-phase-skip

Governance: risk medium, local-trusted-user. Brief resolved persona=Security,
standard tier — proportionate to a 4-line, strengthening guard on the governance
rewind.

## Threat model

The reconcile rewind (`invalidate_from_security`) is the anti-weakening mechanism:
a governance change (risk/threat-profile) forces a fresh Security review by removing
gates `>= SecurityPlan` and repositioning the phase. The one question that matters:
**can the fix let anything skip the SECURITY gate, or weaken the risk-downgrade
halt?**

- **No skip of Security.** The fix guards the reposition on `phase > SecurityPlan`.
  For `phase > SecurityPlan` (the security-critical case — a change that already
  passed Security and is now at Build/Test/…), behavior is UNCHANGED: it still
  rewinds to SecurityPlan to re-review. The fix only changes `phase < SecurityPlan`
  (Architecture/Design), where it now STAYS instead of jumping FORWARD to
  SecurityPlan. Reconcile never skips Security — it rewinds *to* it.
- **No weakening of the risk-downgrade halt.** That halt lives in `cmd_reconcile`
  under `--autonomous` (design.md D7 / Cond 12), separate from this function —
  untouched.
- **Pre-Security phases stay required.** A change left at Architecture without the
  jump is still blocked from archive by `blocking_reasons()` ("Architecture gate not
  recorded"). The bug's only effect was a confusing mid-pipeline state, not a bypass.

The gate-removal loop and waiver retain are unchanged and already no-ops before
Security (nothing gated `>= SecurityPlan` there). No credentials, network, untrusted
input, or dynamic execution.

## Conditions for Builder

1. Guard on `self.phase > Phase::SecurityPlan` only; leave the gate-removal loop +
   waiver retain byte-identical. The `> SecurityPlan` rewind (the security-critical
   path) MUST be unchanged.
2. Pin the downstream rewind with the existing
   `governance_change_retains_history_and_rewinds_only_security_and_downstream` test;
   add coverage that a pre-Security (Architecture) governance change stays put.

## Verdict

**PASS.** The change is strengthening (a rewind can no longer skip a gate forward);
the security-critical rewind branch and the risk-downgrade halt are untouched; no
bypass is introduced. Proceed to Build.
