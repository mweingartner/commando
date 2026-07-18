# Security (code) — sharpen-harness-guidance

Reviewed the real diff (+58 lines, 3 files). Governance: risk low; brief resolved
persona=Security, model=sonnet (standard tier). Proportionate to a doc-text + advisory-
output change with no security surface.

## Findings

None. The diff is:
- **protocol.md (+10):** two guidance sentences in the Harness contract (model-is-
  resolved; novel-surface→`--risk high`), consistent with the reviewed README prompt.
  No code, no execution.
- **cli.rs cmd_conduct (+21):** after the existing begin + call-loop print, a
  best-effort `if let Ok(root)=find_root()` → `if let Ok(ledger)=ledger::load(...)` →
  `if risk.rank() < High` → `println!` a static tip interpolating ONLY
  `ledger.governance.risk` (a closed enum printed by label — never user text, never a
  secret/path). A load failure degrades to no-tip; no panic, no changed exit code, no
  gate/resolution effect. Does NOT recommend `mpd reconcile` (the pre-Security
  phase-skip bug — filed as a follow-up).
- **e2e.rs (+27):** the load-bearing nudge test.

No credential handling, network egress, untrusted-input parsing, path handling, or
dynamic execution. `bounded_text`/gate/resolution logic untouched (grep-confirmed the
diff touches only cmd_conduct's tail + protocol.md + the test).

## Conditions verified

1. The tip reads risk from the loaded ledger (not the raw `--risk` arg), best-effort,
   closed-enum interpolation — confirmed. No `reconcile` recommendation — confirmed.
2. No behavior change to any gate/verdict/resolution path — confirmed (additive output
   only). Load-bearing test: neutering `< High` to `<= High` reddens the high-risk
   silence assertion (Builder verified revert→red→restore).

## Verdict

**PASS.** No security defects; the change is doctrine text + advisory, closed-enum
output behind a best-effort read. Proceed to Test.
