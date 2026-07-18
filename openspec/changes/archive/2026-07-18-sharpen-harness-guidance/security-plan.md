# Security (plan) — sharpen-harness-guidance

Governance: risk low, threat profile local-trusted-user. Proportionate review
(brief resolved persona=Security, model=sonnet, no bump) — the surface is text +
one ledger read + a printed tip; no new capability, no untrusted input.

## Threat model

- **A (protocol.md text):** a bundled directive doc edit. No code path, no
  execution, no trust boundary. The doctrine already ships in the binary; this adds
  two guidance sentences consistent with the reviewed README prompt.
- **B (cmd_conduct nudge):** after `cmd_begin`, load the change's ledger and, if
  `risk.rank() < High`, `println!` a static tip interpolating only the risk enum
  label (low/medium — a closed enum, never user text). No secret, no path, no
  injection surface. The ledger load is best-effort (`if let Ok`) so a load failure
  degrades to no-tip, never a panic or a wrong exit code. Nudge is advisory: it does
  not gate, block, or alter any verdict.

No credential handling, no network egress, no file I/O on untrusted input, no dynamic
execution. Nothing novel.

## Conditions for Builder

1. The tip MUST derive risk from the loaded ledger's `governance.risk` (a closed enum
   printed by label), NOT from the raw `--risk` arg; best-effort load (no panic/error
   on failure). It MUST NOT recommend `mpd reconcile --risk high` (that verb skips
   Architecture pre-Security — out-of-scope bug, follow-up).
2. B changes no gate/resolution/exit behavior — purely additive output. A pins e2e:
   tip present below High, absent at High.

## Verdict

**PASS.** No threat-model gaps; the surface is doc text + advisory output with a
closed-enum interpolation and a best-effort read. Proceed to Build. (Separately
noted, not blocking this change: `reconcile --risk/--threat-profile` before the
Security phase advances to `security-plan` rather than staying put — file as a
follow-up defect.)
