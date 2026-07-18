Canonical checklist.

## 1. Implement
- [x] 1.1 A: add the `model`-is-resolved + novel-surface→`--risk high` rules to the `protocol.md` Harness contract (text only). (assets/directives/protocol.md)
- [x] 1.2 B: `cmd_conduct` loads the ledger after begin and prints ONE risk-high tip when `governance.risk.rank() < High`; forward-looking wording, NO `reconcile` recommendation. (cli.rs)

## 2. Verify
- [x] 2.1 e2e: `mpd conduct x --chore` (below high) prints the tip; `mpd conduct y --chore --risk high` does NOT. Load-bearing (drop the rank guard → the high-risk case reddens). (e2e.rs)
