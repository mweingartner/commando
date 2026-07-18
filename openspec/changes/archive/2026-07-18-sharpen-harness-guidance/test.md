# Test — sharpen-harness-guidance

Governance: risk low. A doc-text + advisory-output change; no parser/codec/protocol
surface, so no fuzz/property pass is warranted — functional coverage + the full suite.

## Coverage

- **B nudge (e2e `conduct_nudges_toward_high_risk_below_high_but_stays_silent_at_high`):**
  `mpd conduct --chore --risk low` prints `Tip: risk=low … full-depth review`; `mpd
  conduct --chore --risk high` prints NO `Tip: risk=`; the nudge never mentions
  `reconcile`. **Load-bearing:** neutering the `rank() < High` guard to `<= High` makes
  the high-risk case print the tip, reddening the negative assertion (verified
  revert→red→restore).
- **A (protocol.md):** text-only; no test needed. The bundled directive still
  `include_str!`-compiles (the full build/test run exercises it).

## Results

Full workspace suite: **all pass, 0 failed** (1 pre-existing ignored perf test).
`cargo clippy --all-targets` clean (0 warnings); `cargo fmt --check` clean. No
implementation bug found.

## Verdict

**PASS.** The nudge is pinned by a load-bearing test; the doctrine text ships cleanly;
the suite is green. Ready for Deploy.
