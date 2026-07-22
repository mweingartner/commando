# Path-precise generic secret detection

## Why

The built-in scanner's `generic-secret-assignment` rule false-positives on
filesystem paths and hyphenated names that contain a secret keyword plus a digit
(e.g. `openspec/changes/archive/2026-07-21-secret-fixture-hygiene`). It keys on a
keyword anywhere in the line, extracts a value, and flags it if the value is
≥20 chars with any letter and any digit — true of every dated archive path whose
change name contains "secret"/"token". This forced a whole-tree `.mpd/state/**`
allowlist exemption (added by `secret-fixture-hygiene`), and every future change
named `*secret*`/`*token*` re-trips the rule at new ledger lines. A rule that
cannot tell a path from a credential erodes trust in the gate it backs.

## What Changes

- Tighten `generic_secret_assignment` only: a keyword-bearing value is flagged
  only when it contains a contiguous run of ≥16 characters from the
  credential-token alphabet `[A-Za-z0-9+]` that itself carries at least one
  letter and one digit. Paths, dates, and hyphenated dictionary names decompose
  into shorter runs separated by `/ - _ .` and whitespace and are no longer
  flagged.
- **Strict monotone tightening**: every value flagged after this change was
  flagged before it (the run gate subsumes the old whole-value letter+digit
  test), so it provably introduces no new false positives — the entire review
  burden is false-negative analysis, done shape-by-shape in the design.
- No dedicated rule (private-key armor, AWS, Slack, GitHub, Google, Stripe,
  OpenAI, JWT), extraction helper, placeholder list, windowing constant, or
  allowlist file is touched.
- Accepted, documented detection losses within the generic backstop's scope:
  UUID-shaped and 4-char-grouped keys (deterministic), and a small probabilistic
  miss for short standard-base64 values containing `/` and unbranded base64url.

Not **BREAKING**.

## Capabilities

### New Capabilities

None.

### Modified Capabilities

- `local-validation` — gains a requirement that the generic secret rule is
  path-precise (flags only contiguous credential-token material), while its
  length/placeholder/keyword conditions and all curated rules stay in force.

## Impact

- Source: `crates/mpd/src/checks/secrets.rs` only (one constant + one helper +
  the revised final gate + tests).
- Spec: `openspec/specs/local-validation/spec.md` gains one requirement at
  archive.
- `.mpd/secret-allowlist.json` is intentionally NOT modified — the `.mpd/state/**`
  exemption stays, on **scope discipline** (this change touches only the rule).
  Honest correction (per Security-plan review): the exemption is NOT needed
  because ledgers carry keyword-bearing digests — digest lines carry no keyword
  (hex cannot spell one) and `extract_quoted` returns the short key, so after
  this precision fix the exemption almost certainly suppresses ZERO built-in
  findings while remaining a blanket, all-rules blind spot. The change's
  verification empirically scans `.mpd/state/**` with the exemption ignored and
  records the count; a follow-up to narrow/remove the exemption is filed
  (separate risk decision — must weigh non-generic shapes in future ledger
  evidence strings).
- Because `crates/**` changes, landing requires the coordinator rebuild +
  `mpd policy activate` re-activation (single-host; orchestrator step).
