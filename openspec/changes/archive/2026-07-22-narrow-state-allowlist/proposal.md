# Narrow the `.mpd/state/**` secret-allowlist exemption

## Why
`.mpd/secret-allowlist.json` lists `.mpd/state/**` under `paths`, which suppresses
ALL secret-scan rules on the ledger directory. It was added by secret-fixture-hygiene
(2026-07-21) only to hide `generic-secret-assignment` false positives on ledger
array-element lines whose text contains a change name with "secret". The
secret-scan-path-precision change (2026-07-22) made that rule path-precise; the
built-in scanner now finds ZERO raw findings across the 19 `.mpd/state/**` files
with the exemption ignored. So the blanket entry now suppresses nothing while
remaining an all-rules blind spot: a real branded token (a GitHub PAT, a Slack
bot token, an AWS access key id) that ever lands in a state file would be silently
exempt at BOTH the pre-commit staged scan and the pre-push outgoing scan (both
honor this allowlist).

## What Changes
- Move `.mpd/state/**` from `paths` (blanket, all-rules) to an `allow` entry
  scoped to the one rule that ever fired there:
  `{ "path": ".mpd/state/**", "rule": "generic-secret-assignment" }`. The curated
  rules (private-key, AWS, Slack, GitHub, Google, Stripe, OpenAI, JWT) now DO scan
  the ledger — a real branded token in a state file is caught — while the generic
  backstop stays suppressed on machine-generated ledger data (digests, receipts,
  paths) that can structurally look token-ish.
- `openspec/changes/archive/**` (also machine-generated, immutable review record)
  is left as-is (out of scope) — a separate decision.

Not **BREAKING**. Behavior change (intentional): a branded-token shape committed
into or pushed from a `.mpd/state/*.json` file is now flagged (was: silently
allowed).

## Capabilities
### New Capabilities
None.
### Modified Capabilities
None (the allowlist is configuration, not a spec'd requirement; the
"Scanner-clean first-party source" spec forbids whole-file suppressions only for
first-party SOURCE, and `.mpd/state` is process state — narrowing strengthens it).

## Impact
- `.mpd/secret-allowlist.json` only. No code change → no coordinator rebuild (the
  allowlist is read at scan time and is NOT part of the canonical policy digest).
- Verified: the built-in generic rule still yields 0 findings on the current
  ledger tree (so the narrowed entry suppresses nothing today), and a planted
  branded-token shape in a `.mpd/state/*.json` file IS now caught by its curated
  rule.
