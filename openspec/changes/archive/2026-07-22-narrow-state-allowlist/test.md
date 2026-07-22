# Test report

## Actor
Tester (claude-code harness). Config-only change; the rule-scoped `allow`
mechanism is already unit-tested, so verification is empirical + the full suite.

## Coverage
- **Mechanism (pre-existing unit test):** `allowlist::tests::allowlist_path_and_rule_matching`
  covers that an `allow{path, rule}` entry suppresses only that rule.
- **Empirical (this change):** `mpd check` shows the ledger's generic finding
  suppressed by the narrowed entry; a planted `ghp_`+36 shape in a temp
  `.mpd/state/*.json` is caught as `[github-token]` (not suppressed). Blind spot
  closed.
- **Full suite** unaffected by the allowlist content (`first_party_source_is_scanner_clean`
  uses an empty allowlist).

## Results
Build/Test objective validation ran the full workspace suite green (unchanged
binary). `mpd check` empirical checks as above. No new test file (mechanism already
covered; config content is data, not unit-tested).

## Verdict
PASS — the narrow is verified to strengthen detection (curated rules now scan the
ledger) while preserving the generic-backstop suppression on machine data.
