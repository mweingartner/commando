# Security (code) review

## Actor
Security (claude-code harness). Config-only change (`.mpd/secret-allowlist.json`),
empirically verified against the running scanner.

## Findings
None. The change is a security-strengthening narrow of a blanket suppression.

## Conditions verified
- **Rule-scoped, not blanket (Cond 1):** `.mpd/state/**` moved from `paths`
  (all-rules) to `allow` as `{path:".mpd/state/**", rule:"generic-secret-assignment"}`
  (no `line`); `openspec/changes/archive/**` stays in `paths` unchanged. Confirmed
  by inspection of the shipped `.mpd/secret-allowlist.json`.
- **Valid JSON / round-trips (Cond 2):** `Allowlist::load` parses it (the scanner
  ran and applied it — see below); a malformed file would load empty and suppress
  nothing, so a parse regression would have SHOWN findings, not hidden them.
- **Scope (Cond 4):** only `.mpd/secret-allowlist.json` changed (+ the change's own
  process artifacts). No code, no rule, no policy digest touched.

## Independent review
Empirical, against the running coordinator (not self-reported logic):
- `mpd check` over the repo → "Secret scan: 1 finding(s) suppressed by allowlist" —
  the single generic-secret-assignment finding on a `.mpd/state` ledger is still
  suppressed by the narrowed rule-scoped entry (behavior preserved for the machine-
  data false-positive class).
- A planted branded-token shape (`ghp_`+36, assembled) in a temp `.mpd/state/*.json`
  file → `Secret scan (builtin-staged) found 1 finding(s): …:1 [github-token]` — the
  curated `github-token` rule CAUGHT it (NOT suppressed by the generic-only entry).
  The blind spot is closed. Probe removed after the check.

## Refutation
Strongest attack: does the narrowed entry still blindly exempt a real token? Refuted
— the curated `github-token` (and every other curated rule) now fires on
`.mpd/state` and survives the filter (demonstrated). The only remaining suppression
is `generic-secret-assignment` on ledger machine-data — a documented, justified
backstop exemption, not an all-rules blind spot.

## Verdict
PASS — verified strengthening of the control; may proceed to Test. No coordinator
rebuild (allowlist is not in the canonical policy digest).
