# Narrowed `.mpd/state/**` secret-allowlist exemption

## Purpose
The secret allowlist blanket-suppressed ALL scan rules on the ledger directory
`.mpd/state/**`. That entry existed only to hide a generic-rule false positive that
a later precision fix already resolved, so it now suppressed nothing while leaving
a blind spot: a real branded token in a ledger file was silently exempt.

## Value
Closes the blind spot: curated secret rules (GitHub, Slack, AWS, private-key, etc.)
now scan the ledger, so a real token committed into or pushed from a state file is
caught — while only the generic backstop stays suppressed on machine-generated
ledger data.

## Scope
**Covers:** `.mpd/secret-allowlist.json` — `.mpd/state/**` moved from `paths`
(all-rules) to an `allow` entry scoped to `generic-secret-assignment` only.
**Unchanged:** `openspec/changes/archive/**` (immutable machine-generated review
record) stays a blanket `paths` exemption — a separate decision.

## Functional details
- `Allowlist` suppresses a finding when a `paths` glob matches (rule-independent) or
  an `allow` entry matches with its optional `rule`. The narrowed entry
  `{path:".mpd/state/**", rule:"generic-secret-assignment"}` therefore suppresses
  only the generic rule on the ledger; every curated rule fires there normally.
- Config-only; no scanner code or policy digest changes, so no coordinator rebuild.

## Usage
- A generic-rule match on ledger machine-data (a keyword-plus-run string) is still
  suppressed. A curated-rule match on a ledger file — e.g. a GitHub PAT or AWS key
  id accidentally embedded — is now reported and blocks the commit/push. (Verified:
  a planted PAT-shape in a temp `.mpd/state` file was caught as a `github-token`
  finding.)
