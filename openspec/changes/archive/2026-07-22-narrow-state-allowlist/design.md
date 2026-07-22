# Design: Narrow the `.mpd/state/**` secret-allowlist exemption

## Actor
Architect (claude-code harness).

## Context
`Allowlist::is_allowed` (allowlist.rs) suppresses a finding if any `paths` glob
matches (rule-independent) OR any `allow` entry matches with
`rule.is_none_or(== rule)` and `line.is_none_or(== line)`. So a `paths` entry is a
blanket all-rules suppression; an `allow` entry with `rule: Some("...")` suppresses
only that rule. The `.mpd/state/**` blanket entry is now inert for the generic rule
(0 findings post path-precision) but blindly exempts curated-rule findings too.

## Goals / Non-Goals
Goal: close the curated-rule blind spot on the ledger while keeping the generic
backstop suppressed there (machine-generated ledger data legitimately carries
digest/receipt strings that a future generic rule could misfire on). Non-Goal: no
code change; no change to `openspec/changes/archive/**` (separate decision); no
change to the scanner or its rules.

## Decisions
**D1 — Narrow, not remove.** Move `.mpd/state/**` to `allow` as
`{path:".mpd/state/**", rule:"generic-secret-assignment"}`. Removal entirely is
defensible (0 generic findings today) but narrowing is strictly safer: it keeps a
targeted margin against future generic false positives on ledger machine-data
while still exposing the ledger to all CURATED rules — which is the real-token
threat that matters. The rule-scoped `allow` mechanism is already unit-tested
(`allowlist_path_and_rule_matching`).

## Risks / Trade-offs
- [A future ledger evidence string trips the generic rule and, being suppressed,
  is missed] → acceptable: the generic rule is a keyword+contiguous-run backstop;
  ledger data that matters (real tokens) is branded and caught by curated rules;
  the generic suppression covers only the machine-data false-positive class.
- [A real generic-only secret (unbranded AWS secret key) committed into a ledger
  is still suppressed] → the same residual the whole-file entry had, now the ONLY
  residual; egress content scan is path-independent and still covers push. Noted.

## Conditions for Builder
1. `.mpd/state/**` removed from `paths`; added to `allow` as `{path, rule:
   "generic-secret-assignment"}` (no `line`). `openspec/changes/archive/**` in
   `paths` unchanged.
2. Valid JSON; `Allowlist::load` parses it (a malformed allowlist loads empty =
   suppresses nothing, so parse-failure would be a silent regression — verify it
   round-trips).
3. Verify (manually, this is config-only): the built-in scanner over `.mpd/state/**`
   still yields 0 findings under the narrowed allowlist; and a planted branded-token
   shape (e.g. a GitHub PAT: `ghp_` + 36 chars, ASSEMBLED not literal) in a temp
   `.mpd/state/*.json` file is NOT suppressed (its curated `github-token` finding
   survives the filter).
4. Scope: `.mpd/secret-allowlist.json` only.

## Verdict
PASS — a security-strengthening config narrow; ready for Security.
