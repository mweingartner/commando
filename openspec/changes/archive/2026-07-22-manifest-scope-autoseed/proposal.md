# Fail-early manifest process-scope validation

## Why

`mpd manifest` seeds `manifest.json` with empty `paths: []`, and the strict-tier
candidate captures only DECLARED dirty paths. If the author omits the change's
own process-state scope, every gate passes and only `mpd archive` fails — late
and cryptically: omitting `openspec/changes/<change>/**` → "candidate closure
cannot read its retained manifest: no manifest.json for this change"; omitting
`docs/<change>.md` → "reviewed documentation postimage … is not a regular
declared durable-doc path". This cost the scan-secrets-fail-closed change several
full pipeline re-drives (2026-07-22).

## What Changes

- The strict Build gate validates process-scope completeness at the moment scope
  freezes (the candidate capture) and refuses with a copy-pasteable error naming
  the exact `paths` entries to add (`openspec/changes/<change>/**`,
  `docs/<change>.md`). This is the earliest correct point — pre-Build phases
  deliberately tolerate an undeclared scope, and Security(code)/Test reuse the
  Build candidate.
- The two late archive errors gain remediation hints (for pre-fix in-flight
  candidates whose manifest digest is already frozen), and `mpd manifest`'s
  guidance names the required entries.
- Deliberately NOT auto-seeding: a non-empty seed would flip the manifest to
  "ready", destroying the Build-gate "no declared scope" forcing function, the
  `mpd next` INCOMPLETE nudge, and the seed contract — worst case binding
  Security/Test receipts to a candidate silently missing undeclared source edits.
- Correction to the archived-change convention: `.mpd/state/<change>.json` (the
  ledger) does NOT need declaring — it is folded via SystemScope at commit
  regardless, and declaring it needlessly trips the `.mpd/` sensitive-path risk
  signal. The new check does not require it.

## Capabilities

### New Capabilities
None.

### Modified Capabilities
None (no spec requirement changes seed contents or completeness timing; the
existing late-validation guarantee is unaffected — this only surfaces it earlier).

## Impact

- `crates/mpd/src/closure.rs` (new pure `missing_process_scope` predicate + two
  error-hint suffixes), `crates/mpd/src/cli.rs` (Build-gate hook + `cmd_manifest`
  guidance), `crates/mpd/tests/e2e.rs` (one e2e + narrow-manifest fixture
  updates). Read-only check, no gate-latency impact. Because it edits crates/**,
  landing needs a coordinator rebuild + reactivation.
