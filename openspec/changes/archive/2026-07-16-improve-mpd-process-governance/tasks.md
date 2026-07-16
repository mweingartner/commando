# Tasks: proportional MPD process governance

## 1. Typed governance state

- [x] 1.1 Add risk level, threat profile, governance, failure class,
  exploitability, reconciliation, attempt, and timestamp models with serde
  defaults and bounded parsers.
- [x] 1.2 Add legacy-ledger/config round-trip tests and attempt/budget helpers.
- [x] 1.3 Add risk/threat-profile invalidation and one-attempt reconciliation
  consumption tests.

## 2. CLI and briefs

- [x] 2.1 Add `begin --risk/--threat-profile` with visible inferred defaults.
- [x] 2.2 Add classified FAIL and Security exploitability flags with strict
  combination validation.
- [x] 2.3 Add
  `mpd reconcile --continue|--narrow|--risk|--threat-profile` and enforce the
  risk-specific attempt threshold.
- [x] 2.4 Surface governance, budget, attempts, reconciliation, classification,
  and timestamps consistently in status/next human and JSON output.

## 3. Doctrine and artifacts

- [x] 3.1 Update protocol/persona directives for declared threat boundaries,
  credible blocking findings, canonical artifacts, and reconciliation.
- [x] 3.2 Keep bundled and project directive/template copies synchronized.
- [x] 3.3 Update README and durable documentation without claiming deferred
  publication, manifest, or evidence-cache features.

## 4. Adversarial and compatibility tests

- [x] 4.1 Unit-test enum parsing, bounded text, defaults, attempt accounting,
  timestamp safety, and invalidation.
- [x] 4.2 E2E-test old command compatibility, begin defaults/overrides, all FAIL
  classes, incomplete Security FAIL rejection, and out-of-order flag rejection.
- [x] 4.3 E2E-test budget warning, blocked excess attempt, one-shot
  reconciliation, history preservation, and JSON/human parity.

## 5. Verification and delivery

- [x] 5.1 Run `cargo fmt --check` and Clippy with warnings denied.
- [x] 5.2 Run the full workspace suite and release build; report actual counts and
  exit codes.
- [x] 5.3 Install the release binary with the established local workflow and
  smoke-test version/help/begin/status/next/reconcile from the installed target.
- [x] 5.4 Complete downstream MPD gates, archive the change, commit only the
  logical change, push `main`, and verify local/remote commit parity.
