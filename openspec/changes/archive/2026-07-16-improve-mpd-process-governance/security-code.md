# Security code review: proportional MPD process governance

## Scope

Reviewed the implementation diff in `cli.rs`, `ledger.rs`, `config.rs`,
`scaffold.rs`, `harness.rs`, directives/templates, and focused end-to-end tests
against the twelve Conditions for Builder and the approved local CLI/repository
threat model.

## Findings

No security findings with a plausible exploit path under the declared model.

The Security-plan LOW hardening note is closed: `harness::terminal_safe` removes
ESC, OSC terminators, C1, and other control characters before the newly rendered
repository-controlled human-history values are printed. JSON remains lossless
and is escaped by `serde_json`. The focused regression test covers ESC/OSC input.

## Conditions verification

1. **Compatibility:** new ledger/config fields are serde-defaulted at their
   additive boundary; legacy ledger and config fixtures deserialize and
   round-trip. Existing terse begin and non-FAIL gate forms remain valid.
2. **Closed and bounded inputs:** risk, threat profile, and failure class are
   closed enums. CLI exploitability and reconciliation text are trimmed,
   nonblank, and capped at 500 Unicode scalar values. None is passed to a path,
   shell, or command runner.
3. **Strict FAIL shape:** verdict, class, Security phase, and all five
   exploitability fields are validated before the ledger is loaded mutably,
   deterministic checks run, or state is written. Invalid combinations return
   without a history event.
4. **No inferred exploitability:** code stores reviewer-supplied structure; it
   performs no keyword scoring or automatic FAIL downgrade.
5. **Attempt integrity:** attempts derive from append-only history. Authorization
   matches phase plus the exact next attempt and is consumed only when that
   matching gate event is recorded. Reconciliation does not alter prior events
   or advance a phase.
6. **Boundary invalidation:** risk/threat changes retain history and remove only
   latest Security-plan-and-downstream verdicts, then rewind to Security plan.
   Design and Architecture gate records remain.
7. **Artifact reads:** page estimates use `openspec_core::read_capped`; limits
   only generate warnings, with no high-risk page cap and no gate mutation.
8. **Output and privacy:** human and JSON surfaces derive from the same typed
   governance/history state. Added telemetry contains summaries and timestamps,
   not raw test output, prompts, source, environment variables, or credentials.
9. **Clock safety:** epoch acquisition defaults safely and duration uses
   saturating subtraction; backward movement cannot panic or underflow.
10. **Synchronized assets:** bundled and dogfood directives are byte-equivalent
    in the diff; bundled and OpenSpec templates carry the same governance/history
    guidance, with regression coverage in the delivery plan.
11. **No overclaim:** code and docs do not implement or claim evidence reuse,
    staged-file ownership, automatic publication, or remote parity.
12. **Required verification:** full formatting, Clippy, workspace, release, and
    installed-binary checks remain assigned to Test/Deploy. Security ran focused
    governance, reconciliation, legacy-config, and terminal-safety tests: 7
    passed, 0 failed across the selected unit/E2E filters.

## Residual trust statement

MPD state is local, editable repository data, not a signed authorization log.
This change correctly does not claim tamper resistance against the same OS user
or a contributor already able to rewrite the repository. Configured test/deploy
commands remain an existing explicit local-project capability and receive none
of the new free-text fields.

## Verdict

**PASS** — the implementation satisfies the approved Security contract. No
credible blocking exploit was found.

## Design Sign-off delta rerun

Reviewed the subsequent status/next rendering change that distinguishes an
unauthorized excess attempt from one carrying an unconsumed reconciliation.

- `attempt_authorization` calls the same phase, exact-next-attempt, unconsumed
  reconciliation predicate used by `attempt_authorized`; presentation does not
  broaden or alter gate authorization.
- Human output renders only the reconciliation kind's closed-enum label and
  numeric attempt/limit. It does not render the repository-stored free-text
  reason, so this delta introduces no terminal-control path.
- JSON emits the same closed-enum label or `null`; `serde_json` performs normal
  escaping and no raw command output or other sensitive value is added.
- The E2E test proves status and next agree in human and JSON output before the
  attempt, and the existing assertion proves the authorization is consumed by
  the matching gate record. The terminal-control regression remains green.
- Focused rerun: 2 tests passed, 0 failed.

**RERUN VERDICT: PASS** — no finding and no change to authorization semantics.

## Tester-remediation delta rerun

Reviewed the attempt-overflow and unreadable/oversized-artifact remediation.

- Attempt increment now uses `saturating_add(1)`. At `usize::MAX` it remains
  unauthorized unless an exact matching authorization exists; it cannot wrap to
  a low attempt number and regain the base allowance.
- Artifact estimation still reads only the three fixed canonical filenames via
  `openspec_core::read_capped`, retaining its symlink refusal and size cap.
  Word accumulation is saturating as additional defense.
- Read failures return typed availability state (`readable: false`, no page
  estimate) and a static diagnostic naming only the fixed canonical filename.
  The underlying OS error, path target, and artifact content are not exposed.
- Human status prints only this generated diagnostic. Next routes it through
  `terminal_safe`; JSON uses `serde_json`. No repository-controlled file content
  enters any warning surface.
- Budget-read failure remains advisory and does not mutate a gate or alter
  attempt/reconciliation authorization semantics.
- Focused rerun: 2 tests passed, 0 failed.

**TESTER-REMEDIATION RERUN VERDICT: PASS** — no plausible exploit path found.
