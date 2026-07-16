# Proportional MPD process governance

## Purpose

MPD now gives every change a durable risk level and credible threat boundary.
It also requires an explicit reconciliation decision before review attempts
continue beyond the selected risk level's allowance. Ordered gates remain
mandatory, but the expected rigor and reasons for blocking are now visible.

## Value

Builders and reviewers see the same governance contract in `begin`, `status`,
`next`, and JSON output. Classified failures distinguish product defects from
test, infrastructure, environment, and policy failures. Security blockers must
state a credible exploit path. Attempt telemetry and advisory artifact budgets
make review churn visible without collecting prompts, command output, source
content, environment variables, or secrets.

## Scope

Existing MPD capabilities remain intact: ordered phase enforcement, durable
gate history, conditional-pass resolution, deterministic checks, archive
blocking, and persona/model-aware briefs.

This bounded v1 adds typed risk and threat declarations, classified FAIL
events, structured Security exploitability fields, attempt timestamps,
advisory artifact guidance, and one-shot reconciliation. Governance changes
retain history and invalidate Security plan and downstream approvals.

This release deliberately does **not** cache or reuse evidence, enforce
change-to-commit or staged-file manifests, publish changes, attest local/remote
Git parity, or make the local ledger tamper-proof. Those capabilities require
separate lifecycle and provenance designs and remain deferred.

## Functional details

Unless project configuration or CLI flags override them, new non-UI changes
default to `low` risk, UI changes default to `medium` risk, and the threat
profile defaults to `local-trusted-user`. Available threat profiles are
`local-trusted-user`, `local-untrusted-input`, `network-client`,
`network-server`, `credential-bearing`, and `high-assurance`. Legacy ledgers
load as `medium`/`local-trusted-user` without invalidating history.

A FAIL requires exactly one class: `product`, `test`, `infrastructure`,
`environment`, or `policy`. A Security-plan or Security-code FAIL additionally
requires nonblank attacker, capability, boundary, harm, and exact-fix fields.
FAIL-only fields are rejected with PASS or CONDITIONAL PASS, and Security-only
fields are rejected for other phases before checks or ledger writes.

Low, medium, and high risk permit one, two, and three attempts per phase before
reconciliation is required. `mpd reconcile` authorizes exactly the next attempt
for the current phase; it never erases or converts a FAIL. Changing risk or
threat profile preserves history, invalidates Security-plan-and-downstream
latest verdicts, and rewinds to Security plan while keeping Design and
Architecture intact.

Low- and medium-risk canonical artifacts receive approximate two- and
eight-page guidance; high risk has no page warning. These warnings are
advisory, use capped reads of `proposal.md`, `design.md`, and `tasks.md`, and do
not fail a gate. Superseded drafts belong under the change's `history/`
directory. Human terminal output strips control characters; JSON remains
normally escaped structured data.

## Usage

Start an explicitly governed change:

```bash
mpd begin add-server --risk high --threat-profile network-server
mpd status
mpd next --harness codex
```

Inspect the same governance and attempt state programmatically:

```bash
mpd status --json
mpd next --harness codex --json
```

Record an environmental failure:

```bash
mpd gate test --fail --class environment --evidence test-host-unavailable
```

Record a blocking Security finding with a complete exploitability case:

```bash
mpd gate security-code --fail --class product \
  --attacker "untrusted network client" \
  --capability "can submit a crafted request" \
  --boundary "request parser to command runner" \
  --harm "executes an unintended local command" \
  --fix "pass parsed arguments directly without a shell"
```

When the attempt allowance is exhausted, authorize only the next review:

```bash
mpd reconcile --continue "implementation corrected; rerun the same gate"
```

To change the governing boundary, provide the new value and a reason. This
rewinds the change to Security plan:

```bash
mpd reconcile --threat-profile network-server \
  "the feature now accepts remote requests"
```
