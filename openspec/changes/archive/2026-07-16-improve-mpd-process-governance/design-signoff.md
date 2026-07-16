# Design Sign-off: proportional MPD process governance

## Runtime inspected

Built the current source with `cargo build -q -p mpd` and exercised
`target/debug/mpd 0.1.0` in disposable Git project
`/tmp/mpd-design-signoff.7zvKL6`.

Commands and observed states:

- `mpd begin governance-default` -> printed inferred `risk low` and
  `local-trusted-user`; current phase Architecture.
- `COLUMNS=50 mpd status` and `mpd next --harness codex` -> governance and
  attempt budget remained text-visible without relying on color.
- `mpd status --json` -> typed governance, artifact budget, attempt limit,
  reconciliation state, gates, and history were present.
- `mpd begin governance-ui --ui --risk high --threat-profile network-server`
  plus `mpd next --json` -> explicit values persisted into the brief.
- `mpd gate security-plan --fail --class product --evidence security.md`
  without exploitability fields -> refused with exit 2 and did not mutate the
  ledger (`attacker must not be blank`).
- The same Security FAIL with attacker/capability/boundary/harm/fix -> recorded
  classified structured evidence.
- A second low-risk attempt without reconciliation -> refused with exit 2 and
  an actionable `mpd reconcile --continue "reason"` command.
- `mpd reconcile --continue ...` -> authorized exactly attempt 2; the retried
  classified FAIL was recorded and both attempts remained in history.
- `mpd reconcile --threat-profile local-untrusted-input ...` -> retained the
  old/new profiles in reconciliation history, removed the stale Security latest
  verdict, preserved Architecture PASS, and rewound/stayed at Security plan.

## Resolved UX finding

The initial build rendered an authorized excess attempt only as:

```text
Governance: risk low, threat profile local-trusted-user
Review attempt: 3/1
```

The corrected build retains that compact ratio and immediately explains it in
both `status` and `next`:

```text
Excess attempt 3 authorized by threat-profile reconciliation (base limit 1).
```

`status --json` reports the same state as `"attempt_authorization":
"threat-profile"`, `current_attempt: 3`, `attempt_limit: 1`, and the matching
unconsumed reconciliation. The prior human/JSON parity failure is closed.

## Verdict

**PASS** — the corrected human status/next presentation names the authorized
exception and base limit, agrees with JSON, remains understandable in a narrow
terminal, and does not weaken the underlying attempt block.

## Tester-remediation delta

Rebuilt current source and replaced the disposable change's `design.md` with a
17 MiB artifact, above the safe read cap. The corrected behavior is consistent:

- narrow-terminal `status` and `next` both print `Warning: canonical artifact
  estimate unavailable: design.md is unreadable or exceeds the safe read limit`;
- neither human surface reports a false zero-page estimate;
- status JSON reports `approx_pages: null`, `readable: false`, and the same
  actionable warning;
- next JSON reports the same text in `artifact_warning`;
- the warning does not silently change a gate or claim the artifact was read.

**Delta verdict: PASS.** The unreadable/oversized state is honest, consistent,
text-only, and usable in the tested narrow terminal. Attempt saturation had no
presentation change and remains covered by the preceding sign-off.
