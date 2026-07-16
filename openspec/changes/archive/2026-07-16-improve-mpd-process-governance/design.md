# Design: proportional MPD process governance

## Context and existing capability audit

Commando already has more of the retrospective recommendations than the
Elysium workflow exposed:

| Recommendation | Existing implementation | This release |
|---|---|---|
| Ordered adversarial gates | `phase.rs` fixes order and applicability | Preserve |
| Durable audit history | `Ledger.history` preserves FAIL -> PASS | Preserve; enrich events |
| Conditions | Conditional PASS conditions block archive | Preserve |
| Machine evidence | Build/Test rerun tests; Security scans; Deploy can execute | Preserve |
| Complete artifacts | status/archive reject template stubs | Preserve |
| Persona/model visibility | `next` resolves harness/persona/model | Add governance context |
| Risk/threat profile | Only implicit directives and `--ui`/kind | Implement |
| Exploitability threshold | Security prose only | Implement structurally |
| Failure classification | FAIL is undifferentiated | Implement |
| Process telemetry | Date, actor, evidence, command/count summaries | Add timestamps/attempts |
| Ceremony circuit breaker | None | Implement attempt budget + reconciliation |
| Evidence caching | Evidence is not input-bound | Defer; never claim reuse |
| Commit/change manifest | Staged secret scan only | Defer |
| Publish parity | Deploy exists; archive mutates tracked files afterward | Defer pending lifecycle redesign |

The product problem is therefore not missing gates. It is missing context and a
missing decision point when review effort becomes disproportionate.

## Goals

- Make risk and credible attacker boundaries durable and visible.
- Make blocking Security findings explain an exploitable path.
- Separate product failures from test/infrastructure/environment/policy failures.
- Capture enough metadata to measure repeated attempts without recording raw
  prompts, output, source contents, credentials, or environment variables.
- Warn on artifact growth and require human-owned reconciliation after repeated
  attempts, without weakening any gate.
- Preserve old ledgers and familiar command forms.

## Non-goals

- Automatically decide whether a vulnerability is real.
- Cache or automatically reuse gate PASS results.
- Infer code dependencies or police staged-file ownership.
- Commit, push, deploy, or attest Git remote parity.
- Add a new phase or remove an existing one.
- Treat approximate page counts as correctness requirements.

## Decisions

### 1. Governance is typed ledger state with conservative defaults

Add to `ledger.rs`:

```rust
enum RiskLevel { Low, Medium, High }
enum ThreatProfile {
    LocalTrustedUser, LocalUntrustedInput, NetworkClient,
    NetworkServer, CredentialBearing, HighAssurance,
}
struct Governance {
    risk: RiskLevel,
    threat_profile: ThreatProfile,
    reconciliations: Vec<Reconciliation>,
}
```

All use kebab-case serde and `FromStr`/display helpers. `Ledger.governance` has
`#[serde(default)]`. The legacy default is `medium` +
`local-trusted-user`: conservative enough not to silently downgrade an existing
change, but appropriate for the tool's normal local developer context.

`mpd begin` adds optional `--risk <level>` and `--threat-profile <profile>`.
When absent, UI changes infer medium risk; other changes infer low risk. Both
resolved values are printed. Explicit values are stored; JSON never forces a
caller to infer them from `--ui`.

Config gains optional `governance` defaults, but CLI values win. Invalid values
fail before creating the change directory. `scaffold::begin` accepts a
`Governance` value rather than independently inferring policy.

### 2. Briefs carry one compact governance contract

`harness::NextBrief` gains `risk`, `threat_profile`, `attempt`,
`attempt_limit`, and `reconciliation_required`. `cmd_next` derives these from
the ledger and prepends them to generic, Claude, Codex, and JSON output.

Security briefs additionally state:

> A blocking FAIL must identify attacker, prerequisite capability, crossed
> boundary, concrete harm, and exact fix. Out-of-profile hardening is advisory
> unless it demonstrates a path into the declared profile.

This is judgment guidance, not keyword-based vulnerability scoring.

### 3. FAIL events are classified; Security FAIL is structured

Add:

```rust
enum FailureClass { Product, Test, Infrastructure, Environment, Policy }
struct Exploitability {
    attacker: String,
    capability: String,
    boundary: String,
    harm: String,
    fix: String,
}
```

`GateRecord` gains optional `failure_class`, `exploitability`, `attempt`,
`started_at_epoch_secs`, and `completed_at_epoch_secs`, all serde-defaulted.
For new FAIL records `--class` is required. For Security plan/code FAIL,
`--attacker`, `--capability`, `--boundary`, `--harm`, and `--fix` are also
required and must be nonblank with bounded lengths. Other phases reject those
Security-specific fields to avoid misleading records. PASS and CONDITIONAL PASS
reject `--class` and exploitability fields.

Attempt is computed as one plus prior history events for that phase. Completion
uses `SystemTime::now()` seconds since Unix epoch. `started_at` is the prior
`next` timestamp when available; otherwise it equals completion. To support
that, `Ledger` stores `phase_started_at_epoch_secs` and updates it whenever
advancement changes the current phase. Wall-clock anomalies clamp duration to
zero rather than underflowing.

Human status shows classification on FAIL history and a concise attempt/duration
summary. JSON emits the complete typed fields. Existing `at: YYYY-MM-DD` remains
for compatibility and readability.

### 4. Budgets warn first and block only further review expansion

Risk defaults:

| Risk | Artifact guidance | Attempts per phase before reconciliation |
|---|---:|---:|
| Low | about 2 pages | 1 |
| Medium | about 8 pages | 2 |
| High | no page warning | 3 |

Approximate pages are `ceil(non-whitespace words / 500)` across canonical
`proposal.md`, `design.md`, and `tasks.md`. This is visibly labeled guidance.
Crossing it emits a warning in status/next but never fails a gate.

An additional gate attempt beyond the risk limit requires an unconsumed
reconciliation authorization. This applies after any recorded verdict; it is
not a retry shortcut. A FAIL remains FAIL until the phase is genuinely rerun
and receives an advancing verdict.

Add command:

```text
mpd reconcile --continue "reason" [--change N]
mpd reconcile --narrow "scope removed" [--change N]
mpd reconcile --risk <level> "reason" [--change N]
mpd reconcile --threat-profile <profile> "reason" [--change N]
```

This extends the existing `resolve` command; it does not overload it. A
`Reconciliation` records kind, reason, prior/new governance value where applicable,
timestamp, phase, and the next authorized attempt number. Reasons are nonblank,
bounded text. Each reconciliation is consumed only by that phase's next gate
record. Changing risk or threat profile invalidates current and downstream latest
verdicts from Security plan onward and rewinds the phase to Security plan;
history is retained. Both changes alter the boundary Security approved and use
the same invalidation rule.

The CLI cannot reliably observe a human rejecting the same sentence twice.
Attempt count is therefore the honest machine-observable proxy. Directives tell
the harness to call reconciliation immediately when the human rejects a
criterion, rather than manufacturing more review prose.

### 5. Artifact history is a convention, not an automatic rewrite

Templates and directives state that proposal/design/tasks are canonical current
state and superseded drafts belong in `history/`. Commando only warns on size;
it does not rewrite user-authored Markdown. This avoids data loss and keeps the
OpenSpec format compatible.

`openspec-core::Project` archive already moves the whole change directory, so a
`history/` subtree remains durable without special merge behavior.

### 6. Publication and evidence reuse remain explicit follow-up work

The current lifecycle gates Deploy, then archives by changing tracked specs/docs.
A Publish PASS recorded before archive would not cover the archived commit; a
PASS recorded after push would dirty the tracked ledger and immediately require
another commit. This release must not claim remote closure.

A future lifecycle change should make archive preparation precede an immutable
commit, then verify the exact remote commit without mutating tracked proof (or
use a CI-signed receipt). Likewise evidence reuse requires content digests,
toolchain/config bindings, and dependency invalidation; this release records
better telemetry but never skips deterministic checks.

## API and file plan

1. `crates/mpd/src/ledger.rs`
   - Add governance/failure/exploitability/reconciliation types and serde-safe
     defaults.
   - Enrich `GateRecord` and `Ledger`; add attempt/budget helpers,
     reconciliation consumption, and risk-change invalidation.
2. `crates/mpd/src/config.rs`
   - Add optional governance defaults; preserve old config loading.
3. `crates/mpd/src/scaffold.rs`
   - Accept resolved governance in `begin`; seed timestamps.
4. `crates/mpd/src/cli.rs`
   - Add begin flags, FAIL evidence flags, and `Reconcile` command.
   - Validate flag combinations before checks or writes.
   - Add compact status/JSON governance, budget, attempt, and failure output.
5. `crates/mpd/src/harness.rs` and `personas.rs`
   - Extend `NextBrief`; render the same governance contract for all harnesses.
6. `crates/mpd/assets/directives/**`, `.mpd/directives/**`
   - Keep bundled and dogfood copies synchronized; document exploitability and
     reconciliation rules.
7. Templates/schema copies under `crates/mpd/assets/` and `openspec/schemas/`
   - Describe canonical artifacts and `history/` convention.
8. `crates/mpd/tests/e2e.rs` plus module tests
   - Cover compatibility, parsing, validation, attempts, reconciliation,
     invalidation, output parity, and bounded inputs.
9. `README.md` and `documentation.md`
   - Explain commands, defaults, threat boundaries, and deferred capabilities
     without claiming remote publication or evidence caching.

## Risks and trade-offs

- **More CLI fields:** only FAIL and advanced reconciliation paths gain required
  flags; ordinary begin/PASS remains terse.
- **Legacy default may differ from original intent:** status labels it as a
  default, and no existing verdict is invalidated on load.
- **Attempt budget can feel blocking:** it blocks only another review attempt,
  requires a reason, and never blocks inspection/status.
- **Security fields can become checkbox prose:** separated Security judgment is
  still required; structure makes reasoning auditable but cannot guarantee it.
- **Timestamps are wall-clock data:** they support rough retrospectives, not
  billing or cryptographic ordering.
- **Risk downgrade could evade rigor:** `--risk` reconciliation invalidates
  Security and is permanently visible; Security must reassess the declared
  boundary before Build.

## Migration plan

1. Add serde-defaulted fields and verify old fixture ledgers/configs load.
2. Add new CLI paths without changing existing successful commands.
3. Update both bundled assets and this repo's installed copies together.
4. Run formatting, clippy, the workspace suite, release build, and dogfood a
   temporary low-risk and medium-risk change.
5. Install the release binary through the project's established local install
   workflow and verify `mpd --version`, help, begin/status/next, and a bounded
   reconciliation flow from the installed executable.

Rollback is a normal revert. New JSON fields are additive; older binaries will
ignore them when deserializing only if their serde models permit unknown fields
(current structs do), while new binaries continue reading old ledgers.

## Conditions for Builder

1. Existing ledgers/configs and existing `begin`, PASS, CONDITIONAL PASS,
   `status`, `next`, and archive workflows MUST remain compatible.
2. All enums and new ledger fields MUST use bounded parsing and serde defaults;
   no untrusted value may become a path or shell fragment.
3. A new FAIL MUST have exactly one failure class. Security FAIL additionally
   MUST have all five nonblank exploitability fields; invalid combinations fail
   before deterministic checks or ledger writes.
4. MPD MUST NOT infer exploitability from keywords or automatically downgrade a
   Security FAIL. Out-of-profile advice remains a reviewer judgment represented
   by evidence/conditions.
5. Attempt count MUST derive from append-only history. Reconciliation authorizes
   exactly one named next attempt and MUST NOT advance, erase, or convert a FAIL.
6. Risk- or threat-profile reconciliation MUST retain history, invalidate
   Security plan and all downstream latest verdicts, and rewind to Security
   plan. It MUST NOT invalidate Design/Architecture records.
7. Artifact page counts are approximate warnings only. High risk has no page
   warning. Reads MUST use the existing symlink-refusing, size-capped helper.
8. Human and JSON outputs MUST agree on risk, threat profile, attempts,
   reconciliation state, and failure class. Output MUST not include raw command
   output, prompts, source content, environment variables, or secrets.
9. Timestamp arithmetic MUST not panic or underflow when clocks move backward.
10. Bundled assets, installed dogfood directives, and OpenSpec template copies
    MUST remain synchronized and receive regression coverage where practical.
11. This release MUST NOT claim content-addressed evidence reuse, commit-scope
    enforcement, automatic publication, or remote-parity verification.
12. Required verification: `cargo fmt --check`,
    `cargo clippy --workspace --all-targets -- -D warnings`,
    `cargo test --workspace`, `cargo build --release -p mpd`, plus installed
    binary smoke tests covering the new command surface.
