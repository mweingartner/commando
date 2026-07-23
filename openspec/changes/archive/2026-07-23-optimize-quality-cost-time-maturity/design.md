# Design: Quality-adjusted cost and time maturity

## Context

MPD already has additive/defaulted `Config`, `GateRecord`, and `Ledger` schemas;
brief-time model resolution in `NextBrief`; per-change aggregation in `ChangeStats`;
content-bound phase receipts in `closure`; and exact-subject validation receipts in
`local_validation`. This change extends those seams. It does not replace gate verdicts,
Candidate/Commit identities, local validation authority, or the phase order.

The seven outcomes are coupled only through typed evidence: usage and provenance feed
budgets/stats; check dispositions feed validation summaries; benchmark evidence may
change reviewed model mappings; operational recovery remains read-only or preview-first.
All external evidence is untrusted structured input. MPD remains a local evidence kernel,
not a model runner, pricing oracle, or proof of semantic insight.

## Goals / Non-Goals

Goals are to measure known quality/cost/time facts with coverage, enforce bounded new
model work, reduce demonstrably redundant checks, adopt a safe docs lane, benchmark
routing, authenticate review/session provenance when configured, and repair four
operator recovery defects. Human and JSON output must share typed states.

Non-goals are online provider calls, prompt/source capture, secret-key custody, automatic
claims of global optimality, weakening Security(code), treating telemetry as a verdict,
changing Git transport, or expanding the certified sandbox/host boundary.

## Decisions

### D1. Add strict, opt-in governance schemas; preserve legacy reads

`config.rs` adds `GovernanceEconomicsConfig` beneath `Config::governance` with per-risk
`BudgetLimits`, `AntiStallPolicy`, and `AttestationPolicy`; and `RoutingPolicy` beneath a
new optional `Config::routing`. All structs use `deny_unknown_fields`, integer units,
bounded collections/strings, and validation methods. Soft is positive and `<= hard`;
limits have explicit caps. Issuer entries contain public verification material or its
reviewed locator/digest, never private keys. A locator is either embedded reviewed public
material or a canonical path beneath a fixed clone-private trust-root; it is opened
no-follow, byte-capped, and rehashed against the activated-policy digest before use.
Arbitrary, ambient, network, candidate-controlled, or symlinked key paths are refused.
Absence means NOT CONFIGURED/NOT REQUIRED, not unlimited or zero. Existing configs and
ledgers deserialize unchanged.

The sole authenticated-attestation algorithm is `sshsig-ed25519-v1`, verified offline by
the tool-lock-bound absolute `/usr/bin/ssh-keygen -Y verify` executable. Its exact
SHA-256, accepted platform/ABI, and allowed typed argv are reviewed in
`security/tool-lock.json`; ambient PATH, dynamic crypto libraries, algorithm agility, and
owner-generated production keys are forbidden. The signed input is a fixed-field,
length-delimited canonical byte encoding of `AttestationPayloadV1` (all bound fields and
counters); JSON is only a strict transport envelope, never the signed serialization.
Issuer keys use one canonical comment-free OpenSSH `ssh-ed25519` encoding, keyed by an
exact bounded issuer/key identity. MPD materializes the message, exact allowed-signers
line, and submitted SSHSIG envelope only under its private per-run root, invokes the
locked argv with the fixed `mpd-attestation-v1` namespace and exact identity, caps/cleans
all effects, and accepts only a successful verifier exit. The current clone already has
`/usr/bin/ssh-keygen` available (SHA-256
`4ed0e089766a35cb8acbaf6e2804e9ec5b187f1baabce5dc832f5a192cb3d7cd`); lock/digest drift
is a BLOCKED Build/verification condition, never a fallback to ad-hoc cryptography.

Commando's reviewed `.mpd/config.json` enables the policies, adds docs profile gate names,
and changes the Codex `Documenter` assignment from unavailable `luna` to the
user-authorized `terra` route. Candidate policy changes retain existing sensitive-path
High classification and trusted-policy activation requirements.

### D2. Bind usage and provenance to one exact gate attempt

Add `attestation.rs` with bounded `UsageEvidenceV1`, `ReviewAttestationV1`, normalized
`UsageRecord`, `ProvenanceRecord`, parse/verify/binding functions, and stable state enums.
It also exposes an additive typed `AttestationVerifierState` shared by human and JSON
reporting: `LOCKED`, `BLOCKED` with one bounded code
(`attestation.verifier-drift`, `attestation.verifier-unavailable`, or
`attestation.trust-root-mismatch`), `INVALID` with one bounded code
(`attestation.namespace`, `attestation.signature`, or `attestation.key`), and `REPLAYED`
(`attestation.replay-consumed`). These states name evidence/verifier refusal, never a
judgment about the underlying review. Each refusal blocks a required-authentication gate
before objective validation; only a completed tool-lock verification can render `LOCKED`.
The signed payload binds schema, issuer/key, change, phase, attempt, actor, harness,
resolved provider/model, opaque session ID, issued time, artifact digest, exact Candidate
or planning-subject digest, and review-subject/session identity. Usage uses non-negative
integers for input/output/cached tokens, active milliseconds, currency, and micro-units.
Duplicate keys, floats, overflow, stale issue time, oversized input, replay, and any
cross-binding fail before objective validation when policy requires attestation. A valid
attestation digest is claimed under the ledger lock before objective execution and is
consumed for that exact attempt even when the later objective result fails; the durable
claim covers the full history rather than just the latest gate map, so concurrent or
repeated gate invocations cannot reuse it. A malformed, rejected, or never-claimed input
does not mutate the ledger.

`GateRecord` gains defaulted optional `usage` and `provenance`; `Ledger` gains a bounded
append-only `brief_expectations` record sufficient to validate phase/attempt/model and
one-use continuation authorization. `mpd gate --attestation <file>` reads once through
contained, no-follow, capped input and stores only normalized fields/digests. Cooperative
mode with no evidence records COOPERATIVE/UNREPORTED. An explicitly supplied, exact-bound
but unsigned or issuer-untrusted usage envelope may record REPORTED usage only when policy
permits cooperative evidence; it never upgrades provenance or independence. Any supplied
malformed or cross-bound envelope is INVALID and refuses the gate even in optional mode;
omission, not invalid evidence, is the compatibility fallback. Actor labels never satisfy
authenticated identity.

The repository also defines strict external-issuer conformance fixtures and a verification
protocol, but MPD does not mint a claim about the model/session that is running it. Required
authenticated mode is fail-closed: if an operator activates it, only an actual external
harness issuer (not a fixture key and not a repository-owner self-report) can produce the
valid exact-attempt envelope needed to proceed. This release does **not** activate or claim
that deployment because no such issuer is available. It ships the verifier and explicit
readiness state only: cooperative/optional provenance remains available, required mode
reports `MISSING`/`NOT DEPLOYED`, and fixtures are test evidence rather than production
evidence.

### D3. Budgets block commissioning, not truth observation

Add `economics.rs` pure aggregation and policy evaluation. It saturatingly aggregates
only reported values, groups currencies, and always returns coverage. Wall time derives
from existing attempt timestamps; active time and token/cost derive only from accepted
evidence. `harness::NextBrief` gains typed efficiency/provenance fields and a block reason.
`next` refuses to issue a new persona brief at a hard limit, after two consecutive
infrastructure/environment/policy blockers, or after 30 minutes without advancement.
Only a bounded, typed blocker classification recorded with the gate outcome can advance
the consecutive-blocker counter; unknown, reviewer-text, and ordinary quality failures
do not. The elapsed-time anchor advances only with durable phase advancement. A clock
regression or ambiguous persisted timestamp blocks new-brief issuance until explicit
reconciliation; a monotonic clock is used only within one process and is never persisted
as cross-process proof. Soft limits warn. `status`, `stats`, evidence inspection,
reconciliation, and recording
already completed gate evidence remain available.

Budget evaluation is per metric. A known lower bound that has already reached a hard
limit blocks even when other attempts are UNREPORTED; otherwise incomplete cost/token/
active-time coverage is UNAVAILABLE and cannot be called WITHIN. Independently complete
wall-time evidence remains enforceable. The aggregate state preserves the strongest
blocking metric while rendering coverage for every metric, so missing evidence cannot
either invent headroom or conceal a demonstrated overrun.

One explicit reconciliation creates one bounded continuation token tied to change,
phase, attempt, reason, and current totals. Consumption is atomic and does not reset
totals or clocks. Clock rollback yields UNAVAILABLE/BLOCKED according to operation;
read-only calls never mutate counters. Telemetry never changes PASS/FAIL by itself.

### D4. Reuse is per check and exact-identity closed

Extend `ValidationCheckResult` with a tagged `ValidationDispositionV1`:
`Executed` or `Reused { source_receipt_id, source_check_digest,
source_duration_millis }`. `ValidationReceiptV1` binds the resolved check graph and each
disposition in its ID. Reuse is decided in `local_validation`, not by name alone, and
requires equality of subject, check definition, trusted/effective policy, tool digest,
certified platform/adapter/canaries, declared inputs/environment, result policy, and
coordinator identity. The source must be a current passing executed result; reuse chains
flatten. Mismatch executes or blocks per existing policy, never silently reuses.

Security(code) remains a fresh gate and its security-specific checks always execute.
Outgoing secret scanning and Commit/pre-push exact-subject rules remain fresh. Closure's
phase-level evidence reuse remains compatible and delegates objective check disposition
to the receipt. Status labels summed source receipt durations as `source-duration
avoided`, not measured savings.

Only current-change, current-subject accepted receipts are searched as reuse sources;
there is no ambient cross-change/global receipt cache. Identity compares the canonical
declared environment and isolation policy, including every result-affecting value, while
ephemeral private-root allocation names are normalized only when the check contract proves
they are non-input implementation details. Receipt dispositions remain Executed/Reused;
the shared validation-plan projection separately represents BLOCKED and NOT RUN checks,
so all four visible states are typed without creating receipts for work that did not run.

### D5. Docs lane is an explicit profile selection, not a bypass

Extend `GateProfiles` with optional docs Build/Security(code)/Test mappings and add a
pure selector returning profile plus reason code. Eligibility requires requested Low,
effective Low, documentation-only classifier truth, no config/policy/code scope, and a
configured profile satisfying a fixed floor: doc staleness/referential checks, process
prose secret scan, and phase-specific minimums. Broken configured floors block rather
than silently substituting. All phases still run.

Commando adds `docs-build`, `docs-security-code`, and `docs-test` profiles. A real
trusted-policy sandbox e2e must conduct a docs-only change through all three and assert
profile/check/receipt identity; negative cases prove code/config/Medium/High cannot enter.
The docs Build profile still executes the typed release build so the existing
Build-to-Deploy artifact invariant remains intact; release-build and secret-scan checks
are never reusable. Only semantically stable adapter identity (adapter kind plus reviewed
bytes), not per-run materialization paths, participates in reuse identity.
Complete absence of the optional docs mapping selects the existing full lane with an
explicit `docs-lane-not-configured` reason. A partial mapping or any configured profile
that misses its fixed floor is malformed reviewed policy and blocks; it never falls back.

### D6. Routing evaluation is offline, deterministic, and preview-first

Add `routing.rs` with capped/strict `RoutingEvidenceV1`, suite/rubric/price/model identity,
seeded blind sample results, metric aggregation, freshness evaluation, dominance, and
deterministic recommendation. Required metrics are quality, escaped defects, rework,
latency, tokens, and currency-specific cost. Missing/unblinded/undersampled/stale/mixed-
currency evidence is insufficient and cannot apply. Ties use stable role/model ordering;
recommendations are Pareto-eligible, never called globally optimal.

`mpd routing evaluate --evidence` is read-only. `routing apply` previews the exact role
map/evidence digest; only `--yes` writes through a guarded atomic config writer after
revalidation and concurrent-file-digest check. The writable target set is derived from a
reviewed allowlist of existing harness/persona model entries, not from evidence labels;
the validated preview must be a subset of that set and the writer rejects additions,
deletions, cross-harness entries, or any non-routing config delta. This policy edit
intentionally invalidates affected freshness and requires normal review/activation.

The evaluator fixture is not adoption evidence. A versioned `routing-v1` task manifest
and blind rubric must be executed by actual external harness sessions for every configured
route under comparison after this change: Codex Sol and Codex Terra, including Terra in
the user-authorized Documenter assignment. Scoring remains blind until results are
committed to the evidence envelope. If those sessions cannot produce sufficient evidence,
deployment records `MISSING`/`INSUFFICIENT` without changing routing; it must not fabricate
Luna samples or treat unit fixtures as a benchmark. A missing callable route or absent
trusted usage/session data cannot be replaced with synthetic evidence.

### D7. Share one typed reporting projection

Add `EfficiencyReport` builders consumed by `next`, gate summaries, `cmd_status`, and
`stats`. `ChangeStats` and `AggregateStats` gain additive usage coverage, currencies,
provenance, validation dispositions, budget events, and routing state. Unreadable ledgers
remain rows. Human rendering uses `terminal_safe` and bounds; JSON contains full bounded
IDs and integer values. Unknown values are excluded and labeled UNREPORTED/UNAVAILABLE;
zero appears only when evidence explicitly reports zero. The report also projects the
typed attestation-verifier `LOCKED`/`BLOCKED`/`INVALID`/`REPLAYED` state and bounded
refusal code without reflecting untrusted verifier output. Existing top-level workflow
truth remains first and unchanged.

### D8. Repair operational diagnosis without broad mutation

Replace `githooks::is_installed() -> bool` internally with `inspect_installation() ->
HookInstallation`, retaining the boolean wrapper for callers. Activated trusted wrappers
are healthy only when activation/coordinator/policy identity checks already implemented
by local validation succeed; manual marker hooks remain distinguishable. Doctor human and
JSON output derive from this typed result and retain a compatibility boolean.

Refactor status selection before active manifest loading into `CurrentSelection`:
None, Active, ArchivedCurrent, PendingArchive, AwaitingCommit, Closed, Invalid. Archived
status reads bounded archive metadata and remains read-only; `next`/`gate` stay blocked.
It never rewrites `.mpd/current` or manufactures Candidate truth.

Add a bounded doctrine manifest/checker to `scripts/check-doc-staleness.sh`'s Rust-backed
or existing shell entry point: direct `Status: SUPERSEDED` / `Superseded by:` banners,
canonical current targets, no chains/cycles/dangling targets, and an explicit finite set
of doctrine keys for known contradictions. This is not general semantic NLP.

Add `cache.rs` with `inspect` and preview/`--yes` prune. Enumeration is restricted to
clone-private MPD candidate roots and identity sidecars. Live ledger, pending archive,
Build output, current receipt, and archived-ledger references are retained. Effects use
descriptor-relative, no-follow operations anchored in the opened fixed cache parent: after
complete reference and identity checks, atomically rename the verified entry into a
same-parent private quarantine, revalidate its inode/sidecar there, then delete only the
detached object through anchored descriptor-relative operations. Any rename, ownership,
replacement, reference, or cleanup ambiguity is BLOCKED and retained. Prune never touches
receipts, logs, policy, tools, source, Git objects, or installed/build output. Archive close
may invoke the same helper, but cleanup truth is reported separately and cannot rewrite
archive truth.

## Exact File / API Plan

- `config.rs`: additive governance/routing/docs-gate schemas, validation, round-trip and
  malformed-policy tests.
- `attestation.rs` (new): strict evidence parser, canonical `sshsig-ed25519-v1` payload
  encoder using the tool-lock-bound `/usr/bin/ssh-keygen -Y verify` verifier,
  signature/issuer verification, exact-binding,
  normalized records, explicit required-mode `NOT DEPLOYED` readiness,
  and external-issuer conformance fixtures;
  property/adversarial tests.
- `security/tool-lock.json` (new): reviewed absolute verifier path, SHA-256, accepted
  platform/ABI, and exact typed `ssh-keygen -Y verify` argv contract used by attestation
  verification; lock drift is a fail-closed Build/verification condition.
- `economics.rs` (new): aggregation, budget/anti-stall/continuation state machine.
- `ledger.rs`: defaulted usage/provenance/brief-expectation/continuation fields and
  compatibility fixtures.
- `harness.rs`: extend `NextBrief`, routing-evidence projection, budget blocker rendering.
- `cli.rs`: `--attestation`; typed status/doctor; routing/cache commands; archived-current
  selection; shared human/JSON rendering.
- `stats.rs`: additive coverage-aware economics/provenance/reuse aggregates.
- `local_validation.rs`: check disposition, exact check-reuse matcher, docs selector/floor,
  receipt ID binding and sandbox e2e support.
- `closure.rs`: preserve phase reuse and expose source-check disposition without relaxing
  Security(code), Commit, or pre-push freshness.
- `routing.rs` and `cache.rs` (new): isolated bounded evaluators/effect executors.
- `benchmarks/routing-v1/**`: versioned task manifest, blind rubric, scoring schema, and
  operator instructions; no model output, source content, credentials, or private key.
- `githooks.rs`: typed installation inspection with compatibility wrapper.
- `.mpd/config.json`, docs and checker: enable reviewed policies, docs profiles, the
  user-authorized Codex Documenter `terra` assignment, supersession relation, and
  operator documentation.
- Unit/property/golden/e2e tests remain beside modules plus `crates/mpd/tests/e2e.rs`.

## Dependency Order

1. Land schemas/state enums and backward-compatibility fixtures.
2. Implement strict attestation parsing/binding and economics aggregation.
3. Wire ledger/gate/brief budgets and shared reporting.
4. Implement check dispositions/reuse, then docs selector/floor and sandbox e2e.
5. Implement routing evaluator before its guarded writer.
6. Implement typed hook/current selection, doctrine checker, then cache preview/effects.
7. Enable Commando config/docs (with cooperative provenance only), execute the blind
   Sol/Terra routing benchmark or preserve its `MISSING`/`INSUFFICIENT` result, run full
   verification, install exact Build output, and perform post-install identity/parity
   checks. Required authenticated provenance remains `NOT DEPLOYED` until independently
   activated with real external-issuer evidence.

Each vertical slice compiles and focused-tests before dependent CLI wiring. Any material
schema/trust-boundary correction returns to Security(plan); semantic UI changes return to
Design Review.

## Alternatives Considered

- Provider API ingestion was rejected because it adds network, credential, availability,
  pricing-freshness, and billing-oracle trust to an otherwise local gate. Harness-issued,
  offline evidence preserves the boundary and makes missing coverage explicit.
- Phase-level-only reuse was retained for prose freshness but rejected as the economics
  primitive: it cannot identify which expensive checks were actually avoided. Check-level
  disposition supplies that fact without weakening the phase verdict.
- Automatically selecting a full profile when a docs profile is malformed was rejected
  because it hides reviewed-policy drift. A configured broken floor is a policy blocker;
  honest ineligibility selects the normal lane.
- Automatically applying the cheapest benchmark winner was rejected because cost alone
  does not preserve quality and blind evidence may be insufficient. Deterministic Pareto
  eligibility plus explicit preview preserves operator judgment.
- Marker-based hook repair and recursive cache deletion were rejected because neither
  establishes identity. Existing activation validation and opened-file/sidecar identity
  checks are the correct trust seams.

## Compatibility and Migration

All durable fields are additive/defaulted. Old configs mean policies absent; old usage is
UNREPORTED; old validation results are treated as executed but are not eligible as a
source for new check-level reuse unless every required identity is present. Existing
phase-level receipts remain readable. Human output is additive; JSON schema versions bump
where consumers require typed changes and retain named compatibility fields. There is no
automatic ledger rewrite. Commando opts in through reviewed config activation.

## Risks / Trade-offs

- [Attestation parsing/signature confusion or fixture promotion] -> one canonical format,
  strict schema, bounded single read, activated-policy-bound local trust roots, explicit
  `sshsig-ed25519-v1` strict tool-lock-bound verifier over fixed-field canonical bytes,
  private temporary verifier state, atomic full-history replay consumption, exact binding,
  and a
  non-activating `NOT DEPLOYED` state until real external evidence.
- [Cost data creates false precision] -> integer reported/attested units, currency
  separation, coverage everywhere, no price inference or online fetch.
- [Budget deadlock] -> block only new briefs; retain observation, evidence recording, and
  one explicit bounded continuation without resetting truth.
- [Reuse masks stale checks] -> full identity closure, executed-origin flattening,
  Security(code)/secret/Commit freshness floors, property tests for every mismatch.
- [Docs lane becomes bypass] -> monotonic classifier/risk eligibility and fail-closed
  floors proven through trusted sandbox e2e.
- [Benchmark gaming or write-scope escalation] -> versioned blind rubric/tasks, seeded
  repetitions, minimum sample sizes, deterministic dominance, preview, a reviewed
  existing-entry target allowlist, and no global-optimum language.
- [Hook false positive] -> reuse activation/coordinator trust validation, not wrapper text.
- [Archived status mutation] -> selection is read-only; next/gate keep refusing.
- [Cleanup deletes live data] -> clone-private fixed roots, identity sidecars, complete
  reference set including archived ledgers, descriptor-relative no-follow quarantine,
  post-rename revalidation, and ambiguity retained.
- [Scope/latency] -> seven vertical slices with stable interfaces; no online dependency;
  focused tests before the authoritative full profile.

## Test Strategy

Unit and property tests cover schema bounds, integer overflow, clock movement, hostile
strings/JSON, replay/cross-binding/atomic claim, `sshsig-ed25519-v1` known-answer and
malformed signature/key/encoding/tool-drift/unavailable/refusal-state tests, trust-root substitution, coverage
arithmetic, blocker taxonomy and clock regression, concurrency/idempotency, every reuse
identity mismatch, dominance/ties/mixed currency/routing target scope, selection states,
supersession cycles, and cache identity/rename races. Golden CLI/JSON tests cover every state word, narrow
non-TTY/NO_COLOR output, and output failure. Integration/e2e tests cover required
attestation before objective execution, one-use continuation, the trusted docs lane and
negative eligibility, guarded routing apply, activated hook diagnosis, archived-current
status, and cache preview/prune interruption/retry.

Final evidence is fmt, clippy, full workspace/all-target tests with real count, explicit
ignored release 10k-path/100MB test with one pass, release build, doc checks, and the
authoritative high-risk exact-Commit profile. It includes tests for optional/cooperative,
fail-closed required, `MISSING`, `INSUFFICIENT`, and `NOT DEPLOYED` states, plus actual
blind Sol/Terra benchmark-session coverage when callable. Deployment uses the existing
typed exact-copy Build receipt; post-deploy reopens and verifies installed identity. No
candidate executes.

## Deploy and Rollback

Deploy only after all gates pass: archive, coherent commit, exact Commit validation,
normal hooked push, remote parity observation, then typed install of the tested release
artifact and installed-file identity verification. The activated reviewed policy commit
must match the deployed coordinator. Rollback is a normal revert of the single coherent
change followed by the same full validation, activation, push/parity, and typed install;
legacy ledger/config readability permits the previous binary to read durable state. Never
force-push, bypass hooks, or restore clone-private receipts/caches as source truth.

## Conditions for Builder

1. Treat attestations, benchmark files, ledgers, paths, labels, clocks, and cache sidecars
   as hostile bounded input; use contained/no-follow reads and terminal-safe rendering.
2. Never store private keys, prompts, source content, raw child output, credentials, or
   provider secrets in config, ledgers, receipts, stats, or Git.
3. Bind authenticated usage/provenance to exact change, phase, attempt, actor, model,
   artifact, subject, and review session; load issuer trust only from activated-policy-bound
   no-follow material, then atomically consume exact-attempt attestations before objective
   execution to reject replay and cross-binding.
4. Missing telemetry is UNREPORTED/UNAVAILABLE, never zero; do not mix currencies or infer
   provider prices. Telemetry alone never changes a gate verdict.
5. Soft limits warn. Hard/anti-stall limits block only a new brief. Reconciliation grants
   exactly one atomic bounded continuation and never resets totals, clocks, or history.
6. Check reuse requires equality of every declared subject/check/policy/tool/host/adapter/
   input/environment/result/coordinator identity and a passing executed origin. Flatten
   origins; never infer reuse from names.
7. Security(code) remains freshly invoked and security-specific checks execute. Outgoing
   secret scans and exact Commit/pre-push validation remain fresh and fail closed.
8. Docs profiles require honest docs-only requested/effective Low scope and the fixed
   floor. A wholly absent optional mapping selects the full lane; partial mappings and
   broken configured floors block. The docs Build retains a fresh release build and typed
   artifact for Deploy. Neither case may silently weaken validation.
9. Routing evidence is offline, bounded, blind, sufficiently sampled, deterministic, and
   previewed before an atomic reviewed config write restricted to an existing reviewed
   routing target allowlist. Never claim unproven optimality.
10. Preserve existing phase order, Candidate/Commit separation, trusted policy activation,
    certified host/sandbox constraints, normal Git transport, and typed install boundary.
11. Doctor must validate activated wrapper identity, not marker text. Archived status is
    read-only and cannot create active manifest/Candidate truth; `next` and `gate` refuse it.
12. Supersession checking is finite and explicit, rejects chains/cycles/dangling targets,
    and never claims general natural-language semantic verification.
13. Cache effects are confined to identity-verified clone-private orphan candidates after
    complete reference checks (including archived ledgers), descriptor-relative no-follow
    quarantine, and post-rename revalidation. Ambiguity retains data and BLOCKS; never
    delete receipts, logs, policy, tools, Git/source, Build, or installed output.
14. All durable fields are additive/defaulted; legacy evidence cannot be silently upgraded
    to authenticated/current/reusable evidence. Preserve schema compatibility fixtures.
15. Preview/read-only commands perform no writes. Mutations are atomic, concurrency checked,
    idempotently retryable, and print PASS only after durable verification.
16. Compile and focused-test each dependency-ordered slice; then run every required full,
    performance, doc, exact-Commit, push/parity, and installed-identity check with real counts.
17. Ship the external-issuer verifier and fail-closed required-mode readiness, but do not
    activate required authenticated provenance using a fixture or owner-self-signed claim.
    Until a real harness-issued exact-session attestation exists, provenance remains
    cooperative/optional and is explicitly `NOT DEPLOYED`.
18. Change Codex Documenter to the user-authorized Terra route. Do not call evaluator
    fixtures a routing benchmark or fabricate Luna samples: run the versioned blind suite
    across configured Sol and Terra routes, or report routing evidence MISSING/
    INSUFFICIENT and leave model mappings unchanged.

## Actor

Architect-Terra-35

## Verdict

PASS
