# Design mock: quality-adjusted cost and time maturity

## Actor

Designer-Terra-34

## Purpose and boundary

This change makes MPD's quality, model cost, and elapsed-time controls observable and
actionable without collapsing them into one misleading "done" or "efficient" claim.
The operator must be able to answer five separate questions from the normal CLI and
from JSON:

1. Was the exact software subject objectively validated, and which checks actually
   executed versus reused equivalent evidence?
2. Who or what attested the semantic review, model, and session, and was that identity
   authenticated or merely self-reported?
3. How many tokens, how much attested model cost, and how much active and wall time did
   the change consume? Missing telemetry must read `UNREPORTED`, never zero.
4. Is the change within its soft/hard budgets and anti-stall bounds, and what single
   safe action is available when it is not?
5. Is model routing supported by current blind benchmark evidence, or is it only a
   static configuration choice?

MPD remains a local evidence kernel, not a model runner, billing oracle, proof that a
review was insightful, or defense against a malicious repository owner. It validates
externally issued attestations only when their issuer is explicitly trusted by the
reviewed local policy. An authenticated session/model claim proves provenance and
separation, not semantic correctness. Provider pricing, benchmark tasks, and scores
are versioned inputs; MPD must not fetch them during a gate.

This release ships external-issuer verification readiness, but does not activate
required authenticated provenance: no real external issuer is available to issue an
exact-session envelope. Its release surface is therefore cooperative/optional and
explicitly reports required authentication as `MISSING`/`NOT DEPLOYED`. If a later
reviewed policy activates required mode, the same verifier fails closed until a trusted
external issuer—not a fixture or owner-self-signed claim—supplies exact-bound evidence.

The change also closes four operator-facing defects: trusted activated hooks must not
be diagnosed as absent, an archived `.mpd/current` pointer must not make status
unusable, superseded doctrine must be visibly and mechanically distinguished from
current doctrine, and abandoned candidate-cache entries must have a bounded,
identity-safe cleanup path.

## Operator mental model

The existing phase order and truth labels remain unchanged. The new facts are nested
under, not substituted for, the existing Candidate, gates/freshness, validation,
archive, commit, authorization, transfer, parity, and installation facts.

Human output uses these stable state words:

| Surface | States | Meaning |
|---|---|---|
| Usage | `ATTESTED`, `REPORTED`, `UNREPORTED`, `INVALID` | Signed issuer evidence, bounded cooperative evidence, no evidence, or rejected evidence |
| Review provenance | `AUTHENTICATED`, `COOPERATIVE`, `MISSING`, `INVALID`, `NOT REQUIRED` | Whether model/session/issuer claims were verified under current policy |
| Required-provenance readiness | `DEPLOYED`, `NOT DEPLOYED` | Whether a real external issuer is available for an activated required-authentication policy |
| Attestation verifier | `LOCKED`, `BLOCKED`, `INVALID`, `REPLAYED` | Reviewed verifier availability/identity, rejected evidence, or a durably consumed exact-attempt envelope |
| Independence | `INDEPENDENT`, `SAME SESSION`, `UNKNOWN`, `NOT APPLICABLE` | Comparison with the current review subject, never a claim about review quality |
| Budget | `WITHIN`, `SOFT LIMIT`, `HARD LIMIT`, `UNAVAILABLE`, `NOT CONFIGURED` | Current totals compared with the effective risk budget |
| Validation work | `EXECUTED`, `REUSED`, `BLOCKED`, `NOT RUN` | Per-check disposition; reused evidence always names its source receipt |
| Routing evidence | `CURRENT`, `STALE`, `INSUFFICIENT`, `MISSING`, `INVALID` | Fitness of benchmark evidence for the configured routing decision |
| Candidate cache | `CLEAN`, `RECLAIMABLE`, `BLOCKED`, `UNKNOWN` | Whether safely owned cache entries remain |

No state named above is synonymous with overall PASS. In particular,
`AUTHENTICATED`, `WITHIN`, `REUSED`, and `CURRENT` are typed details beneath the
existing gate outcome.

## Everyday human surfaces

### `mpd next --harness codex --context`

The brief stays compact and keeps persona/model first. It adds at most four short
lines after the model line:

```text
Phase: Security (code), attempt 1/3
  Persona: Security (model: sol; routing evidence: MISSING)
  Review provenance: COOPERATIVE — required authentication MISSING / NOT DEPLOYED
  Budget: WITHIN — $1.82 / $4.00 soft / $6.00 hard; 61k / 120k tokens
  Anti-stall: WITHIN — 0/2 consecutive blockers; advanced 11m ago
  Gate: mpd gate security-code --pass --by <actor> --evidence <artifact>
```

When a later reviewed policy has activated required authentication and a real external
issuer is configured, the brief instead states `Review provenance required: authenticated
external attestation` and includes `--attestation <file>`. Until then, the release never
claims that a fixture, actor label, or owner assertion is an issuer.

Authenticated verification has one visible, reviewed dependency rather than an ambient
crypto fallback: `security/tool-lock.json` locks the absolute `/usr/bin/ssh-keygen -Y
verify` path, platform/ABI, SHA-256, namespace, and typed argv. When that future policy
requires an attestation, `next` and gate output name the lock dependency. An unavailable
or drifted verifier blocks before objective work; it never searches `PATH`, changes
algorithms, or accepts an unsigned/cooperative substitute for required evidence:

```text
BLOCKED attestation.verifier-drift: /usr/bin/ssh-keygen does not match reviewed security/tool-lock.json.
No objective validation was started.
Next action: restore the reviewed locked verifier or update policy through normal review.
```

If cost or tokens are unavailable, the line says `Budget: UNAVAILABLE — usage is
UNREPORTED; no zero-cost claim`. A soft limit does not block the brief:

```text
  Budget: SOFT LIMIT — cost $4.21 crossed $4.00; hard limit $6.00
  Action after this bounded attempt: reduce scope/model tier or record a replan.
```

A hard limit, two consecutive infrastructure/environment/policy blockers, or 30
minutes without phase advancement blocks a *new* model-work brief before more work is
commissioned. The command exits with the established human-decision code and says:

```text
BLOCKED budget.hard-cost: $6.04 reached the $6.00 hard limit.
No new persona brief was issued.
Next action: mpd reconcile --continue "approve bounded budget overrun and replan"
```

Status, read-only reports, evidence inspection, and recording an already completed
gate remain available. A reconciliation authorizes one bounded continuation; it does
not erase usage, reset the stall clock, widen all future limits, or create a PASS.

### `mpd gate`

Judgment gates accept one optional `--attestation <file>`. When reviewed policy makes
attestation required, the generated gate command includes it and missing/invalid
evidence blocks before objective validation begins. The file is untrusted structured
input and is never printed verbatim. It binds at least change, phase, attempt, actor,
resolved provider/model, opaque session identity, issuer/key identity, issued time,
review subject, artifact digest, Candidate/planning-subject identity, and usage
counters. Numeric usage is non-negative integer input/output/cached tokens, active
milliseconds, and cost in integer micro-units plus currency; floats and NaN-like
tokens are invalid.

A successful gate summary distinguishes review evidence and validation work. This
authenticated example applies only after a later policy activation with a real external
issuer; it is not evidence that the current release has deployed required provenance:

```text
PASS Security (code)
  Review provenance: AUTHENTICATED (issuer external-harness, key 91bd…, session c4f0…)
  Independence: INDEPENDENT from Build session 88aa…
  Usage: ATTESTED — 18,240 input + 3,811 output + 8,004 cached tokens; $0.74; 94s active
  Validation: 3 EXECUTED, 5 REUSED from receipt 54d250d4…
  Candidate: 4b63…; profile: security-code; receipt: 7f08…
```

The cooperative fallback is explicit:

```text
PASS Security (code)
  Review provenance: COOPERATIVE — no trusted issuer configured
  Independence: UNKNOWN — actor labels are not session identity
  Usage: UNREPORTED — cost and token totals are unavailable
```

The initially deployed readiness state is explicit in status and JSON:

```text
Review provenance: COOPERATIVE — no trusted external issuer configured
Required authentication readiness: MISSING / NOT DEPLOYED
```

If policy requires authenticated independence, `MISSING`, `INVALID`, `UNKNOWN`, or
`SAME SESSION` blocks the gate and prints the violated field and one repair action.
Changing an attestation after a brief cannot launder the record: the accepted evidence
must match that phase and attempt's stored brief/model expectations. Replaying a valid
attestation for another change, phase, attempt, artifact, Candidate, or review subject
is `INVALID`.

The same preflight provides precise, terminal-safe error codes without echoing a signature,
key, path, or envelope. Omission remains the documented cooperative fallback only while
required mode is not activated; a supplied invalid envelope never downgrades to omission:

```text
BLOCKED attestation.verifier-unavailable: reviewed /usr/bin/ssh-keygen is unavailable.
INVALID attestation.signature: sshsig-ed25519-v1 verification failed.
INVALID attestation.key: issuer key is not the exact reviewed canonical key.
INVALID attestation.namespace: signature namespace is not mpd-attestation-v1.
BLOCKED attestation.trust-root-mismatch: issuer material differs from activated reviewed policy.
BLOCKED attestation.replay-consumed: this exact attestation was durably consumed for its attempt.
```

All six states refuse the required gate before objective validation. `replay-consumed`
remains consumed even if the first gate later fails, preventing concurrent or historical
replay; it is a provenance/evidence refusal, not a claim that the original review passed.

### `mpd status`

The existing pipeline and workflow-truth sections remain primary. A compact efficiency
section follows governance:

```text
Efficiency:
  Usage             ATTESTED    $2.56 · 83,112 tokens · 7m active
  Budget            WITHIN      cost 43% hard · tokens 35% hard · wall 29% hard
  Anti-stall         WITHIN      0/2 blockers · last advancement 11m ago
  Validation         CURRENT     11 executed · 13 reused · 96s source-duration avoided
  Review provenance AUTHENTICATED 4/4 required gates · independence 4/4
  Routing evidence  CURRENT      suite routing-v1 · evidence 7a31…
```

`source-duration avoided` is the sum of durations recorded by source receipts, labeled
as such; it is not presented as measured wall-clock savings. Missing usage yields
`UNAVAILABLE`, preserves known time/validation counts, and excludes unknown values from
totals rather than substituting zero.

At an objective phase, status also names the selected validation profile and reason:

```text
  Validation plan: docs-test (documentation-only scope + effective Low)
```

or:

```text
  Validation plan: high-risk-test (effective High; docs lane ineligible)
```

A selected docs profile that lacks its secret-scan/doc-staleness floor is
`BLOCKED config.docs-profile-floor`; MPD does not silently run a different profile.

### `mpd stats`

The existing schema remains readable and gains additive per-change/per-phase usage,
provenance, budget, validation-disposition, and routing-evidence summaries. Human
output reports known totals and coverage together:

```text
economics: $18.42 attested (21/25 phases); 4 UNREPORTED; 641k tokens; 52m active
validation: 94 executed; 67 reused; source-duration avoided 19m
provenance: 16/18 required reviews authenticated; 15 independent; 1 same-session; 2 missing
budget events: soft=3 hard=1 anti-stall=2
```

Aggregates never mix currencies and never infer missing prices from model names.
Filters or groupings with incomplete coverage state the numerator/denominator.
Unreadable ledgers remain unreadable rows, not missing data silently removed.

### Routing benchmark

The command group is discoverable as `mpd routing`. `mpd routing evaluate --evidence
<file>` is read-only and ends with `No state changed.` It consumes a bounded,
versioned, preferably issuer-attested benchmark result whose task IDs and blind score
rubric are identified by digest. It compares candidate routes on correctness/escaped
defects, rework, latency, tokens, and cost and reports dominated and Pareto-eligible
routes. It refuses to recommend a route when scores are unblinded, sample minimums are
not met, required metrics are missing, currencies conflict, or evidence is stale.

The user-authorized Codex Documenter route is `terra`. At release, no actual blind
Sol/Terra session coverage may exist; that truthful initial result is visible and makes
no recommendation:

```text
Routing evidence: MISSING — routing-v1 has no sufficient actual blind Sol/Terra sessions.
Documenter route: terra (user-authorized static configuration)
Decision: no route change recommended.
No state changed.
```

Luna is not a configured comparison route and no fixture or synthetic Luna sample counts
as evidence. Only sufficiently sampled, versioned, blind actual sessions for the
configured Sol and Terra routes can advance this state.

```text
Routing evidence: CURRENT (suite routing-v1, 12 tasks x 3 seeded runs, blind scoring)
Role       Current  Recommended  Quality  Escapes  Median cost  Median latency
Architect  sol      sol          0.94     0        $0.81        42s
Builder    terra    terra        0.91     1        $0.37        31s
Documenter terra    terra        0.90     0        $0.08        12s
Decision: current routing is Pareto-eligible; no config change recommended.
No state changed.
```

`mpd routing apply --evidence <file>` is preview-only; it shows the exact role mapping
and evidence digest that would be written. `--yes` applies only a deterministic,
non-dominated recommendation through the guarded configuration writer. It never
changes a route when evidence is insufficient and never claims the chosen mapping is
globally optimal. The resulting config binds the benchmark suite/version/evidence
digest, so changing routes or evidence is visible to freshness and policy review.

### Documentation-only profiles

Commando configures `docs-build`, `docs-security-code`, and `docs-test`. An honestly
documentation-only, requested-Low change sees those names in `next`, `status`, gate
output, and the receipt. Every phase still runs. Code/config/policy scope, effective
Medium/High, missing profile configuration, or a failed profile floor selects the
existing full lane or blocks exactly as the existing proportionate-governance rule
requires. The first adopted lane must be exercised through the real trusted-policy
sandbox fixture; a config-only unit test is not presented as adoption evidence.

### Doctor and recovery

Bare `mpd doctor` distinguishes the hook forms instead of looking for a legacy marker
inside an activated wrapper:

```text
pre-commit gate:     yes (activated trusted wrapper; coordinator 3cd1…)
```

```text
pre-commit gate:     yes (manual-tier hook)
```

```text
pre-commit gate:     no (configured hook is missing, drifted, or untrusted)
```

The JSON field is a typed object (`state`, `kind`, `coordinator_digest`, `blocker`) and
retains a compatibility boolean if an older consumer expects one. An activated wrapper
is healthy only when current activation/trusted-policy identity checks succeed; merely
living under `core.hooksPath` is not enough. The suggested fix for a drifted activated
wrapper is policy diagnosis/reactivation, not `mpd init`.

If `.mpd/current` names a ledger that is already archived or whose active manifest has
moved to the archive, `mpd status` remains read-only and usable:

```text
Current selection: STALE ARCHIVED POINTER (candidate-scope-integrity)
Archive: PASS — AwaitingCommit
No active phase can be gated.
Next action: commit the archived closure, then run `mpd archive --close --yes`.
```

After closure, the safe action is `mpd conduct <change>` or `mpd use <active-change>`.
`next` and `gate` still refuse an archived target. Status never manufactures an active
manifest, rewrites `.mpd/current`, or describes archived evidence as current Candidate
evidence. JSON exposes `selection.state = "archived-current"`, the named change,
archive stage, `active_change: null`, and the same next action.

Current durable documents that replace older behavior carry one visible supersession
relationship. A superseded document begins with a plain-text banner such as:

```text
Status: SUPERSEDED
Superseded by: docs/candidate-scope-integrity.md
```

The documentation checker verifies that the target is a canonical existing current
document, rejects chains/cycles/dangling targets, and rejects known contradictory
current-doctrine claims outside a correctly marked superseded document. Its error
names both documents and the doctrine key; it does not pretend to perform general
natural-language semantic proof.

Candidate-cache recovery is explicit and conservative:

```text
$ mpd cache inspect
Candidate cache: RECLAIMABLE — 2 owned orphan(s), 184 MiB; 1 live candidate retained
No state changed.

$ mpd cache prune
Preview: remove 2 identity-verified orphan(s), 184 MiB; retain 1 live candidate.
No state changed.

$ mpd cache prune --yes
PASS candidate cache cleanup — removed 2 orphan(s), 184 MiB; retained 1 live candidate.
```

Pruning is limited to clone-private, MPD-owned candidate roots/sidecars that are not
referenced by the current ledger, pending archive transaction, Build output, or current
receipt. Symlink, replacement, ownership, identity, race, or reference ambiguity is
`BLOCKED` and leaves that entry untouched. It never removes receipts, logs, tools,
policy, build/install output, source files, or Git objects. Successful archive close
may run the same identity-checked orphan cleanup and reports cleanup separately; a
cleanup blocker cannot rewrite archive truth.

## JSON and configuration contracts

All human views above derive from the same typed result as `--json`. JSON emits one
UTF-8 document on stdout; diagnostics stay on stderr. New fields are additive and use
integer units. A representative status fragment is:

```json
{
  "efficiency": {
    "usage": {
      "state": "attested",
      "coverage": { "reported": 4, "total": 4 },
      "currencies": { "USD": { "micro_units": 2560000 } },
      "input_tokens": 73112,
      "output_tokens": 10000,
      "cached_tokens": 24000,
      "active_millis": 420000
    },
    "budget": {
      "state": "within",
      "effective_risk": "high",
      "metrics": {
        "cost_usd_micro": { "observed": 2560000, "soft": 4000000, "hard": 6000000 },
        "tokens": { "observed": 83112, "soft": 120000, "hard": 180000 }
      }
    },
    "anti_stall": {
      "state": "within",
      "consecutive_blockers": 0,
      "blocker_limit": 2,
      "seconds_since_advancement": 660,
      "no_advancement_limit_secs": 1800
    },
    "validation": {
      "executed_checks": 11,
      "reused_checks": 13,
      "source_duration_avoided_millis": 96000
    },
    "provenance": {
      "state": "authenticated",
      "required": 4,
      "authenticated": 4,
      "independent": 4
    },
    "routing": { "state": "current", "suite": "routing-v1", "evidence_digest": "7a31..." }
  },
  "validation_plan": {
    "profile": "high-risk-test",
    "reason_code": "effective-high",
    "eligible_for_docs_lane": false
  }
}
```

Attestation, budget, and routing policy are opt-in for compatibility, but Commando
enables strict budgets/routing controls for its own changes while leaving required
authenticated provenance cooperative/optional until a real external issuer exists. The
configuration surface has these concepts (exact storage factoring is an Architecture
decision):

```jsonc
{
  "governance": {
    "budgets": {
      "high": {
        "cost_usd_micro": { "soft": 4000000, "hard": 6000000 },
        "tokens": { "soft": 120000, "hard": 180000 },
        "active_millis": { "soft": 1800000, "hard": 2700000 },
        "wall_millis": { "soft": 3600000, "hard": 5400000 }
      },
      "anti_stall": { "consecutive_blockers": 2, "no_advancement_millis": 1800000 }
    },
    "attestation": {
      "mode": "optional",
      "trusted_issuers": [],
      "required_authentication_readiness": "not_deployed"
    }
  },
  "routing": {
    "suite": "routing-v1",
    "evidence_digest": "...",
    "minimum_blind_samples_per_route": 3
  },
  "local_validation": {
    "gates": {
      "docs-build": "docs-build",
      "docs-security-code": "docs-security-code",
      "docs-test": "docs-test"
    }
  }
}
```

Absent policy yields `NOT CONFIGURED`/`NOT REQUIRED` and preserves existing gates.
Malformed policy is an explicit config blocker, not an implicit unlimited budget,
cooperative downgrade, or full-profile substitution. Soft must be less than or equal
to hard, integer limits must be positive and capped, currencies must be named, issuer
key material is clone-private or immutable reviewed public material, and secrets are
never stored in config or ledgers.

## Accessibility, terminal adaptation, and hostile input

- Every important distinction is stated in words and machine fields. Color, icons,
  emoji, alignment, cursor movement, animation, and sound carry no meaning.
- `NO_COLOR`, non-TTY output, and narrow terminals receive the same facts in a
  single-column order. Tables may collapse to labeled rows; no required value is
  truncated. Long IDs may be abbreviated only when the full ID remains in JSON and an
  inspection command.
- Very narrow terminals wrap on semantic boundaries with continuation indentation;
  they do not horizontally scroll or overwrite prior lines. Reports remain useful
  when copied into a log or read by a screen reader.
- Attestation issuers, actors, models, sessions, task IDs, paths, scanner output, Git
  values, and benchmark labels are untrusted. Human rendering applies the existing
  terminal-safe escaping and length caps. JSON uses valid escaping. Raw ANSI/OSC,
  C0/C1, bidi controls, invalid UTF-8, embedded newlines, oversized values, floats in
  integer fields, duplicate keys, and path traversal cannot alter state words, create
  extra rows, become argv, or inject a false PASS.
- Missing and zero are distinct. `0` tokens/cost is displayed only when authenticated
  evidence explicitly reports zero; otherwise the state is `UNREPORTED`.
- Preview commands are visibly read-only and end with `No state changed.` Mutating
  commands print PASS only after durable commit. Output loss follows existing
  idempotent-retry semantics.

## Checkable acceptance criteria

1. Human and JSON golden tests cover every state in the operator mental-model table,
   including narrow/non-TTY/`NO_COLOR`, output breakage, and hostile strings.
2. Status keeps all existing production-truth fields separate and adds efficiency
   facts without changing a gate outcome from telemetry alone.
3. Usage ingestion accepts bounded integer typed evidence, distinguishes attested,
   cooperative, missing, and invalid data, binds it to the exact phase attempt and
   subject, rejects replay/cross-binding, and never converts missing data to zero.
4. This release visibly reports cooperative/optional provenance and required
   authentication `MISSING`/`NOT DEPLOYED`; fixture and owner-self-signed claims cannot
   change that state. If a later policy activates required attestation, missing/invalid
   issuer, signature, model, session, phase, attempt, artifact, subject, or
   review-subject binding blocks before objective execution. Optional mode visibly
   reports the cooperative fallback. The only authenticated verifier is the reviewed
   `security/tool-lock.json`-bound `/usr/bin/ssh-keygen -Y verify` invocation; unavailable
   or digest/platform/argv drift, invalid signature/key/namespace, trust-root mismatch,
   and a durably consumed replay each have a distinct terminal-safe refusal and no
   fallback to `PATH`, alternate crypto, or unsigned evidence.
5. Independence tests prove a review gate cannot use the attested session of its
   current review subject; opaque actor-label alternation cannot satisfy authenticated
   independence.
6. Soft budget crossings warn without creating PASS/FAIL; hard cost/token/time limits
   and the two-blocker/30-minute anti-stall rules refuse a new brief with one bounded
   reconciliation action. Reconciliation preserves totals and authorizes only one
   continuation.
7. Budget property tests cover integer overflow, clock movement, missing coverage,
   `soft <= hard`, effective-risk selection, repeated status calls, and concurrent
   attempts. Read-only observation never increments usage or stall counts.
8. Check-level reuse is accepted only for exact subject, check definition, policy,
   tool, host/adapter, input, environment, result-policy, and coordinator identities.
   Any mismatch executes or blocks; it never silently reuses. Security(code) remains a
   fresh gate invocation and all security-specific checks execute.
9. Receipts and status enumerate each check as executed/reused and identify the source
   receipt. Pre-push and Commit validation preserve exact-subject and fresh outgoing
   secret-scan requirements. Reported avoided duration is labeled source-receipt time,
   not measured savings.
10. A trusted-policy-bootstrapped sandbox e2e drives a documentation-only requested-Low
    change through all three configured docs profiles and proves receipt/profile/check
    identity. Code scope, config scope, effective Medium/High, and broken floor cases
    prove the lighter lane cannot be reached.
11. Routing evaluation uses versioned seeded tasks, blind rubric identities, minimum
    sample counts, and quality/escape/rework/latency/token/cost metrics. Seeded tests
    cover ties, dominated routes, missing data, mixed currency, stale evidence, hostile
    labels, and deterministic recommendation. Insufficient evidence cannot be applied.
12. Applying routing is preview-first, updates only the reviewed role mapping and
    evidence binding, and makes the policy/freshness change visible. The report says
    Pareto-eligible/recommended, never “optimal,” unless that stronger claim is actually
    proven by the declared search space.
13. Bare doctor recognizes both the legacy manual hook and the currently activated,
    identity-valid trusted wrapper; a marker-only, drifted, wrong-coordinator, symlinked,
    or untrusted wrapper is not a false positive. Human and JSON agree.
14. Status on missing current, active current, archived-current, pending archive,
    AwaitingCommit, and closed archive states does not panic or require an active
    manifest. Archived `next`/`gate` remain blocked and status remains read-only.
15. The supersession checker catches the presently contradictory process-prose claim,
    accepts one valid direct supersession banner, rejects missing/dangling/non-canonical
    targets and cycles, and names both documents plus the doctrine key on conflict.
16. Cache inspection/pruning tests cover live references, archived/closed candidates,
    stale sidecars, symlink/replacement/ownership races, interruption, retry, size/count
    caps, and concurrent capture. Only exact owned orphans are removed; ambiguous
    entries are retained and reported BLOCKED.
17. Full workspace tests, the explicit ignored 10k-path/100MB workload, release build,
    documentation checks, and the authoritative high-risk exact-Commit profile pass
    with real test counts. The final deployed binary's typed file identity matches the
    tested Build output.

## Verdict

PASS
