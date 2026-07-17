# Design: per-persona behavior tuning (with an audited interview)

Canonical current-state contract. Superseded drafts go to `history/`.

## Context

mpd is a state-machine CLI that does not run the personas — the harness does. So
"tune behavior" means mpd resolves per-persona config + governance and **carries**
it into the `mpd next` brief; the harness applies it (reasoning effort, extra
reviewers, an appended directive). Today the only per-persona lever is
`config.models[harness][persona]` (config.rs); `config::model_for_governed`
(harness.rs) already bumps Security/Tester to the deep model at `risk=high`, only
ever strengthens, leaves a custom pin untouched, and is surfaced as a note — the
exact precedent this design extends. `directives::for_persona` (directives.rs) is
the wholesale-override path, surfaced only as `modified: bool`. `GateRecord`
(ledger.rs) already carries serde-default provenance (`CheckSummary.scanner`).
Doc Validation's persona is the composite `"Architect & Designer"` (phase.rs).

## Goals / Non-Goals

**Goals.** Real per-persona tunability (rigor, Tester depth, project instructions,
Doc-Validation rigor) that a user can only ever use to *strengthen* a persona
freely, cannot use to *silently* weaken the adversarial guarantee, and can set via
a harness-conducted interview. **Non-Goals.** mpd running a model or an
interactive interview loop (the harness conducts it over mpd's primitives); a new
gate or CONDITIONAL (tuning is brief-carried config, never a gate input); a
bidirectional `verbosity` knob; duplicating `model` into the persona block.

## Decisions

### D1 — Config shape (config.rs, additive, harness-neutral)

```rust
// on Config, beside `models`:
#[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
pub personas: BTreeMap<String, PersonaTuning>,   // keyed by persona DISPLAY name

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PersonaTuning {
    // NOT plain Option<Rigor>: string_enum!'s derived Deserialize is STRICT, and
    // #[serde(default)] only supplies a default when the field is ABSENT, not when
    // it is present-but-invalid. A bad token would fail the whole Config, which
    // Config::load discards wholesale (unwrap_or_default) — silently reverting a
    // custom model pin to a weaker default. So each ordinal field uses a tolerant
    // adapter that maps an unrecognized token to None (degrading only THAT field).
    #[serde(default, deserialize_with = "de_lenient_rigor", skip_serializing_if = "Option::is_none")] pub rigor: Option<Rigor>,
    #[serde(default, deserialize_with = "de_lenient_depth", skip_serializing_if = "Option::is_none")] pub depth: Option<Depth>,  // Tester only
    #[serde(default, skip_serializing_if = "Option::is_none")] pub directive_append: Option<String>,
}
// string_enum!(Rigor, Standard, { Standard=>"standard", Deep=>"deep", Paranoid=>"paranoid" }) + rank() 0/1/2
// string_enum!(Depth, Examples, { Examples=>"examples", Property=>"property", Fuzz=>"fuzz" }) + rank() 0/1/2
// de_lenient_* deserialize a permissive serde_json::Value (which CANNOT fail on a
// well-formed JSON document), then map it to Some(variant) ONLY for an exact known
// variant string; ANYTHING else — unknown token, wrong TYPE (5, true, [..], {}),
// or null — becomes None. The adapter itself never returns Err, so one bad value
// degrades only that field.
```

Model stays in the per-harness `models` map (one source of truth; it is
harness-specific). Per-field lenient deserialization (the `de_lenient_*` adapters
above): a `rigor`/`depth` value that is not an exact known variant string —
whether an unrecognized token OR a wrong-type value (`"rigor": 5`,
`"rigor": true`, `"rigor": ["deep"]`) OR `null` — degrades **that field** to
`None` (bundled behavior), and the **rest of the config — model pins, test command
— survives intact**; the whole `Config` never fails to load. A `deserialize_with`
that internally does `Option::<String>::deserialize` is INSUFFICIENT: it still
errors on a wrong-type token, and `Config::load`'s `unwrap_or_default`
(config.rs:167) would then discard the whole document and silently revert model
pins (Security-plan R2 Finding 2). The adapter MUST deserialize a permissive
`Value` (or an untyped visitor) so it cannot error on any well-formed JSON.

### D2 — Strengthen-only ordinal knobs; the lowest term IS the baseline

`rigor=standard` and `depth=examples` are the *baselines* (no-op overlays), not
weakenings — there is deliberately no sub-baseline term, so a user cannot dial a
persona weaker through the menus. `rigor` → reasoning **effort** (standard → the
persona's tier baseline effort [deep tier `high`, standard tier `medium`]; deep →
`high`; paranoid → `max`) and **reviewers** (paranoid on a review persona → 2,
else 1, clamped ≤ 4). `depth` is a Tester **emphasis** overlay that only ADDS
("property" / "fuzz" emphasis text + an effort nudge); it never removes the base
directive's testing requirements. `depth` on a non-Tester phase is ignored.

### D3 — Doc-Validation keying (handled now)

The resolver keys tuning by a `tuning_key(phase) -> &'static str`: single-persona
phases → the persona display name; the Doc-Validation phase (composite persona)
→ the normalized key `"DocValidation"`. So `personas["DocValidation"].rigor`
tunes the Doc-Validation gate. (Doc-Validation is deep-tier, so its baseline
effort is already `high`.)

### D4 — Governed resolution (harness.rs)

`resolve_tuning_governed(cfg, phase, risk) -> ResolvedTuning { effort:
Option<String>, reviewers: usize, depth: Option<Depth>, directive_append:
Option<String>, weakened: bool, tuning_note: Option<String> }`, called from
`brief()`, sitting beside `model_for_governed`. It is **config-only** (sees only
`cfg`), so its `weakened` is the CONFIG half (`had_append`); the directive
`base_modified` half needs `root` and is folded in by `next` (Cond 9/11) to form
the full `weakened = had_append || base_modified` the brief carries and records.
**Effort is composed as a monotonic `max` of {tier-baseline, rigor-effort,
depth-nudge, high-risk floor}**, comparing on an ordinal rank (`medium<high<max`),
never `String` order (Cond 3, round-3 F3) — the `Option<String>` is only the
serialized surface — never a later assignment that clobbers a stronger value.

**The high-risk effort/reviewer floor eligibility is `risk==High && the phase is
in {SecurityPlan, SecurityCode, Test, DocValidation}` — and MUST NOT include the
`model == builtin_default` clause** that `model_for_governed` carries (revised per
Security-plan Finding 1). That clause exists ONLY so the *model* bump won't
override an unrankable custom model pin; the *effort* floor has no such excuse — a
custom model pin must NOT disable the rigor floor. The floor and the model bump
share only the (risk, phase-set) portion of the predicate. At `risk=High` for that
phase set, effective rigor floors at `deep` (raising a configured `standard`,
recorded as a note) — a resolution-time clamp, NOT a gate verdict. (Doc-Validation
is already deep-tier, so its effort floor is a no-op; the floor is scoped to where
it is meaningful — Security/Tester — while the *tunability* and the flag/stamp
apply to Doc-Validation too.)

### D5 — The integrity guardrail (record-and-flag the un-rankable)

The ordinal knobs cannot weaken (D2) and are floored at high risk (D4). The one
un-rankable vector — a free-text `directive_append`, or a base directive already
`modified: true` — cannot be proven rigor-preserving ("check IMAP cleartext"
strengthens, "ignore auth" guts it, both are just strings), so it is **recorded,
not blocked**:
- `NextBrief.weakened = true` + a `tuning_note`, rendered inline exactly like the
  existing `deep_tier_bump` warning in `governance_lines()`.
- A serde-default `GateRecord.persona_tuning: Option<PersonaTuningRecord>`
  (`{ rigor, depth, had_append, base_modified, weakened }`), stamped when a
  non-baseline tuning was in force. A Security PASS produced by a tuned persona is
  then no longer indistinguishable in the ledger from a full-rigor PASS — Doc
  Validation, a reviewer, or an auditor sees it. Weakening alters the evidence,
  not just a console line. It is never converted into a CONDITIONAL (that would
  manufacture a stuck-state).

**The stamp must survive every path a PASS can take (Security-plan Findings 2–3).**
Three holes the naive "stamp in `cmd_gate` from live config" leaves open, and how
each is closed:

1. **Reuse path (Finding 2).** `cmd_gate` builds a `GateRecord` at TWO sites — the
   execute path (cli.rs ~1599) and the `--reuse` path (cli.rs ~1409, which
   `return`s before the execute site). The stamp MUST be written at **both**
   (a reused gate propagates its recorded stamp). And because a `personas` config
   change otherwise leaves the review criteria silently altered, persona-tuning
   MUST be **bound into the phase dependency snapshot** for the governed phases, so
   a receipt produced under tuning X cannot be silently `--reuse`d after the tuning
   changes (a changed directive means the prior review no longer covers the current
   criteria — even a *strengthening* change must re-execute): the receipt goes
   `Stale` and reuse re-executes.

   **Use a dedicated narrow `DependencyKey::PersonaTuning` (round-2 Finding 3), NOT
   `DependencyKey::Config`.** `DependencyKey::Config`'s digest is `to_vec(config)` —
   the ENTIRE config — so binding it would over-stale those four governed receipts
   on any unrelated edit (`test`, `deploy`, `docs_dir`, `models`), a reuse-liveness
   regression. `DependencyKey::PersonaTuning` digests the persona's **effective
   instructions for that phase** — both the config tuning (`config.personas[
   tuning_key(phase)]`) AND the resolved base-directive text
   (`directives::for_persona(root, persona)`, DocValidation resolving its two
   parts) — so a receipt stales iff *this* persona's effective directive changed,
   by config append OR directive-file edit (round-3 F1: the directive-file vector
   must stale a reused receipt too, symmetric with the config vector). The digest
   needs `root`; if `capture_dependency_values` lacks it, thread it in (a small,
   contained change). The Builder MUST add the variant, bind it in
   `DependencyPolicy::for_phase` for {SecurityPlan, SecurityCode, Test,
   DocValidation}, and update `golden_dependency_policy_table` +
   `no_policy_binds_an_output_first_created_by_a_later_phase` +
   `earliest_available` (classify `PersonaTuning` as config-like ⇒ `DesignMock`, so
   `earliest_available ≤ phase` holds for all four).

2. **`next`→`gate` TOCTOU (Finding 3), closed FAIL-SAFE (round-2 F1) for BOTH
   un-rankable vectors (round-3 F1).** The weakening is applied when the harness
   runs the persona (right after `mpd next`), but the stamp is computed at `mpd
   gate`. `mpd next` is read-only today, so `set(weakening) → next → [gutted review]
   → reset → gate` would recompute a *clean* state and stamp nothing. Closed by
   having **`mpd next` record the resolved *weakening determination* for the current
   `(phase, attempt)` into a serde-default `Ledger.brief_tuning`**, and **`cmd_gate`
   stamp from that recorded brief** when present (live only as a fallback when no
   brief was recorded).

   **CRITICAL: the record MUST cover BOTH un-rankable vectors, not just the config
   append (round-3 F1).** There are two ways to weaken un-rankably: (a) a config
   `directive_append`, and (b) editing a base directive file
   (`.mpd/directives/personas/*.md`) so `directives::for_persona(root, persona)`
   returns `modified: true`. `resolve_tuning_governed(cfg, …)` sees only config, so
   it CANNOT observe (b). Therefore `mpd next` — which has `root` (cli.rs ~1063) —
   MUST compute `base_modified` at brief time (resolving DocValidation's
   `["Architect","Designer"]` parts individually, resolved ONCE per `next` and
   shared with any `--full`/`--context` display — round-4 F4-2) and record it into
   `brief_tuning` ALONGSIDE the config tuning. **This computation + write MUST be
   UNCONDITIONAL and pre-branch — immediately after `brief()` (~cli.rs:1112),
   BEFORE the `--full`/`--context`/`--json` branches — NOT gated behind `if full`
   (cli.rs ~1145) (round-4 F4-1).** If the write hung off `--full`, a harness
   running a plain `mpd next` would record nothing, the gate's absence-fallback
   would become a LIVE `for_persona` read, and `edit directive → next (no --full) →
   restore → gate` would re-open the exact R3-F1 TOCTOU. `cmd_gate` MUST derive the
   `weakened` stamp's `modified` half FROM the recorded brief, with NO
   `directives::for_persona` call anywhere in the stamp path (Security-code MUST
   grep `cmd_gate` to confirm the stamp is derive-from-record only). Leaving (b) as a live
   gate-time read re-opens the exact TOCTOU for the directive-file path: `edit
   directive → next (gutted run) → restore → gate` would stamp clean. Both vectors
   now flow through the identical brief-time record: `brief_tuning` records the full
   `weakened = had_append || base_modified` determination as of the brief the
   harness consumed.

   TWO properties make this fail-safe rather than a new hole (round-2 F1 showed the
   naive version re-opens weakening):
   - **Conditional write — inertness preserved.** `next` writes `brief_tuning`
     ONLY when a non-baseline tuning OR a `base_modified` directive is actually in
     force. An untuned project with unmodified directives writes nothing, so its
     ledger file is byte-unchanged by `next` — the two-tier-neutral promise holds at
     the file level, not just the brief text (R1/R10 must assert the ledger bytes).
   - **Monotonic / weakest-seen — no laundering.** The `(phase, attempt)` record is
     write-once-strengthen-only in the *weakened* direction: once `weakened=true`
     (or a stronger stamp) is recorded for an attempt, a later `next` MUST NOT
     downgrade it — NOT via a clean re-brief (conditional write emits nothing) and
     NOT via a *non-baseline-but-non-weakened* re-brief (e.g. drop the append, set
     `rigor=deep`): that write MUST **merge** weakest-seen, never blind-overwrite
     (round-3 F2). It clears only when a gate consumes the attempt and advancement
     moves to a fresh `(phase, attempt)`. This kills the
     `set → next → reset → next → gate` laundering the naive "overwrite-to-clean"
     rule allowed. It over-flags an honest reset-then-rerun (records `weakened` even
     if the final brief was clean) — the fail-safe direction, acceptable (a spurious
     `weakened` flag is a nuisance an auditor resolves via the retained artifact,
     never a silent weakening).

   `cmd_gate` MUST consume `brief_tuning` only when it matches the current
   `(phase, attempt)`, falling back to a live determination on any mismatch
   (round-3 F4 — so a stale superseded record can never mask). `brief_tuning` is a
   serde-default ledger field consulted ONLY for the stamp; it is NOT part of any
   dependency/brief digest and gates nothing, so making `next` write it cannot stale
   a receipt, break reuse, or manufacture a stuck-state.

3. **The residual is irreducible harness trust — scoped honestly (round-2 Finding
   4).** Even (2) is not a cryptographic guarantee: a harness that re-reads
   `config.json` after `next`, or re-briefs clean and simply doesn't re-run, defeats
   any stamp — which is isomorphic to "the harness actually ran the persona it was
   briefed," a trust mpd fundamentally cannot verify (it never runs the model). So
   the stamp is a **best-effort integrity signal, not a guarantee.** What IS
   closed: BOTH revert sequences performed through the normal flow — config-revert
   (`set/next/reset/gate`) AND directive-file-revert (`edit directive/next/restore/
   gate`) — can no longer launder to a clean stamp, because `next` records the
   weakening determination for both vectors and the gate stamps from that record.
   What remains best-effort: a manual operator who never runs `next` and hand-edits
   config/directives around a raw `gate --pass` (the same total self-trust the
   manual tier already grants — they can `gate --pass` with no persona run at all),
   and a harness that violates the Cond-12 brief-application doctrine. The durable teeth for both are the
   **strict-tier judgment artifact** (security-code.md, retained + reviewable — a
   gutted review leaves a thin artifact an auditor sees) plus the doctrine that the
   harness records the gate *before* any `persona set/reset`. The strong,
   non-bypassable guarantees remain the STRUCTURAL ones (D2 no sub-baseline term,
   D4 high-risk floor, reviewer clamp) — those hold regardless of harness honesty.

### D6 — The interview: mpd owns the primitives, the harness conducts it

mpd is NOT interactive. It exposes:
- `mpd persona list [--json]` — every persona + its current tuning + resolved
  (governed) effective values.
- `mpd persona show <persona> [--json]` — one persona: per field the current
  value, the allowed range, the baseline, and a `dangerous: bool` classification
  (true iff the value is the un-rankable vector — a `directive_append`).
- `mpd persona set <persona> <field> <value>` — validate against the range
  (reject unknown enum terms), classify danger, print `current → new` and a loud
  ⚠ note when setting the un-rankable `directive_append`, then write config.
- `mpd persona reset <persona> [field]` — clear tuning back to baseline.

The **interview** is a documented harness workflow (AGENTS.md/protocol): the
harness loops each persona, reads `mpd persona show --json`, asks the user via its
native Q&A (surfacing current / range / the ⚠ on `directive_append`), and records
with `mpd persona set`. Because the danger classification and the write both live
in mpd, an interview-set value and a hand-edited value are guarded identically; a
model-driven interview cannot secretly weaken a persona.

## Risks / Trade-offs

- [A user weakens Security via free text] → cannot be blocked (un-rankable), but is
  recorded on every gate receipt + flagged on the brief + floored-adjacent at high
  risk; a downstream review sees it. This is the ceiling; blocking it would be a
  stuck-state.
- [Empty/absent config changes behavior] → every field serde-default; a proptest
  pins that an empty `personas` map yields a byte-identical brief.
- [Hostile/fat-fingered `directive_append` corrupts the brief] → sanitized
  (`terminal_safe` + explicit length cap) on resolve, degrading to `None`.
- [Unbounded reviewer fan-out] → `reviewers` clamped ≤ 4 on resolve.
- [A later change turns the weakening flag into a blocking gate] → the resolver's
  doc comment states the two-tier-neutral invariant; a monotonic/no-gate test pins it.
- [Reuse a receipt across a tuning OR directive-file change] → a dedicated narrow
  `DependencyKey::PersonaTuning` (that phase's effective instructions — config
  tuning + resolved base-directive text, NOT the whole config) is bound into the
  four governed phases, so such a receipt goes `Stale` and `--reuse` re-executes;
  the stamp is written at both `GateRecord` sites (D5 §1). Fails safe (over-stale →
  re-execute), never a false reuse.
- [Weaken, run a gutted persona, reset, re-brief, then gate — TOCTOU/laundering] →
  `mpd next` records the brief-tuning it hands the harness *conditionally* (only when
  tuned, so untuned ledgers stay byte-identical) and *monotonically* (weakest-seen:
  a clean re-brief cannot erase a recorded `weakened` until the attempt advances),
  so the gate stamps from that record (D5 §2). This closes the config-revert
  sequence performed through mpd's own verbs. It is NOT airtight against a harness
  that re-reads config or violates the brief-application doctrine — that residual is
  irreducible ("did the harness run what it was briefed?" is unverifiable); the
  stamp is a best-effort signal, the STRUCTURAL knobs (D2/D4) are the guarantees,
  and the retained strict artifact is the audit tooth (D5 §3). Honestly scoped, not
  overclaimed.
- [A `reviewers` value collapses Doc-Validation's dual reviewer] → `dual` (spawn
  Architect + Designer) is derived from the phase (`harness.rs:186
  phase.is_doc_validation()`), independent of any `reviewers` count; `reviewers` is
  purely ADDITIVE and MUST never gate the structural dual (stated so a later
  refactor doesn't wire them together — round-2 Finding 5).
- [One-time staleness of in-flight governed receipts on upgrade] → binding
  `PersonaTuning` into the four governed policies means a pre-upgrade
  Security/Test/DocValidation receipt (lacking the key) goes `Stale` the first time
  it is re-evaluated post-upgrade (`evidence_validity`, missing non-hermetic key ⇒
  `DependencyChanged`). This is the accepted fail-safe direction (over-stale ⇒
  re-execute, never false-reuse), identical to any dependency-policy evolution, and
  does not affect within-build neutrality — the Documenter notes it (round-4 F4-4).
- [`string_enum!` does not auto-generate `rank()`] → `RiskLevel::rank()` (ledger.rs:64)
  is a MANUAL impl; the Builder MUST hand-write `rank()` for `Rigor`/`Depth` and the
  ordinal effort rank (Cond 3), following that precedent (round-4 note).

## Conditions for Builder

1. Every new `Config`/`GateRecord`/`NextBrief` field MUST be `#[serde(default)]`;
   an absent/empty `personas` map MUST yield a byte-identical brief and an
   unchanged gate — pin with a back-compat proptest and an inert test. The new
   `NextBrief` fields MUST additionally carry `#[serde(skip_serializing_if)]`
   (`weakened` skip-if-false, `reviewers` skip-if-`1`/`Option`, `effort` and
   `tuning_note` skip-if-`None`) so the `--json` envelope the evidence/reuse
   harness consumes is byte-identical at baseline — not just the text render.
2. `rigor`/`depth` deserialization MUST be lenient per-field via a `deserialize_with`
   adapter that **deserializes a permissive `serde_json::Value` (or an untyped
   visitor) and therefore CANNOT error on any well-formed JSON**, mapping to
   `Some(variant)` ONLY for an exact known variant string and everything else —
   unknown token, wrong TYPE (`5`, `true`, `["deep"]`, `{}`), or `null` — to `None`.
   An `Option::<String>::deserialize`-based adapter is INSUFFICIENT (it still errors
   on a wrong-type token, which `Config::load`'s `unwrap_or_default` at config.rs:167
   swallows by discarding the whole document and reverting model pins). One bad value
   MUST degrade only that field; the rest of the `Config` (model pins, test command)
   MUST survive and `Config::load` MUST NOT fail — R2 asserts the surviving pins for
   BOTH an unknown-token and a wrong-type value.
3. The ordinal knobs MUST be strengthen-only: their lowest term (`standard` /
   `examples`) is the baseline no-op; there MUST be no sub-baseline term and no
   path by which `rigor`/`depth` lowers effort/reviewers below the persona's tier
   baseline. Effort MUST be composed as a monotonic `max` of {tier-baseline,
   rigor-effort, depth-nudge, high-risk floor} — never a later assignment that
   clobbers a stronger earlier value. **The `max` MUST compare on an explicit
   ordinal effort rank (`medium=0 < high=1 < max=2`), NEVER on `String` ordering**
   (round-3 F3): lexically `"high" < "max" < "medium"`, so a naive `String::max`
   would select `"medium"` (the WEAKEST) over `"high"` — a strengthen-only
   inversion. `depth` MUST be honored only for the Test phase and MUST only add
   emphasis (never remove a base testing requirement).
4. The high-risk effort/reviewer floor MUST use the eligibility predicate
   `risk==High && phase ∈ {SecurityPlan, SecurityCode, Test, DocValidation}` and
   MUST NOT include `model_for_governed`'s `model == builtin_default` clause — a
   custom model pin MUST NOT disable the rigor floor (Finding 1). The floor and
   the model bump share only the (risk, phase-set) portion of the predicate. It
   MUST floor effort at `deep`-tier (`high`) for Security/Tester (Doc-Validation
   is already `high`, so its floor is a no-op — scope the floor to where it is
   meaningful), raising a configured `standard`, never lowering; it MUST be a
   resolution-time clamp, NOT a gate verdict, and MUST never block advancement
   (state this in the resolver's doc comment). R4 MUST include a **custom Security
   model-pin variant** proving the effort floor still raises `medium→high`.
5. `directive_append` MUST be sanitized on resolve with `harness::terminal_safe`
   PLUS an explicit length cap. Precise semantics: an **oversized** value degrades
   to `None` (dropped); **control chars are stripped in place** by `terminal_safe`
   (they do NOT force `None`). It never reaches a rendered brief unsanitized, and
   MUST be APPENDED after the base directive under an explicit header, never
   replacing it (`directives::for_persona`, the base, is unchanged). `weakened`
   MUST be true iff the sanitized value actually carried in the brief is `Some`
   (an append that sanitizes to empty or is dropped applies nothing → `weakened`
   stays false).
6. Any non-baseline tuning in force (`rigor`/`depth` above baseline, a
   `directive_append`, or a `modified:true` base) MUST stamp
   `GateRecord.persona_tuning` **at every `GateRecord` construction site in
   `cmd_gate` — the execute path AND the `--reuse` path (cli.rs ~1409)** (Finding
   2); `weakened` MUST be true iff the un-rankable vector (append or `modified:true`
   base) is present. Persona-tuning MUST be bound into the phase dependency snapshot
   for the governed phases via a **dedicated narrow `DependencyKey::PersonaTuning`**
   digesting that phase's **effective instructions** — config tuning AND the
   resolved base-directive text (D5 §1) — NOT `DependencyKey::Config` (whose
   whole-config digest would over-stale the governed receipts on any unrelated edit,
   round-2 Finding 3) — so a receipt stales iff its persona's effective directive
   changed (config append OR directive-file edit), and NOT on an unrelated edit. The
   Builder MUST bind it in `DependencyPolicy::for_phase` for {SecurityPlan,
   SecurityCode, Test, DocValidation} and update `golden_dependency_policy_table` +
   `no_policy_binds_an_output_first_created_by_a_later_phase` + `earliest_available`.
   The
   un-rankable vector MUST set `NextBrief.weakened` + a `tuning_note`, and MUST NOT
   convert the gate to a CONDITIONAL or block it. R6 MUST include a reuse-path
   variant (stamp present on a reused gate under a tuned persona) and an
   unrelated-edit variant (a `test`/`models` edit does NOT stale a governed receipt).
7. `mpd persona set` MUST reject an unknown enum term (never write it), classify
   danger, and print a loud ⚠ when setting `directive_append`; it MUST ALSO reject
   an unknown persona NAME (allow only the `tuning_key` set incl. `"DocValidation"`)
   so a fat-fingered `Secuirty` cannot silently write an inert `personas[...]` entry
   that `tuning_key` never resolves — undiscoverable config rot that also silently
   no-ops a strengthening the operator believes they applied (round-4 F4-3). `mpd
   persona show --json` MUST expose current + range + baseline + `dangerous` per
   field so the harness interview renders the same warning. All new user-facing text
   (persona values, appends, warnings) MUST pass `harness::terminal_safe`, and the
   config write MUST route through `Config::save` (assert-contained before create +
   write).
8. `reviewers` MUST be clamped ≤ 4 on resolve so no config can trigger an
   unbounded fan-out, and MUST be purely ADDITIVE: it MUST NEVER gate or reduce
   Doc-Validation's structural dual (`harness.rs:186 dual = phase.is_doc_validation()`,
   derived from the phase, not the reviewer count) — a `reviewers` below 2 cannot
   collapse the Architect+Designer spawn (round-2 Finding 5).
9. `tuning_key(phase)` MUST map Doc-Validation to `"DocValidation"` and every
   single-persona phase to its persona display name, so tuning reaches the right
   phase. The floor predicate and the `modified:true`-base check MUST key on the
   **phase** (via `tuning_key`), never the persona string — Doc-Validation's
   persona is the composite `"Architect & Designer"`, so its base-modified check
   MUST resolve the parts `["Architect","Designer"]` individually (as `cmd_next`
   already does at cli.rs ~1146). **The `base_modified` determination MUST be made
   at `next` and recorded into `brief_tuning`; `cmd_gate` MUST derive the
   `modified→weakened` half FROM that record, NOT a fresh live `directives::for_persona`
   read at gate time (round-3 F1)** — a gate-time live read is the TOCTOU that lets
   `edit directive → next → restore → gate` launder a gutted persona to a clean
   stamp. (`render_context_slice` at cli.rs ~1975 resolves the directive via
   `brief.persona`; for the composite DocValidation persona `for_persona` returns
   `None`, so `--context` surfaces no directive there — safe/default, but note the
   `--context`/`--full` inconsistency so the base-modified path is resolved from the
   parts, not the composite.)
10. This change MUST run under strict and retain its own judgment artifacts
    through archive (Cond-16 class).
11. **The stamp MUST survive a `set/edit → next → reset/restore → [re-brief] → gate`
    sequence, FAIL-SAFE, for BOTH un-rankable vectors (Finding 3 + round-2 F1 +
    round-3 F1/F2).** `mpd next` MUST record the resolved weakening determination —
    the config tuning AND the `base_modified` directive state (Cond 9) — for the
    current `(phase, attempt)` into a serde-default `Ledger.brief_tuning`, and
    `cmd_gate` MUST stamp `GateRecord.persona_tuning` from that record **when it
    matches the current `(phase, attempt)`**, falling back to a live determination
    only on absence/mismatch (round-3 F4). The write MUST be:
    - **conditional** — `next` writes `brief_tuning` ONLY when a non-baseline tuning
      OR a `base_modified` directive is in force, so an untuned project with
      unmodified directives leaves its ledger file byte-unchanged by `next` (R1/R10
      MUST assert the ledger bytes, not only the brief text/`--json`); and
    - **monotonic / weakest-seen MERGE** — once `weakened=true` (or a stronger
      stamp) is recorded for a `(phase, attempt)`, NO later `next` may downgrade it:
      not a clean re-brief (conditional write emits nothing) AND not a
      *non-baseline-but-non-weakened* re-brief (e.g. drop the append, set
      `rigor=deep`), which DOES write and MUST **merge** weakest-seen, never
      blind-overwrite (round-3 F2). It clears only when a gate consumes the attempt
      and advances.
    `brief_tuning` MUST be inert to evidence: not part of any dependency/brief digest,
    gating nothing (so making `next` write cannot stale a receipt or create a
    stuck-state). The `base_modified`/`brief_tuning` write MUST be unconditional and
    pre-branch (~cli.rs:1112), NOT gated behind `--full` (round-4 F4-1). Add tests:
    (a) `set(append) → next → reset → gate` yields a **stamped** PASS; (b)
    `set(append) → next → reset → next(clean) → gate` STILL stamped (conditional-write
    path); (b2) `set(append) → next → reset-append + set(rigor=deep) → next → gate`
    STILL stamped `weakened` (exercises the MERGE, not just conditional write —
    round-3 F2); (c) an untuned+unmodified `next` leaves the ledger file
    byte-identical; (d) **directive-file variant**: `edit
    .mpd/directives/personas/security.md → plain next (NO --full) → restore → gate`
    yields a `weakened=true` stamped PASS (round-3 F1 + round-4 F4-1 — the plain-next
    invocation proves the write is unconditional). The manual no-`next` path is
    documented best-effort (D5 §3) — the strict artifact + doctrine are its teeth.
12. Doctrine (protocol.md / AGENTS.md, Cond-7 workflow) MUST state that the harness
    applies the **brief's** sanitized `directive_append`, never re-reads
    `config.json` itself (else the sanitize/length-cap/`None` guard is bypassed),
    and records the gate **before** any `persona set/reset`. A `weakened=true`
    Security or Doc-Validation gate under the **strict** tier SHOULD additionally
    emit the strict human-decision advisory line in `governance_lines` (louder
    surfacing only — still no gate, no CONDITIONAL, no stuck-state).
