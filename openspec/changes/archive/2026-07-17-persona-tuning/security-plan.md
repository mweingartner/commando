# Security (plan) — persona-tuning

Canonical current-state artifact. Superseded review prose lives in the design's
history, not here. Governance: risk medium, threat profile local-trusted-user.

## Threat model

The load-bearing invariant: **a user may freely STRENGTHEN a persona but must never
SILENTLY WEAKEN the adversarial guarantee.** mpd never runs the personas — it
carries per-persona config + governance into the `mpd next` brief; the harness
applies it. So the whole feature is a set of knobs that (1) cannot dial a persona
weaker through structural means, and (2) when a truly un-rankable weakening is
applied, RECORD-AND-FLAG it rather than block (blocking would manufacture a
stuck-state).

Actor = the local trusted operator/harness (no remote attacker; config + directive
files are local, operator-owned). The manual tier already grants total self-trust
(an operator can `gate --pass` with no persona run at all); the strict tier's tooth
is the retained, reviewable judgment artifact. Against that backdrop the design's
job is to make weakening **non-silent** through the normal flow, keep the ordinal
knobs **structurally** strengthen-only, and never overclaim an airtight property
that mpd (which never runs the model) fundamentally cannot verify.

**Trust boundaries reviewed:** `.mpd/config.json` (`personas` block) and
`.mpd/directives/personas/*.md` (base-directive overrides) as the two weakening
vectors; the `mpd next` brief as the config→harness carrier; the `GateRecord`
ledger as the durable audit surface; the reuse/dependency snapshot as the
receipt-validity boundary. No credentials, no network egress, no new file I/O on
untrusted input beyond config/directive reads that already exist.

## Review history — four adversarial rounds (novel integrity surface)

Reviewed at full depth per the novel-surface rigor rule; no findings fixed inline;
re-run after each revision. Every finding below was cross-checked against the real
code, and the design was revised until the closures held.

- **Round 1 — FAIL.** Three silent-weakening paths: (F1) the high-risk effort floor
  inheriting `model_for_governed`'s `model == builtin_default` clause → a custom
  model pin disabled the floor; (F2) the `--reuse` `GateRecord` site left tuning
  unstamped + `personas` not a bound dependency; (F3) `next`→`gate` TOCTOU
  (`set → next → reset → gate` recorded a gutted review as clean); plus (F4) a
  wrong-token config-leniency revert and (F5) keying/compose/byte-identity fixes.
- **Round 2 — FAIL.** The F3 fix backfired: making `next` an UNCONDITIONAL writer
  broke inertness, and "overwrite-to-clean" re-briefing SANCTIONED a laundering path;
  the leniency fix still failed on wrong-TYPE tokens; the dependency binding
  over-staled (whole-`Config` digest); "orchestration tier fully closed" overclaimed.
- **Round 3 — FAIL.** The remaining asymmetry: the config `directive_append` vector
  was TOCTOU-hardened, but the OTHER un-rankable vector — a base directive-file edit
  (`modified:true`) — was still computed LIVE at gate, re-opening
  `edit directive → next → restore → gate`. Plus the monotonic MERGE was untested,
  and `String::max` on effort inverted (`"high" < "medium"` lexically).
- **Round 4 — CONDITIONAL PASS.** All prior FAILs confirmed genuinely closed against
  the code (both vectors now symmetric in stamp AND dependency paths; `root` present
  at all four `capture_dependency_values` sites; `history` survives rewind so
  `(phase, attempt)` keying is sound; golden-table/causality audit satisfiable with
  `PersonaTuning ⇒ DesignMock`). No new Critical/High. Four closable conditions.

## Conditions for Builder

The design's Conditions 1–12 (design.md) are reviewed sound and complete for the
threat model. The four round-4 conditions below MUST be honored; #1 is load-bearing
(it guards the round-3 directive-vector closure) and its closing evidence is a
Security (code) obligation.

1. **[F4-1, load-bearing]** The `base_modified` computation + `brief_tuning` write in
   `cmd_next` MUST be **unconditional and pre-branch** (~cli.rs:1112, immediately
   after `brief()`, before the `--full`/`--context`/`--json` branches) — NOT gated
   behind `if full`. If it hung off `--full`, a plain `mpd next` would record
   nothing and the gate's absence-fallback would become a LIVE `for_persona` read,
   re-opening the R3-F1 TOCTOU. **Closing evidence:** R11(d) drives the directive
   revert via a PLAIN `mpd next` (no `--full`); Security (code) greps `cmd_gate` and
   confirms NO `directives::for_persona` call in the stamp path (derive-from-record
   only). Owner: Builder + Tester; verified at Security (code).
2. **[F4-2]** Resolve the persona directive ONCE per `next`, shared between the
   `base_modified` record and any `--full`/`--context` display (no within-process
   double-read). Owner: Builder.
3. **[F4-3]** `mpd persona set` MUST reject an unknown persona NAME (allow only the
   `tuning_key` set incl. `"DocValidation"`), not just an unknown value — else a
   fat-fingered `Secuirty` silently writes inert config rot and no-ops a
   strengthening the operator believes they applied. Owner: Builder.
4. **[F4-4]** Document the one-time staleness of in-flight governed receipts on
   upgrade (a pre-upgrade Security/Test/DocValidation receipt lacking the
   `PersonaTuning` key goes `Stale` on first post-upgrade re-eval — accepted
   fail-safe, identical to any dependency-policy evolution). Owner: Documenter.

Additional standing conditions carried from the design (not re-litigated here):
Cond 1 byte-identical baseline (brief + `--json` + ledger file); Cond 2
permissive-`Value` leniency; Cond 3 ordinal effort rank (no `String::max`); Cond 4
floor predicate without the model clause; Cond 5 sanitize + `weakened` iff
carried-`Some`; Cond 6 both `GateRecord` sites + narrow `DependencyKey::PersonaTuning`
(config tuning + directive text); Cond 8 `reviewers` additive, never gates the dual;
Cond 9 phase-keyed base-modified from the record; Cond 10 strict + artifact
retention; Cond 11 conditional + monotonic-merge + match-or-fallback; Cond 12
doctrine + strict advisory.

## Verdict

**CONDITIONAL PASS.** All rounds-1–3 silent-weakening paths are genuinely closed and
verified feasible against the code; no Critical/High remains; the two weakening
vectors are symmetric in both the stamp and dependency paths; two-tier neutrality
holds (empty `personas` + unmodified directives ⇒ byte-identical brief, `--json`,
and ledger file after `next`; no new gate/CONDITIONAL/stuck-state). The four
conditions above are closable with concrete evidence and none leaves the
silent-weakening invariant open. Condition 1 touches the exact surface that produced
three prior FAILs, so Security (code) is **mandatory at full depth** and MUST re-run
after any fix — no inline fixes on this integrity surface. Proceed to Build.
