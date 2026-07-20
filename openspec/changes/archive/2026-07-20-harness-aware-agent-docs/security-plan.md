# Security (plan) review

## Actor

Security

## Threat model

Reviewed scope: `proposal.md`, `design.md` (C1–C5), `specs/agent-onboarding/spec.md`,
and the delivered files `/CLAUDE.md` (new) and `/AGENTS.md` (modified section
"Harness and model selection" plus the corrected operating loop). Omitted scope:
`README.md` (owned by `local-first-verification-hardening`, recorded exclusion),
all code under `crates/`, `.mpd/` configuration.

The change is agent-facing markdown only — no code, credentials, network, or parser
surface. The genuine attack/failure surface of instruction files is threefold:

1. **Agent-steering integrity.** `CLAUDE.md` is auto-loaded into every Claude Code
   session; wrong or ambiguous instructions become wrong autonomous behavior
   (invalid flags, weakened gates, mis-trusted output). Mitigation is factual
   accuracy, which I verified against the binary's source rather than the plan's
   word: `Conduct` (crates/mpd/src/cli.rs:77) defines no `--harness` field
   (C2 confirmed — `harness: String` at cli.rs:125 belongs to `Next`);
   `builtin_default` (crates/mpd/src/harness.rs:316) resolves claude-code →
   fable/sonnet and codex → sol/terra with `builtin_fallback` fable → opus
   (harness.rs:343); `Phase::is_deep` (crates/mpd/src/phase.rs:235) is exactly
   {DesignMock, DesignReview, DesignSignoff, Architecture, DocValidation};
   `.mpd/config.json` `models.codex.Documenter = "luna"`. Every model, flag, and
   harness value named in the delivered prose matches (C3, C4 confirmed).
2. **Prompt-injection surface.** Both files are committed, repo-controlled plain
   markdown. The delivered content contains no encoded/hidden text, no directive
   to fetch or execute remote content, no instruction to trust external output or
   bypass gates; it reinforces the existing gate discipline (`--no-verify`
   prohibition, staged-file rules remain intact). The trust boundary is repo write
   access — identical to the code itself, not widened by this change.
3. **Scope creep.** Delivered edits touch only `CLAUDE.md` and `AGENTS.md`; the
   pointer file defers to `AGENTS.md` rather than duplicating drift-prone detail
   (C1 confirmed), and neither file directs agents at paths outside declared
   scope. No secrets present in either file (C5 confirmed). The
   archive/commit/push/`publish --verify` summary in `CLAUDE.md` compresses the
   pre-existing `AGENTS.md` loop, which is itself gated by the activated local
   hooks and `mpd hook pre-push` authorization — no new release authority is
   created.

Residual finding (mitigated, pinned as C6 below): the sentence "every other phase
resolves to Sonnet/Terra" states the *default-risk* resolution. At governance risk
High, `mpd` bumps Security and Tester to the deep-tier model
(harness.rs test `high_risk_bumps_seeded_security_and_tester_to_the_deep_tier`;
this very review ran deep-tier under derived risk HIGH). An agent trusting prose
over the binary could under-provision an adversarial reviewer on a high-risk
change. The delivered text already carries the mandatory mitigation — "treat that
output as authoritative over any prose table, including this one" — and the spec's
"Prose and binary output disagree" scenario encodes it.

## Conditions for Builder

1. **C1 upheld** — `CLAUDE.md` stays a pointer: no loop or model details beyond the
   harness flag and the loop's shape may be duplicated there. Prevents two-copy
   drift producing contradictory agent instructions.
2. **C2 upheld** — no document may show `--harness` on `mpd conduct`
   (`Conduct`, crates/mpd/src/cli.rs, accepts none). Prevents agents failing on
   an unknown-flag error and improvising around the loop.
3. **C3 upheld** — every harness value in prose is exactly one of `generic`,
   `claude-code`, `codex`. Prevents silent fall-through to the generic tier
   labels on a typo'd harness.
4. **C4 upheld** — model prose matches `harness.rs` resolution (fable/opus/sonnet;
   sol/terra; luna Documenter override) with the deep tier per `Phase::is_deep`,
   and the `mpd next`-is-authoritative clause is retained verbatim in spirit.
   Prevents stale model claims steering phase spawns.
5. **C5 upheld** — no secrets; no files touched outside `CLAUDE.md`, `AGENTS.md`,
   and `openspec/changes/harness-aware-agent-docs/`. Prevents scope creep into
   code, config, or the README owned by another change.
6. **C6 (added)** — the prose model mapping must never be citable as grounds to run
   a gate at a weaker model than `mpd next` prints: the "authoritative over any
   prose table" deferral must survive any future edit of the section, because
   governance risk escalation (High → Security/Tester bump to the deep tier,
   `crates/mpd/src/harness.rs`) makes the flat default-risk mapping conditionally
   wrong. Prevents an under-provisioned Security/Test gate on exactly the changes
   where it matters most. Already satisfied by the delivered text; Security (code)
   and Doc Validation must re-verify the clause is present.

## Verdict

PASS

The plan is sound and its factual basis verified against the real CLI, resolver,
phase, and config sources rather than self-report. C1–C5 are complete for the
declared scope; C6 is added above as an already-satisfied invariant to pin for
downstream review. No threat-model gap, trust-boundary change, or credential
surface exists in this change; the residual model-mapping nuance is mitigated in
the delivered text itself.
