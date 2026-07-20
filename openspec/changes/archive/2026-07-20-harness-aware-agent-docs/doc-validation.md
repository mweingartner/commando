# Doc validation

## Actor

Architect+Designer

## Architect lens

**Attempt 1 (FAIL) → Documenter fixes → attempt 2 (PASS).** The first pass
found two material accuracy defects; both are now fixed and re-verified
against ground truth, and every previously-verified claim was spot-checked
unchanged.

The two findings and their verified fixes:

1. **Scope README claim (was false present-tense, now accurate history).**
   Attempt 1: the doc asserted README.md "still carries" the stale
   `mpd conduct my-change --harness codex` example and called
   `local-first-verification-hardening` in-flight — false, since that change
   had landed at HEAD `bd7f92c` (phase `done`, deploy gate recorded, archived
   at `openspec/changes/archive/2026-07-20-local-first-verification-hardening`)
   with a corrected README. Fixed: documentation.md:29-34 now states the
   exclusion as history — README "carried" the stale example, fixing it was
   excluded because the file was owned by `local-first-verification-hardening`,
   "which has since landed (`bd7f92c`) and corrected it — README.md:25 now
   reads `mpd conduct my-change` with no `--harness` flag." Re-verified:
   HEAD is `bd7f92c` ("Land local-first-verification-hardening"),
   README.md:25 is exactly `mpd conduct my-change`, and `grep -rn
   "conduct.*--harness" README.md` returns nothing. The ownership history
   matches proposal.md:24-25 and design.md:38/57, which recorded the stale
   example when this change was scoped.
2. **Symbol name (was nonexistent, now exact).** Attempt 1: the doc cited
   `governed_model_for`, harness.rs:137-171 — no such symbol exists in the
   source. Fixed: documentation.md:65-66 now cites `model_for_governed`,
   harness.rs:152-174. Re-verified: `pub fn model_for_governed(` is
   harness.rs:152 and its closing brace is harness.rs:174 — the corrected
   range is exact, tighter than the original (which spanned the doc comment).

All other factual claims re-derived from the working tree, the built binary,
and the change ledger in attempt 1 remain accurate and unchanged:

- **CLAUDE.md is exactly 9 lines** and is a pointer only: defers to
  `AGENTS.md`, names the loop shape in one parenthetical, states
  `--harness claude-code` — no duplicated model table or loop detail
  (CLAUDE.md:1-9; design.md C1 upheld).
- **`mpd conduct` takes no `--harness`**: `Conduct` spans
  `crates/mpd/src/cli.rs:77-95` with fields name/ui/fix/chore/risk/
  threat_profile only; `./target/debug/mpd conduct --help` lists no
  `--harness`. The `harness` field belongs to `Next` (match arm
  cli.rs:660-666; `mpd next --help`: `--harness <HARNESS>` accepting
  `generic`, `claude-code`, `codex`).
- **C6 authority-clause re-check (required on every pass)**: the clause
  "`mpd next --harness <harness>` prints the resolved model for each phase;
  treat that output as authoritative over any prose table, including this
  one" is present verbatim at AGENTS.md:29-30, and
  `git diff HEAD -- AGENTS.md` is empty — the section was not touched by the
  Documenter's revision. The doc's quotation of it (documentation.md:61-63)
  matches byte-for-byte.
- **Tier resolution matches code**: `builtin_default` (harness.rs:316) is
  fable/sonnet for claude-code and sol/terra for codex; `builtin_fallback`
  (harness.rs:343) maps fable → opus and nothing else (pinned by
  `builtin_fallback_is_fable_only`, harness.rs:727). `Phase::is_deep`
  (phase.rs:235-240) is exactly {Architecture, DesignMock, DesignReview,
  DesignSignoff, DocValidation}. Live check: `./target/debug/mpd next
  --change harness-aware-agent-docs --harness claude-code --context` prints
  "model: fable (fall back to opus if unavailable)" for Doc Validation;
  `--harness codex` prints "model: sol".
- **Luna override**: `.mpd/config.json:239` sets `models.codex.Documenter =
  "luna"`. The config's other five codex entries (sol/sol/terra/terra/terra)
  equal the builtin defaults, so Documenter is the only effective override —
  the doc's "specifically, off the Terra default" holds.
- **Risk-bump demonstration**: the ledger
  (`.mpd/state/harness-aware-agent-docs.json`) records `risk_assessment:
  requested "low", derived "high", effective "high"` (reasons:
  deployment-configured, local-validation-process-hook-sandbox-policy), and
  the bump is pinned by
  `high_risk_bumps_seeded_security_and_tester_to_the_deep_tier`
  (harness.rs:736), exactly as the doc cites. C6 is pinned in
  security-plan.md:73 and re-verified HOLDS in security-code.md:65.

Minor, non-blocking (unchanged from attempt 1): "Security (plan) and Security
(code) both pinned this as condition C6" compresses the actual sequence (plan
added C6 as already-satisfied; code re-verified it HOLDS) — acceptable. The
retired symbol name still appears in test.md:45 and security-code.md:65/99,
but those are frozen phase artifacts, not the durable doc; no action.

## Designer lens

No findings in either attempt; the Documenter's revision touched only the two
Architect-lens passages (Scope paragraph, one symbol citation) and introduced
no new vocabulary or surface descriptions. Re-checked after the edit:

- **Usage loops match the real CLI shapes exactly.** `mpd conduct <change>`
  (positional `<NAME>`, no harness flag — `conduct --help`); `mpd next
  --harness claude-code|codex --context` (both flags real, harness values
  exactly the accepted set — `next --help`); `mpd gate <phase> --pass --by
  <actor> --evidence <artifact>` (all three flags confirmed in `gate --help`);
  `mpd publish --verify` exists (`publish --help`). The two per-harness blocks
  are identical except for the harness value, which is the design point.
- **"Until `mpd next` reports Done"** matches the shipped surface
  (`Phase::Done`; README's own loop says "Repeat until phase=done") and
  AGENTS.md:34's "Repeat `next -> work -> gate` until Done".
- **Established vocabulary used as the project defines it**: conduct, next,
  gate, harness, archive, publish --verify, and the deep/standard tier split
  all match AGENTS.md:18-32 and the phase.rs:230-234 doc comment
  ("deep-cognition tier" / "standard model"). Harness values in prose are
  exactly `claude-code` and `codex`. The revised Scope sentence stays in the
  project's own idiom (change ownership, "landed", commit hash) — no drift or
  invented vocabulary. The closing "trust what `mpd next` prints" instruction
  restates AGENTS.md:29-30 rather than paraphrasing it into something new.

## Verdict

PASS

Attempt 1 failed on two material accuracy defects: a present-tense Scope claim
that README still carried the stale `conduct --harness` example (the owning
change `local-first-verification-hardening` had already landed at `bd7f92c`
and corrected it) and a citation of the nonexistent symbol
`governed_model_for`. The Documenter fixed both; re-verification confirms the
Scope paragraph now states the exclusion accurately as history with the landed
commit and current README.md:25 content, and the citation now names
`model_for_governed` with the exact span harness.rs:152-174. The mandatory C6
re-check passes: the authority clause is verbatim at AGENTS.md:29-30 and
AGENTS.md is unmodified. All other claims — CLAUDE.md's 9-line pointer, the
conduct/next flag surfaces, fable→opus and sol/terra resolution, the luna
Documenter override, `Phase::is_deep`, the requested-low/derived-high risk
bump, and both Usage loops — re-verified accurate against the binary, source,
and ledger.
