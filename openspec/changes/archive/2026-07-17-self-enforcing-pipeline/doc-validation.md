# Doc Validation: self-enforcing-pipeline

Validation of `documentation.md` against the shipped implementation (deep tier;
Architect + Designer perspectives). This change has no UI surface, so the
Designer lens covers the CLI's interaction/output surface rather than a GUI.

## Architect lens

Validated the doc's factual claims against the on-disk code:

- Two-tier model (per-change `strict` bit; `mpd conduct`/`begin --strict` set it;
  manual tier byte-identical) — matches `Ledger.strict`, `cmd_conduct`, the
  `strict`-gated branch in `cmd_gate`. ✓
- Judgment-artifact section mapping (Security plan → Threat model/Conditions for
  Builder/Verdict, etc.; Architecture → design.md `Conditions for Builder`) —
  matches `Phase::judgment_artifact()` (phase.rs) exactly. ✓
- Evidence resolution (strip `#anchor`, reject absolute/`..`, `assert_contained`,
  own-artifact equality, default-to-artifact) — matches `validate_evidence`. ✓
- Waivers (bounded, attempt-scoped, dropped on rewind, WAIVED banner, never
  bypass objective gates / convert a FAIL, rejected with `--reuse`, autonomous
  Security-phase halt) — matches `cmd_gate` + `invalidate_from_security`. ✓
- Anti-evaporation (reuse-path check + archive re-check + containment on
  change-dir/`.mpd` reads) — matches the strict `--reuse` branch, the archive
  sweep, and `read_contained`. ✓
- Model bump note "risk=high → deep tier" — matches harness.rs:238. ✓

**One inaccuracy found and corrected.** The doc described `mpd next --context
--json` as emitting `artifact_path`; the actual `Brief` field is `artifacts`
(`Vec<String>`) alongside `gate_command`. Both mentions were corrected to name the
real fields. No other drift.

## Designer lens

The CLI interaction surface is consistent and discoverable: `mpd --help` lists
`conduct`/`brief`/`use` with intent-revealing one-liners; every strict refusal
prints its escape (`mpd brief <phase>` / `--waive-artifact`), so a human or a
harness parsing stderr is never left at a dead end; the WAIVED banner and the
archive audit summary surface waivers visibly. The manual/orchestration split is
presented as "two ways to drive mpd," matching the routed `AGENTS.md`/protocol
doctrine. No naming/pattern drift from the established verb vocabulary.

## Verdict

**PASS** (after the `artifact_path` → `artifacts`/`gate_command` correction).
`documentation.md` accurately and completely describes the shipped behavior —
Purpose/Value/Scope/Functional details/Usage all present and grounded in code,
with every command and section name verified against the implementation.
