# Security (code) review

## Actor

Security

## Findings

None. This is an actual audit of the shipped files, not a restatement of the plan
review. Reviewed scope: `/CLAUDE.md` (untracked, 9 lines) and `/AGENTS.md`
(122 lines, byte-identical to HEAD `bd7f92c` — `git diff HEAD -- AGENTS.md` is
empty, so the on-disk file reviewed here is exactly the committed content).
Omitted scope: `README.md` (owned by `local-first-verification-hardening`),
`crates/`, `.mpd/` configuration, and this change's own provenance artifacts.

Audit performed on the real bytes:

- **Prompt-injection / hidden-content scan.** Full codepoint enumeration of both
  files: the only non-ASCII characters are U+2014 (em dash, CLAUDE.md:1,
  AGENTS.md:31) and U+2192 (arrow, CLAUDE.md:4) — no bidirectional or
  directional-isolate controls (U+2066–U+2069, the class `harness.rs` itself
  sanitizes against), no zero-width characters. No URLs, HTML comments,
  markdown link targets, or data URIs in either file — nothing that steers an
  agent to fetch or trust remote content. No instruction weakens a gate; the
  only bypass-adjacent phrases are prohibitions (AGENTS.md:95 forbids
  `--no-verify`, force push, destructive reset, source-tree secrets).
- **Gate-steering integrity.** The delivered text reinforces the loop
  (`conduct` → `next` → work → `gate`), the FAIL-blocks rule, and the
  local-first trust boundary; nothing in either file could be cited by a future
  autonomous session as authority to skip or weaken a phase.
- **Secrets.** Pattern scan (API key/token/password/private-key/AWS/GitHub-token
  shapes) over both files: no hits.

## Conditions verified

- **C1 (pointer only) — HOLDS.** `CLAUDE.md` is 9 lines: read `AGENTS.md`, the
  loop's shape in one parenthetical, and the `--harness claude-code` flag with a
  deferral to AGENTS.md's "Harness and model selection". No model table or loop
  detail is duplicated, so no two-copy drift surface exists.
- **C2 (no `--harness` on `conduct`) — HOLDS.** Grep of both files: every
  `--harness` occurrence is on `mpd next` or in the explicit corrective prose
  "`mpd conduct` takes no `--harness` flag" (AGENTS.md:31). The loop block shows
  `mpd conduct <change>` bare (AGENTS.md:12). Verified against the CLI source:
  the `Conduct` variant (crates/mpd/src/cli.rs:77–95) defines `name`, `ui`,
  `fix`, `chore`, `risk`, `threat_profile` — no harness field; `harness` belongs
  to `Next` (cli.rs:660–666).
- **C3 (exact harness values) — HOLDS.** The only harness values in prose are
  `claude-code` (AGENTS.md:22, CLAUDE.md:7) and `codex` (AGENTS.md:25), both
  exact matches for `builtin_default`'s arms (crates/mpd/src/harness.rs:316).
- **C4 (model prose matches resolution) — HOLDS.** Verified against
  `crates/mpd/src/harness.rs` and `crates/mpd/src/phase.rs`, not the plan's
  word: `builtin_default` (harness.rs:316) resolves claude-code → fable (deep) /
  sonnet (standard) and codex → sol (deep) / terra (standard);
  `builtin_fallback` (harness.rs:343) maps fable → opus and nothing else;
  `Phase::is_deep` (phase.rs:235–240) is exactly {DesignMock, DesignReview,
  DesignSignoff, Architecture, DocValidation}, matching the prose "Design,
  Architecture, Doc Validation"; `.mpd/config.json:239` sets the codex
  Documenter override to `luna`. The `mpd next`-is-authoritative clause is
  retained: "treat that output as authoritative over any prose table, including
  this one" (AGENTS.md:29–30).
- **C5 (no secrets, no scope creep) — HOLDS.** No secret-shaped content in
  either file (scan above). Delivered surface is `CLAUDE.md`, `AGENTS.md`, and
  `openspec/changes/harness-aware-agent-docs/` only; `README.md`'s stale
  `conduct --harness` example is untouched, as recorded in the plan's exclusion.
- **C6 (prose never outranks `mpd next`) — HOLDS.** The deferral clause is
  present verbatim at AGENTS.md:29–30 and directly follows the model bullets it
  governs, so the flat "every other phase resolves to Sonnet/Terra" default-risk
  mapping cannot be cited over the binary. The governance behavior that makes
  this clause load-bearing is real: `governed_model_for` bumps Security/Tester
  to the deep tier at High risk (harness.rs:137–171; test
  `high_risk_bumps_seeded_security_and_tester_to_the_deep_tier`,
  harness.rs:736).

## Independent review

Effective risk for this change is **high** (state file: requested low, derived
high — `deployment-configured`), so a second pass re-derived the facts from
sources the first pass did not lean on: (1) the resolver's own test assertions
(`builtin_defaults_when_config_is_empty`, harness.rs:645;
`builtin_default_covers_every_harness_and_tier`, harness.rs:711;
`builtin_fallback_is_fable_only`, harness.rs:727;
`fable_fallback_note_names_opus`, harness.rs:664) independently pin
fable/sonnet, sol/terra, and the fable→opus-only fallback that the prose
claims; (2) `git diff HEAD -- AGENTS.md` (empty) proves the audited AGENTS.md
is the committed content, not a divergent working copy; (3) a byte-level
codepoint enumeration (Python, ord() over every character) rather than the
first pass's grep-class scan confirmed the non-ASCII inventory is exactly
{U+2014, U+2192}. All three angles agree with the first pass.

## Refutation

Strongest attack attempted: **cite the prose model table to run a Security or
Test gate at Sonnet/Terra on a high-risk change** — the exact
under-provisioning C6 exists to prevent, and this very change demonstrates the
trap (requested low, derived high). The attack fails on three independent
layers: the deferral clause in the delivered text subordinates the table to
`mpd next` output; the spec's "Prose and binary output disagree" scenario
encodes the same rule; and the bump is enforced in the binary itself
(`governed_model_for`), so a session that obeys the documented loop gets the
deep-tier model regardless of what the prose says. Second attack: **plant
steering content in the auto-loaded `CLAUDE.md`** — refuted because the file
contains only a deferral to `AGENTS.md` (no independent instructions to
corrupt), and writing it requires repo write access, the same trust boundary as
the code; the change widens nothing. Third attack: **hidden-Unicode or
remote-fetch steering** — refuted by the byte-level enumeration (benign
typography only) and the absence of any URL or link target in either file.

## Verdict

PASS

All six plan conditions verified against the real files and the real CLI,
resolver, phase, and config sources; zero findings. The shipped text contains
no injection surface, no secrets, no scope creep, and no phrase a future
autonomous session could cite to weaken a gate — it strictly reinforces the
existing gate discipline and subordinates its own model prose to `mpd next`.
