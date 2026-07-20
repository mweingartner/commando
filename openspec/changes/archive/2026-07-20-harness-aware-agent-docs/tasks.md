
## 1. File edits

- [x] 1.1 Create root `CLAUDE.md`: pointer to `AGENTS.md`'s required operating loop,
  naming `--harness claude-code` and the "Harness and model selection" section; no
  duplicated loop/model detail (C1). (Verified on disk: `CLAUDE.md` is 9 lines, names
  only the loop's shape — `mpd conduct` → `mpd next` → work → `mpd gate` until Done,
  then archive/commit/push/`mpd publish --verify` — plus the `--harness claude-code`
  flag, and defers to `AGENTS.md`'s "Harness and model selection" section for models;
  carries no model table of its own.)
- [x] 1.2 Update `AGENTS.md`: loop shows `mpd conduct <change>` (no `--harness`) and
  `mpd next --harness <harness> --context`; add "Harness and model selection" section
  with the Claude Code and Codex mappings and the `mpd next`-is-authoritative note
  (C2–C4). (Verified on disk: lines 11-16 show `mpd conduct <change>` with no
  `--harness`; lines 18-32 are the "Harness and model selection" section with both
  mappings and the authoritative-output clause.)

## 2. Verification

- [x] 2.1 Grep both files: no `conduct` invocation carries `--harness`; every named
  harness value is one of `generic|claude-code|codex` (C2, C3). (`grep -n -- "--harness"
  AGENTS.md CLAUDE.md` → 6 hits, all on `mpd next`/prose, none on `mpd conduct`; every
  harness value named is `claude-code` or `codex` — `generic` is not named in either
  file, which is permitted since C3 only bounds values that are used.)
- [x] 2.2 Cross-check prose model claims against `builtin_default`/`builtin_fallback`
  in `crates/mpd/src/harness.rs`, `Phase::is_deep` in `crates/mpd/src/phase.rs`, and
  `models.codex.Documenter` in `.mpd/config.json` (C4). (Read `harness.rs:316-348`:
  `builtin_default` gives claude-code deep/std = fable/sonnet, codex deep/std =
  sol/terra; `builtin_fallback("fable")` = `opus`. Read `phase.rs:235-240`: `is_deep`
  = {DesignMock, Architecture, DesignReview, DesignSignoff, DocValidation}, matching
  AGENTS.md's "Design, Architecture, Doc Validation" collective phrasing. Read
  `.mpd/config.json:233-235`: `models.codex.Documenter = "luna"`, matching the AGENTS.md
  parenthetical. All prose values match; the `mpd next`-is-authoritative sentence is
  present verbatim in AGENTS.md lines 29-30.)
- [x] 2.3 Confirm `git status` shows no modifications outside `CLAUDE.md`, `AGENTS.md`,
  and `openspec/changes/harness-aware-agent-docs/`; no secrets introduced (C5). (`git
  status --porcelain` shows ~50 pre-existing dirty/untracked paths belonging to the
  separate in-flight `local-first-verification-hardening` change (confirmed unrelated:
  e.g. `crates/mpd/src/candidate.rs`, `sandbox.rs`, `local_validation.rs`, `scripts/`,
  `security/` — none reference harness/model docs). The only paths attributable to this
  change are `CLAUDE.md`, `AGENTS.md`, `openspec/changes/harness-aware-agent-docs/`,
  and `.mpd/state/harness-aware-agent-docs.json` — the latter is mpd's own governance
  ledger, written by the `mpd conduct`/`mpd gate` calls earlier phases already ran, not
  hand-edited content, and mirrors the pre-existing `.mpd/state/
  local-first-verification-hardening.json` pattern for the other change. `gitleaks
  detect --no-git` on both `CLAUDE.md` and `AGENTS.md` individually: "no leaks found"
  for each.)
- [x] 2.4 Record the deliberate exclusion: `README.md`'s stale
  `mpd conduct my-change --harness codex` example stays untouched (owned by
  `local-first-verification-hardening`). (`git diff -- README.md` shows the file was
  already rewritten by the other in-flight change and still carries
  `mpd conduct my-change --harness codex` (line 25) and `mpd next --harness codex
  --context` (line 28) in its current working-tree content; this change made no edits
  to `README.md`.)
