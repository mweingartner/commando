Canonical current checklist. Superseded plans → `history/`.

## 1. clap command tree (cli.rs)
- [x] 1.1 Reorder `Command` enum into Core / Author / Recovery tiers; add a grouped top-level `after_help`; `hide = true` on `Begin` and on `Closure` (D1/D5/D3).
- [x] 1.2 Flatten `Manifest { change: Option<String> }`; delete `ManifestCommand`; dispatch → the same seed logic (D2).
- [x] 1.3 `Archive` gains `--recover`/`--abandon`/`--json`; **route them in `run()`'s `Command::Archive` arm BEFORE `cmd_archive`** (Finding 2); mutual-exclusion vs each other + `--skip-specs` + `--change`; `--json` scoped to recover/abandon; keep hidden `Closure` alias unchanged (D3).
- [x] 1.4 `Gate` `--exploit <STRING>` replaces the 5 exploit flags; `parse_exploit` = split '|' → exactly 5 `bounded_text` fields; **exhaustive 4-arm match making `--exploit` MANDATORY on a Security FAIL** (absence errors), rejected outside Security FAIL; update `cmd_gate` signature + callers (D4/Finding 1).

## 2. Verify
- [x] 2.1 e2e: `mpd begin` still starts a manual change (hidden but functional); `mpd manifest` seeds the stub; **reusing the `AwaitingCommit` setup, `mpd archive --recover`/`--abandon` reach the recovery/abandon logic (NOT the "already pending" refusal)** and match the hidden `mpd closure …` alias (Cond 1/3, Finding 2). Load-bearing.
- [x] 2.2 e2e: a well-formed `--exploit` on a Security FAIL records all 5 fields; a malformed `--exploit` (≠5 / blank) is REFUSED; **a Security FAIL with NO `--exploit` is REFUSED**; `--exploit` outside a Security FAIL (incl. with `--reuse`) is REFUSED (Cond 2, Finding 1). Load-bearing (revert the presence/count/blank guard → red).
- [x] 2.3 `mpd --help` lists the core loop first; full suite + clippy + fmt green.
