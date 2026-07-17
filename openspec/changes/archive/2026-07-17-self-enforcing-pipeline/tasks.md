Canonical current checklist. Superseded plans go to `history/`.

## 1. Durability core (the priority)

- [ ] 1.1 Ledger schema: add `Ledger.strict: bool` (write-once/monotonic) + `Waiver { phase, reason, attempt, at_epoch_secs }` (attempt-scoped) + `Ledger.waivers: Vec<Waiver>`, all `#[serde(default)]`. `invalidate_from_security` drops/marks rewound-phase waivers. Legacy round-trip + inert-when-false + monotonicity tests. (ledger.rs)
- [ ] 1.2 `Phase::judgment_artifact() -> Option<(filename, &[required sections])>` and `Phase::upstream_context()`. Unit-tested against skip rules. (phase.rs)
- [ ] 1.3 Refactor `check_documentation` → `check_sections(text, &[&str], min_len)`; wrapper preserves byte-identical behavior. Equivalence test. (cli.rs)
- [ ] 1.4 Judgment templates `assets/templates/judgment/{security-plan,security-code,design-review,design-signoff,test,doc-validation}.md` with required `##` sections (security-code carries conditional Independent review / Refutation). Embed via `include_str!`. (assets + scaffold.rs)
- [ ] 1.5 `mpd brief <phase>` (`Command::Brief`): `scaffold::write_new` the template if absent (symlink-refusing, never overwrites). (cli.rs, scaffold.rs)
- [ ] 1.6 `mpd conduct <name>` + `mpd begin --strict`: begin + set `strict=true` + seed current-phase stub + print the call-loop contract. (cli.rs, scaffold.rs, ledger.rs)
- [ ] 1.7 Strict gate branch in `cmd_gate` (clone the doc-check branch) + `validate_evidence` (assert_contained + exact own-artifact equality + omitted→default-to-artifact, no content read) + `--waive-artifact` (attempt-scoped) + enforce the artifact check on the `--reuse` early-return path too. Strict refusals print the escape. (cli.rs)
- [ ] 1.8 Archive strict re-check: extend the `artifact_stub_issues` call in `cmd_archive` with the applicable-judgment-phase `check_sections` sweep. (cli.rs)

## 2. Stuck-robustness

- [ ] 2.1 `mpd use <change>` (`Command::Use`) over `set_current` (validate name + ledger exists). (cli.rs, ledger.rs)
- [ ] 2.2 `mpd doctor --fix`: add-only `.mpd/.gitignore` heal + test-command sanity (flag `true`/`:`/empty/no-pass-count) + phase stall age. Bare doctor gains stall/sanity lines. (cli.rs)
- [ ] 2.3 Archive transient-path pre-flight (warn/refuse on `--yes` when an in-scope transient path is un-gitignored) + test-gate no-pass-count hint. (cli.rs)

## 3. Adversarial + context (SHOULD)

- [ ] 3.1 Model bump: thread `governance.risk` into `harness::model_for`; override standard tier for Security/Tester at High with a note; extend the `valid_model_id` proptest. (harness.rs, config.rs)
- [ ] 3.2 `mpd next --context`: phase-slice render + `extract_section`; enrich `--json` with `artifact_path` + strict `gate_command`. (cli.rs, harness.rs)
- [ ] 3.3 `mpd status --brief` + gate-history windowing (~12 events); `--json` unchanged. (cli.rs)
- [ ] 3.4 Autonomous-reconcile policy: `mpd reconcile --autonomous --reason`; strict `mpd next` surfaces halt-and-report; downgrade refused. (cli.rs, ledger.rs)

## 4. Routing + dogfood

- [ ] 4.1 Rewrite `AGENTS_MD` + `assets/directives/protocol.md` with a "Two ways to drive mpd" section (humans → manual verbs; harnesses → `mpd conduct`; both learn the escape verbs). (scaffold.rs, assets)
- [ ] 4.2 Dogfood: run this change under strict; its own judgment artifacts must exist and survive archive (the regression against the evaporation it fixes).

## Risk-to-test matrix

- [ ] R1 `strict=false` gate is byte-identical to today → inert-branch test (1.1/1.7).
- [ ] R2 Legacy ledger (no strict/waivers) deserializes + re-serializes clean → round-trip test (1.1).
- [ ] R3 Judgment gate refuses without its artifact; passes when filled; `--evidence smoke` rejected; evidence must be the phase's own artifact → gate tests (1.7).
- [ ] R4 Archive refuses when a judgment artifact evaporated post-gate; `mpd brief` re-creates + archive succeeds → anti-evaporation test (1.8).
- [ ] R5 `--waive-artifact` bypasses only the strict judgment check, never tests/secret/doc/deploy, never a FAIL; bounded + terminal-safe → waiver tests (1.7).
- [ ] R6 `mpd use` restores `.mpd/current` after `closure abandon` → recovery test (2.1).
- [ ] R7 `doctor --fix` is add-only + idempotent + touches only `.mpd/.gitignore`; dirty→refuse→fix→archive-succeeds end-to-end (2.2/2.3).
- [ ] R8 `risk=High` changes the resolved Security/Tester model on a default-init project; only strengthens; unsafe id still degrades → proptest (3.1).
- [ ] R9 Autonomous reconcile continues on continue/narrow but halts on any downgrade (3.4).
- [ ] R10 Symlinked/oversized artifact or evidence reads as empty and fails structurally, never followed; evidence validation exfils nothing (1.7, Conditions 1–2).
- [ ] R11 Waiver is attempt-scoped: waive security-code (attempt 1) → `reconcile --threat-profile …` rewind → the attempt-2 re-run demands the artifact again (B1).
- [ ] R12 Gate-time waiver → archive succeeds with the phase shown WAIVED (not a dead-end) (B2).
- [ ] R13 Strict `mpd gate <phase> --reuse <receipt>` still requires the phase's own non-stub artifact (B3).
- [ ] R14 Autonomous mode refuses ANY threat-profile change + any Security-phase `--waive-artifact` + any risk downgrade; allows continue/narrow + risk upgrade (B4, A4).
- [ ] R15 `doctor --fix` fails closed (no write) when `.mpd/.gitignore` is a symlink/oversized; never touches config.json (A2).
- [ ] R16 Model bump elevates a seeded-default Security/Tester at risk=High but leaves a user-customized pin untouched (A3); `strict` is write-once/monotonic (A6).
- [ ] R17 `--waive-artifact` is rejected with `--reuse` (before the reuse early-return), requires `--pass`, and is rejected on a non-judgment phase; under `--autonomous`, `gate security-code --reuse <r> --waive-artifact "x"` never yields a silent reused PASS (re-review new gap, M1).
