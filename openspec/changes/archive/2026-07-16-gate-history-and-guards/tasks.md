# Tasks: gate-history-and-guards

## 1. Gate history (crates/mpd/src/ledger.rs)
- [ ] 1.1 Add `pub struct GateEvent { pub phase: Phase, pub record: GateRecord }` (Clone, PartialEq, Eq, Serialize, Deserialize).
- [ ] 1.2 Add `#[serde(default)] pub history: Vec<GateEvent>` to `Ledger`; empty in `Ledger::new`.
- [ ] 1.3 `record`: push `GateEvent { phase, record: record.clone() }` to `history` before `gates.insert`. Advancement logic unchanged.
- [ ] 1.4 Tests: FAIL then PASS -> history==[Fail,Pass], gates==Pass, phase advanced; a JSON string without `history` deserializes with empty history and round-trips.

## 2. Stub-artifact guard (crates/mpd/src/cli.rs)
- [ ] 2.1 `fn artifact_stub_issues(project, change) -> Vec<String>` reading proposal/design/tasks.md via `read_capped`; flag `<!--` / missing / empty.
- [ ] 2.2 `cmd_archive`: refuse (exit 1) when non-empty, before applying the archive.
- [ ] 2.3 `cmd_status`: append the stub issues to the "not ready" reasons.
- [ ] 2.4 e2e test: archive blocked on a stub design.md; succeeds when all three are filled.

## 3. status history + nudge (crates/mpd/src/cli.rs)
- [ ] 3.1 `cmd_status`: render a chronological "Gate history:" section from `ledger.history`.
- [ ] 3.2 `cmd_status` JSON: include `history`.
- [ ] 3.3 `cmd_status`: print the next-action nudge (mpd next / resolve / archive) at the end.

## 4. init .mpd/.gitignore (crates/mpd/src/scaffold.rs)
- [ ] 4.1 `init`: `write_new(.mpd/.gitignore, "/current\n/tmp/\n")`.
- [ ] 4.2 Test: init creates `.mpd/.gitignore` containing `current`.

## 5. Verify
- [ ] 5.1 `cargo test --workspace` green; `cargo build` clean; `cargo clippy --workspace` clean.
