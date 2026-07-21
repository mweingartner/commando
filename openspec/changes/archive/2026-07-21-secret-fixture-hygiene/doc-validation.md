# Doc validation

## Actor

Architect+Designer

## Architect lens

Both artifacts — `openspec/changes/secret-fixture-hygiene/documentation.md`
(per-change record) and `docs/secret-fixture-hygiene.md` (durable doc) — were
validated against `git diff HEAD -- crates/mpd/ .mpd/secret-allowlist.json
.claude/pipeline-gates.json` and the tree-built test binary. Every cited
symbol, line number, and behavioral claim was checked against the code on
disk, not against the other pipeline artifacts.

- **Split rule literals** — verified at `crates/mpd/src/checks/secrets.rs`
  line 112 (private-key-block, two-substring `contains`) and lines 118–120
  (the three Slack prefixes), exactly as documentation.md cites. `concat!` is
  compile-time concatenation, so the compiled patterns are byte-identical to
  the un-split literals; matcher behavior is unchanged, confirmed by
  `cargo test -p mpd checks::secrets` — 14 passed, 0 failed.
- **Slack prefix pin** — `detects_slack_tokens_for_every_prefix` at
  secrets.rs line 415 asserts all three prefixes (`b-`, `p-`, `a-` after
  `xox`, assembled at runtime) classify as slack-token. The pre-change file
  (via `git show HEAD`) contains `xox` only in the rule-definition line
  itself, so the docs' claim of previously-zero positive Slack coverage is
  accurate, not inflated. test.md line 16 documents the mutation
  verification the record cites.
- **Digest-tag pins** — `OUTGOING_SCAN_TAG` / `SECRET_RULES_TAG` verified at
  `local_validation.rs` lines 6347–6348;
  `push_authorization_digest_tags_are_pinned_to_their_pre_refactor_bytes`
  verified at line 11843 with hardcoded hex pins (non-circular by
  construction). Independently re-derived during this validation — piping
  the pre-change tag byte-strings (old lines 6519–6520 in `git show
  HEAD:crates/mpd/src/local_validation.rs`) through `shasum -a 256`
  reproduces both pinned hex values exactly. Authorization identity provably
  did not move; the docs' claim is not overstated. security-code.md lines
  107–140 record the same independent re-derivation.
- **Meta-test** — `first_party_source_is_scanner_clean` at secrets.rs line
  513 drives `run_scanner_clean_guard` (line 490), which calls the
  production `scan_paths` — never `checks::scan_secrets`, whose fail-open
  `unwrap_or_default()` sits exactly at `checks/mod.rs` line 176 as cited.
  `SOURCE_HYGIENE_ALLOW` at line 332 ships `&[]`. The walk fails closed
  (io errors propagate; a bad root errors rather than reading clean), and
  the vacuity guards assert a non-empty walk that includes
  `checks/secrets.rs` itself. All exactly as both docs describe; the test
  passes in the tree.
- **Efficacy proof** — `guard_catches_a_reintroduced_contiguous_secret` at
  secrets.rs line 565 plants a runtime-assembled contiguous Slack-shaped
  value in a synthetic tree and asserts the guard reports exactly that
  plant (path, line 1, rule), plus the `target/` exclusion, exact
  (path-suffix, rule) allow scoping, and fail-closed behavior on a failed
  walk. Matches both docs' descriptions precisely.
- **Allowlist removal** — `.mpd/secret-allowlist.json` now lists only
  `openspec/changes/archive/**`; the diff removes the three whole-file
  suppressions named in the docs. `.claude/pipeline-gates.json` retains only
  the `test` key; the `secretAllow` mirror (two entries) is removed. The
  record's claim that those entries had suppressed matching added lines
  repo-wide is accurate — `~/.claude/hooks/pipeline-gate.py` line 179
  compiles them as regexes applied to every added line regardless of file.
- **Counts and scope** — the "13 sites, three classes" figure matches
  design.md's enumerated table; the manifest's 7 path patterns are quoted
  exactly; the retained `archive/**` blind spot, the
  self-consistency-not-GitHub-parity residual, and the out-of-scope
  fail-open wrapper are all stated plainly in both docs, not buried.
  Nothing claims more safety than the change delivers — detection is
  strengthened (new positive coverage plus the meta-test), nothing is
  weakened, and zero authorization-identity movement is machine-pinned.
- **Non-material observation** (no doc change requested) — both docs call
  the gitleaks lane "the wider independent net"; `run_external_scanners`
  runs gitleaks only when installed and silently skips it otherwise. That
  is pre-existing gate behavior accurately inherited, but a reader could
  assume gitleaks is unconditionally present. Below the materiality bar.

## Designer lens

- **The split convention for future fixtures** (durable doc, and the Usage
  section of the record) is accurate and directly actionable — `concat!`
  for compile-time literals, `format!` where a fixture binds a shared
  value, applied uniformly to fixtures, assertions, rule literals, and
  production constants. That matches every shipped site in the diff, and
  the "no source text exempt" rationale correctly reflects design decision
  D1's uniform invariant. The doctrine comment the Usage section points to
  exists at the top of the `checks::secrets` test module as described, and
  the advertised command was run verbatim during this validation and
  behaves as documented (failure output gives path, line, and rule).
- **Vocabulary** — both docs speak the change's established language
  exactly — scanner-clean, fail-open/fail-closed, meta-test, first-party
  source, split fragments, (path-suffix, rule), doctrine comment — all
  grounded in the shipped code comments. No invented terms, no drift.
- **One wording nit, non-blocking** — the durable doc says an allow-list
  extension "must be scoped to an exact path and rule"; the mechanism is a
  path-suffix match. The record states the (path-suffix, rule) shape
  correctly, and the intent (per-file, per-rule scoping with a written
  justification) matches the code comment above `SOURCE_HYGIENE_ALLOW`.
  Not material.
- **Critical scanner-cleanliness check** — both files must survive the very
  guard this change adds (and the commit/pre-push gates). A faithful port
  of the production `scan_line` (all nine rules, exact order and semantics
  read from the working tree) was run over both files — 0 findings in
  documentation.md, 0 findings in docs/secret-fixture-hygiene.md — and an
  independent regex grep for every contiguous token shape also came back
  empty. The Usage example's split literals do not self-match (the AWS
  prefix is followed by a brace, and the two private-key substrings never
  co-occur contiguously on any line). The durable doc quotes no
  secret-shaped literals at all, as reported. This validation record was
  scanned the same way after writing.

## Verdict

PASS

Both artifacts are accurate against the built tree, honestly scoped, and
scanner-clean. The two observations above (gitleaks-when-installed nuance,
exact-path vs path-suffix wording) are below the materiality bar and require
no Documenter action.
