# Test report

## Actor

Tester

## Coverage

**Functional — the critical detection pins (pre-existing from Build, verified
meaningful this phase):**

- `detects_slack_tokens_for_every_prefix` (`checks/secrets.rs:415`) — assembles
  a runtime token for **each** of the three prefixes (`xox` + `b-`, `xox` +
  `p-`, `xox` + `a-` tails) and asserts the slack-token rule fires for every
  one. A wrong `concat!` split of any of the three rule fragments at
  `secrets.rs:118-120` turns exactly this test red (mutation-verified in
  Security (code), Refutation 1a). Covers all three prefixes — nothing thin.
- `detects_private_key_block` (`:366`) — the armor-pair rule pinned.
- `detects_aws_key`, `detects_stripe_openai_jwt`, `detects_unquoted_env_assignment`,
  placeholder/ordinary-code negatives, `long_line_is_bounded`, `filename_rules`
  — the remaining rule surface, unchanged in meaning by the splits.
- Digest-tag pins: `push_authorization_digest_tags_are_pinned_to_their_pre_refactor_bytes`
  (`local_validation.rs:11843`) — both hex constants were computed via
  `shasum -a 256` from the **pre-change** literal bytes (non-circular;
  independently recomputed by Security (code), Condition 15). Green.
- Meta-test guard: `first_party_source_is_scanner_clean` (`:513`) — walks all
  of `crates/` (fail-closed walker: `read_dir`/`file_type` errors propagate;
  skips only `target` components and non-regular entries), scans via the
  **production** `scan_paths` (never the fail-open `checks::scan_secrets`
  wrapper), filters through `SOURCE_HYGIENE_ALLOW` which is **empty**
  (`&[]`, `secrets.rs:332`), and is non-vacuous (asserts a non-empty walk and
  that `checks/secrets.rs` itself is in the walk).

**Deepened this phase — new tests (all in `crates/mpd/src/checks/secrets.rs`):**

1. `guard_catches_a_reintroduced_contiguous_secret` (`:565`) — **guard
   efficacy, in-repo**. Security proved the planted-token catch only in an
   out-of-tree scratchpad harness; this makes the proof part of the standard
   suite. The guard body was extracted into `run_scanner_clean_guard` (`:490`)
   and the meta-test now calls the same helper, so the proof cannot drift from
   the guard it certifies. The test plants a runtime-assembled contiguous
   Slack-shaped value (the incident class) in a synthetic temp tree and
   asserts: the shipped guard configuration reports exactly the plant
   (`leaky.rs`, line 1, rule slack-token); the identical bytes under a
   `target/` component are excluded (walk sees exactly 2 files); an allow
   entry excuses only its exact (path-suffix, rule) pair while a wrong-rule
   entry excuses nothing; and a failed walk (missing root) errors instead of
   reading as clean (boundary/error, Condition 9 fail-closed).
2. `detection_is_invariant_to_token_position` (`:656`) — **property /
   metamorphic** (the scanner is a parser-class component; it previously had
   zero property coverage). 64 proptest cases: keyword-free slack / AWS /
   GitHub fixtures are detected **under their own rule** at any padding,
   including lines beyond `MAX_SCAN_LINE` where the match must come from a
   later window via the `SCAN_WINDOW_OVERLAP` straddle; the straddle band
   around the first window boundary is sampled explicitly. Seeded and
   reproducible: failures persist to
   `crates/mpd/proptest-regressions/checks/secrets.txt` (new file, keep it
   committed).
3. `window_truncated_keyworded_token_still_blocks_as_generic` (`:634`) —
   **regression pin for an edge the property discovered on its first run**
   (persisted seed: pad = 4051, which = 2): when the first 4096-byte window
   truncates a `ghp_` tail below its 36-char minimum and the line carries a
   secret-ish keyword, the generic rule fires in that window before a later
   window sees the full curated token. The *label* softens to
   generic-secret-assignment; detection never disappears — a finding is
   produced and the commit blocks either way. Assessed **not a defect** (the
   scanner's contract is finding/blocking, not label identity across
   adversarial window straddles), and pinned so a future "fix" cannot turn
   the softened label into a miss.

**Regression:** the 13-finding incident class cannot silently return — the
meta-test goes red on any contiguous reintroduction under `crates/` (now
proven inside the suite, not just in Security's harness); Slack (all three
prefixes), private-key-block, AWS, and generic detection are pinned by name;
push-authorization digest identity is pinned to pre-refactor bytes.

**Non-functional:** meta-test alone finishes in 0.10s over the entire
`crates/` tree; the whole `checks::secrets` module (14 tests, including the
64-case property run and the temp-tree efficacy test) is 0.14s wall — the
guard adds negligible suite cost. Memory is bounded by the scanner's own caps
(16 MiB/file, 256 MiB aggregate), which the meta-test inherits by calling
`scan_paths`. Load/stress: `long_line_is_bounded` plus the property's
&gt;8 KiB padded lines exercise the windowing DoS defense. Accessibility: n/a
(no UI surface).

**Integration:** Build and Security (code) ran in sandboxed phases with their
receipts recorded in this change's artifacts; the e2e suite (106 tests,
`CARGO_BIN_EXE`-driven) exercises the commit/pre-push gates against the real
binary with the narrowed allowlist in the tree.

**Honest scope note (Security's accepted residual):** the meta-test enforces
*mpd-self-consistency* — first-party source is clean under mpd's own scanner —
not GitHub push-protection parity. Rule classes GitHub has and mpd lacks are
covered only by the gitleaks lane, and files outside `crates/` are owned by
the now-un-blinded commit/pre-push gates, not by this guard.

## Results

All commands run `--offline --locked`; real counts:

- `cargo test --workspace --all-targets --offline --locked` →
  mpd unit **475 passed**, 0 failed, 1 ignored (pre-existing, unrelated; was
  472 + 1 before this phase — the +3 are the new tests above);
  mpd e2e **106 passed**; openspec-core unit **58 passed**; integration
  suites fidelity 5, merge 15, nonfunctional 2, parse-edge 16, project 20,
  props 9, security 5 — **711 passed, 0 failed** total.
- `cargo test -p mpd checks::secrets --offline --locked` →
  **14 passed, 0 failed** (module was 11 before this phase).
- Meta-test green with the allow structure **empty** (`SOURCE_HYGIENE_ALLOW`
  is `&[]` at `secrets.rs:332`; the efficacy test drives the same const).
- Property suites: proptest lanes across config / ledger / harness / digest /
  candidate / git / cli / closure plus openspec-core `props.rs` (9) all green;
  committed seed corpora (`cli.txt`, `config.txt`, `ledger.txt`) re-run before
  novel cases; the **new** `proptest-regressions/checks/secrets.txt` persists
  the discovered boundary case and replays green against the sharpened
  property.
- `cargo fmt --all -- --check` → clean.
  `cargo clippy --workspace --all-targets --offline --locked -- -D warnings`
  → clean.

Bugs found: none. The property test surfaced one boundary behavior on its
first execution (label softening at a window-truncation boundary on keyworded
lines); investigated, assessed within the scanner's blocking contract
(detection is never lost), and pinned as
`window_truncated_keyworded_token_still_blocks_as_generic` rather than
"fixed" — see Coverage item 3.

Dogfood note: every fixture added this phase is itself assembled from split
literals; the meta-test (which scans this phase's new test code and the new
seed file, both under `crates/`) stayed green throughout — the guard policing
its own reinforcement.

## Verdict

PASS

All suites green with real, non-zero counts; the guard's efficacy is now
proven inside the standard test lane; detection pins cover every split
fragment; no test was weakened. Carry-forward (not a test condition):
Security (code)'s single open Condition 12 — land as one commit with a
scanner-clean message, or verify intermediate blobs — is owned by the main
session at commit time and blocks push, not testing. New files for that
commit: `crates/mpd/src/checks/secrets.rs` (test-module additions only) and
`crates/mpd/proptest-regressions/checks/secrets.txt`.
