# Security (plan) review

## Actor

Security

## Threat model

### Trust boundaries and assets

This change edits the repo's own defensive tooling, so the primary asset is
the tooling itself:

- **Production detection strength.** `checks/secrets.rs` rule literals at :107
  and :113 are the matcher's ground truth. Two rules match bare prefixes
  (slack-token is a bare `contains`; private-key-block is a two-substring
  `contains`), so their own definition lines are the self-match sites — and the
  same bareness means a botched split would silently stop matching real
  tokens. This is the highest-value line-level edit in the change.
- **Push-authorization identity.** The two digest tags at
  `local_validation.rs:6519-6520` are domain-separation constants, not
  secrets: `scanner_digest`/`rules_digest` are fields of `PushAuthorizationV1`,
  which feeds `digest_json` → `push_authorization_id` (:6259), verified on
  save and load (:6276, :6309). Changing their bytes changes every future
  authorization id and silently shifts audit semantics.
- **Gate authority.** The whole-file suppressions in
  `.mpd/secret-allowlist.json` and the `secretAllow` mirror in
  `.claude/pipeline-gates.json` are the blindness that caused the incident;
  removing them is the point of the change.

Adversaries considered: (1) the accidental insider committing a real
credential into first-party source — the incident class; (2) a future
contributor whose refactor of the split literals silently weakens detection;
(3) drift between the guard and the scanner; (4) divergence between mpd's rule
set and GitHub push protection's.

### Attack 1 — does splitting the scanner's own rule literals change detection?

**No — the mechanism is provably safe; the residual risk is edit fidelity,
and it is currently unpinned for Slack.**

- `concat!` on string literals is compile-time concatenation producing a
  `&'static str`; the matcher receives byte-identical patterns. There is no
  runtime assembly path that could diverge.
- Verified through a line-faithful port of `scan_line`: the exact D1
  replacement lines for :107 and :113 produce zero findings as source text,
  while the assembled runtime patterns still classify a Slack prefix, an AWS
  key shape, and a joined key-block armor pair correctly.
- **Gap found:** byte-identity of a split literal cannot be asserted textually
  — writing `assert_eq!(concat!(..), "…")` would reintroduce the contiguous
  text. The only possible pin is behavioral. `private-key-block` has such a
  pin (`detects_private_key_block`); **slack-token has zero positive detection
  coverage anywhere in the test suite** (the secrets.rs module covers AWS,
  key-block, generic, stripe, openai, jwt, github; nothing asserts
  `scan_line` returns slack-token). A typo while splitting :113 — e.g. a
  wrong fragment — would weaken the production scanner with no failing test.
  Condition 11 closes this.

### Attack 2 — allowlist removal: order safety and restored coverage

- **Enumeration independently reproduced.** A faithful port of `scan_line` +
  `suspicious_filename` run over every regular file under `crates/`
  (excluding `target/`) reports exactly the 13 enumerated findings — same
  files, lines, and rules — including the non-`.rs` assets and manifests the
  design's `*.rs` sweep did not cover. Run over all git-tracked files outside
  `openspec/changes/archive/**`, it reports exactly 15: the 13 plus the two
  `secretAllow` mirror lines in `.claude/pipeline-gates.json`. Every one is
  eliminated by this change, and **no other content anywhere relied on the
  three whole-file suppressions** — removal restores coverage without
  blocking anything legitimate; task 3.3 is achievable.
- **Coverage genuinely restored, twice.** The mpd gate regains authority over
  the three files; and the `secretAllow` regexes in the hook suppressed
  matching *added lines anywhere in the repo*, not just in those files — so
  their removal also restores hook coverage repo-wide.
- **Commit ordering is safe as planned.** Narrowing after meta-test green
  (D4, tasks §3) means no commit is made with live findings unsuppressed. The
  removal commit itself cannot self-block: the hook scans only added diff
  lines (the raw literals appear only as deletions), and mpd's staged scan
  reads postimages, which are clean after removal.
- **Gap found — the pre-push outgoing scan is not covered by D4's ordering.**
  `scan_outgoing_objects` (`local_validation.rs:6727`) loads the allowlist
  from the working tree *at push time* and scans **every outgoing blob,
  including intermediate commit states**, with no grandfathering. If the
  Builder splits a file across multiple commits and any intermediate blob of
  `secrets.rs`, `local_validation.rs`, or `pipeline-gates.json` still carries
  contiguous matchable text, the push performed after narrowing is denied —
  and once archived, that history cannot be rewritten without recreating the
  exact `publish --verify` breakage this change exists to prevent. The
  commit gate cannot catch this (it was still suppressed at commit time).
  Condition 12 closes this.

### Attack 3 — meta-test integrity

- **Production-code reuse holds, with one trap.** Calling
  `secrets::scan_paths` directly gives identical windowing, size caps, lossy
  decoding, and filename rules — no parallel pattern list. But the crate also
  exports `checks::scan_secrets`, which wraps `scan_paths` in
  `unwrap_or_default()` (`checks/mod.rs:176`) — a fail-open that converts any
  scan error into "clean". The meta-test must not go through it
  (Condition 13). (That same fail-open sits in the tracked-files gate path;
  out of scope here, flagged as a separate task.)
- **Fail-closed walking verified as designed:** unreadable, oversized, or
  non-regular inputs surface as `scan_paths` errors that fail the test; the
  design correctly refuses to inherit `.mpd/secret-allowlist.json`.
- **Empty allow structure is achievable.** Every D3 replacement recipe was
  pushed through the scan port: all produce zero findings as source text, and
  every assembled runtime value still triggers its intended rule. 13 → 0 with
  zero allow entries is real, not aspirational.
- **Defeat scenarios probed:**
  - *Vacuous pass:* the walker roots at `CARGO_MANIFEST_DIR/../../crates`; if
    that resolution ever drifts (vendored source, moved crate), an empty or
    wrong walk would scan nothing and pass green. Condition 14 requires the
    walked set to prove it contains the tree it claims to guard.
  - *Nested `target/` shadow:* skipping any `target` path component would
    also skip a deliberately created `crates/**/target/` directory. For
    tracked files the un-blinded commit gate backstops this (the builtin gate
    has no target exclusion; only gitleaks' config does). Residual accepted
    for untracked files, which never reach a push.
- **Honest residual — self-consistency, not GitHub parity.** The guard
  enforces that mpd's own scanner finds nothing in first-party source. GitHub
  push protection runs a different, larger, evolving rule set; a future
  fixture matching a GH-only rule would still trip GH013 post-archive. That
  residual is acceptable because the actual incident was *not* a rule-set
  gap: mpd's rules matched the fixture and the allowlist suppressed the
  finding. This change fixes that root cause; gitleaks in the gate lane
  provides the wider independent rule set. The remaining exposure should be
  named in the documentation phase, not papered over.
- Retained archive suppression (`openspec/changes/archive/**`) remains a
  deliberate blind spot for mpd's gate only; GitHub and gitleaks still see
  archive content. Pre-existing posture, unchanged by this plan.

### Attack 4 — production digest tags

- The tags are authorization-identity inputs (see assets above). `concat!`
  hoisting is compile-time and byte-identical; `.as_bytes()` on the hoisted
  `&str` consts feeds `Digest::of_bytes` the same bytes as today's byte-string
  literals. Push-authorization identity cannot move if the edit is correct.
- **Gap found — a circular pin proves nothing.** If the Builder computes the
  expected hex *after* refactoring, from the refactored code, the assertion
  would pin whatever the refactor produced — including a corrupted value. The
  expected hex values must be captured from the current, pre-change literals
  (Condition 15).
- **Trap verified concretely:** a naive pin such as
  `assert_eq!(Digest::of_bytes(SECRET_RULES_TAG.as_bytes()).to_hex(), "<64 hex chars>")`
  is itself a generic-secret-assignment finding — the line carries a keyed
  word in the const name and a quoted 20+ char alphanumeric value. Verified
  through the scan port; the meta-test would catch it (the system fails
  closed), but the recipe is prescribed in Condition 15 to avoid a
  red-loop: bind the expected hex on a line with no secret-ish keyword
  (e.g. `let expected_outgoing = "…";`), which the port verifies clean.

### The design's Conditions for Builder

All ten reviewed against the code. Each is sound, none weakens the scanner,
and together they cover byte-identity, production-code reuse, empty-allow
discipline, no-rule-change, split-not-exempt, digest pinning, red-before-green
evidence, D4 ordering, fail-closed walking, and artifact hygiene. This
change's own markdown (proposal/design/tasks/spec delta and this review) was
scanned with the port: clean. The additions below are supplements closing the
gaps found above, not replacements.

## Conditions for Builder

Conditions 1–10 of `design.md` are adopted verbatim and remain binding. In
addition:

11. **Behavioral pin for every split rule literal — Slack especially.** In the
    same change as splitting `secrets.rs:113`, add positive detection tests
    that assemble each of the three Slack prefixes at runtime from split
    fragments and assert `scan_line` classifies them as slack-token; the
    existing `detects_private_key_block` and `detects_aws_key` tests stay
    green and unmodified. Prevents: a typo in the split silently disabling
    Slack detection — the one rule whose split currently has no test to fail,
    and byte-identity cannot be asserted textually without reintroducing the
    contiguous literal.
12. **Push-safe commit topology.** No commit in the range eventually pushed
    may contain a blob of `crates/mpd/src/checks/secrets.rs`,
    `crates/mpd/src/local_validation.rs`, or `.claude/pipeline-gates.json`
    that carries contiguous scanner-matchable text: land the conversion and
    the narrowing as a single commit, or verify each intermediate commit
    leaves every touched formerly-suppressed file fully clean. Prevents: the
    pre-push outgoing scan (working-tree allowlist over *all* outgoing blobs,
    `local_validation.rs:6727`) permanently wedging an archived history — the
    incident class, self-inflicted.
13. **No fail-open wrapper.** The meta-test calls `secrets::scan_paths`
    directly and propagates every `Err` (including walker/`read_dir` errors)
    into test failure. It must not use `checks::scan_secrets`, whose
    `unwrap_or_default()` (`checks/mod.rs:176`) turns scan errors into a
    clean report. Prevents: an unreadable or non-regular file silently
    passing the guard.
14. **Vacuous-pass guard.** Before asserting zero findings, the meta-test
    asserts the walked file set is non-empty and includes
    `checks/secrets.rs` itself (path-suffix check). Prevents: repo-root
    resolution drift turning the guard into a green no-op.
15. **Non-circular, scanner-clean digest pin.** The two expected digest hex
    values are computed from the *current pre-change* literals and recorded
    in the red-baseline evidence before any refactor of
    `local_validation.rs:6519-6520`; the pinning assertion binds each
    expected hex on a line containing no secret-ish keyword, per the verified
    recipe above. Prevents: a pin that would bless a corrupted tag value, and
    a pin assertion that itself fails the meta-test.

## Verdict

CONDITIONAL PASS

**Judgment:** this change strengthens detection without weakening the
production scanner or altering authorization identity — subject to the
conditions above. It removes the exact suppressions that blinded mpd where
GitHub was not (verified: those entries covered nothing but the 15
now-eliminated self-matches), adds a guard that reuses the production scanner
verbatim so it cannot drift, and the split recipes are verified byte-identical
at runtime and invisible to every rule as source text. The scanner's rule
logic is untouched; the digest-tag bytes are compile-time provably unchanged
and doubly pinned.

Closing conditions: 11–15 above. Owner: Builder. Closing evidence: the red
baseline recording exactly 13 findings plus the two pre-change digest hex
values (15); the new Slack detection tests green (11); meta-test green with
`SOURCE_HYGIENE_ALLOW` empty and the non-empty-walk assertion present
(13, 14); commit topology showing a single commit — or per-commit-clean
touched files — at pre-push time (12). Security (code) re-review verifies all
five before Test; any refused condition converts this verdict to FAIL.
