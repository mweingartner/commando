# Security (code) review

## Actor

Security

## Findings

None. Full-depth audit of the real diff (4 files: `crates/mpd/src/checks/secrets.rs`,
`crates/mpd/src/local_validation.rs`, `.mpd/secret-allowlist.json`,
`.claude/pipeline-gates.json`; 5 hunks per source file, diff read in full)
found no defect: detection is strengthened, nothing is weakened, and
push-authorization identity is byte-provably unchanged. No inline fixes were
made (novel-surface rule).

Non-blocking out-of-scope observations, recorded for later work:

- Pre-existing stale doc comment at `crates/mpd/src/checks/secrets.rs:280-281`
  claims oversized files are "skipped for content", but `scan_paths` actually
  fails closed with an error (:305-311). Code is stricter than comment
  (benign direction); untouched by this change.
- The fail-open `checks::scan_secrets` wrapper (`unwrap_or_default()` at
  `crates/mpd/src/checks/mod.rs:176`) remains in the tracked-files gate path.
  Already flagged by Security (plan) as a separate task; this change correctly
  avoids it (see Conditions 13).
- The meta-test walker skips symlinks (`secrets.rs:463-465`). Residual is nil
  for push exposure (Git commits link text, not target content) and
  `scan_paths` refuses symlinks fail-closed if ever handed one (:299-304);
  matches the design D2 posture.

## Conditions verified

Design Conditions 1-10 plus plan Conditions 11-15, each against the code on
disk. Verification tooling: a byte-identical copy of the shipped
`checks/secrets.rs` (diff-verified against the working tree) compiled
standalone in the session scratchpad, driving the real `scan_paths` over
pre-change (HEAD) and current file contents, plus targeted `cargo test -p mpd`
runs in the repo.

1. **Runtime bytes identical, assertions unweakened — HOLDS.** The redaction
   fixture (`local_validation.rs:11823-11841`) assembles byte-for-byte the old
   value: `AKIA` + `IOSFODNN7EXAMPLE`, `xox` + the `b-EXAMPLE…` tail, and the
   old backslash line-continuation collapsed to the same single space the new
   format string emits. Every assertion compares the same strings as before
   (bindings reused; the prefix re-check assembles `xox` + `b-` at :11838).
   Tag/commit message fixtures (:13136, :13158) assemble the identical 24-char
   value; `outgoing_scan_catches_secrets_fresh_despite_preexisting_receipt`
   passes. Scanner test fixtures (`secrets.rs:387, 403, 405`) keep their exact
   outcomes; tests pass unmodified in meaning.
2. **Meta-test reuses production detection — HOLDS.** It calls `scan_paths`
   directly (`secrets.rs:513-514`); no parallel pattern list exists anywhere
   in the test.
3. **Allow structure ships empty, scoped, documented — HOLDS.**
   `SOURCE_HYGIENE_ALLOW` (`secrets.rs:327-332`) is `&[]`, (path-suffix, rule)
   scoped, doc comment requires written justification and bans full-token
   entries.
4. **No weakening of the scanner — HOLDS.** The production diff to `scan_line`
   is exactly two literal-to-`concat!` conversions plus comments (:112,
   :118-120). Thresholds, placeholder list, windowing (`MAX_SCAN_LINE`,
   `SCAN_WINDOW_OVERLAP`), size caps, and every other rule are untouched
   (verified hunk-by-hunk; 5 hunks, all accounted for).
5. **Split, not exempt — HOLDS.** Zero allow entries; meta-test green.
6. **Digests pinned — HOLDS.** See Condition 15 below.
7. **Red before green — HOLDS, independently reproduced.** The scratchpad
   harness scanned the HEAD versions of both source files and the old
   `pipeline-gates.json` with the *new* rule code: exactly 15 findings — the
   13 enumerated in design.md at exactly the recorded lines (6519, 6520,
   11813, 11814, 11820, 11821, 13104, 13130 in `local_validation.rs`; 107,
   113, 357, 374, 378 in `secrets.rs`) plus the two `secretAllow` mirror
   lines. Matches the tasks 1.2 red baseline; nothing else was ever
   suppressed, so removal blocks nothing legitimate.
8. **Ordering — HOLDS in the tree.** Final tree scans clean with the narrowed
   allowlist (harness scan of all four changed files: zero findings). The
   commit-time half of ordering is Condition 12, below.
9. **Fail-closed walker — HOLDS, empirically.** `walk_regular_files`
   propagates `read_dir`/`file_type` errors (`secrets.rs:455-476`); the test
   `expect`s them into failure (:496-497); `scan_paths` errors on unreadable,
   oversized, and non-regular inputs rather than skipping (:298-319).
10. **Change artifacts scanner-clean — HOLDS for everything on disk.** The
    harness ran the production scanner over every artifact of this change
    (proposal, design, tasks, both security reviews, documentation, manifest,
    spec delta) plus this file: zero findings. Commit and tag messages do not
    exist yet — folded into the closing condition.
11. **Behavioral pin per split rule literal — HOLDS, mutation-verified.**
    `detects_slack_tokens_for_every_prefix` (`secrets.rs:413-425`) assembles
    all three prefixes (`xox` + `b-`, `xox` + `p-`, `xox` + `a-` tails) at
    runtime and asserts slack-token; `detects_private_key_block` (:364-367)
    covers the armor pair. Refutation ran the mutations: corrupting the
    `b-` fragment to `b_` fails the Slack pin; corrupting the second armor
    fragment fails the key-block pin (details under Refutation). A wrong
    split cannot land green.
12. **Push-safe commit topology — OPEN (only remaining condition).** Nothing
    is committed yet; the end-state tree is verified clean, so a single
    commit satisfies this trivially. Owner: main session at commit time.
13. **No fail-open wrapper — HOLDS.** The meta-test never touches
    `checks::scan_secrets`; it calls `secrets::scan_paths` and `expect`s the
    `Result` (:513-514). The doc comment on the test names the trap
    explicitly (:478-483).
14. **Vacuous-pass guard — HOLDS, empirically.** Non-empty-walk assert plus
    the `checks/secrets.rs` path-suffix membership assert (:502-511).
    Refutation compiled the module against an empty fake tree: the guard
    fails loudly on the zero-file walk, and a repo path containing a
    `target` component degrades to the same loud failure, never a silent
    green.
15. **Non-circular, scanner-clean digest pin — HOLDS, independently
    recomputed.** This review recomputed SHA-256 over the pre-change literal
    bytes taken from `git show HEAD` (the un-split byte-strings at old
    :6519-6520) using `shasum -a 256`, with no reference to the new code:
    both digests match the pinned hex at `local_validation.rs:11850-11851`
    (`1692455e…` / `373fb2d8…`) exactly. The pin is anchored to pre-change
    bytes, not to the refactor. The pin lines themselves scan clean (the
    64-hex values bind to identifiers with no secret-ish keyword; the
    harness scan of the whole file returned zero findings). The consts
    (:6347-6348) are used only at the two digest fields (:6530-6531) and in
    the pin test; no other reference to the old literals remains.

Allowlist narrowing verified concretely: `.mpd/secret-allowlist.json` retains
only `openspec/changes/archive/**`; `allowlist.rs:63-64` shows `paths` globs
suppress every rule in matching files, so dropping the three entries restores
whole-file detection there. `.claude/pipeline-gates.json` drops `secretAllow`
entirely; the hook reads it with an empty-list default
(`pipeline-gate.py:179`), and those two regexes had suppressed matching added
lines repo-wide — removal restores hook coverage everywhere, not just in the
three files.

## Independent review

This pass did not trust the Builder's evidence or the plan's ported scanner;
it re-derived everything from primary sources with the production code itself:

- **Byte-identical harness.** Copied the shipped `checks/secrets.rs` to the
  session scratchpad (verified identical with `diff`), compiled it standalone
  with `rustc`, and drove the real `scan_paths` — not a port — over: the HEAD
  (pre-change) versions of both source files and the gates config (exactly
  the 15 enumerated findings at the exact enumerated lines); the current
  versions of all four changed files (zero findings); and all nine change
  artifacts including this review (zero findings).
- **Independent digest recomputation.** Extracted the pre-change tag literals
  from `git show HEAD:crates/mpd/src/local_validation.rs` and hashed them
  with `shasum -a 256` — matching both pinned hex values without consulting
  the new consts. `Digest::of_bytes` confirmed to be plain SHA-256 of exact
  bytes (`crates/mpd/src/digest.rs:62-66`).
- **In-repo authoritative run.** `cargo test -p mpd` with targeted filters:
  all 14 relevant tests green (the full secrets module including the
  meta-test against the real tree, the digest pin, the redaction test, the
  outgoing-scan test), 0 failed.
- **End-to-end detection cross-check.** The strongest identity proof is
  structural: the *new* split-rule scanner detects the *old* contiguous
  fixtures at all 15 sites, including slack-token at four sites and
  private-key-block at its definition site. Any corrupted split fragment
  would have produced a divergent finding set.

## Refutation

Strongest attacks attempted against a PASS, all with the compiled production
code in the scratchpad harness:

1. **"A split literal silently weakened detection."** Refuted twice over.
   (a) Mutation: rebuilt the module with the Slack `b-` fragment corrupted to
   `b_` — `detects_slack_tokens_for_every_prefix` FAILED; rebuilt with the
   second armor fragment corrupted — `detects_private_key_block` FAILED. The
   Condition-11 pins therefore turn exactly this bug class red. (b) Identity:
   the unmutated new rules reproduce every HEAD-era finding at every
   enumerated line, which is only possible if the assembled patterns are
   byte-identical to the originals.
2. **"The guard can pass while a real contiguous secret exists."** Planted a
   contiguous slack-shaped token in a fake `crates/` tree and pointed the
   compiled meta-test at it: FAILED with the exact `path:line rule` plus
   remediation. Pointed it at an empty tree: the Condition-14 assert FAILED
   loudly. Remaining residuals are the ones the plan already accepted with
   backstops: files outside `crates/` (owned by the now-un-blinded commit and
   pre-push gates plus gitleaks), `target`-component paths for untracked
   files only (tracked files hit the un-blinded commit gate, which has no
   target exclusion), and rule classes mpd never had (GitHub-parity residual;
   gitleaks lane provides the wider net). None is widened by this change.
3. **"The digest pin is circular and would bless a corrupted tag."** Refuted:
   this review computed both expected digests from HEAD bytes independently
   before comparing; they match the pinned values. A corrupted `concat!`
   fragment in either const would move the SHA-256 and fail the pin against
   a constant this change could not have influenced.
4. **"The allowlist removal breaks something legitimate."** Refuted: the
   complete pre-change finding set under the three suppressions is the 15
   self-matches (reproduced independently); all 15 are eliminated by the
   splits; the hook tolerates a missing `secretAllow` key by defaulting to
   empty. Nothing else ever depended on the blindness.

The one attack that cannot be refuted from the working tree is topology: a
multi-commit landing whose intermediate blob still carries contiguous text
would wedge the pre-push outgoing scan (plan Attack 2). That is Condition 12,
still open by necessity until commit.

## Verdict

CONDITIONAL PASS

This change strengthens detection with zero weakening and zero
authorization-identity change. Judgment, explicitly: the production matcher
is byte-identical (proven by the new rules re-detecting all 15 pre-change
findings, by mutation tests that turn a bad split red, and by green behavioral
pins for every split rule); push-authorization identity is unchanged (proven
by independent SHA-256 recomputation from HEAD bytes matching both pins); and
detection is strictly stronger (three whole-file suppressions and two
repo-wide hook regexes removed, with the meta-test now enforcing the
scanner-clean invariant in the standard test lane, fail-closed and
non-vacuous).

Single closing condition (Condition 12 + the commit-message half of
Condition 10): land the change as **one commit** whose message is itself
scanner-clean — or, if split, verify every intermediate blob of the three
formerly-suppressed files scans clean — before push. Owner: main session.
Closing evidence: the commit topology at pre-push time. All other conditions
(1-11, 13-15) are verified closed against the code on disk. Proceed to
Design Sign-off/Test; the closing condition blocks push, not testing.
