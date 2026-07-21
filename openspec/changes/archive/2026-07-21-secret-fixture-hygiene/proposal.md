# Secret-Fixture Hygiene

## Why

A realistic Slack-token fixture committed contiguously in
`crates/mpd/src/local_validation.rs` tripped GitHub push protection (GH013)
after archive, and clearing it required a history rewrite over already-archived
commits — permanently breaking `mpd publish --verify` for those changes. The
root cause is a divergence mpd created for itself: `.mpd/secret-allowlist.json`
blanket-suppresses two of its own source files (and `.claude/pipeline-gates.json`
mirrors the raw literals in `secretAllow`), so internal gates were blind exactly
where external scanners were not. `crates/mpd/src/checks/secrets.rs` already
practices the correct split-literal hygiene; `local_validation.rs` does not.

## What Changes

- **Split-literal conversion.** Every contiguous scanner-matchable literal in
  `crates/**` (13 sites, enumerated in `design.md`) is rebuilt at runtime from
  split fragments (`concat!` / `format!`), preserving runtime bytes exactly —
  detection and redaction assertions keep their full-strength values while the
  source text matches no rule. This includes the scanner's own rule-definition
  literals, because two rules (`slack-token`, `private-key-block`) match bare
  prefixes and would otherwise flag their own source.
- **Scanner-clean source meta-test.** A new unit test in
  `crates/mpd/src/checks/secrets.rs` walks every regular file under `crates/`
  (excluding `target/`) and runs the production `scan_paths` over it — the
  same code the commit and pre-push gates use, so guard and scanner cannot
  drift — asserting zero findings. Its allow structure ships empty; any future
  entry must be path+rule scoped with a written justification.
- **Allowlist narrowing.** With the sources clean, the whole-file suppressions
  for `crates/mpd/src/checks/secrets.rs`, `crates/mpd/src/local_validation.rs`,
  and `.claude/pipeline-gates.json` are removed from
  `.mpd/secret-allowlist.json`, and the now-moot `secretAllow` mirror literals
  are removed from `.claude/pipeline-gates.json`. The internal gates regain
  authority over the exact files where the incident originated.
- **No behavior change** to the shipped scanner, redaction, or push
  authorization: rule logic is untouched and the push-authorization digest tag
  bytes are provably identical (compile-time concatenation).

## Capabilities

### New Capabilities

None.

### Modified Capabilities

- `local-validation` — adds the Scanner-clean first-party source requirement:
  first-party source assembles secret fixtures at runtime from split literals,
  a meta-test enforces it with the production scan functions, and the
  version-controlled secret allowlist carries no whole-file suppressions for
  first-party source files.

## Impact

- `crates/mpd/src/checks/secrets.rs` — rule literals split (source text only;
  identical compiled strings), test fixtures split, new meta-test.
- `crates/mpd/src/local_validation.rs` — redaction fixture and outgoing-scan
  message fixtures split; push-authorization digest tags rebuilt via
  compile-time concatenation with a digest-stability assertion.
- `.mpd/secret-allowlist.json`, `.claude/pipeline-gates.json` — suppressions
  narrowed/removed.
- `openspec/specs/local-validation` at archive; `docs/secret-fixture-hygiene.md`.
- No API, dependency, or runtime behavior changes.
