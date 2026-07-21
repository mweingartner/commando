# Secret-Fixture Hygiene

## Purpose

mpd's secret scanner (`crates/mpd/src/checks/secrets.rs`) needs realistic
secret-shaped strings as test fixtures to prove detection and redaction work
at full strength. A contiguous Slack-token fixture in
`crates/mpd/src/local_validation.rs` tripped GitHub's external push
protection (GH013) after archive; because the offending commits were already
archived, clearing it required a `git filter-branch` history rewrite that
permanently broke `mpd publish --verify` for those changes. The deeper cause
was that `.mpd/secret-allowlist.json` blanket-suppressed the whole files that
carried the fixtures — including mpd's own `checks/secrets.rs` — so mpd's own
commit and pre-push gates were blind exactly where GitHub was not.

## Value

No contiguous pushable-secret literal remains anywhere in `crates/**` source:
every fixture, assertion, and even the scanner's own rule-definition literals
for `slack-token` and `private-key-block` (`checks/secrets.rs:112,118-120`)
are assembled at runtime from split fragments (`concat!`/`format!`), with
runtime bytes and detection strength byte-identical to before. Future changes
never need a post-archive history rewrite for this class of incident. The
three whole-file allowlist suppressions in `.mpd/secret-allowlist.json`
(`crates/mpd/src/checks/secrets.rs`, `crates/mpd/src/local_validation.rs`,
`.claude/pipeline-gates.json`) are removed, restoring mpd's own gate
authority over exactly the files where the incident originated; the dead
`secretAllow` mirror array is gone from `.claude/pipeline-gates.json` too, so
hook coverage is restored repo-wide (those regexes had suppressed matching
added lines anywhere, not just in the three files). A new self-enforcing
meta-test, `first_party_source_is_scanner_clean`
(`checks/secrets.rs:513`), dogfoods the production `scan_paths` over the
entire `crates/` tree with an empty allow list, so a reintroduced literal
fails a standard-lane test before it ever reaches a commit or push gate.
Security (code) independently verified byte-identity of every split rule
literal and both push-authorization digest tags by re-deriving them from
pre-change bytes: detection is strengthened, nothing is weakened, and
authorization identity does not move.

## Scope

The manifest (`openspec/changes/secret-fixture-hygiene/manifest.json`)
declares 7 path patterns: `.claude/pipeline-gates.json`,
`.mpd/secret-allowlist.json`, `.mpd/state/secret-fixture-hygiene.json`,
`crates/mpd/**`, `docs/secret-fixture-hygiene.md`,
`openspec/changes/secret-fixture-hygiene/**`, and `openspec/specs/**`.

**Out of scope, explicitly:**

- `openspec/changes/archive/**` — its allowlist suppression is retained
  deliberately as immutable review-history evidence; this change does not
  touch it.
- The fail-open `checks::scan_secrets` wrapper (`checks/mod.rs:176`), whose
  `unwrap_or_default()` turns a scan error into a clean report in the
  tracked-files gate path. Security (plan) flagged it as a pre-existing,
  separate defect; the new meta-test deliberately calls `scan_paths` directly
  and never goes through that wrapper (Condition 13).
- GitHub push-protection parity. The guard enforces mpd-self-consistency —
  that mpd's own scanner finds nothing in first-party source — not that
  mpd's rule set matches GitHub's. GitHub runs a different, larger, evolving
  rule set; the gitleaks lane in the gate remains the wider independent net.
- Changing any detection rule's logic, threshold, or windowing. Rule
  literals moved to `concat!` form only; `scan_line`'s classification
  behavior is untouched.

## Functional details

**Split-literal technique.** Every contiguous scanner-matchable literal in
`crates/**` (13 sites, three classes) is rebuilt at runtime from split
fragments so no rule matches the source text while the assembled runtime
value is byte-identical to the original: `format!("AKIA{}",
"IOSFODNN7EXAMPLE")`-style fixtures, `concat!("xox", "b-")`-style rule
literals, and `concat!`-hoisted push-authorization digest-tag consts
(`OUTGOING_SCAN_TAG`, `SECRET_RULES_TAG` at `local_validation.rs:6347-6348`).
Because `slack-token` and `private-key-block` are bare/two-substring
`contains` rules with no tail-length requirement, their own definition lines
at `checks/secrets.rs:112,118-120` also had to be split — a case the initial
"prefixes are safe" hypothesis missed and design decision D1 corrected.

**Behavioral pins.** `detects_slack_tokens_for_every_prefix`
(`checks/secrets.rs:415`) closes what was previously zero Slack detection
coverage in the test suite by asserting all three prefixes
(`xox`+`b-`/`p-`/`a-`) still classify as `slack-token` after the split — a
typo in the split fragments turns exactly this test red (mutation-verified).
`push_authorization_digest_tags_are_pinned_to_their_pre_refactor_bytes`
(`local_validation.rs:11843`) pins both hoisted digest tags to hex values
computed via `shasum -a 256` from the pre-change literal bytes, non-circular
by construction (Condition 15) and independently re-derived by Security
(code) from `git show HEAD`.

**The meta-test guard.** `first_party_source_is_scanner_clean`
(`checks/secrets.rs:513`) walks every regular file under `crates/` (skipping
only `target/` components and non-regular entries; a failed walk errors
rather than reading as clean), scans the whole set through the production
`scan_paths` — never a re-implemented pattern list, never the fail-open
`checks::scan_secrets` — and filters through `SOURCE_HYGIENE_ALLOW`
(`checks/secrets.rs:332`), which ships `&[]`. It asserts a non-empty walk
that includes `checks/secrets.rs` itself, guarding against a vacuous pass
from repo-root resolution drift. The guard's body was extracted into
`run_scanner_clean_guard` (`checks/secrets.rs:490`) and is exercised twice:
once by the production meta-test, once by
`guard_catches_a_reintroduced_contiguous_secret`
(`checks/secrets.rs:565`), which plants a runtime-assembled contiguous
Slack-shaped value in a synthetic tree and asserts the guard reports exactly
that plant — the efficacy proof now lives inside the standard suite instead
of only in Security's scratchpad harness.

**Retained blind spot.** `openspec/changes/archive/**` stays suppressed in
`.mpd/secret-allowlist.json` — historical, deliberate, unchanged by this
change. The honest residual: this guard enforces mpd-self-consistency, not
GitHub parity — a future fixture matching a GH-only rule class mpd lacks
could still trip GH013 post-archive; that gap is accepted because the actual
incident was not a rule-set gap (mpd's own rules matched the fixture; the
allowlist suppressed the finding), and gitleaks in the gate lane provides the
wider independent net. The fail-open `checks::scan_secrets` wrapper is a
related, out-of-scope follow-up already flagged for separate work.

## Usage

Convention for adding a new secret-shaped fixture anywhere under `crates/`:
assemble it at runtime with `concat!`/`format!` so no contiguous
scanner-matchable literal exists in source, following the doctrine comment at
the top of the `checks::secrets` test module:

```rust
let aws = format!("AKIA{}", "IOSFODNN7EXAMPLE");
let key_block = concat!("-----BEGIN RSA PRI", "VATE KEY-----");
```

`cargo test -p mpd checks::secrets` (or the full `cargo test --workspace`)
enforces the convention automatically via `first_party_source_is_scanner_clean`
— a contiguous reintroduction fails with the exact `path:line rule` before
any commit or push gate is reached. An adopter's own repository that adds
secret-shaped fixtures under a scanner-covered tree should apply the same
pattern: split every fixture and any self-matching rule-definition literal,
and add an equivalent meta-test that calls its own production scan function
directly (never a wrapper that swallows errors) with an empty, path+rule
scoped allow list — the (path-suffix, rule) shape and non-vacuous-walk guard
in `SOURCE_HYGIENE_ALLOW` / `first_party_source_is_scanner_clean` are a
directly copyable template.
