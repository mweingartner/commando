# Design: Secret-Fixture Hygiene

## Actor

Architect

## Context

This file is the canonical current-state contract. Move superseded drafts and
reviews to `history/`; do not accumulate contradictory amendments here.

### The incident

mpd's secret scanner needs realistic-looking secret strings as test fixtures to
prove detection and redaction work. A contiguous Slack-token fixture in
`crates/mpd/src/local_validation.rs` tripped GitHub push protection (GH013) on
push; because the commits were already archived, clearing it required a
`git filter-branch` history rewrite, which permanently broke
`mpd publish --verify` for the rewritten changes (post-archive divergence).
The fixture has since been softened to a placeholder, but the structural
problem remains: nothing prevents the next contiguous fixture.

### Why internal gates missed it

`.mpd/secret-allowlist.json` today blanket-suppresses whole files:

- `crates/mpd/src/checks/secrets.rs`
- `crates/mpd/src/local_validation.rs`
- `.claude/pipeline-gates.json` (which mirrors the two raw fixture literals in
  its `secretAllow` array — the suppression list itself is secret-shaped)
- `openspec/changes/archive/**` (immutable review history; out of scope here)

So mpd's own commit and pre-push scans were blind exactly where GitHub was not.
The allowlist made the divergence invisible instead of impossible.

### The proven pattern already in-tree

The test module of `crates/mpd/src/checks/secrets.rs` (:319-405) already
practices the correct hygiene, with a comment stating the doctrine (:323-325):
fixtures are assembled at runtime from split literals — e.g.
`format!("key = AKIA{}", "IOSFODNN7EXAMPLE")` (:329) and
`concat!("-----BEGIN RSA PRI", "VATE KEY-----")` (:335) — so the
secret-shaped value never appears contiguously in source text, while the
runtime value still exercises detection at full strength.
`local_validation.rs` never adopted the pattern. This change makes the pattern
uniform and machine-enforced.

### Complete enumeration of contiguous scanner-matchable source text

Produced by running a faithful port of `scan_line` over every `crates/**/*.rs`
file (excluding `target/`). 13 findings, three classes:

**Class A — full-token-shaped fixtures (the incident class):**

| Site | Rule | Content |
|---|---|---|
| `crates/mpd/src/local_validation.rs:11813` | aws-access-key-id | fixture `AKIA` + `IOSFODNN7EXAMPLE` inside the redaction byte string |
| `crates/mpd/src/local_validation.rs:11814` | slack-token | fixture `xox` + `b-EXAMPLE-PLACEHOLDER-notarealslacktokenfixture` |
| `crates/mpd/src/local_validation.rs:11820` | aws-access-key-id | assertion repeats `AKIA` + `IOSFODNN7EXAMPLE` contiguously |
| `crates/mpd/src/local_validation.rs:11821` | slack-token | assertion repeats the `xox` + `b-` prefix contiguously |

**Class B — the scanner's own rule-definition literals:**

| Site | Rule | Content |
|---|---|---|
| `crates/mpd/src/checks/secrets.rs:107` | private-key-block | the rule line contains both armor substrings, so it matches itself |
| `crates/mpd/src/checks/secrets.rs:113` | slack-token | the three bare Slack prefix literals match the prefix-contains rule |

**Class C — generic-secret-assignment self-matches:**

| Site | Content |
|---|---|
| `crates/mpd/src/checks/secrets.rs:357` | negative fixture `fn secret() -> u32 { 42 }` — quiet as an argument at runtime, but the enclosing assert line quotes it (25 chars, alpha+digit, keyed by the word secret) |
| `crates/mpd/src/checks/secrets.rs:374` | positive fixture `AWS_SECRET=` + `hunter2verylongvalue1234567` |
| `crates/mpd/src/checks/secrets.rs:378` | positive fixture `password: ` + `hunter2verylongvalue1234567` |
| `crates/mpd/src/local_validation.rs:6519` | **production** push-authorization tag `mpd-builtin-` + `outgoing-secret-scan-v2` (35-char quoted value, keyed, has digit) |
| `crates/mpd/src/local_validation.rs:6520` | **production** tag `mpd-builtin-` + `secret-rules-v1` |
| `crates/mpd/src/local_validation.rs:13104` | tag-message fixture `token = ` + `abc123abc123abc123abc123` |
| `crates/mpd/src/local_validation.rs:13130` | commit-message fixture, same value |

No other secret-shaped literals exist anywhere else in the repo outside the
allowlisted archive: a repo-wide sweep for provider-shaped tokens (AWS, Slack,
GitHub, Google, Stripe, OpenAI, JWT, key blocks) hits only
`local_validation.rs` and the `secretAllow` mirror in
`.claude/pipeline-gates.json`.

### A premise that had to be corrected

The task hypothesis was that rule-prefix literals cannot self-match because the
rules demand length/entropy after the prefix. That is true for
`has_aws_access_key` (exactly 16 following uppercase/digits, :169-190), for
every `contains_prefixed_token` rule (:193-207), and for `has_jwt` (:142-166).
It is **false** for two rules: slack-token is a bare `contains` on the prefix
(:113) with no tail requirement, and private-key-block is a two-substring
`contains` (:107). Both match their own definition lines and any assertion
mentioning the prefix. The design therefore cannot rely on "prefixes are safe";
it enforces a uniform invariant instead (Decision D1).

### Structural constraint

`crates/mpd` is a **bin-only crate** (no `[lib]` target; `tests/e2e.rs` drives
the binary via `CARGO_BIN_EXE`). An integration test cannot link
`checks::secrets`, so the meta-test must live inside the crate as a
`#[cfg(test)]` unit test, where `scan_paths`/`scan_text` are directly callable.

## Goals / Non-Goals

**Goals**

1. No contiguous scanner-matchable text anywhere in `crates/**` — fixtures,
   assertions, rule definitions, and production constants alike.
2. A self-enforcing guard in the standard test lane that reuses the production
   detection code, so the guard and the scanner can never drift.
3. Shrink the runtime allowlist: internal gates regain authority over the
   files where the incident originated.
4. Zero change to runtime behavior: scanner rules, redaction semantics, and
   push-authorization digests are byte-identical.

**Non-Goals**

- Changing any detection rule (tightening slack-token's prefix-contains is
  explicitly rejected here — see D1 alternatives).
- Policing files outside `crates/**` in the meta-test; the commit/pre-push
  gates (now un-blinded) and gitleaks own that ground.
- Touching `openspec/changes/archive/**` or its allowlist entry — archived
  review history is immutable evidence.
- Re-repairing the already-diverged archived changes; that damage is done and
  documented.

## Decisions

### D1 — Uniform invariant: scanner-clean source, not "prefixes are fine"

Every source line in `crates/**` must produce zero findings when scanned by
mpd's own `scan_text`. Because slack-token and private-key-block match bare
prefixes (see Context), even the scanner's own rule-definition literals are
split with `concat!` — a compile-time concatenation with byte-identical
runtime values and zero behavior change:

```rust
// checks/secrets.rs:107 — rule behavior unchanged; source no longer self-matches
if line.contains(concat!("-----", "BEGIN")) && line.contains(concat!("PRIVATE", " KEY")) {
// checks/secrets.rs:113
if line.contains(concat!("xox", "b-")) || line.contains(concat!("xox", "p-")) || ...
```

The uniform invariant keeps the meta-test judgment-free: zero findings, no
classification logic to rot.

Alternatives rejected:
- *Allowlist the rule/assertion lines in the meta-test* — line-pinned entries
  rot on every edit; path+rule entries for slack-token in `secrets.rs` would
  also mask a future real token pasted into that file.
- *Add a tail-length requirement to slack-token* — a production detection
  change smuggled in by a hygiene fix; risks weakening the scanner (violates a
  standing condition) and still leaves private-key-block self-matching.

### D2 — The guard: a Rust meta-test dogfooding `scan_paths`

New `#[test]` in the `checks::secrets` test module (the file that owns the
doctrine comment), e.g. `first_party_source_is_scanner_clean`:

1. Resolve the repo root as `env!("CARGO_MANIFEST_DIR")/../..` and walk
   `<root>/crates` recursively — every **regular file** (all extensions:
   sources, assets, manifests), skipping any path with a `target` component
   and skipping symlinks/non-regular entries (mirroring `scan_paths`'s own
   refusal posture). Sort the list for deterministic failure output.
2. Feed the whole list to the **production** `scan_paths` — the exact function
   the commit gate uses, including filename rules, size caps, and
   `from_utf8_lossy` semantics. No parallel pattern list exists to drift.
3. Filter through a const allow structure scoped to (path-suffix, rule) —
   **shipped empty**:

```rust
/// Path+rule scoped exceptions to the scanner-clean source invariant.
/// Empty by design. Any addition needs a comment justifying why the text
/// cannot be split, and must never cover a full-token-shaped literal.
const SOURCE_HYGIENE_ALLOW: &[(&str, &str)] = &[];
```

4. Assert no findings remain; on failure print `path:line rule` for each hit
   plus the remediation ("assemble the value from split literals — see the
   doctrine comment in this module").

Properties worth having: it runs in `cargo test --workspace` (the configured
`test` check), so it binds Build/Test gates and remote parity without new
plumbing; it scans **untracked** files under `crates/` too, catching a bad
fixture before it is ever staged (fail-closed; `target/` exclusion keeps noise
out); an oversized or non-regular file fails loudly via `scan_paths`'s own
errors rather than being skipped.

Alternatives rejected:
- *Shell guard in `scripts/check-doc-staleness.sh`* — that script is
  doc-doctrine-scoped, and a grep-based guard means a second pattern list that
  drifts from `checks::secrets` the first time a rule changes.
- *Honor `.mpd/secret-allowlist.json` in the meta-test* — inheriting runtime
  suppressions is the exact blindness that caused the incident. The meta-test
  is deliberately stricter than the gate.

### D3 — Split-construction recipes (runtime bytes exactly preserved)

The generic-secret-assignment rule reads the **first quoted substring** of a
line (or the first unquoted value after `=`/`:`), fires only at ≥20 chars with
both a letter and a digit and a secret-ish keyword on the line, and is
suppressed by placeholder markers. The recipes below exploit that shape; each
was verified against a line-faithful port of `scan_line`:

- **Redaction fixture** (`local_validation.rs:11813-11821`) — assemble parts,
  keep the digit out of the format string, reuse the bindings in assertions so
  the token shapes appear exactly once, split:

```rust
let aws = format!("AKIA{}", "IOSFODNN7EXAMPLE");
let slack = format!("xox{}", "b-EXAMPLE-PLACEHOLDER-notarealslacktokenfixture");
let secret = format!("password=hunter{} MPD_SECRET_CANARY {aws} {slack}", 2);
// ... redact_output(secret.as_bytes(), high_entropy) ...
assert!(!rendered.contains(&aws));
assert!(!rendered.contains(&format!("xox{}", "b-")));
```

  The assembled value is byte-for-byte the current fixture (the `\`
  line-continuation in today's literal collapses to a single space), so every
  existing assertion — `hunter2`, the canary, the AWS shape, the Slack prefix,
  the high-entropy hash, `raw_output_retained` — keeps its exact meaning.

- **Production digest tags** (`local_validation.rs:6519-6520`) — hoist to
  named consts built with `concat!`, keeping the first quoted fragment on the
  line under 20 chars; compiled bytes are identical, so the push-authorization
  digests cannot move:

```rust
const OUTGOING_SCAN_TAG: &str = concat!("mpd-builtin-", "outgoing-secret-scan-v2");
const SECRET_RULES_TAG: &str = concat!("mpd-builtin-", "secret-rules-v1");
```

  Guarded by a new unit assertion pinning both digest hex values to their
  current constants (digest stability is load-bearing for authorization
  reuse — see Conditions).

- **Outgoing-scan message fixtures** (`local_validation.rs:13104` and
  `:13130`) — `format!("token = {}{}", "abc123abc123", "abc123abc123")` bound
  to a local; the runtime message is unchanged, so `scan_outgoing_objects`
  still fails with `outgoing-secret-scan-failed` exactly as asserted.

- **Scanner test fixtures** (`secrets.rs:357, 374, 378`) — split so the first
  quoted fragment is short: `concat!("fn secret() -> u32 ", "{ 42 }")`,
  `format!("AWS_SECRET={}", "hunter2verylongvalue1234567")`,
  `format!("password: {}", "hunter2verylongvalue1234567")`. Assertion
  outcomes are untouched (`None`, generic match, generic match).

- **Rule definitions** (`secrets.rs:107, 113`) — per D1.

### D4 — Allowlist narrowing, ordered last

After the tree is scanner-clean (meta-test green):

- `.mpd/secret-allowlist.json` `paths` drops
  `crates/mpd/src/checks/secrets.rs`, `crates/mpd/src/local_validation.rs`,
  and `.claude/pipeline-gates.json`; only `openspec/changes/archive/**`
  remains.
- `.claude/pipeline-gates.json` drops the `secretAllow` array whose two
  entries mirror the old contiguous fixtures (the entries become dead the
  moment the literals are split).

Ordering matters: narrowing before splitting would wedge the very commits that
perform the cleanup. Tasks sequence the conversion first, run the meta-test
red→green, then narrow.

### D5 — Spec delta

`local-validation` (which owns outgoing-blob scanning and allowlist semantics)
gains an ADDED requirement, Scanner-clean first-party source — see
`specs/local-validation/spec.md` in this change. The doctrine comment in
`checks::secrets` remains the in-code articulation.

### D6 — This change's own artifacts obey the invariant

Once the whole-file suppressions are gone, these markdown files are themselves
gate-scanned on commit. Every secret-shaped mention here uses split notation
(backticked fragments joined by `+`), never a contiguous token, never both
key-block armor halves on one line — the same discipline the code adopts.

## Risks / Trade-offs

- [Split literals read worse than plain fixtures] → The doctrine comment at
  the top of the `checks::secrets` test module (extended to name the
  meta-test) explains the why once, next to the enforcing test; recipes in
  this design are copy-pasteable.
- [Meta-test scans untracked files; scratch files under `crates/` could fail
  the suite] → Intentional and fail-closed: a secret-shaped scratch file under
  `crates/` is exactly what must not exist. `target/` is excluded; editors'
  symlinks are skipped as non-regular.
- [A future detection rule makes existing source self-match] → The meta-test
  fails in the same PR that adds the rule, forcing contemporaneous splitting —
  the guard working as designed, not a false positive.
- [Digest-tag refactor accidentally changes push-authorization identity] →
  Pinned-hex unit assertion (D3) plus `concat!` being compile-time make a
  silent change impossible; any drift is a loud test failure.
- [Empty allow structure invites lazy widening later] → Entries require
  path+rule scope and a written justification by doctrine (comment + spec
  requirement); a whole-file entry cannot express itself in the structure.

## Conditions for Builder

1. **Runtime values are byte-identical.** Every split fixture must assemble to
   exactly its current runtime bytes; every existing assertion keeps its
   meaning and strength. No assertion may be weakened, deleted, or made
   conditional to get the meta-test green.
2. **The meta-test reuses production detection code.** It must call
   `checks::secrets::scan_paths` (or `scan_text` plus `suspicious_filename`
   with identical semantics) — never a re-implemented or copied pattern list.
3. **The allow structure ships empty**, is scoped (path-suffix, rule), and its
   doc comment states that additions need written justification and must never
   cover a full-token-shaped literal.
4. **No weakening of the scanner.** No rule logic, threshold, placeholder
   list, cap, or windowing change in `checks/secrets.rs`; rule literals change
   to `concat!` form only, with compiled strings identical.
5. **Prefix self-matches are eliminated by splitting, not by exempting.** The
   slack-token and private-key-block definition lines and every assertion
   mentioning those prefixes use split literals; the meta-test must pass with
   zero allow entries.
6. **Push-authorization digests are pinned.** Hoisting the two digest tags
   must come with an assertion pinning their current digest hex values;
   `push_authorization_id` inputs are unchanged.
7. **Red before green.** Implement the meta-test first and record that it
   reports exactly the 13 enumerated findings (plus none other); then convert
   sites until it passes. The red run is the evidence the guard detects the
   incident class.
8. **Ordering.** Allowlist narrowing (D4) lands only after the meta-test is
   green; the final tree must pass commit-gate scanning with the narrowed
   allowlist and no `secretAllow` entries.
9. **Fail-closed walker.** The meta-test walker skips only `target/`
   components and non-regular files; read or size errors from `scan_paths`
   fail the test rather than skipping the file.
10. **Change artifacts stay scanner-clean.** No contiguous secret-shaped text
    in this change's markdown, specs, docs, or commit messages (commit and tag
    messages are scanned by pre-push and are never allowlisted).

## Verdict

PASS — proceed to Security (plan) review.
