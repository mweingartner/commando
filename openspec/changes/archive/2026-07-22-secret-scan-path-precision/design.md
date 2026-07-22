# Design: Path-precise generic secret detection

## Actor

Architect (claude-code harness, deep tier — high-risk deep_tier_bump).

## Context

`scan_line` (secrets.rs:106-147) tries nine curated rules first and
`generic_secret_assignment` (secrets.rs:219-249) last. The generic rule is the
dependency-free backstop for unbranded credentials (AWS secret access keys, hex
API keys, raw base64 secrets) — shapes with no reliable prefix. Its current value
test (length ≥20 + any letter + any digit, secrets.rs:246-248) accepts any dated
path. Verified live false positives today: the ledger array-element lines
`"openspec/changes/archive/2026-07-21-secret-fixture-hygiene"` (.mpd/state/secret-fixture-hygiene.json)
and `"…2026-07-22-scan-secrets-fail-closed"` (.mpd/state/scan-secrets-fail-closed.json).

The scanner's threat model is **accidental commit of a real credential**, not an
adversary deliberately splitting their own secret across separators (that defeats
any static scanner and always did). Consumers that constrain the fix: pre-push
outgoing-object tests plant `token = "abc123abc123abc123abc123"` (a 24-char run)
in local_validation.rs (several sites) and checks/mod.rs:371 — all must still
trip.

This file is the canonical current-state contract. Move superseded drafts to
`history/`; do not accumulate contradictory amendments here.

## Goals / Non-Goals

**Goals.** (1) A value that is a filesystem path or hyphenated/dotted dictionary
text is never flagged by `generic-secret-assignment`. (2) Every real-credential
fixture currently detected by the generic rule stays detected. (3) Strict
monotone tightening — provably no new false positives. (4) `first_party_source_is_scanner_clean`
(secrets.rs:513) stays green with an empty `SOURCE_HYGIENE_ALLOW`.

**Non-Goals.** No change to the nine curated rules, `extract_quoted`/
`extract_unquoted_value`, `PLACEHOLDERS`, windowing constants, `scan_paths`,
`checks/mod.rs`, `allowlist.rs`, or `.mpd/secret-allowlist.json`. No keyword-position
parsing. No entropy scoring.

## Decisions

**D1 — The gate: contiguous token run.** Replace secrets.rs:246-248 with a new
helper `has_contiguous_token_run(value)`: flag iff the value contains a maximal
run of length ≥ `MIN_TOKEN_RUN` over the token alphabet, where the run contains
≥1 ASCII letter and ≥1 ASCII digit. This **subsumes** the old whole-value
`has_alpha && has_digit` (any qualifying run has both), so `new_flag ⇒ old_flag`
for all inputs — the monotonicity proof documented in the code comment.

**D2 — Alphabet `[A-Za-z0-9+]`.** Include ASCII alphanumerics (core of hex/
base32/base62/base64) and `+` (standard-base64 data char, absent from paths).
Exclude `/` (the path separator — including it resurrects the defect class; this
is the cost that creates the residual base64-with-slash miss), `-`/`_` (separators
of hyphenated names, dates, snake_case, and base64url data chars), `.` and
whitespace (versions, prose, JWT dot-separators — JWTs have their own rule), and
`=` (base64 padding is a 1-2 char suffix; `=` is the assignment separator).

**D3 — Threshold 16.** The smallest credential core the scanner already trusts:
`has_aws_access_key` requires exactly 16 (secrets.rs:176-198) and Stripe requires
a 16-char tail (secrets.rs:131-135; OpenAI `sk-` requires 32, secrets.rs:137).
Below real secrets (hex ≥32, GitHub tails 36+, repo fixtures
20-27). Above dictionary/path segments and abbreviated git-hash dir names (7-12).
At 12 it would re-flag 12-hex path segments; at 20 it would miss 16-19-char cores
the curated rules treat as real. 16 is right.

**D4 — Alternatives rejected.** (a) Shannon-entropy scoring — nondeterministic
feel, still scores hex-ish path segments high, more code in a deliberately
dependency-free scanner. (b) Exempt "path-looking" values — wholesale exemption
of any slash-bearing secret; repo knowledge belongs in the allowlist. (c) Require
the keyword in key position — not monotone, fragile without a real multi-format
parser, loses keyword-in-prose detections. (d) Per-ledger allowlist entries —
symptom treatment; re-trips at new lines.

**D5 — Slot-in.** Inside `generic_secret_assignment`, after the placeholder
check (:243-245), replacing the final gate (:246-248). Order preserved: keyword →
extraction → length ≥20 → placeholder → token-run. Length and placeholder gates
untouched.

## Risks / Trade-offs — detection-weakening (the crux)

The generic rule fires only when a keyword is on the line; shapes assessed for the
keyworded case. Curated rules run BEFORE the generic rule and are byte-identical
after this change.

| Shape | Dedicated rule? | Survives new gate? | Note |
|---|---|---|---|
| AWS access key `AKIA`+16 | Yes | Yes (20-run) | no change |
| **AWS secret key** (40, `A-Za-z0-9/+`) | **No — generic only** | **~99%** (with `+` in-alphabet only `/` splits; one `/` can't drop 40 below a 16-run; ≥2 well-placed ≈1%) | flagship residual; an `AKIA` id usually co-occurs and blocks via the dedicated rule; gitleaks covers it |
| GitHub `ghp_`/`github_pat_` | Yes | Yes (36+/22+ run) | no change |
| GitHub `gho_/ghu_/ghs_/ghr_` | No (pre-existing gap) | Yes (36-run) | identical pre/post |
| Slack `xox*` | Yes | dedicated fires first | no change |
| JWT | Yes | segments ≥16 | no change |
| OpenAI `sk-`, Stripe `sk_live_`, Google `AIza` | Yes | yes / dedicated fires first | no change |
| Hex keys/digests (32/40/64) | No | Yes (single run; P(no digit in 32+ hex) < 1e-13) | still flagged as a real token |
| Std-base64 (24-44) | No | 44: ~99%; **24: ~90%** (one mid `/` can split) | honest residual; gitleaks entropy covers |
| Unbranded base64url (32-43) | No | 43: ~90%; **32 (`secrets.token_urlsafe`-class): ~85%** | base64url is mostly branded (JWT/ghp_/xox*) → dedicated catches, BUT `token_urlsafe` is a realistic unbranded committer; accepted with gitleaks compensation |
| **Env/TOML/YAML Azure AD client secret** (`~.-_` as DATA chars, ~37-char tail) | **No — generic only** | **~50-70%** (2-4 specials in the tail frequently break every ≥16 run) | The most under-counted class. Only the `KEY=value`/`key: value` assignment form is affected — the JSON `"ClientSecret": "…"` form was NEVER covered (`extract_quoted` returns the short key). gitleaks has a dedicated Azure rule. Follow-up: a cheap `\dQ~` prefix rule would close it in the builtin |
| **GitLab `glpat-`** (20-char tail, `-`/`_` possible) | No | old ~97% → **new ~80-90%** | generic-only in the builtin; gitleaks has a dedicated rule. Same follow-up class as Azure |
| **UUID `8-4-4-4-12`** | No | **No — deterministic miss** (max run 12) | accepted: indistinguishable from ubiquitous non-secret UUIDs; pinned by test |
| **Grouped keys `XXXX-XXXX-…`** | No | **No — deterministic miss** | same rationale |
| Private-key body | Armor header rule | body carries no keyword → generic never fired | no change |
| Separator-broken passphrase | No | lost if no ≥16 letter+digit run | today only caught when a digit was present; structurally the path/dictionary shape being deprioritized; accepted |

Other risks: [helper mis-implemented → silent disablement] → 15/16 boundary tests
+ property tests + the existing `guard_catches_a_reintroduced_contiguous_secret`.
[Fixture text trips the source-hygiene guard] → every new positive fixture
assembled via `format!`/`concat!` with each fragment <16 token-alphabet chars.
[Perf] → single O(len) pass, no allocation, cheaper than the existing
`to_ascii_lowercase` on this path; windowing caps input at 4096 bytes.

## Conditions for Builder

1. **Scope**: the only source file modified is `crates/mpd/src/checks/secrets.rs`.
   Do not touch `checks/mod.rs`, `allowlist.rs`, `.mpd/secret-allowlist.json`, any
   curated rule, extraction helper, `PLACEHOLDERS`, or windowing constant.
2. **Monotonicity**: the new predicate must satisfy `new_flag(value) ⇒
   old_flag(value)` for all inputs (the run gate subsumes `has_alpha && has_digit`).
   Document this implication in the function comment.
3. **Every existing positive fixture still flags** — verified by the full suite;
   in particular secrets.rs:378, :404, :634 and the local_validation.rs planted
   `token = "abc123…"` sites and checks/mod.rs:371.
4. **The window-truncation pin (secrets.rs:634-638) passes unchanged** — the
   truncated `ghp_` tail (35 chars) exceeds 16; do not alter the pad arithmetic.
5. **Dedicated rules untouched**: `scan_line` (:106-147) order and all nine
   curated matchers byte-identical.
6. **Source hygiene**: every new fixture whose runtime value must trip a rule is
   assembled via `format!`/`concat!` with each source fragment <16 token-alphabet
   chars. `first_party_source_is_scanner_clean` (:513) passes with an empty
   `SOURCE_HYGIENE_ALLOW` — no allow entries added.
7. **Heuristic documented in code**: `MIN_TOKEN_RUN` constant with a doc comment
   stating the alphabet, threshold rationale (matches AKIA=16 / Stripe tail=16),
   and the accepted-miss classes (UUID, grouped keys, slash-bearing base64) so a
   future reader cannot "fix" the UUID miss without finding the analysis.
8. **Accepted misses pinned as tests**, not implicit (UUID test asserting `None`
   with a comment referencing this decision).
9. **No behavioral change to negatives**: placeholder/ordinary-code tests (:372,
   :386) pass unchanged.
10. **Property-test seeds reproducible** (join the existing
    `crates/mpd/proptest-regressions/` regime); generators constrained (segment
    alphabet `[a-w0-9]`, no `.`) so composed fixtures cannot collide with
    dedicated-rule prefixes (`xox`, `eyJ`, `AKIA`, `ghp_`, `sk-`).
11. **Direct monotonicity property test (SECURITY-plan Condition 2).** Reimplement
    the OLD gate (`len ≥ 20`, non-placeholder, whole-value `has_alpha &&
    has_digit`) in `mod tests` and proptest over arbitrary `String` that
    `has_contiguous_token_run(v) ⇒ old_gate(v)` — mechanically pins "no new false
    positive" forever. Seeded/persisted per the existing regime.
12. **Rule-specific proptest assertions (SECURITY-plan Condition 4).** The
    separator-decomposition proptest (3.1) must assert absence of
    `generic-secret-assignment` specifically (e.g. `scan_line(..) !=
    Some("generic-secret-assignment")`), NOT `== None` — because the `[a-w0-9]`
    segment alphabet plus `_`/`-` joins can rarely compose a `sk-`/`ghp`-prefixed
    tail that a CURATED rule legitimately fires on, which would be a permanent
    seed-persisted spurious failure.
13. **Empirically verify the `.mpd/state/**` exemption is now inert (SECURITY-plan
    Condition 3).** In verification, run the built-in scanner over `.mpd/state/**`
    with the allowlist exemption IGNORED and record the finding count. If zero (as
    expected after this fix), file a follow-up to narrow/remove the
    `.mpd/state/**` entry in `.mpd/secret-allowlist.json`. Do NOT edit the
    allowlist in this change.

## Amendments (post Security-plan review)

Security (plan) returned **CONDITIONAL PASS**; the core claims (monotonicity, no
new FP, curated-rule independence, fixtures survive) were verified sound under
attack. Four conditions folded in above: Condition 1 (Architect, closed) — the
risk table now includes env-style Azure AD client secrets (~50-70% miss) and
GitLab `glpat-`, corrects base64url-at-32 to ~85%, and fixes the OpenAI-tail=32
error in D3; Condition 3 (Architect, closed) — proposal.md now states the true
`.mpd/state/**` rationale (scope discipline; the exemption is ~inert after this
fix) with an empirical scan + follow-up (Builder condition 13); Conditions 2 and
4 (Builder) are conditions 11-12 above, verified at Security (code)/Test.
Non-blocking: gitleaks-compensation rows assume a secret scan actually runs on
push — confirm the CI/hooks story at Security (code).

## Verdict

PASS — proceed to Security (plan). The deterministic losses (UUID, grouped keys)
and probabilistic ones (~1% AWS-secret-key class, ~7-10% short slash/dash base64)
are enumerated with mitigations; no blocking finding: every dedicated-covered
shape is unaffected and every repo fixture for the backstop's shapes survives the
gate. Threshold 16 and alphabet `[A-Za-z0-9+]` confirmed.
