# Path-precise generic secret detection

## Purpose

The built-in scanner's `generic-secret-assignment` rule flagged any
keyword-bearing value that was ≥20 chars with a letter and a digit — which
matched filesystem paths and dated hyphenated names (e.g. an archive path whose
change name contains "secret"). This change makes the rule path-precise: it flags
only values that contain contiguous credential-token material.

## Value

Removes a class of false positives that eroded trust in the gate and forced a
blanket `.mpd/state/**` allowlist exemption. A developer or gate can no longer be
blocked by a path that merely happens to contain a secret keyword and a date,
while real high-entropy tokens are still caught.

## Scope

**Covers:** the generic backstop rule only. It now flags a keyword-bearing value
only when the value contains a run of ≥16 consecutive `[A-Za-z0-9+]` characters
that itself has a letter and a digit. This is a **strict tightening** — every
value flagged after the change was flagged before it, so it introduces no new
false positives.

**Does not cover (unchanged / by design):**
- The eight curated detections (private-key armor, AWS, Slack, GitHub, Google,
  Stripe, OpenAI, JWT) are untouched and run first — their shapes are unaffected.
  (`generic-secret-assignment`, the backstop modified here, is the ninth rule but
  not one of the untouched curated set.)
- The rule's existing keyword, length (≥20), and placeholder conditions still
  apply; the rule only ever became stricter.
- **Accepted misses** (documented in the change's Risks analysis, pinned or
  described by tests): UUID-shaped and 4-char-grouped keys (deterministic, since
  their runs never reach 16); and a probabilistic miss for short base64 values
  split by `/` and for env-style secrets whose tails use `~ . - _` as data
  characters (e.g. Azure AD client secrets, GitLab `glpat-`). These are backstop
  gaps compensated by the curated prefix rules and, where installed, gitleaks.
- The `.mpd/state/**` allowlist exemption is left in place on scope discipline; a
  follow-up tracks narrowing/removing it now that the rule is precise.

## Functional details

- New `MIN_TOKEN_RUN = 16` and helpers `is_token_char` (ASCII alphanumerics +
  `+`) and `has_contiguous_token_run` (single O(len) pass, letter+digit within one
  run) in `crates/mpd/src/checks/secrets.rs`.
- `generic_secret_assignment`'s final gate changed from whole-value
  `has_alpha && has_digit` to `has_contiguous_token_run(value)`. Monotonicity is
  proven by a property test over arbitrary strings; separators `/ - _ .` and
  whitespace break runs.
- No behavior change to any curated rule, to non-matching lines, or to the
  scanner's fail-closed / windowing behavior.

## Usage

Derived from the spec scenarios (behavior of the built-in scanner):

- **Keyword-bearing path — not a secret:**
  a line like `archive_path: "openspec/changes/archive/2026-07-21-secret-fixture-hygiene"`
  (longest token run 8) yields **no** `generic-secret-assignment` finding.
- **Contiguous token — still a secret:**
  a keyword-bearing value whose text is a single contiguous run of 16 or more
  letters-and-digits — a 64-hex digest, or a ~20-character mixed-case
  alphanumeric token — **is** reported as `generic-secret-assignment`. (No literal
  example is embedded here: a real token shape would itself trip this scanner and
  gitleaks — see the module's source-hygiene doctrine.)
- **Accepted miss (documented):** `api_key: "AAAA-1111-BBBB-2222-CCCC-3333"`
  (4-char groups) is not flagged by the generic rule — a real grouped-format key
  should be caught by a dedicated rule or gitleaks.
