# Security (plan) review

## Actor

Security (claude-code harness, deep tier — high-risk deep_tier_bump).

## Threat model

**Change.** Tighten `generic_secret_assignment` (secrets.rs:219) so a
keyword-bearing value is flagged only when it contains a contiguous run of ≥16
`[A-Za-z0-9+]` chars with a letter and a digit — eliminating false positives on
filesystem paths (the motivating case: dated archive paths whose change name
contains "secret"). This makes a SECURITY CONTROL LESS SENSITIVE, so the review
burden is false-negatives, not false-positives.

**Threat model.** Accidental commit of a real credential (a commit-hygiene gate),
NOT an adversary deliberately splitting their own secret across separators (that
defeats any static scanner and always did). The generic rule is the
dependency-free BACKSTOP; the nine curated rules (private-key armor, AWS, Slack,
GitHub, Google, Stripe, OpenAI, JWT) run BEFORE it and are byte-unchanged.

**Verified under attack (not taken on faith).**
- **Monotonicity SOUND**: `has_contiguous_token_run(v) ⇒ (has_alpha(v) &&
  has_digit(v))` for all v — the qualifying run donates its letter+digit to the
  whole value. `+`-in-alphabet cannot create a new positive (a `+`-only run has
  no letter/digit). Upstream gates unchanged ⇒ the rule finding set is a strict
  subset; `scan_line_windows` can only relabel, never create. **No new false
  positive is constructible.**
- **Curated-rule independence**: all nine matchers run first and are unchanged;
  their shapes are unaffected.
- **Fixtures traced**: secrets.rs:380 (20-run), :405/:407 (27-run),
  local_validation.rs planted `abc123…` (24-run, quoted+unquoted), checks/mod.rs:371,
  and the window pin :634 (`ghp_` `_`-split, 35-char tail survives) all still
  flag. Motivating FP (`…2026-07-21-secret-fixture-hygiene`) max run 8 → clean.

## Conditions for Builder

Inherits design.md Conditions for Builder 1-13. The four review conditions:

1. **[Medium — Architect, CLOSED] Honest-enumeration completion.** The risk table
   under-counted generic-only classes whose tails use `~ . - _` as data chars:
   env/TOML/YAML **Azure AD client secrets** (~50-70% miss, not the JSON form
   which was never covered) and **GitLab `glpat-`**; base64url-at-32 corrected to
   ~85%; the "OpenAI tail = 16" error corrected to 32. *Closing evidence:* design.md
   risk table + D3 updated; the classes carried into the Builder's `MIN_TOKEN_RUN`
   doc comment (design.md condition 7).
2. **[Builder, OPEN — archive-blocker] Direct monotonicity property test.**
   Reimplement the old gate in tests, proptest `new_gate(v) ⇒ old_gate(v)` over
   arbitrary strings (design.md condition 11 / tasks 3.3). *Closing evidence:*
   test present and green in the Test-phase suite.
3. **[Medium — Architect doc CLOSED / Builder verify OPEN] `.mpd/state/**`
   rationale corrected + empirically tested.** The "digests still flag"
   justification was FALSE (digest lines carry no keyword; `extract_quoted`
   returns the short key), so the exemption suppresses ~zero findings after this
   fix. proposal.md now states the true rationale (scope discipline); verification
   scans `.mpd/state/**` with the exemption ignored and records the count, filing
   a narrow/remove follow-up if zero (design.md condition 13 / tasks 5.4).
   *Closing evidence:* corrected proposal.md (done) + the recorded scan count.
4. **[Builder, OPEN — archive-blocker] Rule-specific proptest assertion.** The
   separator-decomposition proptest must assert absence of
   `generic-secret-assignment` specifically, not `== None`, to avoid a
   seed-persisted spurious failure from a composed curated-rule prefix (design.md
   condition 12 / tasks 3.1). *Closing evidence:* test code in the Build diff.

## Verdict

**CONDITIONAL PASS.** Core claims hold under attack (monotonicity, no new FP,
curated-rule independence, fixture survival). Conditions 1 and 3's doc half are
CLOSED (risk table + D3 + proposal.md amended). Conditions 2, 4, and 3's
empirical-scan half are Builder/verification obligations tracked as design.md
conditions 11-13; they block archive, not Build. No blocking finding: every
dedicated-covered shape is unaffected, and the generic-only losses (UUID/grouped
deterministic; ~1% AWS-secret-key; Azure/glpat/base64url short-tail probabilistic)
are documented and compensated (adjacent AKIA detection, branded-prefix rules,
gitleaks). Builder may proceed against the amended design.md; per the
novel-surface rule, the Build's new tests are verified at Security (code).

Non-blocking: the gitleaks compensation assumes a secret scan actually runs on
push. `.github/workflows/ci.yml` is deleted; confirm at Security (code) that the
`.githooks`/CI story still runs the suite + a secret scan on every push, or the
"gitleaks covers it" rows lose their backing.
