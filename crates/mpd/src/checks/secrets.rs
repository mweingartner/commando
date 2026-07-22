//! A dependency-free secret scanner — the built-in fallback when gitleaks is
//! not installed.
//!
//! This is intentionally conservative (curated high-signal patterns) so it can
//! *block* a commit without drowning the user in false positives. When gitleaks
//! is available it is preferred; this guarantees a non-zero floor either way.
//! Degraded coverage must never become a silent pass — callers surface which
//! scanner ran via `mpd doctor`.

use std::io;
use std::path::{Path, PathBuf};

/// A single secret-like finding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Finding {
    /// File the finding was in (or the filename rule's target).
    pub path: String,
    /// 1-based line number (0 for filename rules).
    pub line: usize,
    /// The rule that matched.
    pub rule: &'static str,
}

/// Flag files whose *name* alone indicates a secret (`.env`, `*.pem`, keys).
pub fn suspicious_filename(path: &Path) -> Option<&'static str> {
    let name = path.file_name()?.to_str()?;
    if name == ".env" || name.starts_with(".env.") {
        return Some("dotenv-file");
    }
    if name == "id_rsa" || name == "id_dsa" || name == "id_ecdsa" || name == "id_ed25519" {
        return Some("ssh-private-key-file");
    }
    let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("");
    match ext {
        "pem" | "p8" | "p12" | "pfx" | "key" | "keystore" => Some("key-material-file"),
        _ => None,
    }
}

/// Placeholder markers that suppress the generic assignment rule.
const PLACEHOLDERS: &[&str] = &[
    "example",
    "xxxx",
    "your_",
    "your-",
    "<",
    "changeme",
    "redacted",
    "placeholder",
    "dummy",
    "todo",
    "...",
];

/// Minimum length of a contiguous run over the token alphabet (see
/// `is_token_char`, alphabet `[A-Za-z0-9+]`) required for
/// `generic_secret_assignment` to flag a keyworded value (design.md decision
/// D3).
///
/// **Threshold rationale.** 16 matches the smallest credential core the
/// scanner already trusts: `has_aws_access_key` requires exactly 16
/// characters after `AKIA`, and the Stripe prefixes (`sk_live_`/`sk_test_`/
/// `rk_live_`) require a 16-char tail (OpenAI's `sk-` requires 32, the
/// largest of the curated tails). Sixteen sits above dictionary words,
/// hyphenated/dated path segments, and abbreviated git-hash directory names
/// (typically 7-12 chars) and below real secret cores (hex digests >= 32,
/// GitHub token tails 36+, this repo's own credential-shaped fixtures 20-27
/// chars).
///
/// **Accepted misses** (documented, not implicit — do not "fix" these without
/// first reading design.md's Risks table). The deterministic classes are pinned
/// by dedicated tests; the probabilistic special-character-fragmentation classes
/// are documented in the Risks table (their miss rate is < 100%, so a
/// deterministic pin is not meaningful):
/// - UUID-shaped values (`8-4-4-4-12`, hyphen-separated): longest run is 12.
///   Pinned (`generic_rule_ignores_hyphenated_dictionary_values`).
/// - 4-char-grouped keys (`XXXX-XXXX-XXXX-XXXX`): every run is 4. Pinned
///   (`generic_rule_ignores_grouped_keys`).
/// - Slash-bearing base64 secrets (AWS secret access keys, short
///   standard-base64 blobs): a `/` in the body can split an otherwise-long
///   token below the threshold. Mechanism pinned
///   (`generic_rule_alphabet_pins_plus_and_slash`).
/// - Env/TOML/YAML-style Azure AD client secrets, whose ~37-char tail uses
///   `~ . - _` as DATA characters rather than separators, which can
///   fragment the tail into runs under 16.
/// - GitLab `glpat-` tails (20 chars, `-`/`_` possible mid-tail): the same
///   special-character fragmentation as the Azure case above.
const MIN_TOKEN_RUN: usize = 16;

/// Maximum bytes of a line actually scanned. Real secret tokens are short;
/// bounding the prefix keeps the repeated pattern scans linear against an
/// adversarial multi-megabyte single line (scanner DoS defense).
const MAX_SCAN_LINE: usize = 4096;
const SCAN_WINDOW_OVERLAP: usize = 256;

/// Scan a single file's text for secret patterns.
pub fn scan_text(path: &str, text: &str) -> Vec<Finding> {
    let mut findings = Vec::new();
    for (i, line) in text.split('\n').enumerate() {
        let line_no = i + 1;
        if let Some(rule) = scan_line_windows(line) {
            findings.push(Finding {
                path: path.to_string(),
                line: line_no,
                rule,
            });
        }
    }
    findings
}

/// Scan the entire line in overlapping bounded windows. This retains linear
/// work and bounded per-pattern input without the former first-4096-byte blind
/// spot. The overlap is longer than every fixed token prefix and curated token
/// minimum, so a credential split at a window boundary is still observed.
fn scan_line_windows(line: &str) -> Option<&'static str> {
    if line.len() <= MAX_SCAN_LINE {
        return scan_line(line);
    }
    let mut start = 0;
    while start < line.len() {
        while start < line.len() && !line.is_char_boundary(start) {
            start += 1;
        }
        let mut end = (start + MAX_SCAN_LINE).min(line.len());
        while end > start && !line.is_char_boundary(end) {
            end -= 1;
        }
        if let Some(rule) = scan_line(&line[start..end]) {
            return Some(rule);
        }
        if end == line.len() {
            break;
        }
        start = end.saturating_sub(SCAN_WINDOW_OVERLAP);
    }
    None
}

/// Inspect one line, returning the first matching rule.
fn scan_line(line: &str) -> Option<&'static str> {
    // These two rules match bare prefixes with no tail-length requirement, so
    // (uniquely among the rules below) their own definition literals would
    // self-match as source text. `concat!` is compile-time concatenation: the
    // compiled `&'static str` patterns are byte-identical to the un-split
    // literals — this changes no matcher behavior (design D1).
    if line.contains(concat!("-----", "BEGIN")) && line.contains(concat!("PRIVATE", " KEY")) {
        return Some("private-key-block");
    }
    if has_aws_access_key(line) {
        return Some("aws-access-key-id");
    }
    if line.contains(concat!("xox", "b-"))
        || line.contains(concat!("xox", "p-"))
        || line.contains(concat!("xox", "a-"))
    {
        return Some("slack-token");
    }
    if contains_prefixed_token(line, "ghp_", 36) || contains_prefixed_token(line, "github_pat_", 22)
    {
        return Some("github-token");
    }
    if contains_prefixed_token(line, "AIza", 35) {
        return Some("google-api-key");
    }
    if contains_prefixed_token(line, "sk_live_", 16)
        || contains_prefixed_token(line, "sk_test_", 16)
        || contains_prefixed_token(line, "rk_live_", 16)
    {
        return Some("stripe-key");
    }
    if contains_prefixed_token(line, "sk-", 32) {
        return Some("openai-key");
    }
    if has_jwt(line) {
        return Some("jwt");
    }
    if generic_secret_assignment(line) {
        return Some("generic-secret-assignment");
    }
    None
}

/// A JWT: `eyJ` header followed by base64url, a `.`, and more base64url.
fn has_jwt(line: &str) -> bool {
    let mut from = 0;
    while let Some(pos) = line[from..].find("eyJ") {
        let start = from + pos;
        let rest = &line[start..];
        let header_len = rest
            .chars()
            .take_while(|c| c.is_ascii_alphanumeric() || *c == '_' || *c == '-')
            .count();
        if header_len >= 12 {
            let after = &rest[header_len..];
            if let Some(dot) = after.strip_prefix('.') {
                let payload = dot
                    .chars()
                    .take_while(|c| c.is_ascii_alphanumeric() || *c == '_' || *c == '-')
                    .count();
                if payload >= 8 {
                    return true;
                }
            }
        }
        from = start + 3;
    }
    false
}

/// `AKIA` followed by exactly 16 uppercase/alphanumeric characters.
fn has_aws_access_key(line: &str) -> bool {
    let bytes = line.as_bytes();
    let mut i = 0;
    while let Some(pos) = line[i..].find("AKIA") {
        let start = i + pos + 4;
        if start + 16 <= bytes.len() {
            let candidate = &bytes[start..start + 16];
            if candidate
                .iter()
                .all(|&b| b.is_ascii_uppercase() || b.is_ascii_digit())
            {
                // Ensure it isn't part of a longer alnum run beyond 16.
                let after = bytes.get(start + 16).copied();
                if after.is_none_or(|b| !(b.is_ascii_alphanumeric())) {
                    return true;
                }
            }
        }
        i = i + pos + 4;
    }
    false
}

/// A `prefix` followed by at least `min_tail` token characters `[A-Za-z0-9_]`.
fn contains_prefixed_token(line: &str, prefix: &str, min_tail: usize) -> bool {
    let mut search_from = 0;
    while let Some(pos) = line[search_from..].find(prefix) {
        let start = search_from + pos + prefix.len();
        let tail = line[start..]
            .chars()
            .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
            .count();
        if tail >= min_tail {
            return true;
        }
        search_from = search_from + pos + prefix.len();
    }
    false
}

/// A `key = "value"` / `key: "value"` assignment where the key names a secret
/// and the value looks like real entropy (not a placeholder). The value must
/// additionally carry contiguous credential material — a filesystem path or
/// hyphenated/dotted dictionary text (dated archive names, UUIDs, snake_case
/// identifiers) is prose/path shape, not credential shape, and is never
/// flagged (design.md decision D1). This final gate strictly subsumes the
/// prior whole-value `has_alpha && has_digit` test: any run that qualifies
/// under `has_contiguous_token_run` has itself donated a letter and a digit
/// to the whole value, so `has_contiguous_token_run(value) =>
/// (value has_alpha && value has_digit)` for every value — a monotone
/// tightening. No value that was clean before this change becomes flagged;
/// some values that were false positives before now correctly fall through.
fn generic_secret_assignment(line: &str) -> bool {
    let lower = line.to_ascii_lowercase();
    let keyed = [
        "api_key",
        "apikey",
        "secret",
        "access_key",
        "token",
        "password",
    ]
    .iter()
    .any(|k| lower.contains(k));
    if !keyed {
        return false;
    }
    // Find a quoted value, or an unquoted `key = value` / `key: value` token.
    let value = match extract_quoted(line).or_else(|| extract_unquoted_value(line)) {
        Some(v) => v,
        None => return false,
    };
    if value.len() < 20 {
        return false;
    }
    let lv = value.to_ascii_lowercase();
    if PLACEHOLDERS.iter().any(|p| lv.contains(p)) {
        return false;
    }
    has_contiguous_token_run(value)
}

/// A character in the token alphabet `[A-Za-z0-9+]` — the alphabet a
/// contiguous credential run (`has_contiguous_token_run`, `MIN_TOKEN_RUN`) is
/// measured over.
///
/// Deliberately excludes `/` (the path separator — including it resurrects
/// the exact false-positive class this heuristic exists to close), `-`/`_`
/// (separators of hyphenated names, dates, snake_case identifiers, and also
/// base64url data characters), `.` and whitespace (versions, prose, and the
/// JWT dot-separator — JWTs have their own dedicated rule), and `=` (the
/// assignment separator; base64 padding is a 1-2 char suffix that does not
/// affect run length either way).
fn is_token_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || c == '+'
}

/// True iff `value` contains a maximal run of `is_token_char` characters of
/// length at least `MIN_TOKEN_RUN` that itself contains at least one ASCII
/// letter and at least one ASCII digit.
///
/// Single `O(len)` pass over `value`, no allocation: track the current run's
/// length plus whether a letter and a digit have been seen within that run;
/// on a non-token character (or at the end of input) evaluate the just-ended
/// run against the threshold, then reset the run state.
///
/// This SUBSUMES the old whole-value `has_alpha(value) && has_digit(value)`
/// test: any run that satisfies this predicate has, by construction,
/// contributed at least one letter and one digit to the whole value, so
/// `has_contiguous_token_run(v) => (v.chars().any(is_ascii_alphabetic) &&
/// v.chars().any(is_ascii_digit))` holds for every `v` — a monotone
/// tightening, never a new false positive (design.md D1; Security-plan
/// Condition 2). Pinned mechanically by `new_gate_implies_old_gate` below.
fn has_contiguous_token_run(value: &str) -> bool {
    /// Whether a just-ended run of `run_len` token characters, having seen a
    /// letter and/or a digit as recorded, clears the bar.
    fn run_qualifies(run_len: usize, letter_seen: bool, digit_seen: bool) -> bool {
        run_len >= MIN_TOKEN_RUN && letter_seen && digit_seen
    }

    let mut run_len = 0usize;
    let mut letter_seen = false;
    let mut digit_seen = false;
    for c in value.chars() {
        if is_token_char(c) {
            run_len += 1;
            letter_seen |= c.is_ascii_alphabetic();
            digit_seen |= c.is_ascii_digit();
        } else {
            if run_qualifies(run_len, letter_seen, digit_seen) {
                return true;
            }
            run_len = 0;
            letter_seen = false;
            digit_seen = false;
        }
    }
    run_qualifies(run_len, letter_seen, digit_seen)
}

/// Extract the first single- or double-quoted substring.
fn extract_quoted(line: &str) -> Option<&str> {
    for quote in ['"', '\''] {
        if let Some(start) = line.find(quote) {
            if let Some(end_rel) = line[start + 1..].find(quote) {
                return Some(&line[start + 1..start + 1 + end_rel]);
            }
        }
    }
    None
}

/// Extract an unquoted value after the first `=` or `:` separator, stopping at
/// whitespace or a delimiter. Catches `.env`/`export`/YAML-style assignments.
fn extract_unquoted_value(line: &str) -> Option<&str> {
    let sep = line.find(['=', ':'])?;
    let after = line[sep + 1..].trim_start();
    let end = after
        .find(|c: char| c.is_whitespace() || c == '"' || c == '\'' || c == ',' || c == ';')
        .unwrap_or(after.len());
    let val = &after[..end];
    if val.is_empty() {
        None
    } else {
        Some(val)
    }
}

/// Maximum file size the content scanner will load. Larger files (vendored
/// blobs, binaries) are skipped for content but still get filename rules —
/// bounds memory of `mpd check` / the pre-commit hook.
const MAX_FILE_BYTES: u64 = 16 * 1024 * 1024;
const MAX_SCAN_TOTAL_BYTES: u64 = 256 * 1024 * 1024;

/// Scan a set of files on disk. Filename rules apply even when a file cannot be
/// read as UTF-8; content rules apply to readable text under the size cap.
pub fn scan_paths(paths: &[PathBuf]) -> io::Result<Vec<Finding>> {
    let mut findings = Vec::new();
    let mut aggregate = 0_u64;
    for path in paths {
        if let Some(rule) = suspicious_filename(path) {
            findings.push(Finding {
                path: path.display().to_string(),
                line: 0,
                rule,
            });
        }
        let metadata = std::fs::symlink_metadata(path)?;
        if metadata.file_type().is_symlink() || !metadata.is_file() {
            return Err(io::Error::other(format!(
                "secret scanner refuses unsafe non-regular path {}",
                path.display()
            )));
        }
        if metadata.len() > MAX_FILE_BYTES {
            return Err(io::Error::other(format!(
                "secret scanner file exceeds {} byte cap: {}",
                MAX_FILE_BYTES,
                path.display()
            )));
        }
        aggregate = aggregate
            .checked_add(metadata.len())
            .ok_or_else(|| io::Error::other("secret scanner aggregate size overflow"))?;
        if aggregate > MAX_SCAN_TOTAL_BYTES {
            return Err(io::Error::other(
                "secret scanner aggregate input exceeds its cap",
            ));
        }
        let bytes = std::fs::read(path)?;
        let text = String::from_utf8_lossy(&bytes);
        findings.extend(scan_text(&path.display().to_string(), &text));
    }
    Ok(findings)
}

/// Path+rule scoped exceptions to the scanner-clean source invariant enforced
/// by `first_party_source_is_scanner_clean` below. Empty by design. Any
/// addition needs a comment justifying why the text cannot be split, and must
/// never cover a full-token-shaped literal.
#[cfg(test)]
const SOURCE_HYGIENE_ALLOW: &[(&str, &str)] = &[];

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    // Doctrine: every source line under `crates/**` must scan clean under
    // this module's own detection — fixtures, assertions, rule-definition
    // literals, and production constants alike (design `secret-fixture-hygiene`,
    // decision D1). Two rules match bare prefixes with no tail requirement
    // (slack-token, private-key-block), so even *this file's own rule
    // definitions* would self-match as plain text; every rule literal below
    // is therefore split with `concat!` (compile-time, byte-identical
    // runtime value), and every fixture is assembled at runtime — e.g.
    // `format!("key = AKIA{}", "IOSFODNN7EXAMPLE")` and
    // `concat!("-----BEGIN RSA PRI", "VATE KEY-----")` — so the secret-shaped
    // value never appears contiguously in source text while the runtime
    // value still exercises detection at full strength. This is enforced
    // mechanically, not just by convention: `first_party_source_is_scanner_clean`
    // (below) walks every regular file under `crates/` and feeds it to this
    // module's own production `scan_paths`, asserting zero findings against
    // an empty `SOURCE_HYGIENE_ALLOW`. When adding a new fixture or rule
    // literal, split it the same way or the test suite will fail with the
    // exact `path:line rule` of the offending text.

    #[test]
    fn detects_aws_key() {
        let line = format!("key = AKIA{}", "IOSFODNN7EXAMPLE");
        assert_eq!(scan_line(&line), Some("aws-access-key-id"));
    }

    #[test]
    fn detects_private_key_block() {
        let line = concat!("-----BEGIN RSA PRI", "VATE KEY-----");
        assert_eq!(scan_line(line), Some("private-key-block"));
    }

    #[test]
    fn generic_rule_ignores_placeholders() {
        assert_eq!(scan_line("api_key = \"your_api_key_here_xxxx\""), None);
        assert_eq!(scan_line("token: \"example-token-value-1234\""), None);
    }

    #[test]
    fn generic_rule_flags_real_looking_value() {
        assert_eq!(
            scan_line("api_key = \"a9Xk28fjQ0zLmP4rT7wY\""),
            Some("generic-secret-assignment")
        );
    }

    #[test]
    fn generic_rule_ignores_filesystem_paths() {
        // Motivating false positives (design.md Context): dated archive
        // paths whose change name happens to contain a keyword. The longest
        // contiguous token run across these three fixtures is 9
        // ("precision", in the path segment), well under MIN_TOKEN_RUN
        // (16), so the new gate correctly stays quiet — and no curated rule
        // can fire on any of these lines either.
        let ledger_array_element =
            "      \"openspec/changes/archive/2026-07-21-secret-fixture-hygiene\",";
        assert_eq!(scan_line(ledger_array_element), None);

        let quoted_path_assignment =
            "archive_path: \"openspec/changes/archive/2026-07-21-secret-fixture-hygiene\"";
        assert_eq!(scan_line(quoted_path_assignment), None);

        let unquoted_env_path = "SECRET_STATE=.mpd/state/secret-scan-path-precision.json";
        assert_eq!(scan_line(unquoted_env_path), None);
    }

    #[test]
    fn generic_rule_ignores_hyphenated_dictionary_values() {
        // Accepted misses, pinned per design.md's Risks table — do not
        // "fix" without re-reading the analysis there. A dated hyphenated
        // name (longest run 8) and a UUID (longest run 12) both fall below
        // MIN_TOKEN_RUN even though both are keyworded, non-placeholder,
        // and >= 20 chars, i.e. they would have flagged under the old gate.
        let dated_name = "api_key: \"2026-07-21-secret-fixture-hygiene-followup\"";
        assert_eq!(scan_line(dated_name), None);

        let uuid_value = "api_key = \"3fa85f64-5717-4562-b3fc-2c963f66afa6\"";
        assert_eq!(scan_line(uuid_value), None);
    }

    #[test]
    fn generic_rule_ignores_grouped_keys() {
        // Accepted miss (design.md Risks table, same rationale as the UUID
        // case above): a 4-char-grouped license/product key. Every run is
        // exactly 4, well under MIN_TOKEN_RUN, yet it is keyworded,
        // non-placeholder, and >= 20 chars — so the OLD whole-value gate
        // flagged it. Do not "fix" without re-reading the analysis.
        let grouped = "api_key: \"AAAA-1111-BBBB-2222-CCCC-3333\"";
        assert_eq!(scan_line(grouped), None);
    }

    #[test]
    fn generic_rule_still_flags_contiguous_digests() {
        // A 64-char hex-shaped digest is real credential material with no
        // dedicated rule (design.md Risks table: "Hex keys/digests").
        // Assembled from fragments each under 16 token-alphabet chars so
        // this source line stays scanner-clean (see the doctrine comment
        // atop this module) even though the runtime value is one 64-char
        // contiguous run.
        let digest = format!(
            "{}{}{}{}{}",
            "0123456789abc", "def0123456789", "abcdef0123456", "789abcdef0123", "456789abcdef",
        );
        let line = format!("token = \"{}\"", digest);
        assert_eq!(scan_line(&line), Some("generic-secret-assignment"));
    }

    #[test]
    fn generic_rule_run_threshold_boundary() {
        // Boundary pin for MIN_TOKEN_RUN (design.md D3). Each run is
        // assembled from two fragments under 16 chars each so this source
        // line stays scanner-clean; the runs are isolated inside separator
        // padding so their length is exactly what the fragments sum to.
        let run_of_16 = format!("{}{}", "aaaa1111", "bbbb2222");
        let at_threshold = format!("token = \"path-{}-node\"", run_of_16);
        assert_eq!(
            scan_line(&at_threshold),
            Some("generic-secret-assignment"),
            "an exactly-16 letter+digit run must flag"
        );

        let run_of_15 = format!("{}{}", "aaaa111", "bbbb2222");
        let below_threshold = format!("token = \"path-{}-node\"", run_of_15);
        assert_eq!(
            scan_line(&below_threshold),
            None,
            "an exactly-15 letter+digit run must not flag (would have under the old gate)"
        );
    }

    #[test]
    fn generic_rule_alphabet_pins_plus_and_slash() {
        // D2: `+` is in-alphabet (a `+`-joined value is one contiguous run
        // spanning the joins); `/` is excluded (the path separator — each
        // `/`-joined segment is its own isolated run). Same three 8-char
        // segments, only the joiner differs.
        let plus_joined = format!("{}+{}+{}", "aaaa1111", "bbbb2222", "cccc3333");
        let plus_line = format!("token = \"{}\"", plus_joined);
        assert_eq!(
            scan_line(&plus_line),
            Some("generic-secret-assignment"),
            "`+` must not break the run"
        );

        let slash_joined = format!("{}/{}/{}", "aaaa1111", "bbbb2222", "cccc3333");
        let slash_line = format!("token = \"{}\"", slash_joined);
        assert_eq!(
            scan_line(&slash_line),
            None,
            "`/` must break the run into 8-char segments, each below threshold"
        );
    }

    #[test]
    fn ignores_ordinary_code() {
        assert_eq!(scan_line("let token = next_token();"), None);
        assert_eq!(scan_line("// remember to rotate the password"), None);
        assert_eq!(scan_line(concat!("fn secret() -> u32 ", "{ 42 }")), None);
        assert_eq!(scan_line("if provided_token == expected_token {"), None);
    }

    #[test]
    fn detects_stripe_openai_jwt() {
        let stripe = format!("key = sk{}", "_live_0123456789abcdefABCDEF");
        assert_eq!(scan_line(&stripe), Some("stripe-key"));
        let openai = format!("OPENAI_API_KEY=sk{}", "-abcdefghijklmnopqrstuvwxyz012345");
        assert_eq!(scan_line(&openai), Some("openai-key"));
        let jwt = format!("auth: {}hbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjMifQ.abc", "eyJ");
        assert_eq!(scan_line(&jwt), Some("jwt"));
    }

    #[test]
    fn detects_unquoted_env_assignment() {
        let aws_style = format!("AWS_SECRET={}", "hunter2verylongvalue1234567");
        assert_eq!(scan_line(&aws_style), Some("generic-secret-assignment"));
        let password_style = format!("password: {}", "hunter2verylongvalue1234567");
        assert_eq!(
            scan_line(&password_style),
            Some("generic-secret-assignment")
        );
    }

    #[test]
    fn detects_slack_tokens_for_every_prefix() {
        // Condition 11: slack-token had zero positive-detection coverage
        // before this change, so a typo while splitting the rule literal at
        // :113 could silently disable it with no failing test. Each prefix
        // is assembled at runtime from split fragments so the fixture itself
        // stays scanner-clean as source text.
        let xoxb = format!("xox{}", "b-EXAMPLE-PLACEHOLDER-notarealslacktokenfixture");
        assert_eq!(scan_line(&xoxb), Some("slack-token"));
        let xoxp = format!("xox{}", "p-EXAMPLE-PLACEHOLDER-notarealslacktokenfixture");
        assert_eq!(scan_line(&xoxp), Some("slack-token"));
        let xoxa = format!("xox{}", "a-EXAMPLE-PLACEHOLDER-notarealslacktokenfixture");
        assert_eq!(scan_line(&xoxa), Some("slack-token"));
    }

    #[test]
    fn long_line_is_bounded() {
        // A pathological long line is scanned in bounded windows all the way
        // to the end, rather than silently trusting bytes after the first one.
        let mut s = "x".repeat(1_000_000);
        s.push_str(&format!(" token=ghp_{}", "a1".repeat(20)));
        let findings = scan_text("big", &s);
        assert_eq!(findings[0].rule, "github-token");
    }

    #[test]
    fn filename_rules() {
        assert_eq!(
            suspicious_filename(Path::new("config/.env")),
            Some("dotenv-file")
        );
        assert_eq!(
            suspicious_filename(Path::new("certs/server.pem")),
            Some("key-material-file")
        );
        assert_eq!(suspicious_filename(Path::new("src/main.rs")), None);
    }

    /// Recursively collect every regular file under `dir`, skipping any path
    /// with a `target` component and skipping symlinks and other non-regular
    /// entries. `read_dir`/`file_type` errors propagate (fail-closed — see
    /// Condition 9): an unreadable directory must fail the test, never be
    /// silently treated as empty.
    fn walk_regular_files(dir: &Path, out: &mut Vec<PathBuf>) -> io::Result<()> {
        for entry in std::fs::read_dir(dir)? {
            let entry = entry?;
            let path = entry.path();
            if path.components().any(|c| c.as_os_str() == "target") {
                continue;
            }
            let file_type = entry.file_type()?;
            if file_type.is_symlink() {
                continue;
            }
            if file_type.is_dir() {
                walk_regular_files(&path, out)?;
            } else if file_type.is_file() {
                out.push(path);
            }
            // Other non-regular entry kinds (fifo, socket, ...) are skipped —
            // `scan_paths` itself refuses non-regular paths handed to it, so
            // this walker never hands it one in the first place.
        }
        Ok(())
    }

    /// What one guard run yields: the walked file list (for vacuity checks)
    /// and the findings that survived the allow filter.
    type GuardOutcome = (Vec<PathBuf>, Vec<Finding>);

    /// The guard machinery, reusable against any root: walk (fail-closed),
    /// scan with the PRODUCTION `scan_paths`, filter through an allow slice
    /// scoped as (path-suffix, rule). Both the real guard
    /// (`first_party_source_is_scanner_clean`) and its efficacy proof
    /// (`guard_catches_a_reintroduced_contiguous_secret`) drive this exact
    /// code path, so the proof cannot drift from the guard it certifies.
    fn run_scanner_clean_guard(root: &Path, allow: &[(&str, &str)]) -> io::Result<GuardOutcome> {
        let mut files = Vec::new();
        walk_regular_files(root, &mut files)?;
        files.sort();
        let findings = scan_paths(&files)?;
        let remaining = findings
            .into_iter()
            .filter(|f| {
                !allow
                    .iter()
                    .any(|(suffix, rule)| f.path.ends_with(suffix) && f.rule == *rule)
            })
            .collect();
        Ok((files, remaining))
    }

    /// The self-enforcing guard (design decision D2, Conditions 2/3/9/13/14):
    /// walk every regular file under `crates/`, scan it with the PRODUCTION
    /// detector (`scan_paths` directly — it returns the raw findings this guard
    /// asserts over, not the `SecretReport` wrapper that `checks::scan_secrets`
    /// returns; `scan_secrets` is now fail-closed — it propagates scan errors
    /// rather than the historical `unwrap_or_default()` — but the wrapper shape
    /// is still the wrong surface for a raw-findings assertion), and assert zero
    /// findings survive the (empty, by design) `SOURCE_HYGIENE_ALLOW`.
    #[test]
    fn first_party_source_is_scanner_clean() {
        // CARGO_MANIFEST_DIR is `<repo>/crates/mpd`; its grandparent is the
        // repo root, and `<repo>/crates` is the tree this guard protects.
        let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
        let repo_root = manifest_dir
            .parent()
            .and_then(Path::parent)
            .expect("CARGO_MANIFEST_DIR must have a repo root two levels up");
        let crates_root = repo_root.join("crates");

        let (files, remaining) = run_scanner_clean_guard(&crates_root, SOURCE_HYGIENE_ALLOW)
            .expect("walking and scanning crates/ for the scanner-clean guard must not fail");

        // Condition 14 — vacuous-pass guard: a root-resolution drift that
        // silently walks nothing (or the wrong tree) must not read as green.
        assert!(
            !files.is_empty(),
            "scanner-clean guard walked zero files under {} — root resolution likely drifted",
            crates_root.display()
        );
        assert!(
            files.iter().any(|p| p.ends_with("checks/secrets.rs")),
            "scanner-clean guard's walk did not include checks/secrets.rs itself — \
             root resolution likely drifted (Condition 14)"
        );

        if !remaining.is_empty() {
            for f in &remaining {
                eprintln!(
                    "{}:{} {} — assemble the value from split literals; see the \
                     doctrine comment at the top of this test module",
                    f.path, f.line, f.rule
                );
            }
            panic!(
                "{} scanner-matchable finding(s) in first-party source under crates/ \
                 (see stderr for path:line rule + remediation)",
                remaining.len()
            );
        }
    }

    /// Guard efficacy (the guard itself must be falsifiable): drive the exact
    /// machinery of `first_party_source_is_scanner_clean` over a synthetic
    /// tree carrying a reintroduced contiguous Slack-shaped value — the
    /// incident class — and prove the guard reports it, that the `target/`
    /// exclusion holds, that an allow entry excuses only its exact
    /// (path-suffix, rule) pair, and that a failed walk errors rather than
    /// reading as clean (Condition 9). The planted value is assembled at
    /// runtime from split fragments so this source file stays scanner-clean;
    /// the temp file on disk carries the contiguous bytes the guard must see.
    #[test]
    fn guard_catches_a_reintroduced_contiguous_secret() {
        let root = std::env::temp_dir().join(format!(
            "mpd-hygiene-guard-efficacy-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let src = root.join("fake-crate").join("src");
        std::fs::create_dir_all(&src).unwrap();
        std::fs::write(src.join("clean.rs"), "fn quiet() {}\n").unwrap();
        let planted = format!(
            "let leaked = \"xox{}\";\n",
            "b-EXAMPLE-PLACEHOLDER-notarealslacktokenfixture"
        );
        std::fs::write(src.join("leaky.rs"), &planted).unwrap();
        // The same bytes under a `target/` component are deliberately outside
        // the guard's ground (design D2): build artifacts are excluded.
        let target = root.join("fake-crate").join("target");
        std::fs::create_dir_all(&target).unwrap();
        std::fs::write(target.join("artifact.rs"), &planted).unwrap();

        let (files, remaining) = run_scanner_clean_guard(&root, SOURCE_HYGIENE_ALLOW)
            .expect("guard walk+scan over the synthetic tree");
        assert_eq!(
            files.len(),
            2,
            "walk must see exactly the two regular non-target files"
        );
        assert_eq!(
            remaining.len(),
            1,
            "the shipped guard configuration must report exactly the plant"
        );
        assert!(remaining[0].path.ends_with("leaky.rs"));
        assert_eq!(remaining[0].line, 1);
        assert_eq!(remaining[0].rule, "slack-token");

        // Allow-filter scope: the exact (path-suffix, rule) pair excuses the
        // plant; a same-path entry for a different rule excuses nothing.
        let excused = run_scanner_clean_guard(&root, &[("leaky.rs", "slack-token")])
            .unwrap()
            .1;
        assert!(excused.is_empty());
        let wrong_rule = run_scanner_clean_guard(&root, &[("leaky.rs", "aws-access-key-id")])
            .unwrap()
            .1;
        assert_eq!(wrong_rule.len(), 1);

        // Fail-closed: a root whose walk errors must surface the error, never
        // report an empty (clean-looking) outcome.
        assert!(
            run_scanner_clean_guard(&root.join("no-such-dir"), SOURCE_HYGIENE_ALLOW).is_err(),
            "guard must fail closed when the walk itself fails"
        );

        std::fs::remove_dir_all(&root).unwrap();
    }

    /// Regression pin, discovered by `detection_is_invariant_to_token_position`
    /// (persisted seed: `proptest-regressions/checks/secrets.txt`): when the
    /// first scan window truncates a `ghp_` tail below its 36-char minimum
    /// AND the line carries a secret-ish keyword, the generic rule fires in
    /// that window before a later window can see the full curated token. The
    /// LABEL softens; detection never disappears — either way a finding is
    /// produced and the commit blocks. Pin the exact behavior so a future
    /// "fix" cannot turn the softened label into a miss.
    #[test]
    fn window_truncated_keyworded_token_still_blocks_as_generic() {
        let pad = MAX_SCAN_LINE - 45; // first window cuts the tail to 35 chars
        let line = format!("{}token=ghp_{}", "x".repeat(pad), "a1".repeat(20));
        assert_eq!(scan_line_windows(&line), Some("generic-secret-assignment"));
    }

    /// The gate `generic_secret_assignment` used BEFORE this change (design.md
    /// D1 baseline), reimplemented here — never in production code — purely
    /// as the reference point for `new_gate_implies_old_gate` below: any
    /// keyworded, non-placeholder, length->=20 value with at least one ASCII
    /// letter and one ASCII digit ANYWHERE in the value, with no requirement
    /// that they be contiguous.
    fn old_whole_value_gate(value: &str) -> bool {
        value.chars().any(|c| c.is_ascii_alphabetic()) && value.chars().any(|c| c.is_ascii_digit())
    }

    proptest! {
        #![proptest_config(ProptestConfig { cases: 64, ..ProptestConfig::default() })]

        /// Metamorphic position-invariance (seeded + reproducible: failures
        /// persist under `crates/mpd/proptest-regressions/`): a detectable
        /// value is found — under its own rule — no matter how much padding
        /// precedes it, including when the line exceeds `MAX_SCAN_LINE` and
        /// the match must come from a later window via the
        /// `SCAN_WINDOW_OVERLAP` straddle region. Guards the windowing logic
        /// and re-exercises the split rule literals at arbitrary offsets.
        /// The straddle band around the first window boundary is sampled
        /// explicitly, not left to chance. (Fixtures here carry no generic
        /// keyword, so no other rule can pre-empt the expected label at a
        /// truncation boundary; the keyworded variant of that edge is pinned
        /// by `window_truncated_keyworded_token_still_blocks_as_generic`.)
        #[test]
        fn detection_is_invariant_to_token_position(
            pad in prop_oneof![
                0usize..(MAX_SCAN_LINE * 2),
                (MAX_SCAN_LINE - 64)..(MAX_SCAN_LINE + 64),
            ],
            which in 0usize..3,
        ) {
            let (fixture, expected) = match which {
                0 => (
                    format!("xox{}", "b-EXAMPLE-PLACEHOLDER-notarealslacktokenfixture"),
                    "slack-token",
                ),
                1 => (
                    format!("key = AKIA{}", "IOSFODNN7EXAMPLE"),
                    "aws-access-key-id",
                ),
                _ => (format!("ghp_{}", "a1".repeat(20)), "github-token"),
            };
            let line = format!("{}{}", "x".repeat(pad), fixture);
            prop_assert_eq!(scan_line_windows(&line), Some(expected));
        }

        /// Security-plan Condition 4 / design.md Condition 12 (archive-blocker):
        /// values decomposed into 3-8 segments over `[a-w0-9]{1,15}`, joined
        /// by separators outside the token alphabet (`/ - _` and a space),
        /// can never assemble a run >= MIN_TOKEN_RUN — every join breaks the
        /// run and no single segment reaches the threshold on its own — so
        /// the GENERIC rule must never fire on them. Asserted RULE-SPECIFIC
        /// (`!= Some("generic-secret-assignment")`), NOT `== None`: the
        /// `[a-w0-9]` segment alphabet plus `-`/`_` joins can occasionally
        /// compose a tail that legitimately trips a CURATED rule (e.g. an
        /// `sk-`-shaped prefix); that is a different rule's concern and must
        /// not seed-persist a spurious failure here.
        #[test]
        fn separator_decomposed_values_are_never_generic_flagged(
            segments in prop::collection::vec("[a-w0-9]{1,15}", 3..=8),
            seps in prop::collection::vec(
                prop_oneof![Just('/'), Just('-'), Just('_'), Just(' ')],
                7,
            ),
        ) {
            let mut value = String::new();
            for (i, segment) in segments.iter().enumerate() {
                if i > 0 {
                    value.push(seps[i - 1]);
                }
                value.push_str(segment);
            }
            let line = format!("token = \"{}\"", value);
            prop_assert_ne!(scan_line(&line), Some("generic-secret-assignment"));
        }

        /// The mirror image of the property above: a single undecomposed run
        /// over `[a-w0-9]` of length 20-64 (guaranteed by construction to
        /// carry both a letter and a digit) is exactly the shape the generic
        /// rule exists to catch, and the constrained alphabet (no separators,
        /// no uppercase) guarantees no curated rule can pre-empt the label.
        #[test]
        fn contiguous_alnum_tokens_are_flagged(
            value in "[a-w0-9]{20,64}".prop_filter(
                "letter + digit, and no PLACEHOLDERS substring (which the rule \
                 suppresses — `todo`/`changeme`/`redacted`/`placeholder`/`dummy` \
                 are all composable in `[a-w0-9]`, so an unfiltered generator \
                 seed-persists a spurious failure)",
                |v: &String| {
                    v.chars().any(|c| c.is_ascii_alphabetic())
                        && v.chars().any(|c| c.is_ascii_digit())
                        && !PLACEHOLDERS.iter().any(|p| v.contains(p))
                },
            ),
        ) {
            let line = format!("token = \"{}\"", value);
            prop_assert_eq!(scan_line(&line), Some("generic-secret-assignment"));
        }

        /// Direct monotonicity proof (Security-plan Condition 2 / design.md
        /// Condition 11, archive-blocker): over ARBITRARY strings — not just
        /// credential-shaped ones — the new gate implies the old one. This is
        /// the mechanical, permanent version of the "no new false positive"
        /// claim: it cannot regress silently, because any counterexample
        /// shrinks and persists under `proptest-regressions/`.
        #[test]
        fn new_gate_implies_old_gate(value in any::<String>()) {
            if has_contiguous_token_run(&value) {
                prop_assert!(old_whole_value_gate(&value));
            }
        }
    }
}
