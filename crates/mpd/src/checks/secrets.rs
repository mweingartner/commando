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

/// Maximum bytes of a line actually scanned. Real secret tokens are short;
/// bounding the prefix keeps the repeated pattern scans linear against an
/// adversarial multi-megabyte single line (scanner DoS defense).
const MAX_SCAN_LINE: usize = 4096;

/// Scan a single file's text for secret patterns.
pub fn scan_text(path: &str, text: &str) -> Vec<Finding> {
    let mut findings = Vec::new();
    for (i, line) in text.split('\n').enumerate() {
        let line_no = i + 1;
        // Bound work per line at a UTF-8 char boundary (portable; avoids the
        // 1.91-only `floor_char_boundary`).
        let scanned = if line.len() > MAX_SCAN_LINE {
            let mut end = MAX_SCAN_LINE;
            while end > 0 && !line.is_char_boundary(end) {
                end -= 1;
            }
            &line[..end]
        } else {
            line
        };
        if let Some(rule) = scan_line(scanned) {
            findings.push(Finding {
                path: path.to_string(),
                line: line_no,
                rule,
            });
        }
    }
    findings
}

/// Inspect one line, returning the first matching rule.
fn scan_line(line: &str) -> Option<&'static str> {
    if line.contains("-----BEGIN") && line.contains("PRIVATE KEY") {
        return Some("private-key-block");
    }
    if has_aws_access_key(line) {
        return Some("aws-access-key-id");
    }
    if line.contains("xoxb-") || line.contains("xoxp-") || line.contains("xoxa-") {
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
                if after.map_or(true, |b| !(b.is_ascii_alphanumeric())) {
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
/// and the value looks like real entropy (not a placeholder).
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
    let has_alpha = value.chars().any(|c| c.is_ascii_alphabetic());
    let has_digit = value.chars().any(|c| c.is_ascii_digit());
    has_alpha && has_digit
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

/// Scan a set of files on disk. Filename rules apply even when a file cannot be
/// read as UTF-8; content rules apply to readable text under the size cap.
pub fn scan_paths(paths: &[PathBuf]) -> io::Result<Vec<Finding>> {
    let mut findings = Vec::new();
    for path in paths {
        if let Some(rule) = suspicious_filename(path) {
            findings.push(Finding {
                path: path.display().to_string(),
                line: 0,
                rule,
            });
        }
        // Skip content scanning for oversized files (filename rule already ran).
        if std::fs::metadata(path).map(|m| m.len()).unwrap_or(0) > MAX_FILE_BYTES {
            continue;
        }
        if let Ok(text) = std::fs::read_to_string(path) {
            findings.extend(scan_text(&path.display().to_string(), &text));
        }
    }
    Ok(findings)
}

#[cfg(test)]
mod tests {
    use super::*;

    // Fixture secrets are assembled from split literals so the source file
    // itself contains no contiguous credential pattern (keeps generic secret
    // scanners — including the commit gate — from flagging the test data).

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
    fn ignores_ordinary_code() {
        assert_eq!(scan_line("let token = next_token();"), None);
        assert_eq!(scan_line("// remember to rotate the password"), None);
        assert_eq!(scan_line("fn secret() -> u32 { 42 }"), None);
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
        assert_eq!(
            scan_line("AWS_SECRET=hunter2verylongvalue1234567"),
            Some("generic-secret-assignment")
        );
        assert_eq!(
            scan_line("password: hunter2verylongvalue1234567"),
            Some("generic-secret-assignment")
        );
    }

    #[test]
    fn long_line_is_bounded() {
        // A pathological long line must not hang the scanner.
        let mut s = String::from("api_key = \"");
        s.push_str(&"A1".repeat(2_000_000));
        s.push('"');
        let _ = scan_text("big", &s); // completes quickly due to MAX_SCAN_LINE
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
}
