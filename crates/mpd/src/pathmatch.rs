//! The shared `*`/`**` repository-relative path-pattern matcher.
//!
//! Originally lived only in [`crate::allowlist`] (secret-scanner
//! suppressions); the change-manifest scope patterns
//! (`openspec/changes/<name>/manifest.json`'s `paths`/`shared_paths`) use the
//! identical `*`/`**` semantics, so this is the single shared implementation
//! both consume. Behavior is unchanged from the original — this is a pure
//! extraction, not a rewrite.

/// Minimal glob match over `/`-separated paths: `*` matches within a segment,
/// `**` matches across segments (zero or more).
///
/// Segment matching uses the standard iterative last-star algorithm — no
/// recursion and no backtracking explosion — so a crafted pattern with many
/// non-consecutive `**` tokens cannot cause catastrophic runtime or a stack
/// overflow (patterns can originate from a tracked, AI-composed manifest or
/// allowlist file processed by an automated gate).
pub fn glob_match(pattern: &str, text: &str) -> bool {
    let pat: Vec<&str> = pattern.split('/').collect();
    let txt: Vec<&str> = text.split('/').collect();
    match_segments(&pat, &txt)
}

/// Whether at least one strict descendant of `prefix` can match `pattern`.
///
/// Candidate capture uses this to prune unrelated worktree directories before
/// enumeration.  The computation is a small NFA over path segments: `**` may
/// consume a segment or advance without one, while every other segment must
/// match exactly once.  A reachable non-terminal state after consuming the
/// prefix means some additional segment sequence can complete the pattern.
pub fn glob_may_match_descendant(pattern: &str, prefix: &str) -> bool {
    let pat: Vec<&str> = pattern.split('/').collect();
    let txt: Vec<&str> = prefix.split('/').collect();
    let mut states = vec![false; pat.len() + 1];
    states[0] = true;
    epsilon_close(&pat, &mut states);

    for segment in txt {
        let mut next = vec![false; pat.len() + 1];
        for (index, reachable) in states.iter().copied().enumerate().take(pat.len()) {
            if !reachable {
                continue;
            }
            if pat[index] == "**" {
                next[index] = true;
            } else if segment_match(pat[index], segment) {
                next[index + 1] = true;
            }
        }
        epsilon_close(&pat, &mut next);
        states = next;
        if !states.iter().any(|reachable| *reachable) {
            return false;
        }
    }

    states[..pat.len()].iter().any(|reachable| *reachable)
}

fn epsilon_close(pattern: &[&str], states: &mut [bool]) {
    for index in 0..pattern.len() {
        if states[index] && pattern[index] == "**" {
            states[index + 1] = true;
        }
    }
}

fn match_segments(pat: &[&str], txt: &[&str]) -> bool {
    let (mut pi, mut ti) = (0usize, 0usize);
    // The most recent `**` position, and where in `txt` it started matching.
    let (mut star, mut mark) = (None, 0usize);
    while ti < txt.len() {
        if pi < pat.len() && pat[pi] != "**" && segment_match(pat[pi], txt[ti]) {
            pi += 1;
            ti += 1;
        } else if pi < pat.len() && pat[pi] == "**" {
            star = Some(pi);
            mark = ti;
            pi += 1;
        } else if let Some(s) = star {
            // Backtrack: let the last `**` consume one more segment.
            pi = s + 1;
            mark += 1;
            ti = mark;
        } else {
            return false;
        }
    }
    // Any trailing pattern must be all `**` (each matching zero segments).
    while pi < pat.len() && pat[pi] == "**" {
        pi += 1;
    }
    pi == pat.len()
}

/// Wildcard match within a single path segment: `*` matches any run of
/// characters, `?` matches one. No `/` may appear here.
fn segment_match(pat: &str, text: &str) -> bool {
    let p: Vec<char> = pat.chars().collect();
    let t: Vec<char> = text.chars().collect();
    let (mut pi, mut ti) = (0usize, 0usize);
    let (mut star, mut mark) = (None, 0usize);
    while ti < t.len() {
        if pi < p.len() && (p[pi] == '?' || p[pi] == t[ti]) {
            pi += 1;
            ti += 1;
        } else if pi < p.len() && p[pi] == '*' {
            star = Some(pi);
            mark = ti;
            pi += 1;
        } else if let Some(s) = star {
            pi = s + 1;
            mark += 1;
            ti = mark;
        } else {
            return false;
        }
    }
    while pi < p.len() && p[pi] == '*' {
        pi += 1;
    }
    pi == p.len()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn glob_basics() {
        assert!(glob_match("Tests/**", "Tests/foo/Bar.swift"));
        assert!(glob_match("Tests/**", "Tests/Bar.swift"));
        assert!(glob_match("Tests/**", "Tests"));
        assert!(!glob_match("Tests/**", "Sources/Tests/x"));
        assert!(glob_match("**/spec.md", "a/b/spec.md"));
        assert!(glob_match("**/spec.md", "spec.md"));
        assert!(glob_match("*.pem", "server.pem"));
        assert!(!glob_match("*.pem", "dir/server.pem"));
        assert!(glob_match("src/*.rs", "src/main.rs"));
        assert!(!glob_match("src/*.rs", "src/a/main.rs"));
        assert!(glob_match("a/**/c", "a/c"));
        assert!(glob_match("a/**/c", "a/b/x/c"));
    }

    #[test]
    fn descendant_feasibility_prunes_only_impossible_subtrees() {
        assert!(glob_may_match_descendant("src/**", "src"));
        assert!(glob_may_match_descendant("src/**", "src/nested"));
        assert!(!glob_may_match_descendant("src/**", "target"));
        assert!(glob_may_match_descendant("src/*.rs", "src"));
        assert!(!glob_may_match_descendant("src/*.rs", "src/nested"));
        assert!(glob_may_match_descendant("**/spec.md", "target"));
        assert!(glob_may_match_descendant("a/**/c", "a/b"));
        assert!(!glob_may_match_descendant("README.md", "README.md"));
    }

    #[test]
    fn consecutive_double_stars_are_collapsed() {
        assert!(glob_match("**/**/**/x", "a/b/c/x"));
        assert!(glob_match("**/**", "a/b/c"));
    }

    #[test]
    fn pathological_pattern_terminates() {
        // Many non-consecutive `**` against a long non-matching path must not
        // blow up (guards the ReDoS fix). The test completing IS the assertion.
        let pat = "**/a/**/a/**/a/**/a/**/a/**/a/**/a/**/a/**/a/**/a";
        let path = format!("{}y", "x/".repeat(80));
        assert!(!glob_match(pat, &path));
        // And a matching pathological case still resolves true.
        assert!(glob_match("**/a/**/b", "z/z/a/z/z/b"));
    }
}
