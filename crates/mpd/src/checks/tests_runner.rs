//! Running the configured test command and verifying a real pass count.
//!
//! The Build and Test gates cannot accept a caller's word that tests pass —
//! they must observe it. This runs the command and parses a pass count from
//! common frameworks (libtest, pytest, jest, go). A gate that requires tests
//! rejects PASS unless the command exited zero *and* a non-zero count was seen.

use std::path::Path;
use std::process::Command;

/// The result of running the test command.
#[derive(Debug, Clone)]
pub struct TestOutcome {
    /// Whether the command exited successfully.
    pub success: bool,
    /// Parsed pass count, when a recognized framework format was found.
    pub passed: Option<usize>,
    /// The command that was run.
    pub command: String,
    /// A short human summary line.
    pub summary: String,
}

impl TestOutcome {
    /// Whether this outcome is strong enough to back a PASS verdict: the command
    /// succeeded and a non-zero pass count was observed.
    pub fn verified(&self) -> bool {
        self.success && matches!(self.passed, Some(n) if n > 0)
    }
}

/// Run `command` in `dir` via the system shell, capturing output.
pub fn run(command: &str, dir: &Path) -> TestOutcome {
    let output = Command::new("sh")
        .arg("-c")
        .arg(command)
        .current_dir(dir)
        .output();

    match output {
        Ok(out) => {
            let mut combined = String::from_utf8_lossy(&out.stdout).into_owned();
            combined.push_str(&String::from_utf8_lossy(&out.stderr));
            let passed = parse_pass_count(&combined);
            let success = out.status.success();
            let summary = match (success, passed) {
                (true, Some(n)) => format!("passed ({n} tests)"),
                (true, None) => "exited 0 but pass count unverified".to_string(),
                (false, _) => "test command failed".to_string(),
            };
            TestOutcome {
                success,
                passed,
                command: command.to_string(),
                summary,
            }
        }
        Err(e) => TestOutcome {
            success: false,
            passed: None,
            command: command.to_string(),
            summary: format!("could not launch test command: {e}"),
        },
    }
}

/// Parse and sum pass counts from recognized framework output.
///
/// Handles libtest (`test result: ok. 12 passed`), pytest (`12 passed`), jest
/// (`Tests: 12 passed`), any `N passed` token, and Swift Testing
/// (`Test run with N tests ... passed`). Returns `None` if no count is found
/// (which callers treat as *unverified*, not zero).
pub fn parse_pass_count(output: &str) -> Option<usize> {
    let tokens: Vec<&str> = output.split_whitespace().collect();
    let mut total = 0usize;
    let mut found = false;
    for pair in tokens.windows(2) {
        // Look for `<number> passed`.
        let word = pair[1].trim_end_matches([',', '.', ';']);
        if word == "passed" {
            if let Ok(n) = pair[0].trim_end_matches([',', '.']).parse::<usize>() {
                total += n;
                found = true;
            }
        }
    }
    // Swift Testing prints `✔ Test run with <N> tests in <M> suites passed after
    // …` — the count is not adjacent to `passed`, so the token scan above misses
    // it. Fall back to summing the per-run totals from those success lines (one
    // per test bundle). A failed run says `… failed` and also exits non-zero,
    // which the caller already rejects, so only `passed` lines are counted.
    if !found {
        for line in output.lines() {
            if !line.contains("passed") {
                continue;
            }
            if let Some(rest) = line.split("Test run with ").nth(1) {
                if let Some(num) = rest.split_whitespace().next() {
                    if let Ok(n) = num.trim_end_matches([',', '.']).parse::<usize>() {
                        total += n;
                        found = true;
                    }
                }
            }
        }
    }
    if found {
        Some(total)
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_libtest() {
        let out = "test result: ok. 22 passed; 0 failed; 0 ignored";
        assert_eq!(parse_pass_count(out), Some(22));
    }

    #[test]
    fn sums_multiple_binaries() {
        let out = "test result: ok. 5 passed; 0 failed\n\
                   test result: ok. 9 passed; 0 failed";
        assert_eq!(parse_pass_count(out), Some(14));
    }

    #[test]
    fn parses_pytest() {
        assert_eq!(parse_pass_count("==== 12 passed in 0.3s ===="), Some(12));
    }

    #[test]
    fn no_count_is_none() {
        assert_eq!(parse_pass_count("Compiling; Finished"), None);
    }

    #[test]
    fn zero_passed_is_some_zero() {
        // "0 passed" is a parseable count — callers reject it as non-positive.
        assert_eq!(parse_pass_count("test result: ok. 0 passed"), Some(0));
    }

    #[test]
    fn parses_swift_testing() {
        let out = "\u{25c7} Test run started.\n\
                   \u{2714} Suite \"App launch state\" passed after 0.1 seconds.\n\
                   \u{2714} Test run with 3108 tests in 308 suites passed after 141.0 seconds.";
        assert_eq!(parse_pass_count(out), Some(3108));
    }

    #[test]
    fn sums_multiple_swift_testing_bundles() {
        let out = "\u{2714} Test run with 3108 tests in 308 suites passed after 141s.\n\
                   \u{2714} Test run with 34 tests in 1 suite passed after 3s.";
        assert_eq!(parse_pass_count(out), Some(3142));
    }

    #[test]
    fn swift_testing_failure_line_is_not_counted() {
        // A failed run says "failed" (and exits non-zero); no false pass count.
        let out = "\u{2716} Test run with 10 tests in 2 suites failed after 1s.";
        assert_eq!(parse_pass_count(out), None);
    }
}
