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
        // An ambient containment marker must never leak into an uncontained
        // test run: guarded suites would silently skip and count as passes.
        .env_remove("MPD_SANDBOXED")
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
/// (`Tests: 12 passed`), any `N passed` token, Swift Testing
/// (`Test run with N tests ... passed`), and XCTest top-level suite summaries
/// (`Executed N tests, with 0 failures`). Returns `None` if no count is found
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

    // XCTest emits one summary for every nested suite, so summing every
    // `Executed` line would wildly over-count. Count only summaries paired with
    // the outer `All tests` suite. Some direct xctest invocations omit that
    // wrapper; in that case, fall back to the `.xctest` bundle summary.
    let lines: Vec<&str> = output.lines().collect();
    let all_tests_total = xctest_suite_total(&lines, "Test Suite 'All tests' passed");
    let xctest_total = if all_tests_total.is_some() {
        all_tests_total
    } else {
        xctest_bundle_total(&lines)
    };
    if let Some(n) = xctest_total {
        total += n;
        found = true;
    }
    if found {
        Some(total)
    } else {
        None
    }
}

fn xctest_suite_total(lines: &[&str], marker: &str) -> Option<usize> {
    let mut total = 0usize;
    let mut found = false;
    for (index, line) in lines.iter().enumerate() {
        if !line.contains(marker) {
            continue;
        }
        if let Some(count) = lines
            .get(index + 1)
            .and_then(|line| xctest_executed_count(line))
        {
            total += count;
            found = true;
        }
    }
    found.then_some(total)
}

fn xctest_bundle_total(lines: &[&str]) -> Option<usize> {
    let mut total = 0usize;
    let mut found = false;
    for (index, line) in lines.iter().enumerate() {
        if !line.contains(".xctest' passed") {
            continue;
        }
        if let Some(count) = lines
            .get(index + 1)
            .and_then(|line| xctest_executed_count(line))
        {
            total += count;
            found = true;
        }
    }
    found.then_some(total)
}

fn xctest_executed_count(line: &str) -> Option<usize> {
    let rest = line.trim().strip_prefix("Executed ")?;
    let count = rest.split_whitespace().next()?.parse::<usize>().ok()?;
    let failures = rest.split("with ").nth(1)?.split_whitespace().next()?;
    (failures == "0").then_some(count)
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

    #[test]
    fn parses_xctest_without_counting_nested_suites_twice() {
        let out = "Test Suite 'SavedWorldTests' passed at 2026-07-12 12:00:00.000.\n\
                   \t Executed 24 tests, with 0 failures (0 unexpected) in 6.1 seconds\n\
                   Test Suite 'PebbleCoreTests.xctest' passed at 2026-07-12 12:00:01.000.\n\
                   \t Executed 1029 tests, with 0 failures (0 unexpected) in 220.0 seconds\n\
                   Test Suite 'All tests' passed at 2026-07-12 12:00:01.001.\n\
                   \t Executed 1029 tests, with 0 failures (0 unexpected) in 220.0 seconds";
        assert_eq!(parse_pass_count(out), Some(1029));
    }

    #[test]
    fn combines_xctest_with_empty_swift_testing_runner() {
        let out = "Test Suite 'All tests' passed at 2026-07-12 12:00:01.001.\n\
                   \t Executed 1029 tests, with 0 failures (0 unexpected) in 220.0 seconds\n\
                   \u{2714} Test run with 0 tests in 0 suites passed after 0.001 seconds.";
        assert_eq!(parse_pass_count(out), Some(1029));
    }

    #[test]
    fn refuses_xctest_failure_summary() {
        let out = "Test Suite 'All tests' failed at 2026-07-12 12:00:01.001.\n\
                   \t Executed 1029 tests, with 1 failure (0 unexpected) in 220.0 seconds";
        assert_eq!(parse_pass_count(out), None);
    }
}
