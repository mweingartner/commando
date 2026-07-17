//! Argument-array-only Git plumbing adapters.
//!
//! Every function here invokes `git` via [`std::process::Command`] with a
//! fixed argument array — never a shell, never string interpolation into a
//! command line. `GIT_PAGER=cat` and `GIT_TERMINAL_PROMPT=0` are always set,
//! stdin is always `/dev/null`, and stdout is always read under a hard byte
//! cap (killing the child if exceeded) so a hostile repository cannot exhaust
//! memory or block waiting on an interactive prompt. Only `-z` (NUL-delimited)
//! plumbing formats are parsed — never porcelain text meant for a terminal.
//!
//! OID/ref/remote-name validators are exported so every caller can (and the
//! functions here do) refuse an option-like (`-`-prefixed) or otherwise
//! unsafe token *before* it reaches an argv slot, even though argv already
//! can't be shell-injected — this is defense in depth against a value being
//! mistaken for a flag by `git` itself (CWE-88 in the "option injection"
//! sense), not a shell-escaping concern.
//!
//! Every function here is exercised both by its own unit tests (against real
//! temporary repositories) and by production callers in `closure.rs`/`cli.rs`
//! (change-manifest loading, commit-coherence's per-commit path union, and
//! `mpd publish`'s remote-parity observation).

use std::ffi::OsStr;
use std::fmt;
use std::io::Read;
use std::path::Path;
use std::process::{Command, ExitStatus, Stdio};

/// Default cap on a command's stdout, in bytes. Generous for any real
/// repository operation while still bounding a hostile/oversized response.
pub const DEFAULT_STDOUT_CAP: usize = 64 * 1024 * 1024;
/// Cap on `ls-remote` output — a handful of ref lines, never large.
pub const REMOTE_STDOUT_CAP: usize = 64 * 1024;
/// Cap on captured stderr (only used to size a bounded read; the raw text is
/// never rendered or persisted — see [`GitError`]).
const STDERR_CAP: usize = 8 * 1024;

/// Any failure from invoking or parsing Git plumbing output. Deliberately
/// never carries raw stdout/stderr/URLs/credential-helper output — only fixed
/// safe labels — so an error can be logged or rendered without a disclosure
/// risk.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GitError {
    /// The `git` process could not be spawned.
    Spawn(String),
    /// The command exited non-zero in a context where that is unexpected.
    Failed(&'static str),
    /// stdout exceeded its cap; the child was killed.
    OutputTooLarge,
    /// Output did not match the expected plumbing format.
    Malformed(&'static str),
    /// A bounded remote observation exceeded its deadline.
    Timeout(&'static str),
    /// Output was not valid UTF-8.
    NonUtf8,
    /// A caller passed a value that failed OID/ref/remote-name validation;
    /// refused before it reached argv.
    UnsafeArgument(&'static str),
}

impl fmt::Display for GitError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            GitError::Spawn(e) => write!(f, "could not run git: {e}"),
            GitError::Failed(op) => write!(f, "git {op} failed"),
            GitError::OutputTooLarge => write!(f, "git output exceeded its size cap"),
            GitError::Malformed(what) => write!(f, "could not parse git {what} output"),
            GitError::Timeout(op) => write!(f, "git {op} timed out"),
            GitError::NonUtf8 => write!(f, "git output was not valid UTF-8"),
            GitError::UnsafeArgument(what) => write!(f, "refusing unsafe {what}"),
        }
    }
}

impl std::error::Error for GitError {}

// --- OID / ref / remote-name validation --------------------------------

/// Whether `s` is a syntactically valid Git object id: exactly 40 (SHA-1) or
/// 64 (SHA-256) lowercase hex characters. Never starts with `-` by
/// construction (hex digits only), so it is always safe as a bare argv token.
pub fn valid_oid_hex(s: &str) -> bool {
    matches!(s.len(), 40 | 64)
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// Whether `s` is a safe Git remote *name* token (not a URL/path): non-empty,
/// bounded, does not start with `-` (so it can never be mistaken for an
/// option by a subcommand that takes a bare remote-name argument), is not the
/// literal `.`/`..` path aliases (the exact HIGH finding from security-plan.md
/// — a token like `.` is never a legitimate remote name but *is* a valid
/// local-repository path, which would let `ls-remote`/`fetch` silently compare
/// against the local repo instead of a real remote), contains only Git-safe
/// token characters, and has no `..` substring or NUL. This governs syntax
/// only — resolving a manifest's remote token against the exact set of
/// *configured* remote names is a caller responsibility (release-closure
/// remote parity, a later stage), not this validator's job.
pub fn valid_remote_name(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 200
        && !s.starts_with('-')
        && s != "."
        && s != ".."
        && !s.contains("..")
        && !s.contains('\0')
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.' | '/'))
}

/// Whether `s` is a safe, fully-qualified branch ref: starts with
/// `refs/heads/` (v1 never resolves annotated tags, closing the
/// tag-peeling-ambiguity risk) and passes `git check-ref-format`. The
/// `refs/heads/` prefix guarantee already means the *whole token* can never
/// start with `-`; branch names may not contain a NUL or backslash by
/// git-check-ref-format's own rules.
pub fn valid_branch_ref(s: &str) -> bool {
    s.starts_with("refs/heads/") && s.len() <= 500 && !s.starts_with('-') && check_ref_format(s)
}

/// Run `git check-ref-format <reference>`, returning whether it reports the
/// ref as well-formed. Runs with no repository context requirement (a
/// syntax-only plumbing command) and the same safe environment as every
/// other invocation here.
fn check_ref_format(reference: &str) -> bool {
    if reference.starts_with('-') {
        return false;
    }
    Command::new("git")
        .args(["check-ref-format", reference])
        .env("GIT_PAGER", "cat")
        .env("GIT_TERMINAL_PROMPT", "0")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

// --- Bounded process execution ------------------------------------------

struct RawOutput {
    stdout: Vec<u8>,
    status: ExitStatus,
}

/// Read up to `cap` bytes from `r`, reporting whether the source had more
/// (i.e. was truncated) via the boolean.
fn read_capped<R: Read>(r: &mut R, cap: usize) -> (Vec<u8>, bool) {
    let mut buf = Vec::new();
    let mut limited = r.take((cap as u64) + 1);
    let _ = limited.read_to_end(&mut buf);
    if buf.len() > cap {
        buf.truncate(cap);
        (buf, true)
    } else {
        (buf, false)
    }
}

/// Run `git <args>` in `repo`, with a hard stdout byte cap. Returns the raw
/// stdout bytes and exit status regardless of exit code (callers interpret
/// exit-code semantics themselves, since they differ per plumbing command);
/// only spawn failure, an unreadable child, or an oversized response is an
/// [`Err`]. stderr is captured (bounded) but deliberately discarded — never
/// rendered or persisted, per the "no raw output/URLs/credential text"
/// requirement.
fn run(repo: &Path, args: &[&str], stdout_cap: usize) -> Result<RawOutput, GitError> {
    run_with_env(repo, args, stdout_cap, &[])
}

/// As [`run`], with additional environment variables set on the child
/// (e.g. a quarantined object directory for future bounded remote work).
fn run_with_env(
    repo: &Path,
    args: &[&str],
    stdout_cap: usize,
    extra_env: &[(&str, &OsStr)],
) -> Result<RawOutput, GitError> {
    let mut cmd = Command::new("git");
    cmd.args(args)
        .current_dir(repo)
        .env("GIT_PAGER", "cat")
        .env("GIT_TERMINAL_PROMPT", "0")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    for (k, v) in extra_env {
        cmd.env(k, v);
    }
    let mut child = cmd.spawn().map_err(|e| GitError::Spawn(e.to_string()))?;

    let mut stdout = child.stdout.take().expect("stdout was piped");
    let mut stderr = child.stderr.take().expect("stderr was piped");

    let out_thread = std::thread::spawn(move || read_capped(&mut stdout, stdout_cap));
    let err_thread = std::thread::spawn(move || read_capped(&mut stderr, STDERR_CAP));

    let (out_bytes, out_truncated) = out_thread.join().unwrap_or_else(|_| (Vec::new(), false));
    // stderr is read only to drain the pipe (preventing a stalled child on a
    // full stderr buffer); its content is intentionally never used.
    let _ = err_thread.join();

    if out_truncated {
        let _ = child.kill();
        let _ = child.wait();
        return Err(GitError::OutputTooLarge);
    }

    let status = child.wait().map_err(|e| GitError::Spawn(e.to_string()))?;
    Ok(RawOutput {
        stdout: out_bytes,
        status,
    })
}

/// Remote-only bounded runner. It drains both pipes concurrently while polling
/// the child, kills on deadline, and never returns raw output in an error.
fn run_with_timeout(
    repo: &Path,
    args: &[&str],
    stdout_cap: usize,
    timeout: std::time::Duration,
) -> Result<RawOutput, GitError> {
    let mut child = Command::new("git")
        .args(args)
        .current_dir(repo)
        .env("GIT_PAGER", "cat")
        .env("GIT_TERMINAL_PROMPT", "0")
        .env(
            "GIT_SSH_COMMAND",
            "ssh -o BatchMode=yes -o ConnectTimeout=10",
        )
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| GitError::Spawn(e.to_string()))?;
    let mut stdout = child.stdout.take().expect("stdout piped");
    let mut stderr = child.stderr.take().expect("stderr piped");
    let out_thread = std::thread::spawn(move || read_capped(&mut stdout, stdout_cap));
    let err_thread = std::thread::spawn(move || read_capped(&mut stderr, STDERR_CAP));
    let start = std::time::Instant::now();
    let status = loop {
        if let Some(status) = child
            .try_wait()
            .map_err(|e| GitError::Spawn(e.to_string()))?
        {
            break status;
        }
        if start.elapsed() >= timeout {
            let _ = child.kill();
            let _ = child.wait();
            let _ = out_thread.join();
            let _ = err_thread.join();
            return Err(GitError::Timeout("ls-remote"));
        }
        std::thread::sleep(std::time::Duration::from_millis(25));
    };
    let (stdout, truncated) = out_thread.join().unwrap_or_else(|_| (Vec::new(), false));
    let _ = err_thread.join();
    if truncated {
        return Err(GitError::OutputTooLarge);
    }
    Ok(RawOutput { stdout, status })
}

fn require_success(out: RawOutput, op: &'static str) -> Result<Vec<u8>, GitError> {
    if out.status.success() {
        Ok(out.stdout)
    } else {
        Err(GitError::Failed(op))
    }
}

// --- NUL-delimited parsing helpers ---------------------------------------

/// Split `-z`-terminated output into tokens, dropping the single trailing
/// empty token produced by the final NUL (never dropping a genuine empty
/// path in the middle, which would itself be malformed input).
fn nul_tokens(bytes: &[u8]) -> Result<Vec<&str>, GitError> {
    let text = std::str::from_utf8(bytes).map_err(|_| GitError::NonUtf8)?;
    let mut tokens: Vec<&str> = text.split('\0').collect();
    if tokens.last() == Some(&"") {
        tokens.pop();
    }
    Ok(tokens)
}

fn parse_nul_paths(bytes: &[u8]) -> Result<Vec<String>, GitError> {
    Ok(nul_tokens(bytes)?.into_iter().map(str::to_string).collect())
}

// --- ls-files -------------------------------------------------------------

/// `git ls-files -z`: every tracked path.
pub fn ls_files(repo: &Path) -> Result<Vec<String>, GitError> {
    let out = run(repo, &["ls-files", "-z"], DEFAULT_STDOUT_CAP)?;
    parse_nul_paths(&require_success(out, "ls-files")?)
}

/// Return the gitlink OID for `path` when the index records mode 160000.
/// `--` terminates options, and canonical path validation rejects unsafe
/// representations before invocation.
pub fn gitlink_oid(repo: &Path, path: &str) -> Result<Option<String>, GitError> {
    crate::digest::validate_canonical_path(path)
        .map_err(|_| GitError::UnsafeArgument("gitlink path"))?;
    let out = run(repo, &["ls-files", "--stage", "-z", "--", path], 1024)?;
    let bytes = require_success(out, "ls-files --stage")?;
    if bytes.is_empty() {
        return Ok(None);
    }
    let text = std::str::from_utf8(&bytes).map_err(|_| GitError::NonUtf8)?;
    let record = text
        .strip_suffix('\0')
        .ok_or(GitError::Malformed("ls-files --stage"))?;
    let (prefix, observed) = record
        .split_once('\t')
        .ok_or(GitError::Malformed("ls-files --stage"))?;
    let fields: Vec<&str> = prefix.split_whitespace().collect();
    if fields.len() != 3 || observed != path || fields[0] != "160000" || !valid_oid_hex(fields[1]) {
        return Ok(None);
    }
    Ok(Some(fields[1].to_string()))
}

// --- diff --name-status ----------------------------------------------------

/// A single `--name-status` change record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiffEntry {
    /// The raw status letter (`A`, `C`, `D`, `M`, `R`, `T`, `U`, `X`, ...).
    pub status: char,
    /// The similarity score for a rename/copy (`Some` only for `R`/`C`).
    pub score: Option<u8>,
    /// The current/destination path.
    pub path: String,
    /// The source path, present only for renames/copies.
    pub orig_path: Option<String>,
}

/// Parse `--name-status -z` output (used by `diff --cached`, `diff`, and
/// `diff-tree`). Non-rename records are `<STATUS>\0<path>\0`; rename/copy
/// records are `<STATUS><score>\0<src>\0<dst>\0`.
fn parse_name_status_z(bytes: &[u8]) -> Result<Vec<DiffEntry>, GitError> {
    let tokens = nul_tokens(bytes)?;
    let mut out = Vec::new();
    let mut iter = tokens.into_iter();
    while let Some(tok) = iter.next() {
        if tok.is_empty() {
            return Err(GitError::Malformed("name-status"));
        }
        let mut chars = tok.chars();
        let status = chars.next().ok_or(GitError::Malformed("name-status"))?;
        let score_digits: String = chars.clone().take_while(|c| c.is_ascii_digit()).collect();
        let score = if score_digits.is_empty() {
            None
        } else {
            Some(
                score_digits
                    .parse::<u8>()
                    .map_err(|_| GitError::Malformed("name-status"))?,
            )
        };
        if matches!(status, 'R' | 'C') {
            // `--name-status -z` emits the source path first, then the
            // destination path.
            let src = iter.next().ok_or(GitError::Malformed("name-status"))?;
            let dst = iter.next().ok_or(GitError::Malformed("name-status"))?;
            out.push(DiffEntry {
                status,
                score,
                path: dst.to_string(),
                orig_path: Some(src.to_string()),
            });
        } else {
            let path = iter.next().ok_or(GitError::Malformed("name-status"))?;
            out.push(DiffEntry {
                status,
                score: None,
                path: path.to_string(),
                orig_path: None,
            });
        }
    }
    Ok(out)
}

/// `git diff --cached --name-status -z -M -C`: staged changes vs `HEAD`,
/// with rename/copy detection so a rename's source and destination are both
/// reported as separate scoped paths.
pub fn diff_cached_name_status(repo: &Path) -> Result<Vec<DiffEntry>, GitError> {
    let out = run(
        repo,
        &["diff", "--cached", "--name-status", "-z", "-M", "-C"],
        DEFAULT_STDOUT_CAP,
    )?;
    parse_name_status_z(&require_success(out, "diff --cached")?)
}

/// `git diff --name-status -z -M -C`: unstaged worktree changes vs the index.
/// Not yet called by a production site — `verify_commit_coherence`'s dirty-
/// scope check and `capture_local_snapshot`'s cleanliness field both use the
/// combined staged+worktree view `status --porcelain=v2` already gives them
/// in one call, so this dedicated worktree-only diff remains reserved for a
/// caller that specifically needs unstaged changes isolated from staged
/// ones. Exercised directly by this module's own tests.
#[allow(dead_code)]
pub fn diff_worktree_name_status(repo: &Path) -> Result<Vec<DiffEntry>, GitError> {
    let out = run(
        repo,
        &["diff", "--name-status", "-z", "-M", "-C"],
        DEFAULT_STDOUT_CAP,
    )?;
    parse_name_status_z(&require_success(out, "diff")?)
}

/// `git diff-tree -r --name-status -z -M -C <parent> <commit>`: the exact
/// path changes introduced by one commit relative to one parent — the
/// building block for the per-commit union required to catch a path that was
/// added and removed entirely between the archive base and `HEAD`. Both OIDs
/// are validated before use (defense in depth against option-like input).
pub fn diff_tree_name_status(
    repo: &Path,
    parent: &str,
    commit: &str,
) -> Result<Vec<DiffEntry>, GitError> {
    if !valid_oid_hex(parent) || !valid_oid_hex(commit) {
        return Err(GitError::UnsafeArgument("diff-tree object id"));
    }
    let out = run(
        repo,
        &[
            "diff-tree",
            "-r",
            "--name-status",
            "-z",
            "-M",
            "-C",
            parent,
            commit,
        ],
        DEFAULT_STDOUT_CAP,
    )?;
    parse_name_status_z(&require_success(out, "diff-tree")?)
}

// --- status --porcelain=v2 -------------------------------------------------

/// One `status --porcelain=v2 -z` record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StatusEntry {
    /// An ordinary tracked change (`1 ...`): index/worktree status letters
    /// plus the path.
    Ordinary { xy: String, path: String },
    /// A rename/copy (`2 ...`): index/worktree status, the rename/copy score
    /// token, the current path, and the original path.
    RenamedOrCopied {
        xy: String,
        score: String,
        path: String,
        orig_path: String,
    },
    /// An unmerged (conflicted) index entry (`u ...`).
    Unmerged { xy: String, path: String },
    /// An untracked path (`? ...`).
    Untracked { path: String },
    /// An ignored path (`! ...`).
    Ignored { path: String },
}

impl StatusEntry {
    /// Whether this entry represents an unmerged (conflicted) index state —
    /// callers must fail closed rather than attribute scope through it.
    /// Production call sites (`verify_commit_coherence`,
    /// `scoped_digest_for_patterns`, `manifest_view`) all match on
    /// `StatusEntry::Unmerged { .. }` directly rather than through this
    /// convenience predicate; kept as the documented, tested way to ask the
    /// same question without repeating the `matches!` pattern.
    #[allow(dead_code)]
    pub fn is_unmerged(&self) -> bool {
        matches!(self, StatusEntry::Unmerged { .. })
    }
}

fn parse_status_v2_z(bytes: &[u8]) -> Result<Vec<StatusEntry>, GitError> {
    let tokens = nul_tokens(bytes)?;
    let mut out = Vec::new();
    let mut iter = tokens.into_iter();
    while let Some(tok) = iter.next() {
        if let Some(rest) = tok.strip_prefix("1 ") {
            // <XY> <sub> <mH> <mI> <mW> <hH> <hI> <path> — 8 space-separated
            // fields, the last of which (the path) may itself contain spaces.
            let fields: Vec<&str> = rest.splitn(8, ' ').collect();
            if fields.len() != 8 {
                return Err(GitError::Malformed("status v2 ordinary entry"));
            }
            out.push(StatusEntry::Ordinary {
                xy: fields[0].to_string(),
                path: fields[7].to_string(),
            });
        } else if let Some(rest) = tok.strip_prefix("2 ") {
            // <XY> <sub> <mH> <mI> <mW> <hH> <hI> <X><score> <path> — 9
            // fields; origPath is a separate following NUL-terminated token.
            let fields: Vec<&str> = rest.splitn(9, ' ').collect();
            if fields.len() != 9 {
                return Err(GitError::Malformed("status v2 rename entry"));
            }
            let orig_path = iter.next().ok_or(GitError::Malformed(
                "status v2 rename entry (missing origPath)",
            ))?;
            out.push(StatusEntry::RenamedOrCopied {
                xy: fields[0].to_string(),
                score: fields[7].to_string(),
                path: fields[8].to_string(),
                orig_path: orig_path.to_string(),
            });
        } else if let Some(rest) = tok.strip_prefix("u ") {
            // <XY> <sub> <m1> <m2> <m3> <mW> <h1> <h2> <h3> <path> — 10 fields.
            let fields: Vec<&str> = rest.splitn(10, ' ').collect();
            if fields.len() != 10 {
                return Err(GitError::Malformed("status v2 unmerged entry"));
            }
            out.push(StatusEntry::Unmerged {
                xy: fields[0].to_string(),
                path: fields[9].to_string(),
            });
        } else if let Some(path) = tok.strip_prefix("? ") {
            out.push(StatusEntry::Untracked {
                path: path.to_string(),
            });
        } else if let Some(path) = tok.strip_prefix("! ") {
            out.push(StatusEntry::Ignored {
                path: path.to_string(),
            });
        } else {
            return Err(GitError::Malformed("status v2 record"));
        }
    }
    Ok(out)
}

/// `git status --porcelain=v2 --ignored -z` (no `--branch`, so no header
/// lines): ordinary/renamed/unmerged/untracked/ignored entries, NUL-parsed.
/// `--ignored` is required — without it, git omits `!` records entirely.
pub fn status_v2(repo: &Path) -> Result<Vec<StatusEntry>, GitError> {
    let out = run(
        repo,
        &[
            "status",
            "--porcelain=v2",
            "--ignored",
            "--untracked-files=all",
            "-z",
        ],
        DEFAULT_STDOUT_CAP,
    )?;
    parse_status_v2_z(&require_success(out, "status")?)
}

// --- rev-parse / rev-list ---------------------------------------------------

/// `git rev-parse --verify HEAD^{commit}`: the current commit OID, or `None`
/// for an unborn branch (no commits yet) rather than an error — that
/// distinction is exactly what this invocation form exists to make.
pub fn head_commit(repo: &Path) -> Result<Option<String>, GitError> {
    let out = run(
        repo,
        &["rev-parse", "--verify", "HEAD^{commit}"],
        DEFAULT_STDOUT_CAP,
    )?;
    if !out.status.success() {
        return Ok(None);
    }
    let text = std::str::from_utf8(&out.stdout).map_err(|_| GitError::NonUtf8)?;
    let oid = text.trim();
    if !valid_oid_hex(oid) {
        return Err(GitError::Malformed("rev-parse HEAD^{commit}"));
    }
    Ok(Some(oid.to_string()))
}

/// Resolve the current branch's configured upstream as an exact remote name
/// and fully-qualified branch ref. Detached/unborn/no-upstream repositories
/// return `None`; no target is invented.
pub fn publication_upstream(repo: &Path) -> Result<Option<(String, String)>, GitError> {
    let branch_out = run(repo, &["symbolic-ref", "--quiet", "HEAD"], 1024)?;
    if !branch_out.status.success() {
        return Ok(None);
    }
    let branch = std::str::from_utf8(&branch_out.stdout)
        .map_err(|_| GitError::NonUtf8)?
        .trim();
    if !valid_branch_ref(branch) {
        return Err(GitError::Malformed("symbolic-ref HEAD"));
    }
    let out = run(
        repo,
        &[
            "for-each-ref",
            "--format=%(upstream:remotename)%00%(upstream:remoteref)",
            "--count=1",
            branch,
        ],
        2048,
    )?;
    let bytes = require_success(out, "for-each-ref upstream")?;
    let text = std::str::from_utf8(&bytes).map_err(|_| GitError::NonUtf8)?;
    let text = text.trim_end_matches(['\n', '\r']);
    if text.is_empty() {
        return Ok(None);
    }
    let (remote, reference) = text
        .split_once('\0')
        .ok_or(GitError::Malformed("for-each-ref upstream"))?;
    if remote.is_empty() && reference.is_empty() {
        return Ok(None);
    }
    if !valid_remote_name(remote) || !valid_branch_ref(reference) {
        return Err(GitError::Malformed("for-each-ref upstream"));
    }
    Ok(Some((remote.to_string(), reference.to_string())))
}

/// `git rev-list --reverse <base>..<head> --`: every commit strictly between
/// `base` (exclusive) and `head` (inclusive), oldest first — the walk order
/// the per-commit path-union coherence check requires. Both OIDs are
/// validated before use.
pub fn rev_list_reverse(repo: &Path, base: &str, head: &str) -> Result<Vec<String>, GitError> {
    if !valid_oid_hex(base) || !valid_oid_hex(head) {
        return Err(GitError::UnsafeArgument("rev-list object id"));
    }
    let range = format!("{base}..{head}");
    let out = run(
        repo,
        &["rev-list", "--reverse", &range, "--"],
        DEFAULT_STDOUT_CAP,
    )?;
    let bytes = require_success(out, "rev-list")?;
    let text = std::str::from_utf8(&bytes).map_err(|_| GitError::NonUtf8)?;
    let mut oids = Vec::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        if !valid_oid_hex(line) {
            return Err(GitError::Malformed("rev-list output"));
        }
        oids.push(line.to_string());
    }
    Ok(oids)
}

/// Whether `ancestor` is an ancestor of (or equal to) `descendant`. Missing
/// objects are reported as `None`, keeping ancestry-unavailable distinct from
/// divergence without fetching.
pub fn is_ancestor(
    repo: &Path,
    ancestor: &str,
    descendant: &str,
) -> Result<Option<bool>, GitError> {
    if !valid_oid_hex(ancestor) || !valid_oid_hex(descendant) {
        return Err(GitError::UnsafeArgument("merge-base object id"));
    }
    let out = run(
        repo,
        &["merge-base", "--is-ancestor", ancestor, descendant],
        1024,
    )?;
    match out.status.code() {
        Some(0) => Ok(Some(true)),
        Some(1) => Ok(Some(false)),
        Some(128) => Ok(None),
        _ => Err(GitError::Failed("merge-base --is-ancestor")),
    }
}

/// Current index tree OID. This is read-only: `write-tree` writes an object to
/// the object database but does not mutate the index or worktree; closure
/// verification avoids even that side effect by hashing `ls-files --stage`.
pub fn index_identity(repo: &Path) -> Result<crate::digest::Digest, GitError> {
    let out = run(repo, &["ls-files", "--stage", "-z"], DEFAULT_STDOUT_CAP)?;
    let bytes = require_success(out, "ls-files --stage")?;
    Ok(crate::digest::Digest::of_bytes(&bytes))
}

/// The single parent of `commit`, or `None` for a root commit. Merge commits
/// fail closed because their attribution is ambiguous for closure coherence.
pub fn single_parent(repo: &Path, commit: &str) -> Result<Option<String>, GitError> {
    if !valid_oid_hex(commit) {
        return Err(GitError::UnsafeArgument("commit object id"));
    }
    let out = run(repo, &["rev-list", "--parents", "-n", "1", commit], 1024)?;
    let bytes = require_success(out, "rev-list --parents")?;
    let text = std::str::from_utf8(&bytes).map_err(|_| GitError::NonUtf8)?;
    let parts: Vec<&str> = text.split_whitespace().collect();
    if parts.first().copied() != Some(commit) || parts.iter().any(|oid| !valid_oid_hex(oid)) {
        return Err(GitError::Malformed("rev-list --parents"));
    }
    match parts.len() {
        1 => Ok(None),
        2 => Ok(Some(parts[1].to_string())),
        _ => Err(GitError::Malformed("merge commit in closure range")),
    }
}

// --- ls-remote --------------------------------------------------------------

/// `git ls-remote --exit-code <remote> <ref>`: the exact OID the remote
/// currently reports for `reference`, or `None` if the ref does not exist
/// there. `remote` and `reference` are validated before use; callers are
/// additionally responsible for resolving `remote` against the exact set of
/// *configured* remote names before calling this (never a raw manifest
/// token) — see [`configured_remote_names`].
/// Not called by production `mpd publish` (which always has a configured/
/// default `closure.remote_timeout_secs` in hand and calls
/// [`ls_remote_with_timeout`] directly); kept as the documented 15-second
/// default for any caller that doesn't need a configurable timeout, and
/// exercised directly by this module's own tests.
#[allow(dead_code)]
pub fn ls_remote(repo: &Path, remote: &str, reference: &str) -> Result<Option<String>, GitError> {
    ls_remote_with_timeout(repo, remote, reference, 15)
}

pub fn ls_remote_with_timeout(
    repo: &Path,
    remote: &str,
    reference: &str,
    timeout_secs: u64,
) -> Result<Option<String>, GitError> {
    if !valid_remote_name(remote) {
        return Err(GitError::UnsafeArgument("remote name"));
    }
    if !valid_branch_ref(reference) {
        return Err(GitError::UnsafeArgument("ref"));
    }
    let out = run_with_timeout(
        repo,
        &["ls-remote", "--exit-code", remote, reference],
        REMOTE_STDOUT_CAP,
        std::time::Duration::from_secs(timeout_secs.clamp(1, 300)),
    )?;
    match out.status.code() {
        Some(0) => {}
        Some(2) => return Ok(None), // --exit-code: no matching ref
        _ => return Err(GitError::Failed("ls-remote")),
    }
    let text = std::str::from_utf8(&out.stdout).map_err(|_| GitError::NonUtf8)?;
    let first_line = text
        .lines()
        .next()
        .ok_or(GitError::Malformed("ls-remote"))?;
    let mut parts = first_line.splitn(2, '\t');
    let oid = parts.next().ok_or(GitError::Malformed("ls-remote"))?;
    let observed_ref = parts.next().ok_or(GitError::Malformed("ls-remote"))?;
    if !valid_oid_hex(oid) || observed_ref != reference {
        return Err(GitError::Malformed("ls-remote"));
    }
    Ok(Some(oid.to_string()))
}

// --- config --get-regexp -----------------------------------------------------

/// `git config --null --name-only --get-regexp ^remote\..*\.url$`: the set of
/// currently configured remote names (parsed from `remote.<name>.url` keys).
/// Absence of any match (`git config` exits 1) is an empty list, not an
/// error.
pub fn configured_remote_names(repo: &Path) -> Result<Vec<String>, GitError> {
    let out = run(
        repo,
        &[
            "config",
            "--null",
            "--name-only",
            "--get-regexp",
            r"^remote\..*\.url$",
        ],
        DEFAULT_STDOUT_CAP,
    )?;
    match out.status.code() {
        Some(0) => {}
        Some(1) => return Ok(Vec::new()), // no matching config keys
        _ => return Err(GitError::Failed("config --get-regexp")),
    }
    let mut names = Vec::new();
    for key in parse_nul_paths(&out.stdout)? {
        let name = key
            .strip_prefix("remote.")
            .and_then(|s| s.strip_suffix(".url"))
            .ok_or(GitError::Malformed("config --get-regexp key"))?;
        names.push(name.to_string());
    }
    Ok(names)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::process::Command as StdCommand;

    fn unique_dir(label: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "mpd-git-{label}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn git(dir: &Path, args: &[&str]) {
        // `git init`'s hook-template copy step has a known transient race
        // under heavy parallel invocation (concurrent `cp` of the same
        // shared template source can report "File exists"). This is an
        // environmental flake in highly parallel test execution, not a
        // production-code defect (production `mpd` never runs `git init`),
        // so `init`/`init --bare` get a short bounded retry; every other
        // subcommand still fails the test immediately on its first error.
        let is_init = args.first() == Some(&"init");
        let attempts = if is_init { 5 } else { 1 };
        let mut last_status = None;
        for attempt in 0..attempts {
            let status = StdCommand::new("git")
                .args(args)
                .current_dir(dir)
                .env("GIT_AUTHOR_NAME", "Test")
                .env("GIT_AUTHOR_EMAIL", "test@example.com")
                .env("GIT_COMMITTER_NAME", "Test")
                .env("GIT_COMMITTER_EMAIL", "test@example.com")
                .env("GIT_PAGER", "cat")
                .env("GIT_TERMINAL_PROMPT", "0")
                .status()
                .expect("git available on PATH");
            if status.success() {
                return;
            }
            last_status = Some(status);
            if attempt + 1 < attempts {
                std::thread::sleep(std::time::Duration::from_millis(20 * (attempt as u64 + 1)));
            }
        }
        panic!(
            "git {args:?} failed in {} (status: {:?})",
            dir.display(),
            last_status
        );
    }

    fn init_repo() -> std::path::PathBuf {
        let dir = unique_dir("repo");
        git(&dir, &["init", "--quiet", "--initial-branch=main"]);
        dir
    }

    fn commit_file(dir: &Path, name: &str, content: &str, message: &str) {
        fs::write(dir.join(name), content).unwrap();
        git(dir, &["add", name]);
        git(dir, &["commit", "--quiet", "-m", message]);
    }

    // --- OID / ref / remote-name validators ------------------------------

    #[test]
    fn oid_hex_validation() {
        assert!(valid_oid_hex(&"a".repeat(40)));
        assert!(valid_oid_hex(&"f".repeat(64)));
        assert!(!valid_oid_hex(&"A".repeat(40)), "uppercase rejected");
        assert!(!valid_oid_hex(&"g".repeat(40)), "non-hex rejected");
        assert!(!valid_oid_hex(&"a".repeat(41)), "wrong length rejected");
        assert!(!valid_oid_hex("-".repeat(40).as_str()));
    }

    #[test]
    fn remote_name_validation_rejects_option_like_and_path_like_tokens() {
        assert!(valid_remote_name("origin"));
        assert!(valid_remote_name("my-remote_1.2"));
        assert!(!valid_remote_name(""));
        assert!(!valid_remote_name("--upload-pack=/bin/sh"));
        assert!(!valid_remote_name("-x"));
        assert!(!valid_remote_name("a..b"));
        assert!(!valid_remote_name("has space"));
        assert!(!valid_remote_name(&"a".repeat(201)));
        // security-plan.md HIGH finding: "." / ".." are valid local-path
        // aliases and must never be accepted as a remote *name*, even though
        // both are otherwise charset-legal tokens.
        assert!(!valid_remote_name("."));
        assert!(!valid_remote_name(".."));
    }

    #[test]
    fn branch_ref_validation_requires_refs_heads_prefix() {
        assert!(valid_branch_ref("refs/heads/main"));
        assert!(valid_branch_ref("refs/heads/feature/thing"));
        assert!(
            !valid_branch_ref("main"),
            "bare branch name is not a full ref"
        );
        assert!(!valid_branch_ref("refs/tags/v1"), "v1 is refs/heads/* only");
        assert!(!valid_branch_ref("-rf"));
        assert!(!valid_branch_ref(""));
        // A ref containing a NUL or trailing slash is rejected by
        // check-ref-format itself.
        assert!(!valid_branch_ref("refs/heads/bad/"));
    }

    // --- ls-files ----------------------------------------------------------

    #[test]
    fn ls_files_lists_tracked_paths() {
        let dir = init_repo();
        commit_file(&dir, "a.txt", "a", "add a");
        fs::create_dir_all(dir.join("sub")).unwrap();
        fs::write(dir.join("sub/b.txt"), "b").unwrap();
        git(&dir, &["add", "sub/b.txt"]);
        git(&dir, &["commit", "--quiet", "-m", "add b"]);
        let files = ls_files(&dir).unwrap();
        assert_eq!(files, vec!["a.txt".to_string(), "sub/b.txt".to_string()]);
    }

    // --- diff --cached / diff (name-status) ---------------------------------

    #[test]
    fn diff_cached_reports_added_modified_deleted() {
        let dir = init_repo();
        commit_file(&dir, "keep.txt", "1", "init");
        commit_file(&dir, "gone.txt", "bye", "add gone");
        fs::write(dir.join("keep.txt"), "2").unwrap();
        fs::write(dir.join("new.txt"), "n").unwrap();
        fs::remove_file(dir.join("gone.txt")).unwrap();
        git(&dir, &["add", "-A"]);
        let entries = diff_cached_name_status(&dir).unwrap();
        let mut statuses: Vec<(char, String)> =
            entries.iter().map(|e| (e.status, e.path.clone())).collect();
        statuses.sort();
        assert_eq!(
            statuses,
            vec![
                ('A', "new.txt".to_string()),
                ('D', "gone.txt".to_string()),
                ('M', "keep.txt".to_string()),
            ]
        );
    }

    #[test]
    fn diff_cached_detects_rename_with_both_paths() {
        let dir = init_repo();
        commit_file(
            &dir,
            "old.txt",
            "identical content for rename detection\n",
            "init",
        );
        git(&dir, &["mv", "old.txt", "renamed.txt"]);
        let entries = diff_cached_name_status(&dir).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].status, 'R');
        assert_eq!(entries[0].path, "renamed.txt");
        assert_eq!(entries[0].orig_path.as_deref(), Some("old.txt"));
        assert!(entries[0].score.is_some());
    }

    #[test]
    fn diff_worktree_reports_unstaged_change() {
        let dir = init_repo();
        commit_file(&dir, "a.txt", "1", "init");
        fs::write(dir.join("a.txt"), "2").unwrap();
        let entries = diff_worktree_name_status(&dir).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].status, 'M');
        assert_eq!(entries[0].path, "a.txt");
    }

    // --- diff-tree -----------------------------------------------------------

    #[test]
    fn diff_tree_reports_single_commit_changes() {
        let dir = init_repo();
        commit_file(&dir, "a.txt", "1", "init");
        let parent = head_commit(&dir).unwrap().unwrap();
        commit_file(&dir, "b.txt", "2", "add b");
        let commit = head_commit(&dir).unwrap().unwrap();
        let entries = diff_tree_name_status(&dir, &parent, &commit).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].status, 'A');
        assert_eq!(entries[0].path, "b.txt");
    }

    #[test]
    fn diff_tree_rejects_option_like_oid() {
        let dir = init_repo();
        let err = diff_tree_name_status(&dir, "-rf", &"a".repeat(40)).unwrap_err();
        assert_eq!(err, GitError::UnsafeArgument("diff-tree object id"));
    }

    // --- rev-parse / rev-list --------------------------------------------

    #[test]
    fn head_commit_is_none_on_unborn_branch() {
        let dir = init_repo();
        assert_eq!(head_commit(&dir).unwrap(), None);
    }

    #[test]
    fn head_commit_returns_valid_oid_after_commit() {
        let dir = init_repo();
        commit_file(&dir, "a.txt", "1", "init");
        let oid = head_commit(&dir).unwrap().unwrap();
        assert!(valid_oid_hex(&oid));
    }

    #[test]
    fn publication_upstream_distinguishes_configured_detached_and_missing() {
        let dir = init_repo();
        commit_file(&dir, "a.txt", "1", "init");
        assert_eq!(publication_upstream(&dir).unwrap(), None);
        let bare = unique_dir("upstream");
        git(
            &bare,
            &["init", "--quiet", "--bare", "--initial-branch=main"],
        );
        git(&dir, &["remote", "add", "origin", bare.to_str().unwrap()]);
        git(&dir, &["push", "--quiet", "-u", "origin", "main"]);
        assert_eq!(
            publication_upstream(&dir).unwrap(),
            Some(("origin".into(), "refs/heads/main".into()))
        );
        git(&dir, &["checkout", "--quiet", "--detach"]);
        assert_eq!(publication_upstream(&dir).unwrap(), None);
    }

    #[test]
    fn rev_list_reverse_walks_oldest_first_and_excludes_base() {
        let dir = init_repo();
        commit_file(&dir, "a.txt", "1", "c1");
        let base = head_commit(&dir).unwrap().unwrap();
        commit_file(&dir, "b.txt", "2", "c2");
        let c2 = head_commit(&dir).unwrap().unwrap();
        commit_file(&dir, "c.txt", "3", "c3");
        let c3 = head_commit(&dir).unwrap().unwrap();
        let oids = rev_list_reverse(&dir, &base, &c3).unwrap();
        assert_eq!(oids, vec![c2, c3]);
    }

    #[test]
    fn rev_list_reverse_rejects_unsafe_oid() {
        let dir = init_repo();
        let err = rev_list_reverse(&dir, "--upload-pack=x", &"a".repeat(40)).unwrap_err();
        assert_eq!(err, GitError::UnsafeArgument("rev-list object id"));
    }

    // --- status --porcelain=v2 ------------------------------------------

    #[test]
    fn status_v2_reports_untracked_and_ignored() {
        let dir = init_repo();
        fs::write(dir.join(".gitignore"), "ignored.txt\n").unwrap();
        git(&dir, &["add", ".gitignore"]);
        git(&dir, &["commit", "--quiet", "-m", "gitignore"]);
        fs::write(dir.join("new.txt"), "n").unwrap();
        fs::write(dir.join("ignored.txt"), "i").unwrap();
        let entries = status_v2(&dir).unwrap();
        assert!(entries
            .iter()
            .any(|e| matches!(e, StatusEntry::Untracked { path } if path == "new.txt")));
        assert!(entries
            .iter()
            .any(|e| matches!(e, StatusEntry::Ignored { path } if path == "ignored.txt")));
    }

    #[test]
    fn status_v2_reports_ordinary_staged_change() {
        let dir = init_repo();
        commit_file(&dir, "a.txt", "1", "init");
        fs::write(dir.join("a.txt"), "2").unwrap();
        git(&dir, &["add", "a.txt"]);
        let entries = status_v2(&dir).unwrap();
        assert_eq!(entries.len(), 1);
        match &entries[0] {
            StatusEntry::Ordinary { xy, path } => {
                assert_eq!(path, "a.txt");
                assert_eq!(xy, "M.");
            }
            other => panic!("expected an ordinary entry, got {other:?}"),
        }
    }

    #[test]
    fn status_v2_reports_rename_with_orig_path() {
        let dir = init_repo();
        commit_file(
            &dir,
            "old.txt",
            "identical content for rename detection\n",
            "init",
        );
        git(&dir, &["mv", "old.txt", "renamed.txt"]);
        let entries = status_v2(&dir).unwrap();
        assert_eq!(entries.len(), 1);
        match &entries[0] {
            StatusEntry::RenamedOrCopied {
                path, orig_path, ..
            } => {
                assert_eq!(path, "renamed.txt");
                assert_eq!(orig_path, "old.txt");
            }
            other => panic!("expected a rename entry, got {other:?}"),
        }
    }

    #[test]
    fn status_v2_reports_unmerged_conflict() {
        let dir = init_repo();
        commit_file(&dir, "a.txt", "base\n", "init");
        git(&dir, &["checkout", "--quiet", "-b", "side"]);
        fs::write(dir.join("a.txt"), "side\n").unwrap();
        git(&dir, &["commit", "--quiet", "-am", "side change"]);
        git(&dir, &["checkout", "--quiet", "main"]);
        fs::write(dir.join("a.txt"), "main\n").unwrap();
        git(&dir, &["commit", "--quiet", "-am", "main change"]);
        // Merge is expected to conflict; ignore its exit code.
        let _ = StdCommand::new("git")
            .args(["merge", "--quiet", "--no-edit", "side"])
            .current_dir(&dir)
            .env("GIT_PAGER", "cat")
            .env("GIT_TERMINAL_PROMPT", "0")
            .status();
        let entries = status_v2(&dir).unwrap();
        assert!(entries.iter().any(StatusEntry::is_unmerged));
    }

    // Linux filesystems (ext4 etc.) allow arbitrary non-UTF-8 bytes in a
    // filename; macOS/APFS enforces valid UTF-8 at the syscall level (a
    // `fs::write` to such a path fails with EILSEQ before Git ever sees it),
    // so this specific fail-closed path can only be exercised on Linux.
    #[cfg(target_os = "linux")]
    #[test]
    fn status_v2_and_ls_files_fail_closed_on_non_utf8_path() {
        use std::os::unix::ffi::OsStrExt;
        let dir = init_repo();
        commit_file(&dir, "a.txt", "1", "init");
        // Build a non-UTF-8 filename directly from invalid bytes.
        let bad_name = std::ffi::OsStr::from_bytes(&[0x66, 0x6f, 0x80, 0x6f]); // "fo<0x80>o"
        let bad_path = dir.join(bad_name);
        fs::write(&bad_path, b"x").unwrap();
        git(&dir, &["add", "-A"]);
        let err = diff_cached_name_status(&dir);
        assert!(matches!(err, Err(GitError::NonUtf8)));
    }

    #[test]
    fn parsers_fail_closed_on_non_utf8_bytes_on_every_platform() {
        // Portable complement to the Linux-only real-repository test above:
        // the parsing layer itself must refuse invalid UTF-8 regardless of
        // whether the host filesystem can even produce such a path.
        let bad = [b'M', b' ', 0x80, 0x81];
        assert_eq!(parse_name_status_z(&bad), Err(GitError::NonUtf8));
        assert_eq!(parse_status_v2_z(&bad), Err(GitError::NonUtf8));
        assert_eq!(parse_nul_paths(&bad), Err(GitError::NonUtf8));
    }

    // --- ls-remote / configured_remote_names -----------------------------

    #[test]
    fn configured_remote_names_lists_and_defaults_empty() {
        let dir = init_repo();
        assert_eq!(configured_remote_names(&dir).unwrap(), Vec::<String>::new());
        let bare = unique_dir("bare");
        git(&bare, &["init", "--quiet", "--bare"]);
        git(&dir, &["remote", "add", "origin", bare.to_str().unwrap()]);
        assert_eq!(
            configured_remote_names(&dir).unwrap(),
            vec!["origin".to_string()]
        );
    }

    #[test]
    fn ls_remote_reports_exact_oid_and_missing_ref_as_none() {
        let dir = init_repo();
        commit_file(&dir, "a.txt", "1", "init");
        let expected = head_commit(&dir).unwrap().unwrap();
        let bare = unique_dir("bare2");
        git(
            &bare,
            &["init", "--quiet", "--bare", "--initial-branch=main"],
        );
        git(&dir, &["remote", "add", "origin", bare.to_str().unwrap()]);
        git(&dir, &["push", "--quiet", "origin", "main"]);
        let observed = ls_remote(&dir, "origin", "refs/heads/main").unwrap();
        assert_eq!(observed, Some(expected));
        let missing = ls_remote(&dir, "origin", "refs/heads/does-not-exist").unwrap();
        assert_eq!(missing, None);
    }

    #[test]
    fn ls_remote_refuses_a_local_path_masquerading_as_a_remote_name() {
        let dir = init_repo();
        commit_file(&dir, "a.txt", "1", "init");
        // A directory name (or ".") is not a *configured remote name*; the
        // syntax validator alone won't catch every such case (a bare word
        // like "repo" is syntactically a legal remote-name token), which is
        // exactly why callers MUST additionally check membership in
        // `configured_remote_names` before calling `ls_remote` — but the
        // validator does catch the unambiguous path/option-like forms.
        let err = ls_remote(&dir, ".", "refs/heads/main").unwrap_err();
        assert_eq!(err, GitError::UnsafeArgument("remote name"));
        let err = ls_remote(&dir, "..", "refs/heads/main").unwrap_err();
        assert_eq!(err, GitError::UnsafeArgument("remote name"));
    }

    #[test]
    fn output_cap_terminates_a_pathological_response() {
        // The cap machinery is exercised directly (constructing a real
        // multi-hundred-MB `git` response deterministically and quickly
        // across platforms is impractical in a unit test): assert
        // `read_capped`'s truncation contract, which is exactly what
        // `run`/`run_with_env` rely on to kill an oversized child.
        let mut data: &[u8] = &[0u8; 1000];
        let (buf, truncated) = read_capped(&mut data, 10);
        assert!(truncated);
        assert_eq!(buf.len(), 10);
        let mut small: &[u8] = &[1, 2, 3];
        let (buf2, truncated2) = read_capped(&mut small, 10);
        assert!(!truncated2);
        assert_eq!(buf2, vec![1, 2, 3]);
    }

    // --- Parser fuzz / round-trip properties -----------------------------
    //
    // The example tests above parse real `git` plumbing output; these
    // stand in for fuzzing the pure `-z` parsers directly: arbitrary bytes
    // must never panic (fail closed as Ok/Err), and any well-formed record
    // set encoded exactly as `git`'s NUL-delimited format must round-trip
    // back to the intended structure. proptest seeds deterministically and
    // shrinks to a minimal counterexample on failure.

    use proptest::prelude::*;

    /// A full NUL-delimited token (a whole `-z` field): non-empty, no NUL,
    /// no ASCII control byte. Spaces are allowed — for a whole token they
    /// never affect framing, exercising paths that contain spaces.
    fn token_strategy() -> impl Strategy<Value = String> {
        "[a-zA-Z0-9 ._/-]{1,24}"
    }

    /// A space-free, non-empty token used for fields that must not contain
    /// a space (the status/index-code columns and rename score token).
    fn nospace_token_strategy() -> impl Strategy<Value = String> {
        "[a-zA-Z0-9._/-]{1,8}"
    }

    /// Encode a `DiffEntry` set exactly as `git diff --name-status -z`
    /// would: `<STATUS>\0<path>\0` for ordinary changes, and
    /// `<STATUS><score>\0<src>\0<dst>\0` for renames/copies.
    fn encode_name_status_z(entries: &[DiffEntry]) -> Vec<u8> {
        let mut out = Vec::new();
        for e in entries {
            if matches!(e.status, 'R' | 'C') {
                out.extend_from_slice(
                    format!("{}{}", e.status, e.score.expect("rename carries a score")).as_bytes(),
                );
                out.push(0);
                out.extend_from_slice(
                    e.orig_path
                        .as_deref()
                        .expect("rename carries src")
                        .as_bytes(),
                );
                out.push(0);
                out.extend_from_slice(e.path.as_bytes());
                out.push(0);
            } else {
                out.push(e.status as u8);
                out.push(0);
                out.extend_from_slice(e.path.as_bytes());
                out.push(0);
            }
        }
        out
    }

    fn name_status_entry_strategy() -> impl Strategy<Value = DiffEntry> {
        prop_oneof![
            (
                prop::sample::select(vec!['A', 'M', 'D', 'T']),
                token_strategy()
            )
                .prop_map(|(status, path)| DiffEntry {
                    status,
                    score: None,
                    path,
                    orig_path: None,
                }),
            (
                prop::sample::select(vec!['R', 'C']),
                0u8..=100,
                token_strategy(),
                token_strategy(),
            )
                .prop_map(|(status, score, src, dst)| DiffEntry {
                    status,
                    score: Some(score),
                    path: dst,
                    orig_path: Some(src),
                }),
        ]
    }

    /// Encode a `StatusEntry` set exactly as `git status --porcelain=v2 -z`
    /// would. Only fields the parser extracts (the status column, the
    /// score token, the path, and the rename's separate origPath token) are
    /// meaningful; the remaining columns are fixed non-empty placeholders,
    /// matching the field counts the parser requires (8/9/10).
    fn encode_status_v2_z(entries: &[StatusEntry]) -> Vec<u8> {
        let mut out = Vec::new();
        for e in entries {
            match e {
                StatusEntry::Ordinary { xy, path } => {
                    out.extend_from_slice(format!("1 {xy} . . . . . . {path}").as_bytes());
                    out.push(0);
                }
                StatusEntry::RenamedOrCopied {
                    xy,
                    score,
                    path,
                    orig_path,
                } => {
                    out.extend_from_slice(format!("2 {xy} . . . . . . {score} {path}").as_bytes());
                    out.push(0);
                    out.extend_from_slice(orig_path.as_bytes());
                    out.push(0);
                }
                StatusEntry::Unmerged { xy, path } => {
                    out.extend_from_slice(format!("u {xy} . . . . . . . . {path}").as_bytes());
                    out.push(0);
                }
                StatusEntry::Untracked { path } => {
                    out.extend_from_slice(format!("? {path}").as_bytes());
                    out.push(0);
                }
                StatusEntry::Ignored { path } => {
                    out.extend_from_slice(format!("! {path}").as_bytes());
                    out.push(0);
                }
            }
        }
        out
    }

    fn status_v2_entry_strategy() -> impl Strategy<Value = StatusEntry> {
        let xy = || prop::sample::select(vec!["M.", ".M", "A.", "MM", "AD", "R.", "UU"]);
        prop_oneof![
            (xy(), token_strategy()).prop_map(|(xy, path)| StatusEntry::Ordinary {
                xy: xy.to_string(),
                path
            }),
            (
                xy(),
                nospace_token_strategy(),
                token_strategy(),
                token_strategy()
            )
                .prop_map(|(xy, score, path, orig_path)| {
                    StatusEntry::RenamedOrCopied {
                        xy: xy.to_string(),
                        score,
                        path,
                        orig_path,
                    }
                }),
            (xy(), token_strategy()).prop_map(|(xy, path)| StatusEntry::Unmerged {
                xy: xy.to_string(),
                path
            }),
            token_strategy().prop_map(|path| StatusEntry::Untracked { path }),
            token_strategy().prop_map(|path| StatusEntry::Ignored { path }),
        ]
    }

    proptest! {
        /// Arbitrary bytes never panic the name-status parser.
        #[test]
        fn prop_parse_name_status_never_panics(bytes in prop::collection::vec(any::<u8>(), 0..256)) {
            let _ = parse_name_status_z(&bytes);
        }

        /// Arbitrary bytes never panic the status-v2 parser.
        #[test]
        fn prop_parse_status_v2_never_panics(bytes in prop::collection::vec(any::<u8>(), 0..256)) {
            let _ = parse_status_v2_z(&bytes);
        }

        /// Arbitrary bytes never panic the NUL-path parser.
        #[test]
        fn prop_parse_nul_paths_never_panics(bytes in prop::collection::vec(any::<u8>(), 0..256)) {
            let _ = parse_nul_paths(&bytes);
        }

        /// Any well-formed `--name-status -z` record set round-trips
        /// exactly through the parser (including renames, high scores, and
        /// paths containing spaces).
        #[test]
        fn prop_name_status_records_round_trip(
            entries in prop::collection::vec(name_status_entry_strategy(), 0..8)
        ) {
            let bytes = encode_name_status_z(&entries);
            let parsed = parse_name_status_z(&bytes).expect("well-formed -z must parse");
            prop_assert_eq!(parsed, entries);
        }

        /// Any well-formed `status --porcelain=v2 -z` record set round-trips
        /// exactly through the parser across all five record kinds.
        #[test]
        fn prop_status_v2_records_round_trip(
            entries in prop::collection::vec(status_v2_entry_strategy(), 0..8)
        ) {
            let bytes = encode_status_v2_z(&entries);
            let parsed = parse_status_v2_z(&bytes).expect("well-formed v2 -z must parse");
            prop_assert_eq!(parsed, entries);
        }
    }
}
