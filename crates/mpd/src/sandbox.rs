//! Fail-closed network-denial adapter selection and Unix child supervision.

use nix::errno::Errno;
use nix::sys::resource::{getrlimit, rlim_t, setrlimit, Resource};
use nix::sys::signal::{killpg, Signal};
use nix::unistd::{close, execvp, Pid};
use std::ffi::CString;
use std::fs;
#[cfg(target_os = "linux")]
use std::fs::File;
use std::io::{self, Read, Write};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::{
    atomic::{AtomicBool, AtomicUsize, Ordering},
    mpsc, Arc,
};
use std::thread;
use std::time::{Duration, Instant};

const POLL_INTERVAL: Duration = Duration::from_millis(10);
const TERM_GRACE: Duration = Duration::from_millis(250);
const KILL_GRACE: Duration = Duration::from_secs(2);
const MAX_OUTPUT_BYTES: usize = 16 * 1024 * 1024;
const MAX_WORKTREE_BYTES: u64 = 1024 * 1024 * 1024;
const MAX_CHILD_PROCESSES: u64 = 4096;
const MAX_CHILD_OPEN_FILES: u64 = 4096;
const MAX_CHILD_FILE_BYTES: u64 = 1024 * 1024 * 1024;
const MAX_PROCESS_OBSERVATIONS: usize = 32_768;
const MAX_PROCESS_OBSERVER_BYTES: usize = 1024 * 1024;
const PROCESS_OBSERVER_TIMEOUT: Duration = Duration::from_secs(1);
// 48: matches sandbox_macos::MAX_ROOTS — the reviewed tool inventory
// legitimately exceeds 32 once semgrep's per-keg Homebrew python dependency
// surface is declared explicitly. Still a hard compiled ceiling.
const MAX_APPROVED_READ_ROOTS: usize = 48;
const SANDBOX_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

/// The deny-default environment contract for sandboxed children: one source
/// of truth shared by the runner (which sets only these keys), the receipt
/// validator (which requires the configured allowlist to equal it), and the
/// adapter test (which asserts the prepared command stays inside it).
/// Sorted and duplicate-free.
pub(crate) const SANDBOX_ENV_CONTRACT_KEYS: &[&str] = &[
    "CARGO_HOME",
    "CARGO_INCREMENTAL",
    "CARGO_NET_OFFLINE",
    "CARGO_TARGET_DIR",
    "CARGO_TERM_COLOR",
    "DEVELOPER_DIR",
    "GIT_CONFIG_GLOBAL",
    "GIT_CONFIG_NOSYSTEM",
    "GIT_CONFIG_SYSTEM",
    "GIT_OPTIONAL_LOCKS",
    "GIT_PAGER",
    "GIT_TERMINAL_PROMPT",
    "HOME",
    "LANG",
    "LC_ALL",
    "MPD_SANDBOXED",
    "PAGER",
    "PATH",
    "RUSTC",
    "SEMGREP_SEND_METRICS",
    "SSL_CERT_FILE",
    "TERM",
    "TMPDIR",
    "TZ",
];

/// Hard caps installed before the approved argv is executed. These values are
/// deliberately data-only; policy parsing supplies them in a later slice.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RunnerLimits {
    pub per_check: Duration,
    pub aggregate: Duration,
    pub output_bytes: usize,
    pub log_bytes: usize,
    pub worktree_bytes: u64,
    pub child_processes: u64,
    pub child_open_files: u64,
    pub child_file_bytes: u64,
}

impl RunnerLimits {
    pub fn validate(self) -> Result<(), String> {
        if self.per_check.is_zero() || self.aggregate.is_zero() {
            return Err("resource-limit-invalid: time limits must be non-zero".into());
        }
        if self.output_bytes == 0
            || self.log_bytes == 0
            || self.worktree_bytes == 0
            || self.child_processes == 0
            || self.child_open_files < 3
            || self.child_file_bytes == 0
        {
            return Err(
                "resource-limit-invalid: caps must be non-zero and allow standard descriptors"
                    .into(),
            );
        }
        if self.output_bytes > MAX_OUTPUT_BYTES
            || self.log_bytes > MAX_OUTPUT_BYTES
            || self.worktree_bytes > MAX_WORKTREE_BYTES
            || self.child_processes > MAX_CHILD_PROCESSES
            || self.child_open_files > MAX_CHILD_OPEN_FILES
            || self.child_file_bytes > MAX_CHILD_FILE_BYTES
        {
            return Err("resource-limit-invalid: cap exceeds the compiled platform ceiling".into());
        }
        Ok(())
    }

    fn capture_cap(self) -> usize {
        self.output_bytes.min(self.log_bytes)
    }
}

/// A stable local result. This slice never writes a validation receipt or maps
/// a result to an MPD gate; callers must make that policy decision separately.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RunOutcome {
    Passed {
        stdout: Vec<u8>,
        stderr: Vec<u8>,
    },
    Failed {
        status: Option<i32>,
        stdout: Vec<u8>,
        stderr: Vec<u8>,
    },
    Blocked {
        reason: &'static str,
        stdout: Vec<u8>,
        stderr: Vec<u8>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SandboxAttestation {
    pub request_digest: String,
    pub authority_digest: String,
    pub root_inventory_digest: String,
    pub canary_digest: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SandboxedExecution {
    pub outcome: RunOutcome,
    /// Present only after the exact-host helper completed every canary and the
    /// parent accepted its digest-bound READY/GO handshake.
    pub attestation: Option<SandboxAttestation>,
}

/// Run a reviewed, canonical executable through a reviewed network-denial
/// adapter. Resource limits are installed by MPD's hidden helper *inside* the
/// child immediately before `execvp`; this avoids unsafe `pre_exec` hooks.
pub struct SandboxedRun<'a> {
    pub adapter: &'a SandboxAdapter,
    pub supervisor: &'a Path,
    pub program: &'a Path,
    pub args: &'a [String],
    /// Domain-separated binding of the exact subject, accepted policy, and
    /// profile. On macOS it is carried inside the single private control
    /// request with the typed argv and resource limits.
    pub authority_digest: &'a str,
    pub home: &'a Path,
    pub tmp: &'a Path,
    pub worktree: &'a Path,
    /// Clone-private, bootstrap-populated Cargo cache. It is never candidate
    /// controlled and validation keeps Cargo offline.
    pub cargo_home: Option<&'a Path>,
    /// Per-check writable build output below the private temporary root.
    pub cargo_target_dir: Option<&'a Path>,
    /// Canonical digest-locked compiler used by Cargo without ambient PATH.
    pub rustc: Option<&'a Path>,
    /// Additional policy-declared dependency roots (for example a reviewed
    /// Homebrew package-manager root or platform SDK). They are read-only and
    /// capped so candidate configuration cannot grow the sandbox surface.
    pub read_only_roots: &'a [PathBuf],
}

pub struct PreparedSandboxCommand {
    pub command: Command,
    #[cfg(target_os = "macos")]
    control: Option<crate::sandbox_macos::PreparedControl>,
}

impl std::ops::Deref for PreparedSandboxCommand {
    type Target = Command;

    fn deref(&self) -> &Self::Target {
        &self.command
    }
}

pub fn run_sandboxed(
    request: SandboxedRun<'_>,
    limits: RunnerLimits,
) -> Result<SandboxedExecution, String> {
    limits.validate()?;
    let supervisor = canonical_regular_file(request.supervisor)?;
    let program = canonical_regular_file(request.program)?;
    let command = request.adapter.command(
        &supervisor,
        &program,
        request.args,
        request.authority_digest,
        limits,
        request.home,
        request.tmp,
        request.worktree,
        request.cargo_home,
        request.cargo_target_dir,
        request.rustc,
        request.read_only_roots,
    )?;
    supervise_prepared(command, request.worktree, limits)
}

fn supervise_prepared(
    prepared: PreparedSandboxCommand,
    worktree: &Path,
    limits: RunnerLimits,
) -> Result<SandboxedExecution, String> {
    #[cfg(target_os = "macos")]
    if let Some(control) = prepared.control {
        return supervise_controlled(prepared.command, control, worktree, limits);
    }
    Ok(SandboxedExecution {
        outcome: supervise(prepared.command, worktree, limits)?,
        attestation: None,
    })
}

/// Supervise an already assembled adapter command. Kept public within the
/// crate's module boundary for deterministic tests; production callers should
/// use [`run_sandboxed`] so the resource-limit helper cannot be skipped.
pub fn supervise(
    command: Command,
    worktree: &Path,
    limits: RunnerLimits,
) -> Result<RunOutcome, String> {
    supervise_with_observer(command, worktree, limits, process_group_members)
}

fn supervise_with_observer<F>(
    mut command: Command,
    worktree: &Path,
    limits: RunnerLimits,
    observer: F,
) -> Result<RunOutcome, String>
where
    F: Fn(Pid) -> Result<usize, String>,
{
    limits.validate()?;
    command
        .current_dir(worktree)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        // Rust's stable CommandExt API sets the direct child as its own group
        // leader without an unsafe pre_exec closure. Descendants inherit it.
        .process_group(0);
    let mut child = command
        .spawn()
        .map_err(|e| format!("resource-limit-blocked: cannot spawn sandbox child: {e}"))?;
    let pid = Pid::from_raw(
        i32::try_from(child.id())
            .map_err(|_| "resource-limit-blocked: child pid does not fit platform pid type")?,
    );
    let capped = Arc::new(AtomicBool::new(false));
    let captured = Arc::new(AtomicUsize::new(0));
    let stdout = take_reader(
        &mut child,
        limits.capture_cap(),
        Arc::clone(&captured),
        Arc::clone(&capped),
        true,
    )?;
    let stderr = take_reader(
        &mut child,
        limits.capture_cap(),
        captured,
        Arc::clone(&capped),
        false,
    )?;
    monitor_spawned_child(
        child,
        pid,
        CapturedOutput {
            stdout,
            stderr,
            capped,
        },
        worktree,
        limits,
        observer,
    )
}

struct CapturedOutput {
    stdout: thread::JoinHandle<Vec<u8>>,
    stderr: thread::JoinHandle<Vec<u8>>,
    capped: Arc<AtomicBool>,
}

fn monitor_spawned_child<F>(
    mut child: Child,
    pid: Pid,
    output: CapturedOutput,
    worktree: &Path,
    limits: RunnerLimits,
    observer: F,
) -> Result<RunOutcome, String>
where
    F: Fn(Pid) -> Result<usize, String>,
{
    let deadline = Instant::now() + limits.per_check.min(limits.aggregate);
    let terminal = loop {
        if output.capped.load(Ordering::Acquire) {
            break "output-limit";
        }
        if worktree_size(worktree, limits.worktree_bytes).is_err() {
            break "worktree-limit";
        }
        match observer(pid) {
            Ok(count) if count > limits.child_processes as usize => break "resource-limit",
            Ok(_) => {}
            Err(_) => break "process-observer-failed",
        }
        if Instant::now() >= deadline {
            break if limits.aggregate <= limits.per_check {
                "aggregate-timeout"
            } else {
                "check-timeout"
            };
        }
        match child.try_wait() {
            Ok(Some(status)) => {
                terminate_and_prove_empty_group(pid)?;
                let (stdout, stderr) = join_readers(output.stdout, output.stderr)?;
                return Ok(outcome_from_status(status, stdout, stderr));
            }
            Ok(None) => thread::sleep(POLL_INTERVAL),
            Err(e) => {
                let _ = e;
                break "child-wait-failed";
            }
        }
    };
    terminate_and_reap(&mut child, pid)?;
    let (stdout, stderr) = join_readers(output.stdout, output.stderr)?;
    Ok(RunOutcome::Blocked {
        reason: terminal,
        stdout,
        stderr,
    })
}

#[cfg(target_os = "macos")]
fn supervise_controlled(
    mut command: Command,
    control: crate::sandbox_macos::PreparedControl,
    worktree: &Path,
    limits: RunnerLimits,
) -> Result<SandboxedExecution, String> {
    limits.validate()?;
    command
        .current_dir(worktree)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .process_group(0);
    let mut child = command
        .spawn()
        .map_err(|error| format!("sandbox.handshake-spawn: {error}"))?;
    let pid = Pid::from_raw(
        i32::try_from(child.id())
            .map_err(|_| "sandbox.handshake-spawn: child pid is unsupported")?,
    );
    let mut control_input = child
        .stdin
        .take()
        .ok_or("sandbox.control-io: child control input is unavailable")?;
    let control_output = child
        .stdout
        .take()
        .ok_or("sandbox.control-io: child control output is unavailable")?;
    let capped = Arc::new(AtomicBool::new(false));
    let captured = Arc::new(AtomicUsize::new(0));
    let stderr = take_reader(
        &mut child,
        limits.capture_cap(),
        Arc::clone(&captured),
        Arc::clone(&capped),
        false,
    )?;

    control_input
        .write_all(&control.request_line)
        .and_then(|_| control_input.write_all(b"\n"))
        .and_then(|_| control_input.flush())
        .map_err(|error| format!("sandbox.control-io: cannot send request: {error}"))?;
    let (sender, receiver) = mpsc::sync_channel(1);
    thread::spawn(move || {
        let mut output = control_output;
        let line = read_handshake_line(&mut output);
        let _ = sender.send((line, output));
    });
    let handshake_deadline =
        Instant::now() + SANDBOX_HANDSHAKE_TIMEOUT.min(limits.per_check.min(limits.aggregate));
    let (ready, control_output) = loop {
        match receiver.try_recv() {
            Ok(value) => break value,
            Err(mpsc::TryRecvError::Disconnected) => {
                terminate_and_reap(&mut child, pid)?;
                let stderr = stderr
                    .join()
                    .map_err(|_| "sandbox.control-io: stderr reader panicked")?;
                return Ok(SandboxedExecution {
                    outcome: RunOutcome::Blocked {
                        reason: "sandbox-handshake-failed",
                        stdout: Vec::new(),
                        stderr,
                    },
                    attestation: None,
                });
            }
            Err(mpsc::TryRecvError::Empty) => {}
        }
        if child
            .try_wait()
            .map_err(|error| format!("sandbox.control-io: cannot wait for helper: {error}"))?
            .is_some()
        {
            terminate_and_prove_empty_group(pid)?;
            let stderr = stderr
                .join()
                .map_err(|_| "sandbox.control-io: stderr reader panicked")?;
            return Ok(SandboxedExecution {
                outcome: RunOutcome::Blocked {
                    reason: "sandbox-handshake-failed",
                    stdout: Vec::new(),
                    stderr,
                },
                attestation: None,
            });
        }
        if Instant::now() >= handshake_deadline {
            terminate_and_reap(&mut child, pid)?;
            let stderr = stderr
                .join()
                .map_err(|_| "sandbox.control-io: stderr reader panicked")?;
            return Ok(SandboxedExecution {
                outcome: RunOutcome::Blocked {
                    reason: "sandbox-handshake-timeout",
                    stdout: Vec::new(),
                    stderr,
                },
                attestation: None,
            });
        }
        thread::sleep(POLL_INTERVAL);
    };
    let ready = ready?;
    let expected = format!("MPD_READY {}", control.ready_digest);
    if ready != expected.as_bytes() {
        terminate_and_reap(&mut child, pid)?;
        let stderr = stderr
            .join()
            .map_err(|_| "sandbox.control-io: stderr reader panicked")?;
        return Ok(SandboxedExecution {
            outcome: RunOutcome::Blocked {
                reason: "sandbox-ready-mismatch",
                stdout: Vec::new(),
                stderr,
            },
            attestation: None,
        });
    }
    writeln!(control_input, "MPD_GO {}", control.ready_digest)
        .and_then(|_| control_input.flush())
        .map_err(|error| format!("sandbox.control-io: cannot send GO: {error}"))?;
    drop(control_input);
    let stdout = spawn_reader(
        Reader::Stdout(control_output),
        limits.capture_cap(),
        captured,
        Arc::clone(&capped),
    );
    let outcome = monitor_spawned_child(
        child,
        pid,
        CapturedOutput {
            stdout,
            stderr,
            capped,
        },
        worktree,
        limits,
        process_group_members,
    )?;
    Ok(SandboxedExecution {
        outcome,
        attestation: Some(control.attestation),
    })
}

#[cfg(target_os = "macos")]
fn read_handshake_line(reader: &mut impl Read) -> Result<Vec<u8>, String> {
    let mut line = Vec::new();
    let mut byte = [0_u8; 1];
    loop {
        match reader.read(&mut byte) {
            Ok(0) => return Err("sandbox.control-io: EOF before READY".into()),
            Ok(_) if byte[0] == b'\n' => return Ok(line),
            Ok(_) => {
                if line.len() == 256 {
                    return Err("sandbox.control-malformed: READY exceeds its cap".into());
                }
                line.push(byte[0]);
            }
            Err(error) => return Err(format!("sandbox.control-io: cannot read READY: {error}")),
        }
    }
}

/// The hidden helper's narrow contract: set only hard inherited limits, then
/// safely execute the already separated canonical argv. It never parses a
/// shell string and it returns a blocker when any platform limit cannot apply.
pub fn limited_exec(
    cpu_secs: u64,
    processes: u64,
    open_files: u64,
    file_bytes: u64,
    argv: &[String],
) -> Result<(), String> {
    if argv.is_empty() || cpu_secs == 0 || processes == 0 || open_files < 3 || file_bytes == 0 {
        return Err("resource-limit-invalid: invalid limited-exec arguments".into());
    }
    if cpu_secs > 1800
        || processes > MAX_CHILD_PROCESSES
        || open_files > MAX_CHILD_OPEN_FILES
        || file_bytes > MAX_CHILD_FILE_BYTES
    {
        return Err(
            "resource-limit-invalid: limited-exec cap exceeds the compiled platform ceiling".into(),
        );
    }
    let program = canonical_regular_file(Path::new(&argv[0]))?;
    let (_, inherited_file_limit) = getrlimit(Resource::RLIMIT_NOFILE).map_err(|e| {
        format!("resource-limit-blocked: cannot inspect inherited descriptor cap: {e}")
    })?;
    install_limit(Resource::RLIMIT_CPU, cpu_secs, "cpu")?;
    install_process_limit(processes)?;
    install_limit(Resource::RLIMIT_NOFILE, open_files, "open-file")?;
    install_limit(Resource::RLIMIT_FSIZE, file_bytes, "file-size")?;
    close_nonstandard_descriptors(inherited_file_limit)?;
    let program = CString::new(program.as_os_str().as_encoded_bytes())
        .map_err(|_| "resource-limit-invalid: executable path contains NUL")?;
    let exec_args: Result<Vec<CString>, _> = argv
        .iter()
        .map(|arg| CString::new(arg.as_bytes()))
        .collect();
    let exec_args =
        exec_args.map_err(|_| "resource-limit-invalid: executable argv contains NUL")?;
    execvp(&program, &exec_args)
        .map_err(|e| format!("resource-limit-blocked: cannot exec approved argv: {e}"))?;
    unreachable!("execvp returns only on error")
}

fn close_nonstandard_descriptors(inherited_limit: rlim_t) -> Result<(), String> {
    let _ = inherited_limit;
    #[cfg(target_os = "linux")]
    let descriptor_directory = Path::new("/proc/self/fd");
    #[cfg(not(target_os = "linux"))]
    let descriptor_directory = Path::new("/dev/fd");
    let mut descriptors = Vec::new();
    for entry in fs::read_dir(descriptor_directory)
        .map_err(|error| format!("resource-limit-blocked: cannot enumerate descriptors: {error}"))?
    {
        let entry = entry.map_err(|error| {
            format!("resource-limit-blocked: cannot inspect descriptor entry: {error}")
        })?;
        let Some(name) = entry.file_name().to_str().map(str::to_owned) else {
            return Err("resource-limit-blocked: descriptor name is not UTF-8".into());
        };
        let fd = name
            .parse::<i32>()
            .map_err(|_| "resource-limit-blocked: descriptor name is malformed")?;
        if fd > 2 {
            descriptors.push(fd);
            if descriptors.len() > MAX_CHILD_OPEN_FILES as usize {
                return Err(
                    "resource-limit-blocked: inherited descriptor count exceeds cap".into(),
                );
            }
        }
    }
    descriptors.sort_unstable();
    descriptors.dedup();
    for fd in descriptors {
        match close(fd) {
            Ok(()) | Err(Errno::EBADF) => {}
            Err(error) => {
                return Err(format!(
                    "resource-limit-blocked: cannot close inherited descriptor: {error}"
                ))
            }
        }
    }
    Ok(())
}

fn install_limit(resource: Resource, value: u64, name: &str) -> Result<(), String> {
    let value = rlim_t::try_from(value)
        .map_err(|_| format!("resource-limit-invalid: {name} cap is unsupported"))?;
    setrlimit(resource, value, value)
        .map_err(|e| format!("resource-limit-blocked: cannot install {name} cap: {e}"))
}

#[cfg(any(
    target_os = "linux",
    target_os = "android",
    target_os = "freebsd",
    target_os = "netbsd",
    target_os = "aix"
))]
fn install_process_limit(value: u64) -> Result<(), String> {
    install_limit(Resource::RLIMIT_NPROC, value, "process")
}

#[cfg(not(any(
    target_os = "linux",
    target_os = "android",
    target_os = "freebsd",
    target_os = "netbsd",
    target_os = "aix"
)))]
fn install_process_limit(_value: u64) -> Result<(), String> {
    // Darwin does not expose RLIMIT_NPROC through nix. The parent supervisor
    // independently counts the isolated group on every poll and blocks on an
    // observation failure, so this missing native limit is never a fallback.
    Ok(())
}

/// Count only members of the owned process group. Linux reads bounded procfs
/// records; macOS uses the canonical system `ps` with a fixed argv. Neither
/// path interprets repository input or a shell command.
fn process_group_members(group: Pid) -> Result<usize, String> {
    #[cfg(target_os = "linux")]
    {
        return linux_process_group_members(group);
    }
    #[cfg(target_os = "macos")]
    {
        return macos_process_group_members(group);
    }
    #[allow(unreachable_code)]
    Err("process observer is unsupported on this platform".into())
}

#[cfg(target_os = "linux")]
fn linux_process_group_members(group: Pid) -> Result<usize, String> {
    let mut count = 0_usize;
    let mut observed = 0_usize;
    for entry in fs::read_dir("/proc").map_err(|e| format!("cannot enumerate procfs: {e}"))? {
        let entry = entry.map_err(|e| format!("cannot read procfs entry: {e}"))?;
        let name = entry.file_name();
        if !name.as_encoded_bytes().iter().all(u8::is_ascii_digit) {
            continue;
        }
        if observed == MAX_PROCESS_OBSERVATIONS {
            return Err("procfs process observation exceeds its cap".into());
        }
        observed += 1;
        let path = entry.path().join("stat");
        let bytes = match read_file_capped(&path, 8192) {
            Ok(bytes) => bytes,
            Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
            Err(error) => return Err(format!("cannot read procfs stat: {error}")),
        };
        if proc_stat_group(&bytes)? == group.as_raw() {
            count += 1;
        }
    }
    Ok(count)
}

#[cfg(target_os = "linux")]
fn proc_stat_group(bytes: &[u8]) -> Result<i32, String> {
    let close = bytes
        .iter()
        .rposition(|byte| *byte == b')')
        .ok_or_else(|| "malformed procfs stat record".to_string())?;
    let fields = std::str::from_utf8(&bytes[close + 1..])
        .map_err(|_| "non-UTF-8 procfs stat record")?
        .split_ascii_whitespace()
        .collect::<Vec<_>>();
    fields
        .get(2)
        .ok_or_else(|| "truncated procfs stat record".to_string())?
        .parse::<i32>()
        .map_err(|_| "invalid procfs process group".into())
}

#[cfg(target_os = "macos")]
fn macos_process_group_members(group: Pid) -> Result<usize, String> {
    let ps = canonical_regular_file(Path::new("/bin/ps"))?;
    let mut child = Command::new(ps)
        .args(["-axo", "pid=,pgid="])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|e| format!("cannot run canonical process observer: {e}"))?;
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| "cannot capture process observer output".to_string())?;
    let reader = thread::spawn(move || read_stream_capped(stdout, MAX_PROCESS_OBSERVER_BYTES));
    let deadline = Instant::now() + PROCESS_OBSERVER_TIMEOUT;
    while child
        .try_wait()
        .map_err(|e| format!("cannot wait for process observer: {e}"))?
        .is_none()
    {
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            let _ = reader.join();
            return Err("process observer timed out".into());
        }
        thread::sleep(POLL_INTERVAL);
    }
    let bytes = reader
        .join()
        .map_err(|_| "process observer reader panicked")?
        .map_err(|e| format!("cannot read bounded process observer output: {e}"))?;
    parse_ps_group_members(&bytes, group)
}

#[cfg(target_os = "macos")]
fn parse_ps_group_members(bytes: &[u8], group: Pid) -> Result<usize, String> {
    let text = std::str::from_utf8(bytes).map_err(|_| "non-UTF-8 process observer output")?;
    let mut count = 0_usize;
    let mut observed = 0_usize;
    for line in text.lines() {
        if line.is_empty() {
            continue;
        }
        if observed == MAX_PROCESS_OBSERVATIONS {
            return Err("process observation exceeds its record cap".into());
        }
        observed += 1;
        let fields = line.split_ascii_whitespace().collect::<Vec<_>>();
        if fields.len() != 2 {
            return Err("malformed process observer output".into());
        }
        fields[0]
            .parse::<u32>()
            .map_err(|_| "invalid process observer pid")?;
        let pgid = fields[1]
            .parse::<i32>()
            .map_err(|_| "invalid process observer group")?;
        if pgid == group.as_raw() {
            count += 1;
        }
    }
    Ok(count)
}

#[cfg(target_os = "linux")]
fn read_file_capped(path: &Path, cap: usize) -> io::Result<Vec<u8>> {
    let file = File::open(path)?;
    read_stream_capped(file, cap)
}

fn read_stream_capped(mut reader: impl Read, cap: usize) -> io::Result<Vec<u8>> {
    let mut output = Vec::new();
    let mut buffer = [0_u8; 8192];
    loop {
        let count = reader.read(&mut buffer)?;
        if count == 0 {
            return Ok(output);
        }
        if output.len().saturating_add(count) > cap {
            return Err(io::Error::other("observer output exceeds cap"));
        }
        output.extend_from_slice(&buffer[..count]);
    }
}

fn canonical_regular_file(path: &Path) -> Result<PathBuf, String> {
    let canonical = fs::canonicalize(path)
        .map_err(|e| format!("resource-limit-blocked: cannot canonicalize executable: {e}"))?;
    let metadata = fs::metadata(&canonical)
        .map_err(|e| format!("resource-limit-blocked: cannot inspect executable: {e}"))?;
    if !metadata.is_file() {
        return Err("resource-limit-blocked: executable is not a regular file".into());
    }
    Ok(canonical)
}

fn take_reader(
    child: &mut Child,
    cap: usize,
    captured: Arc<AtomicUsize>,
    exceeded: Arc<AtomicBool>,
    stdout: bool,
) -> Result<thread::JoinHandle<Vec<u8>>, String> {
    let pipe = if stdout {
        child.stdout.take().map(Reader::Stdout)
    } else {
        child.stderr.take().map(Reader::Stderr)
    }
    .ok_or_else(|| "resource-limit-blocked: child output pipe is unavailable".to_string())?;
    Ok(spawn_reader(pipe, cap, captured, exceeded))
}

fn spawn_reader(
    pipe: Reader,
    cap: usize,
    captured: Arc<AtomicUsize>,
    exceeded: Arc<AtomicBool>,
) -> thread::JoinHandle<Vec<u8>> {
    thread::spawn(move || read_bounded(pipe, cap, captured, exceeded))
}

enum Reader {
    Stdout(std::process::ChildStdout),
    Stderr(std::process::ChildStderr),
}

impl Read for Reader {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        match self {
            Self::Stdout(pipe) => pipe.read(bytes),
            Self::Stderr(pipe) => pipe.read(bytes),
        }
    }
}

fn read_bounded(
    mut pipe: Reader,
    cap: usize,
    captured: Arc<AtomicUsize>,
    exceeded: Arc<AtomicBool>,
) -> Vec<u8> {
    let mut output = Vec::new();
    let mut buffer = [0_u8; 8192];
    loop {
        match pipe.read(&mut buffer) {
            Ok(0) | Err(_) => break,
            Ok(count) => {
                let before = captured.fetch_add(count, Ordering::AcqRel);
                let remaining = cap.saturating_sub(before);
                output.extend_from_slice(&buffer[..count.min(remaining)]);
                if count > remaining {
                    exceeded.store(true, Ordering::Release);
                }
            }
        }
    }
    output
}

fn join_readers(
    stdout: thread::JoinHandle<Vec<u8>>,
    stderr: thread::JoinHandle<Vec<u8>>,
) -> Result<(Vec<u8>, Vec<u8>), String> {
    let stdout = stdout
        .join()
        .map_err(|_| "resource-limit-blocked: stdout reader panicked")?;
    let stderr = stderr
        .join()
        .map_err(|_| "resource-limit-blocked: stderr reader panicked")?;
    Ok((stdout, stderr))
}

fn outcome_from_status(status: ExitStatus, stdout: Vec<u8>, stderr: Vec<u8>) -> RunOutcome {
    if status.code() == Some(125) {
        return RunOutcome::Blocked {
            reason: "resource-limit-setup",
            stdout,
            stderr,
        };
    }
    if status.success() {
        RunOutcome::Passed { stdout, stderr }
    } else {
        RunOutcome::Failed {
            status: status.code(),
            stdout,
            stderr,
        }
    }
}

fn terminate_and_reap(child: &mut Child, group: Pid) -> Result<(), String> {
    let _ = kill_group(group, Signal::SIGTERM);
    let until = Instant::now() + TERM_GRACE;
    while Instant::now() < until {
        if child
            .try_wait()
            .map_err(|e| format!("resource-limit-blocked: cannot reap child: {e}"))?
            .is_some()
        {
            break;
        }
        thread::sleep(POLL_INTERVAL);
    }
    let _ = kill_group(group, Signal::SIGKILL);
    if child
        .try_wait()
        .map_err(|e| format!("resource-limit-blocked: cannot reap child: {e}"))?
        .is_none()
    {
        child
            .wait()
            .map_err(|e| format!("resource-limit-blocked: cannot wait for child: {e}"))?;
    }
    prove_empty_group(group)
}

fn terminate_and_prove_empty_group(group: Pid) -> Result<(), String> {
    let _ = kill_group(group, Signal::SIGTERM);
    thread::sleep(TERM_GRACE);
    let _ = kill_group(group, Signal::SIGKILL);
    prove_empty_group(group)
}

fn kill_group(group: Pid, signal: Signal) -> Result<(), String> {
    match killpg(group, signal) {
        Ok(()) | Err(Errno::ESRCH) => Ok(()),
        Err(error) => Err(format!(
            "resource-limit-blocked: cannot signal child process group: {error}"
        )),
    }
}

/// Signal zero is the portable group-liveness query: only ESRCH proves the
/// group is gone. EPERM/other errors are blockers, never assumed clean.
fn prove_empty_group(group: Pid) -> Result<(), String> {
    let until = Instant::now() + KILL_GRACE;
    loop {
        match killpg(group, None) {
            Err(Errno::ESRCH) => return Ok(()),
            Ok(()) if Instant::now() < until => thread::sleep(POLL_INTERVAL),
            Ok(()) => {
                return Err(
                    "resource-limit-blocked: child process group survived termination".into(),
                )
            }
            Err(error) => {
                return Err(format!(
                    "resource-limit-blocked: cannot prove child group cleanup: {error}"
                ))
            }
        }
    }
}

fn worktree_size(root: &Path, cap: u64) -> Result<u64, ()> {
    let mut pending = vec![root.to_path_buf()];
    let mut total = 0_u64;
    while let Some(path) = pending.pop() {
        let metadata = fs::symlink_metadata(&path).map_err(|_| ())?;
        if metadata.file_type().is_symlink() {
            return Err(());
        }
        if metadata.is_dir() {
            for entry in fs::read_dir(path).map_err(|_| ())? {
                pending.push(entry.map_err(|_| ())?.path());
            }
        } else if metadata.is_file() {
            total = total.checked_add(metadata.len()).ok_or(())?;
            if total > cap {
                return Err(());
            }
        } else {
            return Err(());
        }
    }
    Ok(total)
}

/// A reviewed platform adapter. The command path is resolved before candidate
/// execution; callers must reject an unavailable adapter rather than falling
/// back to an unsandboxed child.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SandboxAdapter {
    Macos {
        profile: PathBuf,
    },
    Linux {
        executable: PathBuf,
        profile: PathBuf,
    },
}

impl SandboxAdapter {
    /// Select an adapter using fixed repository policy assets only.
    pub fn select(os: &str, root: &Path, executable: Option<PathBuf>) -> Result<Self, String> {
        match os {
            "macos" => {
                #[cfg(target_os = "macos")]
                {
                    crate::sandbox_macos::verify_certified_host()?;
                    crate::sandbox_macos::probe_symbols()?;
                    let profile = crate::sandbox_macos::verify_profile_asset(root)?;
                    Ok(Self::Macos { profile })
                }
                #[cfg(not(target_os = "macos"))]
                {
                    let _ = (root, executable);
                    Err("macOS compatibility adapter is unavailable on this host".into())
                }
            }
            "linux" => {
                let executable = executable
                    .ok_or_else(|| "network-denial adapter is unavailable".to_string())?;
                if !executable.is_absolute() || !executable.is_file() {
                    return Err("network-denial adapter is not a canonical regular file".into());
                }
                let executable = fs::canonicalize(executable)
                    .map_err(|e| format!("cannot canonicalize network-denial adapter: {e}"))?;
                let profile = root.join("security/sandbox/validation.bwrap");
                profile
                    .is_file()
                    .then_some(Self::Linux {
                        executable,
                        profile,
                    })
                    .ok_or_else(|| "Linux bubblewrap profile is missing".into())
            }
            _ => Err("no mandatory network-denial adapter is supported on this platform".into()),
        }
    }

    /// Build a child with a cleared, minimal environment. It does not start the
    /// child; lifecycle and receipt layers own execution.
    #[allow(clippy::too_many_arguments)]
    pub fn command(
        &self,
        program: &Path,
        approved_program: &Path,
        args: &[String],
        authority_digest: &str,
        limits: RunnerLimits,
        home: &Path,
        tmp: &Path,
        worktree: &Path,
        cargo_home: Option<&Path>,
        cargo_target_dir: Option<&Path>,
        rustc: Option<&Path>,
        read_only_roots: &[PathBuf],
    ) -> Result<PreparedSandboxCommand, String> {
        let required_paths = [program, approved_program, home, tmp, worktree];
        if required_paths.iter().any(|path| !path.is_absolute()) {
            return Err("sandbox paths must be absolute".into());
        }
        if read_only_roots.len() > MAX_APPROVED_READ_ROOTS
            || read_only_roots
                .iter()
                .any(|path| !path.is_absolute() || path == Path::new("/"))
        {
            return Err("sandbox read-only roots are invalid or exceed their cap".into());
        }
        if authority_digest.len() != 64
            || !authority_digest
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit())
        {
            return Err("sandbox.control-malformed: authority digest is invalid".into());
        }
        limits.validate()?;
        let (mut command, append_args) = match self {
            Self::Macos { .. } => {
                let mut c = Command::new(program);
                c.arg("__mpd-sandbox-exec");
                (c, false)
            }
            Self::Linux { executable, .. } => {
                let mut c = Command::new(executable);
                c.args([
                    "--unshare-net",
                    "--die-with-parent",
                    "--new-session",
                    "--proc",
                    "/proc",
                    "--dev",
                    "/dev",
                    "--tmpfs",
                    "/tmp",
                ]);
                for system_root in ["/usr", "/bin", "/lib", "/lib64", "/etc"] {
                    let root = Path::new(system_root);
                    if root.exists() {
                        c.arg("--ro-bind").arg(root).arg(root);
                    }
                }
                let mut read_only = std::collections::BTreeSet::new();
                read_only.insert(worktree);
                read_only.insert(executable_root(program));
                read_only.insert(executable_root(approved_program));
                if let Some(path) = cargo_home {
                    read_only.insert(path);
                }
                if let Some(path) = rustc {
                    read_only.insert(executable_root(path));
                }
                read_only.extend(read_only_roots.iter().map(PathBuf::as_path));
                for root in read_only {
                    c.arg("--ro-bind").arg(root).arg(root);
                }
                if let Some(runtime_root) = tmp.parent() {
                    c.arg("--bind").arg(runtime_root).arg(runtime_root);
                }
                c.arg("--chdir").arg(worktree);
                c.arg("--");
                c.arg(program);
                c.args([
                    "__mpd-limited-exec",
                    "--cpu-secs",
                    &limits.per_check.as_secs().max(1).to_string(),
                    "--processes",
                    &limits.child_processes.to_string(),
                    "--open-files",
                    &limits.child_open_files.to_string(),
                    "--file-bytes",
                    &limits.child_file_bytes.to_string(),
                    "--",
                ]);
                c.arg(approved_program);
                (c, true)
            }
        };
        let path = rustc
            .and_then(Path::parent)
            .and_then(|toolchain_bin| {
                std::env::join_paths([toolchain_bin, Path::new("/usr/bin"), Path::new("/bin")]).ok()
            })
            .unwrap_or_else(|| std::ffi::OsString::from("/usr/bin:/bin"));
        if append_args {
            command.args(args);
        }
        // Deterministic Git identity for the contained run: the private HOME
        // has no ambient ~/.gitconfig, so any validated suite that creates
        // real commits (this repository's own fixtures do) would otherwise
        // fail on committer auto-detection. The identity is fixed and
        // non-attributable by construction (Conditions for Builder #17).
        let git_identity = home.join("gitconfig");
        std::fs::write(
            &git_identity,
            "[user]\n\tname = mpd-validation\n\temail = validation@mpd.invalid\n",
        )
        .map_err(|error| format!("sandbox.root-invalid: cannot seed git identity: {error}"))?;
        command
            .env_clear()
            .env("PATH", path)
            .env("HOME", home)
            .env("TMPDIR", tmp)
            .env("CARGO_NET_OFFLINE", "true")
            .env("CARGO_TERM_COLOR", "never")
            .env("GIT_CONFIG_GLOBAL", &git_identity)
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_CONFIG_SYSTEM", "/dev/null")
            .env("GIT_OPTIONAL_LOCKS", "0")
            .env("GIT_PAGER", "cat")
            .env("GIT_TERMINAL_PROMPT", "0")
            .env("LANG", "C")
            .env("LC_ALL", "C")
            .env("PAGER", "cat")
            .env("TERM", "dumb")
            .env("TZ", "UTC");
        if let Some(path) = cargo_home {
            command.env("CARGO_HOME", path);
        }
        if let Some(path) = cargo_target_dir {
            command.env("CARGO_TARGET_DIR", path);
        }
        if let Some(path) = rustc {
            command.env("RUSTC", path);
        }
        command.env("SEMGREP_SEND_METRICS", "off");
        // Containment marker for self-hosted suites: tests that spawn this
        // sandbox or its supervisor cannot nest inside it and skip themselves
        // when the marker is present. Their coverage is preserved by the
        // ordinary (uncontained) suite runs and by this run's own canaries.
        command.env("MPD_SANDBOXED", "1");
        // Validation runtimes are created fresh per run, so incremental
        // compilation buys nothing — and its intra-target hard links trip the
        // owned-tree cleanup guard, which refuses multiply-linked files.
        command.env("CARGO_INCREMENTAL", "0");
        // Pin the trust-anchor file for TLS-initializing tools (semgrep-core's
        // telemetry client builds an authenticator eagerly): the deny-default
        // profile blocks the keychain Mach services its platform probe needs,
        // and /etc/ssl is already a granted read root. Network stays denied.
        #[cfg(target_os = "macos")]
        command.env("SSL_CERT_FILE", "/etc/ssl/cert.pem");
        // Pin the Apple toolchain to the granted CommandLineTools root. The
        // host's xcode-select state is mutable (e.g. an Xcode beta), and any
        // developer dir outside the fixed read roots would make rustc's
        // cc/xcrun link step fail closed inside the sandbox.
        #[cfg(target_os = "macos")]
        command.env("DEVELOPER_DIR", "/Library/Developer/CommandLineTools");

        #[cfg(target_os = "macos")]
        let control = if matches!(self, Self::Macos { .. }) {
            let runtime_root = home
                .parent()
                .ok_or("sandbox.root-invalid: private HOME has no runtime parent")?;
            if tmp.parent() != Some(runtime_root)
                || cargo_target_dir.is_some_and(|target| !target.starts_with(runtime_root))
            {
                return Err(
                    "sandbox.root-invalid: writable paths do not share one runtime root".into(),
                );
            }
            let mut roots = vec![
                worktree.to_path_buf(),
                executable_root(program).to_path_buf(),
                executable_root(approved_program).to_path_buf(),
                rustc
                    .map(executable_root)
                    .unwrap_or_else(|| executable_root(program))
                    .to_path_buf(),
                PathBuf::from("/System"),
                PathBuf::from("/usr"),
                PathBuf::from("/dev"),
                // System libcrypto (loaded by cargo's curl dependency even in
                // fully offline runs) reads /etc/ssl/openssl.cnf at startup
                // and aborts when denied. /etc resolves via the globally
                // allowed metadata read; this grants data reads of the public
                // TLS configuration only. Network remains denied outright.
                PathBuf::from("/private/etc/ssl"),
            ];
            if let Some(cargo_home) = cargo_home {
                roots.push(cargo_home.to_path_buf());
            }
            let command_line_tools = PathBuf::from("/Library/Developer/CommandLineTools");
            if command_line_tools.is_dir() {
                roots.push(command_line_tools);
            }
            roots.extend(read_only_roots.iter().cloned());
            let mut approved_argv = Vec::with_capacity(args.len() + 1);
            approved_argv.push(approved_program.display().to_string());
            approved_argv.extend(args.iter().cloned());
            Some(crate::sandbox_macos::prepare_control(
                &roots,
                runtime_root,
                approved_program,
                authority_digest,
                crate::sandbox_macos::ControlLimits {
                    cpu_secs: limits.per_check.as_secs().max(1),
                    processes: limits.child_processes,
                    open_files: limits.child_open_files,
                    file_bytes: limits.child_file_bytes,
                },
                &approved_argv,
            )?)
        } else {
            None
        };
        Ok(PreparedSandboxCommand {
            command,
            #[cfg(target_os = "macos")]
            control,
        })
    }
}

fn executable_root(path: &Path) -> &Path {
    let parent = path.parent().unwrap_or(path);
    match parent.parent() {
        Some(package_root) if package_root != Path::new("/") => package_root,
        _ => parent,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Baseline limits for supervisor tests that do NOT test deadlines.
    /// The time budgets are deliberately generous: under full-suite parallel
    /// load, spawning `/bin/sh` alone can exceed a milliseconds-scale
    /// deadline, turning a `Passed`/`output-limit`/`worktree-limit`
    /// expectation into a spurious `check-timeout` (observed as a
    /// load-dependent flake in `supervisor_distinguishes_success_and_nonzero_exit`
    /// and `supervisor_blocks_output_and_worktree_floods`). Deadline behavior
    /// itself is pinned by `supervisor_enforces_check_and_aggregate_deadlines`,
    /// which sets its own short budgets explicitly.
    fn limits() -> RunnerLimits {
        RunnerLimits {
            per_check: Duration::from_secs(30),
            aggregate: Duration::from_secs(60),
            output_bytes: 4096,
            log_bytes: 4096,
            worktree_bytes: 64 * 1024,
            child_processes: 32,
            child_open_files: 32,
            child_file_bytes: 64 * 1024,
        }
    }

    fn test_worktree(label: &str) -> PathBuf {
        let root = std::env::temp_dir().join(format!(
            "mpd-supervisor-{label}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir(&root).unwrap();
        root
    }

    fn validation_profile() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../security/sandbox/validation.sb")
    }

    fn supervised_shell(script: &str, root: &Path, limits: RunnerLimits) -> RunOutcome {
        let mut command = Command::new("/bin/sh");
        command.args(["-c", script]);
        supervise(command, root, limits).unwrap()
    }

    #[test]
    fn unsupported_or_missing_adapter_blocks() {
        let root = std::env::temp_dir();
        assert!(SandboxAdapter::select("unknown", &root, None).is_err());
        assert!(SandboxAdapter::select("linux", &root, None).is_err());
    }

    #[test]
    fn command_clears_environment_and_sets_offline_contract() {
        let adapter = SandboxAdapter::Macos {
            profile: validation_profile(),
        };
        let worktree = test_worktree("mac-command-worktree");
        let runtime = test_worktree("mac-command-runtime");
        let home = runtime.join("home");
        let tmp = runtime.join("tmp");
        fs::create_dir(&home).unwrap();
        fs::create_dir(&tmp).unwrap();
        let supervisor = std::env::current_exe().unwrap();
        let command = adapter
            .command(
                &supervisor,
                Path::new("/usr/bin/true"),
                &[],
                &"ab".repeat(32),
                limits(),
                &home,
                &tmp,
                &worktree,
                None,
                None,
                Some(Path::new("/usr/bin/true")),
                &[],
            )
            .unwrap();
        assert_eq!(
            command
                .get_envs()
                .find(|(k, _)| *k == "CARGO_NET_OFFLINE")
                .and_then(|(_, v)| v)
                .unwrap(),
            "true"
        );
        assert_eq!(
            command
                .get_envs()
                .find(|(k, _)| *k == "PATH")
                .and_then(|(_, v)| v)
                .unwrap(),
            "/usr/bin:/usr/bin:/bin"
        );
        assert!(command.get_envs().all(|(key, _)| key != "SSH_AUTH_SOCK"));
        for forbidden in [
            "AWS_SECRET_ACCESS_KEY",
            "DYLD_INSERT_LIBRARIES",
            "GIT_DIR",
            "HTTP_PROXY",
            "MPD_HOST_SECRET",
        ] {
            assert!(command.get_envs().all(|(key, _)| key != forbidden));
        }
        let git_config_global = command
            .get_envs()
            .find(|(key, _)| *key == "GIT_CONFIG_GLOBAL")
            .and_then(|(_, value)| value)
            .unwrap();
        assert!(
            Path::new(git_config_global).starts_with(runtime.join("home")),
            "GIT_CONFIG_GLOBAL must be the runtime-seeded identity, got {git_config_global:?}"
        );
        assert_eq!(
            fs::read_to_string(git_config_global).unwrap(),
            "[user]\n\tname = mpd-validation\n\temail = validation@mpd.invalid\n"
        );
        let set_keys: std::collections::BTreeSet<String> = command
            .get_envs()
            .filter_map(|(key, value)| value.map(|_| key.to_string_lossy().into_owned()))
            .collect();
        for key in &set_keys {
            assert!(
                SANDBOX_ENV_CONTRACT_KEYS.contains(&key.as_str()),
                "prepared command sets env key outside the compiled contract: {key}"
            );
        }
        for key in SANDBOX_ENV_CONTRACT_KEYS {
            // This invocation passes no cargo_home/cargo_target_dir, and the
            // toolchain pin is macOS-conditional.
            if matches!(*key, "CARGO_HOME" | "CARGO_TARGET_DIR") {
                continue;
            }
            if cfg!(not(target_os = "macos")) && matches!(*key, "DEVELOPER_DIR" | "SSL_CERT_FILE") {
                continue;
            }
            assert!(
                set_keys.contains(*key),
                "compiled contract key is never set by the runner: {key}"
            );
        }
        let args = command
            .get_args()
            .map(|arg| arg.to_string_lossy().into_owned())
            .collect::<Vec<_>>();
        assert_eq!(args.first().map(String::as_str), Some("__mpd-sandbox-exec"));
        assert!(!args.iter().any(|arg| arg == worktree.to_str().unwrap()));
        assert!(command.control.is_some());
        fs::remove_dir_all(worktree).unwrap();
        fs::remove_dir_all(runtime).unwrap();
    }

    #[test]
    fn linux_adapter_binds_only_the_owned_runtime_writable() {
        let adapter = SandboxAdapter::Linux {
            executable: PathBuf::from("/usr/bin/bwrap"),
            profile: PathBuf::from("/reviewed/validation.bwrap"),
        };
        // The runner creates the private HOME before building the command;
        // the seeded git identity write requires it to exist.
        let runtime = test_worktree("linux-command-runtime");
        let home = runtime.join("home");
        fs::create_dir(&home).unwrap();
        let command = adapter
            .command(
                Path::new("/reviewed/tool"),
                Path::new("/reviewed/check/bin/check"),
                &[],
                &"ab".repeat(32),
                limits(),
                &home,
                Path::new("/tmp/mpd-run/check-tmp"),
                Path::new("/tmp/mpd-subject"),
                Some(Path::new("/clone/private/cargo-home")),
                Some(Path::new("/tmp/mpd-run/check-tmp/cargo-target")),
                Some(Path::new("/reviewed/rust/bin/rustc")),
                &[PathBuf::from("/reviewed/sdk")],
            )
            .unwrap();
        let args = command
            .get_args()
            .map(|arg| arg.to_string_lossy().into_owned())
            .collect::<Vec<_>>();
        assert!(args
            .windows(3)
            .any(|window| { window == ["--bind", "/tmp/mpd-run", "/tmp/mpd-run"] }));
        assert!(args.iter().any(|arg| arg == "--unshare-net"));
        assert!(args.iter().any(|arg| arg == "--new-session"));
        assert!(args.windows(3).any(|window| {
            window
                == [
                    "--ro-bind",
                    "/clone/private/cargo-home",
                    "/clone/private/cargo-home",
                ]
        }));
        assert!(args
            .windows(3)
            .any(|window| { window == ["--ro-bind", "/tmp/mpd-subject", "/tmp/mpd-subject"] }));
        assert!(args
            .windows(3)
            .any(|window| { window == ["--ro-bind", "/reviewed/sdk", "/reviewed/sdk"] }));
        assert!(!args
            .windows(3)
            .any(|window| window == ["--ro-bind", "/", "/"]));
        fs::remove_dir_all(runtime).unwrap();
    }

    /// True only when actually inside the validation sandbox: the marker
    /// alone is not trusted (an ambient variable must not silently skip
    /// coverage in uncontained runs); the denied-read canary corroborates it.
    fn nested_in_validation_sandbox() -> bool {
        std::env::var_os("MPD_SANDBOXED").is_some() && std::fs::read("/private/etc/hosts").is_err()
    }

    /// SC-1 regression (security-code.md, residual R1): an ambient
    /// `MPD_SANDBOXED` marker alone must NEVER satisfy the containment guard.
    /// The guard requires corroboration by an observed denied read of
    /// `/private/etc/hosts`, so a leaked or hostile marker in an uncontained
    /// run cannot silently convert the guarded supervisor tests into vacuous
    /// passes.
    #[test]
    fn ambient_sandbox_marker_alone_does_not_satisfy_containment_guard() {
        if std::fs::read("/private/etc/hosts").is_err() {
            // Genuinely contained: the uncontained branch is unobservable
            // here; the seven guarded tests cover the in-sandbox conjunct.
            eprintln!("skipped: cannot observe the uncontained branch under containment");
            return;
        }
        // Scoped guard: restore the prior ambient value on every exit path.
        struct EnvVarGuard {
            key: &'static str,
            previous: Option<std::ffi::OsString>,
        }
        impl Drop for EnvVarGuard {
            fn drop(&mut self) {
                match &self.previous {
                    Some(value) => std::env::set_var(self.key, value),
                    None => std::env::remove_var(self.key),
                }
            }
        }
        let guard = EnvVarGuard {
            key: "MPD_SANDBOXED",
            previous: std::env::var_os("MPD_SANDBOXED"),
        };
        // Neither conjunct alone: hosts is readable on this host, so the
        // guard must be false with the marker absent...
        std::env::remove_var(guard.key);
        assert!(
            !nested_in_validation_sandbox(),
            "guard must be false when the marker is absent and hosts is readable"
        );
        // ...and, decisively, false with the marker present but no observed
        // denied read — the ambient variable alone is insufficient.
        std::env::set_var(guard.key, "1");
        assert!(
            !nested_in_validation_sandbox(),
            "ambient MPD_SANDBOXED without observed containment must not skip coverage"
        );
        drop(guard);
    }

    #[test]
    fn supervisor_distinguishes_success_and_nonzero_exit() {
        if nested_in_validation_sandbox() {
            eprintln!("skipped: cannot nest the validation sandbox");
            return;
        }
        let root = test_worktree("status");
        assert!(matches!(
            supervised_shell("printf ok", &root, limits()),
            RunOutcome::Passed { stdout, .. } if stdout == b"ok"
        ));
        assert!(matches!(
            supervised_shell("exit 7", &root, limits()),
            RunOutcome::Failed {
                status: Some(7),
                ..
            }
        ));
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn supervisor_enforces_check_and_aggregate_deadlines() {
        if nested_in_validation_sandbox() {
            eprintln!("skipped: cannot nest the validation sandbox");
            return;
        }
        let root = test_worktree("timeout");
        // Deadline behavior needs a short budget by definition; `sleep 5`
        // exceeds it deterministically regardless of scheduler load (a
        // delayed spawn only makes the timeout more certain, never less).
        let mut short = limits();
        short.per_check = Duration::from_millis(150);
        let outcome = supervised_shell("sleep 5", &root, short);
        assert!(matches!(
            outcome,
            RunOutcome::Blocked {
                reason: "check-timeout",
                ..
            }
        ));
        let mut aggregate = limits();
        aggregate.per_check = Duration::from_secs(1);
        aggregate.aggregate = Duration::from_millis(30);
        let outcome = supervised_shell("sleep 5", &root, aggregate);
        assert!(matches!(
            outcome,
            RunOutcome::Blocked {
                reason: "aggregate-timeout",
                ..
            }
        ));
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn supervisor_reaps_background_pipe_holders() {
        if nested_in_validation_sandbox() {
            eprintln!("skipped: cannot nest the validation sandbox");
            return;
        }
        let root = test_worktree("descendants");
        let started = Instant::now();
        // The background sleep retains stdout/stderr after its parent exits.
        // The supervisor must terminate that inherited-pipe holder, join both
        // readers, and prove the original process group has disappeared.
        let outcome = supervised_shell("sleep 30 & exit 0", &root, limits());
        assert!(matches!(outcome, RunOutcome::Passed { .. }));
        // Far below both the 30 s background sleep and the 30 s per-check
        // budget: the supervisor returned because it reaped the pipe holder,
        // not because anything timed out. 10 s leaves headroom for a loaded
        // scheduler without blunting that discrimination.
        assert!(started.elapsed() < Duration::from_secs(10));
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn supervisor_blocks_process_groups_over_the_cap() {
        if nested_in_validation_sandbox() {
            eprintln!("skipped: cannot nest the validation sandbox");
            return;
        }
        let root = test_worktree("process-cap");
        let mut capped = limits();
        capped.child_processes = 2;
        let outcome = supervised_shell("sleep 30 & sleep 30 & sleep 30 & wait", &root, capped);
        assert!(matches!(
            outcome,
            RunOutcome::Blocked {
                reason: "resource-limit",
                ..
            }
        ));
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn supervisor_blocks_and_reaps_when_process_observation_fails() {
        let root = test_worktree("observer-failure");
        let mut command = Command::new("/bin/sh");
        command.args(["-c", "sleep 30"]);
        let outcome = supervise_with_observer(command, &root, limits(), |_| {
            Err("deliberately malformed observer result".into())
        })
        .unwrap();
        assert!(matches!(
            outcome,
            RunOutcome::Blocked {
                reason: "process-observer-failed",
                ..
            }
        ));
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn supervisor_blocks_output_and_worktree_floods() {
        if nested_in_validation_sandbox() {
            eprintln!("skipped: cannot nest the validation sandbox");
            return;
        }
        let root = test_worktree("flood");
        let mut output = limits();
        output.output_bytes = 128;
        output.log_bytes = 128;
        let outcome = supervised_shell("while :; do printf x; printf y >&2; done", &root, output);
        assert!(matches!(
            outcome,
            RunOutcome::Blocked {
                reason: "output-limit",
                ref stdout,
                ref stderr,
            } if stdout.len() <= 128 && stderr.len() <= 128
        ));
        let mut files = limits();
        files.worktree_bytes = 1024;
        assert!(matches!(
            supervised_shell(
                "dd if=/dev/zero of=flood bs=1024 count=8 2>/dev/null; sleep 5",
                &root,
                files
            ),
            RunOutcome::Blocked {
                reason: "worktree-limit",
                ..
            }
        ));
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn invalid_limits_block_before_child_execution() {
        let mut invalid = limits();
        invalid.child_open_files = 2;
        assert!(invalid
            .validate()
            .unwrap_err()
            .contains("resource-limit-invalid"));
        assert!(limited_exec(0, 1, 3, 1, &["/bin/true".into()])
            .unwrap_err()
            .contains("resource-limit-invalid"));
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn macos_parent_observer_rejects_malformed_output_and_native_nproc_is_optional() {
        assert!(parse_ps_group_members(b"not-a-record\n", Pid::from_raw(1)).is_err());
        assert!(install_process_limit(1).is_ok());
    }
}
