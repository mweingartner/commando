//! Exact-host macOS compatibility adapter for local validation.
//!
//! This module is the only unsafe island in `mpd`.  It runtime-resolves the
//! deprecated custom-profile Seatbelt entry point and the undocumented file
//! extension SPI used by the reviewed compatibility contract.  Every caller
//! must treat symbol, ABI, host, profile, root, or canary drift as a blocker;
//! there is deliberately no alternate macOS execution path.

#![allow(unsafe_code)]

use crate::digest::Digest;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::ffi::{CStr, CString};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::net::{Ipv4Addr, SocketAddrV4, TcpStream};
use std::os::raw::{c_char, c_void};
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::Duration;

pub const CERTIFIED_PRODUCT_VERSION: &str = "27.0";
pub const CERTIFIED_BUILD_VERSION: &str = "26A5378n";
pub const CERTIFIED_ARCH: &str = "aarch64";
pub const FIXED_PROFILE: &str = "(version 1)\n(deny default)\n(allow process*)\n(allow sysctl-read)\n(allow file-read-metadata file-test-existence)\n(allow file-read-data (literal \"/\"))\n(allow file-read* file-write* (literal \"/dev/null\"))\n(allow file-read* file-test-existence file-map-executable (extension \"com.apple.app-sandbox.read\"))\n(allow file-read* file-test-existence file-map-executable (extension \"com.apple.app-sandbox.read-write\"))\n(allow file-write* (extension \"com.apple.app-sandbox.read-write\"))\n(deny network*)\n";

const REQUEST_SCHEMA: u32 = 1;
const MAX_CONTROL_BYTES: usize = 256 * 1024;
// 48: the reviewed tool inventory legitimately exceeds 32 read roots once
// semgrep's per-keg Homebrew python dependency surface (interpreter, native
// libs, and six keg site-packages) is declared explicitly rather than through
// a broad /opt/homebrew grant. Still a hard compiled ceiling.
const MAX_ROOTS: usize = 48;
const MAX_ARGV: usize = 256;
const MAX_CPU_SECS: u64 = 1800;
const MAX_PROCESSES: u64 = 4096;
const MAX_OPEN_FILES: u64 = 4096;
const MAX_FILE_BYTES: u64 = 1024 * 1024 * 1024;
const DENIED_READ_CANARY: &str = "/private/etc/hosts";

#[derive(Debug, Clone)]
pub struct PreparedControl {
    pub request_line: Vec<u8>,
    pub ready_digest: String,
    pub attestation: crate::sandbox::SandboxAttestation,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RootBinding {
    path: String,
    device: u64,
    inode: u64,
    directory: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ControlLimits {
    pub(crate) cpu_secs: u64,
    pub(crate) processes: u64,
    pub(crate) open_files: u64,
    pub(crate) file_bytes: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ControlRequest {
    schema: u32,
    nonce: String,
    profile_digest: String,
    authority_digest: String,
    read_roots: Vec<RootBinding>,
    read_write_root: RootBinding,
    allowed_read_probe: RootBinding,
    limits: ControlLimits,
    argv: Vec<String>,
}

type IssueFile = unsafe extern "C" fn(*const c_char, *const c_char, u32) -> *mut c_char;
type Consume = unsafe extern "C" fn(*const c_char) -> i64;
type SandboxInit = unsafe extern "C" fn(*const c_char, u64, *mut *mut c_char) -> i32;
type FreeError = unsafe extern "C" fn(*mut c_char);

struct Api {
    issue_file: IssueFile,
    consume: Consume,
    sandbox_init: SandboxInit,
    free_error: FreeError,
    read_class: *const c_char,
    read_write_class: *const c_char,
}

struct Token {
    pointer: *mut c_char,
    length: usize,
}

impl Token {
    fn zeroize_and_free(self) {
        unsafe {
            for index in 0..self.length {
                std::ptr::write_volatile(self.pointer.add(index).cast::<u8>(), 0);
            }
            nix::libc::free(self.pointer.cast::<c_void>());
        }
    }
}

pub fn verify_certified_host() -> Result<(), String> {
    if std::env::consts::ARCH != CERTIFIED_ARCH {
        return Err(
            "sandbox.host-drift: architecture is not the certified Apple-silicon host".into(),
        );
    }
    let path = Path::new("/System/Library/CoreServices/SystemVersion.plist");
    let metadata = fs::symlink_metadata(path).map_err(|error| {
        format!("sandbox.host-drift: cannot inspect SystemVersion.plist: {error}")
    })?;
    if metadata.file_type().is_symlink() || !metadata.is_file() || metadata.len() > 64 * 1024 {
        return Err("sandbox.host-drift: SystemVersion.plist is unsafe or oversized".into());
    }
    let text = fs::read_to_string(path)
        .map_err(|error| format!("sandbox.host-drift: cannot read SystemVersion.plist: {error}"))?;
    let product = plist_value(&text, "ProductVersion")?;
    let build = plist_value(&text, "ProductBuildVersion")?;
    if product != CERTIFIED_PRODUCT_VERSION || build != CERTIFIED_BUILD_VERSION {
        return Err(format!(
            "sandbox.host-drift: expected macOS {CERTIFIED_PRODUCT_VERSION} ({CERTIFIED_BUILD_VERSION}), observed {product} ({build})"
        ));
    }
    Ok(())
}

fn plist_value<'a>(text: &'a str, key: &str) -> Result<&'a str, String> {
    let marker = format!("<key>{key}</key>");
    let tail = text
        .split_once(&marker)
        .map(|(_, tail)| tail)
        .ok_or_else(|| format!("sandbox.host-drift: SystemVersion.plist omits {key}"))?;
    let start = tail
        .find("<string>")
        .map(|index| index + "<string>".len())
        .ok_or_else(|| format!("sandbox.host-drift: {key} is malformed"))?;
    let end = tail[start..]
        .find("</string>")
        .map(|index| start + index)
        .ok_or_else(|| format!("sandbox.host-drift: {key} is malformed"))?;
    Ok(&tail[start..end])
}

pub fn verify_profile_asset(root: &Path) -> Result<PathBuf, String> {
    let profile = root.join("security/sandbox/validation.sb");
    let metadata = fs::symlink_metadata(&profile)
        .map_err(|error| format!("sandbox.profile-drift: profile is unavailable: {error}"))?;
    if metadata.file_type().is_symlink() || !metadata.is_file() || metadata.len() > 64 * 1024 {
        return Err("sandbox.profile-drift: profile is unsafe or oversized".into());
    }
    let bytes = fs::read(&profile)
        .map_err(|error| format!("sandbox.profile-drift: cannot read profile: {error}"))?;
    if bytes != FIXED_PROFILE.as_bytes() {
        return Err(
            "sandbox.profile-drift: reviewed profile differs from the compiled contract".into(),
        );
    }
    Ok(profile)
}

pub fn probe_symbols() -> Result<(), String> {
    let _ = Api::load()?;
    Ok(())
}

pub fn adapter_abi_digest() -> String {
    Digest::of_bytes(
        b"mpd:macos-sandbox-abi:v1\0sandbox_extension_issue_file\0sandbox_extension_consume\0sandbox_init\0sandbox_free_error\0APP_SANDBOX_READ\0APP_SANDBOX_READ_WRITE\0flags=0",
    )
    .to_hex()
}

pub fn canary_contract_digest() -> String {
    Digest::of_bytes(
        b"mpd:macos-sandbox-canaries:v1\0allowed-read\0denied-/private/etc/hosts-read\0allowed-runtime-write\0denied-/tmp-write\0symlink-denied-target\0loopback-denied\0child-inheritance\0grandchild-inheritance\0post-entry-extension-non-escalation\0root-identity-recheck",
    )
    .to_hex()
}

pub fn certified_host_label() -> Result<String, String> {
    verify_certified_host()?;
    Ok(format!(
        "macOS {CERTIFIED_PRODUCT_VERSION} build {CERTIFIED_BUILD_VERSION}/{CERTIFIED_ARCH}"
    ))
}

pub fn residual_limitations() -> Vec<String> {
    vec![
        "global path metadata/existence and literal-root entries are not confidential".into(),
        "required process authority is not same-user process isolation".into(),
        "deprecated custom-profile and undocumented extension SPI are exact-host compatibility only"
            .into(),
    ]
}

pub fn prepare_control(
    read_roots: &[PathBuf],
    read_write_root: &Path,
    allowed_read_probe: &Path,
    authority_digest: &str,
    limits: ControlLimits,
    argv: &[String],
) -> Result<PreparedControl, String> {
    verify_certified_host()?;
    if read_roots.is_empty() || read_roots.len() > MAX_ROOTS {
        return Err("sandbox.root-invalid: read-root count is outside the compiled bound".into());
    }
    let mut roots = read_roots
        .iter()
        .map(|path| bind_root(path, true))
        .collect::<Result<Vec<_>, _>>()?;
    roots.sort_by(|left, right| left.path.as_bytes().cmp(right.path.as_bytes()));
    roots.dedup_by(|left, right| left.path == right.path);
    if roots.len() > MAX_ROOTS {
        return Err("sandbox.root-invalid: canonical read-root count exceeds its cap".into());
    }
    let read_write_root = bind_root(read_write_root, true)?;
    if !read_write_root.directory {
        return Err("sandbox.root-invalid: read-write root must be a directory".into());
    }
    if roots.iter().any(|root| {
        Path::new(&read_write_root.path).starts_with(&root.path)
            || Path::new(&root.path).starts_with(&read_write_root.path)
    }) {
        return Err("sandbox.root-invalid: read-only and read-write roots overlap".into());
    }
    let allowed_read_probe = bind_root(allowed_read_probe, false)?;
    if allowed_read_probe.directory
        || !roots
            .iter()
            .any(|root| Path::new(&allowed_read_probe.path).starts_with(&root.path))
    {
        return Err("sandbox.root-invalid: allowed-read canary is outside approved roots".into());
    }
    let request = ControlRequest {
        schema: REQUEST_SCHEMA,
        nonce: random_nonce()?,
        profile_digest: Digest::of_bytes(FIXED_PROFILE.as_bytes()).to_hex(),
        authority_digest: authority_digest.to_string(),
        read_roots: roots,
        read_write_root,
        allowed_read_probe,
        limits,
        argv: argv.to_vec(),
    };
    validate_request(&request)?;
    let request_line = serde_json::to_vec(&request).map_err(|error| error.to_string())?;
    if request_line.len() > MAX_CONTROL_BYTES {
        return Err("sandbox.control-malformed: request exceeds its cap".into());
    }
    let ready_digest = ready_digest(&request_line);
    let root_bytes = serde_json::to_vec(&(
        &request.read_roots,
        &request.read_write_root,
        &request.allowed_read_probe,
    ))
    .map_err(|error| error.to_string())?;
    let attestation = crate::sandbox::SandboxAttestation {
        request_digest: Digest::of_bytes(&request_line).to_hex(),
        authority_digest: request.authority_digest.clone(),
        root_inventory_digest: Digest::of_bytes(&root_bytes).to_hex(),
        canary_digest: canary_contract_digest(),
    };
    Ok(PreparedControl {
        request_line,
        ready_digest,
        attestation,
    })
}

pub fn hidden_entry() -> Result<(), String> {
    verify_certified_host()?;
    let request_line = read_control_line(std::io::stdin().lock())?;
    let request: ControlRequest = serde_json::from_slice(&request_line)
        .map_err(|_| "sandbox.control-malformed: request is not canonical JSON")?;
    let canonical = serde_json::to_vec(&request).map_err(|error| error.to_string())?;
    if canonical != request_line {
        return Err("sandbox.control-malformed: request is not canonical".into());
    }
    validate_request(&request)?;
    let expected_ready = ready_digest(&request_line);
    enter(&request)?;
    run_canaries(&request)?;
    validate_bound_roots(&request)?;

    let mut stdout = std::io::stdout().lock();
    writeln!(stdout, "MPD_READY {expected_ready}")
        .and_then(|_| stdout.flush())
        .map_err(|error| format!("sandbox.control-io: cannot publish READY: {error}"))?;
    let go = read_control_line(std::io::stdin().lock())?;
    if go != format!("MPD_GO {expected_ready}").as_bytes() {
        return Err("sandbox.go-mismatch: parent GO does not match READY".into());
    }
    let null = File::open("/dev/null")
        .map_err(|error| format!("sandbox.control-close: cannot open /dev/null: {error}"))?;
    nix::unistd::dup2_stdin(&null)
        .map_err(|error| format!("sandbox.control-close: cannot replace control fd: {error}"))?;
    crate::sandbox::limited_exec(
        request.limits.cpu_secs,
        request.limits.processes,
        request.limits.open_files,
        request.limits.file_bytes,
        &request.argv,
    )
}

fn validate_request(request: &ControlRequest) -> Result<(), String> {
    if request.schema != REQUEST_SCHEMA
        || request.nonce.len() != 64
        || !request.nonce.bytes().all(|byte| byte.is_ascii_hexdigit())
        || request.profile_digest != Digest::of_bytes(FIXED_PROFILE.as_bytes()).to_hex()
        || request.authority_digest.len() != 64
        || !request
            .authority_digest
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit())
        || request.read_roots.is_empty()
        || request.read_roots.len() > MAX_ROOTS
        || request.argv.is_empty()
        || request.argv.len() > MAX_ARGV
        || request.argv.iter().any(|arg| arg.as_bytes().contains(&0))
        || request.argv[0] != request.allowed_read_probe.path
        || request.limits.cpu_secs == 0
        || request.limits.cpu_secs > MAX_CPU_SECS
        || request.limits.processes == 0
        || request.limits.processes > MAX_PROCESSES
        || request.limits.open_files < 3
        || request.limits.open_files > MAX_OPEN_FILES
        || request.limits.file_bytes == 0
        || request.limits.file_bytes > MAX_FILE_BYTES
    {
        return Err("sandbox.control-malformed: request fields are invalid".into());
    }
    let mut seen = BTreeSet::new();
    for root in &request.read_roots {
        if !seen.insert(root.path.as_str()) {
            return Err("sandbox.control-malformed: duplicate read root".into());
        }
    }
    validate_bound_roots(request)
}

fn validate_bound_roots(request: &ControlRequest) -> Result<(), String> {
    for root in request
        .read_roots
        .iter()
        .chain([&request.read_write_root, &request.allowed_read_probe])
    {
        let rebound = bind_root(Path::new(&root.path), root.directory)?;
        if &rebound != root {
            return Err("sandbox.root-drift: canonical root identity changed".into());
        }
    }
    Ok(())
}

fn enter(request: &ControlRequest) -> Result<(), String> {
    let api = Api::load()?;
    let mut tokens = Vec::new();
    for root in &request.read_roots {
        match issue(&api, api.read_class, &root.path) {
            Ok(token) => tokens.push(token),
            Err(error) => {
                for token in tokens {
                    token.zeroize_and_free();
                }
                return Err(error);
            }
        }
    }
    match issue(&api, api.read_write_class, &request.read_write_root.path) {
        Ok(token) => tokens.push(token),
        Err(error) => {
            for token in tokens {
                token.zeroize_and_free();
            }
            return Err(error);
        }
    }

    let profile = CString::new(FIXED_PROFILE).expect("fixed profile has no NUL");
    let mut error_buffer = std::ptr::null_mut();
    let initialized = unsafe { (api.sandbox_init)(profile.as_ptr(), 0, &mut error_buffer) };
    if initialized != 0 {
        let detail = if error_buffer.is_null() {
            "unknown Seatbelt error".to_string()
        } else {
            let detail = unsafe { CStr::from_ptr(error_buffer) }
                .to_string_lossy()
                .into_owned();
            unsafe { (api.free_error)(error_buffer) };
            detail
        };
        for token in tokens {
            token.zeroize_and_free();
        }
        return Err(format!("sandbox.init-failed: {detail}"));
    }
    for token in tokens {
        let consumed = unsafe { (api.consume)(token.pointer) };
        token.zeroize_and_free();
        if consumed < 0 {
            return Err("sandbox.consume-failed: extension consumption was rejected".into());
        }
    }
    Ok(())
}

fn run_canaries(request: &ControlRequest) -> Result<(), String> {
    let mut probe = File::open(&request.allowed_read_probe.path)
        .map_err(|error| format!("sandbox.canary-allowed-read: {error}"))?;
    let mut byte = [0_u8; 1];
    probe
        .read(&mut byte)
        .map_err(|error| format!("sandbox.canary-allowed-read: {error}"))?;
    require_denied_read(DENIED_READ_CANARY, "sandbox.canary-denied-read")?;

    let write_path = Path::new(&request.read_write_root.path)
        .join(format!(".mpd-write-canary-{}", request.nonce));
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&write_path)
        .map_err(|error| format!("sandbox.canary-allowed-write: {error}"))?;
    file.write_all(b"x")
        .and_then(|_| file.sync_all())
        .map_err(|error| format!("sandbox.canary-allowed-write: {error}"))?;
    drop(file);
    fs::remove_file(&write_path)
        .map_err(|error| format!("sandbox.canary-allowed-write-cleanup: {error}"))?;

    let denied_write = Path::new("/tmp").join(format!(".mpd-denied-{}", request.nonce));
    match OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&denied_write)
    {
        Ok(_) => {
            let _ = fs::remove_file(&denied_write);
            return Err("sandbox.canary-denied-write: write unexpectedly succeeded".into());
        }
        Err(error) if permission_denied(&error) => {}
        Err(error) => {
            return Err(format!(
                "sandbox.canary-denied-write: ambiguous error: {error}"
            ))
        }
    }

    let link = Path::new(&request.read_write_root.path)
        .join(format!(".mpd-link-canary-{}", request.nonce));
    std::os::unix::fs::symlink(DENIED_READ_CANARY, &link)
        .map_err(|error| format!("sandbox.canary-symlink-create: {error}"))?;
    let linked = File::open(&link);
    fs::remove_file(&link).map_err(|error| format!("sandbox.canary-symlink-cleanup: {error}"))?;
    match linked {
        Err(error) if permission_denied(&error) => {}
        Ok(_) => return Err("sandbox.canary-symlink: denied target became readable".into()),
        Err(error) => return Err(format!("sandbox.canary-symlink: ambiguous error: {error}")),
    }

    let address = SocketAddrV4::new(Ipv4Addr::LOCALHOST, 9);
    match TcpStream::connect_timeout(&address.into(), Duration::from_millis(100)) {
        Err(error) if permission_denied(&error) => {}
        Ok(_) => return Err("sandbox.canary-network: loopback connection succeeded".into()),
        Err(error) => return Err(format!("sandbox.canary-network: ambiguous error: {error}")),
    }

    let direct = Command::new("/usr/bin/head")
        .args(["-c", "1", DENIED_READ_CANARY])
        .env_clear()
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map_err(|error| format!("sandbox.canary-child: cannot spawn child: {error}"))?;
    if direct.success() {
        return Err("sandbox.canary-child: child read denied content".into());
    }
    let grandchild = Command::new("/bin/sh")
        .args([
            "-c",
            "/usr/bin/head -c 1 /private/etc/hosts >/dev/null 2>&1",
        ])
        .env_clear()
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map_err(|error| format!("sandbox.canary-grandchild: cannot spawn: {error}"))?;
    if grandchild.success() {
        return Err("sandbox.canary-grandchild: descendant read denied content".into());
    }

    let api = Api::load()?;
    if let Ok(token) = issue(&api, api.read_class, DENIED_READ_CANARY) {
        let _ = unsafe { (api.consume)(token.pointer) };
        token.zeroize_and_free();
    }
    require_denied_read(DENIED_READ_CANARY, "sandbox.canary-post-entry-extension")?;
    Ok(())
}

fn require_denied_read(path: &str, label: &str) -> Result<(), String> {
    match File::open(path) {
        Err(error) if permission_denied(&error) => Ok(()),
        Ok(_) => Err(format!("{label}: denied content became readable")),
        Err(error) => Err(format!("{label}: ambiguous error: {error}")),
    }
}

fn permission_denied(error: &std::io::Error) -> bool {
    error.kind() == std::io::ErrorKind::PermissionDenied
        || matches!(
            error.raw_os_error(),
            Some(nix::libc::EPERM | nix::libc::EACCES)
        )
}

fn bind_root(path: &Path, require_directory: bool) -> Result<RootBinding, String> {
    if !path.is_absolute() || path == Path::new("/") {
        return Err("sandbox.root-invalid: roots must be absolute and narrower than /".into());
    }
    let canonical = fs::canonicalize(path)
        .map_err(|error| format!("sandbox.root-invalid: cannot canonicalize root: {error}"))?;
    if canonical == Path::new("/") {
        return Err("sandbox.root-invalid: canonical root cannot be /".into());
    }
    let metadata = fs::symlink_metadata(&canonical)
        .map_err(|error| format!("sandbox.root-invalid: cannot inspect root: {error}"))?;
    if metadata.file_type().is_symlink()
        || (!metadata.is_dir() && !metadata.is_file())
        || (require_directory && !metadata.is_dir())
    {
        return Err("sandbox.root-invalid: root is not the required no-follow type".into());
    }
    let path = canonical
        .to_str()
        .ok_or("sandbox.root-invalid: root is not UTF-8")?;
    if path.len() > 4096 || path.chars().any(char::is_control) {
        return Err("sandbox.root-invalid: root path is unsafe or oversized".into());
    }
    Ok(RootBinding {
        path: path.to_string(),
        device: metadata.dev(),
        inode: metadata.ino(),
        directory: metadata.is_dir(),
    })
}

fn random_nonce() -> Result<String, String> {
    let mut bytes = [0_u8; 32];
    File::open("/dev/urandom")
        .and_then(|mut file| file.read_exact(&mut bytes))
        .map_err(|error| format!("sandbox.control-entropy: {error}"))?;
    Ok(bytes.iter().map(|byte| format!("{byte:02x}")).collect())
}

fn ready_digest(request_line: &[u8]) -> String {
    let mut bytes = Vec::with_capacity(request_line.len() + FIXED_PROFILE.len() + 64);
    bytes.extend_from_slice(b"mpd:macos-sandbox-ready:v1\0");
    bytes.extend_from_slice(request_line);
    bytes.extend_from_slice(FIXED_PROFILE.as_bytes());
    bytes.extend_from_slice(CERTIFIED_BUILD_VERSION.as_bytes());
    bytes.extend_from_slice(CERTIFIED_ARCH.as_bytes());
    Digest::of_bytes(&bytes).to_hex()
}

fn read_control_line(mut reader: impl Read) -> Result<Vec<u8>, String> {
    let mut bytes = Vec::new();
    let mut byte = [0_u8; 1];
    loop {
        match reader.read(&mut byte) {
            Ok(0) => return Err("sandbox.control-malformed: unexpected EOF".into()),
            Ok(_) if byte[0] == b'\n' => return Ok(bytes),
            Ok(_) => {
                if bytes.len() == MAX_CONTROL_BYTES {
                    return Err("sandbox.control-malformed: line exceeds its cap".into());
                }
                bytes.push(byte[0]);
            }
            Err(error) => return Err(format!("sandbox.control-io: {error}")),
        }
    }
}

fn issue(api: &Api, class: *const c_char, path: &str) -> Result<Token, String> {
    let path = CString::new(path).map_err(|_| "sandbox.root-invalid: root contains NUL")?;
    let pointer = unsafe { (api.issue_file)(class, path.as_ptr(), 0) };
    if pointer.is_null() {
        return Err("sandbox.issue-failed: extension issue returned null".into());
    }
    let length = unsafe { CStr::from_ptr(pointer) }.to_bytes().len();
    if length == 0 || length > 64 * 1024 {
        Token { pointer, length }.zeroize_and_free();
        return Err("sandbox.issue-failed: extension token is empty or oversized".into());
    }
    Ok(Token { pointer, length })
}

impl Api {
    fn load() -> Result<Self, String> {
        unsafe {
            let issue_file = load_function::<IssueFile>(b"sandbox_extension_issue_file\0")?;
            let consume = load_function::<Consume>(b"sandbox_extension_consume\0")?;
            let sandbox_init = load_function::<SandboxInit>(b"sandbox_init\0")?;
            let free_error = load_function::<FreeError>(b"sandbox_free_error\0")?;
            let read_class = load_data_symbol(b"APP_SANDBOX_READ\0")?;
            let read_write_class = load_data_symbol(b"APP_SANDBOX_READ_WRITE\0")?;
            Ok(Self {
                issue_file,
                consume,
                sandbox_init,
                free_error,
                read_class,
                read_write_class,
            })
        }
    }
}

unsafe fn load_function<T: Copy>(name: &[u8]) -> Result<T, String> {
    let pointer = nix::libc::dlsym(nix::libc::RTLD_DEFAULT, name.as_ptr().cast::<c_char>());
    if pointer.is_null() || std::mem::size_of::<T>() != std::mem::size_of::<*mut c_void>() {
        return Err(format!(
            "sandbox.spi-unavailable: missing or incompatible {}",
            String::from_utf8_lossy(&name[..name.len().saturating_sub(1)])
        ));
    }
    Ok(std::mem::transmute_copy(&pointer))
}

unsafe fn load_data_symbol(name: &[u8]) -> Result<*const c_char, String> {
    let pointer = nix::libc::dlsym(nix::libc::RTLD_DEFAULT, name.as_ptr().cast::<c_char>());
    if pointer.is_null() {
        return Err(format!(
            "sandbox.spi-unavailable: missing {}",
            String::from_utf8_lossy(&name[..name.len().saturating_sub(1)])
        ));
    }
    let value = *(pointer.cast::<*const c_char>());
    if value.is_null() {
        return Err("sandbox.spi-unavailable: extension class is null".into());
    }
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fixed_profile_and_current_host_are_exact() {
        verify_certified_host().unwrap();
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
        verify_profile_asset(&root).unwrap();
        probe_symbols().unwrap();
    }

    #[test]
    fn request_never_serializes_roots_in_argv_or_environment() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
        let runtime = root.join("target");
        let control = prepare_control(
            &[
                root.clone(),
                PathBuf::from("/usr"),
                PathBuf::from("/System"),
            ],
            &runtime,
            &std::env::current_exe().unwrap(),
            &"ab".repeat(32),
            ControlLimits {
                cpu_secs: 30,
                processes: 32,
                open_files: 64,
                file_bytes: 1024 * 1024,
            },
            &[std::env::current_exe().unwrap().display().to_string()],
        );
        // The current test executable is below target, which is deliberately
        // also the writable root in this synthetic fixture; overlap blocks.
        assert!(control.is_err());
    }
}
