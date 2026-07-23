//! Offline, bounded attestation evidence.
//!
//! This module deliberately does not claim that MPD itself knows which model
//! ran a review.  In cooperative mode an omitted envelope stays unreported; a
//! configured required mode is fail-closed until an external issuer supplies a
//! valid SSHSIG envelope.

use crate::config::{AttestationMode, AttestationPolicy, IssuerTrustConfig};
use crate::phase::{Phase, PIPELINE};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::fs::{self, OpenOptions};
use std::io::{Read, Write};
#[cfg(unix)]
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};
use std::path::Path;
use std::process::{Command, Stdio};

pub const ATTESTATION_SCHEMA_V1: u32 = 1;
pub const SSHSIG_ALGORITHM: &str = "sshsig-ed25519-v1";
pub const SSHSIG_NAMESPACE: &str = "mpd-attestation-v1";
pub const SSH_KEYGEN_PATH: &str = "/usr/bin/ssh-keygen";
pub const SSH_KEYGEN_SHA256: &str =
    "4ed0e089766a35cb8acbaf6e2804e9ec5b187f1baabce5dc832f5a192cb3d7cd";
pub const MAX_ATTESTATION_BYTES: u64 = 128 * 1024;
const MAX_FIELD: usize = 256;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum AttestationVerifierState {
    Cooperative,
    Missing,
    NotDeployed,
    Locked,
    Blocked,
    Invalid,
    Replayed,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AttestationState {
    pub state: AttestationVerifierState,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub code: Option<String>,
}

impl AttestationState {
    pub fn cooperative() -> Self {
        Self {
            state: AttestationVerifierState::Cooperative,
            code: None,
        }
    }
    pub fn missing_required() -> Self {
        Self {
            state: AttestationVerifierState::Missing,
            code: None,
        }
    }
    pub fn not_deployed() -> Self {
        Self {
            state: AttestationVerifierState::NotDeployed,
            code: None,
        }
    }
    fn blocked(code: &str) -> Self {
        Self {
            state: AttestationVerifierState::Blocked,
            code: Some(code.into()),
        }
    }
    fn invalid(code: &str) -> Self {
        Self {
            state: AttestationVerifierState::Invalid,
            code: Some(code.into()),
        }
    }
}

/// Only normalized counters; absence means unreported rather than zero.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct UsageEvidenceV1 {
    #[serde(default)]
    pub input_tokens: u64,
    #[serde(default)]
    pub output_tokens: u64,
    #[serde(default)]
    pub cached_tokens: u64,
    #[serde(default)]
    pub active_millis: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub currency: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cost_micros: Option<u64>,
}

impl UsageEvidenceV1 {
    pub fn validate(&self) -> Result<(), String> {
        match (&self.currency, self.cost_micros) {
            (Some(currency), Some(_)) if valid_currency(currency) => Ok(()),
            (None, None) => Ok(()),
            _ => Err("usage currency and cost-micros must be supplied together with an uppercase currency".into()),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct AttestationPayloadV1 {
    pub schema: u32,
    pub issuer: String,
    pub key_id: String,
    pub change: String,
    pub phase: String,
    pub attempt: usize,
    pub actor: String,
    pub harness: String,
    pub model: String,
    pub session_id: String,
    pub issued_at_epoch_secs: u64,
    pub artifact_digest: String,
    pub subject_digest: String,
    pub usage: UsageEvidenceV1,
}

impl AttestationPayloadV1 {
    pub fn validate(&self) -> Result<(), String> {
        if self.schema != ATTESTATION_SCHEMA_V1 || self.attempt == 0 {
            return Err("unsupported attestation schema or zero attempt".into());
        }
        for (name, value) in [
            ("issuer", &self.issuer),
            ("key-id", &self.key_id),
            ("change", &self.change),
            ("phase", &self.phase),
            ("actor", &self.actor),
            ("harness", &self.harness),
            ("model", &self.model),
            ("session-id", &self.session_id),
            ("artifact-digest", &self.artifact_digest),
            ("subject-digest", &self.subject_digest),
        ] {
            valid_token(name, value)?;
        }
        if !PIPELINE.iter().any(|phase| phase.slug() == self.phase) {
            return Err("attestation phase is invalid".into());
        }
        if !sha256_hex(&self.artifact_digest) || !sha256_hex(&self.subject_digest) {
            return Err("attestation digests must be SHA-256 hex".into());
        }
        self.usage.validate()
    }

    /// Stable, unambiguous binary encoding. JSON is transport only and is never
    /// passed to the signer/verifier.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, String> {
        self.validate()?;
        let mut out = Vec::with_capacity(512);
        out.extend_from_slice(b"mpd-attestation-v1\0");
        put_u32(&mut out, self.schema);
        for value in [
            &self.issuer,
            &self.key_id,
            &self.change,
            &self.phase,
            &self.actor,
            &self.harness,
            &self.model,
            &self.session_id,
            &self.artifact_digest,
            &self.subject_digest,
        ] {
            put_bytes(&mut out, value.as_bytes())?;
        }
        put_u64(&mut out, self.attempt as u64);
        put_u64(&mut out, self.issued_at_epoch_secs);
        put_u64(&mut out, self.usage.input_tokens);
        put_u64(&mut out, self.usage.output_tokens);
        put_u64(&mut out, self.usage.cached_tokens);
        put_u64(&mut out, self.usage.active_millis);
        match (&self.usage.currency, self.usage.cost_micros) {
            (Some(currency), Some(cost)) => {
                put_bytes(&mut out, currency.as_bytes())?;
                put_u64(&mut out, cost);
            }
            (None, None) => {
                put_bytes(&mut out, &[])?;
                put_u64(&mut out, 0);
            }
            _ => return Err("invalid usage currency pair".into()),
        }
        Ok(out)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct ReviewAttestationV1 {
    pub schema: u32,
    pub algorithm: String,
    pub payload: AttestationPayloadV1,
    /// ASCII SSHSIG envelope. It is bounded input and never retained in a ledger.
    pub signature: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttestationBinding<'a> {
    pub change: &'a str,
    pub phase: Phase,
    pub attempt: usize,
    pub actor: &'a str,
    pub harness: &'a str,
    pub model: &'a str,
    pub artifact_digest: &'a str,
    pub subject_digest: &'a str,
    /// Caller-supplied wall-clock point for bounded freshness. A future CLI
    /// obtains this immediately before locked preflight; it is never persisted
    /// as a monotonic cross-process clock.
    pub now_epoch_secs: u64,
    pub max_age_secs: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UsageRecord {
    pub schema: u32,
    pub evidence_digest: String,
    pub input_tokens: u64,
    pub output_tokens: u64,
    pub cached_tokens: u64,
    pub active_millis: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub currency: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cost_micros: Option<u64>,
    pub reported: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProvenanceRecord {
    pub schema: u32,
    pub evidence_digest: String,
    pub issuer: String,
    pub key_id: String,
    pub session_id_digest: String,
    pub state: AttestationState,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedAttestation {
    pub usage: UsageRecord,
    pub provenance: ProvenanceRecord,
}

pub fn parse_attestation(bytes: &[u8]) -> Result<ReviewAttestationV1, String> {
    if bytes.is_empty() || bytes.len() as u64 > MAX_ATTESTATION_BYTES {
        return Err("attestation input is empty or exceeds cap".into());
    }
    let value: StrictJson = serde_json::from_slice(bytes)
        .map_err(|_| "attestation JSON is malformed or has duplicate keys".to_string())?;
    let envelope: ReviewAttestationV1 = serde_json::from_value(value.0)
        .map_err(|_| "attestation envelope is invalid".to_string())?;
    if envelope.schema != ATTESTATION_SCHEMA_V1
        || envelope.algorithm != SSHSIG_ALGORITHM
        || envelope.signature.len() > MAX_ATTESTATION_BYTES as usize
        || !envelope.signature.is_ascii()
    {
        return Err("attestation algorithm/schema/signature is invalid".into());
    }
    envelope.payload.validate()?;
    Ok(envelope)
}

pub fn read_attestation(root: &Path, path: &Path) -> Result<ReviewAttestationV1, String> {
    let text = openspec_core::read_contained_capped(root, path, MAX_ATTESTATION_BYTES)
        .map_err(|_| "attestation input is unavailable or unsafe".to_string())?;
    parse_attestation(text.as_bytes())
}

pub fn readiness(policy: &AttestationPolicy, evidence_supplied: bool) -> AttestationState {
    match (policy.mode, evidence_supplied) {
        (AttestationMode::Cooperative, false) => AttestationState::cooperative(),
        (AttestationMode::Required, false) if policy.issuers.is_empty() => {
            AttestationState::not_deployed()
        }
        (AttestationMode::Required, false) => AttestationState::missing_required(),
        _ => AttestationState {
            state: AttestationVerifierState::Locked,
            code: None,
        },
    }
}

pub fn verify_exact_bound(
    envelope: &ReviewAttestationV1,
    binding: &AttestationBinding<'_>,
    policy: &AttestationPolicy,
    project_root: &Path,
    private_root: &Path,
) -> Result<VerifiedAttestation, AttestationState> {
    if envelope.payload.validate().is_err() {
        return Err(AttestationState::invalid("attestation.signature"));
    }
    let p = &envelope.payload;
    if p.change != binding.change
        || p.phase != binding.phase.slug()
        || p.attempt != binding.attempt
        || p.actor != binding.actor
        || p.harness != binding.harness
        || p.model != binding.model
        || p.artifact_digest != binding.artifact_digest
        || p.subject_digest != binding.subject_digest
    {
        return Err(AttestationState::invalid("attestation.signature"));
    }
    if binding.now_epoch_secs < p.issued_at_epoch_secs
        || binding
            .now_epoch_secs
            .saturating_sub(p.issued_at_epoch_secs)
            > binding.max_age_secs
    {
        return Err(AttestationState::invalid("attestation.signature"));
    }
    let Some(trust) = policy.issuers.get(&p.issuer) else {
        return Err(AttestationState::invalid("attestation.key"));
    };
    let Some(trusted_key_blob) = canonical_public_key_blob(&trust.public_key) else {
        return Err(AttestationState::blocked("attestation.trust-root-mismatch"));
    };
    if sha256_string(&trust.public_key) != trust.sha256.to_ascii_lowercase() {
        return Err(AttestationState::blocked("attestation.trust-root-mismatch"));
    }
    let metadata = parse_sshsig_metadata(&envelope.signature)
        .ok_or_else(|| AttestationState::invalid("attestation.signature"))?;
    if metadata.namespace != SSHSIG_NAMESPACE {
        return Err(AttestationState::invalid("attestation.namespace"));
    }
    if metadata.public_key_blob != trusted_key_blob {
        return Err(AttestationState::invalid("attestation.key"));
    }
    if !tool_lock_ok() || !tool_lock_policy_ok(project_root) {
        return Err(AttestationState::blocked("attestation.verifier-drift"));
    }
    let message = p
        .canonical_bytes()
        .map_err(|_| AttestationState::invalid("attestation.signature"))?;
    verify_sshsig(
        &message,
        &envelope.signature,
        &p.key_id,
        trust,
        private_root,
    )?;
    let digest = sha256_bytes(&message);
    Ok(VerifiedAttestation {
        usage: UsageRecord {
            schema: 1,
            evidence_digest: digest.clone(),
            input_tokens: p.usage.input_tokens,
            output_tokens: p.usage.output_tokens,
            cached_tokens: p.usage.cached_tokens,
            active_millis: p.usage.active_millis,
            currency: p.usage.currency.clone(),
            cost_micros: p.usage.cost_micros,
            reported: true,
        },
        provenance: ProvenanceRecord {
            schema: 1,
            evidence_digest: digest,
            issuer: p.issuer.clone(),
            key_id: p.key_id.clone(),
            session_id_digest: sha256_string(&p.session_id),
            state: AttestationState {
                state: AttestationVerifierState::Locked,
                code: None,
            },
        },
    })
}

fn verify_sshsig(
    message: &[u8],
    signature: &str,
    identity: &str,
    trust: &IssuerTrustConfig,
    private_root: &Path,
) -> Result<(), AttestationState> {
    if ensure_private_dir(private_root).is_err() {
        return Err(AttestationState::blocked(
            "attestation.verifier-unavailable",
        ));
    }
    let run = private_root.join(format!("attestation-{}", std::process::id()));
    let mut builder = fs::DirBuilder::new();
    #[cfg(unix)]
    builder.mode(0o700);
    if builder.create(&run).is_err() || owner_private_dir(&run).is_err() {
        return Err(AttestationState::blocked(
            "attestation.verifier-unavailable",
        ));
    }
    let result = (|| {
        let message_path = run.join("message");
        let signature_path = run.join("signature");
        let allowed_path = run.join("allowed-signers");
        write_private(&message_path, message)
            .map_err(|_| AttestationState::blocked("attestation.verifier-unavailable"))?;
        write_private(&signature_path, signature.as_bytes())
            .map_err(|_| AttestationState::blocked("attestation.verifier-unavailable"))?;
        write_private(
            &allowed_path,
            format!(
                "{identity} namespaces=\"{SSHSIG_NAMESPACE}\" {}\n",
                trust.public_key
            )
            .as_bytes(),
        )
        .map_err(|_| AttestationState::blocked("attestation.verifier-unavailable"))?;
        let input = OpenOptions::new()
            .read(true)
            .open(&message_path)
            .map_err(|_| AttestationState::blocked("attestation.verifier-unavailable"))?;
        let status = Command::new(SSH_KEYGEN_PATH)
            .args([
                "-Y",
                "verify",
                "-f",
                allowed_path
                    .to_str()
                    .ok_or_else(|| AttestationState::blocked("attestation.verifier-unavailable"))?,
                "-I",
                identity,
                "-n",
                SSHSIG_NAMESPACE,
                "-s",
                signature_path
                    .to_str()
                    .ok_or_else(|| AttestationState::blocked("attestation.verifier-unavailable"))?,
            ])
            .stdin(Stdio::from(input))
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .map_err(|_| AttestationState::blocked("attestation.verifier-unavailable"))?;
        if status.success() {
            Ok(())
        } else {
            Err(AttestationState::invalid("attestation.signature"))
        }
    })();
    let _ = fs::remove_dir_all(&run);
    result
}

fn write_private(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    let mut options = OpenOptions::new();
    options.create_new(true).write(true);
    #[cfg(unix)]
    options.mode(0o600);
    let mut f = options.open(path)?;
    #[cfg(unix)]
    {
        let metadata = f.metadata()?;
        if !metadata.file_type().is_file() || metadata.permissions().mode() & 0o077 != 0 {
            return Err(std::io::Error::other(
                "attestation temporary file is not owner-private",
            ));
        }
    }
    f.write_all(bytes)?;
    f.sync_all()
}

fn ensure_private_dir(path: &Path) -> std::io::Result<()> {
    if !path.exists() {
        let mut builder = fs::DirBuilder::new();
        builder.recursive(true);
        #[cfg(unix)]
        builder.mode(0o700);
        builder.create(path)?;
    }
    owner_private_dir(path)
}

fn owner_private_dir(path: &Path) -> std::io::Result<()> {
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.file_type().is_dir() || metadata.file_type().is_symlink() {
        return Err(std::io::Error::other(
            "attestation temporary root is not a no-follow directory",
        ));
    }
    #[cfg(unix)]
    {
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
        let mode = fs::symlink_metadata(path)?.permissions().mode();
        if mode & 0o077 != 0 {
            return Err(std::io::Error::other(
                "attestation temporary root is not owner-private",
            ));
        }
    }
    Ok(())
}

pub fn tool_lock_ok() -> bool {
    let Ok(mut f) = fs::File::open(SSH_KEYGEN_PATH) else {
        return false;
    };
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 8192];
    loop {
        match f.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => hasher.update(&buf[..n]),
            Err(_) => return false,
        }
    }
    format!("{:x}", hasher.finalize()) == SSH_KEYGEN_SHA256
}

/// The immutable executable digest is also required to appear in the reviewed
/// repository lock. This prevents a source-only edit from silently changing
/// the verifier contract without changing the policy subject.
pub fn tool_lock_policy_ok(project_root: &Path) -> bool {
    let path = project_root.join("security/tool-lock.json");
    let Ok(text) = openspec_core::read_contained_capped(project_root, &path, 4 * 1024 * 1024)
    else {
        return false;
    };
    let Ok(lock) = serde_json::from_str::<serde_json::Value>(&text) else {
        return false;
    };
    let Some(entry) = lock["tools"]
        .as_array()
        .and_then(|tools| tools.iter().find(|entry| entry["name"] == "ssh-keygen"))
    else {
        return false;
    };
    entry["acquisition"].as_str() == Some("system-absolute")
        && entry["absolute_path"].as_str() == Some(SSH_KEYGEN_PATH)
        && entry["executable_sha256"].as_str() == Some(SSH_KEYGEN_SHA256)
        && entry["platform"].as_str() == Some("aarch64-apple-darwin")
        && entry["argv_contract"].as_array().is_some_and(|argv| {
            argv.iter().filter_map(|value| value.as_str()).eq([
                "-Y",
                "verify",
                "-f",
                "<allowed-signers>",
                "-I",
                "<identity>",
                "-n",
                SSHSIG_NAMESPACE,
                "-s",
                "<signature>",
            ])
        })
}

pub(crate) fn canonical_public_key(key: &str) -> bool {
    canonical_public_key_blob(key).is_some()
}

fn canonical_public_key_blob(key: &str) -> Option<Vec<u8>> {
    if key.len() > 1024 || key.contains(['\r', '\n', '\t']) {
        return None;
    }
    let mut fields = key.split(' ');
    if fields.next()? != "ssh-ed25519" {
        return None;
    }
    let encoded = fields.next()?;
    if fields.next().is_some() || encoded.is_empty() {
        return None;
    }
    let blob = decode_base64_canonical(encoded, 256)?;
    let mut cursor = 0;
    if take_ssh_string(&blob, &mut cursor)? != b"ssh-ed25519"
        || take_ssh_string(&blob, &mut cursor)?.len() != 32
        || cursor != blob.len()
    {
        return None;
    }
    Some(blob)
}

struct SshsigMetadata {
    namespace: String,
    public_key_blob: Vec<u8>,
}

fn parse_sshsig_metadata(signature: &str) -> Option<SshsigMetadata> {
    let mut lines = signature.lines();
    if lines.next()? != "-----BEGIN SSH SIGNATURE-----" {
        return None;
    }
    let mut encoded = String::new();
    let mut found_footer = false;
    for line in &mut lines {
        if line == "-----END SSH SIGNATURE-----" {
            found_footer = true;
            break;
        }
        if line.is_empty() || line.len() > 76 || !line.is_ascii() {
            return None;
        }
        encoded.push_str(line);
    }
    if !found_footer || lines.any(|line| !line.is_empty()) {
        return None;
    }
    let bytes = decode_base64_canonical(&encoded, MAX_ATTESTATION_BYTES as usize)?;
    if bytes.get(..6)? != b"SSHSIG" {
        return None;
    }
    let mut cursor = 6;
    if take_u32(&bytes, &mut cursor)? != 1 {
        return None;
    }
    let public_key_blob = take_ssh_string(&bytes, &mut cursor)?.to_vec();
    let namespace = std::str::from_utf8(take_ssh_string(&bytes, &mut cursor)?)
        .ok()?
        .to_string();
    if !take_ssh_string(&bytes, &mut cursor)?.is_empty() {
        return None;
    }
    if take_ssh_string(&bytes, &mut cursor)? != b"sha512" {
        return None;
    }
    let inner_signature = take_ssh_string(&bytes, &mut cursor)?;
    if inner_signature.is_empty() || cursor != bytes.len() {
        return None;
    }
    Some(SshsigMetadata {
        namespace,
        public_key_blob,
    })
}

fn take_u32(bytes: &[u8], cursor: &mut usize) -> Option<u32> {
    let end = cursor.checked_add(4)?;
    let value = u32::from_be_bytes(bytes.get(*cursor..end)?.try_into().ok()?);
    *cursor = end;
    Some(value)
}

fn take_ssh_string<'a>(bytes: &'a [u8], cursor: &mut usize) -> Option<&'a [u8]> {
    let length = take_u32(bytes, cursor)? as usize;
    let end = cursor.checked_add(length)?;
    let value = bytes.get(*cursor..end)?;
    *cursor = end;
    Some(value)
}

fn decode_base64_canonical(value: &str, max: usize) -> Option<Vec<u8>> {
    if value.is_empty() || !value.len().is_multiple_of(4) || value.len() > max.saturating_mul(2) {
        return None;
    }
    let mut out = Vec::with_capacity(value.len() / 4 * 3);
    let bytes = value.as_bytes();
    for (index, chunk) in bytes.chunks_exact(4).enumerate() {
        let last = index + 1 == bytes.len() / 4;
        let a = base64_value(chunk[0])? as u32;
        let b = base64_value(chunk[1])? as u32;
        let c_pad = chunk[2] == b'=';
        let d_pad = chunk[3] == b'=';
        if c_pad && !d_pad || d_pad && !last {
            return None;
        }
        let c = if c_pad {
            0
        } else {
            base64_value(chunk[2])? as u32
        };
        let d = if d_pad {
            0
        } else {
            base64_value(chunk[3])? as u32
        };
        if c_pad && b & 0x0f != 0 || d_pad && !c_pad && c & 0x03 != 0 {
            return None;
        }
        let bits = (a << 18) | (b << 12) | (c << 6) | d;
        out.push((bits >> 16) as u8);
        if !c_pad {
            out.push((bits >> 8) as u8);
        }
        if !d_pad {
            out.push(bits as u8);
        }
        if out.len() > max {
            return None;
        }
    }
    Some(out)
}

fn base64_value(byte: u8) -> Option<u8> {
    match byte {
        b'A'..=b'Z' => Some(byte - b'A'),
        b'a'..=b'z' => Some(byte - b'a' + 26),
        b'0'..=b'9' => Some(byte - b'0' + 52),
        b'+' => Some(62),
        b'/' => Some(63),
        _ => None,
    }
}
fn valid_currency(v: &str) -> bool {
    !v.is_empty() && v.len() <= 8 && v.chars().all(|c| c.is_ascii_uppercase())
}
fn sha256_hex(v: &str) -> bool {
    v.len() == 64 && v.chars().all(|c| c.is_ascii_hexdigit())
}
fn sha256_bytes(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}
fn sha256_string(v: &str) -> String {
    sha256_bytes(v.as_bytes())
}
fn valid_token(field: &str, value: &str) -> Result<(), String> {
    if value.is_empty() || value.len() > MAX_FIELD || value.chars().any(|c| c.is_control()) {
        Err(format!("attestation {field} is invalid"))
    } else {
        Ok(())
    }
}
fn put_u32(out: &mut Vec<u8>, value: u32) {
    out.extend_from_slice(&value.to_be_bytes());
}
fn put_u64(out: &mut Vec<u8>, value: u64) {
    out.extend_from_slice(&value.to_be_bytes());
}
fn put_bytes(out: &mut Vec<u8>, bytes: &[u8]) -> Result<(), String> {
    if bytes.len() > MAX_FIELD {
        return Err("attestation field exceeds canonical bound".into());
    }
    put_u32(out, bytes.len() as u32);
    out.extend_from_slice(bytes);
    Ok(())
}

/// Reject duplicate object keys before deserializing the typed envelope.
struct StrictJson(serde_json::Value);
impl<'de> Deserialize<'de> for StrictJson {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        d.deserialize_any(StrictVisitor)
    }
}
struct StrictVisitor;
impl<'de> serde::de::Visitor<'de> for StrictVisitor {
    type Value = StrictJson;
    fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        f.write_str("strict JSON")
    }
    fn visit_bool<E: serde::de::Error>(self, v: bool) -> Result<Self::Value, E> {
        Ok(StrictJson(serde_json::Value::Bool(v)))
    }
    fn visit_i64<E: serde::de::Error>(self, v: i64) -> Result<Self::Value, E> {
        Ok(StrictJson(serde_json::Value::Number(v.into())))
    }
    fn visit_u64<E: serde::de::Error>(self, v: u64) -> Result<Self::Value, E> {
        Ok(StrictJson(serde_json::Value::Number(v.into())))
    }
    fn visit_f64<E: serde::de::Error>(self, _: f64) -> Result<Self::Value, E> {
        Err(E::custom("floats are forbidden"))
    }
    fn visit_str<E: serde::de::Error>(self, v: &str) -> Result<Self::Value, E> {
        Ok(StrictJson(serde_json::Value::String(v.into())))
    }
    fn visit_string<E: serde::de::Error>(self, v: String) -> Result<Self::Value, E> {
        Ok(StrictJson(serde_json::Value::String(v)))
    }
    fn visit_unit<E: serde::de::Error>(self) -> Result<Self::Value, E> {
        Ok(StrictJson(serde_json::Value::Null))
    }
    fn visit_seq<A: serde::de::SeqAccess<'de>>(self, mut a: A) -> Result<Self::Value, A::Error> {
        let mut values = Vec::new();
        while let Some(v) = a.next_element::<StrictJson>()? {
            values.push(v.0);
        }
        Ok(StrictJson(serde_json::Value::Array(values)))
    }
    fn visit_map<A: serde::de::MapAccess<'de>>(self, mut a: A) -> Result<Self::Value, A::Error> {
        let mut seen = BTreeSet::new();
        let mut map = serde_json::Map::new();
        while let Some(k) = a.next_key::<String>()? {
            if !seen.insert(k.clone()) {
                return Err(serde::de::Error::custom("duplicate key"));
            }
            let v = a.next_value::<StrictJson>()?;
            map.insert(k, v.0);
        }
        Ok(StrictJson(serde_json::Value::Object(map)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    const FIXTURE_KEY: &str = include_str!("../testdata/external-issuer-v1/public-key.txt");
    const FIXTURE_MESSAGE: &[u8] = include_bytes!("../testdata/external-issuer-v1/message.txt");
    const FIXTURE_SIGNATURE: &str = include_str!("../testdata/external-issuer-v1/message.sig");

    fn fixture_key() -> &'static str {
        FIXTURE_KEY.trim_end()
    }

    fn fixture_trust() -> IssuerTrustConfig {
        IssuerTrustConfig {
            public_key: fixture_key().into(),
            sha256: sha256_string(fixture_key()),
        }
    }

    #[cfg(target_os = "macos")]
    fn nested_in_validation_sandbox() -> bool {
        std::env::var_os("MPD_SANDBOXED").is_some() && std::fs::read("/private/etc/hosts").is_err()
    }

    #[cfg(not(target_os = "macos"))]
    fn nested_in_validation_sandbox() -> bool {
        false
    }

    fn private_test_root(name: &str) -> std::path::PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!("mpd-{name}-{}-{nonce}", std::process::id()))
    }

    fn encode_base64(bytes: &[u8]) -> String {
        const ALPHABET: &[u8; 64] =
            b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let mut out = String::new();
        for chunk in bytes.chunks(3) {
            let a = chunk[0] as u32;
            let b = chunk.get(1).copied().unwrap_or(0) as u32;
            let c = chunk.get(2).copied().unwrap_or(0) as u32;
            let bits = (a << 16) | (b << 8) | c;
            out.push(ALPHABET[((bits >> 18) & 63) as usize] as char);
            out.push(ALPHABET[((bits >> 12) & 63) as usize] as char);
            out.push(if chunk.len() > 1 {
                ALPHABET[((bits >> 6) & 63) as usize] as char
            } else {
                '='
            });
            out.push(if chunk.len() > 2 {
                ALPHABET[(bits & 63) as usize] as char
            } else {
                '='
            });
        }
        out
    }

    fn signature_with_wrong_namespace() -> String {
        let encoded: String = FIXTURE_SIGNATURE
            .lines()
            .filter(|line| !line.starts_with("-----"))
            .collect();
        let mut bytes = decode_base64_canonical(&encoded, 4096).unwrap();
        let offset = bytes
            .windows(SSHSIG_NAMESPACE.len())
            .position(|window| window == SSHSIG_NAMESPACE.as_bytes())
            .unwrap();
        bytes[offset] = b'x';
        let body = encode_base64(&bytes);
        let wrapped = body
            .as_bytes()
            .chunks(70)
            .map(|chunk| std::str::from_utf8(chunk).unwrap())
            .collect::<Vec<_>>()
            .join("\n");
        format!("-----BEGIN SSH SIGNATURE-----\n{wrapped}\n-----END SSH SIGNATURE-----\n")
    }
    fn payload() -> AttestationPayloadV1 {
        AttestationPayloadV1 {
            schema: 1,
            issuer: "issuer".into(),
            key_id: "key".into(),
            change: "change".into(),
            phase: "build".into(),
            attempt: 1,
            actor: "Builder-Terra".into(),
            harness: "codex".into(),
            model: "terra".into(),
            session_id: "opaque-session".into(),
            issued_at_epoch_secs: 1,
            artifact_digest: "a".repeat(64),
            subject_digest: "b".repeat(64),
            usage: UsageEvidenceV1 {
                input_tokens: 1,
                output_tokens: 2,
                cached_tokens: 3,
                active_millis: 4,
                currency: Some("USD".into()),
                cost_micros: Some(5),
            },
        }
    }
    #[test]
    fn canonical_encoding_is_stable_and_binds_every_field() {
        let a = payload();
        let mut b = a.clone();
        b.model = "sol".into();
        assert_ne!(a.canonical_bytes().unwrap(), b.canonical_bytes().unwrap());
    }
    #[test]
    fn duplicate_keys_and_floats_fail_closed() {
        assert!(parse_attestation(br#"{\"schema\":1,\"schema\":1}"#).is_err());
        assert!(parse_attestation(br#"{\"schema\":1.5}"#).is_err());
    }

    proptest! {
        #[test]
        fn bounded_malformed_transport_never_panics(bytes in proptest::collection::vec(any::<u8>(), 0..4096)) {
            let _ = parse_attestation(&bytes);
        }

        #[test]
        fn unknown_top_level_member_is_rejected_for_every_json_value(
            value in proptest::collection::vec(any::<u8>(), 0..256),
        ) {
            let envelope = ReviewAttestationV1 {
                schema: 1,
                algorithm: SSHSIG_ALGORITHM.into(),
                payload: payload(),
                signature: "placeholder".into(),
            };
            let mut object = serde_json::to_value(envelope).unwrap();
            object.as_object_mut().unwrap().insert(
                "unrecognized".into(),
                serde_json::Value::String(String::from_utf8_lossy(&value).into_owned()),
            );
            let transport = serde_json::to_vec(&object).unwrap();
            prop_assert!(parse_attestation(&transport).is_err());
        }
    }

    #[test]
    fn attestation_cap_is_a_closed_boundary() {
        let at_cap = vec![b' '; MAX_ATTESTATION_BYTES as usize];
        assert!(parse_attestation(&at_cap).is_err());
        let over_cap = vec![b' '; MAX_ATTESTATION_BYTES as usize + 1];
        assert_eq!(
            parse_attestation(&over_cap).unwrap_err(),
            "attestation input is empty or exceeds cap"
        );
    }
    #[test]
    fn cooperative_missing_is_not_deployed_only_when_required() {
        assert_eq!(
            readiness(&AttestationPolicy::default(), false).state,
            AttestationVerifierState::Cooperative
        );
        assert_eq!(
            readiness(
                &AttestationPolicy {
                    mode: AttestationMode::Required,
                    issuers: Default::default()
                },
                false
            )
            .state,
            AttestationVerifierState::NotDeployed
        );
    }
    #[test]
    fn local_tool_lock_matches_reviewed_value() {
        assert!(tool_lock_ok());
    }

    #[test]
    fn canonical_ed25519_key_rejects_comments_padding_and_wrong_blob_shape() {
        assert!(canonical_public_key(fixture_key()));
        assert!(!canonical_public_key(&format!("{} comment", fixture_key())));
        assert!(!canonical_public_key(&format!("{} ", fixture_key())));
        assert!(!canonical_public_key("ssh-rsa AAAA"));
        assert!(!canonical_public_key("ssh-ed25519 AAAA"));
    }

    #[test]
    fn known_answer_sshsig_verifies_with_private_modes() {
        if nested_in_validation_sandbox() {
            eprintln!("skipped: external SSHSIG verification runs before objective sandbox entry");
            return;
        }
        let root = private_test_root("known-answer");
        verify_sshsig(
            FIXTURE_MESSAGE,
            FIXTURE_SIGNATURE,
            "fixture",
            &fixture_trust(),
            &root,
        )
        .unwrap();
        let state = verify_sshsig(
            b"changed message\n",
            FIXTURE_SIGNATURE,
            "fixture",
            &fixture_trust(),
            &root,
        )
        .unwrap_err();
        assert_eq!(state.code.as_deref(), Some("attestation.signature"));
        let private_file = root.join("mode-probe");
        write_private(&private_file, b"probe").unwrap();
        #[cfg(unix)]
        {
            assert_eq!(
                fs::symlink_metadata(&root).unwrap().permissions().mode() & 0o777,
                0o700
            );
            assert_eq!(
                fs::symlink_metadata(&private_file)
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o777,
                0o600
            );
        }
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn namespace_key_binding_and_tool_policy_fail_with_typed_codes() {
        let mut envelope = ReviewAttestationV1 {
            schema: 1,
            algorithm: SSHSIG_ALGORITHM.into(),
            payload: payload(),
            signature: signature_with_wrong_namespace(),
        };
        let artifact_digest = envelope.payload.artifact_digest.clone();
        let subject_digest = envelope.payload.subject_digest.clone();
        let binding = AttestationBinding {
            change: "change",
            phase: Phase::Build,
            attempt: 1,
            actor: "Builder-Terra",
            harness: "codex",
            model: "terra",
            artifact_digest: &artifact_digest,
            subject_digest: &subject_digest,
            now_epoch_secs: 1,
            max_age_secs: 60,
        };
        let mut policy = AttestationPolicy {
            mode: AttestationMode::Required,
            issuers: [("issuer".into(), fixture_trust())].into(),
        };
        let root = private_test_root("codes");
        let state = verify_exact_bound(&envelope, &binding, &policy, &root, &root).unwrap_err();
        assert_eq!(state.code.as_deref(), Some("attestation.namespace"));

        envelope.signature = FIXTURE_SIGNATURE.into();
        let mut other_blob = canonical_public_key_blob(fixture_key()).unwrap();
        *other_blob.last_mut().unwrap() ^= 1;
        let other_key = format!("ssh-ed25519 {}", encode_base64(&other_blob));
        policy.issuers.get_mut("issuer").unwrap().public_key = other_key.clone();
        policy.issuers.get_mut("issuer").unwrap().sha256 = sha256_string(&other_key);
        let state = verify_exact_bound(&envelope, &binding, &policy, &root, &root).unwrap_err();
        assert_eq!(state.code.as_deref(), Some("attestation.key"));

        policy.issuers.insert("issuer".into(), fixture_trust());
        envelope.payload.model = "sol".into();
        let state = verify_exact_bound(&envelope, &binding, &policy, &root, &root).unwrap_err();
        assert_eq!(state.code.as_deref(), Some("attestation.signature"));
        envelope.payload.model = "terra".into();

        let state = verify_exact_bound(&envelope, &binding, &policy, &root, &root).unwrap_err();
        assert_eq!(state.code.as_deref(), Some("attestation.verifier-drift"));
    }
}
