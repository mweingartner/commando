//! Project-local mpd configuration (`.mpd/config.json`).

use crate::closure::HermeticReusePolicy;
use crate::ledger::{mpd_dir, Depth, Rigor, RiskLevel, ThreatProfile};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::str::FromStr;

/// A per-harness map of persona name → model id.
pub type ModelMap = BTreeMap<String, BTreeMap<String, String>>;

/// Per-persona behavior tuning, keyed by persona DISPLAY name (or the normalized
/// `"DocValidation"` key for the composite Doc-Validation persona) under
/// [`Config::personas`]. Strengthen-only ordinal knobs plus one audited free-text
/// escape (design.md D1). Additive + `#[serde(default)]`; an absent block is the
/// baseline.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PersonaTuning {
    /// Reasoning-rigor knob → reasoning effort + reviewer count. Lenient: a value
    /// that is not an exact known variant string degrades to `None` (see
    /// [`de_lenient_rigor`]).
    #[serde(
        default,
        deserialize_with = "de_lenient_rigor",
        skip_serializing_if = "Option::is_none"
    )]
    pub rigor: Option<Rigor>,
    /// Tester test-emphasis knob (ignored for non-Tester phases). Lenient.
    #[serde(
        default,
        deserialize_with = "de_lenient_depth",
        skip_serializing_if = "Option::is_none"
    )]
    pub depth: Option<Depth>,
    /// A non-destructive directive overlay appended AFTER the bundled directive
    /// (never replacing it). The one un-rankable knob — always recorded/flagged.
    /// Lenient like the ordinals: a non-string (hand-edited wrong type) degrades to
    /// `None` rather than failing the whole `Config` and reverting model pins
    /// (Security-code F1 — uniform per-field degradation for the persona block).
    #[serde(
        default,
        deserialize_with = "de_lenient_string",
        skip_serializing_if = "Option::is_none"
    )]
    pub directive_append: Option<String>,
}

/// Lenient `rigor` deserializer: reads a permissive `serde_json::Value` (which
/// cannot fail on any well-formed JSON node) and maps to `Some(variant)` ONLY for
/// an exact known variant string — an unknown token, a wrong TYPE (`5`, `true`,
/// `["deep"]`, `{}`), or `null` all degrade to `None` (design.md Cond 2, round-2
/// F2). A plain `Option<Rigor>` would instead FAIL the whole `Config` on a
/// wrong-type token, which `Config::load`'s `unwrap_or_default` discards wholesale
/// — silently reverting model pins.
fn de_lenient_rigor<'de, D>(d: D) -> Result<Option<Rigor>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let value = serde_json::Value::deserialize(d)?;
    Ok(value.as_str().and_then(|s| Rigor::from_str(s).ok()))
}

/// Lenient `depth` deserializer — see [`de_lenient_rigor`].
fn de_lenient_depth<'de, D>(d: D) -> Result<Option<Depth>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let value = serde_json::Value::deserialize(d)?;
    Ok(value.as_str().and_then(|s| Depth::from_str(s).ok()))
}

/// Lenient `Option<String>` deserializer: a JSON string → `Some`, anything else
/// (wrong type / null) → `None`, never `Err` (Security-code F1). Keeps a
/// hand-edited wrong-type `directive_append` from failing the whole `Config`.
fn de_lenient_string<'de, D>(d: D) -> Result<Option<String>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let value = serde_json::Value::deserialize(d)?;
    Ok(value.as_str().map(str::to_string))
}

/// Configuration read from `.mpd/config.json`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Config {
    /// Optional project defaults for newly begun changes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub governance: Option<GovernanceDefaults>,
    /// The command that runs the test suite (e.g. `cargo test`). Required for
    /// the Build/Test gates to verify a real, non-zero pass count.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub test: Option<String>,
    /// The command that deploys/installs the built product (e.g.
    /// `script/build_and_run.sh --deploy`). When set, the Deploy gate runs it
    /// and refuses PASS if it exits non-zero — deploy becomes the
    /// machine-enforced end-of-cycle default rather than a manual step. When
    /// unset, the Deploy gate only records deploy-ready evidence.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub deploy: Option<String>,
    /// Project subdirectory where the durable documentation-of-record lands at
    /// archive (default `docs`). Docs always live under the project they are for.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub docs_dir: Option<String>,
    /// Per-harness, per-persona model assignment, e.g.
    /// `models["claude-code"]["Architect"] = "fable"`. Absent entries fall back
    /// to the built-in tier default, so a partial or missing map never breaks
    /// resolution. Edit this as models evolve — no code change needed.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub models: ModelMap,
    /// Fallback model per model id, e.g. `{"fable": "opus"}` — surfaced as a note.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub model_fallbacks: BTreeMap<String, String>,
    /// Optional, explicit hermetic input declaration. Merely declaring this
    /// does not grant reuse: all declared dependencies must be captured in a
    /// receipt and match when reuse is requested.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hermetic_reuse: Option<HermeticReusePolicy>,
    /// Release-closure defaults. Kept nested so publication and evidence
    /// policy remain an explicit, reviewable namespace.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub closure: Option<ClosureConfig>,
    /// Per-persona behavior tuning, keyed by persona DISPLAY name (or
    /// `"DocValidation"`). Absent/empty ⇒ the baseline (byte-identical brief).
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub personas: BTreeMap<String, PersonaTuning>,
    /// Versioned local-only validation graph. Absent legacy configuration stays
    /// readable; enforcement reports a migration blocker instead of guessing lanes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub local_validation: Option<LocalValidationConfig>,
}

/// Data-only schema for local validation policy. Execution code validates this
/// graph before resolving a program or starting a process.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct LocalValidationConfig {
    pub schema: u32,
    pub required_toolchain: RequiredToolchainConfig,
    #[serde(default)]
    pub tools: BTreeMap<String, ToolConfig>,
    #[serde(default)]
    pub checks: BTreeMap<String, CheckConfig>,
    #[serde(default)]
    pub profiles: BTreeMap<String, ProfileConfig>,
    pub gates: GateProfiles,
    pub hooks: HookPolicyConfig,
    pub receipts: ReceiptLimits,
    pub offline: OfflinePolicyConfig,
    pub sandbox: SandboxPolicyConfig,
    pub limits: ResourceLimitsConfig,
    /// The release artifact produced by Build.  This is deliberately separate
    /// from a check argv: a check may compile, but only this named regular file
    /// is allowed to cross the Build → Deploy boundary.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub build_output: Option<BuildOutputConfig>,
    /// Optional exact-copy deployment contract.  Legacy string `deploy` remains
    /// readable, but strict artifact deployment uses this tagged data contract.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub deploy_output: Option<DeployOutputConfig>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct BuildOutputConfig {
    /// Stable policy name used to bind the Build receipt to the Deploy request.
    #[serde(default)]
    pub name: String,
    /// Repository-relative release artifact path.
    pub path: String,
    /// Maximum artifact bytes accepted by the Build → Deploy boundary.
    #[serde(default)]
    pub max_bytes: u64,
    /// Exact Unix mode expected from the release artifact (for example 0o755).
    #[serde(default)]
    pub required_mode: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "mode",
    rename_all = "kebab-case",
    rename_all_fields = "kebab-case",
    deny_unknown_fields
)]
pub enum DeployOutputConfig {
    /// Install exactly the named Build receipt through a typed copy operation,
    /// then reopen and verify the installed bytes without executing them.
    Execute {
        artifact: String,
        install: ExactCopyInstallConfig,
        installed_path: String,
        target: String,
    },
    /// A consciously non-installing Deploy mode. Its contained evidence pointer
    /// is recorded, not executed; legacy string `deploy` is still manual only.
    Readiness { evidence: String, target: String },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct ExactCopyInstallConfig {
    pub kind: ExactCopyInstallKind,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ExactCopyInstallKind {
    ExactCopy,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct ToolConfig {
    pub program: String,
    #[serde(default)]
    pub version_args: Vec<String>,
    pub requirement: ToolRequirement,
    pub install_hint: String,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ToolRequirement {
    Required,
    Optional,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct CheckConfig {
    pub kind: CheckKind,
    pub program: String,
    #[serde(default)]
    pub args: Vec<String>,
    pub timeout_secs: u64,
    pub result_policy: ResultPolicy,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub output: Option<CheckOutputConfig>,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum CheckKind {
    Format,
    Lint,
    Test,
    ReleaseBuild,
    DependencyAudit,
    SecretScan,
    Sast,
    Nonfunctional,
    SelfCheck,
    /// The doc-staleness lane (design.md D3): the mandatory non-secret-scan
    /// floor check for the opt-in `docs-build`/`docs-test` profiles.
    DocCheck,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ResultPolicy {
    ExitZero,
    RustTestCount,
    MpdDoctor,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct ProfileConfig {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub includes: Vec<String>,
    #[serde(default)]
    pub checks: Vec<String>,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct GateProfiles {
    pub build: String,
    pub security_code: String,
    pub test: String,
    pub pre_push: String,
    pub high_risk_test: String,
    /// Opt-in, proportionate lane for a proven documentation-only scope at
    /// effective Low risk (design.md D3). Additive and defaulted: an absent
    /// field parses and behaves byte-identically to today. Never wired into
    /// this repository's own `.mpd/config.json` — adopting it is a
    /// separate, high-rigor config change.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub docs_build: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub docs_security_code: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub docs_test: Option<String>,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct ReceiptLimits {
    pub log_count_cap: usize,
    pub log_byte_cap: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct RequiredToolchainConfig {
    pub rust_release: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host: Option<String>,
    pub components: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct HookPolicyConfig {
    pub path: String,
    pub require_bundled: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct OfflinePolicyConfig {
    pub cargo_lock: String,
    pub cargo_target: String,
    pub advisory_db_path: String,
    pub advisory_revision: String,
    pub advisory_tree: String,
    pub advisory_max_age_days: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct SandboxPolicyConfig {
    pub contract_version: u32,
    pub network_adapter: NetworkAdapter,
    pub environment_allowlist: EnvironmentAllowlist,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum NetworkAdapter {
    PlatformMandatory,
}

/// A deny-default set of environment keys passed to validation children. The
/// transparent codec keeps the schema's array shape while making it impossible
/// to confuse an allowlist with arbitrary environment values in Rust code.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct EnvironmentAllowlist(pub Vec<String>);

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct ResourceLimitsConfig {
    pub checks_per_profile: usize,
    pub aggregate_secs: u64,
    pub output_bytes: usize,
    pub log_bytes: usize,
    pub worktree_bytes: u64,
    pub child_processes: u64,
    pub child_open_files: u64,
    pub child_file_bytes: u64,
}

/// Optional presentation-only metadata. Argument bytes remain in `args` and in
/// receipt digests; only configured indices are replaced in human displays.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct CheckOutputConfig {
    #[serde(default)]
    pub sensitive_args: Vec<usize>,
}

pub struct SensitiveArgvDisplay<'a> {
    args: &'a [String],
    sensitive: &'a [usize],
}

impl<'a> SensitiveArgvDisplay<'a> {
    pub fn new(args: &'a [String], output: Option<&'a CheckOutputConfig>) -> Self {
        Self {
            args,
            sensitive: output.map_or(&[], |value| value.sensitive_args.as_slice()),
        }
    }
}

impl std::fmt::Display for SensitiveArgvDisplay<'_> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for (index, argument) in self.args.iter().enumerate() {
            if index > 0 {
                formatter.write_str(" ")?;
            }
            if self.sensitive.contains(&index) {
                formatter.write_str("[REDACTED]")?;
            } else {
                write!(formatter, "{argument:?}")?;
            }
        }
        Ok(())
    }
}

impl LocalValidationConfig {
    /// Validate shape and graph invariants without executing candidate policy.
    pub fn validate(&self) -> Result<(), String> {
        if self.schema != 1 {
            return Err(format!(
                "unsupported local-validation schema {}",
                self.schema
            ));
        }
        validate_release(&self.required_toolchain.rust_release)?;
        if let Some(host) = &self.required_toolchain.host {
            validate_platform_token(host, "required_toolchain.host")?;
            if host != &self.offline.cargo_target {
                return Err("offline.cargo_target must match required_toolchain.host".into());
            }
        }
        if self.required_toolchain.components.is_empty()
            || self.required_toolchain.components.len() > 16
        {
            return Err("required_toolchain.components must contain 1..=16 entries".into());
        }
        validate_unique_identifiers(
            &self.required_toolchain.components,
            "required_toolchain.components",
        )?;
        validate_repo_path(&self.hooks.path, "hooks.path")?;
        validate_repo_path(&self.offline.cargo_lock, "offline.cargo_lock")?;
        validate_repo_path(&self.offline.advisory_db_path, "offline.advisory_db_path")?;
        validate_platform_token(&self.offline.cargo_target, "offline.cargo_target")?;
        validate_oid(&self.offline.advisory_revision, "offline.advisory_revision")?;
        validate_oid(&self.offline.advisory_tree, "offline.advisory_tree")?;
        if !(1..=90).contains(&self.offline.advisory_max_age_days) {
            return Err("offline.advisory_max_age_days must be in 1..=90".into());
        }
        if self.sandbox.contract_version != 1 {
            return Err(format!(
                "unsupported sandbox contract version {}",
                self.sandbox.contract_version
            ));
        }
        validate_environment_allowlist(&self.sandbox.environment_allowlist)?;
        self.validate_limits()?;
        if self.receipts.log_count_cap == 0 || self.receipts.log_count_cap > 256 {
            return Err("receipt log_count_cap must be in 1..=256".into());
        }
        if self.receipts.log_byte_cap == 0 || self.receipts.log_byte_cap > 16 * 1024 * 1024 {
            return Err("receipt log_byte_cap must be in 1..=16777216".into());
        }
        if self.receipts.log_count_cap < self.limits.checks_per_profile
            || self.receipts.log_byte_cap < self.limits.log_bytes as u64
        {
            return Err("receipt caps must cover configured profile/log limits".into());
        }
        for (name, tool) in &self.tools {
            validate_identifier(name)?;
            validate_program(&tool.program)?;
            validate_tokens(&tool.version_args)?;
            if tool.install_hint.trim().is_empty() || tool.install_hint.len() > 512 {
                return Err(format!("tool {name:?} must have a bounded install_hint"));
            }
        }
        for component in &self.required_toolchain.components {
            if !self.tools.contains_key(component) {
                return Err(format!(
                    "required toolchain component {component:?} is not a declared tool"
                ));
            }
        }
        for (name, check) in &self.checks {
            validate_identifier(name)?;
            validate_program(&check.program)?;
            if !self.tools.contains_key(&check.program) {
                return Err(format!(
                    "check {name:?} references undeclared locked tool {:?}",
                    check.program
                ));
            }
            validate_tokens(&check.args)?;
            if !(1..=1800).contains(&check.timeout_secs) {
                return Err(format!("check {name:?} timeout_secs must be in 1..=1800"));
            }
            if let Some(output) = &check.output {
                if output
                    .sensitive_args
                    .windows(2)
                    .any(|pair| pair[0] >= pair[1])
                    || output
                        .sensitive_args
                        .iter()
                        .any(|index| *index >= check.args.len())
                {
                    return Err(format!(
                        "check {name:?} sensitive_args must be sorted, unique, and index args"
                    ));
                }
            }
        }
        for (name, profile) in &self.profiles {
            validate_identifier(name)?;
            let mut seen = std::collections::BTreeSet::new();
            for include in &profile.includes {
                validate_identifier(include)?;
                if !seen.insert(include) {
                    return Err(format!("profile {name:?} duplicates include {include:?}"));
                }
            }
            let mut seen = std::collections::BTreeSet::new();
            for check in &profile.checks {
                validate_identifier(check)?;
                if !seen.insert(check) {
                    return Err(format!("profile {name:?} duplicates check {check:?}"));
                }
                if !self.checks.contains_key(check) {
                    return Err(format!(
                        "profile {name:?} references unknown check {check:?}"
                    ));
                }
            }
        }
        for name in self.profiles.keys() {
            let effective = self.effective_checks(name)?;
            if effective.is_empty()
                || effective.len() > self.limits.checks_per_profile
                || effective.len() > 64
                || effective.len() > self.receipts.log_count_cap
            {
                return Err(format!(
                    "profile {name:?} effective checks must contain 1..={} entries and fit receipt caps",
                    self.limits.checks_per_profile.min(64)
                ));
            }
        }
        for (gate, profile) in [
            ("build", &self.gates.build),
            ("security-code", &self.gates.security_code),
            ("test", &self.gates.test),
            ("pre-push", &self.gates.pre_push),
            ("high-risk-test", &self.gates.high_risk_test),
        ] {
            validate_identifier(profile)?;
            if !self.profiles.contains_key(profile) {
                return Err(format!(
                    "gate {gate:?} references unknown profile {profile:?}"
                ));
            }
        }
        if let Some(output) = &self.build_output {
            validate_identifier(&output.name)?;
            validate_repo_path(&output.path, "build_output.path")?;
            if output.max_bytes == 0 || output.max_bytes > 8 * 1024 * 1024 * 1024 {
                return Err("build_output.max_bytes must be in 1..=8589934592".into());
            }
            if output.required_mode == 0 || output.required_mode > 0o7777 {
                return Err("build_output.required_mode must be a nonzero Unix mode".into());
            }
        }
        if let Some(deploy) = &self.deploy_output {
            match deploy {
                DeployOutputConfig::Execute {
                    artifact,
                    installed_path,
                    target,
                    ..
                } => {
                    validate_identifier(artifact)?;
                    validate_repo_path(installed_path, "deploy_output.installed_path")?;
                    validate_deploy_label(target, "deploy_output.target")?;
                    let output = self
                        .build_output
                        .as_ref()
                        .ok_or("deploy_output execute requires build_output")?;
                    if artifact != &output.name {
                        return Err("deploy_output artifact must name build_output.name".into());
                    }
                }
                DeployOutputConfig::Readiness { evidence, target } => {
                    validate_repo_path(evidence, "deploy_output.evidence")?;
                    validate_deploy_label(target, "deploy_output.target")?;
                }
            }
        }
        self.validate_required_lane_coverage()?;
        Ok(())
    }

    pub fn effective_checks(&self, profile: &str) -> Result<Vec<String>, String> {
        fn visit(
            config: &LocalValidationConfig,
            profile: &str,
            stack: &mut Vec<String>,
            expanded: &mut std::collections::BTreeSet<String>,
            seen_checks: &mut std::collections::BTreeSet<String>,
            output: &mut Vec<String>,
        ) -> Result<(), String> {
            if stack.iter().any(|entry| entry == profile) {
                stack.push(profile.to_string());
                return Err(format!(
                    "cyclic profile composition: {}",
                    stack.join(" -> ")
                ));
            }
            if expanded.contains(profile) {
                return Ok(());
            }
            let configured = config
                .profiles
                .get(profile)
                .ok_or_else(|| format!("profile references unknown profile {profile:?}"))?;
            stack.push(profile.to_string());
            for include in &configured.includes {
                visit(config, include, stack, expanded, seen_checks, output)?;
            }
            stack.pop();
            for check in &configured.checks {
                if seen_checks.insert(check.clone()) {
                    output.push(check.clone());
                }
            }
            expanded.insert(profile.to_string());
            Ok(())
        }

        validate_identifier(profile)?;
        let mut output = Vec::new();
        visit(
            self,
            profile,
            &mut Vec::new(),
            &mut std::collections::BTreeSet::new(),
            &mut std::collections::BTreeSet::new(),
            &mut output,
        )?;
        Ok(output)
    }

    fn validate_limits(&self) -> Result<(), String> {
        let limits = &self.limits;
        if limits.checks_per_profile == 0 || limits.checks_per_profile > 64 {
            return Err("limits.checks_per_profile must be in 1..=64".into());
        }
        if limits.aggregate_secs == 0 || limits.aggregate_secs > 7_200 {
            return Err("limits.aggregate_secs must be in 1..=7200".into());
        }
        if limits.output_bytes == 0 || limits.output_bytes > 16 * 1024 * 1024 {
            return Err("limits.output_bytes must be in 1..=16777216".into());
        }
        if limits.log_bytes == 0 || limits.log_bytes > 16 * 1024 * 1024 {
            return Err("limits.log_bytes must be in 1..=16777216".into());
        }
        if limits.worktree_bytes == 0 || limits.worktree_bytes > 1024 * 1024 * 1024 {
            return Err("limits.worktree_bytes must be in 1..=1073741824".into());
        }
        if limits.child_processes == 0 || limits.child_processes > 4_096 {
            return Err("limits.child_processes must be in 1..=4096".into());
        }
        if limits.child_open_files < 3 || limits.child_open_files > 4_096 {
            return Err("limits.child_open_files must be in 3..=4096".into());
        }
        if limits.child_file_bytes == 0 || limits.child_file_bytes > 1024 * 1024 * 1024 {
            return Err("limits.child_file_bytes must be in 1..=1073741824".into());
        }
        Ok(())
    }

    fn validate_required_lane_coverage(&self) -> Result<(), String> {
        use CheckKind::*;
        let requirements: [(&str, &str, &[CheckKind]); 5] = [
            (
                "build",
                &self.gates.build,
                &[Format, Lint, Test, ReleaseBuild],
            ),
            (
                "security-code",
                &self.gates.security_code,
                &[SelfCheck, DependencyAudit, SecretScan, Sast],
            ),
            (
                "test",
                &self.gates.test,
                &[
                    Format,
                    Lint,
                    Test,
                    ReleaseBuild,
                    DependencyAudit,
                    SecretScan,
                    Sast,
                    SelfCheck,
                ],
            ),
            (
                "pre-push",
                &self.gates.pre_push,
                &[
                    Format,
                    Lint,
                    Test,
                    ReleaseBuild,
                    DependencyAudit,
                    SecretScan,
                    Sast,
                    SelfCheck,
                ],
            ),
            (
                "high-risk-test",
                &self.gates.high_risk_test,
                &[
                    Format,
                    Lint,
                    Test,
                    ReleaseBuild,
                    DependencyAudit,
                    SecretScan,
                    Sast,
                    SelfCheck,
                    Nonfunctional,
                ],
            ),
        ];
        for (gate, profile_name, required) in requirements {
            let effective = self.effective_checks(profile_name)?;
            let kinds = effective
                .iter()
                .map(|name| self.checks[name].kind)
                .collect::<Vec<_>>();
            for kind in required {
                if !kinds.contains(kind) {
                    return Err(format!(
                        "gate {gate:?} profile {profile_name:?} omits required lane {kind:?}"
                    ));
                }
            }
        }
        Ok(())
    }
}

fn validate_repo_path(value: &str, label: &str) -> Result<(), String> {
    let path = Path::new(value);
    if value.is_empty()
        || value.len() > 512
        || value.chars().any(char::is_control)
        || path.is_absolute()
        || path
            .components()
            .any(|c| !matches!(c, std::path::Component::Normal(_)))
    {
        return Err(format!("unsafe {label} {value:?}"));
    }
    Ok(())
}

fn validate_deploy_label(value: &str, label: &str) -> Result<(), String> {
    if value.is_empty()
        || value.len() > 128
        || value.chars().any(char::is_control)
        || value.trim() != value
    {
        return Err(format!("unsafe {label} {value:?}"));
    }
    Ok(())
}

fn validate_identifier(value: &str) -> Result<(), String> {
    if value.is_empty()
        || value.len() > 64
        || !value
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        || value.starts_with('-')
        || value.ends_with('-')
        || value.contains("--")
    {
        return Err(format!("invalid local-validation identifier {value:?}"));
    }
    Ok(())
}
fn validate_program(value: &str) -> Result<(), String> {
    if value.is_empty()
        || value.len() > 512
        || value.starts_with('/')
        || value.contains("..")
        || value.chars().any(|c| c.is_control())
    {
        return Err(format!("unsafe local-validation program {value:?}"));
    }
    Ok(())
}
fn validate_tokens(tokens: &[String]) -> Result<(), String> {
    if tokens.len() > 64
        || tokens
            .iter()
            .any(|s| s.len() > 4096 || s.chars().any(|c| c.is_control()))
    {
        return Err(
            "local-validation arguments contain too many, oversized, or control tokens".into(),
        );
    }
    Ok(())
}

fn validate_release(value: &str) -> Result<(), String> {
    if value.is_empty()
        || value.len() > 64
        || value.starts_with('.')
        || value.ends_with('.')
        || value.split('.').any(|part| {
            part.is_empty() || part.len() > 8 || !part.bytes().all(|byte| byte.is_ascii_digit())
        })
    {
        return Err("required_toolchain.rust_release is not a bounded numeric release".into());
    }
    Ok(())
}

fn validate_platform_token(value: &str, label: &str) -> Result<(), String> {
    if value.is_empty()
        || value.len() > 128
        || value.starts_with('-')
        || value.starts_with('_')
        || value.ends_with('-')
        || value.ends_with('_')
        || value.contains("--")
        || value.contains("__")
        || !value.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-' || byte == b'_'
        })
    {
        return Err(format!("invalid {label} {value:?}"));
    }
    Ok(())
}

fn validate_oid(value: &str, label: &str) -> Result<(), String> {
    if !matches!(value.len(), 40 | 64)
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(format!("invalid full {label} object id"));
    }
    Ok(())
}

fn validate_unique_identifiers(values: &[String], label: &str) -> Result<(), String> {
    let mut seen = std::collections::BTreeSet::new();
    for value in values {
        validate_identifier(value)?;
        if !seen.insert(value) {
            return Err(format!("{label} contains duplicate {value:?}"));
        }
    }
    Ok(())
}

fn validate_environment_allowlist(allowlist: &EnvironmentAllowlist) -> Result<(), String> {
    if allowlist.0.is_empty() || allowlist.0.len() > 32 {
        return Err("sandbox.environment_allowlist must contain 1..=32 keys".into());
    }
    let mut previous: Option<&str> = None;
    for key in &allowlist.0 {
        if key.is_empty()
            || key.len() > 64
            || !key
                .bytes()
                .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit() || byte == b'_')
            || key.starts_with('_')
            || crate::closure::is_secret_shaped_env_name(key)
        {
            return Err(format!("unsafe sandbox environment key {key:?}"));
        }
        if previous.is_some_and(|prior| prior >= key.as_str()) {
            return Err("sandbox.environment_allowlist must be sorted and duplicate-free".into());
        }
        previous = Some(key);
    }
    Ok(())
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClosureConfig {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub default_remote: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub default_ref: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub remote_timeout_secs: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hermetic_reuse: Option<HermeticReusePolicy>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub human_path_list_limit: Option<usize>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct GovernanceDefaults {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub risk: Option<RiskLevel>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub threat_profile: Option<ThreatProfile>,
}

impl Config {
    /// The documentation subdirectory, defaulting to `docs`.
    pub fn docs_dir(&self) -> &str {
        self.docs_dir.as_deref().unwrap_or("docs")
    }

    pub fn hermetic_reuse_policy(&self) -> Option<&HermeticReusePolicy> {
        self.closure
            .as_ref()
            .and_then(|c| c.hermetic_reuse.as_ref())
            .or(self.hermetic_reuse.as_ref())
    }

    pub fn remote_timeout_secs(&self) -> u64 {
        self.closure
            .as_ref()
            .and_then(|c| c.remote_timeout_secs)
            .filter(|seconds| (1..=300).contains(seconds))
            .unwrap_or(15)
    }

    pub fn human_path_list_limit(&self) -> usize {
        self.closure
            .as_ref()
            .and_then(|c| c.human_path_list_limit)
            .filter(|limit| (1..=1000).contains(limit))
            .unwrap_or(50)
    }

    /// The configured model for a persona under a harness, if any and valid. An
    /// invalid model id (unsafe charset) is treated as absent, so it degrades to
    /// the built-in default rather than surfacing into a rendered `--model` string.
    pub fn model_for(&self, harness: &str, persona: &str) -> Option<&str> {
        let m = self.models.get(harness)?.get(persona).map(String::as_str)?;
        valid_model_id(m).then_some(m)
    }

    /// The configured fallback for a model id, if any and valid.
    pub fn model_fallback(&self, model: &str) -> Option<&str> {
        let f = self.model_fallbacks.get(model).map(String::as_str)?;
        valid_model_id(f).then_some(f)
    }

    /// The tuning for a persona tuning key (persona display name or
    /// `"DocValidation"`), if any.
    pub fn persona_tuning(&self, key: &str) -> Option<&PersonaTuning> {
        self.personas.get(key)
    }
}

/// Whether a model id is a safe token — no shell metacharacters can reach a
/// rendered `--model <id>` command line.
fn valid_model_id(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 64
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))
}

/// The default model map + fallbacks seeded at `mpd init` — today's built-in
/// tier assignments, made explicit and editable.
pub fn default_models() -> (ModelMap, BTreeMap<String, String>) {
    let deep = ["Architect", "Designer"];
    let standard = ["Security", "Builder", "Tester", "Documenter"];
    let mut models = ModelMap::new();
    for (harness, deep_model, std_model) in [
        ("claude-code", "fable", "sonnet"),
        ("codex", "sol", "terra"),
    ] {
        let mut m = BTreeMap::new();
        for p in deep {
            m.insert(p.to_string(), deep_model.to_string());
        }
        for p in standard {
            m.insert(p.to_string(), std_model.to_string());
        }
        models.insert(harness.to_string(), m);
    }
    let mut fallbacks = BTreeMap::new();
    fallbacks.insert("fable".to_string(), "opus".to_string());
    (models, fallbacks)
}

/// Path to `.mpd/config.json`.
pub fn config_path(root: &Path) -> PathBuf {
    mpd_dir(root).join("config.json")
}

impl Config {
    /// Load config, returning defaults if the file is absent, symlinked,
    /// oversized, or malformed (fail-safe — never read through a symlink and
    /// never break resolution on a broken config).
    pub fn load(root: &Path) -> Config {
        let path = config_path(root);
        if openspec_core::assert_contained(root, &path).is_err() {
            return Config::default();
        }
        match openspec_core::read_contained_capped(root, &path, openspec_core::DEFAULT_MAX_BYTES) {
            Ok(text) => serde_json::from_str(&text).unwrap_or_default(),
            Err(_) => Config::default(),
        }
    }

    /// Strict loader for validation and trust decisions.  Unlike the ergonomic
    /// project loader, this never converts missing, unsafe, oversized, or
    /// malformed policy bytes into defaults.
    pub fn load_strict(root: &Path) -> Result<Config, String> {
        let path = config_path(root);
        openspec_core::assert_contained(root, &path)
            .map_err(|e| format!("unsafe local validation config: {e}"))?;
        let text =
            openspec_core::read_contained_capped(root, &path, openspec_core::DEFAULT_MAX_BYTES)
                .map_err(|e| format!("local validation config is unavailable: {e}"))?;
        serde_json::from_str(&text)
            .map_err(|e| format!("local validation config is malformed: {e}"))
    }

    /// Persist config as pretty JSON. The symlink guard is intrinsic to `save`
    /// (not delegated to callers): `assert_contained` is checked before the
    /// directory is created and again immediately before the write, so a planted
    /// dangling/symlinked `.mpd/config.json` cannot redirect the write to an
    /// arbitrary target — mirroring `scaffold::write_new`.
    pub fn save(&self, root: &Path) -> std::io::Result<()> {
        let path = config_path(root);
        openspec_core::assert_contained(root, &path).map_err(std::io::Error::other)?;
        let mut json = serde_json::to_string_pretty(self)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        json.push('\n');
        openspec_core::atomic_write_contained(root, &path, json.as_bytes())
            .map_err(std::io::Error::other)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn repository_local_policy() -> LocalValidationConfig {
        let config: Config = serde_json::from_str(include_str!("../../../.mpd/config.json"))
            .expect("repository config must decode with the current typed schema");
        config
            .local_validation
            .expect("repository config must carry local_validation")
    }

    #[test]
    fn repository_local_policy_is_complete_valid_and_composes_in_stable_order() {
        let policy = repository_local_policy();
        policy.validate().unwrap();
        let test = policy.effective_checks("test").unwrap();
        assert_eq!(policy.effective_checks("pre-push").unwrap(), test);
        let mut high_risk = test;
        high_risk.extend([
            "phase-model-tests".to_string(),
            "scoped-digest-throughput".to_string(),
        ]);
        assert_eq!(
            policy.effective_checks("high-risk-test").unwrap(),
            high_risk
        );
        let encoded = serde_json::to_vec(&policy).unwrap();
        let decoded: LocalValidationConfig = serde_json::from_slice(&encoded).unwrap();
        assert_eq!(decoded, policy);
    }

    #[test]
    fn platform_tokens_accept_supported_underscore_triples_and_reject_unsafe_shapes() {
        for valid in [
            "x86_64-unknown-linux-gnu",
            "x86_64-apple-darwin",
            "aarch64-unknown-linux-gnu",
        ] {
            assert_eq!(validate_platform_token(valid, "platform"), Ok(()));
        }

        for invalid in [
            "../x86_64-unknown-linux-gnu",
            "x86_64/unknown-linux-gnu",
            "x86_64 unknown-linux-gnu",
            "x86_64-unknown-linux-gnu\n",
            "_x86_64-unknown-linux-gnu",
            "x86_64-unknown-linux-gnu_",
            "x86__64-unknown-linux-gnu",
        ] {
            assert!(
                validate_platform_token(invalid, "platform").is_err(),
                "unsafe platform token was accepted: {invalid:?}"
            );
        }
    }

    #[test]
    fn typed_policy_rejects_cycles_unknowns_duplicates_paths_and_ceilings() {
        let baseline = repository_local_policy();

        let mut policy = baseline.clone();
        policy.profiles.get_mut("test").unwrap().includes = vec!["pre-push".into()];
        assert!(policy.validate().unwrap_err().contains("cyclic profile"));

        let mut policy = baseline.clone();
        policy.profiles.get_mut("test").unwrap().includes = vec!["missing".into()];
        assert!(policy.validate().unwrap_err().contains("unknown profile"));

        let mut policy = baseline.clone();
        policy
            .profiles
            .get_mut("build")
            .unwrap()
            .checks
            .push("format".into());
        assert!(policy.validate().unwrap_err().contains("duplicates check"));

        let mut policy = baseline.clone();
        policy.offline.advisory_db_path = "../outside".into();
        assert!(policy
            .validate()
            .unwrap_err()
            .contains("unsafe offline.advisory_db_path"));

        let mut policy = baseline;
        policy.limits.checks_per_profile = 65;
        assert!(policy.validate().unwrap_err().contains("1..=64"));
    }

    #[test]
    fn local_policy_codec_denies_unknown_fields_and_sensitive_display_never_changes_argv() {
        let policy = repository_local_policy();
        let mut value = serde_json::to_value(&policy).unwrap();
        value
            .as_object_mut()
            .unwrap()
            .insert("unknown-policy-field".into(), serde_json::json!(true));
        assert!(serde_json::from_value::<LocalValidationConfig>(value).is_err());

        let args = vec!["--token".into(), "public-secret-value".into(), "run".into()];
        let output = CheckOutputConfig {
            sensitive_args: vec![1],
        };
        let displayed = SensitiveArgvDisplay::new(&args, Some(&output)).to_string();
        assert!(!displayed.contains("public-secret-value"));
        assert!(displayed.contains("[REDACTED]"));
        assert_eq!(
            args[1], "public-secret-value",
            "display is presentation-only"
        );
    }

    #[test]
    fn environment_allowlist_is_sorted_duplicate_free_and_secret_denying() {
        let baseline = repository_local_policy();
        for keys in [
            vec!["PATH".into(), "HOME".into()],
            vec!["PATH".into(), "PATH".into()],
            vec!["GITHUB_TOKEN".into()],
            vec!["path".into()],
        ] {
            let mut policy = baseline.clone();
            policy.sandbox.environment_allowlist = EnvironmentAllowlist(keys);
            assert!(policy.validate().is_err());
        }
    }

    #[test]
    fn default_models_seeds_expected_tiers_and_fallback() {
        let (models, fallbacks) = default_models();
        assert_eq!(
            models["claude-code"]["Architect"], "fable",
            "deep tier on claude-code is fable"
        );
        assert_eq!(models["claude-code"]["Designer"], "fable");
        for standard in ["Security", "Builder", "Tester", "Documenter"] {
            assert_eq!(
                models["claude-code"][standard], "sonnet",
                "standard tier persona {standard} must default to sonnet"
            );
        }
        assert_eq!(models["codex"]["Architect"], "sol");
        assert_eq!(models["codex"]["Designer"], "sol");
        for standard in ["Security", "Builder", "Tester", "Documenter"] {
            assert_eq!(
                models["codex"][standard], "terra",
                "standard tier persona {standard} must default to terra on codex"
            );
        }
        assert_eq!(fallbacks.len(), 1);
        assert_eq!(fallbacks["fable"], "opus");
        // Round-trips through Config::model_for exactly as seeded.
        let cfg = Config {
            models,
            model_fallbacks: fallbacks,
            ..Config::default()
        };
        assert_eq!(cfg.model_for("claude-code", "Architect"), Some("fable"));
        assert_eq!(cfg.model_fallback("fable"), Some("opus"));
        assert_eq!(cfg.model_fallback("sonnet"), None);
    }

    #[test]
    fn invalid_model_id_degrades_to_none() {
        let mut models = ModelMap::new();
        let mut m = BTreeMap::new();
        m.insert("Architect".to_string(), "fine-model_1.2".to_string());
        m.insert("Builder".to_string(), "bad; rm -rf /".to_string()); // shell metachar
        models.insert("claude-code".to_string(), m);
        let cfg = Config {
            models,
            ..Config::default()
        };
        assert_eq!(
            cfg.model_for("claude-code", "Architect"),
            Some("fine-model_1.2")
        );
        assert_eq!(cfg.model_for("claude-code", "Builder"), None); // rejected → built-in default
    }

    #[test]
    fn rejects_oversized_and_empty_model_ids() {
        assert!(!valid_model_id(""));
        assert!(!valid_model_id(&"a".repeat(65)));
        assert!(valid_model_id(&"a".repeat(64)));
        assert!(!valid_model_id("has space"));
        assert!(!valid_model_id("has/slash"));
    }

    #[test]
    fn legacy_config_and_governance_defaults_both_deserialize() {
        let legacy: Config = serde_json::from_str(r#"{"test":"cargo test"}"#).unwrap();
        assert_eq!(legacy.governance, None);
        let configured: Config = serde_json::from_str(
            r#"{"governance":{"risk":"high","threat_profile":"credential-bearing"}}"#,
        )
        .unwrap();
        assert_eq!(
            configured.governance.as_ref().unwrap().risk,
            Some(RiskLevel::High)
        );
        assert_eq!(
            configured.governance.as_ref().unwrap().threat_profile,
            Some(ThreatProfile::CredentialBearing)
        );
    }

    #[test]
    fn closure_defaults_validate_bounds_and_nested_hermetic_policy_wins() {
        let cfg: Config = serde_json::from_str(
            r#"{"closure":{"default_remote":"origin","default_ref":"refs/heads/main","remote_timeout_secs":300,"human_path_list_limit":12,"hermetic_reuse":{"schema":1,"external_state":"none"}}}"#,
        )
        .unwrap();
        assert_eq!(cfg.remote_timeout_secs(), 300);
        assert_eq!(cfg.human_path_list_limit(), 12);
        assert!(cfg.hermetic_reuse_policy().is_some());

        let invalid: Config = serde_json::from_str(
            r#"{"closure":{"remote_timeout_secs":0,"human_path_list_limit":0}}"#,
        )
        .unwrap();
        assert_eq!(invalid.remote_timeout_secs(), 15);
        assert_eq!(invalid.human_path_list_limit(), 50);
    }

    #[cfg(unix)]
    #[test]
    fn load_refuses_symlinked_config() {
        use std::os::unix::fs::symlink;
        let dir = std::env::temp_dir().join(format!("mpd-cfg-sym-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        // Plant a secret config outside the project with an unusual test command.
        let outside = dir.join("outside.json");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(&outside, "{\"test\":\"EXFIL\"}").unwrap();
        let cfg_path = config_path(&dir);
        std::fs::create_dir_all(cfg_path.parent().unwrap()).unwrap();
        symlink(&outside, &cfg_path).unwrap();
        let cfg = Config::load(&dir);
        assert_eq!(cfg.test, None, "must not read through a symlinked config");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[cfg(unix)]
    #[test]
    fn save_refuses_symlinked_config() {
        use std::os::unix::fs::symlink;
        let dir = std::env::temp_dir().join(format!("mpd-cfg-save-sym-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        // A dangling symlink at .mpd/config.json: exists() reads absent, a naive
        // write would follow it to `target` outside the project. save() must refuse.
        let target = dir.join("target-outside.json");
        let cfg_path = config_path(&dir);
        std::fs::create_dir_all(cfg_path.parent().unwrap()).unwrap();
        symlink(&target, &cfg_path).unwrap();
        let err = Config::default().save(&dir).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::Other);
        assert!(!target.exists(), "must not create the symlink target");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn lenient_persona_deser_degrades_bad_tokens_and_the_rest_of_config_survives() {
        // R2 / round-2 F2: an unknown token AND a wrong-TYPE value each degrade
        // ONLY that field to None; the rest of the Config (model pins, test cmd)
        // survives, and Config::load never fails wholesale. A plain Option<Rigor>
        // would fail the whole document on a wrong-type token.
        for bad in [
            r#""nope""#,   // unknown string token
            "5",           // wrong type: number
            "true",        // wrong type: bool
            r#"["deep"]"#, // wrong type: array
            "{}",          // wrong type: object
            "null",        // null
        ] {
            let json = format!(
                r#"{{"test":"cargo test","models":{{"claude-code":{{"Security":"my-strong-model"}}}},"personas":{{"Security":{{"rigor":{bad},"depth":"fuzz"}}}}}}"#
            );
            let cfg: Config = serde_json::from_str(&json)
                .unwrap_or_else(|e| panic!("bad rigor {bad} must not fail Config: {e}"));
            assert_eq!(
                cfg.persona_tuning("Security").unwrap().rigor,
                None,
                "bad rigor {bad} → None"
            );
            // The rest of the field (a valid depth) and the model pin survive intact.
            assert_eq!(
                cfg.persona_tuning("Security").unwrap().depth,
                Some(Depth::Fuzz)
            );
            assert_eq!(
                cfg.model_for("claude-code", "Security"),
                Some("my-strong-model")
            );
            assert_eq!(cfg.test.as_deref(), Some("cargo test"));
        }
        // A valid token still parses.
        let cfg: Config =
            serde_json::from_str(r#"{"personas":{"Security":{"rigor":"paranoid"}}}"#).unwrap();
        assert_eq!(
            cfg.persona_tuning("Security").unwrap().rigor,
            Some(Rigor::Paranoid)
        );

        // Security-code F1: a hand-edited wrong-type `directive_append` degrades to
        // None (not a whole-Config failure that reverts model pins), same as the
        // ordinals — while a real string is preserved.
        let cfg: Config = serde_json::from_str(
            r#"{"models":{"claude-code":{"Security":"pin"}},"personas":{"Security":{"directive_append":5}}}"#,
        )
        .unwrap();
        assert_eq!(
            cfg.persona_tuning("Security").unwrap().directive_append,
            None
        );
        assert_eq!(cfg.model_for("claude-code", "Security"), Some("pin"));
        let cfg: Config = serde_json::from_str(
            r#"{"personas":{"Security":{"directive_append":"check IMAP cleartext"}}}"#,
        )
        .unwrap();
        assert_eq!(
            cfg.persona_tuning("Security")
                .unwrap()
                .directive_append
                .as_deref(),
            Some("check IMAP cleartext")
        );
    }

    #[test]
    fn empty_personas_round_trips_and_is_omitted() {
        // R1: an absent/empty personas block round-trips and never serializes,
        // so a baseline config is byte-identical to a pre-feature one.
        let legacy: Config = serde_json::from_str(r#"{"test":"cargo test"}"#).unwrap();
        assert!(legacy.personas.is_empty());
        let json = serde_json::to_string(&legacy).unwrap();
        assert!(!json.contains("personas"), "empty personas must be omitted");
    }

    #[test]
    fn typed_deploy_codec_is_tagged_and_legacy_config_remains_readable() {
        let legacy: Config = serde_json::from_str(r#"{"deploy":"make install"}"#).unwrap();
        assert_eq!(legacy.deploy.as_deref(), Some("make install"));
        assert!(legacy.local_validation.is_none());

        let deploy = DeployOutputConfig::Execute {
            artifact: "mpd-release".into(),
            install: ExactCopyInstallConfig {
                kind: ExactCopyInstallKind::ExactCopy,
            },
            installed_path: ".local/bin/mpd".into(),
            target: "local-mpd-bin".into(),
        };
        let bytes = serde_json::to_vec(&deploy).unwrap();
        assert_eq!(
            serde_json::from_slice::<DeployOutputConfig>(&bytes).unwrap(),
            deploy
        );
        assert!(serde_json::from_str::<DeployOutputConfig>(
            r#"{"mode":"execute","artifact":"mpd-release","unexpected":true}"#
        )
        .is_err());
    }

    proptest! {
        /// Arbitrary hostile suffixes cannot rescue a policy path containing a
        /// control byte. The validator must fail before any such path reaches
        /// filesystem or process resolution.
        #[test]
        fn arbitrary_control_bearing_policy_paths_are_rejected(suffix in ".{0,128}") {
            let mut policy = repository_local_policy();
            policy.hooks.path = format!(".githooks\n{suffix}");
            prop_assert!(policy.validate().is_err());
        }

        /// The compiled effective-profile ceiling is invariant under all
        /// attacker-chosen larger configured values.
        #[test]
        fn arbitrary_profile_limit_above_ceiling_is_rejected(limit in 65usize..100_000) {
            let mut policy = repository_local_policy();
            policy.limits.checks_per_profile = limit;
            prop_assert!(policy.validate().is_err());
        }

        /// Sensitive presentation metadata must reject every out-of-range
        /// attacker-chosen index (>= the check's argv length) while preserving
        /// the exact argv vector. An in-range index is valid metadata. The
        /// boundary is derived from the actual argv so the invariant holds
        /// regardless of how many args the `format` check carries.
        #[test]
        fn arbitrary_out_of_range_sensitive_index_is_rejected(index in 0usize..10_000) {
            let mut policy = repository_local_policy();
            let check = policy.checks.get_mut("format").unwrap();
            let original = check.args.clone();
            let arg_count = original.len();
            check.output = Some(CheckOutputConfig { sensitive_args: vec![index] });
            if index >= arg_count {
                prop_assert!(policy.validate().is_err());
            } else {
                prop_assert!(policy.validate().is_ok());
            }
            prop_assert_eq!(policy.checks["format"].args.as_slice(), original.as_slice());
        }

        /// `valid_model_id` is a defensive-in-depth charset gate ahead of a
        /// rendered `--model <id>` command line — it must never panic on
        /// arbitrary (including adversarial/unicode) input.
        #[test]
        fn valid_model_id_never_panics_on_arbitrary_input(s in ".*") {
            let _ = valid_model_id(&s);
        }

        /// Any string containing a character outside `[A-Za-z0-9._-]` must be
        /// rejected — this is the property that keeps a shell metacharacter
        /// from ever reaching a rendered model string.
        #[test]
        fn valid_model_id_rejects_any_unsafe_char(s in ".*") {
            let has_unsafe_char = s
                .chars()
                .any(|c| !(c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-')));
            if has_unsafe_char {
                prop_assert!(!valid_model_id(&s));
            }
        }
    }

    /// An arbitrary shallow JSON value — the shapes a hand-edited or
    /// hostile-tool-generated `.mpd/config.json` can plant at
    /// `personas.<p>.rigor`/`.depth`/`.directive_append`: the exact known enum
    /// strings (weighted in so the exact-match branch is genuinely exercised,
    /// not left to astronomically-unlikely random string generation), an
    /// arbitrary other string (unknown token), and every wrong-type shape
    /// (number, bool, null, array, object).
    fn arb_tuning_field_value() -> impl Strategy<Value = serde_json::Value> {
        prop_oneof![
            2 => Just(serde_json::json!("standard")),
            2 => Just(serde_json::json!("deep")),
            2 => Just(serde_json::json!("paranoid")),
            2 => Just(serde_json::json!("examples")),
            2 => Just(serde_json::json!("property")),
            2 => Just(serde_json::json!("fuzz")),
            1 => Just(serde_json::Value::Null),
            2 => any::<bool>().prop_map(serde_json::Value::Bool),
            2 => any::<i32>().prop_map(|n| serde_json::json!(n)),
            4 => "[a-zA-Z0-9 ]{0,12}".prop_map(serde_json::Value::String),
            2 => prop::collection::vec("[a-z]{0,4}", 0..3).prop_map(|v| serde_json::json!(v)),
            2 => Just(serde_json::json!({"nested": "object"})),
        ]
    }

    proptest! {
        /// Design.md Cond 2 / D1, as a property rather than a fixed example
        /// list: an ARBITRARY JSON value (any shape — exact token, unknown
        /// token, or wrong type) at `personas.Security.rigor`/`.depth`/
        /// `.directive_append` simultaneously NEVER makes
        /// `serde_json::from_str::<Config>` fail — each field independently
        /// degrades to `None` unless it is the exact matching token/type — and
        /// the REST of the config (a model pin, the test command) always
        /// survives intact. This is the permissive-`Value` guarantee the
        /// hand-written example test only samples a handful of points of.
        #[test]
        fn arbitrary_tuning_field_values_never_fail_config_load_and_degrade_per_field(
            rigor_v in arb_tuning_field_value(),
            depth_v in arb_tuning_field_value(),
            append_v in arb_tuning_field_value(),
        ) {
            let doc = serde_json::json!({
                "test": "cargo test",
                "models": {"claude-code": {"Security": "my-strong-model"}},
                "personas": {
                    "Security": {
                        "rigor": rigor_v.clone(),
                        "depth": depth_v.clone(),
                        "directive_append": append_v.clone(),
                    }
                }
            });
            let text = serde_json::to_string(&doc).unwrap();
            let cfg: Config = serde_json::from_str(&text).unwrap_or_else(|e| {
                panic!("arbitrary tuning field values must never fail Config::load: {text} -> {e}")
            });
            let t = cfg.persona_tuning("Security").unwrap();

            let expected_rigor = match &rigor_v {
                serde_json::Value::String(s) => match s.as_str() {
                    "standard" => Some(Rigor::Standard),
                    "deep" => Some(Rigor::Deep),
                    "paranoid" => Some(Rigor::Paranoid),
                    _ => None,
                },
                _ => None,
            };
            prop_assert_eq!(t.rigor, expected_rigor, "rigor from {:?}", rigor_v);

            let expected_depth = match &depth_v {
                serde_json::Value::String(s) => match s.as_str() {
                    "examples" => Some(Depth::Examples),
                    "property" => Some(Depth::Property),
                    "fuzz" => Some(Depth::Fuzz),
                    _ => None,
                },
                _ => None,
            };
            prop_assert_eq!(t.depth, expected_depth, "depth from {:?}", depth_v);

            // directive_append has no closed enum: ANY JSON string survives
            // verbatim (the lenient adapter only rejects non-string shapes).
            let expected_append = match &append_v {
                serde_json::Value::String(s) => Some(s.clone()),
                _ => None,
            };
            prop_assert_eq!(t.directive_append.clone(), expected_append, "append from {:?}", append_v);

            // The rest of the Config — the model pin, the test command —
            // always survives, regardless of what the tuning fields carried.
            prop_assert_eq!(cfg.model_for("claude-code", "Security"), Some("my-strong-model"));
            prop_assert_eq!(cfg.test.as_deref(), Some("cargo test"));
        }
    }
}
