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
        match openspec_core::read_capped(&path) {
            Ok(text) => serde_json::from_str(&text).unwrap_or_default(),
            Err(_) => Config::default(),
        }
    }

    /// Persist config as pretty JSON. The symlink guard is intrinsic to `save`
    /// (not delegated to callers): `assert_contained` is checked before the
    /// directory is created and again immediately before the write, so a planted
    /// dangling/symlinked `.mpd/config.json` cannot redirect the write to an
    /// arbitrary target — mirroring `scaffold::write_new`.
    pub fn save(&self, root: &Path) -> std::io::Result<()> {
        let path = config_path(root);
        openspec_core::assert_contained(root, &path).map_err(std::io::Error::other)?;
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let mut json = serde_json::to_string_pretty(self)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        json.push('\n');
        openspec_core::assert_contained(root, &path).map_err(std::io::Error::other)?;
        std::fs::write(path, json)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

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

    proptest! {
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
