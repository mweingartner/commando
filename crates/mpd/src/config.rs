//! Project-local mpd configuration (`.mpd/config.json`).

use crate::ledger::{mpd_dir, RiskLevel, ThreatProfile};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

/// A per-harness map of persona name → model id.
pub type ModelMap = BTreeMap<String, BTreeMap<String, String>>;

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
}
