//! Project-local mpd configuration (`.mpd/config.json`).

use crate::ledger::mpd_dir;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

/// Configuration read from `.mpd/config.json`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Config {
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
}

impl Config {
    /// The documentation subdirectory, defaulting to `docs`.
    pub fn docs_dir(&self) -> &str {
        self.docs_dir.as_deref().unwrap_or("docs")
    }
}

/// Path to `.mpd/config.json`.
pub fn config_path(root: &Path) -> PathBuf {
    mpd_dir(root).join("config.json")
}

impl Config {
    /// Load config, returning defaults if the file is absent.
    pub fn load(root: &Path) -> Config {
        match std::fs::read_to_string(config_path(root)) {
            Ok(text) => serde_json::from_str(&text).unwrap_or_default(),
            Err(_) => Config::default(),
        }
    }

    /// Persist config as pretty JSON.
    pub fn save(&self, root: &Path) -> std::io::Result<()> {
        let path = config_path(root);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let mut json = serde_json::to_string_pretty(self)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        json.push('\n');
        std::fs::write(path, json)
    }
}
