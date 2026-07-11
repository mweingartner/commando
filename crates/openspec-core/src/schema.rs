//! Schema and change-metadata models — the YAML side of the OpenSpec format.
//!
//! A [`Schema`] (`schemas/<name>/schema.yaml`) declares the artifacts a change
//! contains and their dependency edges. [`ChangeMeta`] (`.openspec.yaml` inside
//! a change) records which schema created it and when.

use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::fmt;

/// An error decoding schema or change-metadata YAML.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct YamlError(pub String);

impl fmt::Display for YamlError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl std::error::Error for YamlError {}

/// A workflow schema: the ordered set of artifacts a change produces.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Schema {
    /// Schema identifier (e.g. `spec-driven`, `mpd`).
    pub name: String,
    /// Schema format version.
    #[serde(default)]
    pub version: u32,
    /// Human-readable description.
    #[serde(default)]
    pub description: String,
    /// The artifacts this schema defines, in declared order.
    pub artifacts: Vec<Artifact>,
    /// The optional apply phase (implementation step).
    #[serde(default)]
    pub apply: Option<ApplySpec>,
}

/// One artifact within a [`Schema`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Artifact {
    /// Stable id (e.g. `proposal`, `specs`, `architecture`).
    pub id: String,
    /// Glob or filename the artifact generates (e.g. `proposal.md`, `specs/**/*.md`).
    pub generates: String,
    /// Human-readable description.
    #[serde(default)]
    pub description: String,
    /// Template file name within the schema's `templates/` directory.
    #[serde(default)]
    pub template: Option<String>,
    /// Authoring guidance surfaced to the agent that produces this artifact.
    #[serde(default)]
    pub instruction: String,
    /// Ids of artifacts that must exist before this one.
    #[serde(default)]
    pub requires: Vec<String>,
}

/// The apply (implementation) phase of a schema.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApplySpec {
    /// Artifacts required before apply can begin.
    #[serde(default)]
    pub requires: Vec<String>,
    /// The artifact whose checkboxes track apply progress (e.g. `tasks.md`).
    #[serde(default)]
    pub tracks: Option<String>,
    /// Guidance for the apply phase.
    #[serde(default)]
    pub instruction: String,
}

impl Schema {
    /// Parse a `schema.yaml` document.
    pub fn parse(input: &str) -> Result<Schema, YamlError> {
        serde_yaml_ng::from_str(input).map_err(|e| YamlError(e.to_string()))
    }

    /// Serialize back to YAML.
    pub fn to_yaml(&self) -> Result<String, YamlError> {
        serde_yaml_ng::to_string(self).map_err(|e| YamlError(e.to_string()))
    }

    /// Look up an artifact by id.
    pub fn artifact(&self, id: &str) -> Option<&Artifact> {
        self.artifacts.iter().find(|a| a.id == id)
    }

    /// Artifacts in dependency order (a stable topological sort honoring
    /// `requires`). Returns [`YamlError`] on an unknown dependency or a cycle.
    pub fn ordered(&self) -> Result<Vec<&Artifact>, YamlError> {
        let index: HashMap<&str, &Artifact> =
            self.artifacts.iter().map(|a| (a.id.as_str(), a)).collect();
        for a in &self.artifacts {
            for dep in &a.requires {
                if !index.contains_key(dep.as_str()) {
                    return Err(YamlError(format!(
                        "artifact {:?} requires unknown artifact {:?}",
                        a.id, dep
                    )));
                }
            }
        }
        let mut ordered = Vec::new();
        let mut done: HashSet<&str> = HashSet::new();
        let mut visiting: HashSet<&str> = HashSet::new();
        // Iterative visit preserving declared order for independent artifacts.
        fn visit<'a>(
            id: &'a str,
            index: &HashMap<&'a str, &'a Artifact>,
            done: &mut HashSet<&'a str>,
            visiting: &mut HashSet<&'a str>,
            ordered: &mut Vec<&'a Artifact>,
        ) -> Result<(), YamlError> {
            if done.contains(id) {
                return Ok(());
            }
            if !visiting.insert(id) {
                return Err(YamlError(format!("dependency cycle at artifact {id:?}")));
            }
            let artifact = index[id];
            for dep in &artifact.requires {
                visit(dep.as_str(), index, done, visiting, ordered)?;
            }
            visiting.remove(id);
            done.insert(id);
            ordered.push(artifact);
            Ok(())
        }
        for a in &self.artifacts {
            visit(
                a.id.as_str(),
                &index,
                &mut done,
                &mut visiting,
                &mut ordered,
            )?;
        }
        Ok(ordered)
    }
}

/// Per-change metadata stored at `.openspec.yaml` inside a change directory.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChangeMeta {
    /// The schema this change was created under.
    pub schema: String,
    /// The creation date (`YYYY-MM-DD`).
    #[serde(default)]
    pub created: String,
}

impl ChangeMeta {
    /// Parse a `.openspec.yaml` document.
    pub fn parse(input: &str) -> Result<ChangeMeta, YamlError> {
        serde_yaml_ng::from_str(input).map_err(|e| YamlError(e.to_string()))
    }

    /// Serialize back to YAML.
    pub fn to_yaml(&self) -> Result<String, YamlError> {
        serde_yaml_ng::to_string(self).map_err(|e| YamlError(e.to_string()))
    }
}
