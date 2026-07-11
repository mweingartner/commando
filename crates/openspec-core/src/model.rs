//! The domain model for the OpenSpec format.
//!
//! These types are the *ubiquitous language* of a spec: a [`Spec`] is a
//! deployed capability, a [`Requirement`] a normative behavior contract keyed
//! by its header, a [`Scenario`] a testable case, and a [`DeltaSpec`] a
//! proposed change expressed as ADDED / MODIFIED / REMOVED / RENAMED operations.
//!
//! Parsing produces these types; rendering emits canonical markdown from them;
//! merging applies a [`DeltaSpec`] to a [`Spec`]. The model is deliberately
//! side-effect-free — no I/O lives here.

use serde::{Deserialize, Serialize};

/// A canonical capability specification (`openspec/specs/<capability>/spec.md`).
///
/// Free-form prose that is not a structured requirement is preserved verbatim
/// in [`Spec::lead`] (everything before the first requirement) and
/// [`Spec::tail`] (everything from the first trailing level-2 heading onward),
/// so non-structural content survives a parse/render round-trip unchanged.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Spec {
    /// The `# Title` line content, without the leading `# `.
    pub title: String,
    /// Raw markdown between the title and the first `### Requirement:` header
    /// (e.g. `## Purpose`, `## Requirements`). Preserved verbatim.
    pub lead: String,
    /// The structured requirements, in document order.
    pub requirements: Vec<Requirement>,
    /// Raw markdown after the last requirement, beginning at the first trailing
    /// level-2 (`## `) heading (e.g. `## Why These Decisions`). Preserved verbatim.
    pub tail: String,
}

/// A single normative requirement. The [`name`](Requirement::name) is the
/// unique identifier used for delta matching (normalized by trimming,
/// compared case-sensitively).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Requirement {
    /// Header text after `### Requirement: `, trimmed.
    pub name: String,
    /// Description prose between the header and the first scenario, trimmed of
    /// surrounding blank lines. May contain `**Reason**` / `**Migration**`
    /// annotations when this requirement appears in a REMOVED delta section.
    pub text: String,
    /// The requirement's scenarios, in document order.
    pub scenarios: Vec<Scenario>,
}

impl Requirement {
    /// The normalized key used for delta matching.
    pub fn key(&self) -> &str {
        self.name.trim()
    }
}

/// A single `#### Scenario:` case. Its [`body`](Scenario::body) is preserved
/// verbatim (WHEN/THEN bullets, sub-bullets, fenced code) so nothing is lost.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Scenario {
    /// Header text after `#### Scenario: `, trimmed.
    pub name: String,
    /// Raw body lines after the header, trimmed of surrounding blank lines.
    pub body: String,
}

/// A proposed change to a capability
/// (`openspec/changes/<name>/specs/<capability>/spec.md`), expressed as deltas.
///
/// Merge order is fixed by the OpenSpec conventions and does not depend on the
/// document order of these sections: renames, then removals, then
/// modifications, then additions.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct DeltaSpec {
    /// Optional `# Title` (delta files may omit it).
    pub title: Option<String>,
    /// Raw markdown before the first delta section, preserved verbatim.
    pub lead: String,
    /// `## ADDED Requirements` — new requirements to append.
    pub added: Vec<Requirement>,
    /// `## MODIFIED Requirements` — full replacement content, matched by header.
    pub modified: Vec<Requirement>,
    /// `## REMOVED Requirements` — requirements to delete, matched by header.
    pub removed: Vec<Removed>,
    /// `## RENAMED Requirements` — header renames applied before all else.
    pub renamed: Vec<Rename>,
}

impl DeltaSpec {
    /// Total number of delta operations across all sections.
    pub fn operation_count(&self) -> usize {
        self.added.len() + self.modified.len() + self.removed.len() + self.renamed.len()
    }

    /// `true` when the delta carries no operations.
    pub fn is_empty(&self) -> bool {
        self.operation_count() == 0
    }
}

/// A requirement slated for removal. The [`body`](Removed::body) preserves the
/// `**Reason**` / `**Migration**` prose for the archived record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Removed {
    /// Header text after `### Requirement: `, trimmed. The removal key.
    pub name: String,
    /// Raw body (typically `**Reason**` and `**Migration**` lines), trimmed.
    pub body: String,
}

impl Removed {
    /// The normalized key used for delta matching.
    pub fn key(&self) -> &str {
        self.name.trim()
    }
}

/// A header rename operation: `FROM` an existing header `TO` a new one.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Rename {
    /// The existing requirement name (normalized) to rename.
    pub from: String,
    /// The new requirement name.
    pub to: String,
}

/// A validation finding produced by [`crate::validate`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Issue {
    /// Severity of the finding.
    pub severity: Severity,
    /// Human-readable description.
    pub message: String,
    /// Optional location hint (e.g. requirement name).
    pub location: Option<String>,
}

/// Severity of a validation [`Issue`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    /// A structural defect: the document is not valid OpenSpec.
    Error,
    /// A convention deviation: valid, but discouraged. Promoted to `Error`
    /// under strict validation.
    Warning,
}
