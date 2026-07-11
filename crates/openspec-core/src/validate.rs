//! Structural and convention validation for specs and deltas.
//!
//! [`Severity::Error`] findings mean the document is not valid OpenSpec.
//! [`Severity::Warning`] findings are convention deviations; under `strict`
//! they are treated as failures by [`has_blocking`].

use crate::model::{DeltaSpec, Issue, Requirement, Severity, Spec};
use std::collections::HashSet;

/// Soft cap on requirement-name length (convention: under 50 characters).
const NAME_MAX: usize = 50;

fn error(message: impl Into<String>, location: Option<String>) -> Issue {
    Issue {
        severity: Severity::Error,
        message: message.into(),
        location,
    }
}

fn warning(message: impl Into<String>, location: Option<String>) -> Issue {
    Issue {
        severity: Severity::Warning,
        message: message.into(),
        location,
    }
}

/// `true` if any finding blocks acceptance: any error, or — under `strict` —
/// any warning too.
pub fn has_blocking(issues: &[Issue], strict: bool) -> bool {
    issues.iter().any(|i| match i.severity {
        Severity::Error => true,
        Severity::Warning => strict,
    })
}

fn is_normative(text: &str) -> bool {
    let upper = text.to_ascii_uppercase();
    upper.contains("SHALL") || upper.contains("MUST")
}

/// Validate the shared structure of a requirement that will live in a canonical
/// spec (used for canonical specs and for ADDED/MODIFIED delta requirements).
fn validate_canonical_requirement(req: &Requirement, issues: &mut Vec<Issue>) {
    let loc = Some(req.name.clone());
    if req.name.trim().is_empty() {
        issues.push(error("requirement has an empty name", loc.clone()));
    }
    if req.name.chars().count() > NAME_MAX {
        issues.push(warning(
            format!("requirement name exceeds {NAME_MAX} characters"),
            loc.clone(),
        ));
    }
    if req.scenarios.is_empty() {
        issues.push(error(
            "requirement has no scenarios (every requirement needs at least one `#### Scenario:`)",
            loc.clone(),
        ));
    }
    if !is_normative(&req.text) {
        issues.push(warning(
            "requirement text has no SHALL/MUST normative keyword",
            loc.clone(),
        ));
    }
    for scenario in &req.scenarios {
        if scenario.name.trim().is_empty() {
            issues.push(error("scenario has an empty name", loc.clone()));
        }
        let body_upper = scenario.body.to_ascii_uppercase();
        if !body_upper.contains("WHEN") || !body_upper.contains("THEN") {
            issues.push(warning(
                format!("scenario {:?} is missing WHEN/THEN steps", scenario.name),
                loc.clone(),
            ));
        }
    }
}

/// Validate a canonical capability spec.
pub fn validate_spec(spec: &Spec) -> Vec<Issue> {
    let mut issues = Vec::new();
    if spec.title.trim().is_empty() {
        issues.push(error("spec has an empty title", None));
    }
    if spec.requirements.is_empty() {
        issues.push(warning("spec has no requirements", None));
    }
    let mut seen = HashSet::new();
    for req in &spec.requirements {
        if !seen.insert(req.key().to_string()) {
            issues.push(error(
                format!("duplicate requirement header: {:?}", req.key()),
                Some(req.name.clone()),
            ));
        }
        validate_canonical_requirement(req, &mut issues);
    }
    issues
}

/// Validate a delta spec.
pub fn validate_delta(delta: &DeltaSpec) -> Vec<Issue> {
    let mut issues = Vec::new();
    if delta.is_empty() {
        issues.push(warning("delta has no operations", None));
    }

    // ADDED / MODIFIED requirements must be valid canonical requirements.
    let mut added_seen = HashSet::new();
    for req in &delta.added {
        if !added_seen.insert(req.key().to_string()) {
            issues.push(error(
                format!("duplicate ADDED requirement: {:?}", req.key()),
                Some(req.name.clone()),
            ));
        }
        validate_canonical_requirement(req, &mut issues);
    }
    for req in &delta.modified {
        validate_canonical_requirement(req, &mut issues);
    }

    // REMOVED entries should document a reason.
    for removed in &delta.removed {
        if !removed.body.to_ascii_lowercase().contains("reason") {
            issues.push(warning(
                "REMOVED requirement should include a **Reason**",
                Some(removed.name.clone()),
            ));
        }
    }

    // RENAMED entries need both endpoints.
    for rename in &delta.renamed {
        if rename.from.trim().is_empty() || rename.to.trim().is_empty() {
            issues.push(error(
                "RENAMED entry needs both FROM and TO names",
                Some(format!("{} -> {}", rename.from, rename.to)),
            ));
        }
    }
    issues
}
