//! Rendering [`crate::model`] types back to canonical OpenSpec markdown.
//!
//! Rendering targets **canonical-form idempotence**, not byte-for-byte
//! preservation of arbitrary input: [`render_spec`] emits a normalized layout
//! (blocks separated by exactly one blank line) such that
//! `parse(render(parse(x))) == parse(x)`. Verbatim regions (lead, tail,
//! description, scenario body) are reproduced exactly; only inter-block spacing
//! is normalized.

use crate::model::{DeltaSpec, Removed, Rename, Requirement, Spec};

/// Join non-empty blocks with a single blank line and terminate with a newline.
fn join_blocks(blocks: Vec<String>) -> String {
    let mut out = blocks
        .into_iter()
        .filter(|b| !b.is_empty())
        .collect::<Vec<_>>()
        .join("\n\n");
    out.push('\n');
    out
}

/// Render one requirement (header + description + scenarios) as a single block.
fn render_requirement(req: &Requirement) -> String {
    let mut parts: Vec<String> = vec![format!("### Requirement: {}", req.name)];
    if !req.text.is_empty() {
        parts.push(req.text.clone());
    }
    for scenario in &req.scenarios {
        parts.push(format!("#### Scenario: {}", scenario.name));
        if !scenario.body.is_empty() {
            parts.push(scenario.body.clone());
        }
    }
    parts.join("\n\n")
}

/// Render a REMOVED entry (header + reason/migration body) as a single block.
fn render_removed(removed: &Removed) -> String {
    let mut parts = vec![format!("### Requirement: {}", removed.name)];
    if !removed.body.is_empty() {
        parts.push(removed.body.clone());
    }
    parts.join("\n\n")
}

/// Render a RENAMED entry as a `FROM`/`TO` block.
fn render_rename(rename: &Rename) -> String {
    format!(
        "- FROM: `### Requirement: {}`\n- TO: `### Requirement: {}`",
        rename.from, rename.to
    )
}

/// Render a canonical capability spec to markdown.
pub fn render_spec(spec: &Spec) -> String {
    let mut blocks = vec![format!("# {}", spec.title)];
    if !spec.lead.is_empty() {
        blocks.push(spec.lead.clone());
    }
    for req in &spec.requirements {
        blocks.push(render_requirement(req));
    }
    if !spec.tail.is_empty() {
        blocks.push(spec.tail.clone());
    }
    join_blocks(blocks)
}

/// Render a delta spec to markdown. Sections are emitted in the canonical order
/// ADDED, MODIFIED, REMOVED, RENAMED regardless of input order.
pub fn render_delta(delta: &DeltaSpec) -> String {
    let mut blocks = Vec::new();
    if let Some(title) = &delta.title {
        blocks.push(format!("# {title}"));
    }
    if !delta.lead.is_empty() {
        blocks.push(delta.lead.clone());
    }
    if !delta.added.is_empty() {
        blocks.push("## ADDED Requirements".to_string());
        for req in &delta.added {
            blocks.push(render_requirement(req));
        }
    }
    if !delta.modified.is_empty() {
        blocks.push("## MODIFIED Requirements".to_string());
        for req in &delta.modified {
            blocks.push(render_requirement(req));
        }
    }
    if !delta.removed.is_empty() {
        blocks.push("## REMOVED Requirements".to_string());
        for removed in &delta.removed {
            blocks.push(render_removed(removed));
        }
    }
    if !delta.renamed.is_empty() {
        blocks.push("## RENAMED Requirements".to_string());
        for rename in &delta.renamed {
            blocks.push(render_rename(rename));
        }
    }
    join_blocks(blocks)
}
