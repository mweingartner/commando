//! Harness adapters for `mpd next`.
//!
//! The engine is harness-agnostic: it emits the next persona's brief as text or
//! JSON. A harness with native subagents (Claude Code's `Task`) renders spawn
//! instructions; a bare harness reads the generic text. The same brief drives
//! both — the portability seam.

use crate::personas;
use crate::phase::Phase;
use serde::Serialize;

/// The instruction set for the next phase.
#[derive(Debug, Clone, Serialize)]
pub struct NextBrief {
    /// The change name.
    pub change: String,
    /// The phase slug.
    pub phase: String,
    /// Human label for the phase.
    pub label: String,
    /// Persona responsible.
    pub persona: String,
    /// Mandatory model assignment.
    pub model: String,
    /// OpenSpec artifacts to produce this phase.
    pub artifacts: Vec<String>,
    /// Task guidance for the persona.
    pub guidance: String,
    /// What this phase's gate verifies.
    pub gate: String,
    /// The command to record the gate verdict.
    pub gate_command: String,
}

/// Build the brief for `phase` of `change`.
pub fn brief(change: &str, phase: Phase) -> NextBrief {
    let persona = phase.persona();
    NextBrief {
        change: change.to_string(),
        phase: phase.slug().to_string(),
        label: phase.label().to_string(),
        persona: persona.name.to_string(),
        model: persona.model.to_string(),
        artifacts: personas::artifacts_for(phase)
            .iter()
            .map(|s| s.to_string())
            .collect(),
        guidance: personas::guidance(phase).to_string(),
        gate: personas::gate_hint(phase).to_string(),
        gate_command: format!("mpd gate {} --pass --evidence <pointer>", phase.slug()),
    }
}

/// Render a brief as plain text for a generic harness / human.
pub fn render_generic(b: &NextBrief) -> String {
    let mut out = String::new();
    out.push_str(&format!("▸ Next phase: {} — {}\n", b.label, b.change));
    out.push_str(&format!("  Persona: {} (model: {})\n", b.persona, b.model));
    if !b.artifacts.is_empty() {
        out.push_str(&format!(
            "  Produce artifacts: {}\n",
            b.artifacts.join(", ")
        ));
    }
    out.push_str(&format!("\n  {}\n", b.guidance));
    out.push_str(&format!("\n  Gate: {}\n", b.gate));
    out.push_str(&format!("  When done: {}\n", b.gate_command));
    out
}

/// Render a brief as Claude Code subagent spawn instructions.
pub fn render_claude_code(b: &NextBrief) -> String {
    if b.persona == "main-session" || b.persona == "-" {
        return format!(
            "▸ {} — {}\n  Handle in the main session (no subagent).\n\n  {}\n\n  When done: {}\n",
            b.label, b.change, b.guidance, b.gate_command
        );
    }
    let artifacts = if b.artifacts.is_empty() {
        String::new()
    } else {
        format!("\n\nArtifacts to produce: {}", b.artifacts.join(", "))
    };
    format!(
        "▸ {label} — {change}\n\
         Spawn a subagent (Agent tool):\n\
         - subagent_type: {persona_lc}\n\
         - model: {model}\n\
         - prompt: |\n      {guidance}{artifacts}\n\n\
         Gate ({gate}). When the subagent returns, record: {cmd}\n",
        label = b.label,
        change = b.change,
        persona_lc = b.persona.to_ascii_lowercase(),
        model = b.model,
        guidance = b.guidance,
        artifacts = artifacts,
        gate = b.gate,
        cmd = b.gate_command,
    )
}
