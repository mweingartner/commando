//! Harness adapters for `mpd next`.
//!
//! The engine is harness-agnostic: it emits the next persona's brief as text or
//! JSON. What differs per harness is (a) how a persona is run and (b) which
//! model backs it. Model policy by tier:
//!
//! | Tier                | Claude Code            | Codex            |
//! |---------------------|------------------------|------------------|
//! | Deep (Architecture) | Fable (→ Opus fallback)| Sol (GPT-5.6)    |
//! | Standard (others)   | Sonnet                 | Terra (GPT-5.6)  |
//!
//! Luna (GPT-5.6, lightest) exists but is not assigned by default.

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
    /// Model to run this phase under, resolved for the requested harness.
    pub model: String,
    /// Optional fallback note (e.g. Claude's Opus fallback for Fable).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub model_note: Option<String>,
    /// OpenSpec artifacts to produce this phase.
    pub artifacts: Vec<String>,
    /// Task guidance for the persona.
    pub guidance: String,
    /// What this phase's gate verifies.
    pub gate: String,
    /// The command to record the gate verdict.
    pub gate_command: String,
}

/// Resolve `(model, fallback_note)` for a phase under a harness. Deep-cognition
/// phases (Architecture) get the strongest model; all others get the standard
/// model. Deploy/Done run in the main session (no spawned model).
pub fn model_for(harness: &str, phase: Phase) -> (String, Option<String>) {
    if matches!(phase, Phase::Deploy | Phase::Done) {
        return ("-".to_string(), None);
    }
    let deep = phase.is_deep();
    match harness {
        "codex" => (if deep { "Sol" } else { "Terra" }.to_string(), None),
        "claude-code" => {
            if deep {
                (
                    "Fable".to_string(),
                    Some("fall back to the latest Opus if Fable is unavailable".to_string()),
                )
            } else {
                ("Sonnet".to_string(), None)
            }
        }
        // Harness-neutral: report the tier rather than a concrete model.
        _ => (
            if deep { "deep-cognition" } else { "standard" }.to_string(),
            None,
        ),
    }
}

/// Build the brief for `phase` of `change`, resolving the model for `harness`.
pub fn brief(change: &str, phase: Phase, harness: &str) -> NextBrief {
    let persona = phase.persona();
    let (model, model_note) = model_for(harness, phase);
    NextBrief {
        change: change.to_string(),
        phase: phase.slug().to_string(),
        label: phase.label().to_string(),
        persona: persona.name.to_string(),
        model,
        model_note,
        artifacts: personas::artifacts_for(phase)
            .iter()
            .map(|s| s.to_string())
            .collect(),
        guidance: personas::guidance(phase).to_string(),
        gate: personas::gate_hint(phase).to_string(),
        gate_command: format!("mpd gate {} --pass --evidence <pointer>", phase.slug()),
    }
}

/// The model line, including any fallback note.
fn model_line(b: &NextBrief) -> String {
    match &b.model_note {
        Some(note) => format!("{} ({note})", b.model),
        None => b.model.clone(),
    }
}

/// Render a brief as plain text for a generic harness / human.
pub fn render_generic(b: &NextBrief) -> String {
    let mut out = String::new();
    out.push_str(&format!("▸ Next phase: {} — {}\n", b.label, b.change));
    out.push_str(&format!(
        "  Persona: {} (model tier: {})\n",
        b.persona,
        model_line(b)
    ));
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
        model = model_line(b),
        guidance = b.guidance,
        artifacts = artifacts,
        gate = b.gate,
        cmd = b.gate_command,
    )
}

/// Render a brief for OpenAI Codex. Codex is single-agent (no subagent tool),
/// so a phase is run as a Codex turn/session that adopts the persona directly,
/// on the tier's GPT-5.6 model.
pub fn render_codex(b: &NextBrief) -> String {
    if b.persona == "main-session" || b.persona == "-" {
        return format!(
            "▸ {} — {}\n  Handle in the current Codex session (no persona switch).\n\n  {}\n\n  When done: {}\n",
            b.label, b.change, b.guidance, b.gate_command
        );
    }
    let artifacts = if b.artifacts.is_empty() {
        String::new()
    } else {
        format!("\n  Artifacts to produce: {}", b.artifacts.join(", "))
    };
    format!(
        "▸ {label} — {change}\n\
         Run this phase as the {persona} persona (Codex has no subagent tool —\n\
         adopt the persona in this turn, or start a fresh `codex --model {model}`\n\
         session for model separation):\n\
         - model: {model} (GPT-5.6 tier){artifacts}\n\n\
         {guidance}\n\n\
         Gate ({gate}). When done, record: {cmd}\n",
        label = b.label,
        change = b.change,
        persona = b.persona,
        model = b.model,
        artifacts = artifacts,
        guidance = b.guidance,
        gate = b.gate,
        cmd = b.gate_command,
    )
}
