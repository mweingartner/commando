//! Harness adapters for `mpd next`.
//!
//! The engine is harness-agnostic: it emits the next persona's brief as text or
//! JSON. What differs per harness is (a) how a persona is run and (b) which
//! model backs it. Model policy by tier:
//!
//! | Tier                        | Claude Code            | Codex          |
//! |-----------------------------|------------------------|----------------|
//! | Deep (Design + Architecture)| Fable (→ Opus fallback)| Sol (GPT-5.6)  |
//! | Standard (Security/Build/Test)| Sonnet               | Terra (GPT-5.6)|
//!
//! Luna (GPT-5.6, lightest) exists but is not assigned by default.

use crate::config::Config;
use crate::ledger::Governance;
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
    /// Whether this phase is validated by two personas (Architect + Designer),
    /// so the harness spawns both.
    pub dual: bool,
    /// OpenSpec artifacts to produce this phase.
    pub artifacts: Vec<String>,
    /// Task guidance for the persona.
    pub guidance: String,
    /// What this phase's gate verifies.
    pub gate: String,
    /// The command to record the gate verdict.
    pub gate_command: String,
    pub risk: String,
    pub threat_profile: String,
    pub attempt: usize,
    pub attempt_limit: usize,
    pub reconciliation_required: bool,
    /// Reconciliation kind authorizing this excess attempt, when present.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub attempt_authorization: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub artifact_warning: Option<String>,
}

/// Resolve `(model, fallback_note)` for a phase under a harness. A per-persona
/// entry in the project's `models` config wins; otherwise the built-in tier
/// default applies (deep → fable/sol, standard → sonnet/terra). Deploy/Done run
/// in the main session (no spawned model). A missing/partial config never breaks
/// resolution — it degrades to the built-in default.
pub fn model_for(cfg: &Config, harness: &str, phase: Phase) -> (String, Option<String>) {
    if matches!(phase, Phase::Deploy | Phase::Done) {
        return ("-".to_string(), None);
    }
    let persona = phase.persona().name;
    let model = cfg
        .model_for(harness, persona)
        .map(str::to_string)
        .unwrap_or_else(|| builtin_default(harness, phase.is_deep()).to_string());
    let note = cfg
        .model_fallback(&model)
        .or_else(|| builtin_fallback(&model))
        .map(|f| format!("fall back to {f} if unavailable"));
    (model, note)
}

/// The built-in default model for a harness/tier when config is silent. The
/// harness-neutral `generic` reports the tier name rather than a concrete model.
fn builtin_default(harness: &str, deep: bool) -> &'static str {
    match harness {
        "codex" => {
            if deep {
                "sol"
            } else {
                "terra"
            }
        }
        "claude-code" => {
            if deep {
                "fable"
            } else {
                "sonnet"
            }
        }
        _ => {
            if deep {
                "deep-cognition"
            } else {
                "standard"
            }
        }
    }
}

/// The built-in fallback for a model id when config declares none.
fn builtin_fallback(model: &str) -> Option<&'static str> {
    match model {
        "fable" => Some("opus"),
        _ => None,
    }
}

/// Build the brief for `phase` of `change`, resolving the model for `harness`
/// against the project `cfg`.
#[allow(clippy::too_many_arguments)]
pub fn brief(
    cfg: &Config,
    change: &str,
    phase: Phase,
    harness: &str,
    governance: &Governance,
    attempt: usize,
    reconciliation_required: bool,
    attempt_authorization: Option<String>,
    artifact_warning: Option<String>,
) -> NextBrief {
    let persona = phase.persona();
    let (model, model_note) = model_for(cfg, harness, phase);
    NextBrief {
        change: change.to_string(),
        phase: phase.slug().to_string(),
        label: phase.label().to_string(),
        persona: persona.name.to_string(),
        model,
        model_note,
        dual: phase.is_doc_validation(),
        artifacts: personas::artifacts_for(phase)
            .iter()
            .map(|s| s.to_string())
            .collect(),
        guidance: personas::guidance(phase).to_string(),
        gate: personas::gate_hint(phase).to_string(),
        gate_command: format!("mpd gate {} --pass --evidence <pointer>", phase.slug()),
        risk: governance.risk.to_string(),
        threat_profile: governance.threat_profile.to_string(),
        attempt,
        attempt_limit: governance.risk.attempt_limit(),
        reconciliation_required,
        attempt_authorization,
        artifact_warning,
    }
}

/// Strip terminal control characters from repository-controlled text before
/// human rendering. JSON remains lossless and correctly escaped by serde_json.
pub fn terminal_safe(s: &str) -> String {
    s.chars()
        .filter(|c| !c.is_control() || matches!(c, '\n' | '\t'))
        .collect()
}

fn governance_lines(b: &NextBrief) -> String {
    let mut out = format!(
        "  Governance: risk {}, threat profile {}\n  Review attempt: {}/{}\n",
        b.risk, b.threat_profile, b.attempt, b.attempt_limit
    );
    if let Some(kind) = &b.attempt_authorization {
        out.push_str(&format!(
            "  Excess attempt {} authorized by {} reconciliation (base limit {}).\n",
            b.attempt, kind, b.attempt_limit
        ));
    } else if b.reconciliation_required {
        out.push_str("  Reconciliation required before this attempt.\n");
    }
    if let Some(w) = &b.artifact_warning {
        out.push_str(&format!("  Warning: {}\n", terminal_safe(w)));
    }
    if b.persona == "Security" {
        out.push_str("  Blocking FAIL requires attacker, prerequisite capability, crossed boundary, concrete harm, and exact fix. Out-of-profile hardening is advisory unless it crosses into the declared profile.\n");
    }
    out
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
    out.push_str(&governance_lines(b));
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
    let governance = governance_lines(b);
    if b.persona == "main-session" || b.persona == "-" {
        return format!(
            "▸ {} — {}\n{}  Handle in the main session (no subagent).\n\n  {}\n\n  When done: {}\n",
            b.label, b.change, governance, b.guidance, b.gate_command
        );
    }
    if b.dual {
        return format!(
            "▸ {label} — {change}\n{governance}\
             Spawn TWO subagents in parallel (both model: {model}):\n\
             - subagent_type: architect — functional/scope/technical accuracy\n\
             - subagent_type: designer  — purpose/value/representation\n\n\
             {guidance}\n\n\
             PASS only if both confirm. Record: {cmd}\n",
            label = b.label,
            change = b.change,
            governance = governance,
            model = model_line(b),
            guidance = b.guidance,
            cmd = b.gate_command,
        );
    }
    let artifacts = if b.artifacts.is_empty() {
        String::new()
    } else {
        format!("\n\nArtifacts to produce: {}", b.artifacts.join(", "))
    };
    format!(
        "▸ {label} — {change}\n{governance}\
         Spawn a subagent (Agent tool):\n\
         - subagent_type: {persona_lc}\n\
         - model: {model}\n\
         - prompt: |\n      {guidance}{artifacts}\n\n\
         Gate ({gate}). When the subagent returns, record: {cmd}\n",
        label = b.label,
        change = b.change,
        governance = governance,
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
    let governance = governance_lines(b);
    if b.persona == "main-session" || b.persona == "-" {
        return format!(
            "▸ {} — {}\n{}  Handle in the current Codex session (no persona switch).\n\n  {}\n\n  When done: {}\n",
            b.label, b.change, governance, b.guidance, b.gate_command
        );
    }
    if b.dual {
        return format!(
            "▸ {label} — {change}\n{governance}\
             Validate from BOTH lenses (Codex is single-agent — run each in turn,\n\
             or a fresh `codex --model {model}` session per lens):\n\
             - Architect lens: functional/scope/technical accuracy\n\
             - Designer lens: purpose/value/representation\n\
             - model: {model} (GPT-5.6 tier)\n\n\
             {guidance}\n\n\
             PASS only if both lenses confirm. Record: {cmd}\n",
            label = b.label,
            change = b.change,
            governance = governance,
            model = b.model,
            guidance = b.guidance,
            cmd = b.gate_command,
        );
    }
    let artifacts = if b.artifacts.is_empty() {
        String::new()
    } else {
        format!("\n  Artifacts to produce: {}", b.artifacts.join(", "))
    };
    format!(
        "▸ {label} — {change}\n{governance}\
         Run this phase as the {persona} persona (Codex has no subagent tool —\n\
         adopt the persona in this turn, or start a fresh `codex --model {model}`\n\
         session for model separation):\n\
         - model: {model} (GPT-5.6 tier){artifacts}\n\n\
         {guidance}\n\n\
         Gate ({gate}). When done, record: {cmd}\n",
        label = b.label,
        change = b.change,
        governance = governance,
        persona = b.persona,
        model = b.model,
        artifacts = artifacts,
        guidance = b.guidance,
        gate = b.gate,
        cmd = b.gate_command,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::ModelMap;
    use proptest::prelude::*;
    use std::collections::BTreeMap;

    #[test]
    fn deploy_and_done_report_no_model() {
        let cfg = Config::default();
        assert_eq!(
            model_for(&cfg, "claude-code", Phase::Deploy),
            ("-".to_string(), None)
        );
        assert_eq!(
            model_for(&cfg, "codex", Phase::Done),
            ("-".to_string(), None)
        );
        // Even a harness the config knows nothing about degrades the same way.
        assert_eq!(
            model_for(&cfg, "generic", Phase::Deploy),
            ("-".to_string(), None)
        );
    }

    #[test]
    fn builtin_defaults_when_config_is_empty() {
        let cfg = Config::default();
        // Deep tier (Architecture).
        assert_eq!(
            model_for(&cfg, "claude-code", Phase::Architecture).0,
            "fable"
        );
        assert_eq!(model_for(&cfg, "codex", Phase::Architecture).0, "sol");
        assert_eq!(
            model_for(&cfg, "generic", Phase::Architecture).0,
            "deep-cognition"
        );
        // Standard tier (Build).
        assert_eq!(model_for(&cfg, "claude-code", Phase::Build).0, "sonnet");
        assert_eq!(model_for(&cfg, "codex", Phase::Build).0, "terra");
        assert_eq!(model_for(&cfg, "generic", Phase::Build).0, "standard");
    }

    #[test]
    fn fable_fallback_note_names_opus() {
        let cfg = Config::default();
        let (model, note) = model_for(&cfg, "claude-code", Phase::Architecture);
        assert_eq!(model, "fable");
        assert_eq!(
            note.as_deref(),
            Some("fall back to opus if unavailable"),
            "the fable→opus fallback note must have exact wording"
        );
        // Sonnet (standard tier) has no built-in fallback.
        let (model, note) = model_for(&cfg, "claude-code", Phase::Build);
        assert_eq!(model, "sonnet");
        assert_eq!(note, None);
    }

    #[test]
    fn terminal_rendering_strips_control_sequences() {
        assert_eq!(
            terminal_safe("safe\u{1b}]8;;evil\u{7}text"),
            "safe]8;;eviltext"
        );
        assert_eq!(terminal_safe("line\nnext\tcell"), "line\nnext\tcell");
    }

    #[test]
    fn builtin_default_covers_every_harness_and_tier() {
        assert_eq!(builtin_default("claude-code", true), "fable");
        assert_eq!(builtin_default("claude-code", false), "sonnet");
        assert_eq!(builtin_default("codex", true), "sol");
        assert_eq!(builtin_default("codex", false), "terra");
        assert_eq!(builtin_default("generic", true), "deep-cognition");
        assert_eq!(builtin_default("generic", false), "standard");
        // Any harness-neutral / unrecognized name falls back to the tier label.
        assert_eq!(
            builtin_default("some-future-harness", true),
            "deep-cognition"
        );
        assert_eq!(builtin_default("some-future-harness", false), "standard");
    }

    #[test]
    fn builtin_fallback_is_fable_only() {
        assert_eq!(builtin_fallback("fable"), Some("opus"));
        assert_eq!(builtin_fallback("sonnet"), None);
        assert_eq!(builtin_fallback("sol"), None);
        assert_eq!(builtin_fallback("terra"), None);
        assert_eq!(builtin_fallback(""), None);
    }

    proptest! {
        /// Metamorphic: whatever a project config declares as a persona's model
        /// id, once resolved through `model_for`, an id `Config::model_for`
        /// rejects (unsafe charset, empty, or oversized) must never surface
        /// verbatim into the resolved model or the rendered brief — it degrades
        /// to the built-in default first. A valid id passes through unchanged.
        #[test]
        fn invalid_config_model_id_never_reaches_rendered_output(id in ".*") {
            let mut persona_map = BTreeMap::new();
            persona_map.insert("Architect".to_string(), id.clone());
            let mut models = ModelMap::new();
            models.insert("claude-code".to_string(), persona_map);
            let cfg = Config { models, ..Config::default() };

            // The config's own validity oracle defines "invalid" here.
            let considered_valid = cfg.model_for("claude-code", "Architect").is_some();
            let (model, _note) = model_for(&cfg, "claude-code", Phase::Architecture);

            if considered_valid {
                prop_assert_eq!(&model, &id);
            } else {
                prop_assert_eq!(
                    model.as_str(),
                    "fable",
                    "a rejected id must degrade to the built-in deep default, not leak the raw id"
                );
                let b = brief(
                    &cfg,
                    "change",
                    Phase::Architecture,
                    "claude-code",
                    &Governance::default(),
                    1,
                    false,
                    None,
                    None,
                );
                let rendered = render_claude_code(&b);
                // Only the *model line* is the actual injection surface (a raw
                // id could otherwise coincidentally match ordinary prose
                // punctuation elsewhere in the guidance text).
                if !id.is_empty() && id != "fable" {
                    prop_assert!(
                        !rendered.contains(&format!("model: {id}")),
                        "a rejected model id must never surface on the rendered model line"
                    );
                }
            }
        }
    }
}
