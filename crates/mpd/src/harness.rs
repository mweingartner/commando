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
use crate::ledger::{Depth, Governance, Rigor, RiskLevel};
use crate::personas;
use crate::phase::Phase;
use serde::Serialize;

/// Ordinal rank of a reasoning-effort label (`medium` < `high` < `max`). Effort
/// composition MUST compare on this rank, NEVER on `String` order — lexically
/// `"high" < "max" < "medium"`, so a naive `String::max` would select the WEAKEST
/// (`"medium"`) over `"high"`, a strengthen-only inversion (design.md Cond 3,
/// round-3 F3).
fn effort_rank(effort: &str) -> u8 {
    match effort {
        "max" => 2,
        "high" => 1,
        _ => 0, // "medium" and any unexpected value are the baseline rank
    }
}

/// The stronger of two effort labels by [`effort_rank`] (never `String::max`).
fn max_effort<'a>(a: &'a str, b: &'a str) -> &'a str {
    if effort_rank(a) >= effort_rank(b) {
        a
    } else {
        b
    }
}

fn is_one(n: &usize) -> bool {
    *n == 1
}

fn is_not(b: &bool) -> bool {
    !*b
}

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
    /// Whether this change runs under the strict (self-enforcing) tier — surfaces
    /// the stronger "human decision" phrasing when reconciliation is required.
    pub strict: bool,
    /// True when `risk=High` elevated a standard-tier persona (Security/Tester)
    /// to the harness deep model (design.md D6 / Cond 10). Surfaced as a note.
    pub deep_tier_bump: bool,
    pub attempt: usize,
    pub attempt_limit: usize,
    pub reconciliation_required: bool,
    /// Reconciliation kind authorizing this excess attempt, when present.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub attempt_authorization: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub artifact_warning: Option<String>,
    // --- persona tuning (design.md persona-tuning) ---
    // All five carry `skip_serializing_if` so an untuned brief's `--json` envelope
    // is byte-identical at baseline (design.md Cond 1).
    /// Reasoning-effort override, Some ONLY when tuning/floor raised it above the
    /// tier baseline (`high` or `max`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub effort: Option<String>,
    /// Reviewer count the harness spawns for this persona (≥1, ≤4). Omitted at 1.
    #[serde(skip_serializing_if = "is_one")]
    pub reviewers: usize,
    /// A sanitized directive overlay to append AFTER the base directive (never
    /// replacing it). The one un-rankable knob.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub directive_append: Option<String>,
    /// True when an un-rankable weakening vector was in force (a `directive_append`
    /// OR a `modified:true` base directive) — recorded on the gate receipt for audit.
    #[serde(skip_serializing_if = "is_not")]
    pub weakened: bool,
    /// A human note describing the tuning in force. Omitted at baseline.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tuning_note: Option<String>,
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

/// Resolve `(model, note, bumped)` for a phase under a harness, applying the
/// `risk=High` deep-tier bump for the Security and Tester personas (design.md D6
/// / Cond 10). Baseline resolution is [`model_for`]; on top of it, at
/// `risk=High`, Security/Tester elevate to the harness **deep** default ONLY WHEN
/// their resolved model equals the harness **standard** default — the seeded
/// case. `default_models()` seeds an explicit standard-tier entry for every
/// persona, so a naive "fall back to the deep default" bump would be a dead
/// no-op; this overrides that seeded entry. A **custom/non-standard pin** (the
/// resolved model differs from the standard default) is a deliberate operator
/// choice and is left untouched — bumping it would be a rigor *inversion* (mpd
/// cannot rank a pinned model). The elevated model is the built-in deep default
/// (a compile-time-safe constant) resolved via the same `builtin_default`/
/// fallback path `model_for` uses, so `valid_model_id` degradation is preserved
/// and no unsafe config id can reach a rendered `--model`. It only ever
/// *strengthens*; the documented opt-out is to lower the risk.
pub fn model_for_governed(
    cfg: &Config,
    harness: &str,
    phase: Phase,
    risk: RiskLevel,
) -> (String, Option<String>, bool) {
    let (model, note) = model_for(cfg, harness, phase);
    let persona = phase.persona().name;
    let eligible = risk == RiskLevel::High
        && matches!(persona, "Security" | "Tester")
        && model == builtin_default(harness, false);
    if !eligible {
        return (model, note, false);
    }
    // Override the seeded standard entry with the harness deep default. Compute
    // the note through the same fallback path (deep default → its fallback).
    let deep = builtin_default(harness, true).to_string();
    let deep_note = cfg
        .model_fallback(&deep)
        .or_else(|| builtin_fallback(&deep))
        .map(|f| format!("fall back to {f} if unavailable"));
    (deep, deep_note, true)
}

/// The resolved, governed persona tuning for a phase. **Config-only** — it sees
/// only `cfg`, so `had_append` is the CONFIG half of the un-rankable weakening
/// flag; the directive `base_modified` half needs `root` and is folded in by `mpd
/// next` (design.md D4/Cond 9). It only ever STRENGTHENS: the ordinal knobs have
/// no sub-baseline term (D2), effort composes as a monotonic `max` over
/// [`effort_rank`] (never `String` order, Cond 3), and at `risk=High` the effort
/// floor raises the adversarial set with no model clause (Cond 4). It is a
/// resolution-time overlay, NEVER a gate verdict, and never blocks advancement.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ResolvedTuning {
    /// Effort override, Some ONLY when raised above the tier baseline.
    pub effort: Option<String>,
    /// Reviewer count (≥1, ≤4), additive; never gates the DocValidation dual.
    pub reviewers: usize,
    /// The resolved rigor knob (for the record).
    pub rigor: Option<Rigor>,
    /// The resolved depth knob (Tester emphasis; None off the Test phase).
    pub depth: Option<Depth>,
    /// The sanitized directive overlay (terminal_safe + length-capped), if any.
    pub directive_append: Option<String>,
    /// Whether a sanitized append is carried (config half of `weakened`).
    pub had_append: bool,
    /// A human note describing the tuning/floor in force, if anything is non-baseline.
    pub tuning_note: Option<String>,
}

/// Length cap for a sanitized `directive_append`; an oversized overlay degrades to
/// `None` (dropped) rather than bloating the brief (design.md Cond 5).
const MAX_DIRECTIVE_APPEND: usize = 2000;

/// Resolve the governed persona tuning for `phase` at `risk`. See [`ResolvedTuning`].
pub fn resolve_tuning_governed(cfg: &Config, phase: Phase, risk: RiskLevel) -> ResolvedTuning {
    let tuning = cfg.persona_tuning(phase.tuning_key());
    let baseline = if phase.is_deep() { "high" } else { "medium" };

    // rigor knob → effort (standard/none → baseline; deep → high; paranoid → max)
    let rigor = tuning.and_then(|t| t.rigor);
    let rigor_effort = match rigor.map(Rigor::rank) {
        Some(2) => "max",
        Some(1) => "high",
        _ => baseline,
    };

    // depth (Tester only) → emphasis + an effort nudge; ignored off the Test phase.
    let depth = if matches!(phase, Phase::Test) {
        tuning.and_then(|t| t.depth)
    } else {
        None
    };
    let depth_effort = if depth.map_or(0, Depth::rank) >= 1 {
        "high"
    } else {
        baseline
    };

    // High-risk effort floor for the adversarial set — a governance escalation
    // parallel to the model bump, WITHOUT `model_for_governed`'s model-equality
    // clause (round-2 F1): a custom model pin must NOT disable the floor.
    let floor_eligible = risk == RiskLevel::High
        && matches!(
            phase,
            Phase::SecurityPlan | Phase::SecurityCode | Phase::Test | Phase::DocValidation
        );
    let floor_effort = if floor_eligible { "high" } else { baseline };

    // Compose by a monotonic `max` on the ordinal rank (NEVER String order).
    let composed = [rigor_effort, depth_effort, floor_effort]
        .into_iter()
        .fold(baseline, max_effort);
    let effort = (effort_rank(composed) > effort_rank(baseline)).then(|| composed.to_string());

    // reviewers: paranoid on an adversarial-review persona → 2, else 1; clamp ≤4.
    // Purely additive — never gates DocValidation's structural dual (Cond 8).
    let review_persona = matches!(
        phase,
        Phase::SecurityPlan
            | Phase::SecurityCode
            | Phase::DesignReview
            | Phase::DesignSignoff
            | Phase::DocValidation
    );
    let reviewers = if rigor == Some(Rigor::Paranoid) && review_persona {
        2usize
    } else {
        1
    }
    .min(4);

    // directive_append: sanitize (terminal_safe) + length cap. Oversized → None
    // (dropped); a value that sanitizes to empty applies nothing (weakened stays
    // false — design.md Cond 5).
    let directive_append = tuning
        .and_then(|t| t.directive_append.as_deref())
        .and_then(|raw| {
            if raw.chars().count() > MAX_DIRECTIVE_APPEND {
                return None;
            }
            let safe = terminal_safe(raw);
            let safe = safe.trim();
            (!safe.is_empty()).then(|| safe.to_string())
        });
    let had_append = directive_append.is_some();

    // A human note: accurate about whether the change is persona config or the
    // pure governance floor (so an untuned High-risk brief doesn't claim tuning).
    let has_config = rigor.is_some() || depth.is_some() || had_append;
    let mut parts: Vec<String> = Vec::new();
    if let Some(e) = &effort {
        parts.push(format!("effort {e}"));
    }
    if reviewers > 1 {
        parts.push(format!("{reviewers} reviewers"));
    }
    if let Some(d) = depth {
        parts.push(format!("test depth {}", d.label()));
    }
    if had_append {
        parts.push("directive overlay (un-rankable — recorded)".to_string());
    }
    let tuning_note = if parts.is_empty() {
        None
    } else if has_config {
        Some(format!("persona tuning: {}", parts.join("; ")))
    } else {
        Some(format!("risk=high floor: {}", parts.join("; ")))
    };

    ResolvedTuning {
        effort,
        reviewers,
        rigor,
        depth,
        directive_append,
        had_append,
        tuning_note,
    }
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
    strict: bool,
    attempt: usize,
    reconciliation_required: bool,
    attempt_authorization: Option<String>,
    artifact_warning: Option<String>,
) -> NextBrief {
    let persona = phase.persona();
    let (model, model_note, deep_tier_bump) =
        model_for_governed(cfg, harness, phase, governance.risk);
    // Config-only tuning; `mpd next` folds the directive `base_modified` half into
    // `weakened` after this (Cond 9). `brief()` has a single call site, so there is
    // no brief-vs-record split-brain (round-4).
    let tuning = resolve_tuning_governed(cfg, phase, governance.risk);
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
        strict,
        deep_tier_bump,
        attempt,
        attempt_limit: governance.risk.attempt_limit(),
        reconciliation_required,
        attempt_authorization,
        artifact_warning,
        effort: tuning.effort,
        reviewers: tuning.reviewers,
        directive_append: tuning.directive_append,
        // Config half of the un-rankable weakening flag; `mpd next` ORs in the
        // directive `base_modified` half before rendering/recording (Cond 9/11).
        weakened: tuning.had_append,
        tuning_note: tuning.tuning_note,
    }
}

/// Strip terminal control characters from repository-controlled text before
/// human rendering. JSON remains lossless and correctly escaped by serde_json.
pub fn terminal_safe(s: &str) -> String {
    s.chars()
        .filter(|c| !c.is_control() || matches!(c, '\n' | '\t'))
        // Unicode bidirectional and directional-isolate controls can reorder
        // rendered terminal text (spoofing); they carry no diagnostic value.
        .filter(|c| !matches!(c, '\u{202A}'..='\u{202E}' | '\u{2066}'..='\u{2069}'))
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
        if b.strict {
            // Under the strict tier an excess attempt is not something a harness
            // may self-authorize — it is a halt-and-report point for a human
            // (design.md D7 / Cond 12).
            out.push_str(
                "  Reconciliation required — human decision: a human must authorize this excess attempt (`mpd reconcile ...`).\n",
            );
        } else {
            out.push_str("  Reconciliation required before this attempt.\n");
        }
    }
    if b.deep_tier_bump {
        out.push_str(&format!(
            "  risk=high → deep tier: {} elevated to the deep model {}.\n",
            b.persona, b.model
        ));
    }
    if let Some(note) = &b.tuning_note {
        out.push_str(&format!("  {}\n", terminal_safe(note)));
    }
    if b.weakened {
        out.push_str(
            "  ⚠ persona weakened by an un-rankable directive override — recorded on the gate receipt for audit.\n",
        );
        // Strict advisory (Cond 12): a weakened Security/Doc-Validation gate under
        // the strict tier gets the louder human-decision surfacing — still no gate,
        // no CONDITIONAL, no stuck-state.
        if b.strict && matches!(b.persona.as_str(), "Security" | "Architect & Designer") {
            out.push_str(
                "  human decision: this weakening is recorded, not blocked — a human should confirm it before trusting this gate.\n",
            );
        }
    }
    if let Some(w) = &b.artifact_warning {
        out.push_str(&format!("  Warning: {}\n", terminal_safe(w)));
    }
    if b.persona == "Security" {
        out.push_str("  Blocking FAIL requires attacker, prerequisite capability, crossed boundary, concrete harm, and exact fix. Out-of-profile hardening is advisory unless it crosses into the declared profile.\n");
    }
    out
}

/// The persona's guidance with the tuned directive overlay appended AFTER it under
/// an explicit header (never replacing the base directive — design.md Cond 5). The
/// overlay text is already sanitized (terminal_safe + length-capped) at resolve.
fn guidance_with_overlay(b: &NextBrief) -> String {
    match &b.directive_append {
        Some(text) => format!(
            "{}\n\n  ── persona directive overlay (apply AFTER the base directive) ──\n  {}",
            b.guidance,
            terminal_safe(text).replace('\n', "\n  ")
        ),
        None => b.guidance.clone(),
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
    out.push_str(&format!("\n  {}\n", guidance_with_overlay(b)));
    out.push_str(&format!("\n  Gate: {}\n", b.gate));
    out.push_str(&format!("  When done: {}\n", b.gate_command));
    out
}

/// Render a brief as Claude Code subagent spawn instructions.
pub fn render_claude_code(b: &NextBrief) -> String {
    let governance = governance_lines(b);
    let guidance = guidance_with_overlay(b);
    if b.persona == "main-session" || b.persona == "-" {
        return format!(
            "▸ {} — {}\n{}  Handle in the main session (no subagent).\n\n  {}\n\n  When done: {}\n",
            b.label, b.change, governance, guidance, b.gate_command
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
            guidance = guidance,
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
        guidance = guidance,
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
    let guidance = guidance_with_overlay(b);
    if b.persona == "main-session" || b.persona == "-" {
        return format!(
            "▸ {} — {}\n{}  Handle in the current Codex session (no persona switch).\n\n  {}\n\n  When done: {}\n",
            b.label, b.change, governance, guidance, b.gate_command
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
            guidance = guidance,
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
        guidance = guidance,
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

    /// SC-2 regression (security-code.md, residual R2): the Unicode bidi
    /// embedding/override range (LRE/RLE/PDF/LRO/RLO, U+202A–U+202E) and the
    /// directional-isolate range (LRI/RLI/FSI/PDI, U+2066–U+2069) must be
    /// stripped — a surviving RLO can visually reorder the
    /// candidate-influenced console stderr tail into a spoofed error line.
    #[test]
    fn terminal_rendering_strips_bidi_directional_controls() {
        // Every terminal-relevant directional control, individually.
        assert_eq!(
            terminal_safe(
                "a\u{202A}b\u{202B}c\u{202C}d\u{202D}e\u{202E}f\u{2066}g\u{2067}h\u{2068}i\u{2069}j"
            ),
            "abcdefghij"
        );
        // Bidi controls stripped alongside OSC/BEL (C0) and a C1 control,
        // while the allowed \n / \t survive: exact expected output.
        assert_eq!(
            terminal_safe("err\u{1b}]8;;x\u{7}: \u{9b}\u{202E}txet\u{2066}\nnext\tcol"),
            "err]8;;x: txet\nnext\tcol"
        );
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

    #[test]
    fn high_risk_bumps_seeded_security_and_tester_to_the_deep_tier() {
        // R8: on a default-init project (config seeds the standard tier for every
        // persona), risk=High elevates Security AND Tester to the harness deep
        // model — overriding the seeded standard entry — and only ever
        // strengthens. Deep phases and other personas are unaffected; below High
        // nothing bumps.
        let (models, fallbacks) = crate::config::default_models();
        let cfg = Config {
            models,
            model_fallbacks: fallbacks,
            ..Config::default()
        };
        for (harness, deep, std) in [
            ("claude-code", "fable", "sonnet"),
            ("codex", "sol", "terra"),
        ] {
            for phase in [Phase::SecurityPlan, Phase::SecurityCode, Phase::Test] {
                // Baseline: below High, the seeded standard tier stands.
                let (m, _, bumped) = model_for_governed(&cfg, harness, phase, RiskLevel::Medium);
                assert_eq!(
                    (m.as_str(), bumped),
                    (std, false),
                    "{harness}/{phase:?} medium"
                );
                // High: elevated to the deep default, flagged as bumped.
                let (m, note, bumped) = model_for_governed(&cfg, harness, phase, RiskLevel::High);
                assert_eq!(
                    (m.as_str(), bumped),
                    (deep, true),
                    "{harness}/{phase:?} high"
                );
                // The deep note is carried through the same fallback path.
                if deep == "fable" {
                    assert_eq!(note.as_deref(), Some("fall back to opus if unavailable"));
                }
            }
            // A deep-tier persona (Architect) never "bumps" — it is already deep.
            let (m, _, bumped) =
                model_for_governed(&cfg, harness, Phase::Architecture, RiskLevel::High);
            assert_eq!((m.as_str(), bumped), (deep, false));
            // The Builder is standard-tier but out of the elevated set.
            let (m, _, bumped) = model_for_governed(&cfg, harness, Phase::Build, RiskLevel::High);
            assert_eq!((m.as_str(), bumped), (std, false));
        }
    }

    #[test]
    fn high_risk_leaves_a_custom_security_pin_untouched() {
        // R16: a user-customized (non-standard) pin for Security/Tester is a
        // deliberate operator choice — the bump must NOT override it, even at
        // High (bumping a pin mpd cannot rank would be a rigor inversion).
        let mut persona_map = BTreeMap::new();
        persona_map.insert("Security".to_string(), "my-strong-model".to_string());
        persona_map.insert("Tester".to_string(), "my-strong-model".to_string());
        let mut models = ModelMap::new();
        models.insert("claude-code".to_string(), persona_map);
        let cfg = Config {
            models,
            ..Config::default()
        };
        for phase in [Phase::SecurityPlan, Phase::SecurityCode, Phase::Test] {
            let (m, _, bumped) = model_for_governed(&cfg, "claude-code", phase, RiskLevel::High);
            assert_eq!(
                (m.as_str(), bumped),
                ("my-strong-model", false),
                "a custom pin must survive the high-risk bump on {phase:?}"
            );
        }
    }

    fn cfg_with(persona: &str, tuning: crate::config::PersonaTuning) -> Config {
        let mut personas = BTreeMap::new();
        personas.insert(persona.to_string(), tuning);
        Config {
            personas,
            ..Config::default()
        }
    }

    #[test]
    fn resolve_tuning_baseline_is_inert() {
        // R1: an untuned config at the default risk resolves to nothing — no
        // effort override, one reviewer, no append, no note. The brief's --json
        // then omits every tuning field (byte-identical baseline).
        let t = resolve_tuning_governed(&Config::default(), Phase::SecurityCode, RiskLevel::Medium);
        assert_eq!(t.effort, None);
        assert_eq!(t.reviewers, 1);
        assert!(!t.had_append && t.directive_append.is_none());
        assert_eq!(t.tuning_note, None);

        let b = brief(
            &Config::default(),
            "c",
            Phase::SecurityCode,
            "claude-code",
            &Governance::default(),
            true,
            1,
            false,
            None,
            None,
        );
        let json = serde_json::to_string(&b).unwrap();
        for field in [
            "\"effort\"",
            "\"reviewers\"",
            "\"weakened\"",
            "\"directive_append\"",
            "\"tuning_note\"",
        ] {
            assert!(!json.contains(field), "baseline --json must omit {field}");
        }
    }

    #[test]
    fn high_risk_floors_effort_for_the_adversarial_set_without_a_model_clause() {
        // R4 / R4b: at risk=High the floor raises Security/Tester effort to `high`,
        // and — unlike the model bump — has NO model-equality clause, so a CUSTOM
        // MODEL PIN cannot disable it (round-2 F1). rigor=standard is still floored.
        let mut personas = BTreeMap::new();
        personas.insert(
            "Security".to_string(),
            crate::config::PersonaTuning {
                rigor: Some(Rigor::Standard),
                ..Default::default()
            },
        );
        let mut models = ModelMap::new();
        let mut m = BTreeMap::new();
        m.insert("Security".to_string(), "my-fast-model".to_string());
        models.insert("claude-code".to_string(), m);
        let cfg = Config {
            personas,
            models,
            ..Config::default()
        };
        for phase in [Phase::SecurityPlan, Phase::SecurityCode, Phase::Test] {
            assert_eq!(
                resolve_tuning_governed(&cfg, phase, RiskLevel::High)
                    .effort
                    .as_deref(),
                Some("high"),
                "{phase:?}: floor must raise medium→high even with a custom model pin"
            );
            // Below High, no floor: standard rigor is the baseline no-op.
            assert_eq!(
                resolve_tuning_governed(&cfg, phase, RiskLevel::Medium).effort,
                None,
                "{phase:?}: no floor below High"
            );
        }
        // DocValidation is deep-tier (baseline high), so its floor is a no-op.
        assert_eq!(
            resolve_tuning_governed(&Config::default(), Phase::DocValidation, RiskLevel::High)
                .effort,
            None
        );
    }

    #[test]
    fn effort_composition_uses_ordinal_rank_not_string_order() {
        // R4c / round-3 F3: `deep` rigor → `high`, `paranoid` → `max`. A String::max
        // would wrongly pick "medium" over "high" (lexically "high" < "medium"), a
        // strengthen-only INVERSION — the ordinal rank prevents it.
        let deep = cfg_with(
            "Security",
            crate::config::PersonaTuning {
                rigor: Some(Rigor::Deep),
                ..Default::default()
            },
        );
        assert_eq!(
            resolve_tuning_governed(&deep, Phase::SecurityCode, RiskLevel::Medium)
                .effort
                .as_deref(),
            Some("high"),
            "deep must resolve to high, never the lexically-larger medium"
        );
        let paranoid = cfg_with(
            "Security",
            crate::config::PersonaTuning {
                rigor: Some(Rigor::Paranoid),
                ..Default::default()
            },
        );
        let t = resolve_tuning_governed(&paranoid, Phase::SecurityCode, RiskLevel::Medium);
        assert_eq!(t.effort.as_deref(), Some("max"));
        assert_eq!(
            t.reviewers, 2,
            "paranoid on a review persona adds a reviewer"
        );
    }

    #[test]
    fn depth_is_test_only_and_reviewers_are_additive_and_clamped() {
        // R3/R8/R12: depth applies only to Test; a paranoid non-review persona
        // (Builder) never adds a reviewer; reviewers never exceed the additive max.
        let depth = crate::config::PersonaTuning {
            depth: Some(Depth::Fuzz),
            ..Default::default()
        };
        assert_eq!(
            resolve_tuning_governed(
                &cfg_with("Security", depth.clone()),
                Phase::SecurityCode,
                RiskLevel::Medium
            )
            .depth,
            None,
            "depth is ignored off the Test phase"
        );
        let on_test =
            resolve_tuning_governed(&cfg_with("Tester", depth), Phase::Test, RiskLevel::Medium);
        assert_eq!(on_test.depth, Some(Depth::Fuzz));
        assert_eq!(
            on_test.effort.as_deref(),
            Some("high"),
            "fuzz nudges effort up"
        );

        let paranoid_builder = cfg_with(
            "Builder",
            crate::config::PersonaTuning {
                rigor: Some(Rigor::Paranoid),
                ..Default::default()
            },
        );
        assert_eq!(
            resolve_tuning_governed(&paranoid_builder, Phase::Build, RiskLevel::Medium).reviewers,
            1,
            "a non-review persona never adds a reviewer"
        );
    }

    #[test]
    fn directive_append_is_sanitized_oversized_dropped_and_weakened_iff_carried() {
        // R5: control chars are stripped in place (still carried → weakened); an
        // oversized overlay degrades to None (dropped → NOT weakened); an overlay
        // that sanitizes to empty applies nothing (NOT weakened).
        let ctrl = cfg_with(
            "Security",
            crate::config::PersonaTuning {
                directive_append: Some("check IMAP\u{1b}]8cleartext".to_string()),
                ..Default::default()
            },
        );
        let t = resolve_tuning_governed(&ctrl, Phase::SecurityCode, RiskLevel::Medium);
        assert!(t.had_append);
        assert_eq!(t.directive_append.as_deref(), Some("check IMAP]8cleartext"));

        let oversized = cfg_with(
            "Security",
            crate::config::PersonaTuning {
                directive_append: Some("A".repeat(MAX_DIRECTIVE_APPEND + 1)),
                ..Default::default()
            },
        );
        let t = resolve_tuning_governed(&oversized, Phase::SecurityCode, RiskLevel::Medium);
        assert!(
            !t.had_append && t.directive_append.is_none(),
            "oversized → dropped, not weakened"
        );

        let blank = cfg_with(
            "Security",
            crate::config::PersonaTuning {
                directive_append: Some("   \t  ".to_string()),
                ..Default::default()
            },
        );
        assert!(
            !resolve_tuning_governed(&blank, Phase::SecurityCode, RiskLevel::Medium).had_append,
            "an overlay that sanitizes to empty applies nothing"
        );
    }

    #[test]
    fn doc_validation_dual_is_phase_derived_not_reviewer_gated() {
        // R8/R12: DocValidation's structural dual (spawn Architect + Designer) is
        // derived from the phase, independent of any `reviewers` count.
        let b = brief(
            &Config::default(),
            "c",
            Phase::DocValidation,
            "claude-code",
            &Governance::default(),
            true,
            1,
            false,
            None,
            None,
        );
        assert!(b.dual, "the DocValidation dual is phase-derived");
    }

    // -----------------------------------------------------------------
    // Effort-composition property (design.md Cond 3 / D4): for ANY
    // (rigor, depth, risk, phase), `resolve_tuning_governed` never yields an
    // effort ranked below the phase's tier baseline, and is monotonic in
    // rigor rank — the strengthen-only guarantee, generalized beyond the
    // hand-picked examples above.
    // -----------------------------------------------------------------

    fn arb_phase() -> impl Strategy<Value = Phase> {
        prop_oneof![
            Just(Phase::DesignMock),
            Just(Phase::Architecture),
            Just(Phase::DesignReview),
            Just(Phase::SecurityPlan),
            Just(Phase::Build),
            Just(Phase::SecurityCode),
            Just(Phase::DesignSignoff),
            Just(Phase::Test),
            Just(Phase::Documentation),
            Just(Phase::Deploy),
            Just(Phase::DocValidation),
        ]
    }

    fn arb_risk() -> impl Strategy<Value = RiskLevel> {
        prop_oneof![
            Just(RiskLevel::Low),
            Just(RiskLevel::Medium),
            Just(RiskLevel::High),
        ]
    }

    fn arb_rigor_opt() -> impl Strategy<Value = Option<Rigor>> {
        prop_oneof![
            Just(None),
            Just(Some(Rigor::Standard)),
            Just(Some(Rigor::Deep)),
            Just(Some(Rigor::Paranoid)),
        ]
    }

    fn arb_depth_opt() -> impl Strategy<Value = Option<Depth>> {
        prop_oneof![
            Just(None),
            Just(Some(Depth::Examples)),
            Just(Some(Depth::Property)),
            Just(Some(Depth::Fuzz)),
        ]
    }

    /// A config tuning exactly one persona (keyed by `phase.tuning_key()`) with
    /// the given rigor/depth, no append.
    fn cfg_tuned(phase: Phase, rigor: Option<Rigor>, depth: Option<Depth>) -> Config {
        let mut personas = BTreeMap::new();
        personas.insert(
            phase.tuning_key().to_string(),
            crate::config::PersonaTuning {
                rigor,
                depth,
                directive_append: None,
            },
        );
        Config {
            personas,
            ..Config::default()
        }
    }

    fn tier_baseline(phase: Phase) -> &'static str {
        if phase.is_deep() {
            "high"
        } else {
            "medium"
        }
    }

    proptest! {
        /// The resolved effort is NEVER ranked below the phase's tier baseline,
        /// for any (rigor, depth, risk, phase) combination — the composition is
        /// a monotonic `max` over the baseline, so it can only ever raise.
        #[test]
        fn resolved_effort_never_ranked_below_tier_baseline(
            phase in arb_phase(),
            risk in arb_risk(),
            rigor in arb_rigor_opt(),
            depth in arb_depth_opt(),
        ) {
            let cfg = cfg_tuned(phase, rigor, depth);
            let baseline = tier_baseline(phase);
            let t = resolve_tuning_governed(&cfg, phase, risk);
            let effective = t.effort.as_deref().unwrap_or(baseline);
            prop_assert!(
                effort_rank(effective) >= effort_rank(baseline),
                "phase={phase:?} risk={risk:?} rigor={rigor:?} depth={depth:?} \
                 resolved {effective:?} ranked below baseline {baseline:?}"
            );
        }

        /// Monotonic in rigor rank: for a fixed (depth, risk, phase), raising
        /// rigor's ordinal rank can only raise (never lower) the resolved
        /// effort's rank — a `deep` persona never yields weaker effort than a
        /// `standard` one, and `paranoid` never weaker than `deep` (the
        /// specific case the design calls out is subsumed by this general
        /// property over arbitrary rigor pairs).
        #[test]
        fn resolved_effort_is_monotonic_in_rigor_rank(
            phase in arb_phase(),
            risk in arb_risk(),
            depth in arb_depth_opt(),
            r1 in arb_rigor_opt(),
            r2 in arb_rigor_opt(),
        ) {
            let (lo, hi) = if r1.map_or(0, Rigor::rank) <= r2.map_or(0, Rigor::rank) {
                (r1, r2)
            } else {
                (r2, r1)
            };
            let baseline = tier_baseline(phase);
            let rank_lo = effort_rank(
                resolve_tuning_governed(&cfg_tuned(phase, lo, depth), phase, risk)
                    .effort
                    .as_deref()
                    .unwrap_or(baseline),
            );
            let rank_hi = effort_rank(
                resolve_tuning_governed(&cfg_tuned(phase, hi, depth), phase, risk)
                    .effort
                    .as_deref()
                    .unwrap_or(baseline),
            );
            prop_assert!(
                rank_hi >= rank_lo,
                "phase={phase:?} risk={risk:?} depth={depth:?} lo={lo:?}->{rank_lo} hi={hi:?}->{rank_hi}"
            );
        }

        /// A paranoid persona never resolves to weaker effort than a deep one,
        /// across every (phase, risk, depth) — the concrete instance of
        /// monotonicity the design's Risk/Trade-offs section calls out by name.
        #[test]
        fn paranoid_never_yields_effort_weaker_than_deep(
            phase in arb_phase(),
            risk in arb_risk(),
            depth in arb_depth_opt(),
        ) {
            let baseline = tier_baseline(phase);
            let deep_rank = effort_rank(
                resolve_tuning_governed(&cfg_tuned(phase, Some(Rigor::Deep), depth), phase, risk)
                    .effort
                    .as_deref()
                    .unwrap_or(baseline),
            );
            let paranoid_rank = effort_rank(
                resolve_tuning_governed(&cfg_tuned(phase, Some(Rigor::Paranoid), depth), phase, risk)
                    .effort
                    .as_deref()
                    .unwrap_or(baseline),
            );
            prop_assert!(paranoid_rank >= deep_rank);
        }
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
                    false,
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

        /// Cond 10 extended to the bumped path: whatever a config declares for
        /// Security, at risk=High the governed resolution must (a) never leak a
        /// rejected id, (b) only ever strengthen — the resolved model is either
        /// the valid custom pin (untouched, `bumped=false`) or the built-in deep
        /// default (`bumped=true`), never the raw unsafe id, and never the
        /// standard default when a bump was possible.
        #[test]
        fn high_risk_security_bump_never_leaks_an_unsafe_id(id in ".*") {
            let mut persona_map = BTreeMap::new();
            persona_map.insert("Security".to_string(), id.clone());
            let mut models = ModelMap::new();
            models.insert("claude-code".to_string(), persona_map);
            let cfg = Config { models, ..Config::default() };

            let considered_valid = cfg.model_for("claude-code", "Security").is_some();
            let (model, _note, bumped) =
                model_for_governed(&cfg, "claude-code", Phase::SecurityCode, RiskLevel::High);

            if considered_valid && id != "sonnet" {
                // A valid, non-standard custom pin survives untouched.
                prop_assert_eq!(&model, &id);
                prop_assert!(!bumped, "a custom pin must not be bumped");
            } else {
                // Either the id is invalid (degrades) or it equals the standard
                // default ("sonnet") — both cases elevate to the deep default.
                prop_assert_eq!(model.as_str(), "fable", "seeded/degraded case must bump to deep");
                prop_assert!(bumped);
            }
            // The raw unsafe id never surfaces on the rendered model line.
            let b = brief(
                &cfg,
                "change",
                Phase::SecurityCode,
                "claude-code",
                &Governance { risk: RiskLevel::High, ..Governance::default() },
                false,
                1,
                false,
                None,
                None,
            );
            let rendered = render_claude_code(&b);
            if !considered_valid && !id.is_empty() && id != "fable" {
                prop_assert!(
                    !rendered.contains(&format!("model: {id}")),
                    "a rejected id must never surface on the rendered model line"
                );
            }
        }
    }
}
