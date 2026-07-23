//! Offline, bounded evidence evaluation for model routing.
//!
//! This module deliberately has no filesystem or configuration-writer API.
//! `cli`/`config` own contained reads and guarded atomic writes; this layer
//! consumes already-read bytes, produces a deterministic preview, and makes
//! the caller revalidate both evidence and config digests immediately before a
//! write.  Unit-test fixtures exercise the evaluator but are not benchmark
//! adoption evidence.

use crate::digest::Digest;
use serde::{Deserialize, Serialize};
use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet};

pub const ROUTING_EVIDENCE_SCHEMA: &str = "routing-evidence-v1";
const MAX_EVIDENCE_BYTES: usize = 1_048_576;
const MAX_SAMPLES: usize = 4_096;
const MAX_IDENTIFIER_BYTES: usize = 96;
const MAX_TASK_ID_BYTES: usize = 160;

/// A reviewed existing harness/persona entry.  The model is purposefully not
/// part of the identity: a route update changes the model *at* this existing
/// target, never adds a new target learned from evidence.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RoutingTarget {
    pub harness: String,
    pub persona: String,
}

impl RoutingTarget {
    pub fn validate(&self) -> Result<(), RoutingError> {
        validate_identifier("harness", &self.harness)?;
        validate_identifier("persona", &self.persona)
    }
}

/// One blinded, seeded task observation.  Integer units avoid float parsing,
/// rounding, and locale-dependent recommendations.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RoutingSampleV1 {
    pub harness: String,
    pub persona: String,
    pub model: String,
    pub task_id: String,
    pub blind: bool,
    pub seed: u64,
    /// Rubric score in basis points, 0..=10_000, where larger is better.
    pub quality_bps: u16,
    pub escaped_defects: u32,
    pub rework_steps: u32,
    pub latency_ms: u64,
    pub tokens: u64,
    pub cost_micros: u64,
    /// ISO-4217-like three-letter code.  The evaluator never converts it.
    pub currency: String,
}

impl RoutingSampleV1 {
    fn target(&self) -> RoutingTarget {
        RoutingTarget {
            harness: self.harness.clone(),
            persona: self.persona.clone(),
        }
    }

    fn validate(&self) -> Result<(), RoutingError> {
        self.target().validate()?;
        validate_identifier("model", &self.model)?;
        if self.task_id.is_empty() || self.task_id.len() > MAX_TASK_ID_BYTES {
            return Err(RoutingError::Invalid("task_id must be 1..=160 bytes"));
        }
        if !self
            .task_id
            .bytes()
            .all(|b| b.is_ascii_graphic() || b == b' ')
        {
            return Err(RoutingError::Invalid("task_id contains control characters"));
        }
        if self.quality_bps > 10_000 {
            return Err(RoutingError::Invalid("quality_bps exceeds 10000"));
        }
        validate_currency(&self.currency)
    }
}

/// Versioned, offline evidence envelope.  `suite_digest` and `rubric_digest`
/// bind the exact committed task/rubric material; `samples` carry no prompts,
/// source content, raw model output, secrets, or provider credentials.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RoutingEvidenceV1 {
    pub schema: String,
    pub suite_digest: String,
    pub rubric_digest: String,
    pub generated_unix_secs: u64,
    pub minimum_samples: u32,
    pub samples: Vec<RoutingSampleV1>,
}

impl RoutingEvidenceV1 {
    /// Parse a bounded strict JSON envelope.  Unknown fields, invalid digests,
    /// unsafe identifiers, unblinded samples, and oversized vectors are refused
    /// before evaluation.
    pub fn parse(bytes: &[u8]) -> Result<Self, RoutingError> {
        if bytes.is_empty() || bytes.len() > MAX_EVIDENCE_BYTES {
            return Err(RoutingError::Invalid("evidence size is outside bounds"));
        }
        let evidence: Self = serde_json::from_slice(bytes)
            .map_err(|_| RoutingError::Invalid("routing evidence is not strict JSON"))?;
        evidence.validate()?;
        Ok(evidence)
    }

    pub fn digest(&self) -> Result<String, RoutingError> {
        let bytes = serde_json::to_vec(self)
            .map_err(|_| RoutingError::Invalid("routing evidence cannot be encoded"))?;
        Ok(Digest::of_bytes(&bytes).to_hex())
    }

    fn validate(&self) -> Result<(), RoutingError> {
        if self.schema != ROUTING_EVIDENCE_SCHEMA {
            return Err(RoutingError::Invalid("unsupported routing evidence schema"));
        }
        validate_digest("suite_digest", &self.suite_digest)?;
        validate_digest("rubric_digest", &self.rubric_digest)?;
        if self.minimum_samples == 0 || self.minimum_samples as usize > MAX_SAMPLES {
            return Err(RoutingError::Invalid("minimum_samples is outside bounds"));
        }
        if self.samples.is_empty() || self.samples.len() > MAX_SAMPLES {
            return Err(RoutingError::Invalid("sample count is outside bounds"));
        }
        let mut observed_samples = BTreeSet::new();
        for sample in &self.samples {
            sample.validate()?;
            if !sample.blind {
                return Err(RoutingError::Insufficient("unblinded evidence"));
            }
            if !observed_samples.insert((
                sample.harness.as_str(),
                sample.persona.as_str(),
                sample.model.as_str(),
                sample.task_id.as_str(),
                sample.seed,
            )) {
                return Err(RoutingError::Insufficient("duplicate seeded observation"));
            }
        }
        Ok(())
    }
}

/// Policy and current state supplied by the reviewed configuration layer.
/// All required targets must be existing allowlisted entries.  `current_routes`
/// is the model map read before preview; it is also required at confirmation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RoutingEvaluationInput {
    pub now_unix_secs: u64,
    pub maximum_age_secs: u64,
    pub minimum_samples: u32,
    pub required_targets: BTreeSet<RoutingTarget>,
    pub allowed_targets: BTreeSet<RoutingTarget>,
    pub current_routes: BTreeMap<RoutingTarget, String>,
}

impl RoutingEvaluationInput {
    pub fn validate(&self) -> Result<(), RoutingError> {
        if self.maximum_age_secs == 0 || self.minimum_samples == 0 {
            return Err(RoutingError::Invalid("routing policy has a zero bound"));
        }
        if self.required_targets.is_empty() {
            return Err(RoutingError::Invalid(
                "routing policy has no required targets",
            ));
        }
        for target in &self.required_targets {
            target.validate()?;
            if !self.allowed_targets.contains(target) || !self.current_routes.contains_key(target) {
                return Err(RoutingError::Scope(
                    "required target is not an existing allowlisted route",
                ));
            }
        }
        for (target, model) in &self.current_routes {
            target.validate()?;
            validate_identifier("model", model)?;
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RouteMetrics {
    pub samples: u32,
    pub quality_bps: u64,
    pub escaped_defects: u64,
    pub rework_steps: u64,
    pub latency_ms: u64,
    pub tokens: u64,
    pub cost_micros: u64,
    pub currency: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RouteCandidate {
    pub target: RoutingTarget,
    pub model: String,
    pub metrics: RouteMetrics,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RoutingUpdate {
    pub target: RoutingTarget,
    pub from_model: String,
    pub to_model: String,
}

/// A read-only result.  `NoChange` is intentional when the existing route is
/// Pareto eligible; it does not assert global optimality.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub enum RoutingDecision {
    NoChange { reason: &'static str },
    Apply { updates: Vec<RoutingUpdate> },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RoutingEvaluation {
    pub evidence_digest: String,
    pub candidates: Vec<RouteCandidate>,
    pub decision: RoutingDecision,
}

/// A durable-preview input to a caller-owned atomic config writer.  The
/// module cannot write configuration, so it exposes the exact two digests and
/// mappings that must be revalidated under that writer's lock.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RoutingApplyPlan {
    pub evidence_digest: String,
    pub expected_config_digest: String,
    pub updates: Vec<RoutingUpdate>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RoutingError {
    Invalid(&'static str),
    Insufficient(&'static str),
    Missing(&'static str),
    Scope(&'static str),
    Stale,
    ConcurrentConfigDrift,
    ConcurrentEvidenceDrift,
}

impl std::fmt::Display for RoutingError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Invalid(reason) => write!(f, "invalid routing evidence: {reason}"),
            Self::Insufficient(reason) => write!(f, "insufficient routing evidence: {reason}"),
            Self::Missing(reason) => write!(f, "missing routing evidence: {reason}"),
            Self::Scope(reason) => write!(f, "routing target scope refused: {reason}"),
            Self::Stale => f.write_str("routing evidence is stale"),
            Self::ConcurrentConfigDrift => f.write_str("routing config changed after preview"),
            Self::ConcurrentEvidenceDrift => f.write_str("routing evidence changed after preview"),
        }
    }
}

impl std::error::Error for RoutingError {}

/// Evaluate parsed evidence with no network, clock, filesystem, or config
/// side effect.  The recommendation uses only Pareto dominance inside a
/// target/currency group; it is never a claim of global optimality.
pub fn evaluate(
    evidence: &RoutingEvidenceV1,
    input: &RoutingEvaluationInput,
) -> Result<RoutingEvaluation, RoutingError> {
    evidence.validate()?;
    input.validate()?;
    if input.now_unix_secs < evidence.generated_unix_secs
        || input.now_unix_secs - evidence.generated_unix_secs > input.maximum_age_secs
    {
        return Err(RoutingError::Stale);
    }
    let threshold = evidence.minimum_samples.max(input.minimum_samples);
    let candidates = aggregate(evidence, input, threshold)?;
    let mut updates = Vec::new();
    for target in &input.required_targets {
        let current_model = input
            .current_routes
            .get(target)
            .ok_or(RoutingError::Missing("current route"))?;
        let target_candidates: Vec<&RouteCandidate> = candidates
            .iter()
            .filter(|candidate| &candidate.target == target)
            .collect();
        let current = target_candidates
            .iter()
            .find(|candidate| candidate.model == *current_model)
            .ok_or(RoutingError::Missing("current configured model coverage"))?;
        let dominating_candidates: Vec<&RouteCandidate> = target_candidates
            .iter()
            .copied()
            .filter(|candidate| dominates(candidate, current))
            .collect();
        if !dominating_candidates.is_empty() {
            // A route may move only to a candidate that itself Pareto-dominates
            // the current model. Choosing from every globally nondominated
            // candidate could otherwise select a trade-off candidate that is
            // worse than current on one dimension merely because a different
            // candidate established that an improvement existed.
            let chosen = nondominated(&dominating_candidates)
                .into_iter()
                .min_by(candidate_order)
                .ok_or(RoutingError::Insufficient("no Pareto candidate"))?;
            if chosen.model != *current_model {
                updates.push(RoutingUpdate {
                    target: target.clone(),
                    from_model: current_model.clone(),
                    to_model: chosen.model.clone(),
                });
            }
        }
    }
    updates.sort_by(|a, b| a.target.cmp(&b.target));
    let decision = if updates.is_empty() {
        RoutingDecision::NoChange {
            reason: "current-route-pareto-eligible",
        }
    } else {
        RoutingDecision::Apply { updates }
    };
    Ok(RoutingEvaluation {
        evidence_digest: evidence.digest()?,
        candidates,
        decision,
    })
}

/// Construct a non-mutating preview.  A writer must later call
/// [`revalidate_apply_plan`] while holding its own config lock, then perform
/// its own guarded atomic write of routing fields only.
pub fn preview_apply(
    evaluation: &RoutingEvaluation,
    expected_config_digest: &str,
    input: &RoutingEvaluationInput,
) -> Result<RoutingApplyPlan, RoutingError> {
    validate_digest("config digest", expected_config_digest)?;
    input.validate()?;
    let updates = match &evaluation.decision {
        RoutingDecision::NoChange { .. } => Vec::new(),
        RoutingDecision::Apply { updates } => updates.clone(),
    };
    validate_updates(&updates, input)?;
    Ok(RoutingApplyPlan {
        evidence_digest: evaluation.evidence_digest.clone(),
        expected_config_digest: expected_config_digest.to_string(),
        updates,
    })
}

/// Revalidate a preview against the just-read config/evidence images.  This
/// has no writes and rejects drift before a caller performs the atomic write.
pub fn revalidate_apply_plan(
    plan: &RoutingApplyPlan,
    observed_config_digest: &str,
    observed_evidence_digest: &str,
    input: &RoutingEvaluationInput,
) -> Result<(), RoutingError> {
    if plan.expected_config_digest != observed_config_digest {
        return Err(RoutingError::ConcurrentConfigDrift);
    }
    if plan.evidence_digest != observed_evidence_digest {
        return Err(RoutingError::ConcurrentEvidenceDrift);
    }
    validate_digest("config digest", observed_config_digest)?;
    validate_digest("evidence digest", observed_evidence_digest)?;
    input.validate()?;
    validate_updates(&plan.updates, input)
}

fn aggregate(
    evidence: &RoutingEvidenceV1,
    input: &RoutingEvaluationInput,
    threshold: u32,
) -> Result<Vec<RouteCandidate>, RoutingError> {
    #[derive(Default)]
    struct Accumulator {
        quality_bps: u64,
        escaped_defects: u64,
        rework_steps: u64,
        latency_ms: u64,
        tokens: u64,
        cost_micros: u64,
        samples: u32,
    }
    let mut grouped: BTreeMap<(RoutingTarget, String, String), Accumulator> = BTreeMap::new();
    for sample in &evidence.samples {
        let target = sample.target();
        if !input.allowed_targets.contains(&target) {
            return Err(RoutingError::Scope(
                "evidence names a target outside the reviewed allowlist",
            ));
        }
        let key = (target, sample.model.clone(), sample.currency.clone());
        let acc = grouped.entry(key).or_default();
        acc.quality_bps = acc
            .quality_bps
            .checked_add(sample.quality_bps as u64)
            .ok_or(RoutingError::Invalid("quality overflow"))?;
        acc.escaped_defects = acc
            .escaped_defects
            .checked_add(sample.escaped_defects as u64)
            .ok_or(RoutingError::Invalid("defect overflow"))?;
        acc.rework_steps = acc
            .rework_steps
            .checked_add(sample.rework_steps as u64)
            .ok_or(RoutingError::Invalid("rework overflow"))?;
        acc.latency_ms = acc
            .latency_ms
            .checked_add(sample.latency_ms)
            .ok_or(RoutingError::Invalid("latency overflow"))?;
        acc.tokens = acc
            .tokens
            .checked_add(sample.tokens)
            .ok_or(RoutingError::Invalid("token overflow"))?;
        acc.cost_micros = acc
            .cost_micros
            .checked_add(sample.cost_micros)
            .ok_or(RoutingError::Invalid("cost overflow"))?;
        acc.samples = acc
            .samples
            .checked_add(1)
            .ok_or(RoutingError::Invalid("sample overflow"))?;
    }
    let mut currencies: BTreeMap<RoutingTarget, BTreeSet<String>> = BTreeMap::new();
    for (target, _, currency) in grouped.keys() {
        currencies
            .entry(target.clone())
            .or_default()
            .insert(currency.clone());
    }
    if currencies.values().any(|currencies| currencies.len() != 1) {
        return Err(RoutingError::Insufficient(
            "mixed currencies in a route comparison",
        ));
    }
    let mut candidates = Vec::new();
    for ((target, model, currency), acc) in grouped {
        if acc.samples < threshold {
            continue;
        }
        let n = u64::from(acc.samples);
        candidates.push(RouteCandidate {
            target,
            model,
            metrics: RouteMetrics {
                samples: acc.samples,
                quality_bps: acc.quality_bps / n,
                escaped_defects: acc.escaped_defects / n,
                rework_steps: acc.rework_steps / n,
                latency_ms: acc.latency_ms / n,
                tokens: acc.tokens / n,
                cost_micros: acc.cost_micros / n,
                currency,
            },
        });
    }
    for target in &input.required_targets {
        if !candidates
            .iter()
            .any(|candidate| &candidate.target == target)
        {
            return Err(RoutingError::Insufficient("undersampled required route"));
        }
    }
    candidates.sort_by(|a, b| {
        a.target
            .cmp(&b.target)
            .then_with(|| a.model.cmp(&b.model))
            .then_with(|| a.metrics.currency.cmp(&b.metrics.currency))
    });
    Ok(candidates)
}

fn dominates(left: &RouteCandidate, right: &RouteCandidate) -> bool {
    if left.target != right.target || left.metrics.currency != right.metrics.currency {
        return false;
    }
    let l = &left.metrics;
    let r = &right.metrics;
    l.quality_bps >= r.quality_bps
        && l.escaped_defects <= r.escaped_defects
        && l.rework_steps <= r.rework_steps
        && l.latency_ms <= r.latency_ms
        && l.tokens <= r.tokens
        && l.cost_micros <= r.cost_micros
        && (l.quality_bps > r.quality_bps
            || l.escaped_defects < r.escaped_defects
            || l.rework_steps < r.rework_steps
            || l.latency_ms < r.latency_ms
            || l.tokens < r.tokens
            || l.cost_micros < r.cost_micros)
}

fn nondominated<'a>(candidates: &[&'a RouteCandidate]) -> Vec<&'a RouteCandidate> {
    candidates
        .iter()
        .copied()
        .filter(|candidate| !candidates.iter().any(|other| dominates(other, candidate)))
        .collect()
}

fn candidate_order(a: &&RouteCandidate, b: &&RouteCandidate) -> Ordering {
    let a = *a;
    let b = *b;
    b.metrics
        .quality_bps
        .cmp(&a.metrics.quality_bps)
        .then_with(|| a.metrics.escaped_defects.cmp(&b.metrics.escaped_defects))
        .then_with(|| a.metrics.rework_steps.cmp(&b.metrics.rework_steps))
        .then_with(|| a.metrics.latency_ms.cmp(&b.metrics.latency_ms))
        .then_with(|| a.metrics.tokens.cmp(&b.metrics.tokens))
        .then_with(|| a.metrics.cost_micros.cmp(&b.metrics.cost_micros))
        .then_with(|| a.model.cmp(&b.model))
}

fn validate_updates(
    updates: &[RoutingUpdate],
    input: &RoutingEvaluationInput,
) -> Result<(), RoutingError> {
    let mut seen = BTreeSet::new();
    for update in updates {
        update.target.validate()?;
        validate_identifier("from_model", &update.from_model)?;
        validate_identifier("to_model", &update.to_model)?;
        if update.from_model == update.to_model
            || !input.allowed_targets.contains(&update.target)
            || input.current_routes.get(&update.target) != Some(&update.from_model)
            || !seen.insert(update.target.clone())
        {
            return Err(RoutingError::Scope(
                "update is not an existing allowlisted current route",
            ));
        }
    }
    Ok(())
}

fn validate_identifier(field: &'static str, value: &str) -> Result<(), RoutingError> {
    if value.is_empty()
        || value.len() > MAX_IDENTIFIER_BYTES
        || !value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
    {
        return Err(RoutingError::Invalid(match field {
            "harness" => "unsafe harness identifier",
            "persona" => "unsafe persona identifier",
            "model" | "from_model" | "to_model" => "unsafe model identifier",
            _ => "unsafe identifier",
        }));
    }
    Ok(())
}

fn validate_currency(currency: &str) -> Result<(), RoutingError> {
    if currency.len() == 3 && currency.bytes().all(|b| b.is_ascii_uppercase()) {
        Ok(())
    } else {
        Err(RoutingError::Invalid(
            "currency must be a three-letter uppercase code",
        ))
    }
}

fn validate_digest(field: &'static str, value: &str) -> Result<(), RoutingError> {
    Digest::from_hex(value).map_err(|_| {
        RoutingError::Invalid(match field {
            "suite_digest" => "suite_digest is not canonical SHA-256",
            "rubric_digest" => "rubric_digest is not canonical SHA-256",
            "config digest" => "config digest is not canonical SHA-256",
            _ => "digest is not canonical SHA-256",
        })
    })?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    const DIGEST: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    fn target() -> RoutingTarget {
        RoutingTarget {
            harness: "codex".into(),
            persona: "Builder".into(),
        }
    }

    fn sample(model: &str, quality_bps: u16, cost_micros: u64) -> RoutingSampleV1 {
        RoutingSampleV1 {
            harness: "codex".into(),
            persona: "Builder".into(),
            model: model.into(),
            task_id: "task-01".into(),
            blind: true,
            seed: 7,
            quality_bps,
            escaped_defects: 1,
            rework_steps: 1,
            latency_ms: 100,
            tokens: 200,
            cost_micros,
            currency: "USD".into(),
        }
    }

    fn evidence(samples: Vec<RoutingSampleV1>) -> RoutingEvidenceV1 {
        RoutingEvidenceV1 {
            schema: ROUTING_EVIDENCE_SCHEMA.into(),
            suite_digest: DIGEST.into(),
            rubric_digest: DIGEST.into(),
            generated_unix_secs: 100,
            minimum_samples: 2,
            samples,
        }
    }

    fn input(current: &str) -> RoutingEvaluationInput {
        let mut routes = BTreeMap::new();
        routes.insert(target(), current.into());
        let mut targets = BTreeSet::new();
        targets.insert(target());
        RoutingEvaluationInput {
            now_unix_secs: 110,
            maximum_age_secs: 20,
            minimum_samples: 2,
            required_targets: targets.clone(),
            allowed_targets: targets,
            current_routes: routes,
        }
    }

    #[test]
    fn strict_parser_rejects_unknown_fields_and_unblinded_samples() {
        let mut bytes = serde_json::to_vec(&evidence(vec![sample("terra", 9000, 10)])).unwrap();
        bytes.pop();
        bytes.extend_from_slice(b",\"unexpected\":true}");
        assert_eq!(
            RoutingEvidenceV1::parse(&bytes),
            Err(RoutingError::Invalid("routing evidence is not strict JSON"))
        );
        let mut unblinded = evidence(vec![sample("terra", 9000, 10)]);
        unblinded.samples[0].blind = false;
        assert_eq!(
            RoutingEvidenceV1::parse(&serde_json::to_vec(&unblinded).unwrap()),
            Err(RoutingError::Insufficient("unblinded evidence"))
        );
        let duplicate = evidence(vec![sample("terra", 9000, 10), sample("terra", 9000, 10)]);
        assert_eq!(
            RoutingEvidenceV1::parse(&serde_json::to_vec(&duplicate).unwrap()),
            Err(RoutingError::Insufficient("duplicate seeded observation"))
        );
    }

    #[test]
    fn stale_mixed_currency_and_missing_current_coverage_refuse() {
        let terra_a = sample("terra", 9000, 10);
        let mut terra_b = sample("terra", 9000, 10);
        terra_b.seed = 8;
        let e = evidence(vec![terra_a, terra_b]);
        let mut stale = input("sol");
        stale.now_unix_secs = 121;
        assert_eq!(evaluate(&e, &stale), Err(RoutingError::Stale));
        let mut mixed = e.clone();
        let sol_a = sample("sol", 8000, 20);
        let mut sol_b = sample("sol", 8000, 20);
        sol_b.seed = 8;
        mixed.samples.push(sol_a);
        mixed.samples.push(sol_b);
        mixed.samples[2].currency = "EUR".into();
        mixed.samples[3].currency = "EUR".into();
        assert_eq!(
            evaluate(&mixed, &input("sol")),
            Err(RoutingError::Insufficient(
                "mixed currencies in a route comparison"
            ))
        );
        assert_eq!(
            evaluate(&e, &input("sol")),
            Err(RoutingError::Missing("current configured model coverage"))
        );
    }

    #[test]
    fn dominates_and_produces_deterministic_preview() {
        let mut sol_b = sample("sol", 8000, 20);
        sol_b.seed = 8;
        let mut terra_b = sample("terra", 9000, 10);
        terra_b.seed = 8;
        let e = evidence(vec![
            sample("sol", 8000, 20),
            sol_b,
            sample("terra", 9000, 10),
            terra_b,
        ]);
        let evaluated = evaluate(&e, &input("sol")).unwrap();
        let plan = preview_apply(&evaluated, DIGEST, &input("sol")).unwrap();
        assert_eq!(plan.updates.len(), 1);
        assert_eq!(plan.updates[0].to_model, "terra");
        revalidate_apply_plan(&plan, DIGEST, &evaluated.evidence_digest, &input("sol")).unwrap();
        assert_eq!(
            revalidate_apply_plan(&plan, DIGEST, DIGEST, &input("sol")),
            Err(RoutingError::ConcurrentEvidenceDrift)
        );
    }

    #[test]
    fn nondominated_current_recommends_no_change() {
        let mut fast_expensive = sample("terra", 9000, 30);
        fast_expensive.latency_ms = 50;
        let mut fast_expensive_b = fast_expensive.clone();
        fast_expensive_b.seed = 8;
        let mut sol_b = sample("sol", 8500, 10);
        sol_b.seed = 8;
        let e = evidence(vec![
            sample("sol", 8500, 10),
            sol_b,
            fast_expensive.clone(),
            fast_expensive_b,
        ]);
        let evaluated = evaluate(&e, &input("sol")).unwrap();
        assert_eq!(
            evaluated.decision,
            RoutingDecision::NoChange {
                reason: "current-route-pareto-eligible"
            }
        );
    }

    #[test]
    fn update_is_selected_only_from_candidates_that_dominate_current() {
        let current_a = sample("sol", 8000, 20);
        let mut current_b = current_a.clone();
        current_b.seed = 8;

        let dominator_a = sample("terra", 9000, 20);
        let mut dominator_b = dominator_a.clone();
        dominator_b.seed = 8;

        // This candidate is globally nondominated because its quality is
        // highest, but it is worse than current on cost and cannot be applied.
        let expensive_a = sample("premium", 9500, 30);
        let mut expensive_b = expensive_a.clone();
        expensive_b.seed = 8;

        let evaluated = evaluate(
            &evidence(vec![
                current_a,
                current_b,
                dominator_a,
                dominator_b,
                expensive_a,
                expensive_b,
            ]),
            &input("sol"),
        )
        .unwrap();
        let RoutingDecision::Apply { updates } = evaluated.decision else {
            panic!("a dominating route should produce an update");
        };
        assert_eq!(updates.len(), 1);
        assert_eq!(updates[0].to_model, "terra");
    }

    #[test]
    fn scope_and_config_drift_are_refused_without_writer() {
        let mut outside = sample("terra", 9000, 10);
        outside.persona = "Unreviewed".into();
        let mut outside_second = outside.clone();
        outside_second.seed = 8;
        let e = evidence(vec![outside, outside_second]);
        assert_eq!(
            evaluate(&e, &input("sol")),
            Err(RoutingError::Scope(
                "evidence names a target outside the reviewed allowlist"
            ))
        );
        let mut sol_b = sample("sol", 8000, 20);
        sol_b.seed = 8;
        let mut terra_b = sample("terra", 9000, 10);
        terra_b.seed = 8;
        let e = evidence(vec![
            sample("sol", 8000, 20),
            sol_b,
            sample("terra", 9000, 10),
            terra_b,
        ]);
        let evaluated = evaluate(&e, &input("sol")).unwrap();
        let plan = preview_apply(&evaluated, DIGEST, &input("sol")).unwrap();
        assert_eq!(
            revalidate_apply_plan(
                &plan,
                "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
                &evaluated.evidence_digest,
                &input("sol")
            ),
            Err(RoutingError::ConcurrentConfigDrift)
        );
    }

    proptest! {
        #[test]
        fn parser_never_panics_on_arbitrary_bounded_bytes(bytes in proptest::collection::vec(any::<u8>(), 0..4096)) {
            let _ = RoutingEvidenceV1::parse(&bytes);
        }

        #[test]
        fn identifier_validation_never_panics(value in ".*") {
            let _ = validate_identifier("model", &value);
        }
    }
}
